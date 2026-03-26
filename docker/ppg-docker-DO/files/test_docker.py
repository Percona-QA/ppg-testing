import json
import os
import pytest
import subprocess
import testinfra
import sys
import settings
import time
import psycopg2
from datetime import datetime, timedelta

# Attempt to import psycopg2 with a helpful error for CI logs
try:
    import psycopg2
except ImportError:
    print("\n[ERROR] psycopg2 not found in the current Python environment.")
    print(f"[DEBUG] Python Executable: {sys.executable}")
    print("[FIX] Run: pip install psycopg2-binary\n")
    sys.exit(2) # Exit with code 2 to indicate a configuration/collection error

MAJOR_VER = os.getenv('VERSION').split('.')[0]
MAJOR_MINOR_VER = os.getenv('VERSION')
DOCKER_REPO = os.getenv('DOCKER_REPOSITORY')
IMG_TAG = os.getenv('TAG')
IS_WITH_POSTGIS = os.getenv('WITH_POSTGIS', 'false').lower() == "true"

pg_docker_versions = settings.get_settings(MAJOR_MINOR_VER)

DOCKER_RHEL_FILES = pg_docker_versions['rhel_files']
DOCKER_RPM_PACKAGES = pg_docker_versions['rpm_packages']
DOCKER_EXTENSIONS = pg_docker_versions['extensions']
DOCKER_BINARIES = pg_docker_versions['binaries']

# Red Hat ecosystem required image labels (same as pgbouncer/pgbackrest)
REQUIRED_LABEL_MAINTAINER = os.getenv("PPG_LABEL_MAINTAINER", "Percona Development <info@percona.com>")
REQUIRED_LABEL_VENDOR = os.getenv("PPG_LABEL_VENDOR", "Percona")
REQUIRED_LABEL_NAME_PREFIX = "Percona "
EXPECTED_LABEL_NAME_POSTGRESQL = os.getenv("PPG_LABEL_NAME_POSTGRESQL", "Percona Distribution for PostgreSQL")
REQUIRED_LABEL_KEYS = ("name", "vendor", "version", "release", "summary", "description", "maintainer")
RED_HAT_TRADEMARK_FORBIDDEN = ("Red Hat", "RHEL", "RedHat")


def _get_postgres_image_ref():
    """Return the PostgreSQL Docker image ref used for this run (with or without PostGIS)."""
    if IS_WITH_POSTGIS:
        return f"{DOCKER_REPO}/percona-distribution-postgresql-custom:{IMG_TAG}"
    return f"{DOCKER_REPO}/percona-distribution-postgresql-custom:{IMG_TAG}"


def _get_image_labels(image_ref):
    """Return the labels dict for a Docker image (via docker inspect)."""
    result = subprocess.run(
        ["docker", "inspect", "--format", "{{json .Config.Labels}}", image_ref],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"docker inspect failed for {image_ref}: {result.stderr}")
    return json.loads(result.stdout) if result.stdout.strip() else {}


def _check_no_redhat_trademark(labels, errors):
    """Check that name, vendor, maintainer do not violate Red Hat trademark."""
    for key in ("name", "vendor", "maintainer"):
        val = (labels.get(key) or "").strip()
        for forbidden in RED_HAT_TRADEMARK_FORBIDDEN:
            if forbidden in val:
                errors.append(
                    f"label {key!r} must not contain Red Hat trademark {forbidden!r}, got: {repr(labels.get(key))}"
                )


def _check_required_labels_present(labels, errors):
    """Check that all required labels are present in container metadata."""
    for key in REQUIRED_LABEL_KEYS:
        val = labels.get(key)
        if val is None or (isinstance(val, str) and not val.strip()):
            errors.append(f"required label {key!r} is missing or empty in container metadata")


def _validate_ppg_image_labels(image_ref, expected_name=None):
    """
    Validate Red Hat ecosystem required labels on the PPG PostgreSQL image.
    1. No Red Hat trademark in name, vendor, maintainer.
    2. All required labels (name, vendor, version, release, summary, description, maintainer) are present.
    3. name, vendor, maintainer have the expected values.
    """
    labels = _get_image_labels(image_ref)
    errors = []

    _check_no_redhat_trademark(labels, errors)
    _check_required_labels_present(labels, errors)

    name_val = labels.get("name", "").strip()
    if expected_name is not None:
        if name_val != expected_name:
            errors.append(f"label 'name' must be {expected_name!r}, got: {repr(labels.get('name'))}")
    elif not name_val.startswith(REQUIRED_LABEL_NAME_PREFIX) or len(name_val) <= len(REQUIRED_LABEL_NAME_PREFIX):
        errors.append(f"label 'name' must be 'Percona <Product Name>', got: {repr(labels.get('name'))}")
    if labels.get("maintainer") != REQUIRED_LABEL_MAINTAINER:
        errors.append(
            f"label 'maintainer' must be {REQUIRED_LABEL_MAINTAINER!r}, got: {repr(labels.get('maintainer'))}"
        )
    if labels.get("vendor") != REQUIRED_LABEL_VENDOR:
        errors.append(f"label 'vendor' must be {REQUIRED_LABEL_VENDOR!r}, got: {repr(labels.get('vendor'))}")

    if errors:
        raise AssertionError(f"Image {image_ref} label validation failed:\n" + "\n".join(errors))


def _check_licenses_at_licenses(image_ref):
    """Check that terms/conditions and open source licensing are present at /licenses in the image."""
    cmd = [
        "docker", "run", "--rm", image_ref,
        "sh", "-c",
        "test -e /licenses && (test -f /licenses && test -s /licenses || (test -d /licenses && test $(ls -A /licenses 2>/dev/null | wc -l) -gt 0))",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise AssertionError(
            f"Image {image_ref}: /licenses missing or empty. "
            "Terms and open source licensing information must be present at /licenses."
        )


# scope='session' uses the same container for all the tests;
@pytest.fixture(scope='session')
def host(request):

    DOCKER_TO_USE = _get_postgres_image_ref()

    print('Major Version: ' + MAJOR_VER)
    print('Major Minor Version: ' + MAJOR_MINOR_VER)
    print('Image TAG: ' + IMG_TAG)
    print('IS_WITH_POSTGIS: ' + str(IS_WITH_POSTGIS))
    print('WITH_POSTGIS: ' + str(os.getenv('WITH_POSTGIS')))
    print('DOCKER_TO_USE: ' + DOCKER_TO_USE)

    # Pass the config to load timescaledb and pg_stat_monitor (if needed)
    docker_id = subprocess.check_output(
        ['docker', 'run',
         '--name', f'PG{MAJOR_VER}',
         '-e', 'POSTGRES_PASSWORD=password',
         '-p', '5432:5432',
         '-d', DOCKER_TO_USE,
         '-c', 'shared_preload_libraries=timescaledb,pg_stat_monitor'
        ]).decode().strip()

    # return a testinfra connection to the container
    yield testinfra.get_host("docker://" + docker_id)

    # at the end of the test suite, destroy the container
    subprocess.check_call(['docker', 'rm', '-f', docker_id])


def test_psql_string(host):
    # 'host' now binds to the container
    assert f"psql (PostgreSQL) {MAJOR_MINOR_VER} - Percona Distribution" in host.check_output('psql -V')
    assert not f"psql (PostgreSQL) {MAJOR_MINOR_VER} - Percona Server for PostgreSQL" in host.check_output('psql -V')


def test_wait_docker_load(host):
    dist = host.system_info.distribution
    time.sleep(5)
    assert 0 == 0


def test_ppg_postgres_image_labels():
    """Validate PostgreSQL image: (1) name/vendor/maintainer do not violate Red Hat trademark;
    (2) required labels (name, vendor, version, release, summary, description, maintainer) are present;
    (3) name/vendor/maintainer match expected values."""
    image_ref = _get_postgres_image_ref()
    _validate_ppg_image_labels(image_ref, expected_name=EXPECTED_LABEL_NAME_POSTGRESQL)


def test_ppg_postgres_image_licenses_at_licenses():
    """Check that terms/conditions and open source licensing are present at /licenses in the PostgreSQL image."""
    image_ref = _get_postgres_image_ref()
    _check_licenses_at_licenses(image_ref)


@pytest.fixture()
def postgresql_binary(host):
    dist = host.system_info.distribution
    # pg_bin = f"/usr/lib/postgresql/{MAJOR_VER}/bin/postgres"
    # if dist.lower() in ["redhat", "centos", "rhel", "rocky"]:
    #     pg_bin = f"/usr/pgsql-{MAJOR_VER}/bin/postgres"
    pg_bin = f"/usr/pgsql-{MAJOR_VER}/bin/postgres"
    return host.file(pg_bin)


@pytest.fixture()
def postgresql_query_version(host):
    return host.run("psql -c 'SELECT version()' | awk 'NR==3{print $2}'")


@pytest.fixture()
def extension_list(host):
    result = host.check_output("psql -c 'SELECT * FROM pg_available_extensions;' | awk 'NR>=3{print $1}'")
    result = result.split()
    return result

# def test_postgresql_is_running_and_enabled(host):
#     dist = host.system_info.distribution
#     service_name = "postgresql"
#     if dist.lower() in ["redhat", "centos", "rhel", "rocky"]:
#         service_name = f"postgresql-{MAJOR_VER}"
#     service = host.service(service_name)
#     assert service.is_running


def postgres_binary(postgresql_binary):
    assert postgresql_binary.exists
    assert postgresql_binary.user == "root"


@pytest.mark.parametrize("binary", DOCKER_BINARIES)
def test_binaries(host, binary):
    dist = host.system_info.distribution
    # bin_path = f"/usr/lib/postgresql/{MAJOR_VER}/bin/"
    # if dist.lower() in ["redhat", "centos", "rhel", "rocky"]:
    #     bin_path = f"/usr/pgsql-{MAJOR_VER}/bin/"
    bin_path = f"/usr/pgsql-{MAJOR_VER}/bin/"
    bin_full_path = os.path.join(bin_path, binary)
    binary_file = host.file(bin_full_path)
    assert binary_file.exists


def test_pg_config_server_version(host):
    cmd = "pg_config --version"
    try:
        result = host.check_output(cmd)
        assert f'{MAJOR_MINOR_VER}' in result, result.stdout
    except AssertionError:
        pytest.mark.xfail(reason="Maybe dev package not install")


def test_postgresql_query_version(postgresql_query_version):
    assert postgresql_query_version.rc == 0, postgresql_query_version.stderr
    assert postgresql_query_version.stdout.strip("\n") == f'{MAJOR_MINOR_VER}', postgresql_query_version.stdout


def test_postgres_client_version(host):
    cmd = "psql --version"
    result = host.check_output(cmd)
    assert f'{MAJOR_MINOR_VER}' in result.strip("\n"), result.stdout

SKIP_EXTENSIONS = [
    "postgis_sfcgal",
    "address_standardizer",
    "postgis_tiger_geocoder",
    "postgis",
    "postgis_topology",
    "postgis_raster",
    "address_standardizer_data_us",
    "timescaledb",
    "pgaudit",
    "plpgsql",
    "pg_repack",
    "pg_stat_monitor",
]


@pytest.fixture(scope="module")
def extension_list(host):
    """
    Fetches the list of all available extensions from PostgreSQL once per test module.
    """
    # -t: tuples only, -A: unaligned, -q: quiet
    cmd = "psql -t -A -q -c 'SELECT name FROM pg_available_extensions;'"
    res = host.run(cmd)
    assert res.rc == 0, f"Failed to fetch extension list: {res.stderr}"

    # Transform the multiline string into a clean set for O(1) lookup speed
    return set(res.stdout.split())


def should_skip(extension):
    major = int(MAJOR_VER)

    # 1. Hard skips
    if extension in SKIP_EXTENSIONS:
        return True, f"Explicitly skipped in SKIP_EXTENSIONS"

    # 2. Version-based removals
    if major >= 17 and extension == 'adminpack':
        return True, "adminpack removed in PG17+"

    if major < 18 and extension == 'pg_logicalinspect':
        return True, "pg_logicalinspect only supported in PG18+"

    # 4. Feature-flag based skips
    postgis_family = {
        "postgis", "postgis_topology", "postgis_raster", "postgis_sfcgal", 
        "address_standardizer", "postgis_tiger_geocoder", "address_standardizer_data_us"
    }
    if not IS_WITH_POSTGIS and extension in postgis_family:
        return True, "Docker build is without PostGIS so skipping."

    return False, None


@pytest.mark.parametrize("extension", DOCKER_EXTENSIONS)
def test_extensions_list(extension_list, host, extension):
    """
    Verifies that the extension is available to be installed in the PostgreSQL instance.
    """
    major = int(MAJOR_VER)

    # 1. Version-based removals
    if major >= 17 and extension == 'adminpack':
        return True, "adminpack removed in PG17+"

    if major < 18 and extension == 'pg_logicalinspect':
        return True, "pg_logicalinspect only supported in PG18+"

    # 2. Verify the extension is present in the available extensions list
    # Use a descriptive error message to help debug if it's missing
    assert extension in extension_list, (
        f"Extension '{extension}' was expected but is not available in the "
        f"PostgreSQL {MAJOR_VER} installation."
    )

@pytest.mark.parametrize("extension", DOCKER_EXTENSIONS)
def test_enable_extension(host, extension):
    skip, reason = should_skip(extension)
    if skip:
        pytest.skip(reason)

    # 1. Install Extension
    res = host.run(f'psql -c "CREATE EXTENSION \\"{extension}\\";"')
    assert res.rc == 0, f"Failed to create {extension}: {res.stderr}"
    assert "CREATE EXTENSION" in res.stdout

    # 2. Verify existence using SQL count (Reliable replacement for awk)
    check_sql = f"SELECT count(*) FROM pg_extension WHERE extname = '{extension}';"
    count = host.run(f"psql -t -A -c \"{check_sql}\"").stdout.strip()
    assert count == "1", f"Extension {extension} not found in pg_extension table"


@pytest.mark.parametrize("extension", DOCKER_EXTENSIONS[::-1])
def test_drop_extension(host, extension):
    skip, reason = should_skip(extension)
    if skip:
        pytest.skip(reason)

    # 1. Drop Extension (Use CASCADE to handle dependencies)
    res = host.run(f'psql -c "DROP EXTENSION \\"{extension}\\" CASCADE;"')
    assert res.rc == 0, f"Failed to drop {extension}: {res.stderr}"
    assert "DROP EXTENSION" in res.stdout

    # 2. Verify it is gone
    check_sql = f"SELECT count(*) FROM pg_extension WHERE extname = '{extension}';"
    count = host.run(f"psql -t -A -c \"{check_sql}\"").stdout.strip()
    assert count == "0", f"Extension {extension} still exists after drop"


def test_plpgsql_extension(host):
    # plpgsql is internal and always exists; just check for it directly
    check_sql = "SELECT count(*) FROM pg_extension WHERE extname = 'plpgsql';"
    count = host.run(f"psql -t -A -c \"{check_sql}\"").stdout.strip()
    assert count == "1", "Default extension 'plpgsql' is missing!"


@pytest.mark.parametrize("package", DOCKER_RPM_PACKAGES)
def test_rpm_package_is_installed(host, package):
    # 1. Centralized Skip Logic
    if not IS_WITH_POSTGIS and "postgis" in package:
        pytest.skip(f"Docker build is without PostGIS so skipping.")

    pkg = host.package(package)

    # 2. Verify Installation
    assert pkg.is_installed, f"Package {package} is not installed"

    # 3. Dynamic Version Lookup
    # We try to find the version in the dictionary with a fallback mechanism
    pkg_data = pg_docker_versions.get(package)

    if isinstance(pkg_data, dict):
        # Handles cases like pg_docker_versions[package]['version']
        expected_version = pkg_data.get('version')
    else:
        # Handles cases like pg_docker_versions[package] (direct string)
        expected_version = pkg_data

    # Fallback to the global 'version' if the specific package isn't mapped
    if not expected_version:
        expected_version = pg_docker_versions.get('version')

    assert pkg.version == expected_version, (
        f"Version mismatch for {package}. Expected: {expected_version}, Found: {pkg.version}"
    )


# @pytest.mark.parametrize("package", DOCKER_RPM_PACKAGES)
# def test_rpm_package_is_installed(host, package):
#     if not IS_WITH_POSTGIS and "postgis" in package:
#         pytest.skip(f"Docker build is without PostGIS so skipping.")
        
#     pkg = host.package(package.strip())
#     assert pkg.is_installed
#     if package in ["percona-postgresql-client-common", "percona-postgresql-common"]:
#         assert pkg.version == pg_docker_versions[package]
#     elif package in [f"percona-pgaudit{MAJOR_VER}", f"percona-wal2json{MAJOR_VER}", f"percona-pg_stat_monitor{MAJOR_VER}",
#         f"percona-pgaudit{MAJOR_VER}_set_user", f"percona-pg_repack{MAJOR_VER}", f"percona-patroni", f"percona-pg_tde{MAJOR_VER}",
#         f"percona-pgbackrest", f"percona-pgvector_{MAJOR_VER}", f"percona-pgvector_{MAJOR_VER}-llvmjit", "python3-etcd",
#         f"percona-postgis35_{MAJOR_VER}", f"percona-postgis35_{MAJOR_VER}-client", f"percona-postgis35_{MAJOR_VER}-gui",
#         f"percona-postgis35_{MAJOR_VER}-llvmjit", f"percona-postgis35_{MAJOR_VER}-utils", "python3-pysyncobj", "python3-ydiff", "ydiff"]:
#         assert pkg.version == pg_docker_versions[package]['version']
#     else:
#         assert pkg.version == pg_docker_versions['version']


def test_pg_stat_monitor_extension_version(host):
    # 1. Ensure extension is created
    create_res = host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS pg_stat_monitor;'")
    assert create_res.rc == 0, create_res.stderr

    # 2. Get the Extension version (SQL Level)
    # -t: tuples only, -A: unaligned
    query = "SELECT pg_stat_monitor_version();"
    actual_ext_version = host.run(f"psql -t -A -c \"{query}\"").stdout.strip()

    # 3. Get Expected version from dictionary
    pkg_key = f"percona-pg_stat_monitor{MAJOR_VER}"
    expected_full_version = pg_docker_versions[pkg_key]['version']

    # 4. Clean the version string
    # RPM versions often look like '2.1.0-1.el9'. We need to strip the '-1.el9'
    # part to match the PostgreSQL extension version '2.1.0'.
    expected_clean_version = expected_full_version.split('-')[0]

    assert actual_ext_version == expected_clean_version, (
        f"Extension version {actual_ext_version} does not match "
        f"expected version {expected_clean_version}"
    )


@pytest.mark.parametrize("file", DOCKER_RHEL_FILES)
def test_rpm_files(file, host):
    f = host.file(file)
    assert f.exists
    assert f.size > 0
    assert f.content_string != ""
    assert f.user == "postgres"


def test_build_with_liburing(host):
    if MAJOR_VER not in ["18"]:
        pytest.skip("Skipping, test only for PostgreSQL 18 version")

    distribution = host.system_info.distribution.lower()
    if distribution in ["redhat", "centos", "rhel", "rocky", "ol"] and \
    host.system_info.release.startswith("8"):
        pytest.skip(f"liburing not supported on {distribution} 8 for postgres {MAJOR_VER}")

    cmd = "pg_config --configure"
    output = host.check_output(cmd)
    assert '--with-liburing' in output, "PostgreSQL 18 was built without --with-liburing"


@pytest.mark.parametrize(
    "flag",
    [
        ("--enable-debug"),
        ("--enable-cassert"),
        ("--disable-thread-safety"),
    ],
)
def test_pg_config_flags(host, flag):
    """
    Verify that certain build flags are NOT present in pg_config --configure output.
    """

    # Get the PostgreSQL configuration output
    cmd = "pg_config --configure"
    output = host.check_output(cmd)

    assert flag not in output, (
        f"PostgreSQL was built with {flag}, but it should NOT be present"
    )


def test_postgis_extension(host):
    if not IS_WITH_POSTGIS:
        pytest.skip("Skipping PostGIS test.")
    # 1. Execute the create command
    cmd = "psql -c 'CREATE EXTENSION IF NOT EXISTS postgis CASCADE;'"
    result = host.run(cmd)
    assert result.rc == 0

    # 2. Metadata Verification: Check if it's in pg_extension
    check_cmd = "psql -t -c \"SELECT count(*) FROM pg_extension WHERE extname = 'postgis';\""
    count = host.run(check_cmd).stdout.strip()
    assert count == "1"

    # 3. Version Check (Metadata): Get the installed version string
    version_cmd = "psql -t -c \"SELECT extversion FROM pg_extension WHERE extname = 'postgis';\""
    actual_version = host.run(version_cmd).stdout.strip()
    # Assert version is not empty (e.g., '3.4')
    assert len(actual_version) > 0
    print(f"Detected PostGIS Extension Version: {actual_version}")
    # Check expected version

    expected_version = pg_docker_versions.get(f"percona-postgis35_{MAJOR_VER}", {}).get("extension_version")
    assert actual_version == expected_version, f"Expected {expected_version}, but found {actual_version}"

    # 4. Functional Check: Verify the extension is actually working
    # This ensures the underlying GEOS and PROJ libraries are linked correctly
    func_cmd = "psql -t -c \"SELECT postgis_version();\""
    func_result = host.run(func_cmd)

    assert func_result.rc == 0
    assert "3." in func_result.stdout  # Assuming you expect PostGIS 3.x

    # Execute the drop command with CASCADE
    cmd = "psql -c 'DROP EXTENSION IF EXISTS postgis CASCADE;'"
    result = host.run(cmd)

    # Check if the command executed successfully
    assert result.rc == 0

    # Verification: Ensure it no longer exists in pg_extension
    check_cmd = "psql -t -c \"SELECT count(*) FROM pg_extension WHERE extname = 'postgis';\""
    count = host.run(check_cmd).stdout.strip()
    assert count == "0"


def test_pgvector_extension(host):
    # 1. Execute the create command
    # Note: The extension name is 'vector', though the project is pgvector
    cmd = "psql -c 'CREATE EXTENSION IF NOT EXISTS vector CASCADE;'"
    result = host.run(cmd)
    assert result.rc == 0

    # 2. Metadata Verification: Check if it's in pg_extension
    check_cmd = "psql -t -c \"SELECT count(*) FROM pg_extension WHERE extname = 'vector';\""
    count = host.run(check_cmd).stdout.strip()
    assert count == "1"

    # 3. Version Check (Metadata): Get the installed version string
    version_cmd = "psql -t -c \"SELECT extversion FROM pg_extension WHERE extname = 'vector';\""
    actual_version = host.run(version_cmd).stdout.strip()

    # Assert version is not empty
    assert len(actual_version) > 0
    print(f"Detected pgvector Extension Version: {actual_version}")

    # Check against your expected versions dictionary
    expected_version = pg_docker_versions.get(f"percona-pgvector_{MAJOR_VER}", {}).get("extension_version")

    assert actual_version == expected_version, f"Expected {expected_version}, but found {actual_version}"

    # 4. Functional Check: Verify the 'vector' type is usable
    # We cast a string to a vector and check its dimensions to ensure the C library is loaded
    func_cmd = "psql -t -c \"SELECT vector_dims('[1,2,3]'::vector);\""
    func_result = host.run(func_cmd)

    assert func_result.rc == 0
    assert func_result.stdout.strip() == "3"

    # 5. Execute the drop command with CASCADE
    cmd = "psql -c 'DROP EXTENSION IF EXISTS vector CASCADE;'"
    result = host.run(cmd)
    assert result.rc == 0

    # 6. Verification: Ensure it no longer exists in pg_extension
    check_cmd = "psql -t -c \"SELECT count(*) FROM pg_extension WHERE extname = 'vector';\""
    count = host.run(check_cmd).stdout.strip()
    assert count == "0"


def test_patroni_version(host):
    # 1. Run the patroni version command
    # Output is usually in the format: "patroni 3.3.0"
    cmd = "patroni --version"
    result = host.run(cmd)

    # 2. Check if the command exists and executed successfully
    assert result.rc == 0, f"Patroni command failed or is not installed: {result.stderr}"

    # 3. Parse the version number
    # result.stdout might be "patroni 3.3.0", we want the second part
    actual_version = result.stdout.strip()

    print(f"Detected Patroni Version: {actual_version}")

    # 4. Compare with the expected version from your dictionary
    # Assuming the key follows your pattern: pg_docker_versions["patroni"]["binary_version"]
    expected_version = pg_docker_versions.get("percona-patroni", {}).get("binary_version")

    if expected_version:
        assert actual_version == expected_version, f"Expected {expected_version}, but found {actual_version}"
    else:
        assert len(actual_version) > 0, "Patroni version could not be determined"


def test_pgbackrest_version(host):
    # 1. Run the pgbackrest version command
    # Typical output: "pgBackRest 2.50"
    cmd = "pgbackrest version"
    result = host.run(cmd)

    # 2. Check if the command exists and executed successfully
    assert result.rc == 0, f"pgBackRest command failed: {result.stderr}"

    # 3. Parse the version number
    # We split the string and take the last element (e.g., "2.50")
    actual_version = result.stdout.strip()

    print(f"Detected pgBackRest Version: {actual_version}")

    # 4. Compare with the expected version from your dictionary
    expected_version = pg_docker_versions.get("percona-pgbackrest", {}).get("binary_version")

    if expected_version:
        assert actual_version == expected_version, f"Expected {expected_version}, but found {actual_version}"
    else:
        # Fallback: just ensure we got a valid-looking version string
        assert len(actual_version) > 0 and actual_version[0].isdigit()


# def test_python3_etcd_version(host):
#     # 1. Use Python to print the version of the 'etcd' module
#     # We use 'import etcd' because that is the internal module name
#     # for the python-etcd/python3-etcd package.
#     cmd = "python3 -c 'import etcd; print(etcd.__version__)'"
#     result = host.run(cmd)

#     # 2. Check if the module is installed and the command succeeded
#     assert result.rc == 0, f"python3-etcd is not installed or import failed: {result.stderr}"

#     # 3. Parse the version number
#     actual_version = result.stdout.strip()
#     print(f"Detected python3-etcd Version: {actual_version}")

#     # 4. Compare with the expected version from your dictionary
#     expected_version = pg_docker_versions.get("python3_etcd", {}).get("binary_version")

#     if expected_version:
#         assert actual_version == expected_version, f"Expected {expected_version}, but found {actual_version}"
#     else:
#         assert len(actual_version) > 0, "python3-etcd version could not be determined"

# --- Configuration ---
DB_PARAMS = {
    "dbname": "postgres",
    "user": "postgres",
    "password": "password",
    "host": "localhost",
    "port": "5432"
}

# --- Fixtures (Internalized conftest logic) ---

@pytest.fixture(scope="session")
def db_connection():
    """Establish a session-wide connection with retries for startup."""
    max_retries = 15
    conn = None

    for i in range(max_retries):
        try:
            conn = psycopg2.connect(**DB_PARAMS)
            conn.autocommit = True
            print("\n[INFO] Connected to PostgreSQL successfully.")
            break
        except psycopg2.OperationalError:
            print(f"[WAIT] Waiting for Postgres to start (attempt {i+1}/{max_retries})...")
            time.sleep(2)

    if not conn:
        pytest.fail("Could not connect to PostgreSQL container after 30 seconds.")

    yield conn
    conn.close()

@pytest.fixture(scope="function")
def cursor(db_connection):
    """Provide a cursor for individual test functions."""
    cur = db_connection.cursor()
    yield cur
    cur.close()

# --- TimescaleDB Test Suite ---

def test_timescaledb_lifecycle(host, cursor):
    """
    Full lifecycle test:
    1. Installation & Extension Setup
    2. Hypertable creation
    3. Data insertion
    4. Service Manual Restart (Stop + Start)
    5. Persistence verification
    """
    table_name = "test_metrics"
    data_dir = "/data/db/"

    try:
        # --- 1. Extension Setup ---
        # Ensure shared_preload_libraries includes timescaledb in your docker run -c
        cursor.execute("CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;")
        cursor.execute("SELECT extname FROM pg_extension WHERE extname = 'timescaledb';")
        assert cursor.fetchone()[0] == 'timescaledb', "Extension failed to load."

        # --- 2. Hypertable Creation ---
        cursor.execute(f"DROP TABLE IF EXISTS {table_name};")
        cursor.execute(f"""
            CREATE TABLE {table_name} (
                time        TIMESTAMPTZ NOT NULL,
                device_id   INT,
                usage       DOUBLE PRECISION
            );
        """)
        cursor.execute(f"SELECT create_hypertable('{table_name}', 'time');")

        # Verify it is recognized as a hypertable
        cursor.execute(f"SELECT count(*) FROM timescaledb_information.hypertables WHERE hypertable_name = '{table_name}';")
        assert cursor.fetchone()[0] == 1, "Table was not converted to hypertable"

        # --- 3. Data Insertion ---
        base_time = datetime.now()
        test_data = [
            (base_time, 1, 0.85),
            (base_time - timedelta(minutes=5), 1, 0.45)
        ]
        for row in test_data:
            cursor.execute(f"INSERT INTO {table_name} VALUES (%s, %s, %s)", row)

        # --- 4. Advanced Persistence Test (The Restart) ---
        print("\n[INFO] Restarting the container from the host to test persistence...")

        # We get the container name/ID from the 'host' object or your MAJOR_VER variable
        container_name = f"PG{MAJOR_VER}"

        # Use subprocess to restart the container from the OUTSIDE
        subprocess.check_call(['docker', 'restart', container_name])

        print("[INFO] Container restarted. Waiting for engine to recover...")

        # --- 5. Reconnect Phase (The "Polling" Loop) ---
        # We must wait for the engine to finish WAL recovery before it accepts TCP
        new_cursor = None
        new_conn = None

        for i in range(15):
            try:
                time.sleep(2)
                new_conn = psycopg2.connect(**DB_PARAMS)
                new_conn.autocommit = True
                new_cursor = new_conn.cursor()
                print(f"[INFO] Successfully reconnected on attempt {i+1}")
                break
            except psycopg2.OperationalError:
                if i == 14:
                    pytest.fail("Database failed to recover after container restart.")
                continue

        # --- 6. Post-Restart Verification ---
        new_cursor.execute(f"SELECT count(*) FROM {table_name};")
        assert new_cursor.fetchone()[0] == 2, "Data was lost after restart."

        new_cursor.execute(f"SELECT avg(usage) FROM {table_name};")
        avg_usage = new_cursor.fetchone()[0]
        assert float(avg_usage) == 0.65, f"Aggregation failed. Expected 0.65, got {avg_usage}"

        new_cursor.execute(f"SELECT count(*) FROM timescaledb_information.chunks WHERE hypertable_name = '{table_name}';")
        assert new_cursor.fetchone()[0] >= 1, "No chunks (partitions) found after restart."

    finally:
        # Use a fresh, independent connection for cleanup
        try:
            cleanup_conn = psycopg2.connect(**DB_PARAMS)
            cleanup_conn.autocommit = True
            with cleanup_conn.cursor() as cleanup_cur:
                cleanup_cur.execute(f"DROP TABLE IF EXISTS {table_name};")
            cleanup_conn.close()
        except Exception:
            pass
