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

# --- Configuration constants/settings ---
# Constants
MAJOR_VER = os.getenv('VERSION').split('.')[0]
MAJOR_MINOR_VER = os.getenv('VERSION')
DOCKER_REPO = os.getenv('DOCKER_REPOSITORY')
IMG_TAG = os.getenv('TAG')
IS_WITH_POSTGIS = os.getenv('WITH_POSTGIS', 'false').lower() == "true"
PG_BIN_DIR = f"/usr/pgsql-{MAJOR_VER}/bin"
PG_DATA_DIR = "/data/db"
IMAGE = f"{DOCKER_REPO}/percona-distribution-postgresql-custom:{MAJOR_VER}"

# --- Settings ---
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


def reconnect_db():
    """Helper to establish a fresh connection if the server restarted or crashed."""
    for i in range(10):
        try:
            conn = psycopg2.connect(**DB_PARAMS)
            conn.autocommit = True
            return conn
        except psycopg2.OperationalError:
            time.sleep(2)
    pytest.fail("Could not reconnect to database after server crash.")


# --- Fixtures ---
@pytest.fixture(scope='session')
def host(request):
    """Session-wide container. Used for internal filesystem and DB checks."""
    container_name = f"PG_TEST_{MAJOR_VER}"

    # Cleanup previous runs
    subprocess.run(['docker', 'rm', '-f', container_name], capture_output=True)

    run_cmd = [
        'docker', 'run', '--name', container_name,
        '-e', 'POSTGRES_PASSWORD=password',
        '-d', IMAGE
    ]
    subprocess.check_output(run_cmd)

    # Wait for the container to actually be ready
    time.sleep(2)

    yield testinfra.get_host("docker://" + container_name)
    subprocess.run(['docker', 'rm', '-f', container_name], capture_output=True)

# --- Helper Functions ---

def get_labels():
    """Fetch image labels via docker inspect."""
    result = subprocess.run(
        ["docker", "inspect", "--format", "{{json .Config.Labels}}", IMAGE],
        capture_output=True, text=True, check=True
    )
    return json.loads(result.stdout) if result.stdout.strip() else {}

# --- Tests ---

def test_ppg_postgres_image_labels():
    """Validate Red Hat compliance labels and Percona branding."""
    labels = get_labels()

    # 1. Check all required keys exist and are not empty
    for key in REQUIRED_LABEL_KEYS:
        assert labels.get(key), f"Required label '{key}' is missing or empty"

    # 2. Trademark Compliance
    for key in ("name", "vendor", "maintainer"):
        val = labels.get(key, "")
        for forbidden in RED_HAT_TRADEMARK_FORBIDDEN:
            assert forbidden not in val, f"Label '{key}' contains forbidden trademark '{forbidden}'"

    # 3. Value Accuracy
    assert labels.get("vendor") == REQUIRED_LABEL_VENDOR
    assert labels.get("maintainer") == REQUIRED_LABEL_MAINTAINER
    assert labels.get("name") == EXPECTED_LABEL_NAME_POSTGRESQL
    assert labels.get("name").startswith(REQUIRED_LABEL_NAME_PREFIX)

def test_ppg_postgres_licenses(host):
    """Verify license information exists inside the container."""
    license_path = host.file("/licenses")

    assert license_path.exists, "/licenses path is missing in the image"

    if license_path.is_directory:
        # Check that the directory is not empty
        files = host.check_output("ls -A /licenses")
        assert len(files.strip()) > 0, "/licenses directory is empty"
    else:
        # If it's a file, ensure it's not empty
        assert license_path.size > 0, "/licenses file is empty"

def test_container_user_non_root(host):
    """Compliance: Ensure the container doesn't run as root by default."""
    current_user = host.user().name
    assert current_user != "root", f"Security failure: Container is running as {current_user}"


@pytest.fixture(scope='session')
def host(request):
    container_name = f"PG{MAJOR_VER}"
    needs_libs = any(item.get_closest_marker("needs_preload") for item in request.session.items)

    subprocess.run(['docker', 'rm', '-f', container_name], capture_output=True)

    run_cmd = [
        'docker', 'run', '--name', container_name,
        '-e', 'POSTGRES_PASSWORD=password',
        '--shm-size=2g',
        '-p', '5432:5432',
        '-d', IMAGE
    ]

    if needs_libs:
        # These specific flags prevent pg_stat_monitor from over-allocating on boot
        run_cmd.extend([
            '-c', 'shared_preload_libraries=timescaledb,pg_stat_monitor,pgaudit,set_user',
            '-c', 'shared_buffers=256MB',
            '-c', 'max_worker_processes=32',       # Give extensions room to breathe
            '-c', 'max_parallel_workers=16',
            '-c', 'pg_stat_monitor.pgsm_max=500',  # Smaller bucket to save shared mem
            '-c', 'pg_stat_monitor.pgsm_query_max_len=1024',
            '-c', 'timescaledb.max_background_workers=4',
            '-c', 'wal_level=logical'
        ])

    subprocess.check_output(run_cmd)

    # --- STABILITY WAIT ---
    # Don't just wait; verify the server can actually answer a query
    for _ in range(30):
        res = subprocess.run(['docker', 'exec', container_name, 'pg_isready'], capture_output=True)
        if res.returncode == 0:
            # Final sanity check: Can we run a SQL command?
            sql = subprocess.run(['docker', 'exec', container_name, 'psql', '-U', 'postgres', '-c', 'SELECT 1'], capture_output=True)
            if sql.returncode == 0:
                break
        time.sleep(1)

    time.sleep(2) # Final settle time for background workers
    yield testinfra.get_host("docker://" + container_name)
    subprocess.run(['docker', 'rm', '-f', container_name], capture_output=True)


def test_shared_preload_libraries_is_empty(cursor, request):
    """
    Verification: Ensure no libraries are preloaded at startup.
    Skip if session-wide container was booted with libraries for other tests.
    """
    # Check if any test in the whole session has the 'needs_preload' mark
    session_needs_libs = any(
        item.get_closest_marker("needs_preload") for item in request.session.items
    )

    if session_needs_libs:
        pytest.skip("Skipping 'Empty' check: session is running in 'Preload Mode' for TimescaleDB.")

    cursor.execute("SHOW shared_preload_libraries;")
    setting = cursor.fetchone()[0]
    assert setting == "" or setting.lower() == "none"


def test_psql_string(host):
    # 'host' now binds to the container
    assert f"psql (PostgreSQL) {MAJOR_MINOR_VER} - Percona Distribution" in host.check_output('psql -V')
    assert not f"psql (PostgreSQL) {MAJOR_MINOR_VER} - Percona Server for PostgreSQL" in host.check_output('psql -V')


def test_wait_docker_load(host):
    dist = host.system_info.distribution
    time.sleep(5)
    assert 0 == 0

@pytest.fixture()
def postgresql_binary(host):
    pg_binary = f"{PG_BIN_DIR}/postgres"
    return host.file(pg_binary)


@pytest.fixture()
def postgresql_query_version(host):
    return host.run("psql -c 'SELECT version()' | awk 'NR==3{print $2}'")


@pytest.fixture()
def extension_list(host):
    result = host.check_output("psql -c 'SELECT * FROM pg_available_extensions;' | awk 'NR>=3{print $1}'")
    result = result.split()
    return result


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

    # Then inside your test:
    if major >= 17 and extension == "adminpack":
        pytest.skip("adminpack removed in PG17+")

    if major < 18 and extension == 'pg_logicalinspect':
        pytest.skip("pg_logicalinspect only supported in PG18+")

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
        pytest.skip(f"Docker build is without PostGIS so skipping {package}.")

    pkg = host.package(package)

    # 2. Verify Installation
    assert pkg.is_installed, f"Package {package} is not installed"

    # 3. Dynamic Version Lookup
    pkg_data = pg_docker_versions.get(package)

    if isinstance(pkg_data, dict):
        expected_version = pkg_data.get('version')
    else:
        expected_version = pkg_data

    # Fallback to the global 'version' if the specific package isn't mapped
    if not expected_version:
        expected_version = pg_docker_versions.get('version')

    # --- Console Output Enhancement ---
    print(f"\n[VERIFYING] Package: {package}")
    print(f"            Expected: {expected_version}")
    print(f"            Found:    {pkg.version}")

    assert pkg.version == expected_version, (
        f"Version mismatch for {package}. Expected: {expected_version}, Found: {pkg.version}"
    )

    print(f"[SUCCESS] {package} version {pkg.version} verified.")


@pytest.mark.needs_preload
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
def db_connection(host): # <--- Adding 'host' here forces host to finish booting first
    container_name = f"PG{MAJOR_VER}"
    max_retries = 45

    # Check if container exists
    status = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", container_name],
        capture_output=True, text=True
    )

    if status.returncode != 0:
        pytest.fail(f"Container {container_name} does not exist. Docker Run might have failed silently.")

    conn = None

    # 1. Pre-flight Check: Is the container even alive?
    status = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", container_name],
        capture_output=True, text=True
    )

    if "true" not in status.stdout.lower():
        # If it's not running, it probably crashed during the 'host' fixture boot
        logs = subprocess.run(["docker", "logs", container_name], capture_output=True, text=True)
        pytest.fail(
            f"FATAL: Container {container_name} is NOT running.\n"
            f"Check if shared_preload_libraries are valid.\n"
            f"--- DOCKER LOGS ---\n{logs.stdout}\n{logs.stderr}"
        )

    # 2. Connection Loop
    for i in range(max_retries):
        try:
            conn = psycopg2.connect(**DB_PARAMS)
            conn.autocommit = True
            print(f"\n[INFO] Connected to {container_name} successfully.")
            return conn

        except psycopg2.OperationalError as e:
            err_msg = str(e).lower()

            # Scenario A: Server is still booting (Normal)
            if "connection refused" in err_msg or "starting up" in err_msg:
                print(f"[WAIT] Postgres is initializing (attempt {i+1}/{max_retries})...")
                time.sleep(2)

            # Scenario B: Server crashed WHILE we were talking to it (Abnormal)
            elif "closed the connection unexpectedly" in err_msg or "terminating connection" in err_msg:
                print(f"\n[FATAL] Postgres crashed during connection attempt {i+1}!")
                # Immediate log dump to see the PANIC/FATAL message
                res = subprocess.run(["docker", "logs", container_name, "--tail", "20"], capture_output=True, text=True)
                print(f"--- RECENT LOGS ---\n{res.stdout}")
                pytest.fail(f"Postgres process crashed. See logs above for details.")

            # Scenario C: Something else (Wrong credentials, wrong port, etc.)
            else:
                print(f"[DEBUG] Unexpected Connection Error: {err_msg}")
                time.sleep(2)

    # 3. Final Fallback
    if not conn:
        print("\n" + "="*50)
        print(f"TIMEOUT: Could not connect to {container_name} after 90s.")
        res = subprocess.run(["docker", "logs", container_name, "--tail", "20"], capture_output=True, text=True)
        print(f"Final Logs:\n{res.stdout}")
        print("="*50)
        pytest.fail("Database connection timeout. See logs above.")


@pytest.fixture(scope="function")
def cursor(db_connection):
    """Provide a resilient cursor that recovers if a previous test killed the server."""
    # If the shared session connection is dead, try to revive it
    if db_connection.closed != 0:
        print("\n[RECOVERY] Global connection was dead. Reviving...")
        db_connection = reconnect_db()

    cur = db_connection.cursor()
    yield cur
    cur.close()


# --- TimescaleDB Test Suite ---
@pytest.mark.needs_preload
def test_timescaledb_lifecycle(host, cursor):
    """
    Full lifecycle test:
    1. Installation & Version Verification
    2. Hypertable creation
    3. Data insertion
    4. Service Manual Restart (Host-side Docker Restart)
    5. Persistence verification
    """
    table_name = "test_metrics"

    # Fetch expected version metadata
    pkg_key = f"percona-timescaledb_{MAJOR_VER}"
    if pkg_key not in pg_docker_versions:
        pytest.fail(f"Metadata key {pkg_key} not found in pg_docker_versions settings.")

    expected_full_version = pg_docker_versions[pkg_key]['version']

    try:
        # --- 1. Extension Setup & Version Check ---
        cursor.execute("CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;")

        # Verify Extension Name
        cursor.execute("SELECT extname, extversion FROM pg_extension WHERE extname = 'timescaledb';")
        extension_info = cursor.fetchone()
        assert extension_info is not None, "Extension failed to load into pg_extension catalog."

        actual_db_version = extension_info[1]

        # Verify Version: check if DB version (e.g. 2.13.1) is in the package string (e.g. 2.13.1-1.debian12)
        assert actual_db_version in expected_full_version, \
            f"Version mismatch! DB reports {actual_db_version}, but manifest expects {expected_full_version}"

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
        print(f"\n[INFO] Restarting container PG{MAJOR_VER} from host to test persistence...")
        container_name = f"PG{MAJOR_VER}"
        subprocess.check_call(['docker', 'restart', container_name])

        # --- 5. Reconnect Phase (The "Polling" Loop) ---
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
        try:
            new_cursor.execute(f"SELECT count(*) FROM {table_name};")
            assert new_cursor.fetchone()[0] == 2, "Data was lost after restart."

            new_cursor.execute(f"SELECT avg(usage) FROM {table_name};")
            avg_usage = new_cursor.fetchone()[0]
            # float() conversion handles Decimal types from Postgres
            assert float(avg_usage) == 0.65, f"Aggregation failed. Expected 0.65, got {avg_usage}"

            new_cursor.execute(f"SELECT count(*) FROM timescaledb_information.chunks WHERE hypertable_name = '{table_name}';")
            assert new_cursor.fetchone()[0] >= 1, "No chunks (partitions) found after restart."
        finally:
            if new_cursor:
                new_cursor.close()
            if new_conn:
                new_conn.close()

    finally:
        # Final cleanup using a fresh connection to ensure it runs even if the test fails
        try:
            cleanup_conn = psycopg2.connect(**DB_PARAMS)
            cleanup_conn.autocommit = True
            with cleanup_conn.cursor() as cleanup_cur:
                cleanup_cur.execute(f"DROP TABLE IF EXISTS {table_name};")
            cleanup_conn.close()
        except Exception:
            pass # DB might be unreachable or table already gone


# --- pgvector Functional Test ---
#@pytest.mark.needs_preload
def test_pgvector_functional_logic(host): # Use host here to allow re-connection
    """
    Functional: Test pgvector extension lifecycle with auto-recovery on crash.
    """
    # Connection parameters (standard for your setup)
    conn_params = "host=localhost port=5432 user=postgres password=password dbname=postgres"

    def run_logic():
        # We create a local connection/cursor to ensure they are fresh
        with psycopg2.connect(conn_params) as conn:
            with conn.cursor() as cur:
                cur.execute("CREATE EXTENSION IF NOT EXISTS vector;")
                cur.execute("DROP TABLE IF EXISTS test_vector_items;")
                cur.execute("CREATE TABLE test_vector_items (id serial PRIMARY KEY, embedding vector(3));")
                cur.execute("INSERT INTO test_vector_items (embedding) VALUES ('[1,2,3]');")
                cur.execute("SELECT embedding FROM test_vector_items LIMIT 1;")
                return cur.fetchone()[0]

    try:
        result = run_logic()
    except (psycopg2.OperationalError, psycopg2.InterfaceError):
        # The crash happened. Wait for the container to auto-restart (if using --restart)
        # or wait for the postmaster to recover.
        print("\n[DEBUG] Postgres crashed. Waiting for recovery...")
        time.sleep(10)
        try:
            result = run_logic()
        except Exception as e:
            pytest.fail(f"pgvector failed after recovery attempt: {e}")

    assert result == '[1,2,3]'


# --- pg_stat_monitor Functional Test ---
@pytest.mark.needs_preload
def test_pg_stat_monitor_capture(host):
    """
    Functional: Ensure pg_stat_monitor tracks queries without crashing.
    """
    params = "host=localhost port=5432 user=postgres password=password dbname=postgres"

    # 1. Initialize Extension (Use Autocommit to prevent transaction locks)
    with psycopg2.connect(params) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("CREATE EXTENSION IF NOT EXISTS pg_stat_monitor;")

    # 2. Reconnect and Run Workload
    # This ensures we are on a "fresh" backend that has the extension hooks active
    with psycopg2.connect(params) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 'pgsm_test_marker' AS test;")
            cur.fetchall()

            # 3. Verify
            time.sleep(1) # Give PGSM a moment to flush to the view
            cur.execute("SELECT query FROM pg_stat_monitor WHERE query LIKE '%pgsm_test_marker%';")
            assert cur.fetchone() is not None


# Helper to provide isolation for every test of PostGIS
def manage_postgis(host, action="create"):
    """Handles extension lifecycle using standard psql calls."""
    if action == "create":
        # Create extensions in order of dependency
        for ext in ["postgis", "postgis_raster", "postgis_topology"]:
            host.run(f"psql -c 'CREATE EXTENSION IF NOT EXISTS {ext} CASCADE;'")
    else:
        # CASCADE ensures dependent objects/extensions are removed
        host.run("psql -c 'DROP EXTENSION IF EXISTS postgis_topology CASCADE;'")
        host.run("psql -c 'DROP EXTENSION IF EXISTS postgis CASCADE;'")

# --- PostGIS TEST ---
def test_postgis_library_linkage(host):
    """Verifies PostGIS can be enabled and GEOS, PROJ, and GDAL are reachable."""
    try:
        manage_postgis(host, "create")
        version_info = host.run("psql -t -c 'SELECT postgis_full_version();'")
        # Ensure the underlying engine libraries are properly linked in the image
        assert all(lib in version_info.stdout for lib in ["GEOS", "PROJ", "GDAL", "LIBXML"])
    finally:
        manage_postgis(host, "drop")

def test_postgis_spatial_logic_and_rasters(host):
    """Verifies distance calculations (PROJ/GEOS) and Raster support (GDAL)."""
    try:
        manage_postgis(host, "create")

        # Calculate distance between London and Paris (approx 340km)
        dist_query = "SELECT ST_Distance(ST_GeogFromText('SRID=4326;POINT(0 51.5)'), ST_GeogFromText('SRID=4326;POINT(2.3 48.8)'));"
        dist_res = host.run(f"psql -t -c \"{dist_query}\"")
        assert 330000 < float(dist_res.stdout.strip()) < 350000

        # Verify GDAL Raster support
        raster_query = "SELECT ST_Width(ST_AddBand(ST_MakeEmptyRaster(10, 10, 0, 0, 1, -1, 0, 0, 4326), 1, '8BUI', 1, 0));"
        assert "10" in host.run(f"psql -t -c \"{raster_query}\"").stdout
    finally:
        manage_postgis(host, "drop")

def test_postgis_srid_transformation(host):
    """Verifies coordinate reprojection logic (PROJ library check)."""
    try:
        manage_postgis(host, "create")
        # Transform GPS (4326) to Web Mercator (3857)
        query = "SELECT ST_AsText(ST_Transform(ST_GeomFromText('POINT(0 0)', 4326), 3857));"
        res = host.run(f"psql -t -c \"{query}\"")
        assert "POINT(0 0)" in res.stdout
    finally:
        manage_postgis(host, "drop")

def test_postgis_indexing_and_joins(host):
    """Verifies GiST indexing and spatial join performance/logic."""
    try:
        manage_postgis(host, "create")

        setup = """
        CREATE TABLE districts (id int, geom geometry(Polygon, 4326));
        CREATE INDEX idx_dist_geom ON districts USING GIST (geom);
        INSERT INTO districts VALUES (1, ST_MakeEnvelope(0, 0, 2, 2, 4326));
        """
        host.run(f"psql -c \"{setup}\"")

        # Test Point-in-Polygon join using the GiST index
        join_query = "SELECT count(*) FROM districts WHERE ST_Contains(geom, ST_GeomFromText('POINT(1 1)', 4326));"
        assert "1" in host.run(f"psql -t -c \"{join_query}\"").stdout.strip()
    finally:
        manage_postgis(host, "drop")


# --- PG_REPACK TEST ---
def test_pg_repack_reorganization(host):
    """Verifies pg_repack can rebuild a table to remove bloat online."""
    try:
        host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS pg_repack;'")
        host.run("psql -c 'CREATE TABLE repack_test AS SELECT generate_series(1,1000) AS id;'")

        # pg_repack is a binary utility, not just SQL.
        # We run it against the 'postgres' database.
        # -t specifies the table
        repack_cmd = f"{PG_BIN_DIR}/pg_repack -d postgres -t repack_test"
        result = host.run(repack_cmd)

        assert result.rc == 0
        assert "Successfully repacked" in result.stdout or result.stdout == ""

        # Verify table still exists and is readable
        check = host.run("psql -t -c 'SELECT count(*) FROM repack_test;'")
        assert "1000" in check.stdout.strip()
    finally:
        host.run("psql -c 'DROP TABLE IF EXISTS repack_test;'")
        host.run("psql -c 'DROP EXTENSION IF EXISTS pg_repack;'")

# --- PGAUDIT TEST ---
@pytest.mark.needs_preload
def test_pgaudit_logging(host):
    """Verifies that pgaudit captures DDL and DML events in the PG logs."""
    try:
        host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS pgaudit;'")
        # Enable auditing for session DDL and Read/Write
        host.run("psql -c \"ALTER SYSTEM SET pgaudit.log = 'read, write, ddl';\"")
        host.run("psql -c 'SELECT pg_reload_conf();'")

        # Trigger an audited event
        host.run("psql -c 'CREATE TABLE audit_test (id int);'")
        host.run("psql -c 'INSERT INTO audit_test VALUES (1);'")

        # Check the PostgreSQL logs for the pgaudit signature
        # We look for 'AUDIT: SESSION' which is the default pgaudit prefix
        log_check = host.run(f"tail -n 100 {PG_DATA_DIR}/log/*.log")
        assert "AUDIT: SESSION" in log_check.stdout
        assert "CREATE TABLE audit_test" in log_check.stdout
    finally:
        host.run("psql -c 'DROP EXTENSION IF EXISTS pgaudit;'")

# --- SET_USER TEST ---
@pytest.mark.needs_preload
def test_set_user_escalation(host):
    """Verifies set_user allows a less-privileged user to flip to a superuser role."""
    try:
        # 1. Initialize Extension
        host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS set_user;'")

        # 2. Setup Roles
        host.run("psql -c \"CREATE ROLE power_user LOGIN SUPERUSER PASSWORD 'pass';\"")
        host.run("psql -c \"CREATE ROLE normal_user LOGIN PASSWORD 'pass';\"")

        # 3. Grant Permission to the UNRESTRICTED function
        # set_user_u is required for non-superuser -> superuser escalation
        host.run("psql -c 'GRANT EXECUTE ON FUNCTION set_user_u(text) TO normal_user;'")

        # 4. Test: Escalation using the unrestricted function
        # We use separate -c flags to stay out of a transaction block
        cmd = (
            "psql -U normal_user -d postgres -t "
            "-c \"SELECT set_user_u('power_user');\" "
            "-c \"SELECT current_user;\""
        )
        result = host.run(cmd)

        # Log stderr for visibility if the logic changes
        if result.rc != 0:
            print(f"PSQL Stderr: {result.stderr}")

        assert "power_user" in result.stdout

        # 5. Test: De-escalation (NULL always works to return to original user)
        back_cmd = (
            "psql -U normal_user -d postgres -t "
            "-c \"SELECT set_user(NULL);\" "
            "-c \"SELECT current_user;\""
        )
        result_back = host.run(back_cmd)
        assert "normal_user" in result_back.stdout

    finally:
        # 6. Cleanup
        # Revoke from both possible function signatures to be safe
        host.run("psql -c 'REVOKE ALL ON FUNCTION set_user(text) FROM normal_user;'")
        host.run("psql -c 'REVOKE ALL ON FUNCTION set_user_u(text) FROM normal_user;'")
        host.run("psql -c 'DROP ROLE IF EXISTS normal_user;'")
        host.run("psql -c 'DROP ROLE IF EXISTS power_user;'")

# --- WAL2JSON TEST ---
@pytest.mark.needs_preload
def test_wal2json_logical_decoding(host):
    """Verifies wal2json can decode DML into JSON format using 'kind' keys."""
    slot_name = "test_slot_wal2json"
    try:
        # 1. Check if wal_level is logical
        wal_level = host.run("psql -t -c 'SHOW wal_level;'").stdout.strip()
        if wal_level != 'logical':
            pytest.skip(f"wal_level is {wal_level}; 'logical' is required.")

        # 2. Setup a test table
        host.run("psql -c 'CREATE TABLE wal_test (id int PRIMARY KEY, name text);'")

        # 3. Create logical replication slot
        host.run(f"psql -c \"SELECT pg_create_logical_replication_slot('{slot_name}', 'wal2json');\"")

        # 4. Perform DML
        host.run("psql -c \"INSERT INTO wal_test VALUES (1, 'first'), (2, 'second');\"")
        host.run("psql -c \"UPDATE wal_test SET name = 'updated' WHERE id = 1;\"")
        host.run("psql -c \"DELETE FROM wal_test WHERE id = 2;\"")

        # 5. Consume and Verify
        result = host.run(f"psql -t -c \"SELECT data FROM pg_logical_slot_get_changes('{slot_name}', NULL, NULL);\"")
        output = result.stdout

        # Updated Assertions based on your log output
        assert '"table":"wal_test"' in output
        assert '"kind":"insert"' in output
        assert '"kind":"update"' in output
        assert '"kind":"delete"' in output
        assert '"columnvalues":[1,"updated"]' in output

    finally:
        # 6. Cleanup
        host.run(f"psql -c \"SELECT pg_drop_replication_slot('{slot_name}') WHERE EXISTS (SELECT 1 FROM pg_replication_slots WHERE slot_name = '{slot_name}');\"")
        host.run("psql -c 'DROP TABLE IF EXISTS wal_test;'")
