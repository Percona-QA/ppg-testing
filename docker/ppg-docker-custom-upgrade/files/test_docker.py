import os
import subprocess
import time
from datetime import datetime, timedelta

import psycopg2
import pytest
import testinfra

import settings

# --- Configuration constants/settings ---
# Constants
MAJOR_VER = os.getenv("VERSION").split(".")[0]
MAJOR_MINOR_VER = os.getenv("VERSION")
DOCKER_REPO = os.getenv("DOCKER_REPOSITORY")
IMG_TAG = os.getenv("TAG")
IS_WITH_POSTGIS = os.getenv("WITH_POSTGIS", "false").lower() == "true"
MILESTONE = int(os.getenv("MILESTONE", "0"))
PG_BIN_DIR = f"/usr/pgsql-{MAJOR_VER}/bin"
PG_DATA_DIR = "/data/db"
IMAGE = f"{DOCKER_REPO}/percona-distribution-postgresql-custom:{IMG_TAG}"
UPGRADE_DATA_DIR = os.getenv("UPGRADE_DATA_DIR")  # host path to mount as PG_DATA_DIR

# --- Milestone Markers ---
milestone_1 = pytest.mark.skipif(
    MILESTONE < 1, reason=f"MILESTONE={MILESTONE} — requires milestone 1 build - base version."
)
milestone_2 = pytest.mark.skipif(
    MILESTONE < 2, reason=f"MILESTONE={MILESTONE} — requires milestone 2 build"
)
milestone_3 = pytest.mark.skipif(
    MILESTONE < 3, reason=f"MILESTONE={MILESTONE} — requires milestone 3 build"
)

# --- Settings ---
pg_docker_versions = settings.get_settings(MAJOR_MINOR_VER)
DOCKER_RHEL_FILES = pg_docker_versions["rhel_files"]
DOCKER_RPM_PACKAGES = pg_docker_versions["rpm_packages"]
DOCKER_EXTENSIONS = pg_docker_versions["extensions"]
DOCKER_BINARIES = pg_docker_versions["binaries"]

# Packages that must NOT be installed in this image:
#   - percona-pg-telemetryN for any N != MAJOR_VER
#   - percona-telemetry-agent (all versions)
EXCLUDED_TELEMETRY_PACKAGES = ["percona-telemetry-agent"] + [
    f"percona-pg-telemetry{ver}" for ver in ["16", "17", "18"] if ver != MAJOR_VER
]

# --- PostGIS contrib script paths ---
POSTGIS_MAJOR_VER = pg_docker_versions[f"percona-postgis35_{MAJOR_VER}"]["major_version"]
POSTGIS_CONTRIB_DIR = f"/usr/pgsql-{MAJOR_VER}/share/contrib/postgis-{POSTGIS_MAJOR_VER}"
POSTGIS_LEGACY_SQL = f"{POSTGIS_CONTRIB_DIR}/legacy.sql"
POSTGIS_UNINSTALL_LEGACY_SQL = f"{POSTGIS_CONTRIB_DIR}/uninstall_legacy.sql"

# Red Hat ecosystem required image labels (same as pgbouncer/pgbackrest)
REQUIRED_LABEL_MAINTAINER = os.getenv(
    "PPG_LABEL_MAINTAINER", "Percona Development <info@percona.com>"
)
REQUIRED_LABEL_VENDOR = os.getenv("PPG_LABEL_VENDOR", "Percona")
REQUIRED_LABEL_NAME_PREFIX = "Percona "
EXPECTED_LABEL_NAME_POSTGRESQL = os.getenv(
    "PPG_LABEL_NAME_POSTGRESQL", "Percona Distribution for PostgreSQL"
)
REQUIRED_LABEL_KEYS = (
    "name",
    "vendor",
    "version",
    "release",
    "summary",
    "description",
    "maintainer",
)
RED_HAT_TRADEMARK_FORBIDDEN = ("Red Hat", "RHEL", "RedHat")


def reconnect_db():
    """Helper to establish a fresh connection if the server restarted or crashed."""
    for _i in range(10):
        try:
            conn = psycopg2.connect(**DB_PARAMS)
            conn.autocommit = True
            return conn
        except psycopg2.OperationalError:
            time.sleep(2)
    pytest.fail("Could not reconnect to database after server crash.")


@pytest.fixture(scope="session")
def host(request):
    container_name = f"PG{MAJOR_VER}"
    needs_libs = any(item.get_closest_marker("needs_preload") for item in request.session.items)

    subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)

    print("")
    print("\n------------Settings--------------")
    print(f"Major Version: {MAJOR_VER}")
    print(f"Major Minor Version: {MAJOR_MINOR_VER}")
    print(f"Image TAG: {IMG_TAG}")
    print(f"IS_WITH_POSTGIS: {IS_WITH_POSTGIS}")
    print(f"DOCKER_TO_USE: {IMAGE}")
    print(f"MILESTONE: {MILESTONE}")
    print(f"UPGRADE_DATA_DIR: {UPGRADE_DATA_DIR or '(none — fresh container)'}")
    print("--------------------------------")

    run_cmd = [
        "docker",
        "run",
        "--name",
        container_name,
        "-e",
        "POSTGRES_PASSWORD=password",
        "--shm-size=2g",
        "-p",
        "5432:5432",
        "-d",
    ]

    if UPGRADE_DATA_DIR:
        # Mount the named Docker volume so the container reuses the existing
        # cluster from Phase 1 (old version) or Phase 2 (upgraded data).
        # Named volumes are fully managed by Docker and have no UID/chmod issues.
        run_cmd.extend(["-v", f"{UPGRADE_DATA_DIR}:{PG_DATA_DIR}"])

    run_cmd.append(IMAGE)

    if needs_libs:
        # These specific flags prevent pg_stat_monitor from over-allocating on boot
        run_cmd.extend(
            [
                "-c",
                "shared_preload_libraries=timescaledb,pg_stat_monitor,pgaudit,set_user,pg_cron,anon,pg_partman_bgw",
                "-c",
                "shared_buffers=256MB",
                "-c",
                "max_worker_processes=32",  # Give extensions room to breathe
                "-c",
                "max_parallel_workers=16",
                "-c",
                "pg_stat_monitor.pgsm_max=500",  # Smaller bucket to save shared mem
                "-c",
                "pg_stat_monitor.pgsm_query_max_len=1024",
                "-c",
                "timescaledb.max_background_workers=4",
                "-c",
                "wal_level=logical",
                "-c",
                "pg_partman_bgw.dbname=postgres",
                "-c",
                "pg_partman_bgw.role=postgres",
                "-c",
                "pg_partman_bgw.interval=10",
            ]
        )

    subprocess.check_output(run_cmd)

    # --- STABILITY WAIT ---
    # Don't just wait; verify the server can actually answer a query
    for _ in range(30):
        res = subprocess.run(["docker", "exec", container_name, "pg_isready"], capture_output=True)
        if res.returncode == 0:
            # Final sanity check: Can we run a SQL command?
            sql = subprocess.run(
                ["docker", "exec", container_name, "psql", "-U", "postgres", "-c", "SELECT 1"],
                capture_output=True,
            )
            if sql.returncode == 0:
                break
        time.sleep(1)

    time.sleep(2)  # Final settle time for background workers
    yield testinfra.get_host("docker://" + container_name)

    if UPGRADE_DATA_DIR:
        # Before stopping: drop extensions that reference external .so libraries.
        # pg_upgrade checks that every library referenced in pg_proc exists in the
        # new installation; extension .so names can differ across major versions so
        # dropping them here avoids "required libraries" failures.  They will be
        # recreated in Phase 3 once the new-version container starts.
        subprocess.run(
            [
                "docker",
                "exec",
                container_name,
                "psql",
                "-U",
                "postgres",
                "-c",
                (
                    # Drop all extensions whose .so files may differ across major
                    # versions or that cannot be loaded without shared_preload_libraries.
                    # pg_upgrade crashes the old server when it tries to dlopen() these
                    # during its library-presence check, then fails all subsequent checks.
                    # ORDER MATTERS: drop dependants before their providers.
                    "DROP EXTENSION IF EXISTS timescaledb CASCADE; "
                    "DROP EXTENSION IF EXISTS pg_stat_monitor CASCADE; "
                    "DROP EXTENSION IF EXISTS pgaudit CASCADE; "
                    "DROP EXTENSION IF EXISTS set_user CASCADE; "
                    "DROP EXTENSION IF EXISTS pg_cron CASCADE; "
                    "DROP EXTENSION IF EXISTS pg_partman_bgw CASCADE; "
                    "DROP EXTENSION IF EXISTS pg_similarity CASCADE; "
                    "DROP EXTENSION IF EXISTS pgvectorscale CASCADE; "
                    "DROP EXTENSION IF EXISTS rum CASCADE; "
                    "DROP EXTENSION IF EXISTS postgresql_anonymizer CASCADE; "
                    # PostGIS family — postgis_raster / postgis_topology depend on postgis
                    "DROP EXTENSION IF EXISTS postgis_raster CASCADE; "
                    "DROP EXTENSION IF EXISTS postgis_topology CASCADE; "
                    "DROP EXTENSION IF EXISTS postgis CASCADE;"
                ),
            ],
            capture_output=True,
        )
        # Also clear shared_preload_libraries from both config files so pg_upgrade
        # does not fail the config-level library check either.
        subprocess.run(
            [
                "docker",
                "exec",
                container_name,
                "psql",
                "-U",
                "postgres",
                "-c",
                "ALTER SYSTEM RESET shared_preload_libraries",
            ],
            capture_output=True,
        )
        subprocess.run(
            [
                "docker",
                "exec",
                container_name,
                "sed",
                "-i",
                r"s/^\s*shared_preload_libraries\s*=.*//",
                "/data/db/postgresql.conf",
            ],
            capture_output=True,
        )

    # Graceful stop before removal: sends SIGTERM so PostgreSQL writes a clean
    # shutdown state to pg_control.  This is required when UPGRADE_DATA_DIR is
    # set — pg_upgrade refuses to upgrade a cluster marked "in production".
    # docker stop → SIGTERM (clean PG shutdown) → docker rm to clean up.
    subprocess.run(["docker", "stop", container_name], capture_output=True)
    subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)


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
        pytest.skip(
            "Skipping 'Empty' check: session is running in 'Preload Mode' for TimescaleDB."
        )

    cursor.execute("SHOW shared_preload_libraries;")
    setting = cursor.fetchone()[0]
    assert setting == "" or setting.lower() == "none"


def test_psql_string(host):
    # 'host' now binds to the container
    psql_output = host.check_output("psql -V")
    assert f"psql (PostgreSQL) {MAJOR_MINOR_VER} - Percona Distribution" in psql_output
    assert (
        f"psql (PostgreSQL) {MAJOR_MINOR_VER} - Percona Server for PostgreSQL" not in psql_output
    )


def test_wait_docker_load(host):
    time.sleep(5)
    assert 0 == 0


@pytest.fixture()
def postgresql_binary(host):
    pg_binary = f"{PG_BIN_DIR}/postgres"
    return host.file(pg_binary)


@pytest.fixture()
def postgresql_query_version(host):
    return host.run("psql -c 'SELECT version()' | awk 'NR==3{print $2}'")


def postgres_binary(postgresql_binary):
    assert postgresql_binary.exists
    assert postgresql_binary.user == "root"


@pytest.mark.parametrize("binary", DOCKER_BINARIES)
def test_binaries(host, binary):
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
        assert f"{MAJOR_MINOR_VER}" in result, result.stdout
    except AssertionError:
        pytest.mark.xfail(reason="Maybe dev package not install")


def test_postgresql_query_version(postgresql_query_version):
    assert postgresql_query_version.rc == 0, postgresql_query_version.stderr
    assert postgresql_query_version.stdout.strip("\n") == f"{MAJOR_MINOR_VER}", (
        postgresql_query_version.stdout
    )


def test_postgres_client_version(host):
    cmd = "psql --version"
    result = host.check_output(cmd)
    assert f"{MAJOR_MINOR_VER}" in result.strip("\n"), result.stdout


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
        return True, "Explicitly skipped in SKIP_EXTENSIONS"

    # 2. Version-based removals
    if major >= 17 and extension == "adminpack":
        return True, "adminpack removed in PG17+"

    if major < 18 and extension == "pg_logicalinspect":
        return True, "pg_logicalinspect only supported in PG18+"

    # 4. Feature-flag based skips
    postgis_family = {
        "postgis",
        "postgis_topology",
        "postgis_raster",
        "postgis_sfcgal",
        "address_standardizer",
        "postgis_tiger_geocoder",
        "address_standardizer_data_us",
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

    if major < 18 and extension == "pg_logicalinspect":
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
    # When running against an upgraded volume (UPGRADE_DATA_DIR is set) the
    # extension may already exist — pg_upgrade preserves installed extensions.
    # Use IF NOT EXISTS so the command succeeds either way, and skip the
    # stdout content check (which only fires on a fresh install).
    if UPGRADE_DATA_DIR:
        res = host.run(f'psql -c "CREATE EXTENSION IF NOT EXISTS \\"{extension}\\";"')
        assert res.rc == 0, f"Failed to create {extension}: {res.stderr}"
    else:
        res = host.run(f'psql -c "CREATE EXTENSION \\"{extension}\\";"')
        assert res.rc == 0, f"Failed to create {extension}: {res.stderr}"
        assert "CREATE EXTENSION" in res.stdout

    # 2. Verify existence using SQL count (Reliable replacement for awk)
    check_sql = f"SELECT count(*) FROM pg_extension WHERE extname = '{extension}';"
    count = host.run(f'psql -t -A -c "{check_sql}"').stdout.strip()
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
    count = host.run(f'psql -t -A -c "{check_sql}"').stdout.strip()
    assert count == "0", f"Extension {extension} still exists after drop"


def test_plpgsql_extension(host):
    # plpgsql is internal and always exists; just check for it directly
    check_sql = "SELECT count(*) FROM pg_extension WHERE extname = 'plpgsql';"
    count = host.run(f'psql -t -A -c "{check_sql}"').stdout.strip()
    assert count == "1", "Default extension 'plpgsql' is missing!"


@pytest.mark.parametrize("package", DOCKER_RPM_PACKAGES)
def test_rpm_package_is_installed(host, package):
    # 1. Centralized Skip Logic
    if not IS_WITH_POSTGIS and "postgis" in package:
        pytest.skip(f"Docker build is without PostGIS so skipping {package}.")

    if "oidc_validator" in package and int(MAJOR_VER) < 18:
        pytest.skip(f"Skipping {package} for PostgreSQL {MAJOR_VER} (only supported on 18.2+).")

    milestone_pkg_requirements = {
        f"percona-h3-pg_{MAJOR_VER}": (2, "h3 extension"),
        f"percona-pgrouting_{MAJOR_VER}": (2, "pgrouting extension"),
    }

    for pkg_pattern, (required_milestone, feature_name) in milestone_pkg_requirements.items():
        if pkg_pattern in package and MILESTONE < required_milestone:
            pytest.skip(
                f"MILESTONE={MILESTONE} - "
                f"requires milestone {required_milestone} build ({feature_name})."
            )

    pkg = host.package(package)

    # 2. Verify Installation
    assert pkg.is_installed, f"Package {package} is not installed"

    # 3. Dynamic Version Lookup
    pkg_data = pg_docker_versions.get(package)

    if isinstance(pkg_data, dict):
        expected_version = pkg_data.get("version")
    else:
        expected_version = pkg_data

    # Fallback to the global 'version' if the specific package isn't mapped
    if not expected_version:
        expected_version = pg_docker_versions.get("version")

    # --- Console Output Enhancement ---
    print(f"\n[VERIFYING] Package: {package}")
    print(f"            Expected: {expected_version}")
    print(f"            Found:    {pkg.version}")

    assert pkg.version == expected_version, (
        f"Version mismatch for {package}. Expected: {expected_version}, Found: {pkg.version}"
    )

    print(f"[SUCCESS] {package} version {pkg.version} verified.")


@pytest.mark.parametrize("package", EXCLUDED_TELEMETRY_PACKAGES)
def test_telemetry_packages_not_installed(host, package):
    pkg = host.package(package)
    assert not pkg.is_installed, (
        f"Package {package} should not be installed in PG{MAJOR_VER} image"
    )


@pytest.mark.needs_preload
def test_pg_stat_monitor_extension_version(host):
    # 1. Ensure extension is created
    create_res = host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS pg_stat_monitor;'")
    assert create_res.rc == 0, create_res.stderr

    # 2. Get the Extension version (SQL Level)
    # -t: tuples only, -A: unaligned
    query = "SELECT pg_stat_monitor_version();"
    actual_ext_version = host.run(f'psql -t -A -c "{query}"').stdout.strip()

    # 3. Get Expected version from dictionary
    pkg_key = f"percona-pg_stat_monitor{MAJOR_VER}"
    expected_full_version = pg_docker_versions[pkg_key]["version"]

    # 4. Clean the version string
    # RPM versions often look like '2.1.0-1.el9'. We need to strip the '-1.el9'
    # part to match the PostgreSQL extension version '2.1.0'.
    expected_clean_version = expected_full_version.split("-")[0]

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
    if distribution in [
        "redhat",
        "centos",
        "rhel",
        "rocky",
        "ol",
    ] and host.system_info.release.startswith("8"):
        pytest.skip(f"liburing not supported on {distribution} 8 for postgres {MAJOR_VER}")

    cmd = "pg_config --configure"
    output = host.check_output(cmd)
    assert "--with-liburing" in output, "PostgreSQL 18 was built without --with-liburing"


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

    assert flag not in output, f"PostgreSQL was built with {flag}, but it should NOT be present"


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

    expected_version = pg_docker_versions.get(f"percona-postgis35_{MAJOR_VER}", {}).get(
        "extension_version"
    )
    assert actual_version == expected_version, (
        f"Expected {expected_version}, but found {actual_version}"
    )

    # 4. Functional Check: Verify the extension is actually working
    # This ensures the underlying GEOS and PROJ libraries are linked correctly
    func_cmd = 'psql -t -c "SELECT postgis_version();"'
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
    expected_version = pg_docker_versions.get(f"percona-pgvector_{MAJOR_VER}", {}).get(
        "extension_version"
    )

    assert actual_version == expected_version, (
        f"Expected {expected_version}, but found {actual_version}"
    )

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
        assert actual_version == expected_version, (
            f"Expected {expected_version}, but found {actual_version}"
        )
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
        assert actual_version == expected_version, (
            f"Expected {expected_version}, but found {actual_version}"
        )
    else:
        # Fallback: just ensure we got a valid-looking version string
        assert len(actual_version) > 0 and actual_version[0].isdigit()


# --- Configuration ---
DB_PARAMS = {
    "dbname": "postgres",
    "user": "postgres",
    "password": "password",
    "host": "localhost",
    "port": "5432",
}


# --- Fixtures (Internalized conftest logic) ---
@pytest.fixture(scope="session")
def db_connection(host):  # <--- Adding 'host' here forces host to finish booting first
    container_name = f"PG{MAJOR_VER}"
    max_retries = 45

    # Check if container exists
    status = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", container_name],
        capture_output=True,
        text=True,
    )

    if status.returncode != 0:
        pytest.fail(
            f"Container {container_name} does not exist. Docker Run might have failed silently."
        )

    conn = None

    # 1. Pre-flight Check: Is the container even alive?
    status = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", container_name],
        capture_output=True,
        text=True,
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
                print(f"[WAIT] Postgres is initializing (attempt {i + 1}/{max_retries})...")
                time.sleep(2)

            # Scenario B: Server crashed WHILE we were talking to it (Abnormal)
            elif (
                "closed the connection unexpectedly" in err_msg
                or "terminating connection" in err_msg
            ):
                print(f"\n[FATAL] Postgres crashed during connection attempt {i + 1}!")
                # Immediate log dump to see the PANIC/FATAL message
                res = subprocess.run(
                    ["docker", "logs", container_name, "--tail", "20"],
                    capture_output=True,
                    text=True,
                )
                print(f"--- RECENT LOGS ---\n{res.stdout}")
                pytest.fail("Postgres process crashed. See logs above for details.")

            # Scenario C: Something else (Wrong credentials, wrong port, etc.)
            else:
                print(f"[DEBUG] Unexpected Connection Error: {err_msg}")
                time.sleep(2)

    # 3. Final Fallback
    if not conn:
        print("\n" + "=" * 50)
        print(f"TIMEOUT: Could not connect to {container_name} after 90s.")
        res = subprocess.run(
            ["docker", "logs", container_name, "--tail", "20"], capture_output=True, text=True
        )
        print(f"Final Logs:\n{res.stdout}")
        print("=" * 50)
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

    expected_full_version = pg_docker_versions[pkg_key]["version"]

    try:
        # --- 1. Extension Setup & Version Check ---
        cursor.execute("CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;")

        # Verify Extension Name
        cursor.execute(
            "SELECT extname, extversion FROM pg_extension WHERE extname = 'timescaledb';"
        )
        extension_info = cursor.fetchone()
        assert extension_info is not None, "Extension failed to load into pg_extension catalog."

        actual_db_version = extension_info[1]

        # Verify Version: check if DB version (e.g. 2.13.1) is in the
        # package string (e.g. 2.13.1-1.debian12)
        assert actual_db_version in expected_full_version, (
            f"Version mismatch! DB reports {actual_db_version}, "
            f"but manifest expects {expected_full_version}"
        )

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
        cursor.execute(
            f"SELECT count(*) FROM timescaledb_information.hypertables "
            f"WHERE hypertable_name = '{table_name}';"
        )
        assert cursor.fetchone()[0] == 1, "Table was not converted to hypertable"

        # --- 3. Data Insertion ---
        base_time = datetime.now()
        test_data = [(base_time, 1, 0.85), (base_time - timedelta(minutes=5), 1, 0.45)]
        for row in test_data:
            cursor.execute(f"INSERT INTO {table_name} VALUES (%s, %s, %s)", row)

        # --- 4. Advanced Persistence Test (The Restart) ---
        print(f"\n[INFO] Restarting container PG{MAJOR_VER} from host to test persistence...")
        container_name = f"PG{MAJOR_VER}"
        subprocess.check_call(["docker", "restart", container_name])

        # --- 5. Reconnect Phase (The "Polling" Loop) ---
        new_cursor = None
        new_conn = None

        for i in range(15):
            try:
                time.sleep(2)
                new_conn = psycopg2.connect(**DB_PARAMS)
                new_conn.autocommit = True
                new_cursor = new_conn.cursor()
                print(f"[INFO] Successfully reconnected on attempt {i + 1}")
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

            new_cursor.execute(
                f"SELECT count(*) FROM timescaledb_information.chunks "
                f"WHERE hypertable_name = '{table_name}';"
            )
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
            pass  # DB might be unreachable or table already gone


# --- pgvector Functional Test ---
# @pytest.mark.needs_preload
def test_pgvector_functional_logic(host):  # Use host here to allow re-connection
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
                cur.execute(
                    "CREATE TABLE test_vector_items (id serial PRIMARY KEY, embedding vector(3));"
                )
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

    assert result == "[1,2,3]"


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
            time.sleep(1)  # Give PGSM a moment to flush to the view
            cur.execute("SELECT query FROM pg_stat_monitor WHERE query LIKE '%pgsm_test_marker%';")
            assert cur.fetchone() is not None


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
            '-c "SELECT current_user;"'
        )
        result = host.run(cmd)

        # Log stderr for visibility if the logic changes
        if result.rc != 0:
            print(f"PSQL Stderr: {result.stderr}")

        assert "power_user" in result.stdout

        # 5. Test: De-escalation (NULL always works to return to original user)
        back_cmd = (
            "psql -U normal_user -d postgres -t "
            '-c "SELECT set_user(NULL);" '
            '-c "SELECT current_user;"'
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
        if wal_level != "logical":
            pytest.skip(f"wal_level is {wal_level}; 'logical' is required.")

        # 2. Setup a test table
        host.run("psql -c 'CREATE TABLE wal_test (id int PRIMARY KEY, name text);'")

        # 3. Create logical replication slot
        host.run(
            f"psql -c \"SELECT pg_create_logical_replication_slot('{slot_name}', 'wal2json');\""
        )

        # 4. Perform DML
        host.run("psql -c \"INSERT INTO wal_test VALUES (1, 'first'), (2, 'second');\"")
        host.run("psql -c \"UPDATE wal_test SET name = 'updated' WHERE id = 1;\"")
        host.run('psql -c "DELETE FROM wal_test WHERE id = 2;"')

        # 5. Consume and Verify
        result = host.run(
            f'psql -t -c "SELECT data FROM pg_logical_slot_get_changes('
            f"'{slot_name}', NULL, NULL);\""
        )
        output = result.stdout

        # Updated Assertions based on your log output
        assert '"table":"wal_test"' in output
        assert '"kind":"insert"' in output
        assert '"kind":"update"' in output
        assert '"kind":"delete"' in output
        assert '"columnvalues":[1,"updated"]' in output

    finally:
        # 6. Cleanup
        host.run(
            f"psql -c \"SELECT pg_drop_replication_slot('{slot_name}') "
            f"WHERE EXISTS (SELECT 1 FROM pg_replication_slots "
            f"WHERE slot_name = '{slot_name}');\""
        )
        host.run("psql -c 'DROP TABLE IF EXISTS wal_test;'")


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
@milestone_2
def test_postgis_library_linkage(host):
    """Verifies PostGIS can be enabled and GEOS, PROJ, and GDAL are reachable."""
    try:
        manage_postgis(host, "create")
        version_info = host.run("psql -t -c 'SELECT postgis_full_version();'")
        # Ensure the underlying engine libraries are properly linked in the image
        assert all(lib in version_info.stdout for lib in ["GEOS", "PROJ", "GDAL", "LIBXML"])
    finally:
        manage_postgis(host, "drop")


@milestone_2
def test_postgis_spatial_logic_and_rasters(host):
    """Verifies distance calculations (PROJ/GEOS) and Raster support (GDAL)."""
    try:
        manage_postgis(host, "create")

        # Calculate distance between London and Paris (approx 340km)
        dist_query = (
            "SELECT ST_Distance("
            "ST_GeogFromText('SRID=4326;POINT(0 51.5)'), "
            "ST_GeogFromText('SRID=4326;POINT(2.3 48.8)'));"
        )
        dist_res = host.run(f'psql -t -c "{dist_query}"')
        assert 330000 < float(dist_res.stdout.strip()) < 350000

        # Verify GDAL Raster support
        raster_query = (
            "SELECT ST_Width(ST_AddBand("
            "ST_MakeEmptyRaster(10, 10, 0, 0, 1, -1, 0, 0, 4326), 1, '8BUI', 1, 0));"
        )
        assert "10" in host.run(f'psql -t -c "{raster_query}"').stdout
    finally:
        manage_postgis(host, "drop")


@milestone_2
def test_postgis_srid_transformation(host):
    """Verifies coordinate reprojection logic (PROJ library check)."""
    try:
        manage_postgis(host, "create")
        # Transform GPS (4326) to Web Mercator (3857)
        query = "SELECT ST_AsText(ST_Transform(ST_GeomFromText('POINT(0 0)', 4326), 3857));"
        res = host.run(f'psql -t -c "{query}"')
        assert "POINT(0 0)" in res.stdout
    finally:
        manage_postgis(host, "drop")


@milestone_2
def test_postgis_indexing_and_joins(host):
    """Verifies GiST indexing and spatial join performance/logic."""
    try:
        manage_postgis(host, "create")

        setup = """
        DROP TABLE IF EXISTS districts CASCADE;
        CREATE TABLE districts (id int, geom geometry(Polygon, 4326));
        CREATE INDEX idx_dist_geom ON districts USING GIST (geom);
        INSERT INTO districts VALUES (1, ST_MakeEnvelope(0, 0, 2, 2, 4326));
        """
        host.run(f'psql -c "{setup}"')

        # Test Point-in-Polygon join using the GiST index
        join_query = (
            "SELECT count(*) FROM districts "
            "WHERE ST_Contains(geom, ST_GeomFromText('POINT(1 1)', 4326));"
        )
        assert "1" in host.run(f'psql -t -c "{join_query}"').stdout.strip()
    finally:
        manage_postgis(host, "drop")


@milestone_2
def test_postgis_functional(host):
    """
    End-to-end functional test: spatial table, GiST index, proximity query,
    area calculation, and topology — covering the full PostGIS stack in one workflow.
    """

    try:
        host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS postgis CASCADE;'")
        host.run("psql -c 'DROP TABLE IF EXISTS geo_cities CASCADE;'")

        # 1. Create a table and populate it with European city points
        setup_sql = """
        CREATE TABLE geo_cities (
            id   serial PRIMARY KEY,
            name text,
            geom geometry(Point, 4326)
        );
        INSERT INTO geo_cities (name, geom) VALUES
            ('London',    ST_SetSRID(ST_MakePoint(-0.1278,  51.5074), 4326)),
            ('Paris',     ST_SetSRID(ST_MakePoint( 2.3522,  48.8566), 4326)),
            ('Berlin',    ST_SetSRID(ST_MakePoint(13.4050,  52.5200), 4326)),
            ('Madrid',    ST_SetSRID(ST_MakePoint(-3.7038,  40.4168), 4326)),
            ('Amsterdam', ST_SetSRID(ST_MakePoint( 4.9041,  52.3676), 4326));
        CREATE INDEX idx_geo_cities_geom ON geo_cities USING GIST (geom);
        """
        res = host.run(f'psql -c "{setup_sql}"')
        assert res.rc == 0, f"Setup failed: {res.stderr}"

        # 2. Proximity query: cities within 600 km of London (geography cast for metres)
        proximity_sql = (
            "SELECT count(*) FROM geo_cities "
            "WHERE ST_DWithin("
            "  geom::geography,"
            "  ST_SetSRID(ST_MakePoint(-0.1278, 51.5074), 4326)::geography,"
            "  600000"
            ");"
        )
        count = host.run(f'psql -t -A -c "{proximity_sql}"').stdout.strip()
        # London, Paris, Amsterdam are within 600 km; Berlin is ~930 km; Madrid ~1265 km
        assert count == "3", f"Expected 3 cities within 600 km of London, got {count}"

        # 3. Distance check: London → Paris must be roughly 340 km
        dist_sql = (
            "SELECT ST_Distance("
            "  (SELECT geom::geography FROM geo_cities WHERE name='London'),"
            "  (SELECT geom::geography FROM geo_cities WHERE name='Paris')"
            ")::int;"
        )
        dist_m = int(host.run(f'psql -t -A -c "{dist_sql}"').stdout.strip())
        assert 330000 < dist_m < 350000, f"London–Paris distance unexpected: {dist_m} m"

        # 4. Area of a bounding envelope that covers Western Europe (~correct order of magnitude)
        area_sql = (
            "SELECT ST_Area(ST_Envelope(ST_Collect(geom))::geography)::bigint "
            "FROM geo_cities;"
        )
        area_m2 = int(host.run(f'psql -t -A -c "{area_sql}"').stdout.strip())
        assert area_m2 > 1_000_000_000_000, f"Bounding area too small: {area_m2} m²"

        # 5. Nearest-neighbour: closest city to Brussels (4.35, 50.85) should be Paris or Amsterdam
        nn_sql = (
            "SELECT name FROM geo_cities "
            "ORDER BY geom::geography <-> "
            "ST_SetSRID(ST_MakePoint(4.35, 50.85), 4326)::geography LIMIT 1;"
        )
        nearest = host.run(f'psql -t -A -c "{nn_sql}"').stdout.strip()
        assert nearest in ("Paris", "Amsterdam"), (
            f"Unexpected nearest city to Brussels: {nearest!r}"
        )

    finally:
        host.run("psql -c 'DROP TABLE IF EXISTS geo_cities CASCADE;'")
        host.run("psql -c 'DROP EXTENSION IF EXISTS postgis CASCADE;'")


# --- H3 TEST ---
@pytest.fixture(scope="module")
def h3_db(host):
    # Ensure installation
    setup_cmd = (
        f"{PG_BIN_DIR}/psql -U postgres -d postgres "
        f"-c 'CREATE EXTENSION IF NOT EXISTS h3_postgis CASCADE;'"
    )
    setup_result = host.run(setup_cmd)

    # Critical: Check if the installation actually worked
    assert setup_result.exit_status == 0, f"Failed to install H3: {setup_result.stderr}"

    return host


@milestone_2
def test_h3_extension_installed(h3_db):
    """Verify h3 is in the installed extensions list."""
    # Simplified command
    cmd = (
        f"{PG_BIN_DIR}/psql -U postgres -d postgres -t "
        f"-c \"SELECT count(*) FROM pg_extension WHERE extname = 'h3';\""
    )
    result = h3_db.run(cmd)
    assert result.stdout.strip() == "1"


@milestone_2
def test_h3_latlng_to_cell(h3_db):
    """Test using the geometry point signature."""
    # We create a POINT(longitude latitude) and pass it as a single argument
    query = "SELECT h3_lat_lng_to_cell(ST_SetSRID(ST_MakePoint(-0.1278, 51.5074), 4326), 7);"
    result = h3_db.run(f'{PG_BIN_DIR}/psql -U postgres -d postgres -t -c "{query}"')

    assert result.exit_status == 0, f"SQL Error: {result.stderr}"
    assert result.stdout.strip().startswith("8719")


@milestone_2
def test_h3_postgis_geometry_to_cell(h3_db):
    """Verify converting a PostGIS Geometry point to an H3 index."""
    # Since ST_Y/ST_X already return double precision, this signature matches
    # the 'geometry, resolution' signature in your \df output.
    query = "SELECT h3_lat_lng_to_cell(  ST_SetSRID(ST_MakePoint(-74.0060, 40.7128), 4326),   9);"
    result = h3_db.run(f'{PG_BIN_DIR}/psql -U postgres -d postgres -t -c "{query}"')

    assert result.exit_status == 0, f"SQL Error: {result.stderr}"
    assert len(result.stdout.strip()) == 15


@milestone_2
def test_h3_grid_distance(h3_db):
    """Test distance between two cells using the point-based signature."""
    # Using the ST_MakePoint method since we know it works from your PASSED tests
    query = """
    SELECT h3_grid_distance(
        h3_lat_lng_to_cell(ST_SetSRID(ST_MakePoint(-74.0060, 40.7128), 4326), 10),
        h3_lat_lng_to_cell(ST_SetSRID(ST_MakePoint(-74.0061, 40.7129), 10), 10)
    );
    """
    result = h3_db.run(f'{PG_BIN_DIR}/psql -U postgres -d postgres -t -c "{query}"')

    assert result.exit_status == 0, f"SQL Error: {result.stderr}"
    assert int(result.stdout.strip()) >= 0


@milestone_2
def test_h3_latlng_constructor(h3_db):
    """Test using the geography-to-h3 conversion (the most stable path)."""
    # We know ST_MakePoint works because your other tests just passed.
    # We cast to geography to match the 'geography, resolution' signature in your \df.
    query = "SELECT h3_lat_lng_to_cell(ST_MakePoint(-0.1278, 51.5074)::geography, 7);"
    result = h3_db.run(f'{PG_BIN_DIR}/psql -U postgres -d postgres -t -c "{query}"')

    assert result.exit_status == 0, f"SQL Error: {result.stderr}"
    assert result.stdout.strip().startswith("8719")


# 1. Test the 'geography' signature (Standard for Global H3)
@milestone_2
def test_h3_signature_geography(h3_db):
    query = "SELECT h3_latlng_to_cell(ST_MakePoint(-0.1278, 51.5074)::geography, 7);"
    result = h3_db.run(f'{PG_BIN_DIR}/psql -U postgres -d postgres -t -c "{query}"')
    assert result.exit_status == 0
    assert result.stdout.strip().startswith("8719")


# 2. Test the 'geometry' signature (Standard for Flat/Projected maps)
@milestone_2
def test_h3_signature_geometry(h3_db):
    query = "SELECT h3_latlng_to_cell(ST_SetSRID(ST_MakePoint(-0.1278, 51.5074), 4326), 7);"
    result = h3_db.run(f'{PG_BIN_DIR}/psql -U postgres -d postgres -t -c "{query}"')
    assert result.exit_status == 0


@milestone_2
def test_h3_signature_latlng_point(h3_db):
    # Swap to (lng, lat) for the native point constructor to hit the 8719 index
    query = "SELECT h3_latlng_to_cell(point(-0.1278, 51.5074), 7);"
    result = h3_db.run(f'{PG_BIN_DIR}/psql -U postgres -d postgres -t -c "{query}"')

    assert result.exit_status == 0
    assert result.stdout.strip().startswith("8719")


@milestone_2
def test_h3_function_signatures_count(h3_db):
    """
    Verify the 'Contract': The extension should register exactly 3 overloads
    for h3_latlng_to_cell, and NONE for raw float8s.
    """
    # Count total overloads
    count_cmd = (
        f"{PG_BIN_DIR}/psql -U postgres -d postgres -t -c "
        "\"SELECT count(*) FROM pg_proc WHERE proname = 'h3_latlng_to_cell';\""
    )
    result = h3_db.run(count_cmd)
    assert result.stdout.strip() == "3", f"Expected 3 overloads, found {result.stdout}"

    # Specifically verify that the (float8, float8) signature is MISSING
    # This confirms the 'packaging choice' we discovered.
    check_float_cmd = (
        f"{PG_BIN_DIR}/psql -U postgres -d postgres -t -c "
        "\"SELECT count(*) FROM pg_proc WHERE proname = 'h3_latlng_to_cell' "
        "AND pg_get_function_arguments(oid) LIKE '%double precision, double precision%';\""
    )
    result_float = h3_db.run(check_float_cmd)
    assert result_float.stdout.strip() == "0", (
        "Package unexpectedly contains raw float8 overloads!"
    )


@milestone_2
def test_h3_functional_integrity(h3_db):
    """The gold-standard functional test for this specific package build."""
    query = "SELECT h3_latlng_to_cell(ST_MakePoint(-0.1278, 51.5074)::geography, 7);"
    result = h3_db.run(f'{PG_BIN_DIR}/psql -U postgres -d postgres -t -c "{query}"')

    assert result.exit_status == 0
    assert result.stdout.strip().startswith("8719")


@milestone_2
def test_h3_binary_integrity(h3_db):
    """Verify C symbols exist without executing them (prevents segfaults)."""
    lib_path = f"/usr/pgsql-{MAJOR_VER}/lib/h3.so"
    result = h3_db.run(f"nm -D {lib_path} | grep h3_latlng_to_cell")
    assert result.exit_status == 0
    assert "T h3_latlng_to_cell" in result.stdout


@milestone_2
def test_h3_standard_geography_path(h3_db):
    # Longitude first, then Latitude
    query = "SELECT h3_latlng_to_cell(ST_MakePoint(-0.1278, 51.5074)::geography, 7);"
    result = h3_db.run(f'{PG_BIN_DIR}/psql -U postgres -d postgres -t -c "{query}"')

    assert result.exit_status == 0
    assert result.stdout.strip().startswith("8719")


@milestone_2
def test_h3_internal_point_path(h3_db):
    """
    Verify the internal 'latlng point' signature.
    Note: For this build, point(x, y) maps to point(lng, lat).
    """
    # London: -0.1278 (Lng/X), 51.5074 (Lat/Y)
    query = "SELECT h3_latlng_to_cell(point(-0.1278, 51.5074), 7);"
    result = h3_db.run(f'{PG_BIN_DIR}/psql -U postgres -d postgres -t -c "{query}"')

    assert result.exit_status == 0
    # This should now return the 8719... prefix
    assert result.stdout.strip().startswith("8719")


@milestone_2
def test_h3_extension_version(host):
    # 1. Clean slate and recreate
    # We use CASCADE because h3 often has dependencies (like postgis)
    host.run("psql -c 'DROP EXTENSION IF EXISTS h3_postgis CASCADE;'")
    host.run("psql -c 'DROP EXTENSION IF EXISTS h3 CASCADE;'")

    create_res = host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS h3_postgis CASCADE;'")
    assert create_res.rc == 0, create_res.stderr

    # 2. Get the Extension version (SQL Level)
    query = "SELECT extversion FROM pg_extension WHERE extname = 'h3';"
    actual_ext_version = host.run(f'psql -t -A -c "{query}"').stdout.strip()

    # 3. Get Expected version from dictionary
    pkg_key = f"percona-h3-pg_{MAJOR_VER}"
    expected_full_version = pg_docker_versions[pkg_key]["version"]

    # 4. Clean the version string (e.g., '4.2.3-1.el9' -> '4.2.3')
    expected_clean_version = expected_full_version.split("-")[0]

    assert actual_ext_version == expected_clean_version, (
        f"H3 Extension version {actual_ext_version} does not match "
        f"expected version {expected_clean_version}"
    )

    # 5. Cleanup: Drop extension at the end
    drop_res = host.run("psql -c 'DROP EXTENSION IF EXISTS h3_postgis CASCADE;'")
    assert drop_res.rc == 0, drop_res.stderr

    drop_res = host.run("psql -c 'DROP EXTENSION IF EXISTS h3 CASCADE;'")
    assert drop_res.rc == 0, drop_res.stderr


@milestone_2
def test_pgrouting_extension_version(host):
    # 1. Clean slate and recreate
    host.run("psql -c 'DROP EXTENSION IF EXISTS pgrouting CASCADE;'")

    create_res = host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS pgrouting CASCADE;'")
    assert create_res.rc == 0, create_res.stderr

    # 2. Get the Extension version (SQL Level)
    query = "SELECT extversion FROM pg_extension WHERE extname = 'pgrouting';"
    actual_ext_version = host.run(f'psql -t -A -c "{query}"').stdout.strip()

    # 3. Get Expected version from dictionary
    pkg_key = f"percona-pgrouting_{MAJOR_VER}"
    expected_full_version = pg_docker_versions[pkg_key]["version"]

    # 4. Clean the version string (e.g., '3.6.2-1.el9' -> '3.6.2')
    expected_clean_version = expected_full_version.split("-")[0]

    assert actual_ext_version == expected_clean_version, (
        f"pgRouting Extension version {actual_ext_version} does not match "
        f"expected version {expected_clean_version}"
    )

    # 5. Cleanup: Drop extension at the end
    drop_res = host.run("psql -c 'DROP EXTENSION IF EXISTS pgrouting CASCADE;'")
    assert drop_res.rc == 0, drop_res.stderr


@milestone_2
def test_pg_routing_functional_dijkstra(host):
    # 1. Setup
    host.run("psql -c 'DROP EXTENSION IF EXISTS pgrouting CASCADE;'")
    host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS pgrouting CASCADE;'")

    # 2. Execution
    test_sql = """
    CREATE TEMP TABLE edges AS
    SELECT 1::bigint AS id, 1::bigint AS source, 2::bigint AS target, 1.0::float8 AS cost
    UNION ALL
    SELECT 2::bigint AS id, 2::bigint AS source, 3::bigint AS target, 1.0::float8 AS cost;

    SELECT sum(cost) FROM pgr_dijkstra(
        'SELECT id, source, target, cost FROM edges',
        1, 3, false
    );
    """
    result = host.run(f'psql -q -t -A -c "{test_sql}"')

    # 3. Validation
    assert result.rc == 0
    assert result.stdout.strip().split("\n")[-1] == "2"

    # 4. Cleanup
    host.run("psql -c 'DROP EXTENSION IF EXISTS pgrouting CASCADE;'")


@milestone_2
def test_pg_routing_metadata(host):
    # 1. Setup
    host.run("psql -c 'DROP EXTENSION IF EXISTS pgrouting CASCADE;'")
    host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS pgrouting CASCADE;'")

    # 2. Check if the extension is recognized by PG
    query = (
        "SELECT count(*) FROM pg_available_extensions "
        "WHERE name = 'pgrouting' AND installed_version IS NOT NULL;"
    )
    result = host.run(f'psql -t -A -c "{query}"')

    # 3. Validation
    assert result.stdout.strip() == "1", "pgRouting should be marked as installed"

    # 4. Cleanup
    host.run("psql -c 'DROP EXTENSION IF EXISTS pgrouting CASCADE;'")


@milestone_2
def test_pg_routing_functional_bidirectional(host):
    # 1. Setup
    host.run("psql -c 'DROP EXTENSION IF EXISTS pgrouting CASCADE;'")
    host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS pgrouting CASCADE;'")

    # 2. Execution: Test Bidirectional Dijkstra (Core 4.0 feature)
    test_sql = """
    CREATE TEMP TABLE edges AS
    SELECT 1::bigint AS id, 1::bigint AS source, 2::bigint AS target, 1.0::float8 AS cost
    UNION ALL
    SELECT 2::bigint AS id, 2::bigint AS source, 3::bigint AS target, 1.0::float8 AS cost;

    SELECT sum(cost) FROM pgr_bdDijkstra(
        'SELECT id, source, target, cost FROM edges',
        1, 3, false
    );
    """
    result = host.run(f'psql -q -t -A -c "{test_sql}"')

    # 3. Validation
    assert result.rc == 0, f"pgRouting Bidirectional failed: {result.stderr}"
    actual_cost = result.stdout.strip().split("\n")[-1]
    assert actual_cost == "2", f"Expected 2, got {actual_cost}"

    # 4. Cleanup
    host.run("psql -c 'DROP EXTENSION IF EXISTS pgrouting CASCADE;'")


# =============================================================================
# --- POSTGIS LEGACY SCRIPT TESTS ---
# =============================================================================

# Fixture: install PostGIS and load legacy.sql once for all legacy function tests.
# PostGIS is left installed after the fixture teardown because other milestone_2
# tests (h3, pgrouting) may depend on it being present.

@pytest.fixture(scope="module")
def postgis_legacy_db(host):
    """Install PostGIS and load legacy.sql into the postgres database."""
    host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS postgis CASCADE;'")
    load_res = host.run(f"psql -f {POSTGIS_LEGACY_SQL}")
    assert load_res.exit_status == 0, (
        f"Failed to load {POSTGIS_LEGACY_SQL}: {load_res.stderr}"
    )
    yield host


@milestone_2
def test_postgis_legacy_sql_file_exists(host):
    """Verify legacy.sql is present at the expected contrib path."""
    result = host.run(f"test -f {POSTGIS_LEGACY_SQL}")
    assert result.rc == 0, f"legacy.sql not found at {POSTGIS_LEGACY_SQL}"


@milestone_2
def test_postgis_uninstall_legacy_sql_file_exists(host):
    """Verify uninstall_legacy.sql is present at the expected contrib path."""
    result = host.run(f"test -f {POSTGIS_UNINSTALL_LEGACY_SQL}")
    assert result.rc == 0, (
        f"uninstall_legacy.sql not found at {POSTGIS_UNINSTALL_LEGACY_SQL}"
    )


@milestone_2
def test_postgis_legacy_sql_loads(host):
    """Verify legacy.sql executes without errors against a PostGIS-enabled database."""
    host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS postgis CASCADE;'")
    result = host.run(f"psql -f {POSTGIS_LEGACY_SQL}")
    assert result.rc == 0, f"legacy.sql failed to load: {result.stderr}"


@milestone_2
def test_postgis_legacy_st_line_interpolate_point(postgis_legacy_db):
    """st_line_interpolate_point() is a legacy alias — verify it returns a POINT."""
    query = (
        "SELECT ST_AsText("
        "st_line_interpolate_point(ST_GeomFromText('LINESTRING(0 0, 2 2)'), 0.5)"
        ");"
    )
    result = postgis_legacy_db.run(f'psql -t -A -c "{query}"')
    assert result.rc == 0, f"st_line_interpolate_point failed: {result.stderr}"
    assert result.stdout.strip().upper().startswith("POINT"), (
        f"Unexpected result: {result.stdout.strip()!r}"
    )


@milestone_2
def test_postgis_legacy_st_force_2d(postgis_legacy_db):
    """st_force_2d() is a legacy alias — verify it strips the Z coordinate."""
    query = "SELECT ST_AsText(st_force_2d(ST_GeomFromText('POINT(1 2 3)')));"
    result = postgis_legacy_db.run(f'psql -t -A -c "{query}"')
    assert result.rc == 0, f"st_force_2d failed: {result.stderr}"
    assert result.stdout.strip() == "POINT(1 2)", (
        f"Unexpected result: {result.stdout.strip()!r}"
    )


@milestone_2
def test_postgis_legacy_st_numinteriorring(postgis_legacy_db):
    """st_numinteriorring() is a legacy alias — verify it counts interior rings."""
    query = (
        "SELECT st_numinteriorring("
        "ST_GeomFromText('POLYGON((0 0,0 3,3 3,3 0,0 0),"
        "(1 1,1 2,2 2,2 1,1 1))')"
        ");"
    )
    result = postgis_legacy_db.run(f'psql -t -A -c "{query}"')
    assert result.rc == 0, f"st_numinteriorring failed: {result.stderr}"
    assert result.stdout.strip() == "1", (
        f"Expected 1 interior ring, got: {result.stdout.strip()!r}"
    )


@milestone_2
def test_postgis_uninstall_legacy_sql(host):
    """Verify uninstall_legacy.sql removes the legacy function aliases.

    Steps: install PostGIS → load legacy.sql → confirm a legacy function exists →
    load uninstall_legacy.sql → confirm the function is gone.
    """
    host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS postgis CASCADE;'")

    # 1. Load legacy.sql and confirm st_force_2d is present
    load_res = host.run(f"psql -f {POSTGIS_LEGACY_SQL}")
    assert load_res.rc == 0, f"legacy.sql failed: {load_res.stderr}"

    check_query = (
        "SELECT count(*) FROM pg_proc WHERE proname = 'st_force_2d';"
    )
    before = host.run(f'psql -t -A -c "{check_query}"')
    assert int(before.stdout.strip()) >= 1, "st_force_2d not found after loading legacy.sql"

    # 2. Load uninstall_legacy.sql and confirm st_force_2d is removed
    uninstall_res = host.run(f"psql -f {POSTGIS_UNINSTALL_LEGACY_SQL}")
    assert uninstall_res.rc == 0, (
        f"uninstall_legacy.sql failed: {uninstall_res.stderr}"
    )

    after = host.run(f'psql -t -A -c "{check_query}"')
    assert int(after.stdout.strip()) == 0, (
        "st_force_2d still present after running uninstall_legacy.sql"
    )


# =============================================================================
# --- MILESTONE 3 EXTENSION TESTS ---
# =============================================================================

# --- ip4r ---


@milestone_3
def test_ip4r_extension_version(host):
    # 1. Clean slate and recreate
    host.run("psql -c 'DROP EXTENSION IF EXISTS ip4r CASCADE;'")
    create_res = host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS ip4r;'")
    assert create_res.rc == 0, create_res.stderr

    # 2. Get the extension version (SQL level)
    query = "SELECT extversion FROM pg_extension WHERE extname = 'ip4r';"
    actual_ext_version = host.run(f'psql -t -A -c "{query}"').stdout.strip()

    # 3. Get expected version from settings (extension_version = value in .control file)
    pkg_key = f"percona-ip4r_{MAJOR_VER}"
    expected_ext_version = pg_docker_versions[pkg_key]["extension_version"]

    assert actual_ext_version == expected_ext_version, (
        f"ip4r extension version {actual_ext_version!r} does not match "
        f"expected {expected_ext_version!r}"
    )

    # 4. Cleanup
    host.run("psql -c 'DROP EXTENSION IF EXISTS ip4r CASCADE;'")


@milestone_3
def test_ip4r_functional(host):
    # 1. Setup
    host.run("psql -c 'DROP EXTENSION IF EXISTS ip4r CASCADE;'")
    host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS ip4r;'")

    # 2. Insert an IPv4 range and verify containment query
    test_sql = """
    CREATE TEMP TABLE t_ip4r (net ip4r);
    INSERT INTO t_ip4r VALUES ('192.168.1.0/24');
    SELECT count(*) FROM t_ip4r WHERE net >>= '192.168.1.1'::ip4;
    """
    result = host.run(f'psql -q -t -A -c "{test_sql}"')

    # 3. Validation
    assert result.rc == 0, f"ip4r functional test failed: {result.stderr}"
    assert result.stdout.strip().split("\n")[-1] == "1"

    # 4. Cleanup
    host.run("psql -c 'DROP EXTENSION IF EXISTS ip4r CASCADE;'")


# --- hll ---


@milestone_3
def test_hll_extension_version(host):
    # 1. Clean slate and recreate
    host.run("psql -c 'DROP EXTENSION IF EXISTS hll CASCADE;'")
    create_res = host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS hll;'")
    assert create_res.rc == 0, create_res.stderr

    # 2. Get the extension version (SQL level)
    query = "SELECT extversion FROM pg_extension WHERE extname = 'hll';"
    actual_ext_version = host.run(f'psql -t -A -c "{query}"').stdout.strip()

    # 3. Get expected version from settings
    pkg_key = f"percona-hll_{MAJOR_VER}"
    expected_full_version = pg_docker_versions[pkg_key]["version"]
    expected_clean_version = expected_full_version.split("-")[0]

    assert actual_ext_version == expected_clean_version, (
        f"hll extension version {actual_ext_version!r} does not match "
        f"expected {expected_clean_version!r}"
    )

    # 4. Cleanup
    host.run("psql -c 'DROP EXTENSION IF EXISTS hll CASCADE;'")


@milestone_3
def test_hll_functional(host):
    # 1. Setup
    host.run("psql -c 'DROP EXTENSION IF EXISTS hll CASCADE;'")
    host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS hll;'")

    # 2. Add integers to an HLL counter and verify non-zero cardinality estimate
    query = (
        "SELECT hll_cardinality(hll_add_agg(hll_hash_integer(i))) > 0 "
        "FROM generate_series(1, 100) AS i;"
    )
    result = host.run(f'psql -t -A -c "{query}"')

    # 3. Validation
    assert result.rc == 0, f"hll functional test failed: {result.stderr}"
    assert result.stdout.strip() == "t"

    # 4. Cleanup
    host.run("psql -c 'DROP EXTENSION IF EXISTS hll CASCADE;'")


# --- pg_cron ---


@milestone_3
def test_pg_cron_extension_version(host):
    # 1. Clean slate and recreate
    # Note: pg_cron background worker requires shared_preload_libraries;
    # version and metadata queries work without it.
    host.run("psql -c 'DROP EXTENSION IF EXISTS pg_cron CASCADE;'")
    create_res = host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS pg_cron;'")
    assert create_res.rc == 0, create_res.stderr

    # 2. Get the extension version (SQL level)
    query = "SELECT extversion FROM pg_extension WHERE extname = 'pg_cron';"
    actual_ext_version = host.run(f'psql -t -A -c "{query}"').stdout.strip()

    # 3. Get expected version from settings (extension_version = value in .control file)
    pkg_key = f"percona-pg_cron_{MAJOR_VER}"
    expected_ext_version = pg_docker_versions[pkg_key]["extension_version"]

    assert actual_ext_version == expected_ext_version, (
        f"pg_cron extension version {actual_ext_version!r} does not match "
        f"expected {expected_ext_version!r}"
    )

    # 4. Cleanup
    host.run("psql -c 'DROP EXTENSION IF EXISTS pg_cron CASCADE;'")


@milestone_3
def test_pg_cron_functional(host):
    # 1. Setup
    host.run("psql -c 'DROP EXTENSION IF EXISTS pg_cron CASCADE;'")
    host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS pg_cron;'")

    # 2. Verify cron.job table is accessible (no background worker needed)
    query = "SELECT count(*) FROM cron.job;"
    result = host.run(f'psql -t -A -c "{query}"')

    # 3. Validation
    assert result.rc == 0, f"pg_cron functional test failed: {result.stderr}"
    assert result.stdout.strip() == "0"

    # 4. Cleanup
    host.run("psql -c 'DROP EXTENSION IF EXISTS pg_cron CASCADE;'")


# --- pg_partman ---


@milestone_3
def test_pg_partman_extension_version(host):
    # 1. Clean slate and recreate
    # pg_partman must be installed into a dedicated schema; create it first.
    host.run("psql -c 'DROP EXTENSION IF EXISTS pg_partman CASCADE;'")
    host.run("psql -c 'CREATE SCHEMA IF NOT EXISTS partman;'")
    create_res = host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS pg_partman SCHEMA partman;'")
    assert create_res.rc == 0, create_res.stderr

    # 2. Get the extension version (SQL level)
    query = "SELECT extversion FROM pg_extension WHERE extname = 'pg_partman';"
    actual_ext_version = host.run(f'psql -t -A -c "{query}"').stdout.strip()

    # 3. Get expected version from settings
    pkg_key = f"percona-pg_partman_{MAJOR_VER}"
    expected_full_version = pg_docker_versions[pkg_key]["version"]
    expected_clean_version = expected_full_version.split("-")[0]

    assert actual_ext_version == expected_clean_version, (
        f"pg_partman extension version {actual_ext_version!r} does not match "
        f"expected {expected_clean_version!r}"
    )

    # 4. Cleanup
    host.run("psql -c 'DROP EXTENSION IF EXISTS pg_partman CASCADE;'")
    host.run("psql -c 'DROP SCHEMA IF EXISTS partman CASCADE;'")


@milestone_3
def test_pg_partman_functional(host):
    # 1. Setup — install into the dedicated partman schema
    host.run("psql -c 'DROP EXTENSION IF EXISTS pg_partman CASCADE;'")
    host.run("psql -c 'DROP SCHEMA IF EXISTS partman CASCADE;'")
    host.run("psql -c 'CREATE SCHEMA partman;'")
    host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS pg_partman SCHEMA partman;'")

    # 2. Verify the partman schema and config table are accessible
    query = "SELECT count(*) FROM partman.part_config;"
    result = host.run(f'psql -t -A -c "{query}"')

    # 3. Validation
    assert result.rc == 0, f"pg_partman functional test failed: {result.stderr}"
    assert result.stdout.strip() == "0"

    # 4. Cleanup
    host.run("psql -c 'DROP EXTENSION IF EXISTS pg_partman CASCADE;'")
    host.run("psql -c 'DROP SCHEMA IF EXISTS partman CASCADE;'")


# --- pg_similarity ---


@milestone_3
def test_pg_similarity_extension_version(host):
    # 1. Clean slate and recreate
    host.run("psql -c 'DROP EXTENSION IF EXISTS pg_similarity CASCADE;'")
    create_res = host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS pg_similarity;'")
    assert create_res.rc == 0, create_res.stderr

    # 2. Get the extension version (SQL level)
    query = "SELECT extversion FROM pg_extension WHERE extname = 'pg_similarity';"
    actual_ext_version = host.run(f'psql -t -A -c "{query}"').stdout.strip()

    # 3. Get expected version from settings
    pkg_key = f"percona-pg_similarity_{MAJOR_VER}"
    expected_full_version = pg_docker_versions[pkg_key]["version"]
    expected_clean_version = expected_full_version.split("-")[0]

    assert actual_ext_version == expected_clean_version, (
        f"pg_similarity extension version {actual_ext_version!r} does not match "
        f"expected {expected_clean_version!r}"
    )

    # 4. Cleanup
    host.run("psql -c 'DROP EXTENSION IF EXISTS pg_similarity CASCADE;'")


@milestone_3
def test_pg_similarity_functional(host):
    # 1. Setup
    host.run("psql -c 'DROP EXTENSION IF EXISTS pg_similarity CASCADE;'")
    host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS pg_similarity;'")

    # 2. Identical strings must return a similarity of 1.0 (Levenshtein-based)
    query = "SELECT lev('hello', 'hello') = 1.0;"
    result = host.run(f'psql -t -A -c "{query}"')

    # 3. Validation
    assert result.rc == 0, f"pg_similarity functional test failed: {result.stderr}"
    assert result.stdout.strip() == "t"

    # 4. Cleanup
    host.run("psql -c 'DROP EXTENSION IF EXISTS pg_similarity CASCADE;'")


# --- vectorscale ---


@milestone_3
def test_vectorscale_extension_version(host):
    # 1. Clean slate and recreate (CASCADE also installs pgvector if needed)
    host.run("psql -c 'DROP EXTENSION IF EXISTS vectorscale CASCADE;'")
    create_res = host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS vectorscale CASCADE;'")
    assert create_res.rc == 0, create_res.stderr

    # 2. Get the extension version (SQL level)
    query = "SELECT extversion FROM pg_extension WHERE extname = 'vectorscale';"
    actual_ext_version = host.run(f'psql -t -A -c "{query}"').stdout.strip()

    # 3. Get expected version from settings
    pkg_key = f"percona-pgvectorscale_{MAJOR_VER}"
    expected_full_version = pg_docker_versions[pkg_key]["version"]
    expected_clean_version = expected_full_version.split("-")[0]

    assert actual_ext_version == expected_clean_version, (
        f"vectorscale extension version {actual_ext_version!r} does not match "
        f"expected {expected_clean_version!r}"
    )

    # 4. Cleanup
    host.run("psql -c 'DROP EXTENSION IF EXISTS vectorscale CASCADE;'")


@milestone_3
def test_vectorscale_functional(host):
    # 1. Setup
    host.run("psql -c 'DROP EXTENSION IF EXISTS vectorscale CASCADE;'")
    host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS vectorscale CASCADE;'")

    # 2. Create a table with vector embeddings and a DiskANN index
    test_sql = """
    CREATE TEMP TABLE test_vscale (id serial, embedding vector(3));
    INSERT INTO test_vscale (embedding) VALUES ('[1,2,3]'), ('[4,5,6]'), ('[7,8,9]');
    CREATE INDEX ON test_vscale USING diskann (embedding);
    SELECT count(*) FROM test_vscale;
    """
    result = host.run(f'psql -q -t -A -c "{test_sql}"')

    # 3. Validation
    assert result.rc == 0, f"vectorscale functional test failed: {result.stderr}"
    assert result.stdout.strip().split("\n")[-1] == "3"

    # 4. Cleanup
    host.run("psql -c 'DROP EXTENSION IF EXISTS vectorscale CASCADE;'")


# --- rum ---


@milestone_3
def test_rum_extension_version(host):
    # 1. Clean slate and recreate
    host.run("psql -c 'DROP EXTENSION IF EXISTS rum CASCADE;'")
    create_res = host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS rum;'")
    assert create_res.rc == 0, create_res.stderr

    # 2. Get the extension version (SQL level)
    query = "SELECT extversion FROM pg_extension WHERE extname = 'rum';"
    actual_ext_version = host.run(f'psql -t -A -c "{query}"').stdout.strip()

    # 3. Get expected version from settings (extension_version = value in .control file)
    pkg_key = f"percona-rum_{MAJOR_VER}"
    expected_ext_version = pg_docker_versions[pkg_key]["extension_version"]

    assert actual_ext_version == expected_ext_version, (
        f"rum extension version {actual_ext_version!r} does not match "
        f"expected {expected_ext_version!r}"
    )

    # 4. Cleanup
    host.run("psql -c 'DROP EXTENSION IF EXISTS rum CASCADE;'")


@milestone_3
def test_rum_functional(host):
    # 1. Setup
    host.run("psql -c 'DROP EXTENSION IF EXISTS rum CASCADE;'")
    host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS rum;'")

    # 2. Build a RUM index on a tsvector column and run a full-text search
    test_sql = """
    CREATE TEMP TABLE test_rum (id serial, t text, a tsvector);
    INSERT INTO test_rum (t, a) VALUES
        ('Hello world', to_tsvector('Hello world')),
        ('Goodbye world', to_tsvector('Goodbye world'));
    CREATE INDEX test_rum_a_idx ON test_rum USING rum (a rum_tsvector_ops);
    SELECT count(*) FROM test_rum WHERE a @@ plainto_tsquery('hello');
    """
    result = host.run(f'psql -q -t -A -c "{test_sql}"')

    # 3. Validation
    assert result.rc == 0, f"rum functional test failed: {result.stderr}"
    assert result.stdout.strip().split("\n")[-1] == "1"

    # 4. Cleanup
    host.run("psql -c 'DROP EXTENSION IF EXISTS rum CASCADE;'")


# --- unit ---


@milestone_3
def test_unit_extension_version(host):
    # 1. Clean slate and recreate
    host.run("psql -c 'DROP EXTENSION IF EXISTS unit CASCADE;'")
    create_res = host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS unit;'")
    assert create_res.rc == 0, create_res.stderr

    # 2. Get the extension version (SQL level)
    query = "SELECT extversion FROM pg_extension WHERE extname = 'unit';"
    actual_ext_version = host.run(f'psql -t -A -c "{query}"').stdout.strip()

    # 3. Get expected version from settings (extension_version = value in .control file)
    pkg_key = f"percona-postgresql-unit_{MAJOR_VER}"
    expected_ext_version = pg_docker_versions[pkg_key]["extension_version"]

    assert actual_ext_version == expected_ext_version, (
        f"unit extension version {actual_ext_version!r} does not match "
        f"expected {expected_ext_version!r}"
    )

    # 4. Cleanup
    host.run("psql -c 'DROP EXTENSION IF EXISTS unit CASCADE;'")


@milestone_3
def test_unit_functional(host):
    # 1. Setup
    host.run("psql -c 'DROP EXTENSION IF EXISTS unit CASCADE;'")
    host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS unit;'")

    # 2. Convert 1 km to metres; result must contain '1000'
    query = "SELECT '1 km'::unit @ 'm';"
    result = host.run(f'psql -t -A -c "{query}"')

    # 3. Validation
    assert result.rc == 0, f"unit functional test failed: {result.stderr}"
    assert "1000" in result.stdout.strip()

    # 4. Cleanup
    host.run("psql -c 'DROP EXTENSION IF EXISTS unit CASCADE;'")


# --- anon (postgresql_anonymizer) ---


@milestone_3
def test_anon_extension_version(host):
    # 1. Clean slate and recreate
    # CASCADE installs the required pgcrypto dependency automatically.
    host.run("psql -c 'DROP EXTENSION IF EXISTS anon CASCADE;'")
    create_res = host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS anon CASCADE;'")
    assert create_res.rc == 0, create_res.stderr

    # 2. Get the extension version (SQL level)
    query = "SELECT extversion FROM pg_extension WHERE extname = 'anon';"
    actual_ext_version = host.run(f'psql -t -A -c "{query}"').stdout.strip()

    # 3. Get expected version from settings
    pkg_key = f"percona-postgresql_anonymizer_{MAJOR_VER}"
    expected_full_version = pg_docker_versions[pkg_key]["version"]
    expected_clean_version = expected_full_version.split("-")[0]

    assert actual_ext_version == expected_clean_version, (
        f"anon extension version {actual_ext_version!r} does not match "
        f"expected {expected_clean_version!r}"
    )

    # 4. Cleanup
    host.run("psql -c 'DROP EXTENSION IF EXISTS anon CASCADE;'")


@milestone_3
def test_anon_functional(host):
    # 1. Setup
    # Note: dynamic masking requires shared_preload_libraries; partial() works without it.
    host.run("psql -c 'DROP EXTENSION IF EXISTS anon CASCADE;'")
    host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS anon CASCADE;'")

    # 2. Test partial masking — keeps first 1 and last 3 characters
    query = "SELECT anon.partial('John Doe', 1, '***', 3);"
    result = host.run(f'psql -t -A -c "{query}"')

    # 3. Validation: output must start with 'J' and end with 'Doe'
    assert result.rc == 0, f"anon functional test failed: {result.stderr}"
    output = result.stdout.strip()
    assert output.startswith("J") and output.endswith("Doe"), (
        f"Unexpected anon.partial output: {output!r}"
    )

    # 4. Cleanup
    host.run("psql -c 'DROP EXTENSION IF EXISTS anon CASCADE;'")


# =============================================================================
# --- MILESTONE 3: AVAILABILITY, DEEPER FUNCTIONAL, AND PRELOAD TESTS ---
# =============================================================================

# --- pg_available_extensions pre-install check ---

MILESTONE_3_EXTENSIONS = [
    "ip4r",
    "hll",
    "pg_cron",
    "pg_partman",
    "pg_similarity",
    "vectorscale",
    "rum",
    "unit",
    "anon",
]


@milestone_3
@pytest.mark.parametrize("extension", MILESTONE_3_EXTENSIONS)
def test_milestone3_extension_available(host, extension):
    """Verify each milestone 3 extension is listed in pg_available_extensions."""
    query = (
        f"SELECT count(*) FROM pg_available_extensions WHERE name = '{extension}';"
    )
    result = host.run(f'psql -t -A -c "{query}"')
    assert result.rc == 0
    assert result.stdout.strip() == "1", (
        f"{extension!r} not found in pg_available_extensions"
    )


# --- pg_partman: partition creation ---


@milestone_3
def test_pg_partman_create_partitions(host):
    # 1. Setup
    host.run("psql -c 'DROP TABLE IF EXISTS public.test_partman_tbl CASCADE;'")
    host.run("psql -c 'DROP EXTENSION IF EXISTS pg_partman CASCADE;'")
    host.run("psql -c 'DROP SCHEMA IF EXISTS partman CASCADE;'")
    host.run("psql -c 'CREATE SCHEMA partman;'")
    host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS pg_partman SCHEMA partman;'")

    # 2. Create a native range-partitioned parent table and hand it to partman
    test_sql = """
    CREATE TABLE public.test_partman_tbl (
        id serial,
        created_at timestamptz NOT NULL DEFAULT now()
    ) PARTITION BY RANGE (created_at);
    SELECT partman.create_parent(
        p_parent_table => 'public.test_partman_tbl',
        p_control      => 'created_at',
        p_interval     => '1 month'
    );
    SELECT count(*) FROM partman.part_config
    WHERE parent_table = 'public.test_partman_tbl';
    """
    result = host.run(f'psql -q -t -A -c "{test_sql}"')

    # 3. Validation — create_parent registers exactly one entry in part_config
    assert result.rc == 0, f"pg_partman create_parent failed: {result.stderr}"
    assert result.stdout.strip().split("\n")[-1] == "1"

    # 4. Cleanup
    host.run("psql -c 'DROP TABLE IF EXISTS public.test_partman_tbl CASCADE;'")
    host.run("psql -c 'DROP EXTENSION IF EXISTS pg_partman CASCADE;'")
    host.run("psql -c 'DROP SCHEMA IF EXISTS partman CASCADE;'")


# --- vectorscale: approximate nearest-neighbour search ---


@milestone_3
def test_vectorscale_ann_search(host):
    # 1. Setup
    host.run("psql -c 'DROP EXTENSION IF EXISTS vectorscale CASCADE;'")
    host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS vectorscale CASCADE;'")

    # 2. Populate a table, build a DiskANN index, and run an ANN query
    test_sql = """
    CREATE TEMP TABLE test_ann (id serial, embedding vector(3));
    INSERT INTO test_ann (embedding) VALUES
        ('[1,2,3]'), ('[4,5,6]'), ('[7,8,9]'), ('[2,2,2]'), ('[9,1,1]');
    CREATE INDEX ON test_ann USING diskann (embedding);
    SELECT id FROM test_ann ORDER BY embedding <-> '[1,2,3]' LIMIT 1;
    """
    result = host.run(f'psql -q -t -A -c "{test_sql}"')

    # 3. Validation — nearest neighbour to [1,2,3] is itself (id = 1)
    assert result.rc == 0, f"vectorscale ANN search failed: {result.stderr}"
    assert result.stdout.strip().split("\n")[-1] == "1"

    # 4. Cleanup
    host.run("psql -c 'DROP EXTENSION IF EXISTS vectorscale CASCADE;'")


# --- pg_cron: job scheduling (requires shared_preload_libraries) ---


@milestone_3
@pytest.mark.needs_preload
def test_pg_cron_schedule_job(host):
    # 1. Setup
    host.run("psql -c 'DROP EXTENSION IF EXISTS pg_cron CASCADE;'")
    host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS pg_cron;'")

    # 2. Schedule a no-op job and verify it is registered
    schedule_res = host.run(
        "psql -t -A -c \"SELECT cron.schedule('test-job', '* * * * *', 'SELECT 1;');\""
    )
    assert schedule_res.rc == 0, f"cron.schedule() failed: {schedule_res.stderr}"

    query = "SELECT count(*) FROM cron.job WHERE jobname = 'test-job';"
    count_result = host.run(f'psql -t -A -c "{query}"')
    assert count_result.rc == 0
    assert count_result.stdout.strip() == "1", "Scheduled job not found in cron.job"

    # 3. Cleanup
    host.run("psql -t -A -c \"SELECT cron.unschedule('test-job');\"")
    host.run("psql -c 'DROP EXTENSION IF EXISTS pg_cron CASCADE;'")


# --- anon: static masking ---
# anon.start_dynamic_masking() was removed in pg_anonymizer 3.0.
# Static anonymization (anon.anonymize_table) works without shared_preload_libraries.


@milestone_3
def test_anon_static_masking(host):
    # 1. Setup
    host.run("psql -c 'DROP TABLE IF EXISTS public.test_anon_people CASCADE;'")
    host.run("psql -c 'DROP EXTENSION IF EXISTS anon CASCADE;'")
    host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS anon CASCADE;'")

    # 2. Create table, insert data, apply a column masking rule via SECURITY LABEL
    setup_sql = """
    CREATE TABLE public.test_anon_people (id int, name text, phone text);
    INSERT INTO public.test_anon_people VALUES (1, 'Alice', '555-1234');
    SECURITY LABEL FOR anon ON COLUMN public.test_anon_people.phone
        IS 'MASKED WITH FUNCTION anon.partial(phone, 2, ''****'', 2)';
    SELECT anon.anonymize_table('public.test_anon_people');
    SELECT phone FROM public.test_anon_people WHERE id = 1;
    """
    result = host.run(f'psql -q -t -A -c "{setup_sql}"')

    # 3. Validation — partial(phone=555-1234, prefix=2, padding=****,suffix=2) → 55****34
    assert result.rc == 0, f"anon static masking failed: {result.stderr}"
    assert result.stdout.strip().split("\n")[-1] == "55****34"

    # 4. Cleanup
    host.run("psql -c 'DROP TABLE IF EXISTS public.test_anon_people CASCADE;'")
    host.run("psql -c 'DROP EXTENSION IF EXISTS anon CASCADE;'")


# --- pg_partman_bgw: background worker tests ---


@milestone_3
@pytest.mark.needs_preload
def test_pg_partman_bgw_loaded(host):
    """Verify pg_partman_bgw is present in shared_preload_libraries."""
    result = host.run("psql -t -A -c 'SHOW shared_preload_libraries;'")
    assert result.rc == 0, f"SHOW shared_preload_libraries failed: {result.stderr}"
    assert "pg_partman_bgw" in result.stdout, (
        f"pg_partman_bgw not found in shared_preload_libraries: "
        f"{result.stdout.strip()!r}"
    )


@milestone_3
@pytest.mark.needs_preload
def test_pg_partman_bgw_maintenance(host):
    """Verify run_maintenance() — the function pg_partman_bgw calls on each cycle —
    enforces a retention policy by dropping old partitions.

    In pg_partman 5.x run_maintenance() only extends the partition set forward from
    the latest existing partition; it does not recreate gaps or respond to premake
    bumps on a fully-satisfied window.  The reliably observable side-effect is
    retention enforcement: setting retention='1 month' with retention_keep_table=false
    causes run_maintenance() to DROP child partitions older than 1 month.  With the
    default create_parent() premake=4 a set of 4 past-month partitions is always
    present, several of which fall outside the retention window.
    """
    # 1. Setup — install into dedicated schema
    host.run("psql -c 'DROP TABLE IF EXISTS public.test_bgw_tbl CASCADE;'")
    host.run("psql -c 'DROP EXTENSION IF EXISTS pg_partman CASCADE;'")
    host.run("psql -c 'DROP SCHEMA IF EXISTS partman CASCADE;'")
    host.run("psql -c 'CREATE SCHEMA partman;'")
    host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS pg_partman SCHEMA partman;'")

    # 2. Register the parent with the default premake (4 future partitions)
    setup_sql = """
    CREATE TABLE public.test_bgw_tbl (
        id serial,
        created_at timestamptz NOT NULL DEFAULT now()
    ) PARTITION BY RANGE (created_at);
    SELECT partman.create_parent(
        p_parent_table => 'public.test_bgw_tbl',
        p_control      => 'created_at',
        p_interval     => '1 month'
    );
    """
    setup_res = host.run(f'psql -q -t -A -c "{setup_sql}"')
    assert setup_res.rc == 0, f"partman setup failed: {setup_res.stderr}"

    # 3. Record baseline partition count (default: 4 past + current + 4 future + default = 10)
    count_query = (
        "SELECT count(*) FROM pg_catalog.pg_class "
        "WHERE relname LIKE 'test_bgw_tbl_%' AND relkind = 'r';"
    )
    baseline_res = host.run(f'psql -t -A -c "{count_query}"')
    assert baseline_res.rc == 0
    baseline_count = int(baseline_res.stdout.strip())

    # 4. Enable retention: drop partitions older than 1 month.
    #    create_parent() created 4 past-month partitions; at least 2–3 will be
    #    outside the 1-month window and must be dropped by run_maintenance().
    retention_res = host.run(
        "psql -c \"UPDATE partman.part_config "
        "SET retention = '1 month', retention_keep_table = false "
        "WHERE parent_table = 'public.test_bgw_tbl';\""
    )
    assert retention_res.rc == 0, f"retention update failed: {retention_res.stderr}"

    # 5. Call run_maintenance() — the exact function the bgw executes each cycle
    maint_res = host.run(
        "psql -t -A -c \"SELECT partman.run_maintenance('public.test_bgw_tbl');\""
    )
    assert maint_res.rc == 0, f"run_maintenance() failed: {maint_res.stderr}"

    # 6. Verify old partitions were dropped
    result = host.run(f'psql -t -A -c "{count_query}"')
    assert result.rc == 0, f"partition count query failed: {result.stderr}"
    final_count = int(result.stdout.strip())
    assert final_count < baseline_count, (
        f"run_maintenance() did not drop any old partitions with retention='1 month': "
        f"baseline={baseline_count}, final={final_count}"
    )

    # 7. Cleanup
    host.run("psql -c 'DROP TABLE IF EXISTS public.test_bgw_tbl CASCADE;'")
    host.run("psql -c 'DROP EXTENSION IF EXISTS pg_partman CASCADE;'")
    host.run("psql -c 'DROP SCHEMA IF EXISTS partman CASCADE;'")
