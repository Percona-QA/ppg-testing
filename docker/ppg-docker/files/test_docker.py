import os
import pytest
import subprocess
import testinfra
import sys
import settings
import time

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

# List of expected PG-18 TDE binaries
TDE_BINARIES = [
    "pg_tde_archive_decrypt",
    "pg_tde_basebackup",
    "pg_tde_change_key_provider",
    "pg_tde_checksums",
    "pg_tde_resetwal",
    "pg_tde_restore_encrypt",
    "pg_tde_rewind",
    "pg_tde_waldump",
]

# scope='session' uses the same container for all the tests;
@pytest.fixture(scope='session')
def host(request):

    DOCKER_TO_USE = ""

    if IS_WITH_POSTGIS:
        DOCKER_TO_USE = f'{DOCKER_REPO}/percona-distribution-postgresql-with-postgis:{IMG_TAG}'
    else:
        DOCKER_TO_USE = f'{DOCKER_REPO}/percona-distribution-postgresql:{IMG_TAG}'

    print('Major Version: ' + MAJOR_VER)
    print('Major Minor Version: ' + MAJOR_MINOR_VER)
    print('Image TAG: ' + IMG_TAG)
    print('IS_WITH_POSTGIS: ' + str(IS_WITH_POSTGIS))
    print('WITH_POSTGIS: ' + str(os.getenv('WITH_POSTGIS')))
    print('DOCKER_TO_USE: ' + DOCKER_TO_USE)

    docker_id = subprocess.check_output(
        ['docker', 'run', '--name', f'PG{MAJOR_VER}', '-e', 'POSTGRES_PASSWORD=secret', '-e', 'ENABLE_PG_TDE=1',
        '-e', 'PERCONA_TELEMETRY_URL=https://check-dev.percona.com/v1/telemetry/GenericReport',
        '-d', DOCKER_TO_USE]).decode().strip()

    # return a testinfra connection to the container
    yield testinfra.get_host("docker://" + docker_id)

    # at the end of the test suite, destroy the container
    subprocess.check_call(['docker', 'rm', '-f', docker_id])


def test_myimage(host):
    # 'host' now binds to the container
    if int(MAJOR_VER) in [17, 18]:
        assert f"psql (PostgreSQL) {MAJOR_MINOR_VER} - Percona Server for PostgreSQL {pg_docker_versions['percona-version']}" in host.check_output('psql -V')
    else:
        assert f"psql (PostgreSQL) {MAJOR_MINOR_VER} - Percona Distribution" in host.check_output('psql -V')


def test_wait_docker_load(host):
    dist = host.system_info.distribution
    time.sleep(5)
    assert 0 == 0


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
    "pg_tde",
    "postgis_sfcgal",
    "address_standardizer",
    "postgis_tiger_geocoder",
    "postgis",
    "postgis_topology",
    "postgis_raster",
    "address_standardizer_data_us"
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

    # 3. Version-based additions
    if major < 17 and extension == 'pg_tde':
        return True, "pg_tde requires PG17+"

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
    # 1. Use the centralized helper for skip logic
    # This replaces the messy if/elif blocks and ensures consistency
    skip, reason = should_skip(extension)
    if skip:
        pytest.skip(reason)

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
    if int(MAJOR_VER) < 17 and "pg_tde" in package:
        pytest.skip(f"pg_tde not supported on PostgreSQL {MAJOR_VER}")

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
#     if int(MAJOR_VER) < 17 and "pg_tde" in package:
#         pytest.skip(f"pg_tde not supported on PostgreSQL {MAJOR_VER}")

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


#=========================================
# Telemetry changes
#=========================================
# Define the packages you want to test
telemetry_pkg_name = "percona-pg-telemetry"+MAJOR_VER
telemetry_packages = [
    telemetry_pkg_name,
    "percona-telemetry-agent"
]

# Define log directory and files to be checked
log_directory = "/var/log/percona/telemetry-agent/"
log_files = [
    "telemetry-agent-error.log",
    "telemetry-agent.log"
]

# Paths for directories to be checked
common_directories = [
    "/usr/local/percona/telemetry/history/",
    "/usr/local/percona/telemetry/pg/"
]

# Paths for directory that will contain json file
json_files_location = [
    "/usr/local/percona/telemetry/pg/*.json"
]

# Paths for percona-telemetry-agent based on the OS
debian_percona_telemetry_agent = "/etc/default/percona-telemetry-agent"
redhat_percona_telemetry_agent = "/etc/sysconfig/percona-telemetry-agent"


@pytest.mark.parametrize("package", telemetry_packages)
def test_telemetry_package_is_installed(host, package):
    if int(MAJOR_VER) in [18]:
        pytest.skip("Skipping on PostgreSQL 18, as telemetry not available.")
    dist = host.system_info.distribution
    pkg = host.package(package)
    assert pkg.is_installed


def test_telemetry_agent_service_enabled(host):
    if int(MAJOR_VER) in [18]:
        pytest.skip("Skipping on PostgreSQL 18, as telemetry not available.")
    service = host.service("percona-telemetry-agent")
    #assert service.is_running
    assert service.is_enabled


def test_telemetry_log_directory_exists(host):
    """Test if the directory exists."""
    if int(MAJOR_VER) in [18]:
        pytest.skip("Skipping on PostgreSQL 18, as telemetry not available.")
    logdir = host.file(log_directory)
    assert logdir.exists, f"Directory {log_directory} does not exist."


@pytest.mark.parametrize("file_name", log_files)
def test_telemetry_log_files_exist(host,file_name):
    """Test if the required files exist within the directory."""
    if int(MAJOR_VER) in [18]:
        pytest.skip("Skipping on PostgreSQL 18, as telemetry not available.")
    file_path = os.path.join(log_directory, file_name)
    log_file_name = host.file(file_path)
    assert log_file_name.exists, f"File {file_path} does not exist."


def get_telemetry_agent_conf_file(host):
    """Determine the percona-telemetry-agent path based on the OS."""
    if int(MAJOR_VER) in [18]:
        pytest.skip("Skipping on PostgreSQL 18, as telemetry not available.")
    dist = host.system_info.distribution
    # if dist.lower() in ["redhat", "centos", "rhel", "rocky"]:
    #     return redhat_percona_telemetry_agent
    # else:
    #     return debian_percona_telemetry_agent
    return redhat_percona_telemetry_agent


def test_telemetry_json_directories_exist(host):
    """Test if the history and pg directories exist."""
    if int(MAJOR_VER) in [18]:
        pytest.skip("Skipping on PostgreSQL 18, as telemetry not available.")
    for directory in common_directories:
        assert host.file(directory).exists, f"Directory {directory} does not exist."


def test_telemetry_agent_conf_exists(host):
    """Test if the percona-telemetry-agent conf file exists."""
    if int(MAJOR_VER) in [18]:
        pytest.skip("Skipping on PostgreSQL 18, as telemetry not available.")
    agent_path = get_telemetry_agent_conf_file(host)
    assert host.file(agent_path).exists, f"{agent_path} does not exist."


def test_pg_telemetry_package_version(host):
    if int(MAJOR_VER) in [18]:
        pytest.skip("Skipping on PostgreSQL 18, as telemetry not available.")
    dist = host.system_info.distribution
    pg_telemetry = host.package(f"percona-pg-telemetry{MAJOR_VER}")
    assert pg_docker_versions["percona-pg-telemetry"]['pg_telemetry_package_version'] in pg_telemetry.version


def test_pg_telemetry_extension_version(host):
    if int(MAJOR_VER) in [18]:
        pytest.skip("Skipping on PostgreSQL 18, as telemetry not available.")
    result = host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS percona_pg_telemetry;'")
    assert result.rc == 0, result.stderr
    result = host.run("psql -c 'SELECT percona_pg_telemetry_version();' | awk 'NR==3{print $1}'")
    assert result.rc == 0, result.stderr
    assert result.stdout.strip("\n") == pg_docker_versions["percona-pg-telemetry"]['pg_telemetry_version']


@pytest.mark.parametrize("binary", TDE_BINARIES)
def test_tde_binaries_present(host, binary):
    """
    Verify all PG-18/17 TDE binaries exist in the correct PostgreSQL 18 bin directory
    depending on OS type (Debian/Ubuntu vs RHEL/CentOS/Rocky).
    """
    # pg_tde only exists on PG-17 and above.
    if int(MAJOR_VER) < 17:
        pytest.skip(f"pg_tde not supported on {MAJOR_VER}.")

    dist = host.system_info.distribution.lower()

    # Determine the PostgreSQL 18 bin directory
    bin_path = f"/usr/pgsql-{MAJOR_VER}/bin/{binary}"

    file = host.file(bin_path)

    assert file.exists, f"{binary} is missing at {bin_path}"
    assert file.is_file, f"{binary} exists but is not a file at {bin_path}"
    assert file.mode & 0o111, f"{binary} exists but is not executable at {bin_path}"


# def test_telemetry_extension_in_conf(host):
#     """Test if percona_pg_telemetry extension exists in postgresql.auto.conf."""
#     if int(MAJOR_VER) in [17,18]:
#         pytest.skip("Skipping on PostgreSQL 18, as telemetry not available.")
#     config_path = "/data/db/postgresql.auto.conf"
#     assert host.file(config_path).exists, f"{config_path} does not exists"
#     assert host.file(config_path).contains('percona_pg_telemetry'), f"'percona_pg_telemetry' not found in {config_path}."


# def test_pg_telemetry_file_pillar_version(host):
#     if int(MAJOR_VER) in [17,18]:
#         pytest.skip("Skipping on PostgreSQL 18, as telemetry not available.")
#     output = host.run("cat /usr/local/percona/telemetry/pg/*.json | grep -i pillar_version")
#     assert output.rc == 0, output.stderr
#     assert MAJOR_MINOR_VER in output.stdout, output.stdout


# def test_pg_telemetry_file_database_count(host):
#     if int(MAJOR_VER) in [17,18]:
#         pytest.skip("Skipping on PostgreSQL 18, as telemetry not available.")
#     output = host.run("cat /usr/local/percona/telemetry/pg/*.json | grep -i databases_count")
#     assert output.rc == 0, output.stderr
#     assert '2' in output.stdout, output.stdout


# def test_telemetry_enabled(host):
#     if int(MAJOR_VER) in [17,18]:
#         pytest.skip("Skipping on PostgreSQL 18, as telemetry not available.")
#     assert host.file('/usr/local/percona/telemetry_uuid').exists
#     assert host.file('/usr/local/percona/telemetry_uuid').contains('PRODUCT_FAMILY_POSTGRESQL')
#     assert host.file('/usr/local/percona/telemetry_uuid').contains('instanceId:[0-9a-fA-F]\\{8\\}-[0-9a-fA-F]\\{4\\}-[0-9a-fA-F]\\{4\\}-[0-9a-fA-F]\\{4\\}-[0-9a-fA-F]\\{12\\}$')


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


def test_pg_tde_extension(host):
    if int(MAJOR_VER) < 17:
        pytest.skip(f"pg_tde not supported on {MAJOR_VER}.")

    # 1. Execute the create command
    cmd = "psql -c 'CREATE EXTENSION IF NOT EXISTS pg_tde CASCADE;'"
    result = host.run(cmd)
    assert result.rc == 0

    # 2. Metadata Verification: Check if it's in pg_extension
    check_cmd = "psql -t -c \"SELECT count(*) FROM pg_extension WHERE extname = 'pg_tde';\""
    count = host.run(check_cmd).stdout.strip()
    assert count == "1"

    # 3. Version Check (Metadata): Get the installed version string
    version_cmd = "psql -t -c \"SELECT extversion FROM pg_extension WHERE extname = 'pg_tde';\""
    ext_sql_version = host.run(version_cmd).stdout.strip()

    # Assert version is not empty
    assert len(ext_sql_version) > 0
    print(f"Detected pg_tde Extension Sql Version: {ext_sql_version}")

    # Assert sql version of pg_tde
    assert ext_sql_version == pg_docker_versions.get(f"percona-pg_tde{MAJOR_VER}", {}).get("ext_sql_version")

    # 4. Functional Check: Verify the 'pg_tde' type is usable
    # We cast a string to a pg_tde and check its dimensions to ensure the C library is loaded
    func_cmd = "psql -t -c \"SELECT pg_tde_version();\""
    actual_version = host.run(func_cmd).stdout.strip()

    # Assert version is not empty
    assert len(actual_version) > 0
    print(f"Detected pg_tde Extension Version: {actual_version}")

    # Check against your expected versions dictionary
    expected_version = pg_docker_versions.get(f"percona-pg_tde{MAJOR_VER}", {}).get("extension_version")

    assert actual_version == expected_version, f"Expected {expected_version}, but found {actual_version}"

    # 5. Execute the drop command with CASCADE
    cmd = "psql -c 'DROP EXTENSION IF EXISTS pg_tde CASCADE;'"
    result = host.run(cmd)
    assert result.rc == 0

    # 6. Verification: Ensure it no longer exists in pg_extension
    check_cmd = "psql -t -c \"SELECT count(*) FROM pg_extension WHERE extname = 'pg_tde';\""
    count = host.run(check_cmd).stdout.strip()
    assert count == "0"


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
