import os
import pytest
import subprocess
import testinfra
import sys
import settings
import time
import glob

MAJOR_VER = os.getenv('VERSION').split('.')[0]
MAJOR_MINOR_VER = os.getenv('VERSION')
DOCKER_REPO = os.getenv('DOCKER_REPOSITORY')
IMG_TAG = os.getenv('TAG')
# MAJOR_VER = '17'
# MAJOR_MINOR_VER = '17.5'
# DOCKER_REPO = 'perconalab'
# IMG_TAG = '17'

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

    print('Major Version: ' + MAJOR_VER)
    print('Major Minor Version: ' + MAJOR_MINOR_VER)
    print('Image TAG: ' + IMG_TAG)

    docker_id = subprocess.check_output(
        ['docker', 'run', '--name', f'PG{MAJOR_VER}', '-e', 'POSTGRES_PASSWORD=secret',
        '-e', 'PERCONA_TELEMETRY_URL=https://check-dev.percona.com/v1/telemetry/GenericReport',
        '-d', f'{DOCKER_REPO}/percona-distribution-postgresql:{IMG_TAG}']).decode().strip()

    # return a testinfra connection to the container
    yield testinfra.get_host("docker://" + docker_id)

    # at the end of the test suite, destroy the container
    subprocess.check_call(['docker', 'rm', '-f', docker_id])


def test_myimage(host):
    # 'host' now binds to the container
    if MAJOR_VER in ["11"]:
        pytest.skip("Skipping for ppg 11")
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


@pytest.mark.parametrize("extension", DOCKER_EXTENSIONS)
def test_extenstions_list(extension_list, host, extension):
    dist = host.system_info.distribution
    # Skip adminpack extension for PostgreSQL 17 and above
    if int(MAJOR_VER) in [17, 18] and extension == 'adminpack':
        pytest.skip("Skipping adminpack extension as it is dropped in PostgreSQL 17")
    assert extension in extension_list


@pytest.mark.parametrize("extension", DOCKER_EXTENSIONS)
def test_enable_extension(host, extension):
    dist = host.system_info.distribution
    # Skip adminpack extension for PostgreSQL 17 and above
    if int(MAJOR_VER) in [17, 18] and extension == 'adminpack':
        pytest.skip("Skipping adminpack extension as it is dropped in PostgreSQL 17")
    install_extension = host.run("psql -c 'CREATE EXTENSION \"{}\";'".format(extension))
    assert install_extension.rc == 0, install_extension.stderr
    assert install_extension.stdout.strip("\n") == "CREATE EXTENSION", install_extension.stderr
    extensions = host.run("psql -c 'SELECT * FROM pg_extension;' | awk 'NR>=3{print $3}'")
    if MAJOR_VER in ["11"]:
        extensions = host.run("psql -c 'SELECT * FROM pg_extension;' | awk 'NR>=3{print $1}'")
    assert extensions.rc == 0, extensions.stderr
    assert extension in set(extensions.stdout.split()), extensions.stdout


@pytest.mark.parametrize("extension", DOCKER_EXTENSIONS[::-1])
def test_drop_extension(host, extension):
    dist = host.system_info.distribution
    # Skip adminpack extension for PostgreSQL 17
    if int(MAJOR_VER) in [17, 18] and extension == 'adminpack':
        pytest.skip("Skipping adminpack extension as it is dropped in PostgreSQL 17")
    drop_extension = host.run("psql -c 'DROP EXTENSION \"{}\";'".format(extension))
    assert drop_extension.rc == 0, drop_extension.stderr
    assert drop_extension.stdout.strip("\n") == "DROP EXTENSION", drop_extension.stdout
    extensions = host.run("psql -c 'SELECT * FROM pg_extension;' | awk 'NR>=3{print $3}'")
    if MAJOR_VER in ["11"]:
        extensions = host.run("psql -c 'SELECT * FROM pg_extension;' | awk 'NR>=3{print $1}'")
    assert extensions.rc == 0, extensions.stderr
    assert extension not in set(extensions.stdout.split()), extensions.stdout


def test_plpgsql_extension(host):
    extensions = host.run("psql -c 'SELECT * FROM pg_extension;' | awk 'NR>=3{print $3}'")
    if MAJOR_VER in ["11"]:
        extensions = host.run("psql -c 'SELECT * FROM pg_extension;' | awk 'NR>=3{print $1}'")
    assert extensions.rc == 0, extensions.stderr
    assert "plpgsql" in set(extensions.stdout.split()), extensions.stdout


@pytest.mark.parametrize("package", DOCKER_RPM_PACKAGES)
def test_rpm_package_is_installed(host, package):
    dist = host.system_info.distribution
    pkg = host.package(package)
    assert pkg.is_installed
    if package in ["percona-postgresql-client-common", "percona-postgresql-common"]:
        assert pkg.version == pg_docker_versions[package]
    elif package in [f"percona-pgaudit{MAJOR_VER}", f"percona-wal2json{MAJOR_VER}", f"percona-pg_stat_monitor{MAJOR_VER}",
        f"percona-pgaudit{MAJOR_VER}_set_user", f"percona-pg_repack{MAJOR_VER}"]:
        assert pkg.version == pg_docker_versions[package]['version']
    else:
        assert pkg.version == pg_docker_versions['version']


def test_pg_stat_monitor_extension_version(host):
    result = host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS pg_stat_monitor;'")
    assert result.rc == 0, result.stderr
    result = host.run("psql -c 'SELECT pg_stat_monitor_version();' | awk 'NR==3{print $1}'")
    assert result.rc == 0, result.stderr
    assert result.stdout.strip("\n") == pg_docker_versions[f"percona-pg_stat_monitor{MAJOR_VER}"]['version']


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
def test_rpm_package_is_installed(host, package):
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
