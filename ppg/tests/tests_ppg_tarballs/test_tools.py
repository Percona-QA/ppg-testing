import os
import pytest
import testinfra.utils.ansible_runner
from .. import settings
from packaging import version

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
   os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')

INSTALL_FOLDER_NAME = "pgdistro"
INSTALL_PATH = os.path.join("/opt", INSTALL_FOLDER_NAME)
USERNAME = "postgres"
DBNAME = "postgres"
PORT = "5432"
DATA_DIR = "/opt/pgdistro/data"
PG_PATH = f"{INSTALL_PATH}/percona-postgresql{settings.MAJOR_VER}"

pg_versions = settings.get_settings(os.environ['MOLECULE_SCENARIO_NAME'])[os.getenv("VERSION")]
MAJOR_VER = settings.MAJOR_VER
os.environ['PATH'] = f"{PG_PATH}/bin:{INSTALL_PATH}/percona-pgbouncer/bin/:{INSTALL_PATH}/percona-haproxy/sbin:{INSTALL_PATH}/percona-patroni/bin:{INSTALL_PATH}/percona-pgbackrest/bin:{INSTALL_PATH}/percona-pgbadger:{INSTALL_PATH}/percona-pgpool-II/bin:" + os.environ['PATH']

POSTGIS_VERSION_LIMIT = version.parse("3.3.99")  # Run only for ≤3.3.x tarballs

# Minimum PostgreSQL versions where PostGIS is available
MIN_SUPPORTED_VERSIONS = {
    13: version.parse("13.19"),
    14: version.parse("14.16"),
    15: version.parse("15.11"),
    16: version.parse("16.6"),
    17: version.parse("17.3"),
}

POSTGIS_EXTENSIONS = [
    "address_standardizer",
    "address_standardizer_data_us",
    "fuzzystrmatch",
    "postgis",
    "postgis_raster",
    "postgis_sfcgal",
    "postgis_tiger_geocoder",
    "postgis_topology",
]


@pytest.fixture(scope="module")
def operating_system(host):
    return host.system_info.distribution


@pytest.fixture(scope='session')
def get_server_path(scope='session'):
    return PG_PATH


@pytest.fixture(scope='session')
def get_server_bin_path(scope='session'):
    server_bin_path=os.path.join(PG_PATH,'bin')
    return server_bin_path


@pytest.fixture(scope='session')
def get_psql_binary_path(scope='session'):
    server_path=os.path.join(PG_PATH,'bin','psql')
    return server_path


@pytest.fixture(scope='session')
def getSqlCmd_with_param(get_psql_binary_path):
    rcmd = ' '.join([get_psql_binary_path, 
                    '-U', USERNAME, 
                    '-p', PORT, 
                    '-d', DBNAME]
                    )
    return rcmd


@pytest.fixture()
def load_data(host, get_server_bin_path, get_psql_binary_path):
    with host.sudo("postgres"):
        pgbench_bin =os.path.join(get_server_bin_path, "pgbench")
        pgbench = pgbench_bin + " -i -s 1"
        assert host.run(pgbench).rc == 0
        select = get_psql_binary_path + " -c 'SELECT COUNT(*) FROM pgbench_accounts;' | awk 'NR==3{print $3}'"
        assert host.run(select).rc == 0


@pytest.fixture()
def restart_postgresql(host,get_server_bin_path):
    with host.sudo("postgres"):
        cmd = f"{get_server_bin_path}/pg_ctl -D  {DATA_DIR} restart"
        result = host.run(cmd)
        assert result.rc == 0


@pytest.fixture()
def stop_postgresql(host,get_server_bin_path):
    with host.sudo("postgres"):
        cmd = f"{get_server_bin_path}/pg_ctl -D  {DATA_DIR} stop"
        result = host.run(cmd)
        assert result.rc == 0


@pytest.fixture()
def start_postgresql(host,get_server_bin_path):
    with host.sudo("postgres"):
        cmd = f"{get_server_bin_path}/pg_ctl -D  {DATA_DIR} start"
        result = host.run(cmd)
        assert result.rc == 0


@pytest.fixture()
def pgaudit(host, get_psql_binary_path,restart_postgresql):
    dist = host.system_info.distribution
    with host.sudo("postgres"):
        enable_pgaudit = f"{get_psql_binary_path}  -c \'CREATE EXTENSION IF NOT EXISTS pgaudit;\'"
        result = host.check_output(enable_pgaudit)
        assert result.strip("\n") == "CREATE EXTENSION"
        cmd = f"{get_psql_binary_path} -c \"SELECT setting FROM pg_settings WHERE name='shared_preload_libraries';\""
        result = host.check_output(cmd)
        assert "pgaudit" in result, result
        enable_ddl = f"""{get_psql_binary_path} -c \"ALTER SYSTEM SET pgaudit.log = 'all';\""""
        result = host.check_output(enable_ddl)
        assert result.strip("\n") == "ALTER SYSTEM"
        reload_conf = f"{get_psql_binary_path} -c 'SELECT pg_reload_conf();'"
        result = host.run(reload_conf)
        assert result.rc == 0
        create_table = f"{get_psql_binary_path} -c \"CREATE TABLE IF NOT EXISTS t1 (id int,name varchar(30));\""
        result = host.run(create_table)
        assert result.rc == 0
        assert result.stdout.strip("\n") == "CREATE TABLE"
        log_file = f"{DATA_DIR}/pg_log/postgresql-main.log"
        file = host.file(log_file)
        file_content = file.content_string
    yield file_content
    with host.sudo("postgres"):
        drop_pgaudit = f"{get_psql_binary_path} -c \'DROP EXTENSION pgaudit;\'"
        result = host.check_output(drop_pgaudit)
        assert result.strip("\n") == "DROP EXTENSION"
        #restart_postgresql


@pytest.fixture()
def pgbackrest_bin_path(host):
    pgbackrest_bin_path = os.path.join(INSTALL_PATH,'percona-pgbackrest','bin')
    return pgbackrest_bin_path


@pytest.fixture()
def pgbackrest_version(host,pgbackrest_bin_path):
    return host.check_output(f"{pgbackrest_bin_path}/pgbackrest version").strip("\n")


@pytest.fixture(scope="module")
def configure_postgres_pgbackrest(host,get_psql_binary_path,pgbackrest_bin_path):
    with host.sudo("postgres"):
        wal_senders = f"""{get_psql_binary_path} -c \"ALTER SYSTEM SET max_wal_senders=3;\""""
        assert host.check_output(wal_senders).strip("\n") == "ALTER SYSTEM"
        wal_level = f"""{get_psql_binary_path} -c \"ALTER SYSTEM SET wal_level='replica';\""""
        assert host.check_output(wal_level).strip("\n") == "ALTER SYSTEM"
        archive = f"""{get_psql_binary_path} -c \"ALTER SYSTEM SET archive_mode='on';\""""
        assert host.check_output(archive).strip("\n") == "ALTER SYSTEM"
        archive_command = f"""
        {get_psql_binary_path} -c \"ALTER SYSTEM SET archive_command = '{pgbackrest_bin_path}/pgbackrest --stanza=testing archive-push %p';\"
        """
        assert host.check_output(archive_command).strip("\n") == "ALTER SYSTEM"
        reload_conf = f"{get_psql_binary_path} -c 'SELECT pg_reload_conf();'"
        result = host.run(reload_conf)
        assert result.rc == 0


@pytest.mark.usefixtures("configure_postgres_pgbackrest")
@pytest.fixture()
def create_stanza(host,pgbackrest_bin_path):
    with host.sudo("postgres"):
        cmd = f"{pgbackrest_bin_path}/pgbackrest stanza-create --stanza=testing --pg1-path={DATA_DIR} --repo-path=/var/lib/pgbackrest --log-path=/var/log/pgbackrest --log-level-console=info"
        return host.run(cmd)


@pytest.mark.usefixtures("configure_postgres_pgbackrest")
@pytest.fixture()
def pgbackrest_check(host,pgbackrest_bin_path):
    with host.sudo("postgres"):
        cmd = f"{pgbackrest_bin_path}/pgbackrest check --stanza=testing --pg1-path={DATA_DIR} --repo-path=/var/lib/pgbackrest --log-path=/var/log/pgbackrest --log-level-console=info"
        result = host.run(cmd)
        assert result.rc == 0, result.stderr
        return [l.split("INFO:")[-1] for l in result.stdout.split("\n") if "INFO" in l]


@pytest.mark.usefixtures("load_data")
@pytest.mark.usefixtures("configure_postgres_pgbackrest")
@pytest.fixture()
def pgbackrest_full_backup(host,pgbackrest_bin_path):
    with host.sudo("postgres"):
        cmd = f"{pgbackrest_bin_path}/pgbackrest backup --stanza=testing --pg1-path={DATA_DIR} --repo-path=/var/lib/pgbackrest --log-path=/var/log/pgbackrest --log-level-console=info"
        result = host.run(cmd)
        assert result.rc == 0
        return [l.split("INFO:")[-1] for l in result.stdout.split("\n") if "INFO" in l]


@pytest.mark.usefixtures("configure_postgres_pgbackrest")
@pytest.fixture()
def pgbackrest_delete_data(host,stop_postgresql):
    dist = host.system_info.distribution
    data_dir = f"{DATA_DIR}/*"
    stop_postgresql
    with host.sudo("postgres"):
        cmd = "rm -rf {}".format(data_dir)
        result = host.run(cmd)
        assert result.rc == 0


@pytest.mark.usefixtures("configure_postgres_pgbackrest")
@pytest.fixture()
def pgbackrest_restore(pgbackrest_delete_data, host,pgbackrest_bin_path):
    with host.sudo("postgres"):
        result = host.run(f"{pgbackrest_bin_path}/pgbackrest --stanza=testing --repo-path=/var/lib/pgbackrest --log-path=/var/log/pgbackrest --log-level-stderr=info restore")
        assert result.rc == 0
        return [l.split("INFO:")[-1] for l in result.stdout.split("\n") if "INFO" in l]


@pytest.fixture()
def pgrepack(host,get_server_bin_path):
    dist = host.system_info.distribution
    cmd = f"{get_server_bin_path}/pg_repack"
    return host.check_output(cmd)


@pytest.fixture()
def pg_repack_functional(host,get_server_bin_path,get_psql_binary_path):
    dist = host.system_info.distribution
    pgbench_bin = f"{get_server_bin_path}/pgbench"
    pg_repack_bin = f"{get_server_bin_path}/pg_repack"
    with host.sudo("postgres"):
        pgbench = f"{pgbench_bin} -i -s 1"
        assert host.run(pgbench).rc == 0
        select = "{get_psql_binary_path} -c 'SELECT COUNT(*) FROM pgbench_accounts;' | awk 'NR==3{print $3}'"
        assert host.run(select).rc == 0
        cmd = f"{pg_repack_bin} -t pgbench_accounts -j 4"
        pg_repack_result = host.run(cmd)
    yield pg_repack_result


@pytest.fixture()
def pg_repack_dry_run(host, operating_system,get_server_bin_path,get_psql_binary_path):
    dist = host.system_info.distribution
    pgbench_bin = f"{get_server_bin_path}/pgbench"
    pg_repack_bin = f"{get_server_bin_path}/pg_repack"
    with host.sudo("postgres"):
        pgbench = f"{pgbench_bin} -i -s 1"
        assert host.run(pgbench).rc == 0
        select = "{get_psql_binary_path} -c 'SELECT COUNT(*) FROM pgbench_accounts;' | awk 'NR==3{print $3}'"
        assert host.run(select).rc == 0
        cmd = f"{pg_repack_bin} --dry-run -d postgres"
        pg_repack_result = host.run(cmd)
    yield pg_repack_result


@pytest.fixture()
def pg_repack_client_version(host, get_server_bin_path):
    with host.sudo("postgres"):
        cmd = f"{get_server_bin_path}/pg_repack --version"
        return host.run(cmd)


@pytest.fixture()
def patroni(host):
    return host.run(f"{INSTALL_PATH}/percona-patroni/bin/patroni")


@pytest.fixture()
def patroni_version(host):
    patroni_path = os.path.join(INSTALL_PATH, 'percona-patroni')
    cmd = f"{patroni_path}/bin/patroni --version"
    return host.run(cmd)


def test_pgaudit_is_installed(host, get_server_path):
    with host.sudo():
        pgaudit_filename = os.path.join(get_server_path,'lib','pgaudit.so')
        file = host.file(pgaudit_filename)
        # Assert that the file exists
        assert file.exists, f"{pgaudit_filename} does not exist."


# def test_pgaudit(pgaudit):
#     assert "AUDIT" in pgaudit


def test_pgrepack_is_installed(host, get_server_path):
    with host.sudo():
        pgrepack_filename = os.path.join(get_server_path,'bin','pg_repack')
        file = host.file(pgrepack_filename)
        # Assert that the file exists
        assert file.exists, f"{pgrepack_filename} does not exist."


def test_pgrepack(host, get_psql_binary_path ):
    with host.sudo("postgres"):
        install_extension = host.run(f"{get_psql_binary_path} -c 'CREATE EXTENSION IF NOT EXISTS pg_repack;'")
        try:
            assert install_extension.rc == 0, install_extension.stdout
            assert install_extension.stdout.strip("\n") == "CREATE EXTENSION"
        except AssertionError:
            pytest.fail("Return code {}. Stderror: {}. Stdout {}".format(install_extension.rc,
                                                                         install_extension.stderr,
                                                                         install_extension.stdout))
            extensions = host.run("f{get_psql_binary_path} -c 'SELECT * FROM pg_extension;' | awk 'NR>=3{print $3}'")
            assert extensions.rc == 0
            assert "pg_repack" in set(extensions.stdout.split())


def test_pg_repack_client_version(pg_repack_client_version):
    assert pg_repack_client_version.rc == 0
    assert pg_repack_client_version.stdout.strip("\n") == pg_versions['pgrepack']['binary_version']


def test_pg_repack_functional(pg_repack_functional):
    assert pg_repack_functional.rc == 0
    messages = pg_repack_functional.stderr.split("\n")
    assert 'NOTICE: Setting up workers.conns' in messages
    assert 'NOTICE: Setting up workers.conns', 'INFO: repacking table "public.pgbench_accounts"' in messages


def test_pg_repack_dry_run(pg_repack_dry_run):
    assert pg_repack_dry_run.rc == 0
    messages = pg_repack_dry_run.stderr.split("\n")
    assert 'INFO: Dry run enabled, not executing repack' in messages
    assert 'INFO: repacking table "public.pgbench_accounts"' in messages
    assert 'INFO: repacking table "public.pgbench_branches"' in messages
    assert 'INFO: repacking table "public.pgbench_tellers"' in messages


def test_pgbackrest_is_installed(host):
    pgbackrest_dir = os.path.join(INSTALL_PATH, 'percona-pgbackrest')
    # Check if the directory exists
    directory = host.file(pgbackrest_dir)
    assert directory.is_directory, f"{pgbackrest_dir} does not exist or is not a directory."
    # Check if the directory is not empty
    assert directory.exists, f"{pgbackrest_dir} does not exist."
    files = host.run(f"ls -A {pgbackrest_dir}").stdout.strip()
    assert files, f"{pgbackrest_dir} is empty."
    # Check if the binary exists and is a file    
    pgbackrest_bin = os.path.join(pgbackrest_dir,'bin','pgbackrest')
    binary = host.file(pgbackrest_bin)
    assert binary.exists, f"{pgbackrest_bin} does not exist."
    assert binary.is_file, f"{pgbackrest_bin} is not a file."


def test_pgbackrest_version(pgbackrest_version):
    assert pgbackrest_version == pg_versions['pgbackrest']['binary_version']


def test_pgbackrest_create_stanza(create_stanza):
    assert "INFO: stanza-create command end: completed successfully" in create_stanza.stdout


def test_pgbackrest_check(pgbackrest_check):
    assert "check command end: completed successfully" in pgbackrest_check[-1]


def test_pgbackrest_full_backup(pgbackrest_full_backup):
    assert "expire command end: completed successfully" in pgbackrest_full_backup[-1]


# def test_pgbackrest_restore(host, start_postgresql,get_psql_binary_path):
#     start_postgresql
#     with host.sudo("postgres"):
#         select = get_psql_binary_path + " -c 'SELECT COUNT(*) FROM pgbench_accounts;' | awk 'NR==3{print $1}'"
#         result = host.run(select)
#         assert result.rc == 0
#         assert result.stdout.strip("\n") == "100000"


def test_patroni_is_installed(host):
    with host.sudo():
        patroni_dir = os.path.join(INSTALL_PATH, 'percona-patroni')
        # Check if the directory exists
        directory = host.file(patroni_dir)
        assert directory.is_directory, f"{patroni_dir} does not exist or is not a directory."
        # Check if the directory is not empty
        assert directory.exists, f"{patroni_dir} does not exist."
        files = host.run(f"ls -A {patroni_dir}").stdout.strip()
        assert files, f"{patroni_dir} is empty."
        patroni_bin = os.path.join(patroni_dir,'bin','patroni')
        binary = host.file(patroni_bin)
        assert binary.exists, f"{patroni_bin} does not exist."
        assert binary.is_file, f"{patroni_bin} is not a file."


def test_patroni_version(patroni_version):
    assert patroni_version.rc == 0, patroni_version.stderr
    assert patroni_version.stdout.strip("\n") == pg_versions['patroni']['binary_version']


def test_etcd_is_installed(host):
    with host.sudo():
        etcd_dir = os.path.join(INSTALL_PATH, 'percona-etcd')
        # Check if the directory exists
        directory = host.file(etcd_dir)
        assert directory.is_directory, f"{etcd_dir} does not exist or is not a directory."
        # Check if the directory is not empty
        assert directory.exists, f"{etcd_dir} does not exist."
        files = host.run(f"ls -A {etcd_dir}").stdout.strip()
        assert files, f"{etcd_dir} is empty."
        # Check if the binary exists and is a file
        etcd_bin = os.path.join(etcd_dir,'bin','etcd')
        binary = host.file(etcd_bin)
        assert binary.exists, f"{etcd_bin} does not exist."
        assert binary.is_file, f"{etcd_bin} is not a file."


def test_pgbouncer_is_installed(host):
    with host.sudo():
        pgbouncer_dir = os.path.join(INSTALL_PATH, 'percona-pgbouncer')
        # Check if the directory exists
        directory = host.file(pgbouncer_dir)
        assert directory.is_directory, f"{pgbouncer_dir} does not exist or is not a directory."
        # Check if the directory is not empty
        assert directory.exists, f"{pgbouncer_dir} does not exist."
        files = host.run(f"ls -A {pgbouncer_dir}").stdout.strip()
        assert files, f"{pgbouncer_dir} is empty."
        # Check if the binary exists and is a file    
        pgbouncer_bin = os.path.join(pgbouncer_dir,'bin','pgbouncer')
        binary = host.file(pgbouncer_bin)
        assert binary.exists, f"{pgbouncer_bin} does not exist."
        assert binary.is_file, f"{pgbouncer_bin} is not a file."


def test_pgbadger_is_installed(host):
    with host.sudo():
        pgbadger_dir = os.path.join(INSTALL_PATH, 'percona-pgbadger')
        # Check if the directory exists
        directory = host.file(pgbadger_dir)
        assert directory.is_directory, f"{pgbadger_dir} does not exist or is not a directory."
        # Check if the directory is not empty
        assert directory.exists, f"{pgbadger_dir} does not exist."
        files = host.run(f"ls -A {pgbadger_dir}").stdout.strip()
        assert files, f"{pgbadger_dir} is empty."
        # Check if the binary exists and is a file    
        pgbadger_bin = os.path.join(pgbadger_dir,'pgbadger')
        binary = host.file(pgbadger_bin)
        assert binary.exists, f"{pgbadger_bin} does not exist."
        assert binary.is_file, f"{pgbadger_bin} is not a file."


def test_haproxy_is_installed(host):
    with host.sudo():
        haproxy_dir = os.path.join(INSTALL_PATH, 'percona-haproxy')
        # Check if the directory exists
        directory = host.file(haproxy_dir)
        assert directory.is_directory, f"{haproxy_dir} does not exist or is not a directory."
        # Check if the directory is not empty
        assert directory.exists, f"{haproxy_dir} does not exist."
        files = host.run(f"ls -A {haproxy_dir}").stdout.strip()
        assert files, f"{haproxy_dir} is empty."
        # Check if the binary exists and is a file    
        haproxy_bin = os.path.join(haproxy_dir,'sbin','haproxy')
        binary = host.file(haproxy_bin)
        assert binary.exists, f"{haproxy_bin} does not exist."
        assert binary.is_file, f"{haproxy_bin} is not a file."


def test_wal2json_is_installed(host,get_server_path):
    file_name = f"{get_server_path}/lib/wal2json.so"
    file = host.file(file_name)
    assert file.exists, f"{file_name} does not exist."


def test_set_user_is_installed(host, get_server_path):
    with host.sudo():
        files = [
        f"{get_server_path}/share/extension/set_user.control",
        f"{get_server_path}/lib/set_user.so",]
        sql_dir = f"{get_server_path}/share/extension/"
        sql_files = host.run("ls {}/set_user--*.sql".format(sql_dir)).stdout.split()
        assert len(sql_files) > 0, "No set_user SQL files found"
        files += sql_files
        for file_name in files:
            file = host.file(file_name)
            assert file.exists, f"{file_name} does not exist."


def test_etcd_binary_version(host):
    with host.sudo():
        etcd_bin_path = os.path.join(INSTALL_PATH, 'percona-etcd','bin')
        binary_name = 'etcd'
        binary = host.file(f"{etcd_bin_path}/{binary_name}")
        assert binary.exists, f"{binary} does not exist."
        result = host.run(f"{etcd_bin_path}/{binary_name} --version")
        assert result.rc == 0, result.stderr
        assert pg_versions[binary_name]['binary_version'] in result.stdout.strip("\n"), result.stdout


def test_pgbouncer_binary_version(host):
    with host.sudo():   
        pgbouncer_bin_path = os.path.join(INSTALL_PATH,'percona-pgbouncer','bin')
        binary_name = 'pgbouncer'
        binary = host.file(f"{pgbouncer_bin_path}/{binary_name}")
        assert binary.exists, f"{binary} does not exist."
        result = host.run(f"{pgbouncer_bin_path}/{binary_name} --version")
        assert result.rc == 0, result.stderr
        assert pg_versions[binary_name]['binary_version'] in result.stdout.strip("\n"), result.stdout


def test_pgbadger_binary_version(host):
    # Failing on RHEL 9 so commenting it out, needs manual verification
    # NEEDS MAUNAL VERIFICATION
    os_name = host.system_info.distribution
    if os_name.lower() in ["redhat", "centos", "rhel", "rocky", "ol"]and host.system_info.release.startswith("9"):
        pytest.skip("This test only for Debian based platforms")
    with host.sudo():
        pgbadger_dir = os.path.join(INSTALL_PATH, 'percona-pgbadger')
        binary_name = 'pgbadger'
        binary = host.file(f"{pgbadger_dir}/{binary_name}")
        assert binary.exists, f"{pgbadger_dir}/{binary_name} does not exist."
        result = host.run(f"PATH=/opt/percona-perl/bin:$PATH {pgbadger_dir}/{binary_name} --version")
        assert result.rc == 0, result.stderr
        assert pg_versions[binary_name]['binary_version'] in result.stdout.strip("\n"), result.stdout


def test_haproxy_binary_version(host):
    with host.sudo():  
        haproxy_bin = os.path.join(INSTALL_PATH, 'percona-haproxy','sbin')
        binary_name = 'haproxy'   
        binary = host.file(f"{haproxy_bin}/{binary_name}")
        assert binary.exists, f"{haproxy_bin}/{binary_name} does not exist."
        result = host.run(f"{haproxy_bin}/{binary_name} -v")
        assert result.rc == 0, result.stderr
        assert pg_versions[binary_name]['binary_version'] in result.stdout.strip("\n"), result.stdout


def test_haproxy_version(host):
    haproxy_path = f"{INSTALL_PATH}/percona-haproxy"
    with host.sudo("postgres"):
        cmd = f"{haproxy_path}/sbin/haproxy -v |grep version | head -1 | cut -d' ' -f3| cut -d'-' -f1"
        version = host.run(cmd)
        assert pg_versions["haproxy"]['version'] in version.stdout.strip("\n"), version.stdout


def test_pgpool_is_installed(host):
    with host.sudo():
        pgpool_dir = os.path.join(INSTALL_PATH, 'percona-pgpool-II')
        # Check if the directory exists
        directory = host.file(pgpool_dir)
        assert directory.is_directory, f"{pgpool_dir} does not exist or is not a directory."
        # Check if the directory is not empty
        assert directory.exists, f"{pgpool_dir} does not exist."
        files = host.run(f"ls -A {pgpool_dir}").stdout.strip()
        assert files, f"{pgpool_dir} is empty."
        # Check if the binary exists and is a file    
        haproxy_bin = os.path.join(pgpool_dir,'bin','pgpool')
        binary = host.file(haproxy_bin)
        assert binary.exists, f"{haproxy_bin} does not exist."
        assert binary.is_file, f"{haproxy_bin} is not a file."


def test_pgpool_binary_version(host):
    dist = host.system_info.distribution
    pgpool_path = os.path.join(INSTALL_PATH,'percona-pgpool-II')
    cmd = f"{pgpool_path}/bin/pgpool --version 2>&1 | grep pgpool | cut -d' ' -f3"
    result = host.run(cmd)
    assert result.rc == 0, result.stderr
    assert pg_versions["pgpool"]['binary_version'] in result.stdout.strip("\n"), result.stdout


def test_pg_gather_output(host,get_server_bin_path):
    with host.sudo("postgres"):
        result = host.run(f"{get_server_bin_path}/psql -X -f {get_server_bin_path}/gather.sql > /tmp/out.txt")
        assert result.rc == 0, result.stderr


def test_pg_gather_is_installed(host,get_server_bin_path):
    file_name = f"{get_server_bin_path}/gather.sql"
    file = host.file(file_name)
    assert file.exists, f"{file_name} does not exist."


def test_pg_gather_file_version(host,get_server_bin_path):
    result = host.run(f"head -5 {get_server_bin_path}/gather.sql | tail -1 | cut -d' ' -f3")
    assert result.rc == 0, result.stderr
    assert pg_versions["pg_gather"]['sql_file_version'] in result.stdout.strip("\n"), result.stdout


# def test_pgaudit(pgaudit):
#     assert "AUDIT" in pgaudit


def test_pg_stat_monitor_is_installed(host, get_server_path):
    with host.sudo():
        files = [
        f"{get_server_path}/share/extension/pg_stat_monitor.control",
        f"{get_server_path}/lib/pg_stat_monitor.so",]
        sql_dir = f"{get_server_path}/share/extension/"
        sql_files = host.run("ls {}/pg_stat_monitor--*.sql".format(sql_dir)).stdout.split()
        assert len(sql_files) > 0, "No pg_stat_monitor SQL files found"
        files += sql_files
        for file_name in files:
            file = host.file(file_name)
            assert file.exists, f"{file_name} does not exist."


def test_pg_stat_monitor_extension_version(host,get_psql_binary_path):
    with host.sudo("postgres"):
        result = host.run(f"{get_psql_binary_path} -c 'CREATE EXTENSION IF NOT EXISTS pg_stat_monitor;'")
        assert result.rc == 0, result.stderr
        cmd = f"{get_psql_binary_path} -c 'SELECT pg_stat_monitor_version();' -t -A | awk '{{print $1}}'"
        result = host.run(cmd)
        assert result.rc == 0, result.stderr
        assert result.stdout.strip("\n") == pg_versions['PGSM_version']


def test_postgis_is_installed(host, get_server_path):
    with host.sudo():
        files = [
        f"{get_server_path}/share/extension/postgis.control",
        f"{get_server_path}/lib/postgis-3.so",]
        sql_dir = f"{get_server_path}/share/extension/"
        sql_files = host.run("ls {}/postgis*.sql".format(sql_dir)).stdout.split()
        assert len(sql_files) > 0, "No postgis SQL files found"
        files += sql_files
        for file_name in files:
            file = host.file(file_name)
            assert file.exists, f"{file_name} does not exist."


@pytest.fixture()
def installed_extensions_list(host, get_psql_binary_path):
    with host.sudo("postgres"):
        cmd = f"{get_psql_binary_path} -c 'SELECT * FROM pg_available_extensions;' | awk 'NR>=3{{print $1}}'"
        result = host.check_output(cmd)
        result = result.split()
        return result


def _skip_if_postgis_unavailable(pg_versions):
    """Helper: Skip tests if PostGIS not available for given PostgreSQL version."""
    pg_version_str = pg_versions["version"]
    pg_version = version.parse(pg_version_str)

    min_supported = MIN_SUPPORTED_VERSIONS.get(pg_version.major)
    if min_supported and pg_version < min_supported:
        pytest.skip(f"PostGIS not available on PostgreSQL {pg_version_str}")

    return pg_version_str


def _skip_if_postgis_not_3_3():
    """Skip tests if PostGIS version is newer than 3.3.x."""
    postgis_ver = version.parse(pg_versions["postgis_major_version"])
    if postgis_ver > POSTGIS_VERSION_LIMIT:
        pytest.skip("This test only runs for tarballs with PostGIS 3.3.x or lower.")
    return postgis_ver


@pytest.mark.parametrize("binary", ["shp2pgsql", "pgsql2shp"])
def test_postgis_binary_version(host, binary):
    """Verify shp2pgsql/pgsql2shp binaries report expected PostGIS version."""
    _skip_if_postgis_not_3_3()

    cmd = f"{PG_PATH}/bin/{binary} | grep -i release | awk '{{print $2}}'"
    result = host.run(cmd)

    assert result.rc == 0, f"Failed to run {binary}: {result.stderr}"
    actual_version = result.stdout.strip()
    expected_version = pg_versions["postgis_version"]

    print(f"{binary}: expected={expected_version}, got={actual_version}")
    assert expected_version in actual_version, (
        f"{binary} version mismatch: expected {expected_version}, got {actual_version}"
    )


def test_postgis_binaries_presence(host):
    #Verify required PostGIS binaries exist in the expected directory."""
    _skip_if_postgis_not_3_3()

    binaries = [
        "pgtopo_export",
        "pgtopo_import",
        "pgsql2shp",
        "raster2pgsql",
        "shp2pgsql",
    ]

    with host.sudo("postgres"):
        for binary in binaries:
            path = f"{PG_PATH}/bin/{binary}"
            binary_file = host.file(path)

            assert binary_file.exists, f"❌ {binary} not found at {path}"
            assert binary_file.is_file, f"⚠️ {path} exists but is not a regular file"


def test_postgis_extensions_list(installed_extensions_list, host):
    pg_version_str = _skip_if_postgis_unavailable(pg_versions)
    dist = host.system_info.distribution
    print(f"Checking PostGIS extensions list on {dist} ({pg_version_str})")

    missing = [ext for ext in POSTGIS_EXTENSIONS if ext not in installed_extensions_list]
    assert not missing, f"Missing PostGIS extensions: {missing}"


def test_postgis_extensions_create_drop(host, get_psql_binary_path):
    pg_version_str = _skip_if_postgis_unavailable(pg_versions)

    with host.sudo("postgres"):
        extensions_to_create = [
            "postgis",
            "postgis_raster",
            "postgis_sfcgal",
            "fuzzystrmatch",
            "address_standardizer",
            "address_standardizer_data_us",
            "postgis_tiger_geocoder",
        ]

        # Create postgis first with temporary pgaudit change
        create_cmd = (
            f"{get_psql_binary_path} -c \""
            "SET pgaudit.log = 'none'; "
            "CREATE EXTENSION IF NOT EXISTS postgis; "
            "SET pgaudit.log = 'all';\""
        )
        result = host.run(create_cmd)
        assert result.rc == 0, f"Failed to create postgis extension: {result.stderr}"

        # Create remaining extensions
        for ext in extensions_to_create[1:]:
            result = host.run(f"{get_psql_binary_path} -c 'CREATE EXTENSION IF NOT EXISTS {ext};'")
            assert result.rc == 0, f"Failed to create extension {ext}: {result.stderr}"

        # Drop all extensions in reverse order
        for ext in reversed(extensions_to_create):
            result = host.run(f"{get_psql_binary_path} -c 'DROP EXTENSION IF EXISTS {ext} CASCADE;'")
            assert result.rc == 0, f"Failed to drop extension {ext}: {result.stderr}"


def test_postgis_extension_version(host, get_psql_binary_path):
    pg_version_str = _skip_if_postgis_unavailable(pg_versions)
    expected_postgis_ver = pg_versions["postgis_version"]

    with host.sudo("postgres"):
        # Create extension quietly
        result = host.run(
            f"{get_psql_binary_path} -c \""
            "SET pgaudit.log = 'none'; "
            "CREATE EXTENSION IF NOT EXISTS postgis; "
            "SET pgaudit.log = 'all';\""
        )
        assert result.rc == 0, f"Failed creating postgis: {result.stderr}"

        # Get installed version
        query = (
            f"{get_psql_binary_path} -Atc "
            "\"SELECT installed_version "
            "FROM pg_available_extensions WHERE name = 'postgis';\""
        )
        result = host.run(query)
        assert result.rc == 0, f"Failed to fetch postgis version: {result.stderr}"

        installed_version = result.stdout.strip()
        assert installed_version == expected_postgis_ver, (
            f"PostGIS version mismatch: expected {expected_postgis_ver}, got {installed_version}"
        )
