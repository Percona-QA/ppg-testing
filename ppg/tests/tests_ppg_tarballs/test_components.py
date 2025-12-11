import os
import pytest

import testinfra.utils.ansible_runner
from .. import settings
# from ppg.tests.settings import get_settings, MAJOR_VER

INSTALL_FOLDER_NAME = "pgdistro"
INSTALL_PATH = os.path.join("/opt", INSTALL_FOLDER_NAME)
USERNAME = "postgres"
DBNAME = "postgres"
PORT = "5432"
DATA_DIR = "/opt/pgdistro/data"
PG_PATH = f"{INSTALL_PATH}/percona-postgresql{settings.MAJOR_VER}"

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')

os.environ['PATH'] = f"{PG_PATH}/bin:{INSTALL_PATH}/percona-pgbouncer/bin/:{INSTALL_PATH}/percona-haproxy/sbin:{INSTALL_PATH}/percona-patroni/bin:{INSTALL_PATH}/percona-pgbackrest/bin:{INSTALL_PATH}/percona-pgbadger:{INSTALL_PATH}/percona-pgpool-II/bin:" + os.environ['PATH']

PACKAGES = ["libecpg_compat.so.3", 'libecpg.so.6', "libpgtypes.so.3", "libpq.so.5"]
pg_versions = settings.get_settings(os.environ['MOLECULE_SCENARIO_NAME'])[os.getenv("VERSION")]


@pytest.fixture(scope='session')
def get_server_path(scope='session'):
    return PG_PATH


@pytest.fixture(scope='session')
def get_psql_binary_path(scope='session'):
    server_path=os.path.join(PG_PATH,'bin','psql')
    return server_path


@pytest.fixture()
def perl_function(host,get_psql_binary_path):
    with host.sudo("postgres"):
        install_extension = host.run(get_psql_binary_path + " -c \'DROP EXTENSION IF EXISTS plperl CASCADE;'")
        assert install_extension.rc == 0
        install_extension = host.run(get_psql_binary_path + " -c \'CREATE EXTENSION IF NOT EXISTS plperl;'")
        assert install_extension.rc == 0
        create_function = """CREATE FUNCTION perl_max (integer, integer) RETURNS integer AS $$
    if ($_[0] > $_[1]) { return $_[0]; }
    return $_[1];
$$ LANGUAGE plperl;
        """
        execute_psql = host.run(get_psql_binary_path + " -c \'{}\'".format(create_function))
        assert execute_psql.rc == 0
        assert execute_psql.stdout.strip("\n") == "CREATE FUNCTION"
        return execute_psql


@pytest.fixture()
def python3_function(host,get_psql_binary_path):
    os = host.system_info.distribution
    if os.lower() in ["redhat", "centos", "rhel", "rocky", "ol"]:
        pytest.skip("Skipping python3 extensions for Centos or RHEL")
    with host.sudo("postgres"):
        install_extension = host.run(get_psql_binary_path + " -c 'DROP EXTENSION IF EXISTS plpython3u CASCADE;'")
        assert install_extension.rc == 0
        install_extension = host.run(get_psql_binary_path + " -c 'CREATE EXTENSION IF NOT EXISTS plpython3u;'")
        assert install_extension.rc == 0
        create_function = """CREATE FUNCTION pymax3 (a integer, b integer)
                  RETURNS integer
                AS $$
                  if a > b:
                    return a
                  return b
                $$ LANGUAGE plpython3u;
                        """
        execute_psql = host.run(get_psql_binary_path + " -c \'{}\'".format(create_function))
        assert execute_psql.rc == 0, execute_psql.stderr
        assert execute_psql.stdout.strip("\n") == "CREATE FUNCTION", execute_psql.stdout
        return execute_psql


@pytest.fixture()
def tcl_function(host,get_psql_binary_path):
    with host.sudo("postgres"):
        install_extension = host.run(get_psql_binary_path + " -c 'DROP EXTENSION IF EXISTS pltcl CASCADE;'")
        assert install_extension.rc == 0
        install_extension = host.run(get_psql_binary_path + " -c 'CREATE EXTENSION IF NOT EXISTS pltcl;'")
        assert install_extension.rc == 0
        create_function = """CREATE FUNCTION tcl_max(integer, integer) RETURNS integer AS $$
    if {$1 > $2} {return $1}
    return $2
$$ LANGUAGE pltcl STRICT;
        """
        execute_psql = host.run(get_psql_binary_path+ " -c \'{}\'".format(create_function))
        assert execute_psql.rc == 0
        assert execute_psql.stdout.strip("\n") == "CREATE FUNCTION"
        return execute_psql


@pytest.fixture()
def build_libpq_programm(host):
    os = host.system_info.distribution
    pg_include_cmd = f"{PG_PATH}/bin/pg_config --includedir"
    pg_include = host.check_output(pg_include_cmd)
    lib_dir_cmd = f"{PG_PATH}/bin/pg_config --libdir"
    host.check_output(lib_dir_cmd)
    if os in ["redhat", "centos", "rhel", "rocky", "ol"]:
        return host.run(
            "export LIBPQ_DIR={}/  && export LIBRARY_PATH={}/lib/ &&"
            "gcc -o lib_version /tmp/libpq_command_temp_dir/lib_version.c -I{} -lpq -std=c99".format(PG_PATH,PG_PATH,pg_include))
    return host.run(
        "gcc -o lib_version /tmp/libpq_command_temp_dir/lib_version.c -I{} -lpq -std=c99".format(pg_include))


@pytest.mark.parametrize("package", PACKAGES)
def test_deb_package_is_installed(host, get_server_path, package):
    os_name = host.system_info.distribution
    if os_name.lower() in ["redhat", "centos", "rhel", "rocky", "ol"]:
        pytest.skip("This test only for Debian based platforms")
    with host.sudo():
        package_filename = os.path.join(get_server_path,'lib', package)
        file = host.file(package_filename)
        # Assert that the file exists
        assert file.exists, f"{package} does not exist."


def test_perl_function(host, perl_function,get_psql_binary_path):
    _ = perl_function
    with host.sudo("postgres"):
        result = host.run(get_psql_binary_path+" -c \'SELECT perl_max(1, 2);\' | awk 'NR>=3{print $1}'")
        assert result.rc == 0
        assert result.stdout.strip("\n(1") == "2", result.stdout


def test_tcl_function(host, tcl_function,get_psql_binary_path):
    _ = tcl_function
    with host.sudo("postgres"):
        result = host.run(get_psql_binary_path+" -c \'SELECT tcl_max(1, 2);\' | awk 'NR>=3{print $1}'")
        assert result.rc == 0
        assert result.stdout.strip("\n(1") == "2", result.stdout


def test_python3(host, python3_function,get_psql_binary_path):
    _ = python3_function
    with host.sudo("postgres"):
        result = host.run(get_psql_binary_path+" -c \'SELECT pymax3(1, 2);\' | awk 'NR>=3{print $1}'")
        assert result.rc == 0
        assert result.stdout.strip("\n(1") == "2", result.stdout
