import os
import pytest

import testinfra.utils.ansible_runner
SERVER_VERSION = os.getenv('server_version')
os.environ['VERSION'] = f'ppg-{SERVER_VERSION}'
from .. import settings
# from ppg.tests.settings import get_settings, MAJOR_VER

INSTALL_FOLDER_NAME = "pgdistro"
INSTALL_PATH = os.path.join("/opt", INSTALL_FOLDER_NAME)
USERNAME = os.getenv('user_name')
DBNAME = os.getenv('database_name')
PORT = os.getenv('server_port')
MAJOR_VER = os.getenv('major_version')
DATA_DIR = os.getenv('data_dir')
PG_PATH = f"{INSTALL_PATH}/percona-postgresql{MAJOR_VER}"

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')

os.environ['PATH'] = f"{PG_PATH}/bin:{INSTALL_PATH}/percona-pgbouncer/bin/:{INSTALL_PATH}/percona-haproxy/sbin:{INSTALL_PATH}/percona-patroni/bin:{INSTALL_PATH}/percona-pgbackrest/bin:{INSTALL_PATH}/percona-pgbadger:{INSTALL_PATH}/percona-pgpool-II/bin:" + os.environ['PATH']

PACKAGES = ["libecpg-compat3",  "libecpg-dev", 'libecpg6', "libpgtypes3", "libpq-dev",  "libpq5"]
pg_versions = settings.get_settings(os.environ['MOLECULE_SCENARIO_NAME'])[os.getenv("VERSION")]


@pytest.fixture()
def perl_function(host):
    with host.sudo("postgres"):
        install_extension = host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS \"plperl\";'")
        assert install_extension.rc == 0
        create_function = """CREATE FUNCTION perl_max (integer, integer) RETURNS integer AS $$
    if ($_[0] > $_[1]) { return $_[0]; }
    return $_[1];
$$ LANGUAGE plperl;
        """
        execute_psql = host.run("psql -c \'{}\'".format(create_function))
        assert execute_psql.rc == 0
        assert execute_psql.stdout.strip("\n") == "CREATE FUNCTION"
        return execute_psql


@pytest.fixture()
def python3_function(host):
    os = host.system_info.distribution
    if os.lower() in ["redhat", "centos", "rhel", "ol"]:
        pytest.skip("Skipping python3 extensions for Centos or RHEL")
    with host.sudo("postgres"):
        install_extension = host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS \"plpython3u\";'")
        assert install_extension.rc == 0
        create_function = """CREATE FUNCTION pymax3 (a integer, b integer)
                  RETURNS integer
                AS $$
                  if a > b:
                    return a
                  return b
                $$ LANGUAGE plpython3u;
                        """
        execute_psql = host.run("psql -c \'{}\'".format(create_function))
        assert execute_psql.rc == 0, execute_psql.stderr
        assert execute_psql.stdout.strip("\n") == "CREATE FUNCTION", execute_psql.stdout
        return execute_psql


@pytest.fixture()
def tcl_function(host):
    with host.sudo("postgres"):
        install_extension = host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS \"pltcl\";'")
        assert install_extension.rc == 0
        create_function = """CREATE FUNCTION tcl_max(integer, integer) RETURNS integer AS $$
    if {$1 > $2} {return $1}
    return $2
$$ LANGUAGE pltcl STRICT;
        """
        execute_psql = host.run("psql -c \'{}\'".format(create_function))
        assert execute_psql.rc == 0
        assert execute_psql.stdout.strip("\n") == "CREATE FUNCTION"
        return execute_psql


@pytest.fixture()
def build_libpq_programm(host):
    os = host.system_info.distribution
    pg_include_cmd = "pg_config --includedir"
    pg_include = host.check_output(pg_include_cmd)
    lib_dir_cmd = "pg_config --libdir"
    host.check_output(lib_dir_cmd)
    if os in ["redhat", "centos", "rhel", "ol"]:
        return host.run(
            "export LIBPQ_DIR={PG_PATH}/  && export LIBRARY_PATH={PG_PATH}/lib/ &&"
            "gcc -o lib_version /tmp/libpq_command_temp_dir/lib_version.c -I{} -lpq -std=c99".format(
                settings.MAJOR_VER, settings.MAJOR_VER, pg_include))
    return host.run(
        "gcc -o lib_version /tmp/libpq_command_temp_dir/lib_version.c -I{} -lpq -std=c99".format(pg_include))


@pytest.mark.parametrize("package", PACKAGES)
def test_deb_package_is_installed(host, package):
    os = host.system_info.distribution
    if os.lower() in ["redhat", "centos", "rhel", "ol"]:
        pytest.skip("This test only for Debian based platforms")
    pkg = host.package(package)
    assert pkg.is_installed
    assert pkg.version in pg_versions['deb_pkg_ver'],\
        f"Expected version {pg_versions['deb_pkg_ver']}. Actual version {pkg.version}"


def test_build_libpq_programm(host, build_libpq_programm):
    assert build_libpq_programm.rc == 0
    libpq_version = host.run("./lib_version ")
    assert libpq_version.stdout.strip("\n") == pg_versions['libpq'], libpq_version.stdout
    assert libpq_version.rc == 0


def test_perl_function(host, perl_function):
    _ = perl_function
    with host.sudo("postgres"):
        result = host.run("psql -c \'SELECT perl_max(1, 2);\' | awk 'NR>=3{print $1}'")
        assert result.rc == 0
        assert result.stdout.strip("\n(1") == "2", result.stdout


def test_tcl_function(host, tcl_function):
    _ = tcl_function
    with host.sudo("postgres"):
        result = host.run("psql -c \'SELECT tcl_max(1, 2);\' | awk 'NR>=3{print $1}'")
        assert result.rc == 0
        assert result.stdout.strip("\n(1") == "2", result.stdout


def test_python3(host, python3_function):
    _ = python3_function
    with host.sudo("postgres"):
        result = host.run("psql -c \'SELECT pymax3(1, 2);\' | awk 'NR>=3{print $1}'")
        assert result.rc == 0
        assert result.stdout.strip("\n(1") == "2", result.stdout
