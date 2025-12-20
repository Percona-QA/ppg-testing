import os
import pytest
import time

import testinfra.utils.ansible_runner

from .. import settings

INSTALL_FOLDER_NAME = "pgdistro"
INSTALL_PATH = os.path.join("/opt", INSTALL_FOLDER_NAME)
USERNAME = "postgres"
DBNAME = "postgres"
PORT = "5432"
DATA_DIR = "/opt/pgdistro/data"
PG_PATH = f"{INSTALL_PATH}/percona-postgresql{settings.MAJOR_VER}"


testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')

deb_files = ["postgresql.conf",
                      "pg_hba.conf",
                      "pg_ident.conf"]

rhel_files = ["postgresql.conf",
                       "pg_hba.conf",
                       "pg_ident.conf"]

pg_versions = settings.get_settings(os.environ['MOLECULE_SCENARIO_NAME'])[os.getenv("VERSION")]
RHEL_FILES = rhel_files #pg_versions['rhel_files']
RPM7_PACKAGES = pg_versions['rpm7_packages']
RPM_PACKAGES = pg_versions['rpm_packages']
EXTENSIONS = pg_versions['extensions']
LANGUAGES = pg_versions['languages']
DEB_FILES = deb_files #pg_versions['deb_files']
SKIPPED_DEBIAN = ["ppg-11.8", "ppg-11.9", "ppg-11.10", "ppg-11.12", "ppg-11.17", 'ppg-12.2',
                  'ppg-12.3', "ppg-12.4", "ppg-12.5", "ppg-12.6", "ppg-12.7", "ppg-12.12", "ppg-12.13",
                  "ppg-12.14", "ppg-12.15", "ppg-12.16", "ppg-12.17", "ppg-12.18","ppg-12.19","ppg-12.20",
                  "ppg-13.0", "ppg-13.1",
                  "ppg-15.0", "ppg-15.1"]
BINARIES = pg_versions['binaries']

os.environ['PATH'] = f"{PG_PATH}/bin:{INSTALL_PATH}/percona-pgbouncer/bin/:{INSTALL_PATH}/percona-haproxy/sbin:{INSTALL_PATH}/percona-patroni/bin:{INSTALL_PATH}/percona-pgbackrest/bin:{INSTALL_PATH}/percona-pgbadger:{INSTALL_PATH}/percona-pgpool-II/bin:" + os.environ['PATH']


@pytest.fixture(scope='session')
def get_server_bin_path(scope='session'):
    server_path=os.path.join(PG_PATH,'bin')
    print('Bin Path: ' + server_path)
    return server_path


@pytest.fixture(scope='session')
def get_psql_binary_path(scope='session'):
    server_path=os.path.join(PG_PATH,'bin','psql')
    return server_path


@pytest.fixture(scope='session')
def getSqlCmd_with_param(get_psql_binary_path):
    rcmd = f'{get_psql_binary_path} -U {USERNAME} -p {PORT} -d {DBNAME} '
    print('Sql Command with Param: ' + rcmd)
    return rcmd


@pytest.fixture()
def start_stop_postgresql(host,get_server_bin_path):
    with host.sudo("postgres"):
        cmd = f"{get_server_bin_path}/pg_ctl -D {DATA_DIR} stop"
        result = host.run(cmd)
        assert result.rc == 0
        cmd = f"{get_server_bin_path}/pg_ctl -D {DATA_DIR} start"
        result = host.run(cmd)
        assert result.rc == 0
        cmd = f"{get_server_bin_path}/pg_ctl -D {DATA_DIR} status"
        return host.run(cmd)


@pytest.fixture()
def postgresql_binary(host,get_server_bin_path):
    dist = host.system_info.distribution
    pg_bin = get_server_bin_path + '/postgres'
    if dist.lower() in ["redhat", "centos", "rhel", "rocky", "ol"]:
        pg_bin = pg_bin
    return host.file(pg_bin)


@pytest.fixture()
def postgresql_query_version(host,get_psql_binary_path):
    with host.sudo("postgres"):
        return host.run(get_psql_binary_path + " -c   'SELECT version()' | awk 'NR==3{print $2}'")


@pytest.fixture()
def restart_postgresql(host,get_server_bin_path):
    with host.sudo("postgres"):
        cmd = f"{get_server_bin_path}/pg_ctl -D {DATA_DIR} restart"
        result = host.run(cmd)
        assert result.rc == 0
        cmd = f"{get_server_bin_path}/pg_ctl -D {DATA_DIR} status"
        return host.run(cmd)


@pytest.fixture()
def extension_list(host,get_psql_binary_path):
    with host.sudo("postgres"):
        result = host.check_output(get_psql_binary_path + " -c 'SELECT * FROM pg_available_extensions;' | awk 'NR>=3{print $1}'")
        result = result.split()
        return result


@pytest.fixture()
def insert_data(host, get_server_bin_path, get_psql_binary_path):
    dist = host.system_info.distribution
    print(host.run("find / -name pgbench").stdout)
    pgbench_bin =os.path.join(get_server_bin_path, "pgbench")
    if dist.lower() in ["redhat", "centos", "rhel", "rocky", "ol"]:
        pgbench_bin = os.path.join(get_server_bin_path, "pgbench")
    with host.sudo("postgres"):
        pgbench = f"{pgbench_bin} -i -s 1"
        result = host.run(pgbench)
        assert result.rc == 0, result.stderr
        select = get_psql_binary_path + " -c 'SELECT COUNT(*) FROM pgbench_accounts;' | awk 'NR==3{print $1}'"
        result = host.check_output(select)
    yield result.strip("\n")


def test_psql_client_version(host):
    result = host.run(PG_PATH+'/bin/psql --version')
    print(result)
    assert pg_versions['version'] in result.stdout, result.stdout

# @pytest.mark.upgrade
# @pytest.mark.parametrize("package", pg_versions['deb_packages'])
# def test_deb_package_is_installed(host, package):
#     dist = host.system_info.distribution
#     if dist.lower() in ["redhat", "centos", "rhel", "rocky", "ol"]:
#         pytest.skip("This test only for Debian based platforms")
#     pkg = host.package(package)
#     assert pkg.is_installed
#     assert pkg.version in pg_versions['deb_pkg_ver']


def test_postgres_binary(postgresql_binary):
    assert postgresql_binary.exists
    assert postgresql_binary.user == "root" or postgresql_binary.user == "postgres"


@pytest.mark.upgrade
@pytest.mark.parametrize("binary", BINARIES)
def test_binaries(host,get_server_bin_path, binary):
    dist = host.system_info.distribution
    bin_path = get_server_bin_path
    if dist.lower() in ["redhat", "centos", "rhel", "rocky", "ol"]:
        bin_path = get_server_bin_path
    bin_full_path = os.path.join(bin_path, binary)
    binary_file = host.file(bin_full_path)
    assert binary_file.exists


@pytest.mark.upgrade
def test_pg_config_server_version(host,get_server_bin_path):
    cmd = f"{get_server_bin_path}/pg_config --version"
    try:
        result = host.check_output(cmd)
        assert settings.MAJOR_VER in result, result.stdout
    except AssertionError:
        pytest.mark.xfail(reason="Maybe dev package not install")


@pytest.mark.upgrade
def test_postgresql_query_version(postgresql_query_version):
    assert postgresql_query_version.rc == 0, postgresql_query_version.stderr
    assert postgresql_query_version.stdout.strip("\n") == pg_versions['version'], postgresql_query_version.stdout


@pytest.mark.upgrade
def test_postgres_client_version(host, get_psql_binary_path):
    cmd = f"{get_psql_binary_path} --version"
    result = host.check_output(cmd)
    assert settings.MAJOR_VER in result.strip("\n"), result.stdout


def test_insert_data(insert_data):
    assert insert_data == "100000", insert_data


@pytest.mark.upgrade
@pytest.mark.parametrize("extension", EXTENSIONS)
def test_extenstions_list(extension_list, host, extension):
    dist = host.system_info.distribution
    POSTGIS_DEB_EXTENSIONS = ['postgis_tiger_geocoder-3','postgis_sfcgal-3','postgis_raster-3','postgis_topology-3',
        'address_standardizer_data_us','postgis_tiger_geocoder','postgis_raster','postgis_topology','postgis_sfcgal',
        'address_standardizer-3','postgis-3','address_standardizer','postgis','address_standardizer_data_us-3']
    POSTGIS_RHEL_EXTENSIONS = ['postgis_sfcgal','address_standardizer','postgis_tiger_geocoder','postgis',
        'postgis_topology','postgis_raster','address_standardizer_data_us']
    if dist.lower() in ["redhat", "centos", "rhel", "rocky", "ol"]:
        if extension in POSTGIS_RHEL_EXTENSIONS:
            pytest.skip("Skipping postgis extension " + extension + " for Centos or RHEL as it will fail on upgrade.")
    if dist.lower() in ['debian', 'ubuntu']:
        if extension in POSTGIS_DEB_EXTENSIONS:
            pytest.skip("Skipping postgis extension " + extension + " for debian as it will fail on upgrade.")
    if dist.lower() in ["redhat", "centos", "rhel", "rocky", "ol"]:
        if extension in [
            'plpythonu', "plpython2u", 'jsonb_plpython2u', 'ltree_plpython2u', 'jsonb_plpythonu',
            'ltree_plpythonu', 'hstore_plpythonu', 'hstore_plpython2u']:
            pytest.skip("Skipping extension " + extension + " for Centos or RHEL")
    if dist.lower() in ['debian', 'ubuntu'] and os.getenv("VERSION") in SKIPPED_DEBIAN:
        if extension in ['plpythonu', "plpython2u", 'jsonb_plpython2u', 'ltree_plpython2u', 'jsonb_plpythonu',
                            'ltree_plpythonu', 'hstore_plpythonu', 'hstore_plpython2u']:
            pytest.skip("Skipping extension " + extension + " for DEB based in pg: " + os.getenv("VERSION"))
    # Skip adminpack extension for PostgreSQL 17,18 
    if settings.MAJOR_VER in ["17","18"] and extension == 'adminpack':
        pytest.skip("Skipping adminpack extension as it is dropped in PostgreSQL 17")
    assert extension in extension_list


@pytest.mark.parametrize("extension", EXTENSIONS)
def test_enable_extension(host, get_psql_binary_path , extension):
    dist = host.system_info.distribution
    if dist.lower() in ["redhat", "centos", "rhel", "rocky", "ol"]:
        if extension in ['postgis_sfcgal','address_standardizer','postgis_tiger_geocoder','postgis',
        'postgis_topology','postgis_raster','address_standardizer_data_us']:
            pytest.skip("Skipping extension " + extension + " due to multiple dependencies. Already being checked in test_tools.py.")
        if extension in ['hstore_plpython3u','jsonb_plpython3u', 'ltree_plpython3u']:
            pytest.skip("Skipping " + extension + " extension for Centos or RHEL")
        if extension in [
            'plpythonu', "plpython2u", 'jsonb_plpython2u', 'ltree_plpython2u', 'jsonb_plpythonu',
            'ltree_plpythonu', 'hstore_plpythonu', 'hstore_plpython2u', 'hstore_plpython3u',
            'jsonb_plpython3u', 'ltree_plpython3u']:
            pytest.skip("Skipping extension " + extension + " for Centos or RHEL")

    if dist.lower() in ['debian', 'ubuntu'] and os.getenv("VERSION") in SKIPPED_DEBIAN:
        if extension in ['plpythonu', "plpython2u", 'jsonb_plpython2u', 'ltree_plpython2u', 'jsonb_plpythonu',
                         'ltree_plpythonu', 'hstore_plpythonu', 'hstore_plpython2u', 'hstore_plpython3u',
                         'jsonb_plpython3u', 'ltree_plpython3u']:
            pytest.skip("Skipping extension " + extension + " for DEB based in pg: " + os.getenv("VERSION"))
    if dist.lower() in ['ubuntu'] and extension in ['hstore_plpython3u','jsonb_plpython3u', 'ltree_plpython3u']:
            pytest.skip("Skipping extension " + extension + " for Ubuntu based in pg: " + os.getenv("VERSION"))
    if dist.lower() in ['debian', 'ubuntu'] and extension in ['postgis_tiger_geocoder-3','postgis_sfcgal-3','postgis_raster-3',
        'postgis_topology-3','address_standardizer_data_us','postgis_tiger_geocoder','postgis_raster','postgis_topology',
        'postgis_sfcgal','address_standardizer-3','postgis-3','address_standardizer','postgis','address_standardizer_data_us-3']:
            pytest.skip("Skipping extension " + extension + " due to multiple dependencies. Already being checked in test_tools.py.")
    # Skip adminpack extension for PostgreSQL 17,18
    if settings.MAJOR_VER in ["17","18"] and extension == 'adminpack':
        pytest.skip("Skipping adminpack extension as it is dropped in PostgreSQL 17")
    with host.sudo("postgres"):
        install_extension = host.run(get_psql_binary_path + " -c 'CREATE EXTENSION IF NOT EXISTS \"{}\";'".format(extension))
        assert install_extension.rc == 0, install_extension.stderr
        assert install_extension.stdout.strip("\n") == "CREATE EXTENSION", install_extension.stderr
        extensions = host.run(get_psql_binary_path + " -c 'SELECT * FROM pg_extension;' | awk 'NR>=3{print $3}'")
        if "11." in os.getenv("VERSION"):
            extensions = host.run(get_psql_binary_path + " -c 'SELECT * FROM pg_extension;' | awk 'NR>=3{print $1}'")
        assert extensions.rc == 0, extensions.stderr
        assert extension in set(extensions.stdout.split()), extensions.stdout


@pytest.mark.parametrize("extension", EXTENSIONS[::-1])
def test_drop_extension(host,get_psql_binary_path, extension):
    dist = host.system_info.distribution
    if dist.lower() in ["redhat", "centos", "rhel", "rocky", "ol"]:
        if extension in ['postgis_sfcgal','address_standardizer','postgis_tiger_geocoder','postgis',
        'postgis_topology','postgis_raster','address_standardizer_data_us']:
            pytest.skip("Skipping extension " + extension + " due to multiple dependencies. Already being checked in test_tools.py.")
        if extension in ['hstore_plpython3u','jsonb_plpython3u', 'ltree_plpython3u']:
            pytest.skip("Skipping " + extension + " extension for Centos or RHEL")
        if extension in [
            'plpythonu', "plpython2u", 'jsonb_plpython2u', 'ltree_plpython2u', 'jsonb_plpythonu',
            'ltree_plpythonu', 'hstore_plpythonu', 'hstore_plpython2u', 'hstore_plpython3u',
            'jsonb_plpython3u', 'ltree_plpython3u']:
            pytest.skip("Skipping extension " + extension + " for Centos or RHEL")

    if dist.lower() in ['debian', 'ubuntu'] and os.getenv("VERSION") in SKIPPED_DEBIAN:
        if extension in ['plpythonu', "plpython2u", 'jsonb_plpython2u', 'ltree_plpython2u', 'jsonb_plpythonu',
                         'ltree_plpythonu', 'hstore_plpythonu', 'hstore_plpython2u', 'hstore_plpython3u',
                         'jsonb_plpython3u', 'ltree_plpython3u']:
            pytest.skip("Skipping extension " + extension + " for DEB based in pg: " + os.getenv("VERSION"))
    if dist.lower() in ['ubuntu'] and extension in ['hstore_plpython3u','jsonb_plpython3u', 'ltree_plpython3u']:
            pytest.skip("Skipping extension " + extension + " for Ubuntu based in pg: " + os.getenv("VERSION"))
    if dist.lower() in ['debian', 'ubuntu'] and extension in ['postgis_tiger_geocoder-3','postgis_sfcgal-3','postgis_raster-3',
        'postgis_topology-3','address_standardizer_data_us','postgis_tiger_geocoder','postgis_raster','postgis_topology',
        'postgis_sfcgal','address_standardizer-3','postgis-3','address_standardizer','postgis','address_standardizer_data_us-3']:
            pytest.skip("Skipping extension " + extension + " due to multiple dependencies. Already being checked in test_tools.py.")
    # Skip adminpack extension for PostgreSQL 17, 18
    if settings.MAJOR_VER in ["17","18"] and extension == 'adminpack':
        pytest.skip("Skipping adminpack extension as it is dropped in PostgreSQL 17")
    with host.sudo("postgres"):
        drop_extension = host.run(get_psql_binary_path + " -c 'DROP EXTENSION if exists \"{}\" CASCADE;'".format(extension))
        assert drop_extension.rc == 0, drop_extension.stderr
        assert drop_extension.stdout.strip("\n") == "DROP EXTENSION", drop_extension.stdout
        extensions = host.run(get_psql_binary_path + " -c 'SELECT * FROM pg_extension;' | awk 'NR>=3{print $3}'")
        if "11." in os.getenv("VERSION"):
            extensions = host.run(get_psql_binary_path + " -c 'SELECT * FROM pg_extension;' | awk 'NR>=3{print $1}'")
        assert extensions.rc == 0, extensions.stderr
        assert extension not in set(extensions.stdout.split()), extensions.stdout


@pytest.mark.upgrade
def test_plpgsql_extension(host,get_psql_binary_path):
    with host.sudo("postgres"):
        extensions = host.run(get_psql_binary_path + " -c 'SELECT * FROM pg_extension;' | awk 'NR>=3{print $3}'")
        if "11." in os.getenv("VERSION"):
            extensions = host.run(get_psql_binary_path + " -c 'SELECT * FROM pg_extension;' | awk 'NR>=3{print $1}'")
        assert extensions.rc == 0, extensions.stderr
        assert "plpgsql" in set(extensions.stdout.split()), extensions.stdout


@pytest.mark.parametrize("file", DEB_FILES)
def test_deb_files(host, file):
    os = host.system_info.distribution
    if os.lower() in ["redhat", "centos", "rhel", "rocky", "ol"]:
        pytest.skip("This test only for Debian based platforms")
    with host.sudo("postgres"):
        f = host.file(f"{DATA_DIR}/{file}")
        assert f.exists
        assert f.size > 0
        assert f.content_string != ""
        assert f.user == "postgres"


@pytest.mark.parametrize("file", RHEL_FILES)
def test_rpm_files(file, host):
    os = host.system_info.distribution
    if os in ["debian", "ubuntu"]:
        pytest.skip("This test only for RHEL based platforms")
    with host.sudo("postgres"):
        f = host.file(f"{DATA_DIR}/{file}")
        assert f.exists
        assert f.size > 0
        assert f.content_string != ""
        assert f.user == "postgres"


@pytest.mark.parametrize("language", LANGUAGES)
def test_language(host,get_psql_binary_path, language):
    deb_dists = ['debian', 'ubuntu']
    rpm_dists = ["redhat", "centos", "rhel", "rocky", "ol"]
    dist = host.system_info.distribution
    with host.sudo("postgres"):
        # if dist.lower() in ["redhat", "centos", "rhel", "rocky", "ol"]:
        #     if "python3" in language:
        #         pytest.skip("Skipping python3 language for Centos or RHEL")
        if dist.lower() in rpm_dists and language in ['plpythonu', "plpython2u"]:
            pytest.skip("Skipping python2 extensions for RHEL on Major version 16")
        if dist.lower() in deb_dists and language in ['plpythonu', "plpython2u"]:
            pytest.skip("Skipping python2 extensions for DEB based")
        if language in ['plpythonu', "plpython2u"] and settings.MAJOR_VER in ["12","11"] and host.system_info.release.startswith("9"):
            pytest.skip("Skipping python2 extensions for OL 9 based ppg 12 & 11")
        lang = host.run(get_psql_binary_path + " -c 'CREATE LANGUAGE {};'".format(language))
        assert lang.rc == 0, lang.stderr
        assert lang.stdout.strip("\n") in ["CREATE LANGUAGE", "CREATE EXTENSION"], lang.stdout
        if settings.MAJOR_VER in ["12","11"]:
            drop_lang = host.run(get_psql_binary_path + " -c 'DROP LANGUAGE if exists {};'".format(language))
            assert drop_lang.rc == 0, drop_lang.stderr
            assert drop_lang.stdout.strip("\n") in ["DROP LANGUAGE"], lang.stdout
        else:
            drop_lang = host.run(get_psql_binary_path + " -c 'DROP EXTENSION if exists {};'".format(language))
            assert drop_lang.rc == 0, drop_lang.stderr
            assert drop_lang.stdout.strip("\n") in ["DROP LANGUAGE", "DROP EXTENSION"], lang.stdout


@pytest.mark.upgrade
def test_postgres_client_string(host, get_psql_binary_path):
    if settings.MAJOR_VER in ["11"]:
        pytest.skip("Skipping for ppg 11")
    if settings.MAJOR_VER in ["17"]:
        assert f"psql (PostgreSQL) {pg_versions['version']} - Percona Server for PostgreSQL {pg_versions['percona-version']}" in host.check_output(f"{get_psql_binary_path}  -V")
    else:
        assert f"psql (PostgreSQL) {pg_versions['version']}" in host.check_output(f"{get_psql_binary_path}  -V")


# def test_start_stop_postgresql(start_stop_postgresql):
#     assert start_stop_postgresql.rc == 0, start_stop_postgresql.rc
#     assert "server is running" in start_stop_postgresql.stdout, start_stop_postgresql.stdout


# def test_restart_postgresql(restart_postgresql):
#     assert restart_postgresql.rc == 0, restart_postgresql.stderr
#     assert "server is running" in restart_postgresql.stdout, restart_postgresql.stdout


def test_build_with_liburing(host, get_server_bin_path):
    if settings.MAJOR_VER not in ["18"]:
        pytest.skip("Skipping, test only for PostgreSQL 18 version")

    distribution = host.system_info.distribution.lower()
    if distribution in ["redhat", "centos", "rhel", "rocky", "ol"] and \
    host.system_info.release.startswith("8"):
        pytest.skip(f"liburing not supported on {distribution} 8 for postgres {settings.MAJOR_VER}")

    cmd = f"{get_server_bin_path}/pg_config --configure"
    output = host.check_output(cmd)
    assert '--with-liburing' in output, "PostgreSQL 18 was built without --with-liburing"


@pytest.mark.parametrize(
    "flag",
    [
        ("--enable-cassert"),
        ("--disable-thread-safety"),
    ],
)
def test_pg_config_flags(host, get_server_bin_path, flag):
    """
    Verify that certain build flags are NOT present in pg_config --configure output.
    """

    # Get the PostgreSQL configuration output
    cmd = f"{get_server_bin_path}/pg_config --configure"
    output = host.check_output(cmd)

    assert flag not in output, (
        f"PostgreSQL was built with {flag}, but it should NOT be present"
    )