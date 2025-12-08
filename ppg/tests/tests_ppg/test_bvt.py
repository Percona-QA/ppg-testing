import os
import pytest

import testinfra.utils.ansible_runner

from .. import settings

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')
pg_versions = settings.get_settings(os.environ['MOLECULE_SCENARIO_NAME'])[os.getenv("VERSION")]
RHEL_FILES = pg_versions['rhel_files']
RPM7_PACKAGES = pg_versions['rpm7_packages']
RPM_PACKAGES = pg_versions['rpm_packages']
EXTENSIONS = pg_versions['extensions']
LANGUAGES = pg_versions['languages']
DEB_FILES = pg_versions['deb_files']
SKIPPED_DEBIAN = ["ppg-11.8", "ppg-11.9", "ppg-11.10", "ppg-11.12", "ppg-11.17", 'ppg-12.2',
                  'ppg-12.3', "ppg-12.4", "ppg-12.5", "ppg-12.6", "ppg-12.7", "ppg-12.12", "ppg-12.13",
                  "ppg-12.14", "ppg-12.15", "ppg-12.16", "ppg-12.17", "ppg-12.18", "ppg-12.19","ppg-12.20",
                  "ppg-13.0", "ppg-13.1",
                  "ppg-15.0", "ppg-15.1"]
BINARIES = pg_versions['binaries']

@pytest.fixture()
def postgres_unit_file(host):
    cmd = "sudo systemctl list-units| grep postgresql"
    return host.check_output(cmd)


@pytest.fixture()
def start_stop_postgresql(host):
    cmd = "sudo systemctl stop postgresql"
    result = host.run(cmd)
    assert result.rc == 0
    cmd = "sudo systemctl start postgresql"
    result = host.run(cmd)
    assert result.rc == 0
    cmd = "sudo systemctl status postgresql"
    return host.run(cmd)


@pytest.fixture()
def postgresql_binary(host):
    dist = host.system_info.distribution
    pg_bin = f"/usr/lib/postgresql/{settings.MAJOR_VER}/bin/postgres"
    if dist.lower() in ["redhat", "centos", "rhel", "rocky", "ol"]:
        pg_bin = f"/usr/pgsql-{settings.MAJOR_VER}/bin/postgres"
    return host.file(pg_bin)


@pytest.fixture()
def postgresql_query_version(host):
    with host.sudo("postgres"):
        return host.run("psql -c 'SELECT version()' | awk 'NR==3{print $2}'")


@pytest.fixture()
def restart_postgresql(host):
    cmd = "sudo systemctl restart postgresql"
    result = host.run(cmd)
    assert result.rc == 0
    cmd = "sudo systemctl status postgresql"
    return host.run(cmd)


@pytest.fixture()
def extension_list(host):
    with host.sudo("postgres"):
        result = host.check_output("psql -c 'SELECT * FROM pg_available_extensions;' | awk 'NR>=3{print $1}'")
        result = result.split()
        return result


@pytest.fixture()
def insert_data(host):
    dist = host.system_info.distribution
    print(host.run("find / -name pgbench").stdout)
    pgbench_bin = "pgbench"
    if dist.lower() in ["redhat", "centos", "rhel", "rocky", "ol"]:
        pgbench_bin = f"/usr/pgsql-{pg_versions['version'].split('.')[0]}/bin/pgbench"
    with host.sudo("postgres"):
        pgbench = f"{pgbench_bin} -i -s 1"
        result = host.run(pgbench)
        assert result.rc == 0, result.stderr
        select = "psql -c 'SELECT COUNT(*) FROM pgbench_accounts;' | awk 'NR==3{print $1}'"
        result = host.check_output(select)
    yield result.strip("\n")


def test_psql_client_version(host):
    result = host.run('psql --version')
    assert pg_versions['version'] in result.stdout, result.stdout


@pytest.mark.upgrade
@pytest.mark.parametrize("package", pg_versions['deb_packages'])
def test_deb_package_is_installed(host, package):
    dist = host.system_info.distribution
    if dist.lower() in ["redhat", "centos", "rhel", "rocky", "ol"]:
        pytest.skip("This test only for Debian based platforms")
    if package in ['percona-postgresql-server-dev-all']:
        pytest.skip("Skipping for Q2-2025 releses and moving forward.")
    pkg = host.package(package)
    assert pkg.is_installed
    assert pkg.version in pg_versions['deb_pkg_ver']


@pytest.mark.upgrade
@pytest.mark.parametrize("package", RPM_PACKAGES)
def test_rpm_package_is_installed(host, package):
    with host.sudo():
        dist = host.system_info.distribution
        if dist in ["debian", "ubuntu"]:
            pytest.skip("This test only for RHEL based platforms")
        if host.system_info.release == "7":
            pytest.skip("Only for RHEL8 tests")
        if package in [
                'percona-postgresql12-plpython', "percona-postgresql12-plpython-debuginfo", 
                "percona-postgresql11-plpython", "percona-postgresql11-plpython-debuginfo"] and \
                settings.MAJOR_VER in ["12","11"] and host.system_info.release.startswith("9"):
            pytest.skip("Skipping for OL 9 based ppg 12 & 11")
        pkg = host.package(package)
        assert pkg.is_installed
        if package not in ["percona-postgresql-client-common", "percona-postgresql-common"]:
            assert pkg.version == pg_versions['version']
        else:
            assert pkg.version == pg_versions[package]


@pytest.mark.upgrade
@pytest.mark.parametrize("package", RPM7_PACKAGES)
def test_rpm7_package_is_installed(host, package):
    with host.sudo():
        dist = host.system_info.distribution
        if dist in ["debian", "ubuntu"]:
            pytest.skip("This test only for RHEL based platforms")
        if host.system_info.release.startswith("8") or host.system_info.release.startswith("9"):
            pytest.skip("Only for centos7 tests")
        pkg = host.package(package)
        assert pkg.is_installed
        if package not in ["percona-postgresql-client-common", "percona-postgresql-common"]:
            assert pkg.version == pg_versions['version']
        else:
            assert pkg.version == pg_versions[package]


@pytest.mark.upgrade
def test_postgresql_client_version(host):
    dist = host.system_info.distribution
    pkg = "percona-postgresql-{}".format(settings.MAJOR_VER)
    if dist.lower() in ["redhat", "centos", "rhel", "rocky", "ol"]:
        pytest.skip("This test only for Debian based platforms")
    pkg = host.package(pkg)
    assert settings.MAJOR_VER in pkg.version


@pytest.mark.upgrade
def test_postgresql_version(host):
    dist = host.system_info.distribution
    pkg = "percona-postgresql-client-{}".format(settings.MAJOR_VER)
    if dist.lower() in ["redhat", "centos", "rhel", "rocky", "ol"]:
        pkg = "percona-postgresql{}".format(settings.MAJOR_VER)
    pkg = host.package(pkg)
    assert settings.MAJOR_VER in pkg.version, pkg.version


@pytest.mark.upgrade
def test_postgresql_is_running_and_enabled(host):
    dist = host.system_info.distribution
    if dist.lower() in ["redhat", "centos", "rhel", "rocky", "ol"]:
        service_name = f"postgresql-{settings.MAJOR_VER}"
        service = host.service(service_name)
        assert service.is_running
    if dist.lower() in ['debian', 'ubuntu']:
        service_name = "postgresql"
        service_name_2 = f"postgresql@{settings.MAJOR_VER}-main.service"
        service = host.service(service_name)
        service2 = host.service(service_name_2)
        assert service.is_running or service2.is_running


def test_postgres_unit_file(postgres_unit_file):
    assert "postgresql" in postgres_unit_file


def test_postgres_binary(postgresql_binary):
    assert postgresql_binary.exists
    assert postgresql_binary.user == "root"


@pytest.mark.upgrade
@pytest.mark.parametrize("binary", BINARIES)
def test_binaries(host, binary):
    dist = host.system_info.distribution
    bin_path = f"/usr/lib/postgresql/{settings.MAJOR_VER}/bin/"
    if dist.lower() in ["redhat", "centos", "rhel", "rocky", "ol"]:
        bin_path = f"/usr/pgsql-{settings.MAJOR_VER}/bin/"
    bin_full_path = os.path.join(bin_path, binary)
    binary_file = host.file(bin_full_path)
    assert binary_file.exists


@pytest.mark.upgrade
def test_pg_config_server_version(host):
    cmd = "pg_config --version"
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
def test_postgres_client_version(host):
    cmd = "psql --version"
    result = host.check_output(cmd)
    assert settings.MAJOR_VER in result.strip("\n"), result.stdout


@pytest.mark.upgrade
def test_postgres_client_string(host):
    if settings.MAJOR_VER in ["11"]:
        pytest.skip("Skipping for ppg 11")
    if settings.MAJOR_VER in ["17","18"]:
        assert f"psql (PostgreSQL) {pg_versions['version']} - Percona Server for PostgreSQL {pg_versions['percona-version']}" in host.check_output('psql -V')
    else:
        assert f"psql (PostgreSQL) {pg_versions['version']} - Percona Distribution" in host.check_output('psql -V')


def test_start_stop_postgresql(start_stop_postgresql):
    assert start_stop_postgresql.rc == 0, start_stop_postgresql.rc
    assert "active" in start_stop_postgresql.stdout, start_stop_postgresql.stdout


def test_restart_postgresql(restart_postgresql):
    assert restart_postgresql.rc == 0, restart_postgresql.stderr
    assert "active" in restart_postgresql.stdout, restart_postgresql.stdout


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
            'ltree_plpythonu', 'hstore_plpythonu', 'hstore_plpython2u'] and settings.MAJOR_VER in ["13", "14", "15"]:
            pytest.skip("Skipping extension " + extension + " for Centos or RHEL")
        if extension in [
            'plpythonu', "plpython2u", 'jsonb_plpython2u', 'ltree_plpython2u', 'jsonb_plpythonu',
            'ltree_plpythonu', 'hstore_plpythonu', 'hstore_plpython2u'] and settings.MAJOR_VER in ["12","11"] and \
            host.system_info.release.startswith("9"):
            pytest.skip("Skipping extension " + extension + " for OL 9 based ppg 12 & 11")
    if dist.lower() in ['debian', 'ubuntu'] and os.getenv("VERSION") in SKIPPED_DEBIAN:
        if extension in ['plpythonu', "plpython2u", 'jsonb_plpython2u', 'ltree_plpython2u', 'jsonb_plpythonu',
                            'ltree_plpythonu', 'hstore_plpythonu', 'hstore_plpython2u']:
            pytest.skip("Skipping extension " + extension + " for DEB based in pg: " + os.getenv("VERSION"))
    # Skip adminpack extension for PostgreSQL 17
    if settings.MAJOR_VER in ["17","18"] and extension == 'adminpack':
        pytest.skip("Skipping adminpack extension as it is dropped in PostgreSQL 17")
    assert extension in extension_list


@pytest.mark.parametrize("extension", EXTENSIONS)
def test_enable_extension(host, extension):
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
            'jsonb_plpython3u', 'ltree_plpython3u'] and settings.MAJOR_VER in ["13", "14", "15"]:
            pytest.skip("Skipping extension " + extension + " for Centos or RHEL")
        if extension in [
            'plpythonu', "plpython2u", 'jsonb_plpython2u', 'ltree_plpython2u', 'jsonb_plpythonu',
            'ltree_plpythonu', 'hstore_plpythonu', 'hstore_plpython2u', 'hstore_plpython3u',
            'jsonb_plpython3u', 'ltree_plpython3u'] and settings.MAJOR_VER in ["12","11"] and \
            host.system_info.release.startswith("9"):
            pytest.skip("Skipping extension " + extension + " for OL 9 based ppg 12 & 11")

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
    # Skip adminpack extension for PostgreSQL 17
    if settings.MAJOR_VER in ["17","18"] and extension == 'adminpack':
        pytest.skip("Skipping adminpack extension as it is dropped in PostgreSQL 17")
    with host.sudo("postgres"):
        install_extension = host.run("psql -c 'CREATE EXTENSION \"{}\";'".format(extension))
        assert install_extension.rc == 0, install_extension.stderr
        assert install_extension.stdout.strip("\n") == "CREATE EXTENSION", install_extension.stderr
        extensions = host.run("psql -c 'SELECT * FROM pg_extension;' | awk 'NR>=3{print $3}'")
        if "11." in os.getenv("VERSION"):
            extensions = host.run("psql -c 'SELECT * FROM pg_extension;' | awk 'NR>=3{print $1}'")
        assert extensions.rc == 0, extensions.stderr
        assert extension in set(extensions.stdout.split()), extensions.stdout


@pytest.mark.parametrize("extension", EXTENSIONS[::-1])
def test_drop_extension(host, extension):
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
            'jsonb_plpython3u', 'ltree_plpython3u'] and settings.MAJOR_VER in ["13", "14", "15"]:
            pytest.skip("Skipping extension " + extension + " for Centos or RHEL")
        if extension in [
            'plpythonu', "plpython2u", 'jsonb_plpython2u', 'ltree_plpython2u', 'jsonb_plpythonu',
            'ltree_plpythonu', 'hstore_plpythonu', 'hstore_plpython2u', 'hstore_plpython3u',
            'jsonb_plpython3u', 'ltree_plpython3u'] and settings.MAJOR_VER in ["12","11"] and \
            host.system_info.release.startswith("9"):
            pytest.skip("Skipping extension " + extension + " for OL 9 based ppg 12 & 11")

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
    # Skip adminpack extension for PostgreSQL 17
    if settings.MAJOR_VER in ["17","18"] and extension == 'adminpack':
        pytest.skip("Skipping adminpack extension as it is dropped in PostgreSQL 17")
    with host.sudo("postgres"):
        drop_extension = host.run("psql -c 'DROP EXTENSION \"{}\";'".format(extension))
        assert drop_extension.rc == 0, drop_extension.stderr
        assert drop_extension.stdout.strip("\n") == "DROP EXTENSION", drop_extension.stdout
        extensions = host.run("psql -c 'SELECT * FROM pg_extension;' | awk 'NR>=3{print $3}'")
        if "11." in os.getenv("VERSION"):
            extensions = host.run("psql -c 'SELECT * FROM pg_extension;' | awk 'NR>=3{print $1}'")
        assert extensions.rc == 0, extensions.stderr
        assert extension not in set(extensions.stdout.split()), extensions.stdout


@pytest.mark.upgrade
def test_plpgsql_extension(host):
    with host.sudo("postgres"):
        extensions = host.run("psql -c 'SELECT * FROM pg_extension;' | awk 'NR>=3{print $3}'")
        if "11." in os.getenv("VERSION"):
            extensions = host.run("psql -c 'SELECT * FROM pg_extension;' | awk 'NR>=3{print $1}'")
        assert extensions.rc == 0, extensions.stderr
        assert "plpgsql" in set(extensions.stdout.split()), extensions.stdout


@pytest.mark.parametrize("file", DEB_FILES)
def test_deb_files(host, file):
    os = host.system_info.distribution
    if os.lower() in ["redhat", "centos", "rhel", "rocky", "ol"]:
        pytest.skip("This test only for Debian based platforms")
    with host.sudo("postgres"):
        f = host.file(file)
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
        f = host.file(file)
        assert f.exists
        assert f.size > 0
        assert f.content_string != ""
        assert f.user == "postgres"


@pytest.mark.parametrize("language", LANGUAGES)
def test_language(host, language):
    deb_dists = ['debian', 'ubuntu']
    rpm_dists = ["redhat", "centos", "rhel", "rocky", "ol"]
    dist = host.system_info.distribution
    with host.sudo("postgres"):
        # if dist.lower() in ["redhat", "centos", "rhel", "rocky", "ol"]:
        #     if "python3" in language:
        #         pytest.skip("Skipping python3 language for Centos or RHEL")
        if dist.lower() in rpm_dists and language in ['plpythonu', "plpython2u"] and int(settings.MAJOR_VER) >= 12: # settings.MAJOR_VER in ["12", "13" , "14", "15", "16","17"]:
            pytest.skip("Skipping python2 extensions for RHEL on Major version 16")
        if dist.lower() in deb_dists and language in ['plpythonu', "plpython2u"]:
            pytest.skip("Skipping python2 extensions for DEB based")
        if language in ['plpythonu', "plpython2u"] and settings.MAJOR_VER in ["12","11"] and host.system_info.release.startswith("9"):
            pytest.skip("Skipping python2 extensions for OL 9 based ppg 12 & 11")
        lang = host.run("psql -c 'CREATE LANGUAGE {};'".format(language))
        assert lang.rc == 0, lang.stderr
        assert lang.stdout.strip("\n") in ["CREATE LANGUAGE", "CREATE EXTENSION"], lang.stdout
        if settings.MAJOR_VER in ["12","11"]:
            drop_lang = host.run("psql -c 'DROP LANGUAGE {};'".format(language))
            assert drop_lang.rc == 0, drop_lang.stderr
            assert drop_lang.stdout.strip("\n") in ["DROP LANGUAGE"], lang.stdout
        else:
            drop_lang = host.run("psql -c 'DROP EXTENSION {};'".format(language))
            assert drop_lang.rc == 0, drop_lang.stderr
            assert drop_lang.stdout.strip("\n") in ["DROP LANGUAGE", "DROP EXTENSION"], lang.stdout


@pytest.mark.parametrize("percona_package, vanila_package", pg_versions['deb_provides'])
def test_deb_packages_provides(host, percona_package, vanila_package):
    """Execute command for check provides and check that we have link to vanila postgres
    """
    os = host.system_info.distribution
    if os.lower() in ["redhat", "centos", "rhel", "rocky", "ol"]:
        pytest.skip("This test only for Debs.ian based platforms")
    cmd = "dpkg -s {} | grep Provides".format(percona_package)
    result = host.run(cmd)
    provides = set(result.stdout.split())
    provides = {provide.strip(",") for provide in provides}
    assert result.rc == 0, result.stdout
    assert vanila_package in provides, provides


@pytest.mark.parametrize("percona_package, vanila_package", pg_versions['rpm_provides'])
def test_rpm_package_provides(host, percona_package, vanila_package):
    """Execute command for check provides and check that we have link to vanila postgres
    """
    os = host.system_info.distribution
    if os in ["debian", "ubuntu"]:
        pytest.skip("This test only for RHEL based platforms")
    if host.system_info.release == "7":
        pytest.skip("Only for RHEL8 tests")
    cmd = "rpm -q --provides {} | awk \'{{ print $1 }}\'".format(percona_package)
    result = host.run(cmd)
    provides = set(result.stdout.split("\n"))
    assert result.rc == 0, result.stderr
    assert vanila_package in provides, result.stdout


@pytest.mark.parametrize("percona_package, vanila_package", pg_versions['rpm7_provides'])
def test_rpm7_package_provides(host, percona_package, vanila_package):
    """Execute command for check provides and check that we have link to vanila postgres
    """
    os = host.system_info.distribution
    if os in ["debian", "ubuntu"]:
        pytest.skip("This test only for RHEL based platforms")
    if host.system_info.release.startswith("8") or host.system_info.release.startswith("9"):
        pytest.skip("Only for centos7 tests")
    cmd = "rpm -q --provides {} | awk \'{{ print $1 }}\'".format(percona_package)
    result = host.run(cmd)
    provides = set(result.stdout.split())
    assert result.rc == 0, result.stderr
    assert vanila_package in provides, result.stdout


def test_build_with_liburing(host):
    if settings.MAJOR_VER not in ["18"]:
        pytest.skip("Skipping, test only for PostgreSQL 18 version")

    distribution = host.system_info.distribution.lower()
    if distribution in ["redhat", "centos", "rhel", "rocky", "ol"] and \
    host.system_info.release.startswith("8"):
        pytest.skip(f"liburing not supported on {distribution} 8 for postgres {settings.MAJOR_VER}")

    output = host.check_output("pg_config --configure")
    assert '--with-liburing' in output, "PostgreSQL 18 was built without --with-liburing"
