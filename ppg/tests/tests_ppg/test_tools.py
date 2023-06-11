import os
import pytest

import testinfra.utils.ansible_runner

from .. import settings
# from ppg.tests.settings import get_settings, MAJOR_VER

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')

pg_versions = settings.get_settings(os.environ['MOLECULE_SCENARIO_NAME'])[os.getenv("VERSION")]
MAJOR_VER = settings.MAJOR_VER


@pytest.fixture(scope="module")
def operating_system(host):
    return host.system_info.distribution


@pytest.fixture()
def load_data(host):
    with host.sudo("postgres"):
        pgbench = "pgbench -i -s 1"
        assert host.run(pgbench).rc == 0
        select = "psql -c 'SELECT COUNT(*) FROM pgbench_accounts;' | awk 'NR==3{print $3}'"
        assert host.run(select).rc == 0


@pytest.fixture()
def pgaudit(host):
    dist = host.system_info.distribution
    with host.sudo("postgres"):
        # enable_library = "psql -c \'ALTER SYSTEM SET shared_preload_libraries=\'pgaudit\'\';"
        # result = host.check_output(enable_library)
        # assert result.strip("\n") == "ALTER SYSTEM"
        enable_pgaudit = "psql -c 'CREATE EXTENSION pgaudit;'"
        result = host.check_output(enable_pgaudit)
        assert result.strip("\n") == "CREATE EXTENSION"
        cmd = """
        psql -c \"SELECT setting FROM pg_settings WHERE name='shared_preload_libraries';\"
        """
        result = host.check_output(cmd)
        assert "pgaudit" in result, result
        enable_ddl = """psql -c \"ALTER SYSTEM SET pgaudit.log = 'all';\""""
        result = host.check_output(enable_ddl)
        assert result.strip("\n") == "ALTER SYSTEM"
        reload_conf = "psql -c 'SELECT pg_reload_conf();'"
        result = host.run(reload_conf)
        assert result.rc == 0
        create_table = "psql -c \"CREATE TABLE t1 (id int,name varchar(30));\""
        result = host.run(create_table)
        assert result.rc == 0
        assert result.stdout.strip("\n") == "CREATE TABLE"
        log_file = "/var/log/postgresql/postgresql-{}-main.log".format(settings.MAJOR_VER)
        if dist.lower() in ["debian", "ubuntu"]:
            log_file = "/var/log/postgresql/postgresql-{}-main.log".format(settings.MAJOR_VER)
        elif dist.lower() in ["redhat", "centos", "ol", "rhel"]:
            log_files = "ls /var/lib/pgsql/{}/data/log/".format(settings.MAJOR_VER)
            file_name = host.check_output(log_files).strip("\n")
            log_file = "".join(["/var/lib/pgsql/{}/data/log/".format(settings.MAJOR_VER), file_name])
        file = host.file(log_file)
        file_content = file.content_string
    yield file_content
    with host.sudo("postgres"):
        drop_pgaudit = "psql -c 'DROP EXTENSION pgaudit;'"
        result = host.check_output(drop_pgaudit)
        assert result.strip("\n") == "DROP EXTENSION"
    if dist.lower() in ["debian", "ubuntu"]:
        cmd = "sudo systemctl restart postgresql"
    elif dist.lower() in ["redhat", "centos", "ol", "rhel"]:
        cmd = "sudo systemctl restart postgresql-{}".format(MAJOR_VER)
    result = host.run(cmd)
    assert result.rc == 0


@pytest.fixture()
def pgbackrest_version(host, operating_system):
    return host.check_output("pgbackrest version").strip("\n")


@pytest.fixture(scope="module")
def configure_postgres_pgbackrest(host):
    with host.sudo("postgres"):
        wal_senders = """psql -c \"ALTER SYSTEM SET max_wal_senders=3;\""""
        assert host.check_output(wal_senders).strip("\n") == "ALTER SYSTEM"
        wal_level = """psql -c \"ALTER SYSTEM SET wal_level='replica';\""""
        assert host.check_output(wal_level).strip("\n") == "ALTER SYSTEM"
        archive = """psql -c \"ALTER SYSTEM SET archive_mode='on';\""""
        assert host.check_output(archive).strip("\n") == "ALTER SYSTEM"
        archive_command = """
        psql -c \"ALTER SYSTEM SET archive_command = 'pgbackrest --stanza=testing archive-push %p';\"
        """
        assert host.check_output(archive_command).strip("\n") == "ALTER SYSTEM"
        reload_conf = "psql -c 'SELECT pg_reload_conf();'"
        result = host.run(reload_conf)
        assert result.rc == 0


@pytest.mark.usefixtures("configure_postgres_pgbackrest")
@pytest.fixture()
def create_stanza(host):
    with host.sudo("postgres"):
        cmd = "pgbackrest stanza-create --stanza=testing --log-level-console=info"
        return host.run(cmd)


@pytest.mark.usefixtures("configure_postgres_pgbackrest")
@pytest.fixture()
def pgbackrest_check(host):
    with host.sudo("postgres"):
        cmd = "pgbackrest check --stanza=testing --log-level-console=info"
        result = host.run(cmd)
        assert result.rc == 0, result.stderr
        return [l.split("INFO:")[-1] for l in result.stdout.split("\n") if "INFO" in l]


@pytest.mark.usefixtures("load_data")
@pytest.mark.usefixtures("configure_postgres_pgbackrest")
@pytest.fixture()
def pgbackrest_full_backup(host):
    with host.sudo("postgres"):
        cmd = "pgbackrest backup --stanza=testing --log-level-console=info"
        result = host.run(cmd)
        assert result.rc == 0
        return [l.split("INFO:")[-1] for l in result.stdout.split("\n") if "INFO" in l]


@pytest.mark.usefixtures("configure_postgres_pgbackrest")
@pytest.fixture()
def pgbackrest_delete_data(host):
    dist = host.system_info.distribution
    data_dir = f"/var/lib/postgresql/{MAJOR_VER}/main/*"
    service_name = "postgresql"
    if dist.lower() in ["redhat", "centos", "ol", "rhel"]:
        data_dir = f"/var/lib/pgsql/{MAJOR_VER}/data/*"
        service_name = f"postgresql-{MAJOR_VER}"
    with host.sudo("root"):
        stop_postgresql = 'systemctl stop {}'.format(service_name)
        s = host.run(stop_postgresql)
        assert s.rc == 0
    with host.sudo("postgres"):
        cmd = "rm -rf {}".format(data_dir)
        result = host.run(cmd)
        assert result.rc == 0


@pytest.mark.usefixtures("configure_postgres_pgbackrest")
@pytest.fixture()
def pgbackrest_restore(pgbackrest_delete_data, host):
    with host.sudo("postgres"):
        result = host.run("pgbackrest --stanza=testing --log-level-stderr=info restore")
        assert result.rc == 0
        return [l.split("INFO:")[-1] for l in result.stdout.split("\n") if "INFO" in l]


@pytest.fixture()
def pgrepack(host):
    dist = host.system_info.distribution
    cmd = f"/usr/lib/postgresql/{MAJOR_VER}/bin/pg_repack"
    if dist.lower() in ["redhat", "centos", "ol", "rhel"]:
        cmd = f"/usr/pgsql-{MAJOR_VER}/bin/pg_repack "
    return host.check_output(cmd)


@pytest.fixture()
def pg_repack_functional(host):
    dist = host.system_info.distribution
    pgbench_bin = "pgbench"
    pg_repack_bin = f"/usr/lib/postgresql/{MAJOR_VER}/bin/pg_repack"
    if dist.lower() in ["redhat", "centos", "ol", "rhel"]:
        pgbench_bin = f"/usr/pgsql-{pg_versions['version'].split('.')[0]}/bin/pgbench"
        pg_repack_bin = f"/usr/pgsql-{MAJOR_VER}/bin/pg_repack"
    with host.sudo("postgres"):
        pgbench = f"{pgbench_bin} -i -s 1"
        assert host.run(pgbench).rc == 0
        select = "psql -c 'SELECT COUNT(*) FROM pgbench_accounts;' | awk 'NR==3{print $3}'"
        assert host.run(select).rc == 0
        cmd = f"{pg_repack_bin} -t pgbench_accounts -j 4"
        if dist.lower() in ["redhat", "centos", "ol", "rhel"]:
            cmd = f"{pg_repack_bin} -t pgbench_accounts -j 4"
        pg_repack_result = host.run(cmd)
    yield pg_repack_result


@pytest.fixture()
def pg_repack_dry_run(host, operating_system):
    dist = host.system_info.distribution
    pgbench_bin = "pgbench"
    pg_repack_bin = f"/usr/lib/postgresql/{MAJOR_VER}/bin/pg_repack"
    if dist.lower() in ["redhat", "centos", "ol", "rhel"]:
        pgbench_bin = f"/usr/pgsql-{pg_versions['version'].split('.')[0]}/bin/pgbench"
        pg_repack_bin = f"/usr/pgsql-{MAJOR_VER}/bin/pg_repack"
    with host.sudo("postgres"):
        pgbench = f"{pgbench_bin} -i -s 1"
        assert host.run(pgbench).rc == 0
        select = "psql -c 'SELECT COUNT(*) FROM pgbench_accounts;' | awk 'NR==3{print $3}'"
        assert host.run(select).rc == 0
        cmd = f"{pg_repack_bin} --dry-run -d postgres"
        if operating_system.lower() in ["redhat", "centos", "ol", "rhel"]:
            cmd = f"{pg_repack_bin} --dry-run -d postgres"

        pg_repack_result = host.run(cmd)
    yield pg_repack_result


@pytest.fixture()
def pg_repack_client_version(host, operating_system):
    with host.sudo("postgres"):
        cmd = f"/usr/lib/postgresql/{MAJOR_VER}/bin/pg_repack --version"
        if operating_system.lower() in ["redhat", "centos", "ol", "rhel"]:
            cmd = f"/usr/pgsql-{MAJOR_VER}/bin/pg_repack --version"
        return host.run(cmd)


@pytest.fixture()
def patroni(host):
    return host.run("/opt/patroni/bin/patroni")


@pytest.fixture()
def patroni_version(host):
    cmd = "patroni --version"
    return host.run(cmd)


def test_pgaudit_package(host):
    with host.sudo():
        os = host.system_info.distribution
        pkgn = ""
        if os.lower() in ["redhat", "centos", "ol", "rhel"]:
            pkgn = "percona-pgaudit"
            # pkgn = "percona-pgaudit14_12"
        elif os in ["debian", "ubuntu"]:
            pkgn = "percona-postgresql-{}-pgaudit".format(MAJOR_VER)
            if "12" not in MAJOR_VER:
                dbgsym_pkgn = "percona-postgresql-{}-pgaudit-dbgsym".format(MAJOR_VER)
                dbgsym_pkg = host.package(dbgsym_pkgn)
                assert dbgsym_pkg.is_installed
                assert pg_versions['pgaudit']['version'] in dbgsym_pkg.version
        if pkgn == "":
            pytest.fail("Unsupported operating system")
        pkg = host.package(pkgn)
        assert pkg.is_installed
        assert pg_versions['pgaudit']['version'] in pkg.version


def test_pgaudit(pgaudit):
    assert "AUDIT" in pgaudit


def test_pgrepack_package(host):
    with host.sudo():

        os = host.system_info.distribution
        pkgn = ""
        if os.lower() in ["redhat", "centos", "ol", "rhel"]:
            pkgn = pg_versions['pgrepack_package_rpm']
        elif os in ["debian", "ubuntu"]:
            pkgn = pg_versions['pgrepack_package_deb']
            if MAJOR_VER != "12":
                pkg_dbgsym = host.package("{}-dbgsym".format(pg_versions['pgrepack_package_deb']))
                assert pkg_dbgsym.is_installed
        if pkgn == "":
            pytest.fail("Unsupported operating system")
        pkg = host.package(pkgn)
        assert pkg.is_installed
        assert pg_versions['pgrepack']['version'] in pkg.version


def test_pgrepack(host):
    with host.sudo("postgres"):
        install_extension = host.run("psql -c 'CREATE EXTENSION \"pg_repack\";'")
        try:
            assert install_extension.rc == 0, install_extension.stdout
            assert install_extension.stdout.strip("\n") == "CREATE EXTENSION"
        except AssertionError:
            pytest.fail("Return code {}. Stderror: {}. Stdout {}".format(install_extension.rc,
                                                                         install_extension.stderr,
                                                                         install_extension.stdout))
            extensions = host.run("psql -c 'SELECT * FROM pg_extension;' | awk 'NR>=3{print $3}'")
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


def test_pgbackrest_package(host):
    with host.sudo():
        os = host.system_info.distribution
        pkgn = ""
        if os.lower() in ["redhat", "centos", "ol", "rhel"]:
            pkgn = "percona-pgbackrest"
        elif os in ["debian", "ubuntu"]:
            pkgn = "percona-pgbackrest"
            doc_pkgn = "percona-pgbackrest-doc"
            docs_pkg = host.package(doc_pkgn)
            dbg_pkg = "percona-pgbackrest-dbgsym"
            dbg = host.package(dbg_pkg)
            assert dbg.is_installed
            assert pg_versions['pgbackrest']['version'] in dbg.version
            assert docs_pkg.is_installed
            assert pg_versions['pgbackrest']['version'] in docs_pkg.version
        if pkgn == "":
            pytest.fail("Unsupported operating system")
        pkg = host.package(pkgn)
        assert pkg.is_installed
        assert pg_versions['pgbackrest']['version'] in pkg.version


def test_pgbackrest_version(pgbackrest_version):
    assert pgbackrest_version == pg_versions['pgbackrest']['binary_version']


def test_pgbackrest_create_stanza(create_stanza):
    assert "INFO: stanza-create command end: completed successfully" in create_stanza.stdout


def test_pgbackrest_check(pgbackrest_check):
    assert "check command end: completed successfully" in pgbackrest_check[-1]


def test_pgbackrest_full_backup(pgbackrest_full_backup):
    assert "expire command end: completed successfully" in pgbackrest_full_backup[-1]


def test_pgbackrest_restore(host):
    os = host.system_info.distribution
    if os.lower() in ["redhat", "centos", "ol", "rhel"]:
        service_name = "postgresql-{}".format(MAJOR_VER)
    else:
        service_name = "postgresql"
    with host.sudo("root"):
        stop_postgresql = 'systemctl start {}'.format(service_name)
        assert host.run(stop_postgresql).rc == 0
    with host.sudo("postgres"):
        select = "psql -c 'SELECT COUNT(*) FROM pgbench_accounts;' | awk 'NR==3{print $1}'"
        result = host.run(select)
        assert result.rc == 0
        assert result.stdout.strip("\n") == "100000"


def test_patroni_package(host):
    with host.sudo():

        os = host.system_info.distribution
        pkgn = ""
        if os.lower() in ["ubuntu", "redhat", "centos", "ol", "rhel"]:
            pkgn = "percona-patroni"
        elif os == "debian":
            pkgn = "percona-patroni"
        if pkgn == "":
            pytest.fail("Unsupported operating system")
        pkg = host.package(pkgn)
        assert pkg.is_installed
        assert pg_versions['patroni']['version'] in pkg.version


def test_patroni_version(patroni_version):
    assert patroni_version.rc == 0, patroni_version.stderr
    assert patroni_version.stdout.strip("\n") == pg_versions['patroni']['binary_version']


def test_patroni_service(host):
    patroni = host.service("patroni")
    assert patroni.is_enabled


def test_pg_stat_monitor_package_version(host):
    dist = host.system_info.distribution
    if dist.lower() in ["ubuntu", "debian"]:
        pg_stat = host.package(f"percona-pg-stat-monitor{MAJOR_VER}")
    else:
        pg_stat = host.package(f"percona-pg_stat_monitor{MAJOR_VER}")
    assert pg_versions['PGSM_package_version'] in pg_stat.version


def test_pg_stat_monitor_extension_version(host):
    with host.sudo("postgres"):
        result = host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS pg_stat_monitor;'")
        assert result.rc == 0, result.stderr
        result = host.run("psql -c 'SELECT pg_stat_monitor_version();' | awk 'NR==3{print $1}'")
        assert result.rc == 0, result.stderr
        assert result.stdout.strip("\n") == pg_versions['PGSM_version']


def test_postgis_package_version(host):
    ppg_version=float(pg_versions['version'])

    if (pg_versions['version'].startswith("15") and ppg_version <= 15.2) or \
    (pg_versions['version'].startswith("14") and ppg_version <= 14.7) or \
    (pg_versions['version'].startswith("13") and ppg_version <= 13.10) or \
    (pg_versions['version'].startswith("12") and ppg_version <= 12.14) or \
    (pg_versions['version'].startswith("11") and ppg_version <= 11.19):
        pytest.skip("Postgis not available on " + pg_versions['version'])

    dist = host.system_info.distribution
    if dist.lower() in ["ubuntu", "debian"]:
        postgis = host.package(f"percona-postgresql-{MAJOR_VER}-postgis-3")
        assert pg_versions['postgis_package_version'] in postgis.version
        postgis = host.package(f"percona-postgresql-{MAJOR_VER}-postgis-3-scripts")
        assert pg_versions['postgis_package_version'] in postgis.version
        postgis = host.package("percona-postgresql-postgis-scripts")
        assert pg_versions['postgis_package_version'] in postgis.version
        postgis = host.package("percona-postgresql-postgis")
        assert pg_versions['postgis_package_version'] in postgis.version
    else:
        postgis = host.package("percona-postgis33")
        assert pg_versions['postgis_package_version'] in postgis.version
        postgis = host.package("percona-postgis33-client")
        assert pg_versions['postgis_package_version'] in postgis.version
        postgis = host.package("percona-postgis33-debuginfo")
        assert pg_versions['postgis_package_version'] in postgis.version
        postgis = host.package("percona-postgis33-devel")
        assert pg_versions['postgis_package_version'] in postgis.version
        postgis = host.package("percona-postgis33-docs")
        assert pg_versions['postgis_package_version'] in postgis.version
        postgis = host.package("percona-postgis33-gui")
        assert pg_versions['postgis_package_version'] in postgis.version
        postgis = host.package("percona-postgis33-llvmjit")
        assert pg_versions['postgis_package_version'] in postgis.version
        postgis = host.package("percona-postgis33-utils")
        assert pg_versions['postgis_package_version'] in postgis.version
        if host.system_info.release.startswith("8") or host.system_info.release.startswith("9"):
            postgis = host.package("percona-postgis33-client-debuginfo")
            assert pg_versions['postgis_package_version'] in postgis.version
            postgis = host.package("percona-postgis33-gui-debuginfo")
            assert pg_versions['postgis_package_version'] in postgis.version


@pytest.fixture()
def installed_extensions_list(host):
    with host.sudo("postgres"):
        result = host.check_output("psql -c 'SELECT * FROM pg_available_extensions;' | awk 'NR>=3{print $1}'")
        result = result.split()
        return result


def test_postgis_extenstions_list(installed_extensions_list, host):
    ppg_version=float(pg_versions['version'])

    if (pg_versions['version'].startswith("15") and ppg_version <= 15.2) or \
    (pg_versions['version'].startswith("14") and ppg_version <= 14.7) or \
    (pg_versions['version'].startswith("13") and ppg_version <= 13.10) or \
    (pg_versions['version'].startswith("12") and ppg_version <= 12.14) or \
    (pg_versions['version'].startswith("11") and ppg_version <= 11.19):
        pytest.skip("Postgis not available on " + pg_versions['version'])

    dist = host.system_info.distribution
    POSTGIS_DEB_EXTENSIONS = ['postgis_tiger_geocoder-3','postgis_sfcgal-3','postgis_raster-3','postgis_topology-3',
        'address_standardizer_data_us','postgis_tiger_geocoder','postgis_raster','postgis_topology','postgis_sfcgal',
        'address_standardizer-3','postgis-3','address_standardizer','postgis','address_standardizer_data_us-3']
    POSTGIS_RHEL_EXTENSIONS = ['postgis_sfcgal','address_standardizer','postgis_tiger_geocoder','postgis',
        'postgis_topology','postgis_raster','address_standardizer_data_us']
    if dist.lower() in ["redhat", "centos", "rhel", "ol"]:
        for extension in POSTGIS_RHEL_EXTENSIONS:
            print(extension)
            assert extension in installed_extensions_list
    if dist.lower() in ['debian', 'ubuntu']:
        for extension in POSTGIS_DEB_EXTENSIONS:
            print(extension)
            assert extension in installed_extensions_list


def test_postgis_extensions_create_drop(host):
    ppg_version=float(pg_versions['version'])

    if (pg_versions['version'].startswith("15") and ppg_version <= 15.2) or \
    (pg_versions['version'].startswith("14") and ppg_version <= 14.7) or \
    (pg_versions['version'].startswith("13") and ppg_version <= 13.10) or \
    (pg_versions['version'].startswith("12") and ppg_version <= 12.14) or \
    (pg_versions['version'].startswith("11") and ppg_version <= 11.19):
        pytest.skip("Postgis not available on " + pg_versions['version'])

    with host.sudo("postgres"):
        # result = host.run("psql -c 'SET pgaudit.log = 'none';'")
        # assert result.rc == 0, result.stderr
        result = host.run("psql -c \"SET pgaudit.log = 'none'; CREATE EXTENSION IF NOT EXISTS postgis; SET pgaudit.log = 'all';\"")
        assert result.rc == 0, result.stderr
        result = host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS postgis_raster;'")
        assert result.rc == 0, result.stderr
        result = host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS postgis_sfcgal;'")
        assert result.rc == 0, result.stderr
        result = host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS fuzzystrmatch;'")
        assert result.rc == 0, result.stderr
        result = host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS address_standardizer;'")
        assert result.rc == 0, result.stderr
        result = host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS address_standardizer_data_us;'")
        assert result.rc == 0, result.stderr
        result = host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS postgis_tiger_geocoder;'")
        assert result.rc == 0, result.stderr
        result = host.run("psql -c 'DROP EXTENSION address_standardizer CASCADE;'")
        assert result.rc == 0, result.stderr
        result = host.run("psql -c 'DROP EXTENSION address_standardizer_data_us CASCADE;'")
        assert result.rc == 0, result.stderr
        result = host.run("psql -c 'DROP EXTENSION postgis_tiger_geocoder CASCADE;'")
        assert result.rc == 0, result.stderr
        result = host.run("psql -c 'DROP EXTENSION fuzzystrmatch CASCADE;'")
        assert result.rc == 0, result.stderr
        result = host.run("psql -c 'DROP EXTENSION postgis_raster CASCADE;'")
        assert result.rc == 0, result.stderr
        result = host.run("psql -c 'DROP EXTENSION postgis_sfcgal CASCADE;'")
        assert result.rc == 0, result.stderr
        result = host.run("psql -c 'DROP EXTENSION postgis CASCADE;'")
        assert result.rc == 0, result.stderr
        # result = host.run("psql -c 'SET pgaudit.log = 'all';'")
        # assert result.rc == 0, result.stderr


def test_postgis_extension_version(host):
    ppg_version=float(pg_versions['version'])

    if (pg_versions['version'].startswith("15") and ppg_version <= 15.2) or \
    (pg_versions['version'].startswith("14") and ppg_version <= 14.7) or \
    (pg_versions['version'].startswith("13") and ppg_version <= 13.10) or \
    (pg_versions['version'].startswith("12") and ppg_version <= 12.14) or \
    (pg_versions['version'].startswith("11") and ppg_version <= 11.19):
        pytest.skip("Postgis not available on " + pg_versions['version'])

    with host.sudo("postgres"):
        # result = host.run("psql -c 'SET pgaudit.log = 'none';'")
        # assert result.rc == 0, result.stderr
        result = host.run("psql -c \"SET pgaudit.log = 'none'; CREATE EXTENSION IF NOT EXISTS postgis; SET pgaudit.log = 'all';\"")
        assert result.rc == 0, result.stderr
        result = host.run("psql -c \"SELECT installed_version FROM pg_available_extensions WHERE name LIKE 'postgis';\" | awk 'NR==3{print $1}'")
        assert result.rc == 0, result.stderr
        assert result.stdout.strip("\n") == pg_versions['postgis_version']
        # result = host.run("psql -c 'SET pgaudit.log = 'all';'")
        # assert result.rc == 0, result.stderr


@pytest.mark.parametrize("package", ['pgbadger', 'pgbouncer', 'haproxy'])
def test_package_version(host, package):
    package_name = "-".join(["percona", package])
    pkg = host.package(package_name)
    assert pkg.is_installed
    assert pg_versions[package]['version'] in pkg.version, pkg.version


def test_wal2json_version(host):
    dist = host.system_info.distribution
    if dist.lower() in ["ubuntu", "debian"]:
        wal2json = host.package(f"percona-postgresql-{MAJOR_VER}-wal2json")
    else:
        wal2json = host.package(f"percona-wal2json{MAJOR_VER}")
    assert wal2json.is_installed
    assert pg_versions["wal2json"]['version'] in wal2json.version, wal2json.version


def test_set_user_version(host):
    dist = host.system_info.distribution
    if dist.lower() in ["ubuntu", "debian"]:
        set_user = host.package(f"percona-pgaudit{MAJOR_VER}-set-user")
    else:
        set_user = host.package(f"percona-pgaudit{MAJOR_VER}_set_user")
    assert set_user.is_installed
    assert pg_versions["set_user"]['version'] in set_user.version, set_user.version


@pytest.mark.parametrize("binary", ['pgbadger', 'pgbouncer'])
def test_binary_version(host, binary):
    result = host.run(f"PATH=\"/usr/pgsql-{MAJOR_VER}/bin/:/usr/lib/postgresql/{MAJOR_VER}/bin/:/usr/sbin/:$PATH\" && {binary} --version")
    assert result.rc == 0, result.stderr
    assert pg_versions[binary]['binary_version'] in result.stdout.strip("\n"), result.stdout


def test_etcd(host):
    dist = host.system_info.distribution
    if dist.lower() in ["redhat", "centos", "ol", "rhel"]:
        if "8" in host.system_info.release:
            etcd_package = host.package("etcd")
            assert etcd_package.is_installed
            service = host.service("etcd")
            assert service.is_running
            assert service.is_enabled


def test_python_etcd(host):
    dist = host.system_info.distribution
    if dist.lower() in ["redhat", "centos", "ol", "rhel"]:
        if "8" in host.system_info.release:
            package = host.package("python3-etcd")
            assert package.is_installed


def test_patroni_cluster(host):
    assert host.service("etcd").is_running
    with host.sudo("postgres"):
        select = 'cd && psql --host 127.0.0.1 --port 5000 postgres -c "select version()"'
        result = host.run(select)
        assert result.rc == 0, result.stderr


def test_haproxy_version(host):
    with host.sudo("postgres"):
        version = host.run("haproxy -v")
        assert pg_versions["haproxy"]['version'] in version.stdout.strip("\n"), version.stdout


def test_pgpool_package_version(host):
    dist = host.system_info.distribution
    if dist.lower() in ["ubuntu", "debian"]:
        pgpool = host.package(f"percona-pgpool2")
    else:
        pgpool = host.package(f"percona-pgpool-II-pg{MAJOR_VER}")
    assert pgpool.is_installed
    assert pg_versions["pgpool"]['version'] in pgpool.version, pgpool.version


def test_pgpool_binary_version(host):
    dist = host.system_info.distribution
    if dist.lower() in ["redhat", "centos", "ol", "rhel",'ubuntu']:
        result = host.run(f"pgpool --version 2>&1 | grep pgpool | cut -d' ' -f3")
        assert result.rc == 0, result.stderr
        assert pg_versions["pgpool"]['binary_version'] in result.stdout.strip("\n"), result.stdout


def test_pgpool_service(host):
    dist = host.system_info.distribution
    service_name = ""
    if dist.lower() in ["ubuntu", "debian"]:
        service_name = f"percona-pgpool2"
    else:
        service_name = f"pgpool"
    service = host.service(service_name)
    with host.sudo("postgres"):
            assert service.is_running
            assert service.is_enabled
