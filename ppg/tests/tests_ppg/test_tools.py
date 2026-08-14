import json
import os
import re

import pytest
import testinfra.utils.ansible_runner
from .. import settings
from packaging import version
# from ppg.tests.settings import get_settings, MAJOR_VER

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')

pg_versions = settings.get_settings(os.environ['MOLECULE_SCENARIO_NAME'])[os.getenv("VERSION")]
MAJOR_VER = settings.MAJOR_VER

POSTGIS_VERSION_LIMIT = version.parse("3.3.99")  # Run only for ≤3.3.x tarballs

# List of expected PG-18 TDE binaries
TDE_BINARIES = [
    "pg_tde_archive_decrypt",
    "pg_tde_basebackup",
    "pg_tde_change_key_provider",
    "pg_tde_checksums",
    "pg_tde_resetwal",
    "pg_tde_restore_encrypt",
    "pg_tde_rewind",
    "pg_tde_upgrade",
    "pg_tde_waldump",
]

# Minimum PostgreSQL versions where llvmjit is functional (fixed build)
LLVMJIT_MIN_VERSIONS = {
    14: version.parse("14.23"),
    15: version.parse("15.18"),
    16: version.parse("16.14"),
    17: version.parse("17.10"),
    18: version.parse("18.4"),
}

# Minimum PostgreSQL versions where percona-patroni requires python3.12+ on RHEL
# (the first version strictly after 14.23, 15.18, 16.14, 17.10, 18.4)
PATRONI_PYTHON312_MIN_VERSIONS = {
    14: version.parse("14.24"),
    15: version.parse("15.19"),
    16: version.parse("16.15"),
    17: version.parse("17.11"),
    18: version.parse("18.5"),
}

# Versions an in-place upgrade must originate FROM before the python3.12
# patroni dependency is expected to have been picked up. Below these, the
# upgrade path itself (as opposed to a fresh install) isn't guaranteed to
# have refreshed patroni to the python3.12 build yet (seen on RHEL 8 major
# upgrade 15.18 -> 16.15 and minor upgrade 16.14 -> 16.15, both landing on
# python(abi) = 3.6 instead).
PATRONI_PYTHON312_UPGRADE_FROM_MIN_VERSIONS = {
    14: version.parse("14.24"),
    15: version.parse("15.19"),
    16: version.parse("16.15"),
    17: version.parse("17.11"),
    18: version.parse("18.6"),
}

# Minimum PostgreSQL versions where pg_cron is available
PG_CRON_MIN_VERSIONS = {
    14: version.parse("14.23"),
    15: version.parse("15.18"),
    16: version.parse("16.14"),
    17: version.parse("17.10"),
    18: version.parse("18.4"),
}

# Minimum PostgreSQL versions where percona-pg-telemetry became a weak
# dependency (Recommends/Suggests) of the server package instead of a hard
# Requires/Depends, and percona-telemetry-agent stopped being pulled in at
# all (PG-2615).
TELEMETRY_WEAK_DEP_MIN_VERSIONS = {
    14: version.parse("14.24"),
    15: version.parse("15.19"),
    16: version.parse("16.15"),
    17: version.parse("17.11"),
    18: version.parse("18.5"),
}

# Minimum PostgreSQL versions where pg_tde_upgrade binary is available
PG_TDE_UPGRADE_MIN_VERSIONS = {
    17: version.parse("17.10"),
    18: version.parse("18.4"),
}

# Minimum PostgreSQL versions where libpgpoolpcp3 replaces libpgpool2 on Debian/Ubuntu
LIBPGPOOLPCP3_MIN_VERSIONS = {
    14: version.parse("14.23"),
    15: version.parse("15.18"),
    16: version.parse("16.14"),
    17: version.parse("17.10"),
    18: version.parse("18.4"),
}

# Minimum PostgreSQL versions where pg_gather install location changed
PG_GATHER_MIN_VERSIONS = {
    13: version.parse("13.23"),
    14: version.parse("14.20"),
    15: version.parse("15.15"),
    16: version.parse("16.11"),
    17: version.parse("17.7"),
    18: version.parse("18.1"),
}

# Minimum PostgreSQL versions where PostGIS is available
POSTGIS_MIN_SUPPORTED_VERSIONS = {
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
        elif dist.lower() in ["redhat", "centos", "rocky", "ol", "rhel"]:
            # log_filename rotates by day-of-week (postgresql-%a.log), so more
            # than one file can exist if the run crosses a day boundary --
            # take the most recently modified one, not the raw `ls` output
            # (which would otherwise glue multiple filenames together with an
            # embedded newline and break the `cat` below).
            log_files = "ls -t /var/lib/pgsql/{}/data/log/".format(settings.MAJOR_VER)
            file_name = host.check_output(log_files).splitlines()[0]
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
    elif dist.lower() in ["redhat", "centos", "rocky", "ol", "rhel"]:
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
    if dist.lower() in ["redhat", "centos", "rocky", "ol", "rhel"]:
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
    if dist.lower() in ["redhat", "centos", "rocky", "ol", "rhel"]:
        cmd = f"/usr/pgsql-{MAJOR_VER}/bin/pg_repack "
    return host.check_output(cmd)


@pytest.fixture()
def pg_repack_functional(host):
    dist = host.system_info.distribution
    pgbench_bin = "pgbench"
    pg_repack_bin = f"/usr/lib/postgresql/{MAJOR_VER}/bin/pg_repack"
    if dist.lower() in ["redhat", "centos", "rocky", "ol", "rhel"]:
        pgbench_bin = f"/usr/pgsql-{pg_versions['version'].split('.')[0]}/bin/pgbench"
        pg_repack_bin = f"/usr/pgsql-{MAJOR_VER}/bin/pg_repack"
    with host.sudo("postgres"):
        pgbench = f"{pgbench_bin} -i -s 1"
        assert host.run(pgbench).rc == 0
        select = "psql -c 'SELECT COUNT(*) FROM pgbench_accounts;' | awk 'NR==3{print $3}'"
        assert host.run(select).rc == 0
        cmd = f"{pg_repack_bin} -t pgbench_accounts -j 4"
        if dist.lower() in ["redhat", "centos", "rocky", "ol", "rhel"]:
            cmd = f"{pg_repack_bin} -t pgbench_accounts -j 4"
        pg_repack_result = host.run(cmd)
    yield pg_repack_result


@pytest.fixture()
def pg_repack_dry_run(host, operating_system):
    dist = host.system_info.distribution
    pgbench_bin = "pgbench"
    pg_repack_bin = f"/usr/lib/postgresql/{MAJOR_VER}/bin/pg_repack"
    if dist.lower() in ["redhat", "centos", "rocky", "ol", "rhel"]:
        pgbench_bin = f"/usr/pgsql-{pg_versions['version'].split('.')[0]}/bin/pgbench"
        pg_repack_bin = f"/usr/pgsql-{MAJOR_VER}/bin/pg_repack"
    with host.sudo("postgres"):
        pgbench = f"{pgbench_bin} -i -s 1"
        assert host.run(pgbench).rc == 0
        select = "psql -c 'SELECT COUNT(*) FROM pgbench_accounts;' | awk 'NR==3{print $3}'"
        assert host.run(select).rc == 0
        cmd = f"{pg_repack_bin} --dry-run -d postgres"
        if operating_system.lower() in ["redhat", "centos", "rocky", "ol", "rhel"]:
            cmd = f"{pg_repack_bin} --dry-run -d postgres"

        pg_repack_result = host.run(cmd)
    yield pg_repack_result


@pytest.fixture()
def pg_repack_client_version(host, operating_system):
    with host.sudo("postgres"):
        cmd = f"/usr/lib/postgresql/{MAJOR_VER}/bin/pg_repack --version"
        if operating_system.lower() in ["redhat", "centos", "rocky", "ol", "rhel"]:
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
        if os.lower() in ["redhat", "centos", "rocky", "ol", "rhel"]:
            pkgn = f"percona-pgaudit{MAJOR_VER}"
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
        if os.lower() in ["redhat", "centos", "rocky", "ol", "rhel"]:
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
        if os.lower() in ["redhat", "centos", "rocky", "ol", "rhel"]:
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
    if os.lower() in ["redhat", "centos", "rocky", "ol", "rhel"]:
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
        if os.lower() in ["ubuntu", "redhat", "centos", "rocky", "ol", "rhel"]:
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


def _skip_if_patroni_python312_unavailable():
    """Skip if the python3.12+ patroni dependency isn't expected yet for the
    current PostgreSQL version."""
    current_ver = version.parse(pg_versions.get("version", "0.0"))
    min_ver = PATRONI_PYTHON312_MIN_VERSIONS.get(current_ver.major)
    if min_ver is None or current_ver < min_ver:
        pytest.skip(f"python3.12+ patroni dependency not expected for "
                    f"PostgreSQL {pg_versions.get('version')}")


def _skip_if_patroni_python312_upgrade_pending():
    """Skip if this is an in-place upgrade from a version below
    PATRONI_PYTHON312_UPGRADE_FROM_MIN_VERSIONS -- the upgrade path isn't
    guaranteed to have refreshed patroni to the python3.12 build yet. Comes
    from Jenkins-pipelines via FROM_VERSION; a no-op on a fresh install."""
    from_version = os.getenv("FROM_VERSION")
    if not from_version:
        return
    from_ver = version.parse(from_version.split("-", 1)[-1])
    min_ver = PATRONI_PYTHON312_UPGRADE_FROM_MIN_VERSIONS.get(from_ver.major)
    if min_ver is not None and from_ver < min_ver:
        pytest.skip(f"upgrading from PostgreSQL {from_version}, which predates the "
                    f"python3.12 patroni dependency ({min_ver}) -- the upgrade path "
                    f"itself isn't expected to have picked it up yet")


@pytest.mark.upgrade
def test_patroni_requires_python312(host):
    """percona-patroni must declare a hard dependency on python3.12 or newer on
    RHEL-based platforms. Pure dependency-metadata check, valid whether this
    host was freshly installed or just upgraded -- marked `upgrade` so it also
    runs in the minor/major upgrade verifier passes."""
    _skip_if_patroni_python312_unavailable()
    _skip_if_patroni_python312_upgrade_pending()
    dist = host.system_info.distribution
    if dist.lower() in ["ubuntu", "debian"]:
        pytest.skip("python3.12+ dependency pin only applies to RHEL-based packaging")
    with host.sudo():
        result = host.run("rpm -q --requires percona-patroni")
        assert result.rc == 0, f"failed to query percona-patroni requires: {result.stderr}"
        match = re.search(r"python\(abi\)\s*=\s*(\d+)\.(\d+)", result.stdout)
        assert match, (
            f"percona-patroni on {dist} {host.system_info.release} does not declare a "
            f"python(abi) requirement. Requires:\n{result.stdout}"
        )
        abi_version = (int(match.group(1)), int(match.group(2)))
        assert abi_version >= (3, 12), (
            f"percona-patroni on {dist} {host.system_info.release} requires python(abi) "
            f"{abi_version[0]}.{abi_version[1]}, expected 3.12 or newer. "
            f"Requires:\n{result.stdout}"
        )


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


def _skip_if_postgis_unavailable(pg_versions):
    """Helper: Skip tests if PostGIS not available for given PostgreSQL version."""
    pg_version_str = pg_versions["version"]
    pg_version = version.parse(pg_version_str)

    min_supported = POSTGIS_MIN_SUPPORTED_VERSIONS.get(pg_version.major)
    if min_supported and pg_version < min_supported:
        pytest.skip(f"PostGIS not available on PostgreSQL {pg_version_str}")

    return pg_version_str


def _skip_if_postgis_not_3_3():
    """Skip tests if PostGIS version is newer than 3.3.x."""
    postgis_ver = version.parse(pg_versions["postgis_major_version"])
    if postgis_ver > POSTGIS_VERSION_LIMIT:
        pytest.skip("This test only runs for installation with PostGIS 3.3.x or lower.")
    return postgis_ver


def test_postgis_package_version(host):
    """Verify that all installed PostGIS packages match the expected version."""
    _skip_if_postgis_unavailable(pg_versions)
    expected_version = pg_versions["postgis_package_version"]

    dist = host.system_info.distribution.lower()
    release = host.system_info.release

    if dist in ["ubuntu", "debian"]:
        package_names = [
            f"percona-postgresql-{MAJOR_VER}-postgis-3",
            f"percona-postgresql-{MAJOR_VER}-postgis-3-scripts",
            "percona-postgresql-postgis-scripts",
            "percona-postgresql-postgis",
        ]
    else:
        package_names = [
            f"percona-postgis35_{MAJOR_VER}",
            f"percona-postgis35_{MAJOR_VER}-client",
            f"percona-postgis35_{MAJOR_VER}-debuginfo",
            f"percona-postgis35_{MAJOR_VER}-devel",
            f"percona-postgis35_{MAJOR_VER}-docs",
            f"percona-postgis35_{MAJOR_VER}-gui",
            f"percona-postgis35_{MAJOR_VER}-llvmjit",
            f"percona-postgis35_{MAJOR_VER}-utils",
        ]

        # Add version-specific debug packages
        if release.startswith(("8", "9")):
            package_names.extend([
                f"percona-postgis35_{MAJOR_VER}-client-debuginfo",
                f"percona-postgis35_{MAJOR_VER}-gui-debuginfo",
            ])

    for pkg_name in package_names:
        pkg = host.package(pkg_name)
        assert pkg.is_installed, f"Package not installed: {pkg_name}"
        assert expected_version in pkg.version, (
            f"{pkg_name} version mismatch: expected {expected_version}, got {pkg.version}"
        )


@pytest.fixture()
def installed_extensions_list(host):
    with host.sudo("postgres"):
        result = host.check_output("psql -c 'SELECT * FROM pg_available_extensions;' | awk 'NR>=3{print $1}'")
        result = result.split()
        return result


def test_postgis_extenstions_list(installed_extensions_list, host):
    pg_version_str = _skip_if_postgis_unavailable(pg_versions)

    dist = host.system_info.distribution
    POSTGIS_DEB_EXTENSIONS = ['postgis_tiger_geocoder-3','postgis_sfcgal-3','postgis_raster-3','postgis_topology-3',
        'address_standardizer_data_us','postgis_tiger_geocoder','postgis_raster','postgis_topology','postgis_sfcgal',
        'address_standardizer-3','postgis-3','address_standardizer','postgis','address_standardizer_data_us-3']
    POSTGIS_RHEL_EXTENSIONS = ['postgis_sfcgal','address_standardizer','postgis_tiger_geocoder','postgis',
        'postgis_topology','postgis_raster','address_standardizer_data_us']
    if dist.lower() in ["redhat", "centos", "rhel", "rocky", "ol"]:
        for extension in POSTGIS_RHEL_EXTENSIONS:
            print(extension)
            assert extension in installed_extensions_list
    if dist.lower() in ['debian', 'ubuntu']:
        for extension in POSTGIS_DEB_EXTENSIONS:
            print(extension)
            assert extension in installed_extensions_list


def test_postgis_extensions_create_drop(host):
    """Verify PostGIS-related extensions can be created and dropped cleanly."""
    _skip_if_postgis_unavailable(pg_versions)

    with host.sudo("postgres"):
        # List of extensions to test
        extensions = [
            "postgis",
            "postgis_raster",
            "postgis_sfcgal",
            "fuzzystrmatch",
            "address_standardizer",
            "address_standardizer_data_us",
            "postgis_tiger_geocoder",
        ]

        # Create postgis first with pgaudit temporarily disabled
        result = host.run(
            "psql -c \"SET pgaudit.log = 'none'; "
            "CREATE EXTENSION IF NOT EXISTS postgis; "
            "SET pgaudit.log = 'all';\""
        )
        assert result.rc == 0, f"Failed to create postgis: {result.stderr}"

        # Create all other extensions
        for ext in extensions[1:]:
            result = host.run(f"psql -c 'CREATE EXTENSION IF NOT EXISTS {ext};'")
            assert result.rc == 0, f"Failed to create {ext}: {result.stderr}"

        # Drop extensions in reverse order (to satisfy dependencies)
        for ext in reversed(extensions):
            result = host.run(f"psql -c 'DROP EXTENSION IF EXISTS {ext} CASCADE;'")
            assert result.rc == 0, f"Failed to drop {ext}: {result.stderr}"

        # result = host.run("psql -c 'SET pgaudit.log = 'all';'")
        # assert result.rc == 0, result.stderr


def test_postgis_extension_version(host):
    pg_version_str = _skip_if_postgis_unavailable(pg_versions)

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


@pytest.mark.parametrize("binary", ["shp2pgsql", "pgsql2shp"])
def test_postgis_binary_version(host, binary):
    """Verify that PostGIS client binaries report the expected version."""
    cmd = f"{binary} | grep -i release | awk '{{print $2}}'"
    result = host.run(cmd)

    assert result.rc == 0, f"Failed to execute {binary}: {result.stderr}"

    extension_version = result.stdout.strip()
    expected_version = pg_versions["postgis_version"]

    print(f"{binary}: expected={expected_version}, got={extension_version}")

    assert expected_version in extension_version, (
        f"{binary} version mismatch: expected {expected_version}, got {extension_version}"
    )


def test_postgis_binary_presence(host):
    dist = host.system_info.distribution
    with host.sudo("postgres"):
        if dist.lower() in ["redhat", "centos", "rhel", "rocky", "ol"]:
            postgis_major_version = float(pg_versions['postgis_major_version'])
            #if postgis_major_version >= 3.5:
            #    postgis_binaries_path = "/usr/bin"
            #else:
            #    postgis_binaries_path = f"/usr/pgsql-{MAJOR_VER}/bin"
            if str(pg_versions['postgis_version']) == "3.5.4":
                postgis_binaries_path = "/usr/bin"
            else:
                postgis_binaries_path = f"/usr/pgsql-{MAJOR_VER}/bin"

            # List of expected PostGIS binaries
            binaries = [
                "pgtopo_export",
                "pgtopo_import",
                "pgsql2shp",
                "raster2pgsql",
                "shp2pgsql-gui",
                "shp2pgsql",
            ]

            for binary in binaries:
                binary_file = host.file(f"{postgis_binaries_path}/{binary}")
                assert binary_file.exists, f"{binary} does not exist in {postgis_binaries_path}"
                assert binary_file.is_file, f"{binary} is not a regular file"

        if dist.lower() in ['debian', 'ubuntu']:
            # List of expected PostGIS binaries
            binaries = [
                "pgtopo_export",
                "pgtopo_import",
                "raster2pgsql",
                "pgsql2shp",
                "shp2pgsql",
            ]

            for binary in binaries:
                binary_file = host.file(f"/usr/bin/{binary}")
                assert binary_file.exists, f"{binary} does not exist in /usr/bin"
                assert binary_file.is_file, f"{binary} is not a regular file"


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
    # dist = host.system_info.distribution
    # if dist.lower() in ["redhat", "centos", "rocky", "ol", "rhel"]:
    #     if "8" in host.system_info.release:
    etcd_package = host.package("etcd")
    assert etcd_package.is_installed
    service = host.service("etcd")
    assert service.is_running
    assert service.is_enabled


def test_python_etcd(host):
    dist = host.system_info.distribution
    if dist.lower() in ["redhat", "centos", "rocky", "ol", "rhel"]:
        if "8" in host.system_info.release:
            package = host.package("python3-etcd")
            assert package.is_installed


def _patroni_config_path(host):
    dist = host.system_info.distribution.lower()
    if dist in ["ubuntu", "debian"]:
        return "/var/lib/postgresql/patroni_test/postgresql1.yml"
    return "/var/lib/pgsql/patroni_test/postgresql1.yml"


def _dump_patroni_diagnostics(host):
    """Best-effort diagnostics for a patroni cluster test failure -- gathered
    inline so a flaky CI failure carries the evidence needed to root-cause
    it (patronictl's view of the cluster, plus each unit's own status/log),
    instead of requiring live SSH archaeology after molecule has already
    destroyed the instance. Only ever called from a failing assertion's
    message (lazily evaluated by `assert`), so it costs nothing when tests
    pass."""
    lines = []
    with host.sudo("postgres"):
        cluster = host.run(f"patronictl -c {_patroni_config_path(host)} list")
    lines.append("--- patronictl list ---")
    lines.append((cluster.stdout or "(no stdout)").strip())
    if cluster.stderr:
        lines.append(cluster.stderr.strip())

    with host.sudo():
        for svc in ["patroni", "patroni0", "patroni1", "patroni2", "etcd", "haproxy"]:
            status = host.run(f"systemctl status {svc} --no-pager -l")
            lines.append(f"--- systemctl status {svc} ---")
            lines.append(status.stdout.strip())

            journal = host.run(f"journalctl -u {svc} --no-pager -n 40")
            lines.append(f"--- journalctl -u {svc} (last 40 lines) ---")
            lines.append(journal.stdout.strip())

    return "\n".join(lines)


def test_patroni_cluster(host):
    assert host.service("etcd").is_running
    with host.sudo("postgres"):
        select = 'cd && psql --host 127.0.0.1 --port 5000 postgres -c "select version()"'
        result = host.run(select)
    assert result.rc == 0, f"{result.stderr}\n\n{_dump_patroni_diagnostics(host)}"


@pytest.fixture(scope="module")
def patroni_cluster_data(host):
    """Run patronictl against the patroni0/1/2 test cluster and return the
    parsed member list. A single successful psql connect through haproxy
    (test_patroni_cluster above) tolerates one dead member as long as
    haproxy still finds a healthy backend among the rest -- that's exactly
    how the patroni0/base-patroni.service etcd identity collision went
    unnoticed for so long. Checking patronictl's member list directly (like
    patroni/setup/tests/test_patroni.py already does) catches a missing or
    unhealthy member precisely instead of relying on haproxy's tolerance."""
    with host.sudo("postgres"):
        result = host.run(f"patronictl -c {_patroni_config_path(host)} list -f json")
        assert result.rc == 0, f"{result.stderr}\n\n{_dump_patroni_diagnostics(host)}"
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        pytest.fail(f"Failed to parse patronictl JSON output: {e}\nOutput: {result.stdout}")


@pytest.mark.upgrade
def test_patroni_cluster_member_count(host, patroni_cluster_data):
    expected_nodes = 3
    assert len(patroni_cluster_data) == expected_nodes, (
        f"Expected {expected_nodes} patroni cluster members (patroni0/1/2), "
        f"found {len(patroni_cluster_data)}: {patroni_cluster_data}\n\n"
        f"{_dump_patroni_diagnostics(host)}"
    )


@pytest.mark.upgrade
def test_patroni_cluster_has_one_leader(host, patroni_cluster_data):
    roles = [node.get("Role") for node in patroni_cluster_data]
    leader_count = roles.count("Leader")
    assert leader_count == 1, (
        f"Expected exactly 1 Leader among the patroni cluster members, "
        f"found {leader_count}: {patroni_cluster_data}\n\n"
        f"{_dump_patroni_diagnostics(host)}"
    )


def test_haproxy_version(host):
    with host.sudo("postgres"):
        version = host.run("haproxy -v")
        assert pg_versions["haproxy"]['version'] in version.stdout.strip("\n"), version.stdout


def test_etcd_package_version(host):
    etcd = host.package(f"etcd")
    assert etcd.is_installed
    assert pg_versions["etcd"]['version'] in etcd.version, etcd.version


def test_etcd_binary_version(host):
    result = host.run(f"etcd --version 2>&1 | grep etcd | cut -d' ' -f3")
    assert result.rc == 0, result.stderr
    assert pg_versions["etcd"]['version'] in result.stdout.strip("\n"), result.stdout


def test_pgpool_package_version(host):
    dist = host.system_info.distribution
    if dist.lower() in ["ubuntu", "debian"]:
        pgpool = host.package(f"percona-pgpool2")
    else:
        pgpool = host.package(f"percona-pgpool-II-pg{MAJOR_VER}")
    assert pgpool.is_installed
    assert pg_versions["pgpool"]['version'] in pgpool.version, pgpool.version


def test_pgpool_libpgpool_package(host):
    """Verify the correct libpgpool variant is installed on Debian/Ubuntu.
    libpgpoolpcp3 replaces libpgpool2 from: 14.23, 15.18, 16.14, 17.10, 18.4."""
    dist = host.system_info.distribution.lower()
    if dist not in ["ubuntu", "debian"]:
        pytest.skip("libpgpool package check only applies to Debian/Ubuntu.")

    current_ver = version.parse(pg_versions.get("version", "0.0"))
    min_ver = LIBPGPOOLPCP3_MIN_VERSIONS.get(current_ver.major)

    if min_ver is not None and current_ver >= min_ver:
        pkg = host.package("libpgpoolpcp3")
        assert pkg.is_installed, (
            f"libpgpoolpcp3 should be installed on PostgreSQL {current_ver} "
            f"(>= {min_ver}) but is not."
        )
        old_pkg = host.package("libpgpool2")
        assert not old_pkg.is_installed, (
            f"libpgpool2 should NOT be installed on PostgreSQL {current_ver} "
            f"(replaced by libpgpoolpcp3 from {min_ver})."
        )
    else:
        pkg = host.package("libpgpool2")
        assert pkg.is_installed, (
            f"libpgpool2 should be installed on PostgreSQL {current_ver} "
            f"(libpgpoolpcp3 not available until {min_ver})."
        )


def test_pgpool_binary_version(host):
    dist = host.system_info.distribution
    if dist.lower() in ["redhat", "centos", "rocky", "ol", "rhel",'ubuntu']:
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


def _is_old_gather_version(pg_version):
    """Return True if gather.sql should be read from /usr/bin for old PG versions."""
    min_supported = PG_GATHER_MIN_VERSIONS.get(pg_version.major)
    return bool(min_supported and pg_version < min_supported)


def _gather_sql_path(dist, major_version):
    """Return correct gather.sql path for new PG versions."""
    if dist.lower() in {"ubuntu", "debian"}:
        return f"/usr/share/postgresql/{major_version}/contrib/gather.sql"
    return f"/usr/pgsql-{major_version}/share/contrib/gather.sql"


def test_pg_gather_output(host):
    dist = host.system_info.distribution

    pg_version_str = pg_versions["version"]
    pg_version = version.parse(pg_version_str)

    with host.sudo("postgres"):
        if _is_old_gather_version(pg_version):
            sql_path = "/usr/bin/gather.sql"
        else:
            sql_path = _gather_sql_path(dist, MAJOR_VER)

        result = host.run(f"cd && psql -X -f {sql_path} > out.txt")

    assert result.rc == 0, result.stderr


def test_pg_gather_file_version(host):
    dist = host.system_info.distribution

    pg_version_str = pg_versions["version"]
    pg_version = version.parse(pg_version_str)

    with host.sudo("postgres"):
        if _is_old_gather_version(pg_version):
            cmd = "cd && psql -X -f /usr/bin/gather.sql > out.txt"
        else:
            sql_path = _gather_sql_path(dist, MAJOR_VER)
            cmd = f"head -5 {sql_path} | tail -1 | cut -d' ' -f3"

        result = host.run(cmd)

    assert result.rc == 0, result.stderr

    expected_version = pg_versions["pg_gather"]["sql_file_version"]
    assert expected_version in result.stdout.strip(), result.stdout


# def test_pg_gather_output(host):
#     dist = host.system_info.distribution

#     # Minimum PostgreSQL versions where pg_gather install location were changed
#     PG_GATHER_VERSIONS = {
#         13: version.parse("13.23"),
#         14: version.parse("14.20"),
#         15: version.parse("15.15"),
#         16: version.parse("16.11"),
#         17: version.parse("17.7"),
#         18: version.parse("18.1"),
#     }

#     pg_version_str = pg_versions["version"]
#     pg_version = version.parse(pg_version_str)

#     min_supported = PG_GATHER_VERSIONS.get(pg_version.major)
#     if min_supported and pg_version < min_supported:
#         with host.sudo("postgres"):
#             result = host.run("cd && psql -X -f /usr/bin/gather.sql > out.txt")
#             assert result.rc == 0, result.stderr
#     else:
#         with host.sudo("postgres"):
#             if dist.lower() in ["ubuntu", "debian"]:
#                 result = host.run(f"cd && psql -X -f /usr/share/postgresql/{MAJOR_VER}/contrib/gather.sql > out.txt")
#             else:
#                 result = host.run(f"cd && psql -X -f /usr/pgsql-{MAJOR_VER}/share/contrib/gather.sql > out.txt")
#             assert result.rc == 0, result.stderr


# def test_pg_gather_file_version(host):
#     dist = host.system_info.distribution

#     # Minimum PostgreSQL versions where pg_gather install location were changed
#     PG_GATHER_VERSIONS = {
#         13: version.parse("13.23"),
#         14: version.parse("14.20"),
#         15: version.parse("15.15"),
#         16: version.parse("16.11"),
#         17: version.parse("17.7"),
#         18: version.parse("18.1"),
#     }

#     pg_version_str = pg_versions["version"]
#     pg_version = version.parse(pg_version_str)

#     min_supported = PG_GATHER_VERSIONS.get(pg_version.major)
#     if min_supported and pg_version < min_supported:
#         with host.sudo("postgres"):
#             result = host.run("cd && psql -X -f /usr/bin/gather.sql > out.txt")
#     else:
#         with host.sudo("postgres"):
#             if dist.lower() in ["ubuntu", "debian"]:
#                 result = host.run(f"head -5 /usr/share/postgresql/{MAJOR_VER}/contrib/gather.sql | tail -1 | cut -d' ' -f3")
#             else:
#                 result = host.run(f"head -5 /usr/pgsql-{MAJOR_VER}/share/contrib/gather.sql | tail -1 | cut -d' ' -f3")
#     assert result.rc == 0, result.stderr
#     assert pg_versions["pg_gather"]['sql_file_version'] in result.stdout.strip("\n"), result.stdout


def test_pg_gather_package_version(host):
    dist = host.system_info.distribution
    if dist.lower() in ["ubuntu", "debian"]:
        pg_gather = host.package(f"percona-pg-gather")
    else:
        pg_gather = host.package(f"percona-pg_gather")
    assert pg_gather.is_installed
    assert pg_versions["pg_gather"]['version'] in pg_gather.version, pg_gather.version


def test_pgvector_package_version(host):
    dist = host.system_info.distribution
    ppg_version=float(pg_versions['version'])

    if ppg_version <= 12.22:
        pytest.skip("pgvector not available on " + pg_versions['version'])

    if dist.lower() in ["ubuntu", "debian"]:
        pgvector = host.package(f"percona-postgresql-{MAJOR_VER}-pgvector")
    else:
        pgvector = host.package(f"percona-pgvector_{MAJOR_VER}")
    assert pgvector.is_installed
    assert pg_versions["pgvector"]['version'] in pgvector.version, pgvector.version


def test_pgvector(host):
    ppg_version=float(pg_versions['version'])

    if ppg_version <= 12.22:
        pytest.skip("pgvector not available on " + pg_versions['version'])

    with host.sudo("postgres"):
        install_extension = host.run("psql -c 'CREATE EXTENSION \"vector\";'")
        try:
            assert install_extension.rc == 0, install_extension.stdout
            assert install_extension.stdout.strip("\n") == "CREATE EXTENSION"
        except AssertionError:
            pytest.fail("Return code {}. Stderror: {}. Stdout {}".format(install_extension.rc,
                                                                         install_extension.stderr,
                                                                         install_extension.stdout))
            extensions = host.run("psql -c 'SELECT * FROM pg_extension;' | awk 'NR>=3{print $3}'")
            assert extensions.rc == 0
            assert "vector" in set(extensions.stdout.split())

    with host.sudo("postgres"):
        extension_version = host.run("psql -c \"select extversion from pg_extension where extname = 'vector';\" | awk 'NR==3{print $1}'")
        try:
            assert extension_version.rc == 0, extension_version.stdout
            assert pg_versions["pgvector"]['extension_version'] in extension_version.stdout.strip("\n"), extension_version.stdout
        except AssertionError:
            pytest.fail("Return code {}. Stderror: {}. Stdout {}".format(extension_version.rc,
                                                                            extension_version.stderr,
                                                                            extension_version.stdout))


def test_pg_telemetry_package_version(host):
    if settings.MAJOR_VER in ["18"]:
        pytest.skip("Telemetry not supported on PSP 18 and onwards.")
    dist = host.system_info.distribution
    if dist.lower() in ["ubuntu", "debian"]:
        pg_telemetry = host.package(f"percona-pg-telemetry{MAJOR_VER}")
    else:
        pg_telemetry = host.package(f"percona-pg-telemetry{MAJOR_VER}")
    assert pg_versions['pg_telemetry_package_version'] in pg_telemetry.version


def test_pg_telemetry_extension_version(host):
    if settings.MAJOR_VER in ["18"]:
        pytest.skip("Telemetry not supported on PSP 18 and onwards.")
    with host.sudo("postgres"):
        result = host.run("psql -c 'CREATE EXTENSION IF NOT EXISTS percona_pg_telemetry;'")
        assert result.rc == 0, result.stderr
        result = host.run("psql -c 'SELECT percona_pg_telemetry_version();' | awk 'NR==3{print $1}'")
        assert result.rc == 0, result.stderr
        assert result.stdout.strip("\n") == pg_versions['pg_telemetry_version']


def _telemetry_weak_dep_expected():
    """True if this version ships the PG-2615 weak-dependency packaging."""
    current_ver = version.parse(pg_versions.get("version", "0.0"))
    min_ver = TELEMETRY_WEAK_DEP_MIN_VERSIONS.get(current_ver.major)
    return min_ver is not None and current_ver >= min_ver


def test_pg_telemetry_agent_not_a_dependency(host):
    """PG-2615: percona-telemetry-agent must not be installed on versions
    shipping the weak-dependency packaging -- it's no longer a dependency
    of percona-pg-telemetry at all."""
    if settings.MAJOR_VER in ["18"]:
        pytest.skip("Telemetry not supported on PSP 18 and onwards.")
    if not _telemetry_weak_dep_expected():
        pytest.skip(f"pre-PG-2615 packaging for PostgreSQL {pg_versions.get('version')}; "
                    f"agent is expected here instead")
    agent = host.package("percona-telemetry-agent")
    assert not agent.is_installed, (
        "percona-telemetry-agent is installed, but PG-2615 removed it as a "
        "runtime dependency of percona-pg-telemetry."
    )


@pytest.mark.upgrade
def test_pg_server_package_recommends_not_requires_telemetry(host):
    """PG-2615: the PG server package must Recommend (not Require)
    percona-pg-telemetry. Pure dependency-metadata check, valid whether this
    host was freshly installed or just upgraded -- marked `upgrade` so it
    also runs in the minor/major upgrade verifier passes (see
    tasks/verify_telemetry_upgrade.yml for the Ansible-layer equivalent)."""
    if settings.MAJOR_VER in ["18"]:
        pytest.skip("Telemetry not supported on PSP 18 and onwards.")
    if not _telemetry_weak_dep_expected():
        pytest.skip(f"pre-PG-2615 packaging for PostgreSQL {pg_versions.get('version')}")

    telemetry_pkg = f"percona-pg-telemetry{MAJOR_VER}"
    dist = host.system_info.distribution.lower()
    if dist in ["redhat", "centos", "rocky", "ol", "rhel"]:
        server_pkg = f"percona-postgresql{MAJOR_VER}-server"
        requires = host.run(f"rpm -q --requires {server_pkg}").stdout
        recommends = host.run(f"rpm -q --recommends {server_pkg}").stdout
    else:
        server_pkg = f"percona-postgresql-{MAJOR_VER}"
        requires = host.run(f"dpkg-query -W -f='${{Depends}}\\n' {server_pkg}").stdout
        recommends = host.run(f"dpkg-query -W -f='${{Recommends}}\\n' {server_pkg}").stdout

    assert telemetry_pkg not in requires, (
        f"{server_pkg} still hard-requires {telemetry_pkg}: {requires}"
    )
    assert telemetry_pkg in recommends, (
        f"{server_pkg} does not recommend {telemetry_pkg}: {recommends}"
    )


@pytest.mark.upgrade
def test_pg_telemetry_package_does_not_depend_on_agent(host):
    """PG-2615: percona-pg-telemetry must not depend on
    percona-telemetry-agent at all. Pure dependency-metadata check, marked
    `upgrade` for the same reason as
    test_pg_server_package_recommends_not_requires_telemetry above."""
    if settings.MAJOR_VER in ["18"]:
        pytest.skip("Telemetry not supported on PSP 18 and onwards.")
    if not _telemetry_weak_dep_expected():
        pytest.skip(f"pre-PG-2615 packaging for PostgreSQL {pg_versions.get('version')}")

    telemetry_pkg = f"percona-pg-telemetry{MAJOR_VER}"
    dist = host.system_info.distribution.lower()
    if dist in ["redhat", "centos", "rocky", "ol", "rhel"]:
        requires = host.run(f"rpm -q --requires {telemetry_pkg}").stdout
    else:
        requires = host.run(f"dpkg-query -W -f='${{Depends}}\\n' {telemetry_pkg}").stdout

    assert "percona-telemetry-agent" not in requires, (
        f"{telemetry_pkg} still depends on percona-telemetry-agent: {requires}"
    )


@pytest.mark.upgrade
def test_pg_telemetry_agent_state_after_upgrade(host):
    """PG-2615: percona-telemetry-agent's expected state after a minor
    upgrade depends on where it upgraded FROM, not just the target version --
    unlike the tests above, this one only makes sense in the upgrade
    verifier pass (it skips outright without a FROM_VERSION, i.e. on a fresh
    install). Mirrors the "agent survives a hard-dep -> weak-dep transition"
    check in tasks/verify_telemetry_upgrade.yml, but only for same-major
    (in-place) upgrades -- cross-major upgrades install the new major's
    packages side by side rather than upgrading anything in place, and are
    covered by the Ansible-layer check instead."""
    if settings.MAJOR_VER in ["18"]:
        pytest.skip("Telemetry not supported on PSP 18 and onwards.")
    from_version = os.getenv("FROM_VERSION")
    if not from_version:
        pytest.skip("no FROM_VERSION (not an upgrade scenario)")

    from_ver = version.parse(from_version.split("-", 1)[-1])
    to_ver = version.parse(pg_versions.get("version", "0.0"))
    if from_ver.major != to_ver.major:
        pytest.skip("cross-major upgrade; old major's packages aren't touched in place, "
                    "see tasks/verify_telemetry_upgrade.yml instead")

    from_min_ver = TELEMETRY_WEAK_DEP_MIN_VERSIONS.get(from_ver.major)
    from_weak_dep = from_min_ver is not None and from_ver >= from_min_ver
    to_weak_dep = _telemetry_weak_dep_expected()

    agent = host.package("percona-telemetry-agent")
    if not from_weak_dep and to_weak_dep:
        assert agent.is_installed, (
            f"percona-telemetry-agent is missing after upgrading from a "
            f"hard-dependency version ({from_version}) to a weak-dependency "
            f"version ({pg_versions.get('version')}) -- it should never be "
            f"force-removed just because it stopped being a dependency."
        )
    elif to_weak_dep:
        # weak-dep -> weak-dep: the agent should never have been installed.
        assert not agent.is_installed, (
            "percona-telemetry-agent is installed on a weak-dependency-to-"
            "weak-dependency upgrade; nothing should have pulled it in."
        )


@pytest.mark.parametrize("binary", TDE_BINARIES)
def test_tde_binaries_present(host, binary):
    """
    Verify all PG-18/17 TDE binaries exist in the correct PostgreSQL 18 bin directory
    depending on OS type (Debian/Ubuntu vs RHEL/CentOS/Rocky).
    """
    # pg_tde only exists on PG-17 and above.
    if int(settings.MAJOR_VER) < 17:
        pytest.skip(f"pg_tde not supported on {MAJOR_VER}.")

    # pg_tde_upgrade was introduced in 17.10 / 18.4.
    if binary == "pg_tde_upgrade":
        current_ver = version.parse(pg_versions.get("version", "0.0"))
        min_ver = PG_TDE_UPGRADE_MIN_VERSIONS.get(current_ver.major)
        if min_ver is None or current_ver < min_ver:
            pytest.skip(
                f"pg_tde_upgrade not available on PostgreSQL {pg_versions.get('version')} "
                f"(requires >= {min_ver})"
            )

    dist = host.system_info.distribution.lower()

    # Determine the PostgreSQL 18 bin directory
    if dist in ["ubuntu", "debian"]:
        bin_path = f"/usr/lib/postgresql/{MAJOR_VER}/bin/{binary}"
    else:  # RHEL / Rocky / AlmaLinux / Amazon Linux 2023
        bin_path = f"/usr/pgsql-{MAJOR_VER}/bin/{binary}"

    file = host.file(bin_path)

    assert file.exists, f"{binary} is missing at {bin_path}"
    assert file.is_file, f"{binary} exists but is not a file at {bin_path}"
    assert file.mode & 0o111, f"{binary} exists but is not executable at {bin_path}"


def test_tde_perl_test_module_present(host):
    """
    Ensure the TDE Perl test module TdeCluster.pm is present in the pgxs directory
    on both Debian/Ubuntu and RHEL-based systems.
    """
    # pg_tde Perl module only exists on PG-17 and above.
    if int(settings.MAJOR_VER) < 17:
        pytest.skip(f"pg_tde not supported on {MAJOR_VER}.")

    dist = host.system_info.distribution.lower()

    if dist in ["ubuntu", "debian"]:
        path = f"/usr/lib/postgresql/{MAJOR_VER}/lib/pgxs/src/test/perl/PostgreSQL/Test/TdeCluster.pm"
    else:
        path = f"/usr/pgsql-{MAJOR_VER}/lib/pgxs/src/test/perl/PostgreSQL/Test/TdeCluster.pm"

    f = host.file(path)
    assert f.exists, f"Missing: {path}"
    assert f.is_file, f"Path is not a file: {path}"
    assert f.size > 0, f"File is empty: {path}"

def test_pgxs_perl_modules_present(host):
    """
    Verify presence of PostgreSQL PGXS Perl test modules on PG-17 and PG-18
    for both Debian/Ubuntu and RHEL-based systems.
    """

    dist = host.system_info.distribution.lower()
    major = int(MAJOR_VER)

    # Debian/Ubuntu path vs RHEL path
    if dist in ["ubuntu", "debian"]:
        base = f"/usr/lib/postgresql/{MAJOR_VER}/lib/pgxs/src/test/perl"
    else:
        base = f"/usr/pgsql-{MAJOR_VER}/lib/pgxs/src/test/perl"

    # PGXS files for PG-17 (AdjustDump.pm does NOT exist on PG17)
    PGXS_PG17 = [
        "PostgreSQL/Test/AdjustUpgrade.pm",
        "PostgreSQL/Test/BackgroundPsql.pm",
        "PostgreSQL/Test/Cluster.pm",
        "PostgreSQL/Test/Kerberos.pm",
        "PostgreSQL/Test/RecursiveCopy.pm",
        "PostgreSQL/Test/SimpleTee.pm",
        "PostgreSQL/Test/Utils.pm",
        "PostgreSQL/Version.pm",
    ]

    # PGXS files for PG-18
    PGXS_PG18 = [
        "PostgreSQL/Test/AdjustDump.pm",
        "PostgreSQL/Test/AdjustUpgrade.pm",
        "PostgreSQL/Test/BackgroundPsql.pm",
        "PostgreSQL/Test/Cluster.pm",
        "PostgreSQL/Test/Kerberos.pm",
        "PostgreSQL/Test/RecursiveCopy.pm",
        "PostgreSQL/Test/SimpleTee.pm",
        "PostgreSQL/Test/Utils.pm",
        "PostgreSQL/Version.pm",
    ]

    # Select correct file list
    if major == 17:
        required_files = PGXS_PG17
    elif major == 18:
        required_files = PGXS_PG18
    else:
        pytest.skip(f"Test only applies to PG-17 and PG-18 (got PG-{major}).")

    # Validate all required files
    for rel_path in required_files:
        path = f"{base}/{rel_path}"
        f = host.file(path)
        assert f.exists, f"Missing required PGXS file: {path}"
        assert f.is_file, f"Not a file: {path}"
        assert f.size > 0, f"File is empty: {path}"


@pytest.mark.skipif(int(MAJOR_VER) < 17, reason=f"pg_tde requires PG 17+, found {MAJOR_VER}")
def test_pg_tde_extension(host):
    # Use -t (tuples only) and -A (unaligned) for bulletproof parsing
    psql_base = "psql -t -A -c"

    with host.sudo("postgres"):
        try:
            # 1. Execute the create command
            create_res = host.run(f"{psql_base} 'CREATE EXTENSION IF NOT EXISTS pg_tde CASCADE;'")
            assert create_res.rc == 0, f"Failed to create pg_tde: {create_res.stderr}"

            # 2. Metadata Verification (Existence)
            count = host.run(f"{psql_base} \"SELECT count(*) FROM pg_extension WHERE extname = 'pg_tde';\"").stdout.strip()
            assert count == "1", "pg_tde extension not found in pg_extension table"

            # 3. Version Check (Catalog Metadata)
            sql_version = host.run(f"{psql_base} \"SELECT extversion FROM pg_extension WHERE extname = 'pg_tde';\"").stdout.strip()
            expected_sql_v = pg_versions.get('PG_TDE_sql_version')
            assert sql_version == expected_sql_v, f"SQL version mismatch. Expected {expected_sql_v}, found {sql_version}"

            # 4. Functional Check (C-Library Version)
            # This verifies the shared library is actually loaded into memory
            lib_version = host.run(f"{psql_base} \"SELECT pg_tde_version();\"").stdout.strip()
            expected_lib_v = pg_versions.get('PG_TDE_version')
            assert lib_version == expected_lib_v, f"Library version mismatch. Expected {expected_lib_v}, found {lib_version}"

        finally:
            # 5. Cleanup (The 'finally' block ensures this runs even if assertions above fail)
            drop_res = host.run(f"{psql_base} 'DROP EXTENSION IF EXISTS pg_tde CASCADE;'")

            # 6. Final Verification
            final_count = host.run(f"{psql_base} \"SELECT count(*) FROM pg_extension WHERE extname = 'pg_tde';\"").stdout.strip()
            assert final_count == "0", "Failed to drop pg_tde extension cleanly"


@pytest.mark.skipif(int(MAJOR_VER) < 17, reason=f"pg_tde is only supported on PostgreSQL 17+, current version: {MAJOR_VER}")
def test_pg_tde_package_version(host):
    dist = host.system_info.distribution.lower()
    expected_version = pg_versions.get('PG_TDE_package_version')

    # 1. Determine package names based on OS family
    # Debian/Ubuntu uses hyphens (-); RHEL/CentOS/Oracle uses underscores (_)
    if dist in ["ubuntu", "debian"]:
        package_names = [
            f"percona-pg-tde{MAJOR_VER}", 
            f"percona-pg-tde{MAJOR_VER}-client"
        ]
    else:
        # Assuming RPM-based (RHEL/OEL/AL)
        package_names = [f"percona-pg_tde{MAJOR_VER}"]

    # 2. Iterate and verify each package
    for pkg_name in package_names:
        pkg = host.package(pkg_name)

        # Check if installed
        assert pkg.is_installed, f"Package {pkg_name} is not installed on {dist}"

        # Check version
        assert expected_version in pkg.version, (
            f"Version mismatch for {pkg_name}. "
            f"Expected to find: {expected_version}, Found: {pkg.version}"
        )


def _skip_if_llvmjit_unavailable():
    """Skip if llvmjit is not available (fixed build) for the current PostgreSQL version."""
    current_ver = version.parse(pg_versions.get("version", "0.0"))
    min_ver = LLVMJIT_MIN_VERSIONS.get(current_ver.major)
    if min_ver is None or current_ver < min_ver:
        pytest.skip(f"llvmjit not available for PostgreSQL {pg_versions.get('version')}")


def _llvmjit_lib_path(host):
    """Return the OS-appropriate path to the PostgreSQL lib directory."""
    dist = host.system_info.distribution.lower()
    if dist in ["redhat", "centos", "rocky", "ol", "rhel"]:
        return f"/usr/pgsql-{MAJOR_VER}/lib"
    return f"/usr/lib/postgresql/{MAJOR_VER}/lib"


def _llvmjit_pg_config(host):
    """Return the OS-appropriate pg_config binary path."""
    dist = host.system_info.distribution.lower()
    if dist in ["redhat", "centos", "rocky", "ol", "rhel"]:
        return f"/usr/pgsql-{MAJOR_VER}/bin/pg_config"
    return f"/usr/lib/postgresql/{MAJOR_VER}/bin/pg_config"


def test_llvmjit_files_present(host):
    """Strategy 1: Verify that LLVM JIT .so and .bc files are present and non-empty."""
    _skip_if_llvmjit_unavailable()
    base_path = _llvmjit_lib_path(host)
    expected_files = [
        f"{base_path}/llvmjit.so",
        f"{base_path}/llvmjit_types.bc",
    ]
    for path in expected_files:
        f = host.file(path)
        assert f.exists, f"Missing LLVM JIT file: {path}"
        assert f.is_file, f"Path exists but is not a file: {path}"
        assert f.size > 0, f"File {path} exists but is empty!"


def test_llvmjit_rpm_ownership(host):
    """Strategy 2: Verify llvmjit.so and llvmjit_types.bc are owned by the llvmjit RPM package.
    Applies to RHEL-family systems only."""
    _skip_if_llvmjit_unavailable()
    dist = host.system_info.distribution.lower()
    if dist not in ["redhat", "centos", "rocky", "ol", "rhel"]:
        pytest.skip("RPM ownership check only applies to RHEL-family systems.")
    lib_path = _llvmjit_lib_path(host)
    expected_pkg = f"percona-postgresql{MAJOR_VER}-llvmjit"
    for filename in ["llvmjit.so", "llvmjit_types.bc"]:
        path = f"{lib_path}/{filename}"
        result = host.run(f"rpm -qf {path}")
        assert result.rc == 0, f"rpm -qf failed for {path}: {result.stderr}"
        assert expected_pkg in result.stdout, (
            f"{path} is not owned by {expected_pkg}. Got: {result.stdout.strip()}"
        )


def test_llvmjit_statically_linked(host):
    """Strategy 3: Verify llvmjit.so has no dynamic dependency on libLLVM (statically linked).
    Applies to RHEL-family systems where Percona ships a statically linked LLVM."""
    _skip_if_llvmjit_unavailable()
    dist = host.system_info.distribution.lower()
    if dist not in ["redhat", "centos", "rocky", "ol", "rhel"]:
        pytest.skip("Static LLVM linking check only applies to RHEL-family systems.")
    so_path = f"{_llvmjit_lib_path(host)}/llvmjit.so"
    result = host.run(f"ldd {so_path}")
    assert result.rc == 0, f"ldd failed on {so_path}: {result.stderr}"
    assert "libLLVM" not in result.stdout, (
        f"llvmjit.so has a dynamic libLLVM dependency — expected static linking.\n"
        f"ldd output:\n{result.stdout}"
    )


def test_llvmjit_symbols_present(host):
    """Strategy 4: Verify the JIT provider entry point is exported from llvmjit.so.

    PostgreSQL loads the JIT provider via dlopen() + dlsym("_PG_jit_provider_init").
    That function fills a JitProviderCallbacks struct with internal function pointers
    (compile_expr, etc.) — those are never dlsym'd directly and are therefore not
    required to be dynamic exports.  _PG_jit_provider_init is the only symbol that
    must appear in the dynamic symbol table on every platform (RHEL, Debian, Ubuntu)."""
    _skip_if_llvmjit_unavailable()
    so_path = f"{_llvmjit_lib_path(host)}/llvmjit.so"

    result = host.run(f"nm -D {so_path} | grep -q '_PG_jit_provider_init'")
    assert result.rc == 0, (
        f"Expected JIT symbol '_PG_jit_provider_init' not found in {so_path}. "
        f"The library may be missing or incorrectly built."
    )


def test_llvmjit_no_undefined_cxx_symbols(host):
    """Strategy 4b: Verify llvmjit.so has no undefined C++ stdlib symbols (_ZSt*).
    Catches the bug where llvmjit.so failed to load at runtime with:
      ERROR: could not load library 'llvmjit.so': undefined symbol: _ZSt21__glibcxx_assert_fail...
    These symbols must be statically linked into llvmjit.so on RHEL builds."""
    _skip_if_llvmjit_unavailable()
    dist = host.system_info.distribution.lower()
    if dist not in ["redhat", "centos", "rocky", "ol", "rhel"]:
        pytest.skip("Undefined C++ symbol check only applies to RHEL-family systems.")
    so_path = f"{_llvmjit_lib_path(host)}/llvmjit.so"
    result = host.run(f"nm -D {so_path} | awk '$2 == \"U\" && $3 ~ /^_ZSt/ {{print}}'")
    assert result.rc == 0, f"nm -D failed on {so_path}: {result.stderr}"
    assert result.stdout.strip() == "", (
        f"llvmjit.so has undefined C++ stdlib symbols (_ZSt*) — "
        f"this will cause a runtime load failure.\n"
        f"Undefined symbols found:\n{result.stdout}"
    )


def test_llvmjit_functional(host):
    """Strategy 5: Verify JIT actually loads and compiles at runtime via EXPLAIN ANALYZE.
    Reproduces the exact failure scenario: if llvmjit.so has undefined symbols the query
    returns ERROR instead of a plan with a JIT: section."""
    _skip_if_llvmjit_unavailable()
    with host.sudo("postgres"):
        result = host.run(
            "psql -c \""
            "SET jit = on; "
            "SET jit_above_cost = 0; "
            "SET jit_inline_above_cost = 0; "
            "SET jit_optimize_above_cost = 0; "
            "EXPLAIN (ANALYZE, VERBOSE, BUFFERS) "
            "SELECT count(*) FROM generate_series(1, 1000000) g WHERE g % 2 = 0;\""
        )
    assert result.rc == 0, (
        f"JIT load failed — possible undefined symbol in llvmjit.so.\n"
        f"stderr: {result.stderr}\nstdout: {result.stdout}"
    )
    assert "JIT:" in result.stdout, (
        f"JIT was not triggered. EXPLAIN ANALYZE output:\n{result.stdout}"
    )


def test_llvmjit_pg_config_compiled_with_llvm(host):
    """Strategy 6: Verify PostgreSQL was compiled with --with-llvm via pg_config --configure."""
    _skip_if_llvmjit_unavailable()
    pg_config = _llvmjit_pg_config(host)
    result = host.run(f"{pg_config} --configure")
    assert result.rc == 0, f"pg_config --configure failed: {result.stderr}"
    assert "--with-llvm" in result.stdout, (
        f"PostgreSQL was not compiled with --with-llvm.\n"
        f"pg_config --configure output:\n{result.stdout}"
    )


def test_pg_oidc_validator_package_version(host):
    # 1. Check Major Version
    major = int(settings.MAJOR_VER)
    if major < 18:
        pytest.skip(f"pg_oidc_validator supported only on PG-18+ (got {major})")

    # 2. Check Specific Minor Version (18.2)
    current_ver_str = pg_versions.get('version', '0.0')
    # Use packaging.version or simple float conversion
    if version.parse(current_ver_str) < version.parse("18.2"):
        pytest.skip(f"pg_oidc_validator requires PG 18.2+, found {current_ver_str}")

    expected_version = pg_versions.get("PG_OIDC_VALIDATOR_package_version")
    if not expected_version:
        pytest.skip("PG_OIDC_VALIDATOR_package_version not defined in pg_versions.")

    # Determine package name based on OS family
    dist = host.system_info.distribution.lower()
    pkg_name = "percona-pg-oidc-validator18" if dist in ["ubuntu", "debian"] else "percona-pg_oidc_validator18"

    pkg = host.package(pkg_name)
    assert pkg.is_installed, f"Package {pkg_name} is not installed"

    # Using 'in' allows for build metadata variations (e.g., 1.0.1-1.el8)
    assert expected_version in pkg.version, (
        f"Version mismatch for {pkg_name}: expected {expected_version}, got {pkg.version}"
    )


def test_pg_oidc_validator_config(host):
    """Verify pg_oidc_validator GUCs and pg_hba.conf are configured correctly.

    Full end-to-end OAuth authentication will be covered by a dedicated OIDC job
    that runs Keycloak. This test confirms the environmental setup is active.
    """
    # 1. Version guardrails
    major = int(settings.MAJOR_VER)
    if major < 18:
        pytest.skip(f"pg_oidc_validator supported only on PG-18+ (got {major})")

    current_ver_str = pg_versions.get('version', '0.0')
    if version.parse(current_ver_str) < version.parse("18.2"):
        pytest.skip(f"pg_oidc_validator requires PG 18.2+, found {current_ver_str}")

    psql = "psql -t -A -c"

    with host.sudo("postgres"):
        # 2. Verify GUC: oauth_validator_libraries
        # 'in' handles the case where multiple libraries are configured
        result = host.run(
            f"{psql} \"SELECT setting FROM pg_settings WHERE name = 'oauth_validator_libraries';\""
        )
        assert result.rc == 0, f"Failed to query pg_settings: {result.stderr}"
        assert "pg_oidc_validator" in result.stdout, (
            f"oauth_validator_libraries is '{result.stdout.strip()}', expected to include 'pg_oidc_validator'"
        )

        # 3. Dynamically locate config files — avoids hardcoded distro paths
        conf_path = host.run(f"{psql} \"SHOW config_file;\"").stdout.strip()
        hba_path = host.run(f"{psql} \"SHOW hba_file;\"").stdout.strip()

        # 4. Verify pg_oidc_validator.authn_field is set in postgresql.conf
        # The library loads lazily on first auth, so pg_settings won't reflect it until then.
        # Checking the config file directly is the reliable approach.
        # Both checks run under postgres sudo to ensure access on RHEL (data dir is 700).
        result = host.run(f"grep -q 'pg_oidc_validator.authn_field' {conf_path}")
        assert result.rc == 0, f"pg_oidc_validator.authn_field not found in {conf_path}"

        # 5. Verify pg_hba.conf has an active (uncommented) oauth entry for oidc_test_user
        result = host.run(f"grep -v '^#' {hba_path} | grep -q 'oauth.*oidc_test_user\\|oidc_test_user.*oauth'")
        assert result.rc == 0, (
            f"No active (uncommented) oauth entry for 'oidc_test_user' found in {hba_path}"
        )


def test_pg_oidc_validator_loaded_module_version(host):
    """Verify pg_oidc_validator's own embedded version (compiled in via
    PG_MODULE_MAGIC_EXT), read through PG18's pg_get_loaded_modules() --
    independent of whatever the OS package metadata says in
    test_pg_oidc_validator_package_version above. The library loads lazily
    on first OAuth attempt, so force it into the session with LOAD first.
    """
    major = int(settings.MAJOR_VER)
    if major < 18:
        pytest.skip(f"pg_oidc_validator supported only on PG-18+ (got {major})")

    current_ver_str = pg_versions.get('version', '0.0')
    if version.parse(current_ver_str) < version.parse("18.2"):
        pytest.skip(f"pg_oidc_validator requires PG 18.2+, found {current_ver_str}")

    expected_version = pg_versions.get("PG_OIDC_VALIDATOR_version")
    if not expected_version:
        pytest.skip("PG_OIDC_VALIDATOR_version not defined in pg_versions.")

    psql = "psql -t -A -c"
    with host.sudo("postgres"):
        # LOAD and the SELECT must run in the same session -- LOAD only
        # loads the module into the backend that issues it, and a separate
        # `psql` invocation would open a fresh connection where the module
        # was never loaded.
        result = host.run(
            f"{psql} \"LOAD 'pg_oidc_validator'; SELECT version FROM "
            f"pg_get_loaded_modules() WHERE module_name = 'pg_oidc_validator';\""
        )
        assert result.rc == 0, f"failed to query pg_get_loaded_modules(): {result.stderr}"
        assert result.stdout.strip() == expected_version, (
            f"pg_oidc_validator loaded-module version mismatch: expected "
            f"{expected_version}, got '{result.stdout.strip()}'"
        )


def _skip_if_pg_cron_unavailable():
    """Skip if pg_cron is not available for the current PostgreSQL version."""
    current_ver = version.parse(pg_versions.get("version", "0.0"))
    min_ver = PG_CRON_MIN_VERSIONS.get(current_ver.major)
    if min_ver is None or current_ver < min_ver:
        pytest.skip(f"pg_cron not available on PostgreSQL {pg_versions.get('version')}")


def test_pg_cron_package_version(host):
    """Verify pg_cron package is installed with the expected version."""
    _skip_if_pg_cron_unavailable()

    dist = host.system_info.distribution.lower()
    expected_version = pg_versions.get("PG_CRON_package_version")
    if not expected_version:
        pytest.skip("PG_CRON_package_version not defined in pg_versions.")

    if dist in ["ubuntu", "debian"]:
        pkg_name = f"percona-postgresql-{MAJOR_VER}-cron"
    else:
        pkg_name = f"percona-pg_cron_{MAJOR_VER}"

    pkg = host.package(pkg_name)
    assert pkg.is_installed, f"Package {pkg_name} is not installed"
    assert expected_version in pkg.version, (
        f"Version mismatch for {pkg_name}: expected {expected_version}, got {pkg.version}"
    )


def test_pg_cron_extension(host):
    """Verify pg_cron extension can be created, schedules jobs, and is removed cleanly."""
    _skip_if_pg_cron_unavailable()

    psql = "psql -t -A -c"
    expected_sql_version = pg_versions.get("PG_CRON_sql_version")

    with host.sudo("postgres"):
        try:
            # 1. Create extension
            result = host.run(f"{psql} 'CREATE EXTENSION IF NOT EXISTS pg_cron;'")
            assert result.rc == 0, f"Failed to create pg_cron: {result.stderr}"

            # 2. Verify it is registered in pg_extension
            count = host.run(
                f"{psql} \"SELECT count(*) FROM pg_extension WHERE extname = 'pg_cron';\""
            ).stdout.strip()
            assert count == "1", "pg_cron extension not found in pg_extension"

            # 3. Verify extension SQL version
            if expected_sql_version:
                sql_ver = host.run(
                    f"{psql} \"SELECT extversion FROM pg_extension WHERE extname = 'pg_cron';\""
                ).stdout.strip()
                assert sql_ver == expected_sql_version, (
                    f"pg_cron SQL version mismatch: expected {expected_sql_version}, got {sql_ver}"
                )

            # 4. Schedule a job and verify it appears in cron.job
            schedule_result = host.run(
                f"{psql} \"SELECT cron.schedule('pg_cron_test_job', '* * * * *', 'SELECT 1');\""
            )
            assert schedule_result.rc == 0, f"Failed to schedule job: {schedule_result.stderr}"

            job_count = host.run(
                f"{psql} \"SELECT count(*) FROM cron.job WHERE jobname = 'pg_cron_test_job';\""
            ).stdout.strip()
            assert job_count == "1", "Scheduled job not found in cron.job"

            # 5. Unschedule the test job
            unschedule = host.run(
                f"{psql} \"SELECT cron.unschedule('pg_cron_test_job');\""
            )
            assert unschedule.rc == 0, f"Failed to unschedule job: {unschedule.stderr}"

        finally:
            # 6. Always drop the extension to keep state clean
            drop = host.run(f"{psql} 'DROP EXTENSION IF EXISTS pg_cron CASCADE;'")
            final_count = host.run(
                f"{psql} \"SELECT count(*) FROM pg_extension WHERE extname = 'pg_cron';\""
            ).stdout.strip()
            assert final_count == "0", "Failed to drop pg_cron extension cleanly"


# def test_pg_telemetry_file_pillar_version(host):
#     output = host.run("cat /usr/local/percona/telemetry/pg/*.json | grep -i pillar_version")
#     assert output.rc == 0, output.stderr
#     assert pg_versions['version'] in output.stdout, output.stdout


# def test_pg_telemetry_file_database_count(host):
#     output = host.run("cat /usr/local/percona/telemetry/pg/*.json | grep -i databases_count")
#     assert output.rc == 0, output.stderr
#     assert '2' in output.stdout, output.stdout
