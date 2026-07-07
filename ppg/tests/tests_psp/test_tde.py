# PSP-specific pg_tde presence checks.
#
# The equivalents in tests_ppg/test_tools.py are gated on MAJOR_VER >= 17
# (pg_tde only ever shipped in ppg-17/18); on PSP pg_tde is a first-class
# component of every release, so these run unconditionally.
#
# Presence/version only — encryption is not enabled by the psp-16 roles.
# Functional TDE coverage lives in pg_tde/tde and pg_tde/upgrade.
import os

import pytest
import testinfra.utils.ansible_runner

from .. import settings

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')

pg_versions = settings.get_settings(os.environ['MOLECULE_SCENARIO_NAME'])[os.getenv("VERSION")]
MAJOR_VER = settings.MAJOR_VER

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


@pytest.mark.parametrize("binary", TDE_BINARIES)
def test_tde_binaries_present(host, binary):
    dist = host.system_info.distribution.lower()
    if dist in ["ubuntu", "debian"]:
        bin_path = f"/usr/lib/postgresql/{MAJOR_VER}/bin/{binary}"
    else:
        bin_path = f"/usr/pgsql-{MAJOR_VER}/bin/{binary}"

    file = host.file(bin_path)
    assert file.exists, f"{binary} is missing at {bin_path}"
    assert file.is_file, f"{binary} exists but is not a file at {bin_path}"
    assert file.mode & 0o111, f"{binary} exists but is not executable at {bin_path}"


def test_pg_tde_package_version(host):
    dist = host.system_info.distribution.lower()
    expected_version = pg_versions.get('PG_TDE_package_version')

    if dist in ["ubuntu", "debian"]:
        package_names = [
            f"percona-pg-tde{MAJOR_VER}",
            f"percona-pg-tde{MAJOR_VER}-client",
            f"percona-pg-tde{MAJOR_VER}-dbgsym",
        ]
    else:
        package_names = [
            f"percona-pg_tde{MAJOR_VER}",
            f"percona-pg_tde{MAJOR_VER}-devel",
            f"percona-pg_tde{MAJOR_VER}-debugsource",
            f"percona-pg_tde{MAJOR_VER}-debuginfo",
        ]

    for pkg_name in package_names:
        pkg = host.package(pkg_name)
        assert pkg.is_installed, f"Package {pkg_name} is not installed on {dist}"
        assert expected_version in pkg.version, (
            f"Version mismatch for {pkg_name}. "
            f"Expected to find: {expected_version}, Found: {pkg.version}"
        )


def test_pg_tde_extension(host):
    psql_base = "psql -t -A -c"
    count_sql = "SELECT count(*) FROM pg_extension WHERE extname = 'pg_tde';"

    with host.sudo("postgres"):
        try:
            create_res = host.run(f"{psql_base} 'CREATE EXTENSION IF NOT EXISTS pg_tde CASCADE;'")
            assert create_res.rc == 0, f"Failed to create pg_tde: {create_res.stderr}"

            count = host.run(f'{psql_base} "{count_sql}"').stdout.strip()
            assert count == "1", "pg_tde extension not found in pg_extension table"

            sql_version = host.run(
                f"{psql_base} \"SELECT extversion FROM pg_extension WHERE extname = 'pg_tde';\""
            ).stdout.strip()
            expected_sql_v = pg_versions.get('PG_TDE_sql_version')
            assert sql_version == expected_sql_v, (
                f"SQL version mismatch. Expected {expected_sql_v}, found {sql_version}"
            )

            lib_version = host.run(f"{psql_base} \"SELECT pg_tde_version();\"").stdout.strip()
            expected_lib_v = pg_versions.get('PG_TDE_version')
            assert lib_version == expected_lib_v, (
                f"Library version mismatch. Expected {expected_lib_v}, found {lib_version}"
            )

        finally:
            host.run(f"{psql_base} 'DROP EXTENSION IF EXISTS pg_tde CASCADE;'")

            final_count = host.run(f'{psql_base} "{count_sql}"').stdout.strip()
            assert final_count == "0", "Failed to drop pg_tde extension cleanly"
