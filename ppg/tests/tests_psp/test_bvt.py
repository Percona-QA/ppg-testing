# PSP 16 BVT: PSP is the ppg-16.x package set plus pg_tde (see tests_psp/test_tde.py),
# so the ppg BVT applies verbatim — re-export it rather than fork 300 lines.
# pytest collects imported test_* functions; fixtures come along with the import.
import os

import pytest
import testinfra.utils.ansible_runner

from .. import settings
from ..tests_ppg.test_bvt import *  # noqa: F401,F403

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')
pg_versions = settings.get_settings(os.environ['MOLECULE_SCENARIO_NAME'])[os.getenv("VERSION")]


# Override: the ppg test expects the "Percona Distribution" psql banner for
# PG <= 16, but PSP builds brand the client as Percona Server for PostgreSQL.
# TODO: tighten to the exact "... {percona-version}" form once the first run
# confirms the full banner string PSP 16 ships.
@pytest.mark.upgrade
def test_postgres_client_string(host):
    banner = host.check_output('psql -V')
    assert f"psql (PostgreSQL) {pg_versions['version']}" in banner, banner
    assert "Percona Server for PostgreSQL" in banner, banner
