import os

import testinfra.utils.ansible_runner


testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


def test_pgsm_installed(host):
    """Verify pg_stat_monitor shared library is present on the host.

    NOTE: Full regression tests (make installcheck USE_PGXS=1) are executed
    in the Ansible verify playbook (verify.yml). Running them again here would
    be redundant and significantly slow down the test cycle. This testinfra
    check is intentionally kept lightweight.
    """
    result = host.run("find /usr /opt -name 'pg_stat_monitor*.so' 2>/dev/null | head -1")
    assert result.stdout.strip() != "", "pg_stat_monitor shared library not found on host"
