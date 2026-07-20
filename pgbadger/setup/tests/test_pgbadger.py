import os

import testinfra.utils.ansible_runner


testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


def test_pgbadger(host):
    with host.sudo("postgres"):
        result = host.run('cd /tmp/pgbadger && prove')
        print(result.stdout)
        if result.rc != 0:
            print(result.stderr)
            raise AssertionError


def test_packaged_pgbadger_binary_runs(host):
    # This is the only check that the real
    # percona-pgbadger package (installed by setup/tasks/main.yml) is
    # actually intact and runnable.
    result = host.run("pgbadger --version")
    assert result.rc == 0, result.stderr
    assert result.stdout.strip(), "pgbadger --version returned no output"

