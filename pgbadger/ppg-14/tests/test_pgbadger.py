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


