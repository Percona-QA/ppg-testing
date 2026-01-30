import os
import time

import testinfra.utils.ansible_runner


testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


def test_pg_stat_monitor(host):
    with host.sudo("postgres"):
        os = host.system_info.distribution

        result = host.run("locale -a | grep en_US.utf8")
        if result.rc != 0:
            print("WARNING: UTF-8 Locale still missing!")

#        result = host.run("cd /tmp/pg_stat_monitor && export LANG=en_US.UTF-8 && export LC_ALL=en_US.UTF-8 && export LC_COLLATE=C && export PG_TEST_PORT_DIR=tmp/pg_stat_monitor && make installcheck USE_PGXS=1")
        result = host.run("cd /tmp/pg_stat_monitor && export LC_CTYPE=en_US.UTF-8 && export LC_COLLATE=C && unset LC_ALL && export PG_TEST_PORT_DIR=tmp/pg_stat_monitor && make installcheck USE_PGXS=1")
        print(result.stdout)
        if result.rc != 0:
            print(result.stderr)
            regress_diff_file = host.file("/tmp/pg_stat_monitor/regression.diffs")
            if regress_diff_file.exists:
                print(regress_diff_file.content_string)
            raise AssertionError
