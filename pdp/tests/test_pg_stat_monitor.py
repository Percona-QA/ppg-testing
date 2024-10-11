import os
import time

import testinfra.utils.ansible_runner


testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


def test_pg_stat_monitor(host):
    with host.sudo("postgres"):
        os = host.system_info.distribution
        if os.lower() in ["redhat", "centos", "ol", "rhel"] and host.system_info.release == "7":
            result = host.run("cd /tmp/pg_stat_monitor && export LANG=C && export LC_CTYPE=C && export LC_ALL=C && export PG_TEST_PORT_DIR=tmp/pg_stat_monitor && make installcheck USE_PGXS=1")
        else:
            result = host.run("cd /tmp/pg_stat_monitor && export LANG=C.UTF-8 && export LC_CTYPE=C && export LC_ALL=C && export PG_TEST_PORT_DIR=tmp/pg_stat_monitor && make installcheck USE_PGXS=1")
        if result.rc != 0:
            print(result.stderr)
            print(result.stdout)
            print(host.file("/tmp/pg_stat_monitor/regression.diffs").content_string)
            raise AssertionError
