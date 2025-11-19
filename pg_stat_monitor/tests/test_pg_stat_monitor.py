import os
import time

import testinfra.utils.ansible_runner


testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


def test_pg_stat_monitor(host):
    with host.sudo("postgres"):
        os = host.system_info.distribution
        if os.lower() in ["redhat", "centos", "rocky", "rhel"] and host.system_info.release == "7":
            result = host.run("cd /tmp/pg_stat_monitor && export PG_TEST_NOCLEAN=1 && export LANG=C && export LC_CTYPE=C && export LC_ALL=C && export PG_TEST_PORT_DIR=tmp/pg_stat_monitor && make installcheck USE_PGXS=1")
        else:
            result = host.run("cd /tmp/pg_stat_monitor && export PG_TEST_NOCLEAN=1 && export LANG=C.UTF-8 && export LC_CTYPE=C && export LC_ALL=C && export PG_TEST_PORT_DIR=tmp/pg_stat_monitor && make installcheck USE_PGXS=1")
        print(result.stderr)
        print(result.stdout)

        files_result = host.run("ls -l /tmp/pg_stat_monitor")
        print("Contents of /tmp/pg_stat_monitor:")
        print(files_result.stdout)

        tmp_check_result = host.run("ls -l /tmp/pg_stat_monitor/tmp_check")
        print("Contents of /tmp/pg_stat_monitor/tmp_check:")
        print(tmp_check_result.stdout)

        # tmp_result_logs = host.run("ls -l /tmp/pg_stat_monitor/tmp_check/log")
        # print("Contents of /tmp/pg_stat_monitor/tmp_check/log:")
        # print(tmp_result_logs.stdout)

        # cat_logs_result = host.run("cat /tmp/pg_stat_monitor/tmp_check/log/*.log")
        # print("Contents of /tmp/pg_stat_monitor/tmp_check/log/.log_file:")
        # print(cat_logs_result.stdout)



        print("-------------------------------- MISC TEST RESULTS --------------------------------")

        misc_result_log = host.run("cat /tmp/pg_stat_monitor/tmp_check/log/021_misc_1_pgsm_regression.log")
        print("Contents of /tmp/pg_stat_monitor/tmp_check/log/021_misc_1_pgsm_regression.log:")
        print(misc_result_log.stdout)

        misc_result_regression_diffs = host.run("cat /tmp/pg_stat_monitor/tmp_check/log/regress_log_021_misc_1")
        print("Contents of /tmp/pg_stat_monitor/tmp_check/log/regress_log_021_misc_1:")
        print(misc_result_regression_diffs.stdout)

        misc_debug_result = host.run("cat /tmp/pg_stat_monitor/t/results/021_misc_1.out")
        print("Contents of /tmp/pg_stat_monitor/t/results/021_misc_1.out:")
        print(misc_debug_result.stdout)

        misc_real_log = host.run("cat /tmp/pg_stat_monitor/tmp_check/t_021_misc_1_pgsm_regression_data/pgdata/log/*")
        print("Contents of /tmp/pg_stat_monitor/tmp_check/t_021_misc_1_pgsm_regression_data/pgdata/log/*:")
        print(misc_real_log.stdout)

        print("-------------------------------- HISTOGRAM TEST RESULTS --------------------------------")

        histogram_result_log = host.run("cat /tmp/pg_stat_monitor/tmp_check/log/030_histogram_pgsm_regression.log")
        print("Contents of /tmp/pg_stat_monitor/tmp_check/log/030_histogram_pgsm_regression.log:")
        print(histogram_result_log.stdout)

        histogram_result_regression_diffs = host.run("cat /tmp/pg_stat_monitor/tmp_check/log/regress_log_030_histogram")
        print("Contents of /tmp/pg_stat_monitor/tmp_check/log/regress_log_030_histogram:")
        print(histogram_result_regression_diffs.stdout)

        histogram_debug_result = host.run("cat /tmp/pg_stat_monitor/t/results/030_histogram.out.debug")
        print("Contents of /tmp/pg_stat_monitor/t/results/030_histogram.out.debug:")
        print(histogram_debug_result.stdout)

        histogram_real_log = host.run("cat /tmp/pg_stat_monitor/tmp_check/t_030_histogram_pgsm_regression_data/pgdata/log/*")
        print("Contents of /tmp/pg_stat_monitor/tmp_check/t_030_histogram_pgsm_regression_data/pgdata/log/*:")
        print(histogram_real_log.stdout)

        print("-------------------------------- END --------------------------------")


        if result.rc != 0:
            # print(host.file("/tmp/pg_stat_monitor/regression.diffs").content_string)
            raise AssertionError
