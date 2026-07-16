import os
import re
import time

import testinfra.utils.ansible_runner


testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')

# Postgres instances 1/2 are started via bare `pg_ctl`, not systemd units (unlike
# patroni), so failing over here means invoking pg_ctl directly with the
# version-specific binary path - same VERSION parsing pgpool/setup/tasks/main.yml
# uses for major_version.
MAJOR_VERSION = os.environ['VERSION'].split('.')[0].split('-')[1]
PG_BIN = "/usr/pgsql-{}/bin".format(MAJOR_VERSION)


def _psql_via_pgpool(host, sql, dbname="postgres"):
    with host.sudo("postgres"):
        result = host.run(
            'psql -h 127.0.0.1 -Uappuser -p 9999 {} -c "{}"'.format(
                dbname, sql.replace('"', '\\"')
            )
        )
    return result


def _psql_direct(host, sql, port=5432):
    with host.sudo("postgres"):
        return host.run('psql -p {} -tAc "{}"'.format(port, sql.replace('"', '\\"')))


def test_pgpool_query_succeeds(host):
    result = _psql_via_pgpool(host, "select datname from pg_database")
    assert result.rc == 0, result.stderr


def test_pgpool_reports_healthy_primary_and_standby(host):
    result = _psql_via_pgpool(host, "show pool_nodes")
    assert result.rc == 0, result.stderr
    assert "down" not in result.stdout, result.stdout
    assert "primary" in result.stdout, result.stdout
    assert "standby" in result.stdout, result.stdout


def test_pgpool_version_reported(host):
    result = _psql_via_pgpool(host, "show pool_version")
    assert result.rc == 0, result.stderr
    assert result.stdout.strip(), "show pool_version returned no output"


def _pcp(host, command, args=""):
    with host.sudo("postgres"):
        return host.run(
            "{} -h localhost -p 9898 -U pcpuser {}".format(command, args)
        )


def test_pgpool_pcp_admin_interface(host):
    """
    Smoke-checks pgpool's administrative (PCP) interface, which is separate
    from the main SQL-proxy port (9999) tested everywhere else in this file
    and had no coverage at all. Auth is set up in
    pgpool/setup/tasks/main.yml via pcp.conf + a postgres-owned .pcppass
    file (pcpuser/PcpUser@321).
    """
    result = _pcp(host, "pcp_pool_status")
    assert result.rc == 0, result.stderr
    assert result.stdout.strip(), "pcp_pool_status returned no output"


def _node_line_matches(output, port, role):
    return re.search(r"{}[^\n]*\|[^\n]*{}".format(port, role), output) is not None


def _pool_nodes_select_cnt(host, port):
    result = _psql_via_pgpool(host, "show pool_nodes")
    assert result.rc == 0, result.stderr
    for line in result.stdout.splitlines():
        parts = [p.strip() for p in line.split("|")]
        # columns: node_id, hostname, port, status, pg_status, lb_weight, role, select_cnt, ...
        if len(parts) < 8:
            continue
        if parts[2] == str(port):
            return int(parts[7])
    return None


def test_pgpool_load_balances_read_queries_across_both_nodes(host):
    """
    pgpool.conf sets load_balance_mode = 'on' - this is one of pgpool's two
    headline features (the other being failover, tested below) and had zero
    coverage until now. pgpool picks a backend per session, not per query, so
    running the same read query over many separate connections should
    statistically land on both the primary and the standby given the 50/50
    backend_weight in pgpool.conf.
    """
    baseline_primary = _pool_nodes_select_cnt(host, 5432)
    baseline_standby = _pool_nodes_select_cnt(host, 5433)
    assert baseline_primary is not None and baseline_standby is not None, (
        "could not parse select_cnt for both nodes from show pool_nodes"
    )

    for _ in range(20):
        result = _psql_via_pgpool(host, "select 1")
        assert result.rc == 0, result.stderr

    after_primary = _pool_nodes_select_cnt(host, 5432)
    after_standby = _pool_nodes_select_cnt(host, 5433)

    assert after_primary > baseline_primary, (
        "load balancing never routed a read query to the primary (port 5432) "
        "over 20 separate connections"
    )
    assert after_standby > baseline_standby, (
        "load balancing never routed a read query to the standby (port 5433) "
        "over 20 separate connections - pgpool may be sending all reads to the "
        "primary despite load_balance_mode=on"
    )


def test_pgpool_failover(host):
    """
    Stops the primary Postgres instance (instance 1, port 5432) to simulate a
    crash, promotes the standby (instance 2, port 5433), and confirms pgpool
    detects the new primary and continues to route both reads and writes
    correctly. This is pgpool's core value proposition (streaming_replication
    clustering mode) and was previously never exercised at all.
    """
    with host.sudo("postgres"):
        stop_result = host.run(
            "{}/pg_ctl -D /tmp/data1 -m fast stop".format(PG_BIN)
        )
    assert stop_result.rc == 0, stop_result.stderr

    with host.sudo("postgres"):
        promote_result = host.run(
            "{}/pg_ctl promote -D /tmp/data2".format(PG_BIN)
        )
    assert promote_result.rc == 0, promote_result.stderr

    deadline = time.time() + 60
    promoted = False
    while time.time() < deadline:
        check = _psql_direct(host, "select pg_is_in_recovery()", port=5433)
        if check.stdout.strip() == "f":
            promoted = True
            break
        time.sleep(5)
    assert promoted, "standby (port 5433) did not finish promotion within 60s"

    deadline = time.time() + 60
    pool_nodes_after_failover = None
    while time.time() < deadline:
        result = _psql_via_pgpool(host, "show pool_nodes")
        if result.rc == 0 and _node_line_matches(result.stdout, 5433, "primary"):
            pool_nodes_after_failover = result.stdout
            break
        time.sleep(5)
    assert pool_nodes_after_failover is not None, (
        "pgpool did not report the promoted standby (port 5433) as primary within 60s"
    )

    write_result = None
    deadline = time.time() + 30
    while time.time() < deadline:
        write_result = _psql_via_pgpool(
            host,
            "CREATE TABLE IF NOT EXISTS failover_check(id int); INSERT INTO failover_check VALUES (1);",
            dbname="monitor",
        )
        if write_result.rc == 0:
            break
        time.sleep(5)
    assert write_result is not None and write_result.rc == 0, (
        "Write through pgpool failed after failover promotion: {}".format(
            write_result.stderr if write_result else "no attempt made"
        )
    )


def test_pgpool_failback(host):
    """
    After test_pgpool_failover promotes the standby (port 5433) to primary,
    the old primary (port 5432, stopped) has a diverged timeline and can't
    just be restarted - rebuilding it as a fresh standby of the new primary
    (the same pg_basebackup -R approach pgpool/setup/tasks/main.yml uses to
    build the original standby) is the safe way to restore a healthy 2-node
    topology, regardless of whether wal_log_hints/checksums were enabled at
    initdb time (which would be needed for a faster pg_rewind-based rejoin).

    Node 0 in pgpool.conf is always backend_hostname0/port0 (port 5432) -
    that mapping is static configuration, not something that changes with
    which node is currently primary/standby.
    """
    with host.sudo("postgres"):
        host.run("rm -rf /tmp/data1")

    with host.sudo("postgres"):
        basebackup_result = host.run(
            "{}/pg_basebackup -h 127.0.0.1 -p 5433 -U postgres -D /tmp/data1 -Fp -Xs -R".format(
                PG_BIN
            )
        )
    assert basebackup_result.rc == 0, basebackup_result.stderr

    # The backup copies data2's postgresql.conf verbatim (port = 5433 already
    # appended there) - append port = 5432 after it so it takes effect
    # (postgres uses the last occurrence of a duplicate setting in the file).
    with host.sudo("postgres"):
        host.run("echo 'port = 5432' >> /tmp/data1/postgresql.conf")

    with host.sudo("postgres"):
        start_result = host.run(
            "{}/pg_ctl -D /tmp/data1 -l logfile-data1-rejoin start".format(PG_BIN)
        )
    assert start_result.rc == 0, start_result.stderr

    deadline = time.time() + 60
    streaming = False
    while time.time() < deadline:
        check = _psql_direct(host, "select pg_is_in_recovery()", port=5432)
        if check.stdout.strip() == "t":
            streaming = True
            break
        time.sleep(5)
    assert streaming, "rejoined node (port 5432) did not enter streaming recovery within 60s"

    deadline = time.time() + 60
    replication_confirmed = False
    while time.time() < deadline:
        check = _psql_direct(host, "select count(*) from pg_stat_replication", port=5433)
        if check.stdout.strip().isdigit() and int(check.stdout.strip()) >= 1:
            replication_confirmed = True
            break
        time.sleep(5)
    assert replication_confirmed, (
        "new primary (port 5433) never saw the rejoined standby (port 5432) "
        "in pg_stat_replication"
    )

    # Passive detection: pgpool's regular health check should notice the
    # rejoined node on its own. Some pgpool versions/configs treat a node
    # that was fully marked "down" (as opposed to a node that's merely
    # unreachable for one check) as needing an explicit re-attach rather
    # than auto-recovering - falling back to pcp_attach_node covers that
    # case rather than assuming passive detection always works.
    def _rejoined_and_healthy():
        result = _psql_via_pgpool(host, "show pool_nodes")
        return (
            result.rc == 0
            and _node_line_matches(result.stdout, 5432, "standby")
            and _node_line_matches(result.stdout, 5433, "primary")
            and "down" not in result.stdout
        )

    deadline = time.time() + 60
    pool_nodes_after_failback = None
    while time.time() < deadline:
        if _rejoined_and_healthy():
            pool_nodes_after_failback = True
            break
        time.sleep(5)

    if pool_nodes_after_failback is None:
        _pcp(host, "pcp_attach_node", args="-n 0")
        deadline = time.time() + 30
        while time.time() < deadline:
            if _rejoined_and_healthy():
                pool_nodes_after_failback = True
                break
            time.sleep(5)

    assert pool_nodes_after_failback, (
        "pgpool did not report a healthy 2-node topology (5432=standby, "
        "5433=primary) after failback, even after an explicit pcp_attach_node"
    )
