import os
import time

import testinfra.utils.ansible_runner


testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')

MAJOR_VERSION = os.environ['VERSION'].split('.')[0].split('-')[1]
PGDATA = "/var/lib/postgresql/{}/main".format(MAJOR_VERSION)
STANZA = "test"

# These tests exercise the real percona-pgbackrest package (installed by
# pgbackrest/setup/tasks/main.yml, which also writes pgbackrest.conf and
# enables archive_mode/archive_command). Test order matters here: each test
# builds on state left by the previous one (stanza -> full backup ->
# incremental backup -> restore).

def _pgbackrest(host, args):
    with host.sudo("postgres"):
        return host.run("pgbackrest --stanza={} {}".format(STANZA, args))


def _psql(host, sql):
    with host.sudo("postgres"):
        return host.run('psql -tAc "{}"'.format(sql.replace('"', '\\"')))


def _wait_for_postgres_ready(host, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = _psql(host, "SELECT 1;")
        if result.rc == 0:
            return True
        time.sleep(2)
    return False


def _wait_for_postgres_stopped(host, timeout=30):
    """
    "systemctl stop postgresql" can return before the specific postgresql instance's
    background workers (e.g. PG17+'s WAL summarizer, the archiver) have
    actually released pg_wal and data directories, producing
    "rm: cannot remove 'pg_wal': Directory not empty" (seen on a real PG18
    CI run). Poll until no live (non-zombie) postgres process remains.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        with host.sudo():
            check = host.run("ps -C postgres -o stat= | grep -v '^Z' | grep -q .")
        if check.rc != 0:
            return True
        time.sleep(1)
    return False


def test_pgbackrest_stanza_create(host):
    result = _pgbackrest(host, "--log-level-console=info stanza-create")
    assert result.rc == 0, result.stderr


def test_pgbackrest_full_backup(host):
    result = _pgbackrest(host, "--type=full --log-level-console=info backup")
    assert result.rc == 0, result.stderr

    info = _pgbackrest(host, "info")
    assert info.rc == 0, info.stderr
    assert "status: ok" in info.stdout, info.stdout
    assert "full backup:" in info.stdout, info.stdout


def test_pgbackrest_incremental_backup(host):
    create = _psql(host, "CREATE TABLE pgbackrest_smoke_marker (id int, note text);")
    assert create.rc == 0, create.stderr

    insert = _psql(
        host,
        "INSERT INTO pgbackrest_smoke_marker VALUES (1, 'pgbackrest-incr-restore-marker');",
    )
    assert insert.rc == 0, insert.stderr

    switch = _psql(host, "SELECT pg_switch_wal();")
    assert switch.rc == 0, switch.stderr

    result = _pgbackrest(host, "--type=incr --log-level-console=info backup")
    assert result.rc == 0, result.stderr

    info = _pgbackrest(host, "info")
    assert info.rc == 0, info.stderr
    assert "incr backup:" in info.stdout, info.stdout


def test_pgbackrest_restore_recovers_data(host):
    """
    Stops Postgres, wipes the data directory, restores the backup set
    (full + incremental) using the packaged pgbackrest binary, and confirms
    the marker row written before the incremental backup comes back -
    proving the packaged binary can actually recover data, not just
    produce a backup set. Verified against this exact sequence in a local
    Docker container before this test was written.
    """
    with host.sudo():
        stop_result = host.run("systemctl stop postgresql")
    assert stop_result.rc == 0, stop_result.stderr

    assert _wait_for_postgres_stopped(host, timeout=30), (
        "Postgres process(es) still running against {} 30s after "
        "systemctl stop postgresql".format(PGDATA)
    )

    with host.sudo():
        wipe_result = host.run("rm -rf {}/*".format(PGDATA))
    assert wipe_result.rc == 0, wipe_result.stderr

    restore_result = _pgbackrest(host, "--log-level-console=info restore")
    assert restore_result.rc == 0, restore_result.stderr

    with host.sudo():
        start_result = host.run("systemctl start postgresql")
    assert start_result.rc == 0, start_result.stderr

    assert _wait_for_postgres_ready(host, timeout=60), (
        "Postgres did not accept connections within 60s after restore"
    )

    restored_marker = _psql(
        host, "SELECT note FROM pgbackrest_smoke_marker WHERE id = 1;"
    )
    assert restored_marker.rc == 0, restored_marker.stderr
    assert "pgbackrest-incr-restore-marker" in restored_marker.stdout, (
        "Restored database is missing the marker row - restore did not "
        "actually recover the incremental backup: {}".format(restored_marker.stdout)
    )
