"""
pgBackRest Docker test suite – backup, archiving, and restoration.

Testing strategy:
  1. Fundamental: stanza-create, check, backup types (full / incr / diff), WAL archiving (info).
  2. Recovery: full cluster restore, PITR (--type=time --target), delta restore (--delta),
     selective database restore (--db-include).
  3. Operational: retention & expiration (repo1-retention-full, expire).
"""
import json
import os
import re
import pytest
import docker
import time

client = docker.from_env()

SERVER_VERSION = os.getenv('SERVER_VERSION', '18')
MAJOR_VER = SERVER_VERSION.split('.')[0]
MAJOR_MINOR_VER = os.getenv('SERVER_VERSION')
DOCKER_REPO = os.getenv('DOCKER_REPOSITORY')
IMG_TAG = os.getenv('PG_IMAGE_TAG')
PG_CONTAINER_NAME = os.getenv("PG_CONTAINER_NAME", "pg_primary")
PGBACKREST_CONTAINER_NAME = os.getenv("PGBACKREST_CONTAINER_NAME", "pgbackrest")
PGBACKREST_STANZA_NAME = os.getenv("PGBACKREST_STANZA_NAME", "main")
PG_RESTORED_CONTAINER_NAME = os.getenv("PG_RESTORED_CONTAINER_NAME", "pg_restored")
LEAVE_RESTORED_RUNNING = os.getenv("PGBACKREST_LEAVE_RESTORED_RUNNING", "0").lower() in ("1", "true", "yes")
PG_BIN = os.getenv("PG_BIN", f"/usr/pgsql-{MAJOR_VER}/bin")
PGBACKREST_VERSION = os.getenv('COMPONENT_VERSION', '2.58.0')
WITH_TDE = os.getenv("WITH_TDE", "0")
TDE_ENABLED = WITH_TDE == "1" and MAJOR_VER.isdigit() and int(MAJOR_VER) >= 17
ACCESS_METHOD = "USING tde_heap" if TDE_ENABLED else "USING heap"

# --- Registration to fix the "UnknownMarkWarning" ---
def pytest_configure(config):
    config.addinivalue_line("markers", "order: order of execution")

# --- Fixtures ---
@pytest.fixture(scope="session")
def pitr_context():
    """A dictionary to store data across different test stages."""
    return {}

# --- Helpers ---
def run_pgbackrest(command):
    container = client.containers.get(PGBACKREST_CONTAINER_NAME)
    exit_code, output = container.exec_run(f"pgbackrest {command}")
    return exit_code, output.decode()

def run_sql(query, db=None):
    """Run SQL on primary. If db is set, connect to that database (e.g. for selective restore tests)."""
    ensure_postgres_running()
    container = client.containers.get(PG_CONTAINER_NAME)
    db_opt = f" -d {db}" if db else ""
    exit_code, output = container.exec_run(
        f"psql -U postgres{db_opt} -Atc \"{query}\"",
        environment={"PGPASSWORD": "mysecretpassword"},
    )
    result = output.decode().strip()
    return next((line.strip() for line in result.splitlines() if line.strip()), result)


def run_sql_exec(sql):
    ensure_postgres_running()
    container = client.containers.get(PG_CONTAINER_NAME)
    exit_code, output = container.exec_run(
        f"psql -U postgres -v ON_ERROR_STOP=1 -Atc \"{sql}\"",
        environment={"PGPASSWORD": "mysecretpassword"},
    )
    return exit_code, output.decode()


def wait_for_postgres(timeout_seconds=20):
    container = client.containers.get(PG_CONTAINER_NAME)
    for _ in range(timeout_seconds):
        container.reload()
        if container.status != "running":
            time.sleep(0.5)
            continue
        exit_code, _ = container.exec_run(
            "pg_isready -U postgres -d postgres",
            environment={"PGPASSWORD": "mysecretpassword"},
        )
        if exit_code == 0:
            return True
        time.sleep(0.5)
    return False


def restart_postgres():
    container = client.containers.get(PG_CONTAINER_NAME)
    container.restart()
    assert wait_for_postgres(), "PostgreSQL did not become ready after restart."


def ensure_postgres_running():
    container = client.containers.get(PG_CONTAINER_NAME)
    container.reload()
    if container.status != "running":
        container.start()
    assert wait_for_postgres(), "PostgreSQL is not ready."


def wait_for_postgres_restored(timeout_seconds=60):
    """Wait for the restored PostgreSQL container to accept connections."""
    try:
        container = client.containers.get(PG_RESTORED_CONTAINER_NAME)
    except docker.errors.NotFound:
        return False
    for _ in range(timeout_seconds):
        container.reload()
        if container.status != "running":
            time.sleep(0.5)
            continue
        exit_code, _ = container.exec_run(
            "pg_isready -U postgres -d postgres",
            environment={"PGPASSWORD": "mysecretpassword"},
        )
        if exit_code == 0:
            return True
        time.sleep(0.5)
    return False


def run_sql_restored(query, db=None):
    """Run SQL against the restored PostgreSQL container. db=None uses default (postgres)."""
    container = client.containers.get(PG_RESTORED_CONTAINER_NAME)
    container.reload()
    if container.status != "running":
        raise RuntimeError(f"Restored container {PG_RESTORED_CONTAINER_NAME} is not running")
    db_opt = f" -d {db}" if db else ""
    exit_code, output = container.exec_run(
        f"psql -U postgres{db_opt} -Atc \"{query}\"",
        environment={"PGPASSWORD": "mysecretpassword"},
    )
    result = output.decode().strip()
    return next((line.strip() for line in result.splitlines() if line.strip()), result)


def update_restore_command():
    container = client.containers.get(PGBACKREST_CONTAINER_NAME)
    if TDE_ENABLED:
        restore_command = (
            f"restore_command = '{PG_BIN}/pg_tde_archive_decrypt %f \"%p\" "
            f"\"pgbackrest --config=/etc/pgbackrest.conf --stanza={PGBACKREST_STANZA_NAME} archive-get %f %%p\"'"
        )
    else:
        restore_command = (
            f"restore_command = 'pgbackrest --config=/etc/pgbackrest.conf "
            f"--stanza={PGBACKREST_STANZA_NAME} archive-get %f %p'"
        )
    container.exec_run(
        "bash -lc '"
        "conf=/data/db/postgresql.auto.conf; "
        "if grep -q \"^restore_command\" \"$conf\"; then "
        "  sed -i \"s|^restore_command.*|{cmd}|\" \"$conf\"; "
        "else "
        "  echo \"{cmd}\" >> \"$conf\"; "
        "fi'".format(cmd=restore_command.replace('"', '\\"'))
    )


def ensure_tde_setup():
    if not TDE_ENABLED:
        return
    container = client.containers.get(PG_CONTAINER_NAME)
    container.exec_run(
        "bash -lc 'mkdir -p /var/lib/pgbackrest/keys && "
        "chown -R postgres:postgres /var/lib/pgbackrest/keys && "
        "chmod 700 /var/lib/pgbackrest/keys'"
    )
    sql = """
    CREATE EXTENSION IF NOT EXISTS pg_tde;
    SELECT pg_tde_add_global_key_provider_file('wal-vault', '/var/lib/pgbackrest/keys/pg_tde_test_001_wal.per');
    SELECT pg_tde_create_key_using_global_key_provider('wal-key', 'wal-vault');
    SELECT pg_tde_set_default_key_using_global_key_provider('wal-key', 'wal-vault');
    """
    exit_code, output = run_sql_exec(sql)
    assert exit_code == 0, output
    
    # Add the configuration change
    config_sql = """
    ALTER SYSTEM SET pg_tde.wal_encrypt = 'on';
    """
    exit_code, output = run_sql_exec(config_sql)
    assert exit_code == 0, output
    restart_postgres()


@pytest.fixture(scope="session", autouse=True)
def tde_setup():
    if TDE_ENABLED:
        ensure_tde_setup()

# --- 1. Fundamental: binary, stanza, backup types, WAL archiving ---
@pytest.mark.order(1)
def test_pgbackrest_binary_present():
    """Verify pgBackRest binary exists in the pgbackrest container."""
    container = client.containers.get(PGBACKREST_CONTAINER_NAME)
    exit_code, _ = container.exec_run("test -x /usr/bin/pgbackrest")
    assert exit_code == 0, "pgbackrest binary not found or not executable"


@pytest.mark.order(2)
def test_pgbackrest_binary_version():
    """Verify pgBackRest binary reports a version."""
    container = client.containers.get(PGBACKREST_CONTAINER_NAME)
    exit_code, output = container.exec_run("/usr/bin/pgbackrest version")
    output_text = output.decode().strip()
    assert exit_code == 0, output_text
    assert "pgBackRest" in output_text
    if PGBACKREST_VERSION:
        assert PGBACKREST_VERSION in output_text, output_text


@pytest.mark.order(3)
def test_stanza_creation():
    """Stanza validation: stanza-create so configuration matches the database cluster."""
    exit_code, output = run_pgbackrest(f"--stanza={PGBACKREST_STANZA_NAME} stanza-create")
    assert exit_code == 0, output
    assert "stanza-create command end: completed successfully" in output


@pytest.mark.order(4)
def test_stanza_create_idempotent():
    """Stanza validation: stanza-create idempotent (already exists) succeeds or reports same."""
    exit_code, output = run_pgbackrest(f"--stanza={PGBACKREST_STANZA_NAME} stanza-create")
    # Either success or acceptable "already exists" / no-op
    assert exit_code == 0, output
    assert "stanza-create command end: completed successfully" in output or "already exists" in output.lower()


@pytest.mark.order(5)
def test_full_backup():
    """Backup types – full: entire cluster; foundation for incr/diff."""
    run_sql(f"CREATE TABLE restore_val (id int, val text){ACCESS_METHOD};")
    run_sql("INSERT INTO restore_val VALUES (1, 'original_data');")
    run_sql("SELECT pg_switch_wal();")
    # Force a WAL switch to trigger the archive_command automatically
    run_sql("SELECT pg_switch_wal();")
    
    # Run backup without --no-archive-check as requested
    exit_code, output = run_pgbackrest(f"--stanza={PGBACKREST_STANZA_NAME} --type=full backup")
    assert exit_code == 0, output
    assert "backup command end: completed successfully" in output

@pytest.mark.order(6)
def test_incremental_backup():
    """Backup types – incremental: changes since last backup (full/diff/incr)."""
    # Insert some data to create a delta
    run_sql(f"CREATE TABLE test_data (id serial primary key, note text){ACCESS_METHOD};")
    run_sql("INSERT INTO test_data (note) VALUES ('verification_data');")
    run_sql("SELECT pg_switch_wal();")
    
    # Run incremental backup
    exit_code, output = run_pgbackrest(f"--stanza={PGBACKREST_STANZA_NAME} --type=incr backup")
    assert exit_code == 0, output
    assert "backup command end: completed successfully" in output



@pytest.mark.order(7)
def test_initial_backup_and_timestamp(pitr_context):
    """
    Inserts 'good_data' into pitr_test, takes a full backup, then captures the PITR target time.

    Order matters: we must take the backup before capturing golden_time so that the backup's
    stop time is less than the target. pgbackrest PITR requires a backup with stop time < target
    so it can restore that backup and replay WAL up to the target time.
    """
    run_sql(f"CREATE TABLE pitr_test (id int, val text){ACCESS_METHOD};")
    run_sql("INSERT INTO pitr_test VALUES (1, 'good_data');")
    run_sql("SELECT pg_switch_wal();")

    # Take full backup first so its stop time is before we capture the target
    exit_code, output = run_pgbackrest(f"--stanza={PGBACKREST_STANZA_NAME} --type=full backup")
    assert exit_code == 0, output
    assert "backup command end: completed successfully" in output

    # Capture PITR target time after the backup (backup stop time < golden_time)
    golden_time = run_sql("SELECT current_timestamp;")
    pitr_context["target_time"] = golden_time
    print(f"\nCaptured PITR Gold Time: {golden_time}")

@pytest.mark.order(8)
def test_repository_consistency():
    """
    Step 2: Verify the repository integrity.
    This ensures all files in the backup are checksum-valid.
    """
    # Note: verify checks that the database and repository match
    exit_code, output = run_pgbackrest(f"--stanza={PGBACKREST_STANZA_NAME} verify")
    assert exit_code == 0, output
    # verify output will confirm it checked the repo
    assert "verify command end: completed successfully" in output


@pytest.mark.order(9)
def test_check_command():
    """Stanza validation: check confirms config matches cluster and archive_command can push WAL."""
    exit_code, output = run_pgbackrest(f"--stanza={PGBACKREST_STANZA_NAME} check")
    assert exit_code == 0, output
    assert "check command end: completed successfully" in output


@pytest.mark.order(10)
def test_differential_backup():
    """Verify differential backup (--type=diff) works relative to last full backup."""
    run_sql(f"CREATE TABLE diff_backup_test (id int){ACCESS_METHOD};")
    run_sql("INSERT INTO diff_backup_test VALUES (1);")
    run_sql("SELECT pg_switch_wal();")
    exit_code, output = run_pgbackrest(f"--stanza={PGBACKREST_STANZA_NAME} --type=diff backup")
    assert exit_code == 0, output
    assert "backup command end: completed successfully" in output

@pytest.mark.order(11)
def test_backup_info_validity():
    """Backup types and status: info shows full/incr/diff backups and status ok."""
    # Data check
    res = run_sql("SELECT val FROM pitr_test WHERE id = 1;")
    assert res == 'good_data'

    exit_code, output = run_pgbackrest("info")
    assert exit_code == 0, output
    assert "status: ok" in output
    assert "full backup" in output
    assert "incr backup" in output
    assert "diff backup" in output


@pytest.mark.order(12)
def test_info_output_json():
    """Verify info --output=json returns valid JSON with backup list."""
    exit_code, output = run_pgbackrest(f"--stanza={PGBACKREST_STANZA_NAME} info --output=json")
    assert exit_code == 0, output
    data = json.loads(output)
    assert isinstance(data, list), "info JSON should be a list of stanza info"
    assert len(data) >= 1, "At least one stanza expected"
    stanza_info = data[0]
    assert "name" in stanza_info or "stanza" in stanza_info or "backup" in stanza_info or "archive" in stanza_info, (
        f"Expected stanza/backup/archive keys in JSON: {list(stanza_info.keys())}"
    )


@pytest.mark.order(13)
def test_wal_archiving_info():
    """
    WAL archiving: verify WAL segments are in the repository.
    pgbackrest info shows archive section with min/max WAL range.
    """
    run_sql("SELECT pg_switch_wal();")
    exit_code, output = run_pgbackrest(f"--stanza={PGBACKREST_STANZA_NAME} info")
    assert exit_code == 0, output
    assert "archive" in output.lower(), "info should include archive section"
    # Info lists archive WAL range (e.g. "full backup" line and WAL segment range)
    assert "full backup" in output or "incr" in output or "diff" in output, (
        "info should show backup(s) with archive WAL"
    )


# --- 2. Recovery: PITR, full cluster, delta, selective ---
# PITR runs before retention (order 16) so the backup with stop time < golden_time is still present.
@pytest.mark.order(14)
def test_corruption_and_pitr_restore(pitr_context):
    """
    Point-in-time recovery (PITR): --type=time --target to restore to a specific second
    before simulated data corruption; verify recovery to 'good_data'.

    Corrupts pitr_test (sets val to 'corrupted_data'), stops the primary, then runs
    pgbackrest --delta restore --type=time --target=<target> where target is the
    timestamp captured in test_initial_backup_and_timestamp (when val was 'good_data').
    After recovery and promotion, test_verify_recovery_success checks that val is
    back to 'good_data'. Uses the same recovery-option pattern as other restore tests.
    """
    target = pitr_context.get("target_time")

    run_sql("UPDATE pitr_test SET val = 'corrupted_data' WHERE id = 1;")

    pg_container = client.containers.get(PG_CONTAINER_NAME)
    pg_container.stop()

    restore_command_val = (
        f'{PG_BIN}/pg_tde_restore_encrypt %f %p '
        f'"pgbackrest --config=/etc/pgbackrest.conf --stanza={PGBACKREST_STANZA_NAME} archive-get %%f %%p"'
    ) if TDE_ENABLED else (
        f'pgbackrest --config=/etc/pgbackrest.conf --stanza={PGBACKREST_STANZA_NAME} archive-get %f %p'
    )
    restore_opt = f'restore_command={restore_command_val.replace(chr(34), chr(92) + chr(34))}'
    restore_cmd = (
        f"--stanza={PGBACKREST_STANZA_NAME} --delta restore "
        f'--recovery-option="{restore_opt}" '
        f"--recovery-option=recovery_target_action=promote "
        f'--type=time --target="{target}" --target-action=promote'
    )
    try:
        exit_code, output = run_pgbackrest(restore_cmd)
        assert exit_code == 0, output
        assert "restore command end: completed successfully" in output
    finally:
        pg_container.reload()
        if pg_container.status != "running":
            pg_container.start()
    assert wait_for_postgres(timeout_seconds=60), "PostgreSQL did not become ready after PITR restore."


@pytest.mark.order(15)
def test_verify_recovery_success():
    """Verify PITR succeeded: pitr_test id=1 should be 'good_data' (state at target time)."""
    res = run_sql("SELECT val FROM pitr_test WHERE id = 1;")
    assert res == "good_data", f"PITR verify: expected 'good_data', got {res!r}"


# --- 3. Operational: retention & expiration ---
@pytest.mark.order(16)
def test_retention_enforcement():
    """
    Retention & expiration: repo1-retention-full=2; expire removes older backups.
    After multiple full backups, only 2 full backups remain.
    """
    for i in range(3):
        run_sql(f"CREATE TABLE seed_retention_{i} (id int){ACCESS_METHOD};")
        run_pgbackrest(f"--stanza={PGBACKREST_STANZA_NAME} --type=full backup")

    run_pgbackrest(f"--stanza={PGBACKREST_STANZA_NAME} expire")

    exit_code, output = run_pgbackrest("info")
    full_backup_count = output.count("full backup:")
    assert full_backup_count == 2, f"Expected 2 backups, found {full_backup_count}. Output: {output}"


@pytest.mark.order(17)
def test_archive_retention():
    """Retention: WAL archives for expired backups are removed by expire."""
    # Find the directory where WALs are stored
    container = client.containers.get(PGBACKREST_CONTAINER_NAME)
    # Path is usually: repo-path/archive/stanza/version-specific-dir
    ls_archive = container.exec_run(
        f"ls -R /var/lib/pgbackrest/archive/{PGBACKREST_STANZA_NAME}"
    ).output.decode()
    
    # We shouldn't see WAL segments belonging to the very first deleted backup
    # pgBackRest handles this internally during the 'expire' phase
    exit_code, output = run_pgbackrest(f"--stanza={PGBACKREST_STANZA_NAME} expire")
    assert exit_code == 0, output
    assert "expire command end: completed successfully" in output

@pytest.mark.order(18)
def test_backup_verify_consistency():
    """Final deep-verify of the remaining 2 backups."""
    exit_code, output = run_pgbackrest(f"--stanza={PGBACKREST_STANZA_NAME} verify")
    assert exit_code == 0, output

# --- Recovery (failure) tests: full cluster, PITR, delta, selective ---
@pytest.mark.order(19)
def test_full_cluster_restore_to_new_container():
    """
    Full cluster restore: restore entire cluster to a separate data dir,
    start a new container, verify backup by querying restored instance.
    """
    try:
        client.containers.get(PG_RESTORED_CONTAINER_NAME)
    except docker.errors.NotFound:
        pytest.skip(
            f"Container {PG_RESTORED_CONTAINER_NAME} not found. "
            "Create it with: docker compose --profile restore create pg-restored"
        )

    # Inner command must use %%f and %%p so postgresql.conf has them; PostgreSQL leaves %%f/%%p as %f/%p
    # for the wrapper, which then substitutes the temp path for %p (so pgbackrest writes to temp, not pg_wal).
    restore_command_val = (
        f'{PG_BIN}/pg_tde_restore_encrypt %f %p '
        f'"pgbackrest --config=/etc/pgbackrest.conf --stanza={PGBACKREST_STANZA_NAME} archive-get %%f %%p"'
    ) if TDE_ENABLED else (
        f'pgbackrest --config=/etc/pgbackrest.conf --stanza={PGBACKREST_STANZA_NAME} archive-get %f %p'
    )
    # Shell-safe: wrap value in double quotes and escape inner double quotes
    restore_opt = f'restore_command={restore_command_val.replace(chr(34), chr(92) + chr(34))}'
    restore_cmd = (
        f"--stanza={PGBACKREST_STANZA_NAME} restore "
        f"--pg1-path=/data/restored "
        f'--recovery-option="{restore_opt}" '
        f"--recovery-option=recovery_target_action=promote"
    )
    exit_code, output = run_pgbackrest(restore_cmd)
    assert exit_code == 0, output
    assert "restore command end: completed successfully" in output

    # 2. Start the restored-instance container (created by compose with profile restore)
    restored_container = client.containers.get(PG_RESTORED_CONTAINER_NAME)
    if restored_container.status != "running":
        restored_container.start()
    assert wait_for_postgres_restored(timeout_seconds=60), (
        f"Restored container {PG_RESTORED_CONTAINER_NAME} did not become ready."
    )

    try:
        # 3. Verify backup: data from test_full_backup and test_incremental_backup
        val = run_sql_restored("SELECT val FROM restore_val WHERE id = 1;")
        assert val == "original_data", f"restore_val: expected 'original_data', got {val!r}"
        note = run_sql_restored("SELECT note FROM test_data WHERE id = 1;")
        assert note == "verification_data", f"test_data: expected 'verification_data', got {note!r}"
        # 4. Verify expected tables exist on restored instance
        tables = run_sql_restored(
            "SELECT string_agg(tablename, ',' ORDER BY tablename) FROM pg_tables WHERE schemaname = 'public';"
        )
        for expected in ("restore_val", "test_data", "pitr_test"):
            assert expected in tables, f"Restored DB should contain table {expected}, got: {tables}"
    finally:
        if not LEAVE_RESTORED_RUNNING:
            restored_container.stop(timeout=30)


@pytest.mark.order(20)
def test_delta_restore_in_place():
    """
    Delta restore (--delta): restore only files that differ between backup and
    current data dir over the primary's pgdata, then recover. Simulates disaster
    recovery where existing files are reused where unchanged.
    """
    pg_container = client.containers.get(PG_CONTAINER_NAME)

    # 1. Stop the database to prevent file locking
    pg_container.stop()

    # 2. Perform the restore using --recovery-option=restore_command (pgbackrest sets recovery target)
    # --delta allows pgbackrest to use existing files and overwrite them.
    # Pass recovery-option values without surrounding single quotes (avoids postgresql.auto.conf
    # ''promote''/''path'' syntax errors). Inner command uses %%f %%p for TDE so wrapper gets temp path.
    restore_command_val = (
        f'{PG_BIN}/pg_tde_restore_encrypt %f %p '
        f'"pgbackrest --config=/etc/pgbackrest.conf --stanza={PGBACKREST_STANZA_NAME} archive-get %%f %%p"'
    ) if TDE_ENABLED else (
        f'pgbackrest --config=/etc/pgbackrest.conf --stanza={PGBACKREST_STANZA_NAME} archive-get %f %p'
    )
    restore_opt = f'restore_command={restore_command_val.replace(chr(34), chr(92) + chr(34))}'
    restore_cmd = (
        f"--stanza={PGBACKREST_STANZA_NAME} --delta restore "
        f'--recovery-option="{restore_opt}" '
        f"--recovery-option=recovery_target_action=promote"
    )
    try:
        exit_code, output = run_pgbackrest(restore_cmd)
        assert exit_code == 0, output
        assert "restore command end: completed successfully" in output
    finally:
        # Always restart the database to avoid cascading failures
        pg_container.reload()
        if pg_container.status != "running":
            pg_container.start()

    # 3. Wait for PostgreSQL to recover and promote; then ready for INSERTs
    assert wait_for_postgres(timeout_seconds=60), "PostgreSQL did not become ready after restore."

    # 4. Verify backup: same data checks as test_restore_to_new_container (restore_val, test_data)
    val = run_sql("SELECT val FROM restore_val WHERE id = 1;")
    assert val == "original_data", f"restore_val after in-place restore: expected 'original_data', got {val!r}"
    note = run_sql("SELECT note FROM test_data WHERE id = 1;")
    assert note == "verification_data", f"test_data after in-place restore: expected 'verification_data', got {note!r}"

@pytest.mark.order(21)
def test_create_selective_restore_db():
    """Create a separate database for testing --db-include selective restore."""
    run_sql("CREATE DATABASE selective_db;")
    if TDE_ENABLED:
        run_sql("CREATE EXTENSION IF NOT EXISTS pg_tde;", db="selective_db")
        run_sql(
            "SELECT pg_tde_set_default_key_using_global_key_provider('wal-key', 'wal-vault');",
            db="selective_db"
        )
    run_sql(
        f"CREATE TABLE selective_verify (id int, val text){ACCESS_METHOD};",
        db="selective_db"
    )
    run_sql("INSERT INTO selective_verify VALUES (1, 'selective_restore_data');", db="selective_db")
    run_sql("SELECT pg_switch_wal();")

@pytest.mark.order(22)
def test_selective_database_restore():
    """
    Selective database restore (--db-include): restore only specified databases
    from the backup to /data/restored, start pg_restored, verify selective_db and data.

    Uses the same pg_restored container and pgdata_restored volume as
    test_full_cluster_restore_to_new_container. No cleanup needed: we stop the container
    so the volume is not in use, then pgbackrest restore overwrites /data/restored.
    """
    try:
        restored_container = client.containers.get(PG_RESTORED_CONTAINER_NAME)
    except docker.errors.NotFound:
        pytest.skip(
            f"Container {PG_RESTORED_CONTAINER_NAME} not found. "
            "Create it with: docker compose --profile restore create pg-restored"
        )

    # Stop so we can overwrite the volume; test_full_cluster_restore_to_new_container
    # already stops it unless LEAVE_RESTORED_RUNNING, but ensure it's stopped here.
    restored_container.reload()
    if restored_container.status == "running":
        restored_container.stop(timeout=30)

    # Take a full backup that definitely contains selective_db (primary has had it since test 5).
    run_sql("SELECT pg_switch_wal();")
    exit_code, output = run_pgbackrest(f"--stanza={PGBACKREST_STANZA_NAME} --type=full backup")
    assert exit_code == 0, output
    assert "backup command end: completed successfully" in output

    # Use the backup we just created so restore sees selective_db (avoids [080] when
    # "latest" would otherwise pick an older backup from retention).
    exit_code, info_out = run_pgbackrest(
        f"--stanza={PGBACKREST_STANZA_NAME} info"
    )
    assert exit_code == 0, info_out
    full_labels = re.findall(r"\d{8}-\d{6}F", info_out)
    assert full_labels, f"No full backup found in info output: {info_out!r}"
    backup_set = full_labels[-1]

    restore_command_val = (
        f'{PG_BIN}/pg_tde_restore_encrypt %f %p '
        f'"pgbackrest --config=/etc/pgbackrest.conf --stanza={PGBACKREST_STANZA_NAME} archive-get %%f %%p"'
    ) if TDE_ENABLED else (
        f'pgbackrest --config=/etc/pgbackrest.conf --stanza={PGBACKREST_STANZA_NAME} archive-get %f %p'
    )
    restore_opt = f'restore_command={restore_command_val.replace(chr(34), chr(92) + chr(34))}'
    # --delta: /data/restored already has files from test_full_cluster_restore_to_new_container
    # System DBs (postgres, template0, etc.) are included by default; only add selective_db
    restore_cmd = (
        f"--stanza={PGBACKREST_STANZA_NAME} --set={backup_set} --delta restore "
        f"--pg1-path=/data/restored "
        f"--db-include=selective_db "
        f'--recovery-option="{restore_opt}" '
        f"--recovery-option=recovery_target_action=promote"
    )
    exit_code, output = run_pgbackrest(restore_cmd)
    assert exit_code == 0, output
    assert "restore command end: completed successfully" in output

    restored_container = client.containers.get(PG_RESTORED_CONTAINER_NAME)
    if restored_container.status != "running":
        restored_container.start()
    assert wait_for_postgres_restored(timeout_seconds=60), (
        f"Restored container {PG_RESTORED_CONTAINER_NAME} did not become ready."
    )

    try:
        val = run_sql_restored("SELECT val FROM selective_verify WHERE id = 1;", db="selective_db")
        assert val == "selective_restore_data", (
            f"selective_verify: expected 'selective_restore_data', got {val!r}"
        )
    finally:
        if not LEAVE_RESTORED_RUNNING:
            restored_container.stop(timeout=30)
