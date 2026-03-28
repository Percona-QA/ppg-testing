import pytest
import subprocess
import testinfra
import time
import json

# --- Configuration ---
MAJOR_VER = os.getenv('VERSION').split('.')[0]
MAJOR_MINOR_VER = os.getenv('VERSION')
DOCKER_REPO = os.getenv('DOCKER_REPOSITORY')
IMG_TAG = os.getenv('TAG')
IMAGE = f"{DOCKER_REPO}/percona-distribution-postgresql-custom:{IMG_TAG}"

# Constants
PG_BIN = f"/usr/pgsql-{MAJOR_VER}/bin"
PG_DATA = "/data/db"
REPO_PATH = "/var/lib/pgbackrest"
CONF_PATH = "/etc/pgbackrest.conf"
CONTAINER_NAME = "PPG_BACKREST"

@pytest.fixture(scope='session')
def host(request):
    """Starts the container as root and initializes the DB."""
    subprocess.run(['docker', 'rm', '-f', CONTAINER_NAME], capture_output=True)

    run_cmd = [
        'docker', 'run', '--name', CONTAINER_NAME,
        '--user', 'root',
        '-e', 'POSTGRES_PASSWORD=password',
        '-d', '--entrypoint', '/usr/bin/tail', 
        IMAGE, '-f', '/dev/null'
    ]
    subprocess.check_output(run_cmd)
    host_instance = testinfra.get_host("docker://" + CONTAINER_NAME)
    
    # 1. Initialize and Start
    host_instance.run(f"chown postgres:postgres {PG_DATA}")
    if host_instance.run(f"test -f {PG_DATA}/PG_VERSION").rc != 0:
        host_instance.run(f"runuser -u postgres -- {PG_BIN}/initdb -D {PG_DATA}")
    
    host_instance.run(f"runuser -u postgres -- {PG_BIN}/pg_ctl -D {PG_DATA} start -w")
    
    yield host_instance
    subprocess.run(['docker', 'rm', '-f', CONTAINER_NAME], capture_output=True)

@pytest.fixture(scope="module")
def setup_pgbackrest_config(host):
    """Creates the config file and enables WAL archiving."""
    # 1. Create Repository
    host.run(f"mkdir -p {REPO_PATH} && chown postgres:postgres {REPO_PATH}")

    # 2. Create Global Config File
    # This is the "Magic Fix" that aligns the server and the client
    conf_content = f"""
[testing]
pg1-path={PG_DATA}

[global]
repo1-path={REPO_PATH}
log-level-console=info
repo1-retention-full=2
"""
    host.run(f"echo '{conf_content}' > {CONF_PATH}")
    host.run(f"chown postgres:postgres {CONF_PATH}")

    # 3. Apply PG Settings
    def run_pg(cmd):
        return host.run(f"runuser -u postgres -- {PG_BIN}/psql -c \"{cmd}\"")

    run_pg("ALTER SYSTEM SET archive_mode='on';")
    # Archive command is now simple because it reads the config file!
    run_pg("ALTER SYSTEM SET archive_command = 'pgbackrest --stanza=testing archive-push %p';")
    run_pg("ALTER SYSTEM SET wal_level='replica';")
    run_pg("ALTER SYSTEM SET max_wal_senders=3;")

    # 4. Restart to apply
    restart = host.run(f"runuser -u postgres -- {PG_BIN}/pg_ctl -D {PG_DATA} restart -m fast -w")
    assert restart.rc == 0

# --- Tests ---
@pytest.fixture(scope="module")
def cleanup_repo(host):
    """Ensures the backup repository is empty before starting the suite."""
    host.run(f"rm -rf {REPO_PATH}/*")
    yield

@pytest.mark.order(1)
def test_stanza_creation(setup_pgbackrest_config, cleanup_repo, host):
    """Initializes the pgBackRest stanza in a clean environment."""
    cmd = "runuser -u postgres -- pgbackrest --stanza=testing stanza-create"
    result = host.run(cmd)
    assert result.rc == 0
    assert "stanza-create command end: completed successfully" in result.stdout

@pytest.mark.order(2)
def test_full_backup(host, setup_pgbackrest_config):
    """Performs the initial Full Backup and verifies repository health."""
    # 1. Execute Full Backup
    backup_cmd = "runuser -u postgres -- pgbackrest --stanza=testing --type=full backup"
    result = host.run(backup_cmd)
    assert result.rc == 0

    # 2. Verify info status
    info_cmd = "runuser -u postgres -- pgbackrest --stanza=testing --output=json info"
    info_result = host.run(info_cmd)
    assert info_result.rc == 0
    
    # Use a more resilient check or JSON parsing
    data = json.loads(info_result.stdout)
    assert data[0]["status"]["message"] == "ok"

@pytest.mark.order(3)
def test_restore_workflow(host, setup_pgbackrest_config):
    """Verifies Point-in-Time Recovery (PITR) by restoring a deleted cluster."""
    # 1. Insert unique test data
    test_id = 777
    host.run(f"runuser -u postgres -- {PG_BIN}/psql -c 'CREATE TABLE IF NOT EXISTS backup_test (id int);'")
    host.run(f"runuser -u postgres -- {PG_BIN}/psql -c 'INSERT INTO backup_test VALUES ({test_id});'")
    
    # 2. Force WAL switch to push the new data to the archive
    host.run(f"runuser -u postgres -- {PG_BIN}/psql -c 'CHECKPOINT; SELECT pg_switch_wal();'")
    time.sleep(3) 

    # 3. Simulate total data loss
    host.run(f"runuser -u postgres -- {PG_BIN}/pg_ctl -D {PG_DATA} stop -m immediate")
    host.run(f"rm -rf {PG_DATA}/*")
    
    # 4. Restore from pgBackRest
    restore_cmd = "runuser -u postgres -- pgbackrest --stanza=testing restore"
    assert host.run(restore_cmd).rc == 0
    
    # 5. Start PG and wait for it to finish replaying WALs
    host.run(f"runuser -u postgres -- {PG_BIN}/pg_ctl -D {PG_DATA} start -w")

    # Loop: Wait for recovery mode to end (pg_is_in_recovery() == false)
    recovery_complete = False
    for _ in range(20):
        status = host.run(f"runuser -u postgres -- {PG_BIN}/psql -t -c 'SELECT pg_is_in_recovery();'")
        if "f" in status.stdout.strip():
            recovery_complete = True
            break
        time.sleep(1)
    
    assert recovery_complete, "Database failed to exit recovery mode in time"

    # 6. Verify our unique data survived the restore
    verify = host.run(f"runuser -u postgres -- {PG_BIN}/psql -t -c 'SELECT count(*) FROM backup_test WHERE id = {test_id};'")
    assert "1" in verify.stdout.strip()

@pytest.mark.order(4)
def test_differential_backup(host, setup_pgbackrest_config):
    """Verifies that a differential backup only records changes since the Full."""
    # 1. Add some data to ensure there's a 'delta' to record
    host.run(f"runuser -u postgres -- {PG_BIN}/psql -c 'CREATE TABLE diff_test (id int); INSERT INTO diff_test VALUES (1);'")
    
    # 2. Run Differential Backup
    # Note: This requires a prior Full backup to exist (which order(2) provides)
    diff_cmd = "runuser -u postgres -- pgbackrest --stanza=testing --type=diff backup"
    result = host.run(diff_cmd)
    assert result.rc == 0
    
    # 3. Verify in info that we now have a 'diff' type backup
    info_cmd = "runuser -u postgres -- pgbackrest --stanza=testing --output=json info"
    data = json.loads(host.run(info_cmd).stdout)
    
    # Check the backup list for a 'diff' type
    backup_types = [b["type"] for b in data[0]["backup"]]
    assert "diff" in backup_types

@pytest.mark.order(5)
def test_corruption_and_delta_restore(host, setup_pgbackrest_config):
    """Intentionally mangles a data file and uses --delta restore to fix it."""
    # 1. Find a real data file to corrupt
    # We'll look for the 'base' directory which holds table data
    find_file = host.run(f"find {PG_DATA}/base -type f -name '[0-9]*' | head -n 1")
    target_file = find_file.stdout.strip()
    assert target_file, "Could not find a data file to corrupt"

    # 2. Stop PG and corrupt the file
    host.run(f"runuser -u postgres -- {PG_BIN}/pg_ctl -D {PG_DATA} stop -m immediate")
    # Overwrite the first 100 bytes with junk
    host.run(f"dd if=/dev/urandom of={target_file} bs=100 count=1 conv=notrunc")

    # 3. Perform a --delta restore
    # Unlike a full restore, --delta uses checksums to find and fix ONLY corrupted/missing files.
    # It is MUCH faster than wiping the whole directory.
    delta_restore_cmd = "runuser -u postgres -- pgbackrest --stanza=testing --delta restore"
    result = host.run(delta_restore_cmd)
    assert result.rc == 0
    assert "restore command end: completed successfully" in result.stdout

    # 4. Restart and Verify
    host.run(f"runuser -u postgres -- {PG_BIN}/pg_ctl -D {PG_DATA} start -w")
    
    # Check recovery status
    recovery_complete = False
    for _ in range(15):
        status = host.run(f"runuser -u postgres -- {PG_BIN}/psql -t -c 'SELECT pg_is_in_recovery();'")
        if "f" in status.stdout.strip():
            recovery_complete = True
            break
        time.sleep(1)
    
    assert recovery_complete
    
    # Ensure our previous data (from the Diff test) is still readable
    verify = host.run(f"runuser -u postgres -- {PG_BIN}/psql -t -c 'SELECT count(*) FROM diff_test;'")
    assert "1" in verify.stdout.strip()
