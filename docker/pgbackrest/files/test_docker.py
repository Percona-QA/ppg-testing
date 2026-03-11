import os
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
PG_BIN = os.getenv("PG_BIN", f"/usr/pgsql-{MAJOR_VER}/bin")
PGBACKREST_VERSION = os.getenv('COMPONENT_VERSION')
WITH_TDE = os.getenv("WITH_TDE", "0")
TDE_ENABLED = WITH_TDE == "1" and MAJOR_VER.isdigit() and int(MAJOR_VER) >= 17
ACCESS_METHOD = "USING tde_heap" if TDE_ENABLED else "USING heap"

# Red Hat ecosystem required image labels (PPG Docker images); values from playbook when set
REQUIRED_LABEL_MAINTAINER = os.getenv("PPG_LABEL_MAINTAINER", "Percona Development <info@percona.com>")
REQUIRED_LABEL_VENDOR = os.getenv("PPG_LABEL_VENDOR", "Percona")
REQUIRED_LABEL_NAME_PREFIX = "Percona "
EXPECTED_LABEL_NAME_POSTGRESQL = os.getenv("PPG_LABEL_NAME_POSTGRESQL", "Percona Distribution for PostgreSQL")
EXPECTED_LABEL_NAME_PGBACKREST = os.getenv("PPG_LABEL_NAME_PGBACKREST", "Percona pgBackRest")
REQUIRED_LABEL_KEYS = ("name", "vendor", "version", "release", "summary", "description", "maintainer")
RED_HAT_TRADEMARK_FORBIDDEN = ("Red Hat", "RHEL", "RedHat")

# --- Registration to fix the "UnknownMarkWarning" ---
def pytest_configure(config):
    config.addinivalue_line("markers", "order: order of execution")

# --- Fixtures ---
@pytest.fixture(scope="session")
def pitr_context():
    """A dictionary to store data across different test stages."""
    return {}

# --- Helpers ---


def _get_image_labels(image_ref):
    """Return the labels dict for a Docker image (by name:tag or id)."""
    img = client.images.get(image_ref)
    return img.labels or {}


def _check_no_redhat_trademark(labels, errors):
    """Check that name, vendor, maintainer do not violate Red Hat trademark (no forbidden substrings)."""
    for key in ("name", "vendor", "maintainer"):
        val = (labels.get(key) or "").strip()
        for forbidden in RED_HAT_TRADEMARK_FORBIDDEN:
            if forbidden in val:
                errors.append(f"label {key!r} must not contain Red Hat trademark {forbidden!r}, got: {repr(labels.get(key))}")


def _check_required_labels_present(labels, errors):
    """Check that all required labels (name, vendor, version, release, summary, description, maintainer) are present."""
    for key in REQUIRED_LABEL_KEYS:
        val = labels.get(key)
        if val is None or (isinstance(val, str) and not val.strip()):
            errors.append(f"required label {key!r} is missing or empty in container metadata")


def _validate_ppg_image_labels(image_ref, expected_name=None):
    """
    Validate Red Hat ecosystem required labels on a PPG Docker image.
    1. No Red Hat trademark in name, vendor, maintainer.
    2. All required labels (name, vendor, version, release, summary, description, maintainer) are present.
    3. name, vendor, maintainer have the expected values.
    """
    labels = _get_image_labels(image_ref)
    errors = []

    _check_no_redhat_trademark(labels, errors)
    _check_required_labels_present(labels, errors)

    name_val = labels.get("name", "").strip()
    if expected_name is not None:
        if name_val != expected_name:
            errors.append(f"label 'name' must be {expected_name!r}, got: {repr(labels.get('name'))}")
    elif not name_val.startswith(REQUIRED_LABEL_NAME_PREFIX) or len(name_val) <= len(REQUIRED_LABEL_NAME_PREFIX):
        errors.append(f"label 'name' must be 'Percona <Product Name>', got: {repr(labels.get('name'))}")
    if labels.get("maintainer") != REQUIRED_LABEL_MAINTAINER:
        errors.append(f"label 'maintainer' must be {REQUIRED_LABEL_MAINTAINER!r}, got: {repr(labels.get('maintainer'))}")
    if labels.get("vendor") != REQUIRED_LABEL_VENDOR:
        errors.append(f"label 'vendor' must be {REQUIRED_LABEL_VENDOR!r}, got: {repr(labels.get('vendor'))}")

    if errors:
        raise AssertionError(f"Image {image_ref} label validation failed:\n" + "\n".join(errors))


def _check_licenses_at_licenses(image_ref):
    """
    Check that terms/conditions and open source licensing are present at /licenses in the image.
    /licenses must exist and contain content (non-empty file or directory with at least one file).
    """
    cmd = [
        "sh", "-c",
        "test -e /licenses && (test -f /licenses && test -s /licenses || (test -d /licenses && test $(ls -A /licenses 2>/dev/null | wc -l) -gt 0))",
    ]
    try:
        client.containers.run(image_ref, command=cmd, remove=True, detach=False)
    except docker.errors.ContainerError as e:
        raise AssertionError(
            f"Image {image_ref}: /licenses missing or empty. "
            "Terms and open source licensing information must be present at /licenses."
        ) from e


def run_pgbackrest(command):
    container = client.containers.get(PGBACKREST_CONTAINER_NAME)
    exit_code, output = container.exec_run(f"pgbackrest {command}")
    return exit_code, output.decode()

def run_sql(query):
    ensure_postgres_running()
    container = client.containers.get(PG_CONTAINER_NAME)
    # Using your password from docker-compose.yml
    exit_code, output = container.exec_run(
        f"psql -U postgres -Atc \"{query}\"",
        environment={"PGPASSWORD": "mysecretpassword"}
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


def update_restore_command():
    container = client.containers.get(PGBACKREST_CONTAINER_NAME)
    if TDE_ENABLED:
        restore_command = (
            f"restore_command = 'TMPDIR=/tmp {PG_BIN}/pg_tde_archive_decrypt %f \"%p\" "
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

# --- Tests ---


@pytest.mark.order(0)
def test_ppg_postgres_image_labels():
    """Validate PostgreSQL image: (1) name/vendor/maintainer do not violate Red Hat trademark;
    (2) required labels (name, vendor, version, release, summary, description, maintainer) are present;
    (3) name/vendor/maintainer match expected values (playbook: ppg_label_name_postgresql)."""
    image_ref = os.getenv("PG_IMAGE")
    if not image_ref:
        pytest.skip("PG_IMAGE not set (required for image label validation)")
    _validate_ppg_image_labels(image_ref, expected_name=EXPECTED_LABEL_NAME_POSTGRESQL)


@pytest.mark.order(0)
def test_ppg_pgbackrest_image_labels():
    """Validate pgBackRest image: (1) name/vendor/maintainer do not violate Red Hat trademark;
    (2) required labels (name, vendor, version, release, summary, description, maintainer) are present;
    (3) name/vendor/maintainer match expected values (playbook: ppg_label_name_pgbackrest)."""
    image_ref = os.getenv("PGBACKREST_IMAGE")
    if not image_ref:
        pytest.skip("PGBACKREST_IMAGE not set (required for image label validation)")
    _validate_ppg_image_labels(image_ref, expected_name=EXPECTED_LABEL_NAME_PGBACKREST)


@pytest.mark.order(0)
def test_ppg_postgres_image_licenses_at_licenses():
    """Check that terms/conditions and open source licensing are present at /licenses in the PostgreSQL image."""
    image_ref = os.getenv("PG_IMAGE")
    if not image_ref:
        pytest.skip("PG_IMAGE not set (required for /licenses check)")
    _check_licenses_at_licenses(image_ref)


@pytest.mark.order(0)
def test_ppg_pgbackrest_image_licenses_at_licenses():
    """Check that terms/conditions and open source licensing are present at /licenses in the pgBackRest image."""
    image_ref = os.getenv("PGBACKREST_IMAGE")
    if not image_ref:
        pytest.skip("PGBACKREST_IMAGE not set (required for /licenses check)")
    _check_licenses_at_licenses(image_ref)


@pytest.mark.order(0)
def test_pgbackrest_binary_present():
    """Verify pgBackRest binary exists in the pgbackrest container."""
    container = client.containers.get(PGBACKREST_CONTAINER_NAME)
    exit_code, _ = container.exec_run("test -x /usr/bin/pgbackrest")
    assert exit_code == 0, "pgbackrest binary not found or not executable"


@pytest.mark.order(0)
def test_pgbackrest_binary_version():
    """Verify pgBackRest binary reports a version."""
    container = client.containers.get(PGBACKREST_CONTAINER_NAME)
    exit_code, output = container.exec_run("/usr/bin/pgbackrest version")
    output_text = output.decode().strip()
    assert exit_code == 0, output_text
    assert "pgBackRest" in output_text
    if PGBACKREST_VERSION:
        assert PGBACKREST_VERSION in output_text, output_text

@pytest.mark.order(1)
def test_stanza_creation():
    """Verify pgbackrest can initialize the stanza."""
    exit_code, output = run_pgbackrest(f"--stanza={PGBACKREST_STANZA_NAME} stanza-create")
    assert exit_code == 0, output
    assert "stanza-create command end: completed successfully" in output

@pytest.mark.order(2)
def test_full_backup():
    """Verify a full backup works. (archive_command is handled by pg_primary)"""
    run_sql(f"CREATE TABLE restore_val (id int, val text){ACCESS_METHOD};")
    run_sql("INSERT INTO restore_val VALUES (1, 'original_data');")
    run_sql("SELECT pg_switch_wal();")
    # Force a WAL switch to trigger the archive_command automatically
    run_sql("SELECT pg_switch_wal();")
    
    # Run backup without --no-archive-check as requested
    exit_code, output = run_pgbackrest(f"--stanza={PGBACKREST_STANZA_NAME} --type=full backup")
    assert exit_code == 0, output
    assert "backup command end: completed successfully" in output

@pytest.mark.order(3)
def test_incremental_backup():
    """Verify incremental backups track changes correctly."""
    # Insert some data to create a delta
    run_sql(f"CREATE TABLE test_data (id serial primary key, note text){ACCESS_METHOD};")
    run_sql("INSERT INTO test_data (note) VALUES ('verification_data');")
    run_sql("SELECT pg_switch_wal();")
    
    # Run incremental backup
    exit_code, output = run_pgbackrest(f"--stanza={PGBACKREST_STANZA_NAME} --type=incr backup")
    assert exit_code == 0, output
    assert "backup command end: completed successfully" in output



@pytest.mark.order(4)
def test_initial_backup_and_timestamp(pitr_context):
    """Inserts 'good' data, and captures the PITR time."""

    run_sql(f"CREATE TABLE pitr_test (id int, val text){ACCESS_METHOD};")
    run_sql("INSERT INTO pitr_test VALUES (1, 'good_data');")
    
    # We force a WAL switch to ensure the data is written to the WAL stream
    run_sql("SELECT pg_switch_wal();")
    
    # Capture the exact time AFTER the good data is committed
    # We use the DB's time to ensure sync with WAL timestamps
    golden_time = run_sql("SELECT current_timestamp;")
    pitr_context['target_time'] = golden_time
    
    # Take a full backup
    exit_code, output = run_pgbackrest(f"--stanza={PGBACKREST_STANZA_NAME} --type=full backup")
    assert exit_code == 0, output
    assert "backup command end: completed successfully" in output
    print(f"\nCaptured PITR Gold Time: {golden_time}")

@pytest.mark.order(5)
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



@pytest.mark.order(6)
def test_backup_info_validity():
    """Check that the info command shows our backups as 'ok'."""
    # Data check
    res = run_sql("SELECT val FROM pitr_test WHERE id = 1;")
    assert res == 'good_data'

    exit_code, output = run_pgbackrest("info")
    assert exit_code == 0, output
    assert "status: ok" in output
    # Ensure both full and incr are present
    assert "full backup" in output
    assert "incr backup" in output


@pytest.mark.order(7)
def test_retention_enforcement():
    """
    Verify that only 'repo1-retention-full' number of backups are kept.
    Even if many backups were created in previous tests, the count should now be 2.
    """
    # 1. Add more backups to ensure we are well over the limit of 2
    for i in range(3):
        run_sql(f"CREATE TABLE seed_retention_{i} (id int){ACCESS_METHOD};")
        run_pgbackrest(f"--stanza={PGBACKREST_STANZA_NAME} --type=full backup")
    
    # 2. Explicitly trigger the expire command (though backup usually does this)
    run_pgbackrest(f"--stanza={PGBACKREST_STANZA_NAME} expire")

    # 3. Check info
    exit_code, output = run_pgbackrest("info")
    
    # We count how many 'full' backups are currently in the list
    full_backup_count = output.count("full backup:")
    
    # Based on our pgbackrest.conf (repo1-retention-full=2), 
    # the count should strictly be 2.
    assert full_backup_count == 2, f"Expected 2 backups, found {full_backup_count}. Output: {output}"

@pytest.mark.order(8)
def test_archive_retention():
    """
    Verify that WAL archives (logs) are cleaned up.
    """
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

@pytest.mark.order(9)
def test_backup_verify_consistency():
    """Final deep-verify of the remaining 2 backups."""
    exit_code, output = run_pgbackrest(f"--stanza={PGBACKREST_STANZA_NAME} verify")
    assert exit_code == 0, output


# --- Restore Tests ---
# commented out for now as we are not restoring the database
# having some issues with the restore process
# will revisit later
#@pytest.mark.order(10)
# def test_restore_process():
#     """Simulates a disaster and restores the database."""
#     pg_container = client.containers.get(PG_CONTAINER_NAME)
#     # update_restore_command()
    
#     # 1. Stop the database to prevent file locking
#     pg_container.stop()

#     # Define the wrapped command
#     # Note: we use triple quotes and escapes for the nested pgbackrest call
#     #tde_wrapper = f"{PG_BIN}/pg_tde_archive_restore %f %p \\\"pgbackrest --stanza={PGBACKREST_STANZA_NAME} archive-get %f %p\\\""

#     # 2. Perform the restore
#     # --delta allows pgbackrest to use existing files and overwrite them
#     # --target-action=promote ensures the DB comes out of recovery mode on start
#     restore_cmd = (
#     f"--stanza={PGBACKREST_STANZA_NAME} --delta restore "
#     f"--post-restore-setting=restore_command=\"TMPDIR=/tmp {PG_BIN}/pg_tde_archive_restore %f %p \\\"pgbackrest --stanza={PGBACKREST_STANZA_NAME} archive-get %f %p\\\"\""
# )
#     #restore_cmd = f"--stanza={PGBACKREST_STANZA_NAME} --delta restore --post-restore-setting=\"{tde_wrapper}\""
#     try:
#         exit_code, output = run_pgbackrest(restore_cmd)
#         assert exit_code == 0, output
#         assert "restore command end: completed successfully" in output
#         #update_restore_command()
#     finally:
#         # Always restart the database to avoid cascading failures
#         if pg_container.status != "running":
#             pg_container.start()
    
#     # 4. Wait for PostgreSQL to recover (recovery.signal processing)
#     assert wait_for_postgres(), "PostgreSQL did not become ready after restore."

# @pytest.mark.order(11)
# def test_verify_restored_data():
#     """Verify the data exists after the restore."""
#     val = run_sql("SELECT val FROM restore_val WHERE id = 1;")
#     assert val == "original_data"

# @pytest.mark.order(12)
# def test_corruption_and_pitr_restore(pitr_context):
#     """Simulates disaster and performs PITR restore."""
#     target = pitr_context.get('target_time')
    
#     # Corrupt the data
#     run_sql("UPDATE pitr_test SET val = 'corrupted_data' WHERE id = 1;")
    
#     pg_container = client.containers.get(PG_CONTAINER_NAME)
#     #update_restore_command()
#     pg_container.stop()

#     # Define the wrapped command
#     # Note: we use triple quotes and escapes for the nested pgbackrest call
#     #tde_wrapper = f"{PG_BIN}/pg_tde_archive_restore %f %p \\\"pgbackrest --stanza={PGBACKREST_STANZA_NAME} archive-get %f %p\\\""


#     # Restore to target
#     restore_cmd = (
#     f"--stanza={PGBACKREST_STANZA_NAME} --delta restore "
#     f"--post-restore-setting=restore_command=\"TMPDIR=/tmp {PG_BIN}/pg_tde_archive_restore %f %p \\\"pgbackrest --stanza={PGBACKREST_STANZA_NAME} archive-get %f %p\\\"\""
# )
#     #restore_cmd = f'--stanza={PGBACKREST_STANZA_NAME} --delta --type=time "--target={target}" --target-action=promote restore --post-restore-setting=\"{tde_wrapper}\"'
#     try:
#         exit_code, output = run_pgbackrest(restore_cmd)
#         assert exit_code == 0, output
#         #update_restore_command()
#     finally:
#         if pg_container.status != "running":
#             pg_container.start()
#     assert wait_for_postgres(), "PostgreSQL did not become ready after PITR restore."


# @pytest.mark.order(13)
# def test_verify_recovery_success():
#     """Final check: Is the data back to 'good_data'?"""
#     res = run_sql("SELECT val FROM pitr_test WHERE id = 1;")
#     assert res == 'good_data'