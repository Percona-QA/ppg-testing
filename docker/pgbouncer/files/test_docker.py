import os
import docker
import time
import pytest
import shlex

client = docker.from_env()

# Env vars aligned with playbook.yml / tasks main.yml (same names passed to pytest)
PG_CLIENT_CONTAINER_NAME = os.getenv("PG_CLIENT_CONTAINER_NAME", "ppg_client")
PG_CONTAINER_NAME = os.getenv("PG_CONTAINER_NAME", "ppg_server_primary")
PGBOUNCER_CONTAINER_NAME = os.getenv("PGBOUNCER_CONTAINER_NAME", "ppg_pgbouncer")
PGB_HOST = os.getenv("PGBOUNCER_HOST", os.getenv("PGBOUNCER_CONTAINER_NAME", "pgbouncer"))
PGB_PORT = os.getenv("PGBOUNCER_PORT", "6432")
PG_USER = os.getenv("POSTGRES_USER", "postgres")
PG_PASS = os.getenv("POSTGRES_PASSWORD", "mysecretpassword")
PG_DB = os.getenv("PG_DB", "postgres")
PGBOUNCER_ADMIN_USER = os.getenv("PGBOUNCER_ADMIN_USER", "pgbouncer_admin")
PGBOUNCER_ADMIN_PASS = os.getenv("PGBOUNCER_ADMIN_PASS", "adminpass")
PGBOUNCER_VERSION = os.getenv("COMPONENT_VERSION")

# TDE Logic
SERVER_VERSION = os.getenv('SERVER_VERSION', '18')
WITH_TDE = os.getenv("WITH_TDE", "0")
TDE_ENABLED = WITH_TDE == "1" and int(SERVER_VERSION.split('.')[0]) >= 17
ACCESS_METHOD = "USING tde_heap" if TDE_ENABLED else "USING heap"

# --- Clean Helpers ---

def run_sql(query, host=PGB_HOST, port=PGB_PORT, user=PG_USER, password=PG_PASS, db=PG_DB):
    """Executes SQL from the client container."""
    container = client.containers.get(PG_CLIENT_CONTAINER_NAME)
    cmd = f"psql -h {host} -p {port} -U {user} -d {db} -Atc {shlex.quote(query)}"
    exit_code, output = container.exec_run(["bash", "-lc", cmd], environment={"PGPASSWORD": password})
    return exit_code, output.decode().strip()

def wait_for_ready(timeout=30):
    """Simple loop to check if pgbouncer is routing traffic."""
    for _ in range(timeout):
        ec, _ = run_sql("SELECT 1")
        if ec == 0: return True
        time.sleep(1)
    return False

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

def ensure_postgres_running():
    container = client.containers.get(PG_CONTAINER_NAME)
    container.reload()
    if container.status != "running":
        container.start()
    assert wait_for_postgres(), "PostgreSQL is not ready."

def run_sql_exec(sql):
    ensure_postgres_running()
    container = client.containers.get(PG_CONTAINER_NAME)
    exit_code, output = container.exec_run(
        f"psql -U postgres -v ON_ERROR_STOP=1 -Atc \"{sql}\"",
        environment={"PGPASSWORD": "mysecretpassword"},
    )
    return exit_code, output.decode()

def restart_postgres():
    container = client.containers.get(PG_CONTAINER_NAME)
    container.restart()
    assert wait_for_postgres(), "PostgreSQL did not become ready after restart."

# --- Fixtures ---

def ensure_tde_setup():
    if not TDE_ENABLED:
        return
    container = client.containers.get(PG_CONTAINER_NAME)
    container.exec_run(
        "bash -lc 'mkdir -p /var/lib/postgresql/keys && "
        "chown -R postgres:postgres /var/lib/postgresql/keys && "
        "chmod 700 /var/lib/postgresql/keys'"
    )
    sql = """
    CREATE EXTENSION IF NOT EXISTS pg_tde;
    SELECT pg_tde_add_global_key_provider_file('wal-vault', '/var/lib/postgresql/keys/pg_tde_test_001_wal.per');
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
def test_pgbouncer_binary_present():
    """Verify pgBouncer binary exists in the pgbouncer container."""
    container = client.containers.get(PGBOUNCER_CONTAINER_NAME)
    exit_code, _ = container.exec_run("test -x /usr/bin/pgbouncer")
    assert exit_code == 0, "pgbouncer binary not found or not executable"


@pytest.mark.order(0)
def test_pgbouncer_binary_version():
    """Verify pgBouncer binary reports a version."""
    container = client.containers.get(PGBOUNCER_CONTAINER_NAME)
    exit_code, output = container.exec_run("/usr/bin/pgbouncer --version")
    output_text = output.decode().strip()
    assert exit_code == 0, output_text
    assert "PgBouncer" in output_text
    if PGBOUNCER_VERSION:
        assert PGBOUNCER_VERSION in output_text, output_text

@pytest.mark.order(1)
def test_connection():
    """Step 1: Can we even talk to PgBouncer?"""
    ec, out = run_sql("SELECT version()")
    assert ec == 0
    assert "PostgreSQL" in out

@pytest.mark.order(2)
def test_tde_table():
    """Step 2: Can we create encrypted tables through the proxy?"""
    if not TDE_ENABLED:
        pytest.skip()
    # Same session: CREATE + INSERT so one PgBouncer connection (avoids transaction-mode quirks)
    ec, out = run_sql(
        f"DROP TABLE IF EXISTS tde_test; "
        f"CREATE TABLE tde_test (id int) {ACCESS_METHOD}; "
        f"INSERT INTO tde_test VALUES (1)"
    )
    assert ec == 0, f"TDE table create/insert failed: {out}"

@pytest.mark.order(3)
def test_pause_resume():
    """Step 3: Can we admin the proxy?"""
    # Pause using admin credentials
    run_sql(f"PAUSE {PG_DB}", db="pgbouncer", user=PGBOUNCER_ADMIN_USER, password=PGBOUNCER_ADMIN_PASS)

    # Verify it hangs (using timeout)
    ec, _ = run_sql("timeout 1 psql -c 'SELECT 1'")
    assert ec != 0

    # Resume
    run_sql(f"RESUME {PG_DB}", db="pgbouncer", user=PGBOUNCER_ADMIN_USER, password=PGBOUNCER_ADMIN_PASS)
    assert wait_for_ready()

@pytest.mark.order(4)
def test_pgbouncer_stats():
    """Verify PgBouncer is tracking stats for our database."""
    # Run some traffic
    for _ in range(5):
        run_sql("SELECT 1")

    # Check stats in the 'pgbouncer' internal DB
    ec, out = run_sql("SHOW STATS", db="pgbouncer", user=PGBOUNCER_ADMIN_USER, password=PGBOUNCER_ADMIN_PASS)

    assert ec == 0
    # Verify the specific database line exists in the output
    assert PG_DB in out, f"Database {PG_DB} not found in stats: {out}"

    # Structural check: Count pipes (|).
    # SHOW STATS returns ~22 columns, so we expect a lot of pipes.
    assert out.count("|") >= 10, f"Output structure looks wrong: {out}"

@pytest.mark.order(5)
def test_tde_access_method_verification():
    """Verify that the table is actually using the TDE access method in the catalog."""
    if not TDE_ENABLED:
        pytest.skip()

    # Query the Postgres catalog to see the access method
    query = f"SELECT amname FROM pg_class c JOIN pg_am a ON c.relam = a.oid WHERE relname = 'tde_test';"
    ec, out = run_sql(query)

    assert ec == 0
    assert out == "tde_heap", f"Table should be using tde_heap, but found: {out}"

@pytest.mark.order(6)
def test_multi_session_consistency():
    """Verify that data inserted in one session is readable in another via the proxy."""
    table_name = "consistency_test"

    # Session 1: Create and Insert
    run_sql(f"DROP TABLE IF EXISTS {table_name}; CREATE TABLE {table_name} (id int, val text) {ACCESS_METHOD};")
    run_sql(f"INSERT INTO {table_name} VALUES (42, 'secret_content');")

    # Session 2: Read
    ec, out = run_sql(f"SELECT val FROM {table_name} WHERE id = 42;")
    assert ec == 0
    assert out == "secret_content"

@pytest.mark.order(7)
def test_pgbouncer_reload():
    """Verify that RELOAD works without breaking connectivity."""
    # Check current state
    assert run_sql("SELECT 1")[0] == 0

    # Execute RELOAD on the admin console
    ec, out = run_sql("RELOAD", db="pgbouncer", user=PGBOUNCER_ADMIN_USER, password=PGBOUNCER_ADMIN_PASS)
    assert ec == 0

    # If TDE is enabled, verify the specific table. If not, just verify basic SQL.
    query = "SELECT count(*) FROM tde_test" if TDE_ENABLED else "SELECT 1"
    ec, out = run_sql(query)
    assert ec == 0, f"Connectivity lost after RELOAD: {out}"

@pytest.mark.order(8)
def test_unprivileged_user_access():
    """Security check: Ensure a user without the password/proper auth is rejected."""
    # Attempt to connect with a fake password
    ec, out = run_sql("SELECT 1", password="wrong_password")
    # PgBouncer/Postgres should return a non-zero exit code for failed auth
    assert ec != 0
    assert "password authentication failed" in out.lower() or "auth failed" in out.lower()

@pytest.mark.order(9)
def test_encryption_at_rest_verification():
    """Negative Test: Verify raw data file does not contain plain-text string."""
    if not TDE_ENABLED:
        pytest.skip()

    secret_string = "SUPER_SECRET_TDE_DATA_12345"
    table_name = "tde_leak_test"

    # 1. Create table and insert unique string
    run_sql(f"CREATE TABLE {table_name} (val text) {ACCESS_METHOD};")
    run_sql(f"INSERT INTO {table_name} VALUES ('{secret_string}');")

    # 2. Flush data to disk
    run_sql("CHECKPOINT;", host=PG_CONTAINER_NAME, port=5432)

    # 3. Search the raw data files in the PGDATA directory for the secret string
    # We expect this to fail (Exit code 1) because the data should be encrypted
    db_cont = client.containers.get(PG_CONTAINER_NAME)
    grep_cmd = f"grep -r '{secret_string}' /var/lib/postgresql/data"
    exit_code, output = db_cont.exec_run(["bash", "-lc", grep_cmd])

    assert exit_code != 0, "Security Failure: Plain-text string found in raw data files!"

@pytest.mark.order(10)
def test_pgbouncer_pool_health():
    """Verify pool management state for the TDE database."""
    ec, out = run_sql("SHOW POOLS", db="pgbouncer", user=PGBOUNCER_ADMIN_USER, password=PGBOUNCER_ADMIN_PASS)

    assert ec == 0
    # Verify our database and user are present in the pool list
    assert PG_DB in out, f"Database {PG_DB} not found in pools: {out}"
    assert PG_USER in out, f"User {PG_USER} not found in pools: {out}"

    # Check that the pool mode is visible (e.g., 'transaction' or 'session')
    assert "transaction" in out or "session" in out or "statement" in out

@pytest.mark.order(11)
def test_transaction_mode_handling():
    """Verify Transaction pooling works (with TDE if enabled)."""
    # Use the TDE table if available, otherwise use a standard temp table
    target_table = "tde_test" if TDE_ENABLED else "tx_pool_test"

    setup_sql = ""
    if not TDE_ENABLED:
        setup_sql = f"CREATE TEMP TABLE {target_table} (id int);"

    tx_sql = f"""
    {setup_sql}
    BEGIN;
    INSERT INTO {target_table} VALUES (999);
    SELECT count(*) FROM {target_table} WHERE id = 999;
    COMMIT;
    """
    ec, out = run_sql(tx_sql)
    assert ec == 0, f"Transaction failed: {out}"
    # 'out' might contain multiple lines; we check that '1' is the result of the SELECT
    assert "1" in out
