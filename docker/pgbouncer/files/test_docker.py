import os
import docker
import time
import pytest
import shlex

client = docker.from_env()

# --- Simplified Global Config (Matches your pgbackrest style) ---
PG_CLIENT = os.getenv("PG_CLIENT_CONTAINER", "pg_client")
PG_PRIMARY = os.getenv("PG_CONTAINER_NAME", "pg_primary")
PGB_HOST = os.getenv("PGBOUNCER_HOST", "pgbouncer")
PGB_PORT = os.getenv("PGBOUNCER_PORT", "6432")
PG_USER = os.getenv("POSTGRES_USER", "postgres")
PG_PASS = os.getenv("POSTGRES_PASSWORD", "mysecretpassword")
PG_DB = os.getenv("PG_DB", "postgres")

# TDE Logic
SERVER_VERSION = os.getenv('SERVER_VERSION', '18')
WITH_TDE = os.getenv("WITH_TDE", "0")
TDE_ENABLED = WITH_TDE == "1" and int(SERVER_VERSION.split('.')[0]) >= 17
ACCESS_METHOD = "USING tde_heap" if TDE_ENABLED else "USING heap"

# --- Clean Helpers ---

def run_sql(query, host=PGB_HOST, port=PGB_PORT, user=PG_USER, password=PG_PASS, db=PG_DB):
    """Executes SQL from the client container."""
    container = client.containers.get(PG_CLIENT)
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

# --- Fixtures ---

@pytest.fixture(scope="session", autouse=True)
def setup_tde():
    if not TDE_ENABLED:
        return

    # 1. Setup keys on the DB container directly

    db_cont = client.containers.get(PG_PRIMARY)
    db_cont.exec_run(
        "bash -lc 'mkdir -p /var/lib/postgresql/keys && "
        "chown -R postgres:postgres /var/lib/postgresql/keys && "
        "chmod 700 /var/lib/postgresql/keys'"
    )
    # 2. Init TDE (Notice we talk to PG_PRIMARY port 5432 directly for setup)
    init_sql = """
    CREATE EXTENSION IF NOT EXISTS pg_tde;
    SELECT pg_tde_add_global_key_provider_file('v', '/var/lib/postgresql/keys/k.per');
    SELECT pg_tde_create_key_using_global_key_provider('wk', 'v');
    SELECT pg_tde_set_default_key_using_global_key_provider('wk', 'v');
    ALTER SYSTEM SET pg_tde.wal_encrypt = 'on';
    """
    run_sql(init_sql, host=PG_PRIMARY, port=5432)

    # 3. Restart and Wait
    db_cont.restart()
    assert wait_for_ready(), "Database/Proxy did not recover"

# --- Tests ---

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
    run_sql(f"PAUSE {PG_DB}", db="pgbouncer", user="pgbouncer_admin", password="adminpass")

    # Verify it hangs (using timeout)
    ec, _ = run_sql("timeout 1 psql -c 'SELECT 1'")
    assert ec != 0

    # Resume
    run_sql(f"RESUME {PG_DB}", db="pgbouncer", user="pgbouncer_admin", password="adminpass")
    assert wait_for_ready()