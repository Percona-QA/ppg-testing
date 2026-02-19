import os
import shlex
import subprocess
import time

import pytest


def _run_command(args, timeout=30):
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _docker_exec(container_name, command, timeout=30):
    return _run_command(
        ["docker", "exec", "-i", container_name, "bash", "-lc", command],
        timeout=timeout,
    )


def _execute_psql(container_name, query, user, password, host, port, db, timeout=20):
    psql_cmd = (
        f"PGPASSWORD={shlex.quote(password)} "
        f"psql -p {shlex.quote(str(port))} -U {shlex.quote(user)} "
        f"-h {shlex.quote(host)} {shlex.quote(db)} -t -c {shlex.quote(query)}"
    )
    return _docker_exec(container_name, psql_cmd, timeout=timeout)


@pytest.fixture(scope="session")
def config():
    """Session config from env; names and defaults match playbook.yml vars."""
    return {
        # Client container that runs psql (compose service pg_client)
        "pg_client_container": os.getenv("PG_CLIENT_CONTAINER", "pg_client"),
        # pgBouncer host (compose service name) / playbook: pgbouncer_container_name
        "pgb_host": os.getenv("PGBOUNCER_HOST", os.getenv("PGBOUNCER_CONTAINER_NAME", "pgbouncer")),
        # playbook: pgbouncer_port / PGBOUNCER_PORT
        "pgb_port": os.getenv("PGBOUNCER_PORT", "6432"),
        # PostgreSQL user/password (compose POSTGRES_USER / POSTGRES_PASSWORD)
        "pg_user": os.getenv("POSTGRES_USER", "postgres"),
        "pg_pass": os.getenv("POSTGRES_PASSWORD", "mysecretpassword"),
        # playbook/compose: PG_DB
        "pg_db": os.getenv("PG_DB", "postgres"),
        # playbook: pgbouncer_admin_user / pgbouncer_admin_pass
        "pgb_admin_user": os.getenv("PGBOUNCER_ADMIN_USER", "pgbouncer_admin"),
        "pgb_admin_pass": os.getenv("PGBOUNCER_ADMIN_PASS", "adminpass"),
    }


@pytest.fixture(scope="session", autouse=True)
def ensure_docker_available():
    result = _run_command(["docker", "ps"], timeout=10)
    if result.returncode != 0:
        pytest.skip(f"Docker not available: {result.stderr.strip()}")


def _check_conn(cfg):
    result = _execute_psql(
        cfg["pg_client_container"],
        "SELECT 1;",
        cfg["pg_user"],
        cfg["pg_pass"],
        cfg["pgb_host"],
        cfg["pgb_port"],
        cfg["pg_db"],
    )
    return result.returncode == 0, result


def test_client_connection_via_pgbouncer(config):
    success, result = _check_conn(config)
    assert success, (
        f"Client ('{config['pg_user']}') connection via PgBouncer "
        f"({config['pg_db']}) failed: {result.stderr.strip()}"
    )


def test_admin_connection_to_pgbouncer_console(config):
    result = _execute_psql(
        config["pg_client_container"],
        "SHOW VERSION;",
        config["pgb_admin_user"],
        config["pgb_admin_pass"],
        config["pgb_host"],
        config["pgb_port"],
        "pgbouncer",
    )
    assert result.returncode == 0, (
        f"Admin ('{config['pgb_admin_user']}') connection to PgBouncer Admin failed: "
        f"{result.stderr.strip()}"
    )


def test_pgbouncer_version_check(config):
    result = _execute_psql(
        config["pg_client_container"],
        "SHOW VERSION;",
        config["pgb_admin_user"],
        config["pgb_admin_pass"],
        config["pgb_host"],
        config["pgb_port"],
        "pgbouncer",
    )
    assert result.returncode == 0, f"Could not retrieve PgBouncer version: {result.stderr.strip()}"
    assert "PgBouncer" in result.stdout, f"Unexpected version output: {result.stdout.strip()}"


def test_pause_resume_admin_flow(config):
    pause_result = _execute_psql(
        config["pg_client_container"],
        f"PAUSE {config['pg_db']};",
        config["pgb_admin_user"],
        config["pgb_admin_pass"],
        config["pgb_host"],
        config["pgb_port"],
        "pgbouncer",
    )
    assert pause_result.returncode == 0, f"PAUSE command failed: {pause_result.stderr.strip()}"
    assert "PAUSE" in pause_result.stdout, f"PAUSE command failed: {pause_result.stdout.strip()}"

    blocked_cmd = (
        f"timeout 5 "
        f"PGPASSWORD={shlex.quote(config['pg_pass'])} "
        f"psql -p {shlex.quote(str(config['pgb_port']))} -U {shlex.quote(config['pg_user'])} "
        f"-h {shlex.quote(config['pgb_host'])} {shlex.quote(config['pg_db'])} "
        f"-t -c {shlex.quote('SELECT 1;')}"
    )
    blocked_result = _docker_exec(config["pg_client_container"], blocked_cmd, timeout=10)
    assert blocked_result.returncode != 0, (
        "New client connection was NOT blocked/queued by PAUSE."
    )

    resume_result = _execute_psql(
        config["pg_client_container"],
        f"RESUME {config['pg_db']};",
        config["pgb_admin_user"],
        config["pgb_admin_pass"],
        config["pgb_host"],
        config["pgb_port"],
        "pgbouncer",
    )
    assert resume_result.returncode == 0, f"RESUME command failed: {resume_result.stderr.strip()}"
    assert "RESUME" in resume_result.stdout, f"RESUME command failed: {resume_result.stdout.strip()}"

    time.sleep(2)
    success, result = _check_conn(config)
    assert success, f"Client connection not restored after RESUME: {result.stderr.strip()}"

