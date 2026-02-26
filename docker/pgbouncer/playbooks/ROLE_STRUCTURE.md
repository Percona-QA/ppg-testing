# pgBouncer Docker Role Structure

## Overview

The pgBouncer Docker test suite uses Ansible tasks (included directly from the playbook) that run pytest against a Docker Compose stack. The stack runs PostgreSQL (pg-primary), pgBouncer, and a client container (pg_client). Tests run on the host in the role-managed `/tmp/docker_test` workspace; pytest uses `docker exec` into the client container to run `psql` against pgBouncer.

## Directory Structure

```
docker/pgbouncer/
├── files/
│   ├── docker-compose.yml    # Compose: pg-primary, pgbouncer, pg_client (network pgb_net)
│   ├── pgbouncer.ini         # pgBouncer config template (auth_type=md5, listen_port, admin_users)
│   ├── userlist.txt          # Placeholder; userlist generated at runtime by tasks
│   ├── test_docker.py        # Pytest: client connection, admin console, PAUSE/RESUME
│   └── run.sh                # Optional local runner
├── tasks/
│   ├── main.yml              # All tasks: prereqs, prepare, execute
│   └── docker_install.yml    # Docker/Docker Compose installation
├── playbooks/
│   ├── playbook.yml          # Main playbook (vars + import_tasks)
│   ├── requirements.yml      # Ansible dependencies
│   └── ROLE_STRUCTURE.md     # This file
├── molecule/                 # Molecule scenarios (e.g. rocky-9, debian-12, rhel-10)
├── inventory.yml             # Inventory (local or remote)
└── README.md                 # Usage and env var reference
```

## Task Organization

### Prerequisites Section
- Ensures RHEL 10 dependencies (yum-utils, device-mapper-persistent-data, lvm2, kernel-modules-extra, br_netfilter) when applicable
- Includes `docker_install.yml`: installs Docker and Docker Compose (Debian, RHEL, etc.)

### Prepare Section
- Creates `/tmp/docker_test`
- Copies `docker-compose.yml` to `/tmp/docker_test`
- Renders `pgbouncer.ini` from template (uses `pgbouncer_port`, `postgres_user`, `pgbouncer_admin_user`)
- Generates `userlist.txt` at runtime with MD5 hashes for `postgres_user` and `pgbouncer_admin_user` (format: `md5(password+username)`)
- Detects Docker Compose command (V1 vs V2)
- Fails if Docker Compose is not available
- Starts PostgreSQL and pgBouncer services: `docker compose up -d` (all services: pg-primary, pgbouncer, pg_client)
- Waits for PostgreSQL container to become healthy

### Test Execution Section
- Copies `test_docker.py` to `/tmp/docker_test`
- Installs python3-venv on Debian/Ubuntu when needed
- Ensures Python venv in `/tmp/docker_test/validation` (or falls back to system Python)
- Installs bash on Debian when needed
- Ensures python3-pip for system fallback on RHEL when not using venv
- Installs pytest dependencies: `pytest`, `pytest-testinfra`, `pytest-order`, `docker`, `psycopg2-binary`, `passlib`
- Runs pytest: `pytest test_docker.py -vv -s -rpfs` with environment variables passed from playbook
- Prints stdout/stderr on failure

## Test Files

### test_docker.py
Configuration is driven by environment variables aligned with `playbook.yml` (same pattern as docker/pgbackrest). Session fixture `config` reads: `PG_CLIENT_CONTAINER`, `PGBOUNCER_HOST`/`PGBOUNCER_CONTAINER_NAME`, `PGBOUNCER_PORT`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `PG_DB`, `PGBOUNCER_ADMIN_USER`, `PGBOUNCER_ADMIN_PASS`. Tests run in natural order:

1. **test_client_connection_via_pgbouncer** – Client (postgres) connects through pgBouncer to database `postgres`
2. **test_admin_connection_to_pgbouncer_console** – Admin user connects to pgBouncer admin DB and runs `SHOW VERSION`
3. **test_pgbouncer_version_check** – Asserts version output contains "PgBouncer"
4. **test_pause_resume_admin_flow** – Admin runs `PAUSE` on the DB, asserts new client is blocked, then `RESUME` and verifies client can connect again

## Variables

Playbook variables are set from environment (e.g. Jenkins) with defaults; they drive both Compose and pytest.

### Key Variables (defined in playbook.yml)

**Images and repository**
- `DOCKER_REPOSITORY`: Image repository (`percona` or `perconalab`)
- `PG_SERVER_VERSION`, `PG_IMAGE_TAG`: PostgreSQL version and image tag
- `PGBOUNCER_COMPONENT_VERSION`, `PGBOUNCER_IMAGE_TAG`: pgBouncer version and image tag
- `postgres_test_image`, `pgbouncer_test_image`: Full image names
- `pg_bin_path`: Optional path to PostgreSQL binaries

**Containers and connectivity**
- `postgres_container_name`: e.g. `ppg_server_primary`
- `pgbouncer_container_name`: e.g. `ppg_pgbouncer`
- `max_connections`: PostgreSQL max_connections
- `postgres_user`, `postgres_password`: PostgreSQL superuser (used by Compose and userlist)
- `pgbouncer_admin_user`, `pgbouncer_admin_pass`: pgBouncer admin console user (userlist + tests)
- `pgbouncer_port`: Listen port (default `6432`)

**Test and execution**
- `pgbouncer_test_suite`, `pgbouncer_test_log_level`, `pgbouncer_test_cleanup_after`, `pgbouncer_test_verbose`
- `pgbouncer_test_install_docker`, `pgbouncer_test_install_docker_compose`, `pgbouncer_test_add_user_to_docker_group`, `pgbouncer_test_docker_compose_version`
- `pgbouncer_test_timeout`: Execution timeout in seconds (default 7200)

## Usage

### Using the playbook

The playbook includes tasks directly (no role path):

```yaml
- name: Converge
  hosts: all
  become: true
  become_method: sudo
  vars:
    # ... (see playbook.yml)
  tasks:
    - name: Display Docker image configuration
      debug: ...
    - name: Run pgBouncer docker tests
      import_tasks: "../tasks/main.yml"
```

### Environment variables

Set before running (e.g. in Jenkins or shell):

- `REPOSITORY`, `SERVER_VERSION`, `DOCKER_SERVER_TAG`, `COMPONENT_NAME`, `COMPONENT_VERSION`, `DOCKER_COMPONENT_TAG`
- `MAX_CONNECTIONS`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `PGBOUNCER_ADMIN_USER`, `PGBOUNCER_ADMIN_PASS`, `PGBOUNCER_PORT`
- Optional: `test_suite`, `log_level`, `cleanup_after`, `verbose`

### Command line

```bash
ansible-playbook -i inventory.yml playbooks/playbook.yml
# Or with extra vars:
ansible-playbook -i inventory.yml playbooks/playbook.yml -e "verbose=true"
```

## Tags

Tasks are tagged for selective runs:

- **prerequisites** – Prereq checks and Docker/Docker Compose install
- **prepare** – Directory, configs, userlist, Compose up, wait for PostgreSQL
- **execute** – Venv, pip deps, pytest run
- **always** – Tasks that always run when the play runs

Example: run only prepare (no tests):

```bash
ansible-playbook -i inventory.yml playbooks/playbook.yml --tags prepare
```
