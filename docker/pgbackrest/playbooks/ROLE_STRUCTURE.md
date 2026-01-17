# pgBackRest Docker Role Structure

## Overview

The pgBackRest Docker test suite uses an Ansible role that mirrors the ppg-docker
layout and runs pytest directly (no `run.sh` in the execution flow). Docker
Compose spins up PostgreSQL and the pgBackRest repo container, and the tests run
inside the role-managed `/tmp/docker_test` workspace.

## Directory Structure

```
docker/pgbackrest-docker/
├── files/
│   ├── docker-compose.yml      # Docker Compose configuration
│   ├── pgbackrest.conf         # pgBackRest configuration file
│   └── test_docker.py          # Main pytest test file
├── tasks/
│   ├── main.yml                # Role tasks (prereqs, setup, execution)
│   └── docker_install.yml      # Docker/Docker Compose install tasks
├── playbooks/
│   ├── playbook.yml            # Main playbook
│   ├── requirements.yml        # Ansible dependencies
│   └── ROLE_STRUCTURE.md       # This file
├── molecule/                   # Molecule test configurations
└── inventory.yml               # Inventory (local or remote)
```

## Task Organization

### Prerequisites Section
- Validates Docker and Docker Compose
- Installs Docker if missing (Debian, RHEL, macOS)
- Installs Docker Compose if missing (binary, then pip fallback)
- Starts and enables Docker service (Linux)
- Adds user to docker group (Linux, optional)

### Environment Preparation Section
- Creates `/tmp/docker_test`
- Copies `docker-compose.yml` and `pgbackrest.conf`
- Detects Docker Compose command (V1 or V2)
- Starts PostgreSQL and pgBackRest services
- Waits for PostgreSQL to become healthy

### Test Execution Section
- Copies `test_docker.py` to `/tmp/docker_test`
- Creates a Python venv if available (fallbacks to system Python)
- Installs pytest dependencies (`pytest`, `pytest-testinfra`, `pytest-order`, `docker`)
- Runs pytest directly
- Prints stdout/stderr on failure

## Test Files

### test_docker.py
The main pytest file. Tests run in a defined order using `@pytest.mark.order`:

1. `test_stanza_creation()` - Initializes the stanza
2. `test_full_backup()` - Full backup with WAL archiving
3. `test_incremental_backup()` - Incremental backup after data change
4. `test_restore_process()` - Restore workflow (stop, restore, start)
5. `test_verify_restored_data()` - Validate restored data
6. `test_initial_backup_and_timestamp()` - PITR baseline and capture target time
7. `test_repository_consistency()` - Verify repository integrity
8. `test_corruption_and_pitr_restore()` - PITR restore after corruption
9. `test_verify_recovery_success()` - Validate PITR recovery data
10. `test_backup_info_validity()` - Validate `pgbackrest info` output
11. `test_retention_enforcement()` - Enforce retention policy
12. `test_archive_retention()` - Validate WAL archive cleanup
13. `test_backup_verify_consistency()` - Final repository verify

## Variables

All role variables are prefixed with `pgbackrest_test_` to avoid conflicts.

### Key Variables (defined in playbook.yml)

- `DOCKER_REPOSITORY`: Docker repository for images (`percona` or `perconalab`)
- `PG_IMAGE_TAG`: PostgreSQL image tag
- `PGBACKREST_IMAGE_TAG`: pgBackRest image tag
- `pgbackrest_test_project_dir`: Project directory path
- `pgbackrest_test_pg_image`: PostgreSQL Docker image (constructed from repo + tag)
- `pgbackrest_test_pgbackrest_image`: pgBackRest Docker image (constructed from repo + tag)
- `postgres_container_name`: PostgreSQL container name (used by Docker Compose and pytest)
- `pgbackrest_container_name`: pgBackRest container name (used by Docker Compose and pytest)
- `pgbackrest_stanza_name`: Stanza name used by tests
- `pgbackrest_test_skip_setup`: Skip Docker setup (default: false)
- `pgbackrest_test_verbose`: Verbose output flag
- `pgbackrest_test_install_docker`: Install Docker if missing (default: true)
- `pgbackrest_test_install_docker_compose`: Install Docker Compose if missing (default: true)
- `pgbackrest_test_add_user_to_docker_group`: Add user to docker group (default: true)
- `pgbackrest_test_docker_compose_version`: Docker Compose version for standalone install
- `pgbackrest_test_timeout`: Execution timeout in seconds

## Usage

### Using the Role in Playbook

The playbook (`playbooks/playbook.yml`) includes the role tasks directly:

```yaml
- name: Converge
  hosts: all
  become: true
  vars:
    pgbackrest_test_pg_image: "percona/percona-distribution-postgresql:latest"
    pgbackrest_test_pgbackrest_image: "percona/percona-pgbackrest:latest"
  tasks:
    - name: Include all tasks
      include_tasks: ../tasks/main.yml
```

### Command Line Variables

The playbook maps short variable names to role variables:

```bash
ansible-playbook -i inventory.yml playbooks/playbook.yml \
  -e "pg_image=percona/percona-distribution-postgresql:18" \
  -e "pgbackrest_image=percona/percona-pgbackrest:2.57.0" \
  -e "verbose=true"
```

## Tags

The role supports selective execution using tags:

- `prerequisites` - Run prerequisites check and installation only
- `prepare` - Run preparation tasks only (Docker setup, service startup)
- `execute` - Run test execution only (pytest)
- `always` - Tasks that always run
