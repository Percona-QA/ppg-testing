# pgBackRest Docker Role - Local Execution Guide

## Prerequisites

1. **Install Ansible**:
   ```bash
   pip install ansible
   # or
   brew install ansible  # macOS
   ```

2. **Install Ansible Collections**:
   ```bash
   cd docker/pgbackrest-docker/playbooks
   ansible-galaxy collection install -r requirements.yml
   ```

3. **Docker and Docker Compose**:
   - Docker should be installed (the role can install it if needed)
   - Docker Compose V1 or V2 should be available

## Running Locally

### Basic Execution

From the `docker/pgbackrest-docker` directory:

```bash
# Set environment variables (optional, defaults will be used if not set)
export REPOSITORY=percona
export PG_IMAGE_TAG=18
export PGBACKREST_IMAGE_TAG=2.57.0

# Run the playbook
ansible-playbook -i inventory.yml playbooks/playbook.yml
```

### With Custom Image Tags

```bash
export REPOSITORY=perconalab
export PG_IMAGE_TAG=18
export PGBACKREST_IMAGE_TAG=2.57.0

ansible-playbook -i inventory.yml playbooks/playbook.yml
```

### Using Command Line Variables

You can also override variables directly:

```bash
ansible-playbook -i inventory.yml playbooks/playbook.yml \
  -e "REPOSITORY=perconalab" \
  -e "PG_IMAGE_TAG=18" \
  -e "PGBACKREST_IMAGE_TAG=2.57.0" \
  -e "verbose=true"
```

### Running Specific Tasks with Tags

```bash
# Run only prerequisites (Docker installation, etc.)
ansible-playbook -i inventory.yml playbooks/playbook.yml --tags prerequisites

# Run only setup (skip prerequisites and tests)
ansible-playbook -i inventory.yml playbooks/playbook.yml --tags prepare

# Run only tests (assumes setup is already done)
ansible-playbook -i inventory.yml playbooks/playbook.yml --tags execute

# Skip Docker installation (if Docker is already installed)
ansible-playbook -i inventory.yml playbooks/playbook.yml --skip-tags install

# Skip setup (if containers are already running)
ansible-playbook -i inventory.yml playbooks/playbook.yml -e "skip_setup=true" --tags execute
```

### Verbose Output

```bash
ansible-playbook -i inventory.yml playbooks/playbook.yml -e "verbose=true" -v
```

### Skip Setup (Use Existing Containers)

If you already have containers running and just want to run tests:

```bash
ansible-playbook -i inventory.yml playbooks/playbook.yml \
  -e "skip_setup=true" \
  --tags execute
```

## Environment Variables

The playbook reads the following environment variables:

- **REPOSITORY**: Docker repository (default: `percona`)
  - Options: `percona` or `perconalab`
- **PG_IMAGE_TAG**: PostgreSQL image tag (default: `latest`)
  - Example: `17.5`, `16.4`, `latest`
- **PGBACKREST_IMAGE_TAG**: pgBackRest image tag (default: `latest`)
  - Example: `2.47`, `2.48`, `latest`
- **PGBACKREST_SKIP_PYTEST_SETUP**: Skip pytest session setup (default: `false`)
  - Set to `true` if you want to handle initial DB/stanza/backup setup outside pytest
- **PGBACKREST_RECREATE_ENV**: Recreate docker-compose environment per pytest session (default: `true`)
  - Set to `false` to reuse existing containers/volumes
- **PGBACKREST_CLEAN_STANZA_ON_MISMATCH**: Clean repo stanza data on mismatch (default: `false`)
  - Set to `true` to remove `/var/lib/pgbackrest/backup/main` and `/var/lib/pgbackrest/archive/main` when stanza creation fails with mismatch errors

## What the Role Does

Note: initial database setup, stanza creation, and the first backup run in
`test_docker.py` as a pytest session setup. Use
`PGBACKREST_SKIP_PYTEST_SETUP=true` if you want to handle setup outside pytest.

1. **Prerequisites** (tag: `prerequisites`):
   - Checks for Docker and Docker Compose
   - Installs Docker if missing
   - Installs Docker Compose if missing
2. **Environment Preparation** (tag: `prepare`):
   - Copies Docker Compose file
   - Copies pgBackRest configuration
   - Starts PostgreSQL and pgBackRest containers
   - Waits for services to be healthy
3. **Test Execution** (tag: `execute`):
   - Copies `test_docker.py` to `/tmp/docker_test`
   - Creates Python virtual environment if possible (fallbacks to system Python)
   - Installs pytest dependencies (pytest, testinfra, pytest-order, docker)
   - Runs pytest tests directly (no `run.sh` in flow)

## Troubleshooting

### Docker Permission Issues

If you get permission errors with Docker:

```bash
# Add your user to docker group (Linux)
sudo usermod -aG docker $USER
newgrp docker

# Or run with sudo
ansible-playbook -i inventory.yml playbooks/playbook.yml --ask-become-pass
```

### Skip Docker Installation

If Docker is already installed and you want to skip installation:

```bash
ansible-playbook -i inventory.yml playbooks/playbook.yml \
  -e "pgbackrest_test_install_docker=false" \
  -e "pgbackrest_test_install_docker_compose=false"
```

### Check Container Status

```bash
# Check if containers are running
docker ps

# Check container logs
docker logs <postgres_container_name>   # default: pg_primary
docker logs <pgbackrest_container_name>   # default: pgbackrest_repo
```

### Clean Up

To clean up containers and volumes:

```bash
cd docker/pgbackrest-docker
docker-compose down -v
# or
docker compose down -v
```

## Example: Complete Local Test Run

```bash
cd /Users/shahid/Percona/ppg-testing/docker/pgbackrest-docker

# Set environment variables
export REPOSITORY=percona
export PG_IMAGE_TAG=18
export PGBACKREST_IMAGE_TAG=2.57.0

# Install Ansible collections (first time only)
cd playbooks
ansible-galaxy collection install -r requirements.yml
cd ..

# Run the playbook
ansible-playbook -i inventory.yml playbooks/playbook.yml -e "verbose=true"
```

## Directory Structure

```
docker/pgbackrest-docker/
├── files/
│   ├── docker-compose.yml      # Docker services configuration
│   ├── pgbackrest.conf         # pgBackRest configuration
│   └── test_docker.py          # Main pytest test file
├── tasks/
│   ├── main.yml                # Role tasks
│   └── docker_install.yml      # Docker/Docker Compose install tasks
├── playbooks/
│   ├── playbook.yml            # Main playbook
│   └── requirements.yml        # Ansible dependencies
└── inventory.yml               # Ansible inventory
```

## Test Output

The tests output to stdout/stderr; all output is shown in the terminal when the
playbook runs.
