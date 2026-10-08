# Upgrade CI and runbook — `pg_tde/upgrade` role + local pytest runs

> **Status:** the CI flow in section 1 (staged checker, `tde-upgrade` /
> `tde-upgrade-parallel` jobs, key-provider / HA / checksum parameters) lives on
> branch `pg-tde-upgrade-harden` and is **not merged to `main` yet**. Sections A
> and B run from this directory and do not depend on it.

Full pytest catalog: [`upgrade_matrix.md`](upgrade_matrix.md).

---

## 1. CI: the `pg_tde/upgrade` Ansible role

Ansible owns *getting there* (real Percona repos, packages, systemd, `pg_tde_upgrade`).
pytest owns *checking it*: the role calls the staged checker
[`tests/test_tde_upgrade_check.py`](../tests/test_tde_upgrade_check.py) against the
packaged service cluster through `PGHOST`/`PGPORT`. Jenkins jobs are generated from
`pg_tde/upgrade/scenario.yml` (`tools/gen_jenkins.py`):

| Job | Purpose |
|-----|---------|
| `tde-upgrade` | one platform, one upgrade |
| `tde-upgrade-parallel` | the same upgrade across the platform matrix |

### 1.1 Flow

| Step | What happens |
|------|--------------|
| Install FROM | `FROM_VERSION` server packages + pg_tde (packages, or built from `FROM_TDE_BRANCH`) |
| `prepare` | extension, global provider + server key, WAL encryption on; role restarts the server |
| `setup` | seed the standard dataset, check it is encrypted on disk, write `upgrade_check_state.json` |
| Upgrade | `server_minor` / `tde_only`: package swap + restart. `server_major`: `pg_tde_upgrade --check`, then `--link` |
| `verify-before-alter` | read-only: data, encryption state, providers and keys unchanged with the new library on the old extension catalog |
| `ALTER EXTENSION pg_tde UPDATE` | every database; failures fail the job |
| `verify` | same checks, `extversion`, ciphertext on disk, writes, new tde tables, key rotation |
| `verify-replica` | `HA=true` only: replica in recovery, caught up, same data/keys, encrypted on disk and in WAL |

The job also fails on a no-op upgrade (expected `version()` / `pg_tde_version()` must
differ from the state file when a bump is expected).

### 1.2 Parameters

| Parameter | Meaning |
|-----------|---------|
| `FROM_VERSION`, `TO_VERSION` | e.g. `ppg-17.10`, `ppg-18.4` |
| `UPGRADE_TYPE` | `server_minor`, `server_major` (`pg_tde_upgrade --link`), `tde_only` |
| `TDE_UPGRADE` | also upgrade pg_tde during a server upgrade (ignored for `tde_only`) |
| `FROM_REPO`, `TO_REPO` | `testing` / `experimental` / `release` |
| `INSTALL_FROM_PACKAGES` | pg_tde from packages (default) or built from `FROM_TDE_BRANCH` / `TO_TDE_BRANCH` |
| `USE_OBS_REPO`, `OBS_HOST`, `OBS_PROJECT` | install the TO version from OBS |
| `KEY_PROVIDER` | `file`, or `vault` / `openbao` / `kmip` (KMS started in docker by the role; `tde_b` always stays on a file provider) |
| `HA` | add a streaming replica; rolling upgrade for minor / `tde_only`, rebuilt after a major |
| `DATA_CHECKSUMS` | `default` / `on` / `off` for the FROM cluster; with checksums on, the upgraded cluster is checked offline with `pg_tde_checksums` |
| `RUN_PYTEST_UPGRADE_SECTION`, `PYTEST_UPGRADE_TESTS` | `server_major` only: also run the pytest major-upgrade tests (default `tests/test_tde_pg_upgrade.py`) on the packaged FROM and TO binaries (about 6 min) |
| `FROM/TO_PKG_RELEASE`, `FROM/TO_TDE_PKG_VERSION` | pin server build increment / pg_tde package version |
| `FROM/TO_PERCONA_SERVER_VERSION` | assert `SELECT version()` reports this patch version |
| `DESTROY_ENV` | `false` keeps the VM for debugging |

The authoritative list, with defaults, is `params:` in `pg_tde/upgrade/scenario.yml`.

### 1.3 Running the checker by hand

The stages are selected with `--upgrade-stage` (`prepare`, `setup`,
`verify-before-alter`, `verify`, `verify-replica`); without it the module is skipped.

```bash
cd pg_tde/core/files/pytest && source .env.sh
pytest tests/test_tde_upgrade_check.py --upgrade-stage=setup \
    --upgrade-check-dir=/var/lib/pg_tde_upgrade_check
```

Options: `--upgrade-check-dir` (default `/var/lib/pg_tde_upgrade_check`),
`--replica-port` (for `verify-replica`). Skip it with `--skip-sections=upgrade_check`.

---

## Two upgrade types run from this directory

| Track | Name | PostgreSQL | Data dir | Tooling in this repo |
|-------|------|------------|----------|----------------------|
| **A — Major** | `pytest -m upgrade` | Different major (typ. **17 → 18**) | New cluster via `pg_tde_upgrade` | `tests/test_tde_pg_upgrade.py` + `tests/test_upgrade.py` |
| **B — Minor patch** | `run_minor_upgrade_workflow.sh` | Same major (**18 → 18**) | **Same** `$PGDATA` | `run_minor_upgrade_workflow.sh` + `tests/test_tde_minor_upgrade.py` |

These use two side-by-side install trees or a staged local workflow, not the
packaged service cluster the role upgrades.

---

## A. Major upgrade (pytest, local)

See [`upgrade_matrix.md`](upgrade_matrix.md) for the per-class breakdown.

### A.1 Pytest run

Single command covering all major TDE regression + plain `pg_upgrade`:

```bash
cd pg_tde/core/files/pytest && source .env.sh

export OLD_INSTALL_DIR=/home/ubuntu/pgwork/pginst/17   # adjust
export INSTALL_DIR=/home/ubuntu/pgwork/pginst/18

pytest -m upgrade \
  --old-install-dir="$OLD_INSTALL_DIR" \
  --install-dir="$INSTALL_DIR" \
  tests/test_tde_pg_upgrade.py tests/test_upgrade.py \
  -v --tb=short
```

### A.2 Version-specific subsets

| Old / new pg_tde.control | Run these classes | Skip reason for others |
|--------------------------|-------------------|------------------------|
| **2.1 → 2.2** (cross-minor) | `TestPg2381EmptyKeyMigration`, `TestPg2379MultiDbKeyMigration` + all other major classes | `TestPg2381MajorUpgradeSamePgTdeControl` skips |
| **2.2 → 2.2** (same control, e.g. PG17 2.2.0 → PG18 2.2.1) | `TestPg2381MajorUpgradeSamePgTdeControl`, `TestPspToPspUpgrade`, … | `TestPg2381EmptyKeyMigration`, `TestPg2379MultiDbKeyMigration` skip |

Check control version:

```bash
grep default_version "$OLD_INSTALL_DIR"/share/*/extension/pg_tde.control
grep default_version "$INSTALL_DIR"/share/*/extension/pg_tde.control
```

### A.3 Staged VM workflow (packages, Debian/RHEL)

```bash
cd pg_tde/core/files/pytest
sudo mkdir -p /var/lib/pg_tde_major_upgrade && sudo chown "$USER" /var/lib/pg_tde_major_upgrade

bash run_major_upgrade_workflow.sh \
  --old-pg-major 17 \
  --new-pg-major 18
```

See [`major_upgrade.md`](major_upgrade.md) for `--method debian`, split phases, and troubleshooting.

## B. 18.4.1 → 18.4.2 (in-place patch / minor bump)

Same PostgreSQL **major** (18), same `$PGDATA`, operator replaces packages
(18.4.1 → 18.4.2), then pytest Verify runs `ALTER EXTENSION pg_tde UPDATE` when
the catalog minor advances.

This is **not** `pg_upgrade` and **not** `tests/test_upgrade.py`.

### B.1 Automated full workflow (recommended)

```bash
cd pg_tde/core/files/pytest

sudo mkdir -p /var/lib/pg_tde_minor_upgrade
sudo chown "$USER" /var/lib/pg_tde_minor_upgrade

# Defaults: 18.4.1 from **release** → 18.4.2 from **testing**
bash run_minor_upgrade_workflow.sh

# Explicit (same as defaults):
OLD_PG_VERSION=18.4.1 NEW_PG_VERSION=18.4.2 \
OLD_REPO_COMPONENT=release NEW_REPO_COMPONENT=testing \
bash run_minor_upgrade_workflow.sh
```

### B.2 Manual staged pytest (split CI jobs)

**Phase 1 — Setup (18.4.1 packages):**

```bash
export PG_TDE_UPGRADE_DATA_DIR=/var/lib/pg_tde_minor_upgrade
export INSTALL_DIR=/usr/lib/postgresql/18

bash setup_test_env.sh --install-pkgs --pg-major 18.4.1 --repo-component release --components server,pg_tde

pytest tests/test_tde_minor_upgrade.py::TestPgTdeMinorUpgradeSetup \
  tests/test_tde_minor_upgrade.py::TestPgTdeMinorUpgradeSetupHA \
  tests/test_tde_minor_upgrade.py::TestPg2381MinorUpgradeSetup \
  --install-dir="$INSTALL_DIR" \
  --upgrade-data-dir="$PG_TDE_UPGRADE_DATA_DIR" \
  -v
```

**Phase 2 — Operator:** stop clusters, `apt`/`yum` upgrade to **18.4.2** (do not wipe PGDATA).

**Phase 3 — Verify (18.4.2 packages):**

```bash
bash setup_test_env.sh --install-pkgs --pg-major 18.4.2 --repo-component testing --components server,pg_tde

pytest tests/test_tde_minor_upgrade.py::TestPgTdeMinorUpgradeVerify \
  tests/test_tde_minor_upgrade.py::TestPgTdeMinorUpgradeVerifyHA \
  tests/test_tde_minor_upgrade.py::TestPg2381MinorUpgradeVerify \
  --install-dir="$INSTALL_DIR" \
  --upgrade-data-dir="$PG_TDE_UPGRADE_DATA_DIR" \
  -v
```

### B.3 Non-staged behaviour tests (single pytest run on 18.4.2)

Run after packages are on 18.4.2; no `--upgrade-data-dir`:

```bash
pytest tests/test_tde_minor_upgrade.py::TestTdeMinorUpgradePreConditions \
  tests/test_tde_minor_upgrade.py::TestAlterExtensionUpdate \
  tests/test_tde_minor_upgrade.py::TestRollingRestart \
  tests/test_tde_minor_upgrade.py::TestWalArchivingContinuity \
  --install-dir="$INSTALL_DIR" -v
```

### B.4 What each staged scenario checks

| Scenario dir | Setup | Verify | Validates |
|--------------|-------|--------|-----------|
| `single/` | 500-row `tde_heap`, WAL enc on | `ALTER EXTENSION`, row digests, new INSERT | Core 18.4.1→18.4.2 path |
| `single_pg2381/` | Drop/recreate + `VACUUM FULL` churn | Same + post-churn query | PG-2381 smgr key migration |
| `ha/` | Primary + streaming standby | Both nodes after package bump | HA / rolling-upgrade safety |

### B.5 When `ALTER EXTENSION` is a no-op

If 18.4.1 and 18.4.2 ship the **same** `pg_tde.control` `default_version` (e.g. both
`2.2`), Verify still passes: data, keys, and WAL settings must match
`upgrade_state.json`; `ALTER EXTENSION pg_tde UPDATE` is idempotent.

Confirm:

```bash
psql -c "SELECT extversion FROM pg_extension WHERE extname='pg_tde';"
psql -c "SELECT pg_tde_version();"
```

---

## Combined local checklist

Use this to run the local major pytest suites **and** the 18.4.1→18.4.2 bump on one VM.

| # | Track | Action | Pass criterion |
|---|-------|--------|----------------|
| 1 | Major | `pytest -m upgrade tests/test_tde_pg_upgrade.py` | All tests pass (minus expected skips for your control-version pair) |
| 2 | Major | `run_major_upgrade_workflow.sh` (optional VM smoke) | Debian or pytest method completes verify |
| 3 | Minor | `run_minor_upgrade_workflow.sh` 18.4.1→18.4.2 | Setup + Verify green |
| 4 | Minor | `--with-pg2381` | PG-2381 churn scenario green (needs pg_tde with PR #582) |
| 5 | Minor | Non-staged HA/ALTER EXTENSION tests | All pass on 18.4.2 |

---

## Environment notes

| Item | Major (17→18) | Minor (18.4.1→18.4.2) |
|------|---------------|------------------------|
| Flags | `--old-install-dir` + `--install-dir` | `--upgrade-data-dir` (staged) |
| Persistent data | Ephemeral pytest temp dirs; optional `/var/lib/pg_tde_major_upgrade` | `/var/lib/pg_tde_minor_upgrade` |
| Skip section | `--skip-sections=upgrade` | `--skip-sections=minor_upgrade` |
| io_uring | `--io-method=io_uring` only when build + host allow | same |

---

## Related files

| Path | Role |
|------|------|
| `run_minor_upgrade_workflow.sh` | 18.4.1→18.4.2 staged driver (section B.1) |
| `run_major_upgrade_workflow.sh` | PG 17→18 staged driver |
| `docs/upgrade_matrix.md` | Full test catalog |
| `docs/minor_upgrade.md` | Minor upgrade runbook |
| `docs/major_upgrade.md` | Major upgrade runbook |
