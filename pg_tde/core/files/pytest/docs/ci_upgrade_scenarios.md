# CI upgrade scenarios — `tde-upgrade-parallel` + 18.4.1 → 18.4.2

Runbook for matching Percona Jenkins job
[`tde-upgrade-parallel`](https://pg.cd.percona.com/job/tde-upgrade-parallel/)
and the in-place **18.4.1 → 18.4.2** patch bump.

Full pytest catalog: [`upgrade_matrix.md`](upgrade_matrix.md).

---

## Two upgrade types in this doc

| Track | Jenkins-style name | PostgreSQL | Data dir | Tooling in this repo |
|-------|-------------------|------------|----------|----------------------|
| **A — Major parallel** | `tde-upgrade-parallel` | Different major (typ. **17 → 18**) | New cluster via `pg_tde_upgrade` | `tests/test_tde_pg_upgrade.py` |
| **B — Minor patch** | (same job or separate minor job) | Same major (**18 → 18**) | **Same** `$PGDATA` | `run_minor_upgrade_workflow.sh` + `tests/test_tde_minor_upgrade.py` |

---

## A. `tde-upgrade-parallel` (major upgrade matrix)

The Jenkins job runs a parallel matrix of major-upgrade bash scripts that are not
part of this repo. The pytest suite here covers the same scenarios; see
[`upgrade_matrix.md`](upgrade_matrix.md) for the per-class breakdown.

### A.1 Pytest run

Single command covering the major TDE regression:

```bash
cd pg_tde/core/files/pytest && source .env.sh

export OLD_INSTALL_DIR=/home/ubuntu/pgwork/pginst/17   # adjust
export INSTALL_DIR=/home/ubuntu/pgwork/pginst/18

pytest -m upgrade \
  --old-install-dir="$OLD_INSTALL_DIR" \
  --install-dir="$INSTALL_DIR" \
  tests/test_tde_pg_upgrade.py \
  -v --tb=short
```

### A.2 Version-specific subsets

| Old / new pg_tde.control | Run these classes | Skip reason for others |
|--------------------------|-------------------|------------------------|
| **2.1 → 2.2** (cross-minor) | `TestPg2381EmptyKeyMigration`, `TestPg2379MultiDbKeyMigration` + all other major classes | `TestPg2381MajorUpgradeSamePgTdeControl` skips |
| **2.2 → 2.2** (same control, e.g. PG17 2.2.0 → PG18 2.2.1) | `TestPg2381MajorUpgradeSamePgTdeControl`, `TestTdeMajorUpgradeBasics`, … | `TestPg2381EmptyKeyMigration`, `TestPg2379MultiDbKeyMigration` skip |

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

This is **not** `pg_upgrade` / `pg_tde_upgrade` and **not** `tests/test_tde_pg_upgrade.py`.

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

Single-install HA checks (no binaries change, marked `replication`); run after packages are on 18.4.2, no `--upgrade-data-dir`:

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

## Combined CI checklist

Use this when reproducing the Jenkins job **and** the 18.4.1→18.4.2 bump on one VM.

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
