# pg_tde upgrade test matrix

Complete catalog of **major** (PostgreSQL `pg_upgrade` / `pg_tde_upgrade`) and **minor**
(in-place pg_tde package bump on the same PG major) tests in this repository.

Related runbooks:

| Topic | Document | Workflow script |
|-------|----------|-----------------|
| Major PG 17→18 + `pg_tde_upgrade` | [`major_upgrade.md`](major_upgrade.md) | `run_major_upgrade_workflow.sh` |
| In-place bump (e.g. **18.4.1 → 18.4.2**) | [`minor_upgrade.md`](minor_upgrade.md) | `run_minor_upgrade_workflow.sh` |
| Jenkins `tde-upgrade-parallel` CI | [`ci_upgrade_scenarios.md`](ci_upgrade_scenarios.md) | `pytest -m upgrade` |
| Skip whole areas | [`test_sections.md`](test_sections.md) | `--skip-sections=upgrade` / `minor_upgrade` |

---

## Definitions

| | **Major upgrade** | **Minor upgrade** |
|--|-------------------|-------------------|
| PostgreSQL | Different major (e.g. 17 → 18) | **Same** major (e.g. both 17, or 18.3 → 18.4) |
| Data directory | **New** cluster via `pg_upgrade` / `pg_tde_upgrade` | **Same** `$PGDATA` |
| Operator action | Install new PG major; run `pg_tde_upgrade` when TDE data exists | Replace pg_tde packages; `ALTER EXTENSION pg_tde UPDATE` |
| Typical pg_tde path | 2.1 on PG17 → 2.2 on PG18 | 2.1.x → 2.2.x on `/usr/lib/postgresql/17` |
| Pytest marker | `upgrade` | `minor_upgrade` (staged Setup/Verify only) |
| Required flags | `--old-install-dir` + `--install-dir` | `--upgrade-data-dir` (staged) or two install trees (one-shot) |

**Do not confuse:**

- `TestPg2379MultiDbKeyMigration::test_in_place_package_upgrade_multidb_distinct_keys` — minor bump helper living in `test_tde_pg_upgrade.py` (same PG major, different install dirs).

---

## Version / skip matrix

Many tests gate on `pg_tde.control` `default_version` on old vs new install trees.

| Install pairing | Active test classes | Skipped classes |
|-----------------|---------------------|-----------------|
| PG17 pg_tde **2.1** → PG18 pg_tde **2.2** | `TestPg2381EmptyKeyMigration`, `TestPg2379MultiDbKeyMigration` | `TestPg2381MajorUpgradeSamePgTdeControl` |
| PG17 pg_tde **2.2** → PG18 pg_tde **2.2** (same control) | `TestPg2381MajorUpgradeSamePgTdeControl`, all other major tests | `TestPg2381EmptyKeyMigration`, `TestPg2379MultiDbKeyMigration` (need cross-minor) |
| Same PG major, pg_tde 2.1 → 2.2 (in-place) | `test_tde_minor_upgrade.py` staged tests | Major-only PG-2381 / PG-2379 classes |
| Missing `--old-install-dir` | — | All `upgrade`-marked tests skip |
| Missing `--upgrade-data-dir` | Non-staged minor tests still run | Staged Setup/Verify minor tests skip |

PG-2381 (empty smgr key files after churn) fix: [percona/pg_tde#582](https://github.com/percona/pg_tde/pull/582).  
PG-2379 (per-DB principal keys during migration) fix: [percona/pg_tde#581](https://github.com/percona/pg_tde/pull/581).

---

## Pytest inventory (106 tests)

Collected with default `io=worker` parametrization. Use `--io-method-matrix` to multiply by `sync` / `worker` / `io_uring` where supported.

### Quick run commands

```bash
cd postgresql/pytest && source .env.sh

# Major — full TDE regression
pytest -m upgrade \
  --old-install-dir=/path/to/pg17 \
  --install-dir=/path/to/pg18 \
  tests/test_tde_pg_upgrade.py -v

# Major — TDE only
pytest -m upgrade --old-install-dir=... --install-dir=... \
  tests/test_tde_pg_upgrade.py -v

# Minor — staged (after Setup + package swap)
pytest -m minor_upgrade \
  --install-dir=/path/to/pg \
  --upgrade-data-dir=/var/lib/pg_tde_minor_upgrade \
  tests/test_tde_minor_upgrade.py -v

# Single-install HA checks in the minor file (no binaries change; marker replication)
pytest tests/test_tde_minor_upgrade.py::TestAlterExtensionUpdate -v --install-dir=...

# Skip
pytest tests/ --skip-sections=upgrade,minor_upgrade -v
```

---

## Major upgrade — `tests/test_tde_pg_upgrade.py` (52 tests)

Marker: `upgrade`, `slow`. Requires `--old-install-dir` and `--install-dir` (different PG majors).

Always uses `pg_tde_upgrade` when the source cluster has pg_tde key material (plain `pg_upgrade` is not supported on encrypted clusters). After start, every `tde_heap` relation, index and TOAST table in every database must still report `pg_tde_is_encrypted`, then `ALTER EXTENSION pg_tde UPDATE` runs.

### `TestTdeMajorUpgradeBasics` (5)

| Test | Validates |
|------|-----------|
| `test_tde_heap_data_survives` | Row digest identical after `pg_tde_upgrade`; table still `tde_heap` |
| `test_alter_extension_update_after_upgrade` | `extversion` reaches the new `default_version`; second UPDATE is a no-op |
| `test_multiple_databases_different_keys` | Per-database principal keys; digests identical |
| `test_check_mode_with_tde_configured` | `pg_tde_upgrade --check` passes with pg_tde loaded |
| `test_key_provider_and_keys_preserved` | Providers (name/type/options), server and database keys unchanged; new tables encrypted |

**Bash parity:** `pg_tde_upgrade_ppg_to_psp.sh`, `pg_tde_upgrade_psp_to_psp.sh`

### `TestUpgradeAccessMethodPermutations` — heap ↔ tde_heap (5)

| Test | Validates |
|------|-----------|
| `test_all_heap_baseline` | Plain heap only; no pg_tde involvement |
| `test_all_tde_heap_pg2240_fix` | All `tde_heap`; PG-2240 core path |
| `test_mixed_heap_and_tde_heap` | Mixed access methods coexist post-upgrade |
| `test_heap_enable_tde_after_upgrade` | Plain upgrade, enable TDE on new cluster |
| `test_tde_heap_convert_to_heap_before_upgrade` | Convert to heap before upgrade; no `pg_tde/` copy |

**Bash parity:** `postgresql/automation/tests/pg_tde_upgrade_access_method.sh` (5 scenarios)

### `TestUpgradeWalEncryptionPaths` — WAL encryption modes (4)

| Test | Validates |
|------|-----------|
| `test_wal_enc_off_to_off` | WAL enc off throughout |
| `test_wal_enc_on_to_off` | Enable in old; disable before upgrade |
| `test_wal_enc_on_to_reenable` | Upgrade with WAL enc off; re-enable on new |
| `test_check_mode_with_wal_enc_on` | `--check` with WAL encryption active |

**Bash parity:** `postgresql/automation/tests/pg_tde_upgrade_wal_encryption.sh` (4 paths)

### `TestPgTdeUpgradePitrWithEncryptedWal` (1)

| Test | Validates |
|------|-----------|
| `test_pitr_after_pg_tde_upgrade_with_encrypted_wal` | PITR after major upgrade: `pg_tde_archive_decrypt` / `pg_tde_restore_encrypt`, base backup, recovery target time |

### `TestUpgradeEnforceEncryption` (1)

| Test | Validates |
|------|-----------|
| `test_upgrade_with_enforce_encryption_active` | `pg_tde.enforce_encryption=on` does not corrupt legacy `heap` tables during schema restore |

### `TestPgTdeUpgradeModes` — link / clone / parallel (3)

| Test | Validates |
|------|-----------|
| `test_pg_tde_upgrade_link_mode` | `--link` upgrade mode |
| `test_pg_tde_upgrade_clone_mode` | Clone mode (no link) |
| `test_pg_tde_upgrade_parallel_jobs` | Parallel `-j` jobs |

### `TestPgTdeUpgradeComplexSchema` (6)

| Test | Validates |
|------|-----------|
| `test_pg_tde_upgrade_partitioned_tde_heap` | Range-partitioned `tde_heap` |
| `test_pg_tde_upgrade_foreign_key_cascade_on_tde_heap` | FK cascade on encrypted tables |
| `test_pg_tde_upgrade_indexes_on_tde_heap` | B-tree, partial, expression indexes |
| `test_pg_tde_upgrade_with_multiple_key_providers` | Multiple global providers |
| `test_pg_tde_upgrade_views_sequences_checks_partial_indexes` | Views, sequences, CHECK constraints |
| `test_pg_tde_upgrade_explicit_global_key_provider_migration` | Explicit global provider migration |

**Bash parity (partial):** `postgresql/automation/tests/pg_tde_upgrade_scenarios_test.sh` (7 scenarios)

### `TestUpgradeBashScriptParity` (2)

| Test | Validates | Bash source |
|------|-----------|-------------|
| `test_upgrade_database_key_provider_and_partitions` | DB-level key provider + partitioned tables | `upgrade_testing/tests/pg_tde_upgrade_basic_test.sh` |
| `test_upgrade_with_wal_encryption_left_on` | Upgrade with `pg_tde.wal_encrypt=ON` during upgrade | `upgrade_testing/tests/pg_tde_upgrade_wal_encryption.sh` |

### `TestPgTdeUpgradeRefusalsAndConfig` (7)

| Test | Validates |
|------|-----------|
| `test_wal_encrypt_setting_not_carried_over` | `pg_tde.wal_encrypt` (auto.conf) is not migrated; data readable |
| `test_refuses_checksum_mismatch` | `--check` refuses checksums on → off |
| `test_refuses_running_old_cluster_and_leaves_it_intact` | Full run refused; old encrypted data intact |
| `test_refuses_non_empty_target` | `--check` refuses a target with user tables |
| `test_refuses_unclean_shutdown` | Crashed cluster with encrypted WAL refused; recovery replays it |
| `test_pg_tde_installed_no_encrypted_tables` | Keys carried over without encrypted tables; new tables encrypt |
| `test_inheritance_on_tde_heap` | INHERITS hierarchy on tde_heap |

### `TestTdeUpgradeExtremeCornerCases` (5)

| Test | Validates |
|------|-----------|
| `test_upgrade_massive_toast_data` | Large TOAST payloads in `tde_heap` |
| `test_upgrade_key_rotation_history` | Key rotation history preserved |
| `test_upgrade_unlogged_tde_heap` | `UNLOGGED` `tde_heap` tables |
| `test_upgrade_extension_in_custom_schema` | Extension in non-`public` schema |
| `test_upgrade_dropped_and_recreated_tables` | Drop/recreate churn before upgrade |

### `TestPg2381EmptyKeyMigration` — needs pg_tde 2.1→2.2 cross-minor (4)

| Test | Validates |
|------|-----------|
| `test_major_upgrade_after_vacuum_full_empty_key_file` | `VACUUM FULL` → zero-byte `*_keys` files |
| `test_major_upgrade_after_drop_table_empty_key_slot` | `DROP TABLE` → empty smgr key slots |
| `test_major_upgrade_combined_churn_matches_ghost_repro` | Drop/recreate + `VACUUM FULL` (ghost relfilenode) |
| `test_inplace_same_datadir_startup_after_churn` | Same-datadir startup after churn (no full pg_upgrade) |

**Repro scripts:** `postgresql/bugs/pg_tde_upgrade_issue.sh`, `pg_tde_ghost_relfilenode_upgrade_repro.sh`

### `TestPg2381MajorUpgradeSamePgTdeControl` — needs same `pg_tde.control` on both majors (3)

| Test | Validates |
|------|-----------|
| `test_major_upgrade_ghost_repro_same_pg_tde_control` | Ghost churn when both installs are pg_tde 2.2 |
| `test_major_upgrade_vacuum_full_same_pg_tde_control` | `VACUUM FULL` empty key file path |
| `test_major_upgrade_drop_table_same_pg_tde_control` | `DROP TABLE` empty slot path |

Use when PG17 and PG18 both ship `pg_tde.control` **2.2** (e.g. 2.2.0 vs 2.2.1 patch).

### `TestPg2379MultiDbKeyMigration` — needs pg_tde 2.1→2.2 cross-minor (6)

| Test | Validates |
|------|-----------|
| `test_three_databases_three_keys_major_upgrade` | Three DBs, three principal keys |
| `test_alter_extension_order_postgres_first_then_secondary` | `ALTER EXTENSION` order: postgres → db_b |
| `test_alter_extension_order_secondary_first_then_postgres` | `ALTER EXTENSION` order: db_b → postgres |
| `test_same_principal_key_on_two_databases` | Shared principal key across DBs |
| `test_extension_only_database_without_tde_tables` | Extension present, no `tde_heap` tables |
| `test_in_place_package_upgrade_multidb_distinct_keys` | **Minor** one-shot: same PG major, two install dirs, no `--upgrade-data-dir` |

---

## Minor upgrade — `tests/test_tde_minor_upgrade.py` (11 tests)

### Staged workflow (marker: `minor_upgrade`)

Requires `--upgrade-data-dir` / `PG_TDE_UPGRADE_DATA_DIR`. Two pytest invocations separated by an operator package swap.

| Scenario dir | Setup test | Verify test | What it exercises |
|--------------|------------|-------------|-------------------|
| `single/` | `TestPgTdeMinorUpgradeSetup::test_prepare_persistent_state_for_minor_upgrade` | `TestPgTdeMinorUpgradeVerify::test_minor_upgrade_verification_flow` | 500-row `tde_heap`, WAL enc on, checksums in `upgrade_state.json`, `ALTER EXTENSION` |
| `single_pg2381/` | `TestPg2381MinorUpgradeSetup::test_prepare_pg2381_churn_for_minor_upgrade` | `TestPg2381MinorUpgradeVerify::test_verify_pg2381_churn_after_minor_upgrade` | Drop/recreate + `VACUUM FULL` churn (PG-2381 / PR 582) |
| `ha/` | `TestPgTdeMinorUpgradeSetupHA::test_prepare_persistent_ha_state_for_minor_upgrade` | `TestPgTdeMinorUpgradeVerifyHA::test_ha_minor_upgrade_verification_flow` | Primary + streaming standby; package bump on shared persistent PGDATA |

**Workflow:** `run_minor_upgrade_workflow.sh` (default PG 18.3 → 18.4; `--with-pg2381` for churn scenario).

### Non-staged (single pytest run, `tmp_path`)

Run on the **target** pg_tde build; no `--upgrade-data-dir`. No binaries change here: these are HA pre-condition checks, marked `replication` (not `minor_upgrade`).

| Class | Tests | Purpose |
|-------|-------|---------|
| `TestTdeMinorUpgradePreConditions` | `test_catalog_version_vs_binary_version`, `test_wal_encryption_active_on_both_nodes` | Catalog `extversion` vs `pg_tde_version()`; WAL enc on HA pair |
| `TestAlterExtensionUpdate` | `test_alter_extension_update_safety_and_idempotency` | `ALTER EXTENSION` idempotent; keys and data preserved |
| `TestRollingRestart` | `test_rolling_restart_preserves_cluster_state` | Patroni-style rolling restart order |
| `TestWalArchivingContinuity` | `test_pitr_from_archive_works_after_rolling_restart` | PITR from archive after rolling restart |

---

## Bash / automation matrix (non-pytest)

### `postgresql/automation/tests/`

| Script | Type | Scenarios |
|--------|------|-----------|
| `pg_tde_upgrade_test.sh` | Major | Single DB key provider + encrypted + partitioned tables; manual `pg_tde/` copy note (PG-2240) |
| `pg_tde_upgrade_ppg_to_psp.sh` | Major | 4: data intact, ALTER EXTENSION, multi-DB, `--check` |
| `pg_tde_upgrade_psp_to_psp.sh` | Major | 2+: data survives, multi-DB different keys |
| `pg_tde_upgrade_access_method.sh` | Major | 5 heap↔tde_heap permutations |
| `pg_tde_upgrade_wal_encryption.sh` | Major | 4 WAL enc paths |
| `pg_tde_upgrade_scenarios_test.sh` | Major | 7: multi-DB, mixed AM+FK, complex schema, TOAST, partitions, global provider, `--check` |

Run via `test_runner.sh` with `--server_build_path` and `--old_server_build_path`.

### `postgresql/upgrade_testing/tests/`

| Script | Type | Notes |
|--------|------|-------|
| `pg_tde_upgrade_basic_test.sh` | Major | DB-level provider + partitions; uses `pg_tde_upgrade` wrapper |
| `pg_tde_upgrade_wal_encryption.sh` | Major | Global provider + WAL enc on during upgrade |

Invoked through `upgrade_testing/wrapper/pg_tde_upgrade_runner.sh`.

### `postgresql/bugs/` (manual repros, not CI gates)

| Script | Purpose |
|--------|---------|
| `pg_tde_major_upgrade_plain_pg_upgrade_repro.sh` | Why plain `pg_upgrade` fails with TDE |
| `pg_tde_upgrade_issue.sh` | PG-2381 decrypt failure repro |
| `pg_tde_ghost_relfilenode_upgrade_repro.sh` | Ghost relfilenode + upgrade |
| `pg_tde_upgrade_21_to_22_decrypt_repro.sh` | 2.1→2.2 decrypt repro |

---

## Staged VM workflows

### Major — `run_major_upgrade_workflow.sh`

| Phase | `--setup-only` | `--upgrade-only` | `--verify-only` |
|-------|----------------|------------------|-----------------|
| Install PG17 + pg_tde | ✓ | | |
| Populate source cluster / state | ✓ | | |
| Install PG18 + pg_tde | | ✓ | |
| `pg_tde_upgrade` | | ✓ | |
| Start, `ALTER EXTENSION`, `vacuumdb`, row check | | | ✓ |

Methods: `pytest` (smoke via `TestTdeMajorUpgradeBasics`), `debian` (`initdb` under `/var/lib/postgresql/pg_tde_major_upgrade/`), `auto`.

### Minor — `run_minor_upgrade_workflow.sh`

| Phase | Action |
|-------|--------|
| 1 | Install old pg_tde (`OLD_PG_MAJOR`, default **18.4.1**) |
| 2 | `TestPgTdeMinorUpgradeSetup` (+ optional HA, PG-2381) |
| 3 | Install new pg_tde (`NEW_PG_MAJOR`, default **18.4.2**) |
| 4 | `TestPgTdeMinorUpgradeVerify` (+ optional HA, PG-2381) |

---

## Choosing the right suite

| Your environment | Run |
|------------------|-----|
| PG17 packages + PG18 source tree; both pg_tde control **2.2** | Major: `TestTdeMajorUpgradeBasics`, `TestPg2381MajorUpgradeSamePgTdeControl`, `run_major_upgrade_workflow.sh` |
| PG17 pg_tde 2.1 → PG18 pg_tde 2.2 | Major: `TestPg2381EmptyKeyMigration`, `TestPg2379MultiDbKeyMigration` |
| Same PG major, package bump 2.1→2.2 | Minor: `run_minor_upgrade_workflow.sh` or staged Setup/Verify |
| Two dev trees, same PG major, different pg_tde control | `test_in_place_package_upgrade_multidb_distinct_keys` |
| No second install tree | Minor non-staged tests only; major tests skip |

---

## Cross-reference: pytest ↔ bash

| Pytest class / test | Bash / TAP parity |
|---------------------|-------------------|
| `TestTdeMajorUpgradeBasics` | `pg_tde_upgrade_ppg_to_psp.sh`, `pg_tde_upgrade_psp_to_psp.sh` |
| `TestUpgradeAccessMethodPermutations` | `pg_tde_upgrade_access_method.sh` |
| `TestUpgradeWalEncryptionPaths` | `pg_tde_upgrade_wal_encryption.sh` (automation) |
| `TestPgTdeUpgradeComplexSchema` | `pg_tde_upgrade_scenarios_test.sh` (partial) |
| `TestUpgradeBashScriptParity` | `upgrade_testing/tests/pg_tde_upgrade_*.sh` |
| `TestPgTdeUpgradePitrWithEncryptedWal` | `pg_tde_upgrade_pitr_test.sh` (automation, if present) |
| Staged minor Setup/Verify | No single bash script — operator package swap is the gap pytest models |

---

## File index

| Path | Role |
|------|------|
| `tests/test_tde_pg_upgrade.py` | Deep `pg_tde_upgrade` regression (52 tests) |
| `tests/test_tde_minor_upgrade.py` | In-place pg_tde bump (11 tests) |
| `run_major_upgrade_workflow.sh` | Staged major upgrade driver |
| `run_minor_upgrade_workflow.sh` | Staged minor upgrade driver (default **18.4.1 → 18.4.2**) |
| `docs/ci_upgrade_scenarios.md` | CI runbook: Jenkins job + 18.4.1→18.4.2 |
| `docs/major_upgrade.md` | Major upgrade runbook |
| `docs/minor_upgrade.md` | Minor upgrade runbook |
| `docs/upgrade_matrix.md` | This document |
