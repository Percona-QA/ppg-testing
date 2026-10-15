# PPG package tests

These tests install Percona Distribution for PostgreSQL (PPG) packages on a fresh VM and check that they work.

They cover PostgreSQL 14 to 18 and Percona Server for PostgreSQL 16 (PSP 16).

Tarball tests are separate, see [pg-tarballs/](pg-tarballs/).

---

## Jenkins jobs

| Job | What it runs | OSes |
|---|---|---|
| `ppg` | One scenario on one OS | The OS chosen in `PLATFORM` |
| `ppg-multiOS-parallel` | One scenario on many OSes at once | All OSes, or the ones listed in `PLATFORMS` |
| `ppg-upgrade-parallel` | One upgrade scenario on many OSes at once | Always all OSes |

Pipeline files are in [jenkins-pipelines/ppg](https://github.com/Percona-Lab/jenkins-pipelines/tree/master/ppg).

The `SCENARIO` parameter picks which test runs.

---

## Scenarios

Each PostgreSQL version has the same set of scenarios. Replace `NN` with `14`, `15`, `16`, `17` or `18`.

| Scenario | What it tests | Job |
|---|---|---|
| `pg-NN` | Full install: server, extensions and tools | `ppg`, `ppg-multiOS-parallel` |
| `pg-NN-meta-server` | The `percona-ppg-server` meta package | `ppg`, `ppg-multiOS-parallel` |
| `pg-NN-meta-ha` | The `percona-ppg-server-ha` meta package | `ppg`, `ppg-multiOS-parallel` |
| `pg-NN-minor-upgrade` | Upgrade to a newer minor version, e.g. 17.10 → 17.11 | `ppg-upgrade-parallel` |
| `pg-NN-major-upgrade` | `pg_upgrade` from the previous major, e.g. 16 → 17 | `ppg-upgrade-parallel` |

PSP 16 has the same five scenarios, named `psp-16`, `psp-16-meta-server`, and so on.

### `pg-NN`: full install

Installs:
- the PostgreSQL server and client packages
- the extensions and tools shipped with PPG, such as pgaudit, pgBackRest, Patroni, pg_stat_monitor and PostGIS

It also sets up a small Patroni cluster with etcd and HAProxy.

The tests check that:
- every package is installed, with the expected version
- the server starts, stops and restarts
- every extension can be created and dropped
- each tool works, e.g. a pgBackRest backup and restore, and the Patroni cluster has one leader

Tests: [tests/tests_ppg/](tests/tests_ppg/). PSP 16 uses [tests/tests_psp/](tests/tests_psp/), which adds pg_tde checks.

### `pg-NN-meta-server`

Installs only the server meta package.

The tests check that it pulled in the server, contrib, pg_stat_monitor, pgaudit, pg_repack and wal2json packages.

Tests: [tests/tests_meta_server/](tests/tests_meta_server/)

### `pg-NN-meta-ha`

Installs only the HA meta package.

The tests check that Patroni, etcd and HAProxy are installed with the expected versions. The HA stack is installed but not started.

Tests: [tests/tests_meta_ha/](tests/tests_meta_ha/)

### `pg-NN-minor-upgrade`

1. Install the old version (`FROM_VERSION`) and start the server.
2. Load test data.
3. Switch to the new version's repo and update the packages to `VERSION`.
4. Restart the server.

The tests check that the packages are now at `VERSION` and that the test data is unchanged.

### `pg-NN-major-upgrade`

1. Install the previous major (`FROM_VERSION`) and start the server.
2. Load test data.
3. Install the new major (`VERSION`).
4. Run `pg_upgrade` from the old cluster to the new one.
5. Start the new server.

The tests check that the packages are now at `VERSION` and that the test data is unchanged.

Both upgrade scenarios run only the tests marked `upgrade`.

---

## How a run works

1. Jenkins checks out this repo (branch `TESTING_BRANCH`).
2. It creates one AWS VM per OS.
3. **Prepare:** basic OS setup. Only the parallel jobs run this step.
4. **Converge:** enable the package repo and install packages, as described for the scenario.
5. **Verify:** run the tests.
6. **Cleanup:** uninstall the packages. Major upgrades remove only the old version's packages, and minor upgrades skip this step.
7. **Destroy:** delete the VMs.
   - The parallel jobs always destroy them.
   - `ppg` keeps the VM if `DESTROY_ENV` is unticked, which is useful for debugging.

The parallel jobs post the result to the `#postgresql-test` Slack channel.

---

## Jenkins parameters

| Parameter | Default | Used by | What it does |
|---|---|---|---|
| `SCENARIO` | first in list | all | Which scenario to run (see above) |
| `VERSION` | `ppg-18.4` | all | Version to test, e.g. `ppg-17.11` or `psp-16.15`. For upgrades, the version to upgrade **to** |
| `FROM_VERSION` | `ppg-18.3` | upgrade | Version to upgrade **from** |
| `REPO` | `testing` | `ppg`, multiOS | Repo channel: `testing`, `release` or `experimental` |
| `FROM_REPO` / `TO_REPO` | `testing` | upgrade | Repo channel for the old and new version |
| `MAJOR_REPO` | off | `ppg`, multiOS | Use the major repo (`ppg-17`) instead of the minor repo (`ppg-17.11`) |
| `IO_METHOD` | `worker` | `ppg`, multiOS | PostgreSQL 18 only: `worker`, `sync` or `io_uring` |
| `PLATFORM` | `debian-12` | `ppg` | The OS to test |
| `PLATFORMS` | empty (all) | multiOS | OSes to test, separated by spaces, e.g. `rocky-9 debian-13` |
| `DESTROY_ENV` | on | `ppg` | Delete the VM after the run |
| `TESTING_BRANCH` | `main` | all | Branch of this repo to use |
| `USE_OBS_REPO` | off | multiOS, upgrade | Install from OBS instead of repo.percona.com |
| `OBS_PROJECT` | empty | multiOS, upgrade | Exact OBS project, e.g. `isv:percona:PR:pr-42:ppg:staging:18` |
| `OBS_HOST` | empty | multiOS, upgrade | OBS download server. Empty means `download.opensuse.org` |
| `EXPECTED_VERSIONS` | empty | multiOS, upgrade | Override the expected package versions, one `package=version` per line |
| `RUN_LABELS` | `Manual` | multiOS, upgrade | A label for the run. Not used by the tests |

### Installing from OBS

When `USE_OBS_REPO` is ticked, the OBS project is built from `REPO` and `VERSION`:

| `REPO` | OBS project for `VERSION=ppg-17.11` |
|---|---|
| `testing` | `isv:percona:ppg:staging:17` |
| `release` | `isv:percona:ppg:releases:17` |
| `experimental` | `isv:percona:ppg:devel:17` |

PSP 16 adds `:tde` to the project name, e.g. `isv:percona:ppg:staging:16:tde`.

If `OBS_PROJECT` is set, it is used as is.

For upgrades, only the new version comes from OBS. The old version always comes from repo.percona.com.

### Examples

Test PPG 17.11 from the testing repo on all OSes:

```
Job:       ppg-multiOS-parallel
SCENARIO:  pg-17
VERSION:   ppg-17.11
REPO:      testing
```

Test a 16 → 17 major upgrade:

```
Job:           ppg-upgrade-parallel
SCENARIO:      pg-17-major-upgrade
FROM_VERSION:  ppg-16.15
FROM_REPO:     release
VERSION:       ppg-17.11
TO_REPO:       testing
```

---

## Operating systems

All jobs use the same list of 28 OSes, each on x86_64 and ARM:

Debian 12, 13 · Oracle Linux 8, 9, 10 · RHEL 8, 9, 10 · Rocky 8, 9, 10 · Ubuntu 22.04 (jammy), 24.04 (noble), 26.04 (resolute)

The list is in [catalog/os-lists.yml](../catalog/os-lists.yml) (`all`).

---

## Running locally

See [local/README.md](../local/README.md) for setup.

```bash
task ppg SCENARIO=pg-17 OS=rocky-9 -- --param VERSION=ppg-17.11
```

---

## Where things are

| Path | What it is |
|---|---|
| [versions.yml](versions.yml) | Versions and settings for each scenario |
| [tests/](tests/) | The tests |
| [tests/versions/](tests/versions/) | Expected package versions for each release |
| [../templates/groups/](../templates/groups/) | Templates the scenario folders are made from |

The scenario folders (`pg-17/`, `pg-17-major-upgrade/`, …) are not in git. [tools/gen_groups.py](../tools/gen_groups.py) creates them from `versions.yml` and the templates, and Jenkins does this automatically at the start of each run.

To change a scenario, edit `versions.yml` or the templates, not the generated folders.

---

## Adding a new PostgreSQL version (example: PG 19)

You don't create the `pg-19*` folders by hand. Once `versions.yml` has a `pg-19` entry, all five scenarios are generated from it.

### 1. Add `pg-19` to `versions.yml`

Copy the `pg-18` block in [versions.yml](versions.yml), rename it to `pg-19`, and update:

| Field | Set it to |
|---|---|
| `major` | `19` |
| `default_version` | The newest 19 release, e.g. `ppg-19.1` |
| `minor-upgrade` → `default_from_version` | An older 19 release, e.g. `ppg-19.0` |
| `major-upgrade` → `default_from_version` | The same value as `pg-18`'s `default_version` |
| `gates` and other settings | Review them; they hold version-specific rules |

`minor-upgrade` needs an older 19 release to upgrade from. Until a second 19 release exists, there is nothing to upgrade from, so leave `pg-19-minor-upgrade` out of Jenkins (step 6).

### 2. Add the expected versions for the tests

The tests compare installed packages against these files:

- [tests/versions/ppg.py](tests/versions/ppg.py):
  - add a `get_pg19_versions()` function, copied from `get_pg18_versions()` with `18` changed to `19`;
  - add an entry for each 19 release, e.g. `"ppg-19.1"`.
- Every other file in [tests/versions/](tests/versions/), such as `pgbackrest.py` and `patroni.py`: add the 19 release with that component's version. Use the same key style as the existing entries; some files use `"ppg-18.6"` and others `"18.6"`.
- [tests/settings.py](tests/settings.py): add a `"ppg-19.1"` block, copied from the latest `"ppg-18.x"` block. In the copy, change every 18 value, not only the `"18.6"` keys:

  | Field | Example for 19.1 |
  |---|---|
  | `version` | `19.1` |
  | `percona-version` | `19.1.1` |
  | `libpq_version` and `libpq` | `190001` |
  | `pgrepack_package_rpm` / `_deb` | `percona-pg_repack19` / `percona-postgresql-19-repack` |
  | `percona-postgresql-common` / `client-common` | The version shipped with 19.1 |

### 3. Check the tests for version-specific rules

Some tests have rules or tables per major version, e.g. `elif major == 18:`, or a table with one line each for 14 to 18. Find them by searching for `18`:

```bash
grep -nE "\b18:|== *18\b|\"18\"|\(17, 18\)" ppg/tests/tests_ppg/*.py ppg/tests/tests_meta_*/*.py ppg/tests/settings.py
```

For each hit, decide whether 19 needs the same rule, and add a `19` line or case where it does.

A missing `19` doesn't make anything fail. The check is silently skipped or behaves as for older versions. For example, `test_build_with_liburing` runs only when the version is exactly 18. So review every hit; a green run doesn't prove these are right.

### 4. Update the generator's tests

[tools/tests/test_gen_groups.py](../tools/tests/test_gen_groups.py) hard-codes the number of versions, so it fails until you update it:

- `test_expected_group_names`: change `len(names) == 30` to `35` (5 more scenarios).
- `test_shared_tasks_render`: change `range(14, 19)` to `range(14, 20)`.

### 5. Check that it works

```bash
python3 tools/gen_groups.py --list | grep pg-19
```

```bash
pytest tools/tests
```

The first command should list the five `pg-19` scenarios. The second checks `versions.yml` and the generated files. Run both with the repo's Python environment (`task venv` creates it in `.venv`), which has the modules they need.

Then run one scenario locally:

```bash
task ppg SCENARIO=pg-19 OS=rocky-9 -- --param VERSION=ppg-19.1
```

### 6. Add the scenarios to Jenkins

In [jenkins-pipelines](https://github.com/Percona-Lab/jenkins-pipelines), add the new names to the `SCENARIO` lists:

- `vars/ppgScenarios.groovy`: `pg-19`, `pg-19-meta-ha`, `pg-19-meta-server`
- `vars/ppgUpgradeScenarios.groovy`: `pg-19-major-upgrade` (and `pg-19-minor-upgrade` once a second 19 release exists)

### What you don't need to change

- **Templates:** the version checks in [templates/groups/](../templates/groups/) use "18 and newer" (`major >= 18`), so 19 follows the 18 rules. Edit them only if 19 needs different behaviour.
- **`.gitignore`:** it already ignores the generated `pg-19*` folders.
- **OBS repo:** with `USE_OBS_REPO`, the project name is built from `VERSION`, e.g. `isv:percona:ppg:staging:19`.
