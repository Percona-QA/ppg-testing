# Molecule Scenarios Report — `ppg-testing`

## Scope and Layout

The repo contains **54 Molecule "scenario roots"** spread across four top-level areas:

- `ppg/` — core Percona Distribution for PostgreSQL (PPG) install / upgrade / meta-package matrices for PG 13–18
- `docker/` — image-level QA for the official Percona Docker images (server, pgBouncer, pgBackRest)
- `psp/` — full source builds of PostgreSQL/PSP + pg_tde for server regression and pgbench performance comparisons
- one-off extension folders (`pg_audit`, `pg_repack`, `pg_tde/*`, `pg_stat_monitor/*`, `pgvector`, `pgbadger`, `pgbouncer`, `pgbackrest`, `pgpool`, `patroni`, `postgis`, `wal2json`, `pgaudit13_set_user`)

Each "scenario root" expands into a fan of per-platform Molecule sub-scenarios (e.g. [ppg/pg-17/molecule/](ppg/pg-17/molecule/) has 26 OS × arch combinations: Debian 11/12/13, Ubuntu Jammy/Noble, RHEL 8/9/10, Oracle Linux 8/9, Rocky 8/9/10, plus an ARM variant of each). The sub-scenarios share their `playbook.yml` / role / verifier and only differ in AMI, ssh user, vpc subnet, and instance type — so what each scenario *tests* is best described by its role/verifier pair.

All scenarios use the same shape: `dependency: galaxy`, `driver: ${driver}` (injected at runtime, normally EC2), Ansible provisioner pulling shared `create.yml` / `destroy.yml` / `prepare.yml` from [playbooks/](playbooks/), and a per-scenario `converge` playbook. Most use the `testinfra` verifier; a few use the `ansible` verifier (the docker and psp scenarios).

### Install method at a glance

Each scenario installs the software under test in one of three ways:

- **Packages** (`apt` / `yum` from the Percona repo) — the default for the PPG install/upgrade/meta-package matrices, the docker scenarios (which pull pre-built images), and the simpler component scenarios.
- **Source build** — clone upstream sources, `configure`/`make`/`make install`, then exercise the regression suite that ships with that source tree. Used for most extension scenarios and both `psp/` scenarios.
- **Hybrid / configurable** — installs packages but also clones and builds against them (e.g. `pgvector`), or chooses between the two at runtime via env var (`pg_tde/auxiliary` with `BUILD_FROM_SOURCE`, `pg_stat_monitor/*` with `PGSM_PACKAGE_INSTALL`).

The "Install method" column on each scenario below makes this explicit. A consolidated summary lives in [§4](#4-install-method-summary).

---

## 1. Core PPG scenarios under `ppg/`

These exercise the PPG repository, packages, and lifecycle. Verifiers point into [ppg/tests/](ppg/tests/) and are selected per scenario family.

### 1.1 Fresh install of a major version — `pg-13`, `pg-14`, `pg-15`, `pg-16`, `pg-17`, `pg-18`
- **Install method:** packages (Percona repo via `percona-release`).
- Role: `pg-NN` ([ppg/pg-17/tasks/main.yml](ppg/pg-17/tasks/main.yml) is representative).
- Steps: configure Percona repo, install the full PPG package set for major NN (server, client, contrib, plperl/plpython3/pltcl, dbgsym/debuginfo), `initdb`, start service, install PPG tools, verify telemetry, build a small libpq C program (compile-link sanity — note: this builds a *test program*, not the server).
- Verifier: [ppg/tests/tests_ppg/](ppg/tests/tests_ppg/) — `test_bvt.py` (package presence, version of `psql`/`postgres`, service state, `pg_config`, binary list), `test_components.py` (per-package install, libpq build, plperl/pltcl/plpython3 functions), `test_tools.py`.

### 1.2 Minor upgrade — `pg-13-minor-upgrade` … `pg-18-minor-upgrade`
- **Install method:** packages (two repos: `FROM_REPO` then `TO_REPO`).
- Role: `pg-NN-minor-upgrade` ([ppg/pg-17-minor-upgrade/tasks/main.yml](ppg/pg-17-minor-upgrade/tasks/main.yml)).
- Steps: install PPG NN from `FROM_REPO` / `FROM_VERSION`, start, then disable old repo, enable `TO_REPO` / `VERSION`, `apt`/`yum` upgrade, restart, `select version()`. No `pg_upgrade` is run — same major.
- Verifier: same `tests_ppg` set, so the upgraded cluster is re-checked package-by-package and the `psql` client/server versions must reflect `VERSION`.
- Skip guards for unsupported (distro × version) pairs (e.g. RHEL 10 + PG ≤ 16.9, Debian 13 + PG ≤ 17.6).

### 1.3 Major upgrade — `pg-13-major-upgrade` … `pg-18-major-upgrade`
- **Install method:** packages on both sides; the upgrade itself uses `pg_upgrade` against the two installed package trees.
- Role: `pg-NN-major-upgrade` ([ppg/pg-17-major-upgrade/tasks/main.yml](ppg/pg-17-major-upgrade/tasks/main.yml)).
- Steps: install PPG (NN-1) from `FROM_VERSION`, init/start, then enable the new repo, install PPG NN packages, `pg_createcluster` (Debian) / second `initdb` (RHEL), stop both clusters, run `pg_upgrade` against old/new bindirs, swap ports (old → 5433, new → 5432), inject `shared_preload_libraries = 'pg_stat_monitor'`, drop the old cluster, restart, `select version()`.
- Verifier: `tests_ppg` again (the dedicated full-upgrade verifier in `tests/test_full_upgrade/test_upgrade.py` is wired into other jobs, not these scenarios per molecule.yml).

### 1.4 Meta-package "server" install — `pg-13-meta-server` … `pg-18-meta-server`
- **Install method:** packages — specifically the single `percona-ppg-server-NN` meta-package, asserting it transitively drags in the expected component set.
- Role: `pg-NN-meta-server` ([ppg/pg-17-meta-server/tasks/main.yml](ppg/pg-17-meta-server/tasks/main.yml)) which includes `tasks/install_ppg_meta_server.yml`.
- Tests that the meta-package pulls in: server, contrib, pg_stat_monitor, pgaudit, pg_repack, wal2json.
- Verifier: [ppg/tests/tests_meta_server/test_meta_server.py](ppg/tests/tests_meta_server/test_meta_server.py) — parametrized presence checks for that exact list (DEB and RPM variants).

### 1.5 Meta-package "HA" install — `pg-13-meta-ha` … `pg-18-meta-ha`
- **Install method:** packages — the `percona-ppg-ha-NN` meta-package.
- Role: `pg-NN-meta-ha` ([ppg/pg-17-meta-ha/tasks/main.yml](ppg/pg-17-meta-ha/tasks/main.yml)) → `tasks/install_ppg_meta_ha.yml`.
- Tests that the HA meta-package pulls in `percona-patroni`, `etcd` (+python3-etcd), `percona-haproxy`. Verifier [ppg/tests/tests_meta_ha/test_meta_ha.py](ppg/tests/tests_meta_ha/test_meta_ha.py) also asserts the *versions* of patroni/haproxy match what's recorded in `tests/versions/`.

### 1.6 Tarball install — `pg-tarballs`
- **Install method:** pre-built tarball — neither package nor source build. Downloads a Percona-published binary tarball, extracts it to `/opt/pgdistro/`, and runs the cluster from there.
- Role: `pg-tarballs` ([ppg/pg-tarballs/tasks/main.yml](ppg/pg-tarballs/tasks/main.yml)).
- Downloads the binary tarball from `TARBALL_URL` (rewriting `x86_64`→`aarch64` for ARM hosts), installs OpenSSL of `SSL_VERSION`, lays it out under `/opt/pgdistro/percona-postgresql{N}/`, runs `initdb -A trust -k`, starts via `pg_ctl`, exercises `xml2` and `plperl` extension creation, installs PPG tools tarball, and copies the libpq sanity-build source.
- Verifier: [ppg/tests/tests_ppg_tarballs/](ppg/tests/tests_ppg_tarballs/) (parallel suite that knows about `/opt/pgdistro` paths instead of system packages).

---

## 2. Docker scenarios under `docker/`

Each has 11 platform sub-scenarios (debian-12/13, ubuntu-jammy, rhel-10, rocky-9, plus arm64 variants). Verifier is `ansible` (the converge playbook performs the assertions itself, often by running pytest inside a venv on the host).

**Install method (all docker scenarios): pre-built Docker images.** The host installs Docker itself from packages and pulls Percona images from Docker Hub — no compilation of the software under test happens here.

### 2.1 `ppg-docker` — vanilla server image smoke test
- Role: `ppg-docker` ([docker/ppg-docker/tasks/main.yml](docker/ppg-docker/tasks/main.yml)).
- Installs Docker, copies [docker/ppg-docker/files/test_docker.py](docker/ppg-docker/files/test_docker.py), and runs `pytest test_docker.py` in a venv against `percona/percona-distribution-postgresql:<TAG>`. Tests cover image-label compliance (Red Hat ecosystem labels: `name`, `vendor`, `version`, `release`, `summary`, `description`, `maintainer`, no "Red Hat"/"RHEL" trademark leakage), expected RHEL files, RPM packages, extensions and binaries (including a TDE binary list for PG 18+), with `WITH_POSTGIS` toggle.

### 2.2 `ppg-docker-custom` — custom-built server image
- Role: `ppg-docker-custom` ([docker/ppg-docker-custom/tasks/main.yml](docker/ppg-docker-custom/tasks/main.yml)).
- Same shape as `ppg-docker` but targets `percona-distribution-postgresql-custom:<TAG>` (the custom-build pipeline image). Test set is broader: `test_docker.py`, `test_labels_licences.py`, `test_patroni_ha.py`, `test_pgbackrest.py`, gated by `MILESTONE` markers (1/2/3) so the same scenario runs incrementally over the custom-build milestones.

### 2.3 `ppg-docker-custom-upgrade` — major version upgrade between custom images
- Role: `ppg-docker-custom-upgrade` ([docker/ppg-docker-custom-upgrade/tasks/main.yml](docker/ppg-docker-custom-upgrade/tasks/main.yml)).
- Adds [test_upgrade.py](docker/ppg-docker-custom-upgrade/files/test_upgrade.py): three-phase test — start `OLD_VERSION` container on a host volume, insert sentinel data, stop it, run an "upgrade mediator" container that performs `pg_upgrade` against `/pgolddata` and `/pgnewdata`, then start `NEW_VERSION` on the upgraded volume and assert version/extensions/binaries plus sentinel survival.

### 2.4 `pgbouncer` — pgBouncer image
- Role: `pgbouncer` ([docker/pgbouncer/playbooks/playbook.yml](docker/pgbouncer/playbooks/playbook.yml)).
- Boots `percona/percona-distribution-postgresql:<PG_IMAGE_TAG>` + `percona/percona-pgbouncer:<PGBOUNCER_IMAGE_TAG>` + a client container, applies admin/user/pass + port wiring, runs the pgbouncer test suite. Has a `WITH_TDE` toggle that's force-disabled for PG <17. Validates the same Red Hat label set on both server and pgBouncer images.

### 2.5 `pgbackrest` — pgBackRest image
- Role: `pgbackrest` ([docker/pgbackrest/playbooks/playbook.yml](docker/pgbackrest/playbooks/playbook.yml)).
- Same docker-compose-style fixture (server + pgbackrest + stanza `main`), `WITH_TDE` aware. Exercises stanza creation, backup/restore via `percona/percona-pgbackrest:<TAG>`, and image-label checks.

---

## 3. Extension / component scenarios

These have a smaller platform matrix (`amd` / `arm`, sometimes per-distro) and cover an individual product. The role is named `setup` in nearly all cases. The PPG server underneath is always installed from Percona packages; the column "Install method (component)" describes how the *component being tested* is installed.

| Scenario root | Platforms | Install method (component) | What it tests |
|---|---|---|---|
| [pgpool/setup/](pgpool/setup/) | amd / arm | **Packages** (`percona-pgpool-II-pg{N}` + extensions) | Two PG instances on 5432/5433, push `pgpool.conf`, create `monitor`/`appuser` roles in both backends, start pgpool, verify routing through 9999 (`show pool_nodes`, `show pool_version`) |
| [pgvector/setup/](pgvector/setup/) | amd / arm | **Hybrid** — installs `percona-postgresql-{N}-pgvector` on Debian *and* clones+builds pgvector from source | Run pgvector regression and TAP tests against the freshly-built tree |
| [patroni/setup/](patroni/setup/) | amd / arm | **Packages** (`percona-patroni`, `etcd`, `python3-etcd`, `percona-haproxy`) | Single-host 3-node Patroni cluster with `etcd` DCS and HAProxy frontend; renders `postgresql{0,1,2}.yml`, copies systemd units, starts etcd → patroni → haproxy |
| [pg_audit/setup/](pg_audit/setup/) | amd / arm | **Source build** | Clone pgaudit, `make`/`make install` against PPG-N, configure `shared_preload_libraries`, run pgaudit regression |
| [pg_repack/setup/](pg_repack/setup/) | amd / arm | **Source build** | Clone pg_repack, build, set up tablespaces, run pg_repack regression |
| [pgaudit13_set_user/setup/](pgaudit13_set_user/setup/) (RHEL) and [pgaudit13_set_user/setup_ubuntu/](pgaudit13_set_user/setup_ubuntu/) (Debian) | amd / arm | **Source build** | Build & install `set_user` from source, configure preload, run set_user regression. Two distro-split scenario roots because of differing prerequisites |
| [pgbackrest/setup/](pgbackrest/setup/) | amd / arm | **Source build** (separate from `docker/pgbackrest`) | Clone upstream pgbackrest, free port 80, run pgbackrest's own regression suite — this builds the test harness and the C binary |
| [pgbadger/setup/](pgbadger/setup/) | amd / arm | **Source build** | Clone pgbadger, Perl `Makefile.PL` → `make`, smoke against PPG-N |
| [pgbouncer/setup/](pgbouncer/setup/) | amd / arm | **Hybrid** — installs `percona-pgbouncer` package *and* clones+builds upstream pgbouncer (`autogen.sh` → `configure` → `make`), then runs pytest regression against the built tree | Non-Docker pgbouncer regression |
| [postgis/setup/](postgis/setup/) | amd / arm | **Packages** | PostGIS package install, extension creation, optional regression |
| [wal2json/setup/](wal2json/setup/) | amd / arm | **Source build** | Clone wal2json, build, set `wal_level=logical`, exercise replication-slot decoding |
| [pg_tde/auxiliary/](pg_tde/auxiliary/) | full distro × arch matrix | **Configurable** — `INSTALL_FROM_PACKAGES` / `BUILD_FROM_SOURCE` env vars switch between package install and full source build of PSP+pg_tde | Installs Go, swap, ulimits, optional `io_uring`; pulls the `percona-qa` test runner; runs `test_runner.sh --io_method ${IO_METHOD}` |
| [pg_tde/tde/](pg_tde/tde/) | full distro × arch matrix | **Source build** of pg_tde against a package-installed PSP | Same prereq/swap/io_uring setup as `auxiliary`; configures KMIP/Vault/OpenBao key providers; runs the pg_tde TAP tests |
| [pg_stat_monitor/pgsm/](pg_stat_monitor/pgsm/) | full distro × arch matrix | **Configurable** — source build by default; `PGSM_PACKAGE_INSTALL=true` switches to package-only. PPG server underneath comes from Percona packages | pg_stat_monitor against **PPG** repos (`postgis35` family); runs upstream pg_stat_monitor TAP tests |
| [pg_stat_monitor/pgsm_pgdg/](pg_stat_monitor/pgsm_pgdg/) | full distro × arch matrix | Same as above but PostgreSQL underneath comes from the **PGDG community** repo, not Percona | Variant for PGDG community PostgreSQL — `postgis33` prefix, extra LLVM/clang version probes. Exists so PGSM is exercised on both Percona and upstream community builds |

---

## 4. Source-build full-server scenarios under `psp/`

These are the only scenarios where **PostgreSQL itself is built from source** (the other source-build scenarios above only build extensions against an already-installed server). They use the same Ansible verifier pattern as the docker scenarios — assertions live inside the converge playbook.

### 4.1 `psp/server_tests` — server regression on a from-source build
- **Install method:** **full source build** of PostgreSQL/PSP plus pg_tde. No Percona packages installed.
- 26 platform sub-scenarios — full distro × arch matrix (Debian 11/12/13, Ubuntu Jammy/Noble, RHEL 8/9/10, OL 8/9, Rocky 8/9/10, plus `-arm` of each).
- Role: `server_tests` ([psp/server_tests/tasks/main.yml](psp/server_tests/tasks/main.yml)).
- Steps: prereqs (swap, ulimits, optional `io_uring`), clone PSP and pg_tde sources, `./configure` (with `--with-liburing` on supported OS) → `make install-world` → install Injection-points extension → `initdb` → build & install pg_tde → enable in `postgresql.conf` → start server. Then runs three regression suites in sequence: pg_tde check, server regression, `make check-all` (with regression-diff capture on failure), and finally `installcheck-world` with TDE.

### 4.2 `psp/performance_tests` — pgbench HEAP vs TDE_HEAP comparison
- **Install method:** **full source build** of PostgreSQL/PSP plus pg_tde (separate role to `server_tests`, narrower platform set).
- 6 platform sub-scenarios: debian-12, ubuntu-noble, ol-9, plus `-arm` of each — chosen so the benchmark numbers stay comparable.
- Role: `performance_tests` ([psp/performance_tests/tasks/main.yml](psp/performance_tests/tasks/main.yml)).
- Steps: install Vault from HashiCorp's repo for KMIP testing, build PostgreSQL/PSP from source (`./configure --prefix=/opt/pgsql --enable-depend ...` → `make world-bin` → `make install-world-bin`), build & install pg_tde, run `pgbench` against the **HEAP** access method, then again against **TDE_HEAP**, writing both runs to `/tmp/access_method_benchmark_report.txt`. Driven by `pgbench_scale` / `pgbench_clients` / `pgbench_threads` / `pgbench_duration` vars.

---

## 5. Install-method summary

### Build software from source

The component being tested is compiled from upstream sources (typically against an already-installed PPG):

- [pg_audit/setup/](pg_audit/setup/) — `pgaudit` extension
- [pg_repack/setup/](pg_repack/setup/) — `pg_repack` extension
- [pgaudit13_set_user/setup/](pgaudit13_set_user/setup/) and [pgaudit13_set_user/setup_ubuntu/](pgaudit13_set_user/setup_ubuntu/) — `set_user` extension
- [pgbadger/setup/](pgbadger/setup/) — `pgbadger`
- [pgbackrest/setup/](pgbackrest/setup/) — upstream `pgbackrest` regression
- [wal2json/setup/](wal2json/setup/) — `wal2json` decoder
- [pg_tde/tde/](pg_tde/tde/) — `pg_tde` extension
- [pgvector/setup/](pgvector/setup/) — `pgvector` (also installs the package on Debian; see Hybrid below)
- [pgbouncer/setup/](pgbouncer/setup/) — upstream `pgbouncer` regression (also installs the package; see Hybrid below)
- **The whole PostgreSQL server is built from source** in:
  - [psp/server_tests/](psp/server_tests/)
  - [psp/performance_tests/](psp/performance_tests/)

### Install from packages (Percona repo)

No compilation of the software under test:

- All 30 PPG-version scenarios under `ppg/`: every `pg-NN`, `pg-NN-minor-upgrade`, `pg-NN-major-upgrade`, `pg-NN-meta-server`, `pg-NN-meta-ha` for NN ∈ {13, 14, 15, 16, 17, 18}
- [pgpool/setup/](pgpool/setup/), [patroni/setup/](patroni/setup/), [postgis/setup/](postgis/setup/)

### Configurable (env-var switch between package and source)

- [pg_tde/auxiliary/](pg_tde/auxiliary/) — `INSTALL_FROM_PACKAGES` and `BUILD_FROM_SOURCE` toggle the path
- [pg_stat_monitor/pgsm/](pg_stat_monitor/pgsm/) and [pg_stat_monitor/pgsm_pgdg/](pg_stat_monitor/pgsm_pgdg/) — source build by default; `PGSM_PACKAGE_INSTALL=true` flips to packages

### Hybrid (installs package *and* builds from source in the same run)

- [pgvector/setup/](pgvector/setup/) — package on Debian + always-build from source for the regression
- [pgbouncer/setup/](pgbouncer/setup/) — package install followed by upstream-source build and regression

### Pre-built tarball

- [ppg/pg-tarballs/](ppg/pg-tarballs/) — extracts a published binary tarball into `/opt/pgdistro/`

### Pre-built Docker images

The host installs Docker from packages and pulls Percona images from the registry — neither package install nor source build of the software under test:

- [docker/ppg-docker/](docker/ppg-docker/)
- [docker/ppg-docker-custom/](docker/ppg-docker-custom/)
- [docker/ppg-docker-custom-upgrade/](docker/ppg-docker-custom-upgrade/)
- [docker/pgbouncer/](docker/pgbouncer/)
- [docker/pgbackrest/](docker/pgbackrest/)

---

## 6. Things worth knowing when reading or running these

- All `molecule.yml` files are templated against env vars (`${driver}`, `${region}`, `${ami_*}`, `${vpc_subnet_id_aws*}`, `${BUILD_NUMBER}`, `${JOB_NAME}`) and only run cleanly under the Jenkins wrapper; standalone runs need those exported.
- The `create`/`destroy`/`prepare` playbooks live at the repo root in [playbooks/](playbooks/) — every scenario points back there via relative paths, which is why the role lives in a sibling `playbooks/playbook.yml` instead of `molecule/<scenario>/converge.yml`.
- The verifier directory is what really tells you "what is being tested": `tests_ppg` for full-distro and upgrade jobs, `tests_meta_server` / `tests_meta_ha` for the meta-package jobs, `tests_ppg_tarballs` for tarballs, `tests/test_full_upgrade/` is reserved for the full-upgrade Jenkins job (not used directly by these molecule.yml files), and `test_vanila_components/test_postgis.py` is component-specific.
- Per-version skip guards inside the converge tasks (e.g. "RHEL 10 + PG ≤ 17.5", "Debian 13 + PG ≤ 17.6") let the same scenario run against unsupported combos without failing the whole matrix.
