# PPG tarball tests

These tests install the PPG **tarball** on a fresh VM and check that it works. The tarball is a single `.tar.gz` that contains PostgreSQL and the PPG extensions and tools.

Package tests are separate, see [ppg/README.md](../README.md).

---

## Tarball variants

Each tarball is built against one OpenSSL version, so each one is tested only on the OSes that ship that OpenSSL:

| Variant | `SSL_VERSION` | Tested on |
|---|---|---|
| OpenSSL 1.1 | `1` | Oracle Linux 8, RHEL 8, Rocky 8 |
| OpenSSL 3 | `3` | Debian 12, Oracle Linux 9 and 10, RHEL 9 and 10, Rocky 9 and 10, Ubuntu 22.04 and 24.04 |
| OpenSSL 3.5 | `3.5` | Debian 13, Ubuntu 26.04 |

Every OS is tested on both x86_64 and ARM.

---

## Jenkins jobs

There is one job for each variant:

| Job | Variant |
|---|---|
| `tarball-parallel-ssl1` | OpenSSL 1.1 |
| `tarball-parallel-ssl3` | OpenSSL 3 |
| `tarball-parallel-ssl35` | OpenSSL 3.5 |

Each job runs on every OS of its variant at once.

Pipeline files are in [jenkins-pipelines/ppg](https://github.com/Percona-Lab/jenkins-pipelines/tree/master/ppg).

---

## What it tests

- **Server:** the binaries are present, the server starts, stops and restarts, the version is right, data can be inserted, and every extension can be created and dropped.
- **Tools:** each tool in the tarball is present with the expected version and works. For example:
  - a pgBackRest backup;
  - pg_repack;
  - etcd (health check, writing and reading a key);
  - a Patroni cluster;
  - connections through HAProxy, pgBouncer and pgpool;
  - a pg_tde encrypted table.
- **Tarball quality:** the binaries find all their shared libraries, the `psql` wrapper works, a small `pg_regress` run passes, and the install directory has the right owner.
- **Client libraries:** a small libpq program compiles and runs, and PL/Perl, PL/Tcl and PL/Python3 functions work.

The expected versions come from the same files as the package tests, [ppg/tests/versions/](../tests/versions/), keyed by `VERSION`.

Tests: [ppg/tests/tests_ppg_tarballs/](../tests/tests_ppg_tarballs/)

---

## How a run works

1. Jenkins checks out this repo (branch `TESTING_BRANCH`).
2. It creates one AWS VM per OS.
3. **Prepare:** basic OS setup.
4. **Converge:**
   1. Find the tarball: `TARBALL_URL`, or the tarball in `OBS_PROJECT` for this variant (see below). On ARM hosts, `x86_64` in the URL is replaced with `aarch64`.
   2. Install OpenSSL and the other required system libraries.
   3. Unpack the tarball into `/opt/pgdistro`. The run fails if the tarball's PostgreSQL major doesn't match `VERSION`.
   4. Create a database cluster and start the server. On PostgreSQL 18 and newer, set `io_method`.
   5. Set up the tools: pgBackRest, etcd, a 3-node Patroni cluster and HAProxy.
5. **Verify:** run the tests.
6. **Destroy:** delete the VMs.

The jobs post the result to the `#postgresql-test` Slack channel.

---

## Jenkins parameters

| Parameter | Default | What it does |
|---|---|---|
| `VERSION` | `ppg-18.4` | PostgreSQL version in the tarball, e.g. `ppg-17.10`. Used to pick the expected versions |
| `TARBALL_URL` | The 18.4 tarball of the job's variant on downloads.percona.com | Link to the x86_64 tarball |
| `SSL_VERSION` | Fixed per job (`1`, `3` or `3.5`) | The tarball variant |
| `IO_METHOD` | `worker` | PostgreSQL 18 and newer: `worker`, `sync` or `io_uring` |
| `TESTING_BRANCH` | `main` | Branch of this repo to use |
| `RUN_LABELS` | `Manual` | A label for the run. Not used by the tests |
| `OBS_PROJECT` | empty | OBS tarballs project, e.g. `isv:percona:ppg:staging:18:tarballs`. Used only when `TARBALL_URL` is empty |
| `OBS_HOST` | empty | OBS download server. Empty means `download.opensuse.org` |
| `EXPECTED_VERSIONS` | empty | Override the expected versions, one `package=version` per line |

**`VERSION` and `TARBALL_URL` must match.** The defaults both point at 18.4, so to test another release, change both.

**Testing a tarball from OBS:** leave `TARBALL_URL` empty and set `OBS_PROJECT`. The job looks in the project for the tarball matching the job's variant, the host's architecture and the major version from `VERSION`. Set `VERSION` to the release that is in the project (e.g. `ppg-18.6`), or the version checks fail.

`IO_METHOD=io_uring` isn't supported on Oracle Linux 8, RHEL 8 or Rocky 8; those hosts use `worker` instead.

### Examples

Test the 17.10 tarballs for OpenSSL 3 from downloads.percona.com:

```
Job:          tarball-parallel-ssl3
VERSION:      ppg-17.10
TARBALL_URL:  https://downloads.percona.com/downloads/TESTING/pg_tarballs-17.10/percona-postgresql-17.10-ssl3-linux-x86_64.tar.gz
```

Test the OpenSSL 3.5 tarball built in OBS staging:

```
Job:          tarball-parallel-ssl35
VERSION:      ppg-18.6
TARBALL_URL:  (empty)
OBS_PROJECT:  isv:percona:ppg:staging:18:tarballs
```

---

## Running locally

See [local/README.md](../../local/README.md) for setup. This group has no `--param` options, so set the values as environment variables:

```bash
export VERSION=ppg-18.6 SSL_VERSION=3
```

```bash
export TARBALL_URL=https://downloads.percona.com/downloads/TESTING/pg_tarballs-18.6/percona-postgresql-18.6-ssl3-linux-x86_64.tar.gz
```

```bash
task run GROUP=ppg/pg-tarballs OS=rocky-9
```

---

## Where things are

| Path | What it is |
|---|---|
| [scenario.yml](scenario.yml) | OS list and test steps |
| [tasks/main.yml](tasks/main.yml) | Converge steps: find, install and start the tarball |
| [../../tasks/install_ppg_tarballs.yml](../../tasks/install_ppg_tarballs.yml) | Unpacks the tarball |
| [../../tasks/install_ppg_tools_tarballs.yml](../../tasks/install_ppg_tools_tarballs.yml) | Sets up pgBackRest, etcd, Patroni and HAProxy |
| [files/](files/) | Patroni and HAProxy configuration |
| [../tests/tests_ppg_tarballs/](../tests/tests_ppg_tarballs/) | The tests |
