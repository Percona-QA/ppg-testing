"""
test_upgrade.py — PostgreSQL major version upgrade tests.

Upgrade workflow
────────────────
  Phase 1  Pre-upgrade  : start OLD_VERSION container on a host-mounted volume,
                          verify it is healthy, insert a sentinel row.
  Phase 2  Upgrade      : stop the old container, run the pg_upgrade mediator,
                          capture its exit code and output.
  Phase 3  Post-upgrade : start NEW_VERSION container on the upgraded volume,
                          verify new version, extensions, binaries, and
                          that the sentinel data survived intact.

Environment variables
─────────────────────
  OLD_VERSION        Full source version   (e.g. "17.9")
  NEW_VERSION        Full target version   (e.g. "18.3")
  DOCKER_REPOSITORY  Image registry prefix (e.g. "perconalab")
  OLD_TAG            Tag for the old custom image  (default: OLD_VERSION)
  NEW_TAG            Tag for the new custom image  (default: NEW_VERSION)
  UPGRADE_TAG        Tag for the upgrade mediator  (default: "v2")
  UPGRADE_BASE_DIR   Host directory for PG volumes (default: ~/pgupgrade)

Volume layout on the host
─────────────────────────
  <UPGRADE_BASE_DIR>/pg<OLD_MAJOR>olddata/postgres  →  old container /data/db
  <UPGRADE_BASE_DIR>/pg<NEW_MAJOR>newdata/postgres  →  new container /data/db

  The upgrade mediator maps:
    <UPGRADE_BASE_DIR>/pg<OLD_MAJOR>olddata  →  /pgolddata   (old data at /pgolddata/postgres)
    <UPGRADE_BASE_DIR>/pg<NEW_MAJOR>newdata  →  /pgnewdata   (new data at /pgnewdata/postgres)
"""

import os
import pathlib
import shutil
import subprocess
import time

import pytest
import testinfra

import settings

# ── Configuration ─────────────────────────────────────────────────────────────

# When SKIP_UPGRADE=true the upgrade pipeline fixture skips the pre-upgrade
# container setup and the pg_upgrade mediator step.  It assumes the host
# data volumes were already populated by an external orchestrator (run.sh).
# Use this when running test_upgrade.py as part of a larger workflow where
# the upgrade has already been performed.
SKIP_UPGRADE = os.environ.get("SKIP_UPGRADE", "false").lower() == "true"

# Marker applied to TestUpgradeExecution — those tests verify the mediator
# itself and are meaningless when the upgrade was run externally.
skip_if_upgrade_external = pytest.mark.skipif(
    SKIP_UPGRADE,
    reason="SKIP_UPGRADE=true — upgrade was run externally; skipping mediator tests",
)

OLD_MAJOR_MINOR = os.environ.get("OLD_VERSION", "17.9")
NEW_MAJOR_MINOR = os.environ.get("NEW_VERSION", "18.3")
OLD_MAJOR = OLD_MAJOR_MINOR.split(".")[0]
NEW_MAJOR = NEW_MAJOR_MINOR.split(".")[0]

DOCKER_REPO = os.environ.get("DOCKER_REPOSITORY", "perconalab")
IMG_TAG_OLD = os.environ.get("OLD_TAG", OLD_MAJOR_MINOR)
IMG_TAG_NEW = os.environ.get("NEW_TAG", NEW_MAJOR_MINOR)
UPGRADE_IMG_TAG = os.environ.get("UPGRADE_TAG", "v2")

# When run.sh drives the upgrade it passes UPGRADE_NEW_VOL (a Docker named
# volume) instead of a host path.  In standalone mode (SKIP_UPGRADE=false)
# the fixture manages its own host-path volumes.
UPGRADE_NEW_VOL = os.environ.get("UPGRADE_NEW_VOL")

OLD_IMAGE = f"{DOCKER_REPO}/percona-distribution-postgresql-custom:{IMG_TAG_OLD}"
NEW_IMAGE = f"{DOCKER_REPO}/percona-distribution-postgresql-custom:{IMG_TAG_NEW}"
UPGRADE_IMAGE = f"{DOCKER_REPO}/percona-distribution-postgresql-upgrade-custom:{UPGRADE_IMG_TAG}"

PG_OLD_BIN_DIR = f"/usr/pgsql-{OLD_MAJOR}/bin"
PG_NEW_BIN_DIR = f"/usr/pgsql-{NEW_MAJOR}/bin"
PG_DATA_DIR = "/data/db"

# Host-side volume roots
UPGRADE_BASE_DIR = os.environ.get("UPGRADE_BASE_DIR", str(pathlib.Path.home() / "pgupgrade"))
OLD_DATA_HOST = os.path.join(UPGRADE_BASE_DIR, f"pg{OLD_MAJOR}olddata")
NEW_DATA_HOST = os.path.join(UPGRADE_BASE_DIR, f"pg{NEW_MAJOR}newdata")

# Container names
OLD_CONTAINER = f"ppg_upgrade_old_{OLD_MAJOR}_{NEW_MAJOR}"
NEW_CONTAINER = f"ppg_upgrade_new_{OLD_MAJOR}_{NEW_MAJOR}"

# Sentinel data written before the upgrade and verified after
SENTINEL_TABLE = "upgrade_sentinel"
SENTINEL_VALUE = f"upgraded_from_pg{OLD_MAJOR}_to_pg{NEW_MAJOR}"

OLD_SETTINGS = settings.get_settings(OLD_MAJOR_MINOR)
NEW_SETTINGS = settings.get_settings(NEW_MAJOR_MINOR)
NEW_EXTENSIONS = NEW_SETTINGS["extensions"]
NEW_BINARIES = NEW_SETTINGS["binaries"]
NEW_RPM_PACKAGES = NEW_SETTINGS["rpm_packages"]

# ── Helpers ───────────────────────────────────────────────────────────────────


def _remove_container(name: str) -> None:
    """Force-remove a container, ignoring errors if it does not exist."""
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)


def _wait_for_postgres(container_name: str, bin_dir: str, timeout: int = 60) -> None:
    """Poll pg_isready until PostgreSQL is accepting connections, or raise."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        res = subprocess.run(
            [
                "docker",
                "exec",
                container_name,
                f"{bin_dir}/pg_isready",
                "-U",
                "postgres",
            ],
            capture_output=True,
        )
        if res.returncode == 0:
            return
        time.sleep(2)
    raise TimeoutError(f"PostgreSQL in container {container_name!r} not ready after {timeout}s")


# ── Upgrade pipeline fixture ──────────────────────────────────────────────────


@pytest.fixture(scope="session")
def upgrade_pipeline():
    """
    Manages the upgrade lifecycle and yields state for all test classes.

    Two operating modes
    ───────────────────
    Standalone mode  (SKIP_UPGRADE=false, the default)
      Performs the full three-phase lifecycle:
        1. Create host volume dirs, start OLD container, insert sentinel row.
        2. Stop old container, run pg_upgrade mediator, capture result.
        3. Start NEW container on upgraded data, yield state.

    External-upgrade mode  (SKIP_UPGRADE=true)
      Assumes run.sh (or another orchestrator) already ran the upgrade and
      populated NEW_DATA_HOST.  Skips phases 1-2 entirely and just starts
      the NEW container.  Use this when test_upgrade.py is called as part of
      the run.sh workflow so the upgrade is not repeated.

    Yielded state dict keys
    ───────────────────────
      pre_pg_version   str | None        SELECT version() from old container,
                                         or None when upgrade was external.
      upgrade_result   CompletedProcess  result of the mediator docker run,
                       | None            or None when upgrade was external.
      new_host         testinfra host    testinfra handle for the new container.
    """
    print("\n" + "=" * 64)
    print(f"  Upgrade:       PG {OLD_MAJOR_MINOR}  →  PG {NEW_MAJOR_MINOR}")
    print(f"  New image:     {NEW_IMAGE}")
    if UPGRADE_NEW_VOL:
        print(f"  New data vol:  {UPGRADE_NEW_VOL}")
    else:
        print(f"  New data dir:  {NEW_DATA_HOST}/postgres")
    print(f"  SKIP_UPGRADE:  {SKIP_UPGRADE}")
    print("=" * 64)

    pre_pg_version = None
    upgrade_result = None

    if not SKIP_UPGRADE:
        # ── Full standalone lifecycle ──────────────────────────────────────────

        print(f"  Old image:     {OLD_IMAGE}")
        print(f"  Upgrade image: {UPGRADE_IMAGE}")
        print(f"  Old data dir:  {OLD_DATA_HOST}/postgres")

        # Remove stale data from previous runs
        for stale_dir in (OLD_DATA_HOST, NEW_DATA_HOST):
            if pathlib.Path(stale_dir).exists():
                shutil.rmtree(stale_dir)
                print(f"  Removed stale data dir: {stale_dir}")

        # Create only the parent directories — Docker creates the postgres
        # subdirectory as root when processing the bind mount, allowing the
        # container's entrypoint to chown/chmod it without permission errors.
        pathlib.Path(OLD_DATA_HOST).mkdir(parents=True, exist_ok=True)
        pathlib.Path(NEW_DATA_HOST).mkdir(parents=True, exist_ok=True)

        # Start old container with data volume
        _remove_container(OLD_CONTAINER)
        subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                OLD_CONTAINER,
                "-e",
                "POSTGRES_PASSWORD=password",
                "--shm-size=2g",
                "-v",
                f"{OLD_DATA_HOST}/postgres:{PG_DATA_DIR}",
                OLD_IMAGE,
            ],
            check=True,
        )
        _wait_for_postgres(OLD_CONTAINER, PG_OLD_BIN_DIR)
        time.sleep(2)

        old_host = testinfra.get_host(f"docker://{OLD_CONTAINER}")

        pre_pg_version = old_host.run(
            f"{PG_OLD_BIN_DIR}/psql -U postgres -tAc 'SELECT version()'"
        ).stdout.strip()
        print(f"\n  Pre-upgrade PostgreSQL: {pre_pg_version}")

        # Insert sentinel row — must survive the upgrade
        old_host.run(
            f"{PG_OLD_BIN_DIR}/psql -U postgres -c "
            f'"CREATE TABLE {SENTINEL_TABLE} (val TEXT);'
            f" INSERT INTO {SENTINEL_TABLE} VALUES ('{SENTINEL_VALUE}');\""
        )
        print(f"  Sentinel inserted: {SENTINEL_TABLE}.val = '{SENTINEL_VALUE}'")

        # Stop old container (data stays in volume)
        subprocess.run(["docker", "stop", OLD_CONTAINER], check=True)
        subprocess.run(["docker", "rm", OLD_CONTAINER], check=True)
        print("\n  Old container stopped. Running pg_upgrade mediator …")

        upgrade_result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--name",
                f"ppg_upgrade_mediator_{OLD_MAJOR}_{NEW_MAJOR}",
                "-e",
                f"OLD_VERSION={OLD_MAJOR}",
                "-e",
                f"NEW_VERSION={NEW_MAJOR}",
                "-e",
                "OLD_DATABASE_NAME=postgres",
                "-e",
                "NEW_DATABASE_NAME=postgres",
                "-v",
                f"{OLD_DATA_HOST}:/pgolddata",
                "-v",
                f"{NEW_DATA_HOST}:/pgnewdata",
                UPGRADE_IMAGE,
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
        print(f"  Mediator exit code: {upgrade_result.returncode}")
        if upgrade_result.stdout:
            print(f"  Mediator stdout:\n{upgrade_result.stdout[:500]}")
        if upgrade_result.stderr:
            print(f"  Mediator stderr:\n{upgrade_result.stderr[:500]}")

    else:
        # ── External-upgrade mode: upgrade already done by run.sh ─────────────
        if UPGRADE_NEW_VOL:
            print(
                f"  SKIP_UPGRADE=true — reusing upgraded data from "
                f"Docker volume {UPGRADE_NEW_VOL!r}"
            )
            result = subprocess.run(
                ["docker", "volume", "inspect", UPGRADE_NEW_VOL],
                capture_output=True,
            )
            if result.returncode != 0:
                pytest.fail(
                    f"SKIP_UPGRADE=true but Docker volume {UPGRADE_NEW_VOL!r} "
                    f"not found — did run.sh complete Phase 2?"
                )
        else:
            print(f"  SKIP_UPGRADE=true — reusing upgraded data from {NEW_DATA_HOST}/postgres")
            if not pathlib.Path(NEW_DATA_HOST, "postgres").exists():
                pytest.fail(
                    f"SKIP_UPGRADE=true but upgraded data not found at "
                    f"{NEW_DATA_HOST}/postgres — did run.sh complete Phase 2?"
                )

    # ── Start new container on the upgraded data ───────────────────────────────
    # Use the named volume when provided by run.sh; otherwise use the host path.
    new_data_vol = (
        f"{UPGRADE_NEW_VOL}:{PG_DATA_DIR}"
        if UPGRADE_NEW_VOL
        else f"{NEW_DATA_HOST}/postgres:{PG_DATA_DIR}"
    )
    _remove_container(NEW_CONTAINER)
    subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            NEW_CONTAINER,
            "-e",
            "POSTGRES_PASSWORD=password",
            "--shm-size=2g",
            "-v",
            new_data_vol,
            NEW_IMAGE,
        ],
        check=True,
    )
    _wait_for_postgres(NEW_CONTAINER, PG_NEW_BIN_DIR)
    time.sleep(2)

    new_host = testinfra.get_host(f"docker://{NEW_CONTAINER}")
    print(f"  New container {NEW_CONTAINER!r} is ready.\n")

    yield {
        "pre_pg_version": pre_pg_version,
        "upgrade_result": upgrade_result,
        "new_host": new_host,
    }

    # ── Teardown ───────────────────────────────────────────────────────────────
    _remove_container(NEW_CONTAINER)


# ── Phase 2: Upgrade execution verification ───────────────────────────────────


@skip_if_upgrade_external
class TestUpgradeExecution:
    """
    Verify the pg_upgrade mediator ran to completion without errors.

    Skipped when SKIP_UPGRADE=true (upgrade was run externally by run.sh).
    """

    def test_upgrade_exit_code(self, upgrade_pipeline):
        result = upgrade_pipeline["upgrade_result"]
        assert result.returncode == 0, (
            f"pg_upgrade mediator exited with code {result.returncode}.\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )

    def test_upgrade_produced_output(self, upgrade_pipeline):
        result = upgrade_pipeline["upgrade_result"]
        assert result.stdout.strip(), (
            "pg_upgrade mediator produced no stdout — upgrade may not have run"
        )

    def test_upgrade_no_fatal_keywords(self, upgrade_pipeline):
        result = upgrade_pipeline["upgrade_result"]
        output = (result.stdout + result.stderr).lower()
        for keyword in ("fatal", "panic", "aborted"):
            assert keyword not in output, (
                f"Keyword {keyword!r} found in upgrade output:\n"
                f"stdout: {result.stdout}\nstderr: {result.stderr}"
            )


# ── Phase 3a: Post-upgrade version verification ───────────────────────────────


class TestPostUpgradeVersion:
    """Verify the new container is running the expected PostgreSQL major version."""

    def test_new_postgres_major_version(self, upgrade_pipeline):
        new_host = upgrade_pipeline["new_host"]
        result = new_host.run(f"{PG_NEW_BIN_DIR}/psql -U postgres -tAc 'SHOW server_version'")
        assert result.rc == 0, f"SHOW server_version failed: {result.stderr}"
        assert result.stdout.strip().startswith(NEW_MAJOR), (
            f"Expected version starting with {NEW_MAJOR!r}, got {result.stdout.strip()!r}"
        )

    def test_new_version_differs_from_old(self, upgrade_pipeline):
        """Server version string on new container must not match the old one."""
        new_host = upgrade_pipeline["new_host"]
        result = new_host.run(f"{PG_NEW_BIN_DIR}/psql -U postgres -tAc 'SELECT version()'")
        assert result.rc == 0
        pre = upgrade_pipeline["pre_pg_version"]
        if pre is None:
            # pre_pg_version is only captured in standalone mode; when the upgrade
            # was run externally (SKIP_UPGRADE=true) we skip the string comparison
            # and just verify the new major version is present instead.
            assert NEW_MAJOR in result.stdout, (
                f"Expected PG {NEW_MAJOR} in version string, got: {result.stdout.strip()!r}"
            )
        else:
            assert pre not in result.stdout, (
                f"Old version string {pre!r} still present in new container"
            )

    def test_psql_accepts_queries(self, upgrade_pipeline):
        new_host = upgrade_pipeline["new_host"]
        result = new_host.run(f"{PG_NEW_BIN_DIR}/psql -U postgres -c 'SELECT 1 AS ok'")
        assert result.rc == 0, f"psql query failed: {result.stderr}"
        assert "ok" in result.stdout


# ── Phase 3b: Data integrity ──────────────────────────────────────────────────


class TestPostUpgradeDataIntegrity:
    """Verify that data written before the upgrade survived intact."""

    def test_sentinel_table_exists(self, upgrade_pipeline):
        new_host = upgrade_pipeline["new_host"]
        result = new_host.run(
            f"{PG_NEW_BIN_DIR}/psql -U postgres -tAc "
            f"\"SELECT to_regclass('public.{SENTINEL_TABLE}')\""
        )
        assert result.rc == 0
        assert SENTINEL_TABLE in result.stdout, (
            f"Sentinel table {SENTINEL_TABLE!r} not found after upgrade"
        )

    def test_sentinel_value_intact(self, upgrade_pipeline):
        new_host = upgrade_pipeline["new_host"]
        result = new_host.run(
            f'{PG_NEW_BIN_DIR}/psql -U postgres -tAc "SELECT val FROM {SENTINEL_TABLE} LIMIT 1"'
        )
        assert result.rc == 0
        assert SENTINEL_VALUE in result.stdout, (
            f"Expected sentinel value {SENTINEL_VALUE!r}, got {result.stdout.strip()!r}"
        )

    def test_system_catalogs_accessible(self, upgrade_pipeline):
        new_host = upgrade_pipeline["new_host"]
        result = new_host.run(
            f"{PG_NEW_BIN_DIR}/psql -U postgres -tAc 'SELECT count(*) FROM pg_catalog.pg_class'"
        )
        assert result.rc == 0
        count = int(result.stdout.strip())
        assert count > 0, "pg_catalog.pg_class is empty — system catalog may be corrupt"

    def test_user_tables_in_pg_class(self, upgrade_pipeline):
        """The sentinel table must appear in pg_class as a user relation."""
        new_host = upgrade_pipeline["new_host"]
        result = new_host.run(
            f"{PG_NEW_BIN_DIR}/psql -U postgres -tAc "
            f"\"SELECT relname FROM pg_class WHERE relname = '{SENTINEL_TABLE}'\""
        )
        assert result.rc == 0
        assert SENTINEL_TABLE in result.stdout, (
            f"Sentinel table {SENTINEL_TABLE!r} not in pg_class after upgrade"
        )


# ── Phase 3c: Binaries ────────────────────────────────────────────────────────


class TestPostUpgradeBinaries:
    """Verify all expected PostgreSQL binaries exist in the new image."""

    def test_expected_binaries_present(self, upgrade_pipeline):
        new_host = upgrade_pipeline["new_host"]
        missing = [
            b for b in NEW_BINARIES if new_host.run(f"test -f {PG_NEW_BIN_DIR}/{b}").rc != 0
        ]
        assert not missing, f"Missing binaries in {PG_NEW_BIN_DIR}: {missing}"

    def test_pg_upgrade_binary_present(self, upgrade_pipeline):
        """The new image must ship pg_upgrade itself for future upgrades."""
        new_host = upgrade_pipeline["new_host"]
        result = new_host.run(f"test -f {PG_NEW_BIN_DIR}/pg_upgrade")
        assert result.rc == 0, f"pg_upgrade binary missing at {PG_NEW_BIN_DIR}/pg_upgrade"

    def test_initdb_binary_present(self, upgrade_pipeline):
        new_host = upgrade_pipeline["new_host"]
        result = new_host.run(f"test -f {PG_NEW_BIN_DIR}/initdb")
        assert result.rc == 0, f"initdb binary missing at {PG_NEW_BIN_DIR}/initdb"


# ── Phase 3d: Extensions ──────────────────────────────────────────────────────


class TestPostUpgradeExtensions:
    """Verify key extensions load cleanly on the upgraded cluster."""

    # Safe to CREATE without shared_preload_libraries or extra setup
    _LOADABLE_WITHOUT_PRELOAD = [
        "hstore",
        "pg_trgm",
        "uuid-ossp",
        "citext",
        "ltree",
        "pgcrypto",
        "tablefunc",
        "unaccent",
        "pg_stat_statements",
        "pgrowlocks",
        "pgstattuple",
    ]

    def test_core_extensions_create(self, upgrade_pipeline):
        new_host = upgrade_pipeline["new_host"]
        failed = []
        for ext in self._LOADABLE_WITHOUT_PRELOAD:
            res = new_host.run(
                f"{PG_NEW_BIN_DIR}/psql -U postgres -c "
                f'"CREATE EXTENSION IF NOT EXISTS \\"{ext}\\""'
            )
            if res.rc != 0:
                failed.append((ext, res.stderr.strip()))
        assert not failed, f"Extensions failed to CREATE on new version: {failed}"

    def test_available_extensions_match_settings(self, upgrade_pipeline):
        """Every extension listed in NEW_SETTINGS must appear in pg_available_extensions."""
        new_host = upgrade_pipeline["new_host"]
        result = new_host.run(
            f"{PG_NEW_BIN_DIR}/psql -U postgres -tAc "
            "'SELECT name FROM pg_available_extensions ORDER BY name'"
        )
        assert result.rc == 0
        available = result.stdout.splitlines()
        missing = [ext for ext in NEW_EXTENSIONS if ext not in available]
        assert not missing, f"Extensions in settings not available in PG {NEW_MAJOR}: {missing}"


# ── Phase 3e: Packages ────────────────────────────────────────────────────────


class TestPostUpgradePackages:
    """Verify expected RPM packages are installed in the new image."""

    def test_new_version_rpm_packages_installed(self, upgrade_pipeline):
        new_host = upgrade_pipeline["new_host"]
        missing = [pkg for pkg in NEW_RPM_PACKAGES if new_host.run(f"rpm -q {pkg}").rc != 0]
        assert not missing, f"RPM packages not installed in new image: {missing}"

    def test_data_directory_path(self, upgrade_pipeline):
        new_host = upgrade_pipeline["new_host"]
        result = new_host.run(f"{PG_NEW_BIN_DIR}/psql -U postgres -tAc 'SHOW data_directory'")
        assert result.rc == 0
        assert PG_DATA_DIR in result.stdout, (
            f"Expected data_directory={PG_DATA_DIR!r}, got {result.stdout.strip()!r}"
        )

    def test_config_files_exist(self, upgrade_pipeline):
        new_host = upgrade_pipeline["new_host"]
        config_files = NEW_SETTINGS["rhel_files"]
        missing = [f for f in config_files if not new_host.file(f).exists]
        assert not missing, f"PostgreSQL config files missing after upgrade: {missing}"
