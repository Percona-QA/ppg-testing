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

# PostGIS legacy script paths on the NEW image
_NEW_POSTGIS_MAJOR_VER = NEW_SETTINGS.get(f"percona-postgis35_{NEW_MAJOR}", {}).get(
    "major_version", "3.5"
)
_NEW_POSTGIS_LEGACY_SQL = (
    f"/usr/pgsql-{NEW_MAJOR}/share/contrib"
    f"/postgis-{_NEW_POSTGIS_MAJOR_VER}/legacy.sql"
)
_NEW_POSTGIS_UNINSTALL_LEGACY_SQL = (
    f"/usr/pgsql-{NEW_MAJOR}/share/contrib"
    f"/postgis-{_NEW_POSTGIS_MAJOR_VER}/uninstall_legacy.sql"
)

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

    def test_telemetry_packages_not_installed(self, upgrade_pipeline):
        new_host = upgrade_pipeline["new_host"]
        excluded = ["percona-telemetry-agent"] + [
            f"percona-pg-telemetry{ver}" for ver in ["16", "17", "18"] if ver != NEW_MAJOR
        ]
        installed = [pkg for pkg in excluded if new_host.run(f"rpm -q {pkg}").rc == 0]
        assert not installed, (
            f"Packages that should not be installed in PG{NEW_MAJOR} image: {installed}"
        )


# ── Shared extension metadata ─────────────────────────────────────────────────
#
# Used by both TestPostUpgradeExtensionFiles (new-image post-upgrade checks)
# and TestUpgradeImageExtensionFiles (all-three-PG-versions checks inside
# the upgrade mediator image).
#
# Each entry: (label, control_file)
# SO-file verification is done dynamically by reading module_pathname from the
# .control file — see _so_from_control() below.  This handles all naming
# conventions automatically:
#   - versioned names  (pgrouting-4.0.so, timescaledb-2.26.0.so)
#   - plain names      (h3.so, ip4r.so, …)
#   - pure-SQL exts    (pg_partman — no module_pathname, no .so)

# Extensions present in ALL three PG major versions (16, 17, 18).
# Each entry: (label, control_file)
# The label must match the extension name in pg_available_extensions.
_EXT_SPECS = [
    # ── milestone-3 batch ────────────────────────────────────────────────────
    ("timescaledb",    "timescaledb.control"),
    ("h3",             "h3.control"),
    ("h3_postgis",     "h3_postgis.control"),
    ("pgrouting",      "pgrouting.control"),
    ("ip4r",           "ip4r.control"),
    ("hll",            "hll.control"),
    ("pg_cron",        "pg_cron.control"),
    ("pg_partman",     "pg_partman.control"),   # pure-SQL: no .so (skipped auto.)
    ("pg_similarity",  "pg_similarity.control"),
    ("vectorscale",    "vectorscale.control"),
    ("rum",            "rum.control"),
    ("unit",           "unit.control"),
    ("anon",           "anon.control"),
    # ── core / milestone-1-2 batch ───────────────────────────────────────────
    ("pg_repack",      "pg_repack.control"),
    ("pgaudit",        "pgaudit.control"),
    ("pg_stat_monitor","pg_stat_monitor.control"),
    ("set_user",       "set_user.control"),
    ("vector",         "vector.control"),       # pgvector; extension name = vector
    ("postgis",        "postgis.control"),
]

# Preload-only modules available for PG 18 only.
# These have NO .control file and do NOT appear in pg_available_extensions.
# They are loaded via shared_preload_libraries and ship only as .so files.
# Verification: check the .so library directly at /usr/pgsql-{major}/lib/.
_SO_ONLY_PG18_MODULES = [
    ("pg_oidc_validator", "pg_oidc_validator.so"),
]

# wal2json is a logical-replication output plugin, not a regular extension.
# It has NO .control file and does NOT appear in pg_available_extensions.
# Verification: check the .so library directly at /usr/pgsql-{major}/lib/.
_WALJSON_SO = "wal2json.so"

# System-level tools that are not PG extensions and have no per-major-version
# path.  We verify their binaries are present in the image.
_SYSTEM_TOOL_BINARIES = [
    ("patroni",    "/usr/bin/patroni"),
    ("pgbackrest", "/usr/bin/pgbackrest"),
]

# All supported PG major versions shipped inside the upgrade mediator image.
# Maps major version string → full major.minor version used as settings key.
_UPGRADE_IMAGE_PG_VERSIONS: dict[str, str] = {
    "16": "16.13",
    "17": "17.9",
    "18": "18.3",
}

# Pre-built parametrize lists for TestUpgradeImageExtensionFiles.
# Cross-product: every PG major version × every extension spec.
_UPGRADE_IMG_CTRL_PARAMS = [
    (major, label, ctrl)
    for major in _UPGRADE_IMAGE_PG_VERSIONS
    for label, ctrl in _EXT_SPECS
]

# PG 18-only parametrize entries for SO-only modules (no .control file).
_UPGRADE_IMG_PG18_SO_PARAMS = [
    ("18", label, so)
    for label, so in _SO_ONLY_PG18_MODULES
]


def _so_from_control(host, major, control_file):
    """Read ``module_pathname`` from an extension's ``.control`` file and
    return the expected ``.so`` path.

    Returns
    -------
    ``(path, None)``
        Absolute path of the ``.so`` library derived from ``module_pathname``.
    ``(None, None)``
        No ``module_pathname`` line found — this is a pure-SQL extension with
        no shared library (e.g. ``pg_partman``); caller should skip the test.
    ``(None, error_str)``
        The ``.control`` file could not be read; caller should fail the test.

    Why control-file–based discovery?
    ----------------------------------
    The ``module_pathname`` value in a ``.control`` file is the exact string
    PostgreSQL passes to ``dlopen()`` at ``CREATE EXTENSION`` time.  Using it
    as the source of truth handles every naming convention automatically:

    * ``pgrouting-4.0``    → ``/usr/pgsql-{major}/lib/pgrouting-4.0.so``
    * ``timescaledb-2.26.0`` → ``/usr/pgsql-{major}/lib/timescaledb-2.26.0.so``
    * ``vectorscale``      → ``/usr/pgsql-{major}/lib/vectorscale.so``
    * *(absent)*           → pure-SQL extension, no ``.so`` to check
    """
    ctrl_path = f"/usr/pgsql-{major}/share/extension/{control_file}"
    cat = host.run(f"cat {ctrl_path}")
    if cat.rc != 0:
        return None, f"cannot read {ctrl_path!r}"

    for line in cat.stdout.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("module_pathname"):
            _, _, value = stripped.partition("=")
            value = value.strip().strip("'\"")
            if "$libdir/" in value:
                lib_name = value.split("$libdir/", 1)[1].strip("'\"")
                return f"/usr/pgsql-{major}/lib/{lib_name}.so", None

    return None, None  # no module_pathname → pure-SQL extension


# ── Phase 3f: Milestone extension file verification (new image) ───────────────


class TestPostUpgradeExtensionFiles:
    """Verify that every milestone extension's package files are installed at
    the correct PostgreSQL prefix in the **new** image.

    pg_upgrade requires all extension ``.control`` files (and the ``.so``
    libraries they reference) to be present in the *new* PG prefix before it
    will upgrade a cluster that uses those extensions.  These tests catch:

    * Missing packages in the new image build.
    * Extensions installed for the wrong PG major version (wrong prefix).
    * ``.so`` or ``.control`` filename changes between major versions.

    The CI upgrade matrix (e.g. PG 16→17, PG 17→18) covers multiple upgrade
    paths; a single run covers the ``NEW_MAJOR`` prefix only.
    """

    @pytest.mark.parametrize(
        "label,control_file",
        _EXT_SPECS,
        ids=[e[0] for e in _EXT_SPECS],
    )
    def test_extension_control_file_at_new_pg_prefix(
        self, upgrade_pipeline, label, control_file
    ):
        """Verify each extension's ``.control`` file is at
        ``/usr/pgsql-{NEW_MAJOR}/share/extension/``."""
        new_host = upgrade_pipeline["new_host"]
        path = f"/usr/pgsql-{NEW_MAJOR}/share/extension/{control_file}"
        result = new_host.run(f"test -f {path}")
        assert result.rc == 0, (
            f"{label}: .control file not found at {path!r} "
            f"in new PG {NEW_MAJOR} image"
        )

    @pytest.mark.parametrize(
        "label,control_file",
        _EXT_SPECS,
        ids=[e[0] for e in _EXT_SPECS],
    )
    def test_extension_so_via_control_file(
        self, upgrade_pipeline, label, control_file
    ):
        """Verify each extension's ``.so`` shared library exists at the path
        declared in its ``module_pathname`` field.

        The ``.control`` file is read from the container and its
        ``module_pathname`` value is used to derive the expected ``.so`` path.
        Pure-SQL extensions (no ``module_pathname``) are skipped automatically.
        Versioned filenames such as ``pgrouting-4.0.so`` and
        ``timescaledb-2.26.0.so`` are handled transparently."""
        new_host = upgrade_pipeline["new_host"]
        so_path, err = _so_from_control(new_host, NEW_MAJOR, control_file)
        if err:
            pytest.fail(f"{label}: {err}")
        if so_path is None:
            pytest.skip(
                f"{label}: no module_pathname in {control_file} "
                f"— pure-SQL extension, no .so to verify"
            )
        result = new_host.run(f"test -f {so_path}")
        assert result.rc == 0, (
            f"{label}: .so not found at {so_path!r} in new PG {NEW_MAJOR} image "
            f"(path derived from module_pathname in {control_file})"
        )

    def test_postgis_legacy_scripts_at_new_pg_prefix(self, upgrade_pipeline):
        """Verify PostGIS ``legacy.sql`` and ``uninstall_legacy.sql`` are
        present at the contrib path in the new image.

        These scripts are not extensions but are required by the PostGIS
        upgrade workflow and must ship at the versioned contrib directory."""
        new_host = upgrade_pipeline["new_host"]
        for path in (_NEW_POSTGIS_LEGACY_SQL, _NEW_POSTGIS_UNINSTALL_LEGACY_SQL):
            result = new_host.run(f"test -f {path}")
            assert result.rc == 0, (
                f"PostGIS contrib script not found at {path!r} "
                f"in new PG {NEW_MAJOR} image"
            )

    def test_milestone_extensions_in_pg_available_extensions(self, upgrade_pipeline):
        """Verify all milestone extensions appear in ``pg_available_extensions``
        on the upgraded cluster.

        This is a catalog-level complement to the file-system checks above:
        PostgreSQL must be able to see and describe each extension before it
        can be installed or re-created after the upgrade.

        Note: ``wal2json`` is excluded (output plugin, not an extension).
        ``pg_oidc_validator`` is excluded too — it is a preload-only module
        with no ``.control`` file and does not appear in
        ``pg_available_extensions``."""
        new_host = upgrade_pipeline["new_host"]
        ext_names = [label for label, _ in _EXT_SPECS]
        # h3_postgis installs via CREATE EXTENSION h3_postgis CASCADE; include it
        missing = []
        for ext in ext_names:
            query = (
                f"SELECT count(*) FROM pg_available_extensions "
                f"WHERE name = '{ext}';"
            )
            result = new_host.run(
                f'{PG_NEW_BIN_DIR}/psql -U postgres -tAc "{query}"'
            )
            if result.rc != 0 or result.stdout.strip() != "1":
                missing.append(ext)
        assert not missing, (
            f"Extensions not visible in pg_available_extensions "
            f"on new PG {NEW_MAJOR}: {missing}"
        )

    def test_wal2json_so_at_new_pg_prefix(self, upgrade_pipeline):
        """``wal2json`` is a logical-replication output plugin with no
        ``.control`` file.  Verify its ``.so`` is present at the PG lib path."""
        new_host = upgrade_pipeline["new_host"]
        path = f"/usr/pgsql-{NEW_MAJOR}/lib/{_WALJSON_SO}"
        result = new_host.run(f"test -f {path}")
        assert result.rc == 0, (
            f"wal2json: {_WALJSON_SO!r} not found at {path!r} "
            f"in new PG {NEW_MAJOR} image"
        )

    @pytest.mark.skipif(
        NEW_MAJOR != "18",
        reason="pg_oidc_validator is only packaged for PG 18",
    )
    def test_pg_oidc_validator_pg18_only(self, upgrade_pipeline):
        """``pg_oidc_validator`` ships for PG 18 only.  It is a preload-only
        module (loaded via ``shared_preload_libraries``) with no ``.control``
        file.  Verify its ``.so`` library is present at the new-image PG prefix."""
        new_host = upgrade_pipeline["new_host"]
        for label, so_name in _SO_ONLY_PG18_MODULES:
            so_path = f"/usr/pgsql-{NEW_MAJOR}/lib/{so_name}"
            assert new_host.run(f"test -f {so_path}").rc == 0, (
                f"{label}: .so not found at {so_path!r} in new PG {NEW_MAJOR} image"
            )

    @pytest.mark.parametrize(
        "label,binary_path",
        _SYSTEM_TOOL_BINARIES,
        ids=[e[0] for e in _SYSTEM_TOOL_BINARIES],
    )
    def test_system_tool_binary_present(
        self, upgrade_pipeline, label, binary_path
    ):
        """``patroni`` and ``pgbackrest`` are not PG extensions; verify their
        system binaries are present in the new image."""
        new_host = upgrade_pipeline["new_host"]
        result = new_host.run(f"test -f {binary_path}")
        assert result.rc == 0, (
            f"{label}: binary not found at {binary_path!r} in new image"
        )


# ── Upgrade image inspection fixture ─────────────────────────────────────────


@pytest.fixture(scope="module")
def upgrade_image_host():
    """Start the upgrade mediator image with a ``sleep`` entrypoint so its
    file system can be inspected without triggering the actual pg_upgrade
    workflow.

    The upgrade mediator image ships all three PostgreSQL major versions
    (16, 17, 18) side by side under ``/usr/pgsql-{major}/`` so it can bridge
    any adjacent-version upgrade path.  This fixture gives tests a live
    container to run ``test -f`` and similar commands against.
    """
    container_name = "ppg_upgrade_image_inspect"
    subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
    subprocess.run(
        [
            "docker", "run", "-d",
            "--name", container_name,
            "--entrypoint", "sleep",
            UPGRADE_IMAGE,
            "3600",
        ],
        check=True,
    )
    time.sleep(2)
    yield testinfra.get_host(f"docker://{container_name}")
    subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)


# ── Phase 0: Upgrade image — all-three-PG-versions file verification ──────────


class TestUpgradeImageExtensionFiles:
    """Verify that every milestone extension is installed for **all three**
    PostgreSQL major versions (16, 17, 18) inside the upgrade mediator image.

    The upgrade mediator image must ship complete extension packages for every
    supported major version because:

    * pg_upgrade needs the **new**-version files present before it starts.
    * The same image is reused for every adjacent-major upgrade path
      (16→17, 17→18, and future 18→19).
    * A missing package at *any* prefix breaks the corresponding upgrade path
      silently — the upgrade proceeds but ``CREATE EXTENSION`` fails afterward.

    These tests start the upgrade image with a ``sleep`` entrypoint (no actual
    upgrade is run) and inspect the file system with ``test -f`` for each
    extension × PG major version combination.

    Test IDs use the ``pg{major}-{label}`` naming convention so failures
    pinpoint exactly which extension is missing from which PG prefix, e.g.::

        FAILED test_upgrade.py::TestUpgradeImageExtensionFiles::
               test_extension_control_file[pg17-pg_partman]
    """

    @pytest.mark.parametrize(
        "major,label,control_file",
        _UPGRADE_IMG_CTRL_PARAMS,
        ids=[f"pg{m}-{l}" for m, l, _ in _UPGRADE_IMG_CTRL_PARAMS],
    )
    def test_extension_control_file(
        self, upgrade_image_host, major, label, control_file
    ):
        """Verify ``.control`` file at ``/usr/pgsql-{major}/share/extension/``
        for every extension × PG major version combination."""
        path = f"/usr/pgsql-{major}/share/extension/{control_file}"
        result = upgrade_image_host.run(f"test -f {path}")
        assert result.rc == 0, (
            f"{label}: .control file missing at {path!r} in upgrade image "
            f"(PG {major})"
        )

    @pytest.mark.parametrize(
        "major,label,control_file",
        _UPGRADE_IMG_CTRL_PARAMS,
        ids=[f"pg{m}-{l}" for m, l, _ in _UPGRADE_IMG_CTRL_PARAMS],
    )
    def test_extension_so_via_control_file(
        self, upgrade_image_host, major, label, control_file
    ):
        """Verify the ``.so`` library declared in each extension's
        ``module_pathname`` exists at ``/usr/pgsql-{major}/lib/``.

        Pure-SQL extensions (no ``module_pathname``) are skipped.
        Versioned ``.so`` names (``pgrouting-4.0.so``,
        ``timescaledb-2.26.0.so``) are resolved automatically from the
        ``.control`` file — no hardcoded filenames in the test."""
        so_path, err = _so_from_control(upgrade_image_host, major, control_file)
        if err:
            pytest.fail(f"{label} (PG {major}): {err}")
        if so_path is None:
            pytest.skip(
                f"{label}: no module_pathname in {control_file} "
                f"— pure-SQL extension, no .so to verify"
            )
        result = upgrade_image_host.run(f"test -f {so_path}")
        assert result.rc == 0, (
            f"{label}: .so missing at {so_path!r} in upgrade image (PG {major}). "
            f"Path derived from module_pathname in {control_file}."
        )

    @pytest.mark.parametrize(
        "major,major_minor",
        list(_UPGRADE_IMAGE_PG_VERSIONS.items()),
        ids=[f"pg{m}" for m in _UPGRADE_IMAGE_PG_VERSIONS],
    )
    def test_postgis_legacy_scripts(
        self, upgrade_image_host, major, major_minor
    ):
        """Verify PostGIS ``legacy.sql`` and ``uninstall_legacy.sql`` exist
        under the correct versioned contrib directory for each PG major version.
        """
        ver_settings = settings.get_settings(major_minor)
        postgis_major = ver_settings.get(
            f"percona-postgis35_{major}", {}
        ).get("major_version", "3.5")
        contrib_dir = (
            f"/usr/pgsql-{major}/share/contrib/postgis-{postgis_major}"
        )
        for script in ("legacy.sql", "uninstall_legacy.sql"):
            path = f"{contrib_dir}/{script}"
            result = upgrade_image_host.run(f"test -f {path}")
            assert result.rc == 0, (
                f"PostGIS {script!r} missing at {path!r} in upgrade image "
                f"(PG {major})"
            )

    @pytest.mark.parametrize(
        "major",
        list(_UPGRADE_IMAGE_PG_VERSIONS.keys()),
        ids=[f"pg{m}" for m in _UPGRADE_IMAGE_PG_VERSIONS],
    )
    def test_wal2json_so_all_pg_versions(self, upgrade_image_host, major):
        """``wal2json`` is a logical-replication output plugin with no
        ``.control`` file.  Verify its ``.so`` for every PG major version."""
        path = f"/usr/pgsql-{major}/lib/{_WALJSON_SO}"
        result = upgrade_image_host.run(f"test -f {path}")
        assert result.rc == 0, (
            f"wal2json: {_WALJSON_SO!r} missing at {path!r} in upgrade image "
            f"(PG {major})"
        )

    @pytest.mark.parametrize(
        "major,label,so_name",
        _UPGRADE_IMG_PG18_SO_PARAMS,
        ids=[f"pg18-{l}" for _, l, _ in _UPGRADE_IMG_PG18_SO_PARAMS],
    )
    def test_pg18_only_so_only_module(
        self, upgrade_image_host, major, label, so_name
    ):
        """``pg_oidc_validator`` is only packaged for PG 18.  It is a
        preload-only module (no ``.control`` file); verify its ``.so`` library
        is present in the upgrade image's PG 18 lib prefix."""
        so_path = f"/usr/pgsql-{major}/lib/{so_name}"
        result = upgrade_image_host.run(f"test -f {so_path}")
        assert result.rc == 0, (
            f"{label}: .so missing at {so_path!r} in upgrade image (PG {major})"
        )

    def test_telemetry_packages_not_installed(self, upgrade_image_host):
        """The upgrade mediator image ships PG 16, 17, and 18 simultaneously.
        None of the version-specific telemetry packages nor the telemetry agent
        should be installed in it."""
        excluded = [
            "percona-telemetry-agent",
            "percona-pg-telemetry16",
            "percona-pg-telemetry17",
            "percona-pg-telemetry18",
        ]
        installed = [pkg for pkg in excluded if upgrade_image_host.run(f"rpm -q {pkg}").rc == 0]
        assert not installed, (
            f"Packages that should not be installed in the upgrade mediator image: {installed}"
        )
