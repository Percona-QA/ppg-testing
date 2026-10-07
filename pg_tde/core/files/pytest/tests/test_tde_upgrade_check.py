"""
Staged upgrade checker for an *existing* pg_tde cluster (the packaged service
cluster the pg_tde/upgrade molecule role installs), reached through
PGHOST/PGPORT as the postgres OS user.

Unlike the other upgrade tests this module never creates clusters or installs
binaries. The caller drives the upgrade and runs one stage per pytest call:

  prepare              FROM cluster, pg_tde preloaded: extension + global
                       provider + server key, ALTER SYSTEM pg_tde.wal_encrypt.
                       -> caller restarts the server
  setup                seed the standard dataset, check it is encrypted on
                       disk, write upgrade_check_state.json
                       -> caller performs the upgrade
  verify-before-alter  read-only: data, encryption state, providers and keys
                       unchanged, with the new pg_tde library on the old
                       extension catalog
                       -> caller runs ALTER EXTENSION pg_tde UPDATE
  verify               the same checks again, plus extversion, and that the
                       upgraded cluster is still usable (writes, new tables,
                       key rotation)

    pytest tests/test_tde_upgrade_check.py --upgrade-stage=setup \
        --upgrade-check-dir=/var/lib/pg_tde_upgrade_check

Key provider: file by default. When the caller drops a key_provider.json
into --upgrade-check-dir (written by the pg_tde/upgrade role for
KEY_PROVIDER=vault|openbao|kmip, with the KMS already running), the global
provider (server key, tde_c) and tde_a's database provider use that KMS;
tde_b always keeps a file provider, so every run also covers a mixed setup.

Without --upgrade-stage every test here is skipped, so full-suite runs are
unaffected.
"""
from __future__ import annotations

import json
import subprocess
import uuid
from pathlib import Path
from typing import Dict, List, Optional

import pytest

pytestmark = [pytest.mark.upgrade_check]

STATE_FILE = "upgrade_check_state.json"
SCHEMA = "upg"

GLOBAL_PROVIDER = "upg_global_provider"
SERVER_KEY = "upg_server_key"

# tde_a: database-scope provider, principal key rotated once before the upgrade
# tde_b: a second database-scope provider and key (per-database key isolation)
# tde_c: key from the global provider, default_table_access_method = tde_heap
#        and pg_tde.enforce_encryption = on
TDE_DBS = ("tde_a", "tde_b", "tde_c")

# Tables whose content is fingerprinted, with the column to order rows by.
DIGEST_TABLES = {
    "orders": "id",
    "toasty": "id",
    "measurements": "id, ts",
    "summary_mv": "bucket",
    "scratch_unlogged": "id",
    "plain_control": "id",
}


# ── plumbing ────────────────────────────────────────────────────────────────


def _stage(config) -> str:
    return (config.getoption("--upgrade-stage") or "").strip()


@pytest.fixture(autouse=True)
def _only_in_stage(request):
    """Run a test only in the stage(s) named by its @stages(...) marker."""
    current = _stage(request.config)
    if not current:
        pytest.skip("--upgrade-stage not given (staged upgrade checker)")
    m = request.node.get_closest_marker("stages")
    if m and current not in m.args:
        pytest.skip(f"not part of stage {current!r}")


def stages(*names):
    return pytest.mark.stages(*names)


VERIFY = ("verify-before-alter", "verify")


def psql(sql: str, db: str = "postgres") -> str:
    """Run SQL against the target cluster (PGHOST/PGPORT); stdout, unaligned."""
    proc = subprocess.run(
        ["psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-d", db, "-f", "-"],
        input=sql,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"psql -d {db} failed:\n{sql}\n--\n{proc.stderr}")
    return proc.stdout.strip()


def psql_fails(sql: str, db: str) -> Optional[str]:
    """Return the error text if ``sql`` fails, None if it succeeds."""
    try:
        psql(sql, db)
    except RuntimeError as e:
        return str(e)
    return None


# Function scope (like state below): a module-scoped fixture is set up before
# the autouse stage filter, and would create the directory -- or fail on
# permissions -- in full-suite runs that give no --upgrade-stage.
@pytest.fixture
def check_dir(request) -> Path:
    p = Path(request.config.getoption("--upgrade-check-dir"))
    p.mkdir(parents=True, exist_ok=True)
    return p


@pytest.fixture
def state(check_dir) -> Dict:
    f = check_dir / STATE_FILE
    if not f.exists():
        pytest.fail(f"{f} missing: run --upgrade-stage=setup on the FROM cluster first")
    return json.loads(f.read_text())


def _canary_hex(check_dir: Path) -> str:
    """One random marker per run, so stale bytes from older runs never match."""
    f = check_dir / "canary"
    if not f.exists():
        f.write_text(uuid.uuid4().hex)
    return f.read_text().strip()


def canary_tde(check_dir: Path) -> str:
    return "tdecanary" + _canary_hex(check_dir)


def canary_plain(check_dir: Path) -> str:
    return "plaincanary" + _canary_hex(check_dir)


# ── key providers ───────────────────────────────────────────────────────────


def key_provider_config(check_dir: Path) -> Dict:
    """{"type": "file"} unless the caller wrote key_provider.json:
      {"type": "vault", "url": ..., "mount": ..., "token_path": ..., "ca_path": null}
      {"type": "kmip", "host": ..., "port": ..., "cert_path": ..., "key_path": ..., "ca_path": ...}
    (openbao uses type "vault": same vault_v2 API.)"""
    f = check_dir / "key_provider.json"
    if not f.exists():
        return {"type": "file"}
    return json.loads(f.read_text())


def _lit(v) -> str:
    if v is None:
        return "NULL"
    if isinstance(v, int):
        return str(v)
    return "'" + str(v).replace("'", "''") + "'"


def _call_padded(fn: str, args: list, db: str) -> None:
    """SELECT fn(args...), padding trailing optional arguments (e.g. the
    vault_v2 namespace added in later pg_tde releases) with NULL."""
    nargs = int(psql(f"SELECT max(pronargs) FROM pg_proc WHERE proname = '{fn}';", db) or 0)
    if nargs < len(args):
        raise RuntimeError(f"{fn} takes {nargs} arguments, {len(args)} given")
    padded = list(args) + [None] * (nargs - len(args))
    psql(f"SELECT {fn}({', '.join(_lit(a) for a in padded)});", db)


def add_key_provider(scope: str, name: str, cfg: Dict, file_path: Path, db: str) -> None:
    """scope: 'global' or 'database'. *file_path* is used for type file."""
    kind = cfg["type"]
    if kind == "file":
        _call_padded(f"pg_tde_add_{scope}_key_provider_file", [name, str(file_path)], db)
    elif kind == "vault":
        _call_padded(
            f"pg_tde_add_{scope}_key_provider_vault_v2",
            [name, cfg["url"], cfg["mount"], cfg["token_path"], cfg.get("ca_path")],
            db,
        )
    elif kind == "kmip":
        _call_padded(
            f"pg_tde_add_{scope}_key_provider_kmip",
            [name, cfg["host"], int(cfg["port"]), cfg["cert_path"], cfg["key_path"], cfg.get("ca_path")],
            db,
        )
    else:
        raise ValueError(f"unknown key provider type {kind!r}")


# ── snapshot helpers ────────────────────────────────────────────────────────


def table_digests(db: str) -> Dict[str, List]:
    out = {}
    for table, order in DIGEST_TABLES.items():
        row = psql(
            f"SELECT count(*), md5(coalesce(string_agg(t::text, '|' ORDER BY {order}), '')) "
            f"FROM {SCHEMA}.{table} t;",
            db,
        )
        count, digest = row.split("|")
        out[table] = [int(count), digest]
    return out


def relations(db: str) -> Dict[str, Dict]:
    """
    Every storage-bearing relation of the dataset, keyed by a name that is
    stable across pg_upgrade (TOAST tables as "<table>:toast"), with its
    encryption state and on-disk path.
    """
    rows = psql(
        f"""
        WITH rels AS (
          SELECT c.relname AS key, c.oid FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = '{SCHEMA}' AND c.relkind IN ('r', 'i', 'm', 'S')
          UNION ALL
          SELECT c.relname || ':toast', c.reltoastrelid FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = '{SCHEMA}' AND c.reltoastrelid <> 0
        )
        SELECT key, pg_tde_is_encrypted(oid::regclass), pg_relation_filepath(oid::regclass)
        FROM rels ORDER BY key;
        """,
        db,
    )
    out = {}
    for line in rows.splitlines():
        key, enc, path = line.split("|")
        out[key] = {"encrypted": enc == "t", "path": path}
    return out


def providers(db: str) -> Dict[str, List]:
    """Key providers (name, type, options) visible from ``db``, by scope."""
    def listing(fn: str) -> List:
        return sorted(
            psql(f"SELECT name || '|' || type || '|' || options::text FROM {fn}();", db).splitlines()
        )
    return {
        "database": listing("pg_tde_list_all_database_key_providers"),
        "global": listing("pg_tde_list_all_global_key_providers"),
    }


def key_info(db: str) -> str:
    return psql("SELECT key_name || '|' || provider_name FROM pg_tde_key_info();", db)


def server_key_info() -> str:
    return psql("SELECT key_name || '|' || provider_name FROM pg_tde_server_key_info();")


def data_directory() -> Path:
    return Path(psql("SHOW data_directory;"))


def relation_files(datadir: Path, relpath: str) -> List[Path]:
    """Main fork segments of a relation: <relfilenode>, <relfilenode>.1, ..."""
    base = datadir / relpath
    files = [base] if base.exists() else []
    seg = 1
    while (datadir / f"{relpath}.{seg}").exists():
        files.append(datadir / f"{relpath}.{seg}")
        seg += 1
    return files


def files_containing(files: List[Path], needle: bytes) -> List[str]:
    hits = []
    for f in files:
        try:
            if needle in f.read_bytes():
                hits.append(str(f))
        except FileNotFoundError:  # WAL segment recycled while scanning
            continue
    return hits


def assert_ciphertext_on_disk(check_dir: Path) -> None:
    """
    After a CHECKPOINT the tde canary must not appear in any relation file of
    the dataset, nor in pg_wal (WAL encryption is on). The plain_control
    table is the control: its canary must be found, which proves the scan
    reads the right files.
    """
    psql("CHECKPOINT;")
    datadir = data_directory()
    tde_needle = canary_tde(check_dir).encode()
    plain_needle = canary_plain(check_dir).encode()
    leaks, control_found = [], False
    for db in TDE_DBS:
        for key, rel in relations(db).items():
            files = relation_files(datadir, rel["path"])
            if key.startswith("plain_control"):
                control_found |= bool(files_containing(files, plain_needle))
                continue
            leaks += [f"{db}.{key}: {p}" for p in files_containing(files, tde_needle)]
    assert control_found, "control canary not found in plain_control's files: the on-disk scan is broken"
    assert not leaks, "plaintext tde canary found on disk:\n" + "\n".join(leaks)

    wal = [p for p in (datadir / "pg_wal").iterdir() if p.is_file() and len(p.name) == 24]
    wal_leaks = files_containing(wal, tde_needle) + files_containing(wal, plain_needle)
    assert not wal_leaks, "plaintext canary found in WAL with pg_tde.wal_encrypt on:\n" + "\n".join(wal_leaks)


# ── stage: prepare ──────────────────────────────────────────────────────────


@stages("prepare")
def test_prepare_server_key_and_wal_encryption(check_dir):
    psql("CREATE EXTENSION IF NOT EXISTS pg_tde;")
    add_key_provider(
        "global", GLOBAL_PROVIDER, key_provider_config(check_dir),
        check_dir / "global_keyring.per", "postgres",
    )
    psql(
        f"""
        SELECT pg_tde_create_key_using_global_key_provider('{SERVER_KEY}', '{GLOBAL_PROVIDER}');
        SELECT pg_tde_set_server_key_using_global_key_provider('{SERVER_KEY}', '{GLOBAL_PROVIDER}');
        ALTER SYSTEM SET pg_tde.wal_encrypt = on;
        """
    )


# ── stage: setup ────────────────────────────────────────────────────────────


@stages("setup")
def test_setup_wal_encryption_active():
    assert psql("SHOW pg_tde.wal_encrypt;") == "on", (
        "pg_tde.wal_encrypt is not on: restart the server after --upgrade-stage=prepare"
    )


def _seed_keys(db: str, check_dir: Path) -> None:
    psql("CREATE EXTENSION pg_tde;", db)
    if db == "tde_c":
        psql(
            f"""
            SELECT pg_tde_create_key_using_global_key_provider('upg_tde_c_key', '{GLOBAL_PROVIDER}');
            SELECT pg_tde_set_key_using_global_key_provider('upg_tde_c_key', '{GLOBAL_PROVIDER}');
            """,
            db,
        )
        return
    provider = f"upg_{db}_provider"
    # tde_a follows the configured KMS; tde_b always uses a file provider.
    cfg = key_provider_config(check_dir) if db == "tde_a" else {"type": "file"}
    add_key_provider("database", provider, cfg, check_dir / (db + "_keyring.per"), db)
    psql(
        f"""
        SELECT pg_tde_create_key_using_database_key_provider('upg_{db}_key1', '{provider}');
        SELECT pg_tde_set_key_using_database_key_provider('upg_{db}_key1', '{provider}');
        """,
        db,
    )


def _seed_data(db: str, check_dir: Path) -> None:
    # tde_c defaults to tde_heap, so its tables get it without USING; the
    # other databases ask for it explicitly.
    am = "" if db == "tde_c" else "USING tde_heap"
    tde, plain = canary_tde(check_dir), canary_plain(check_dir)
    psql(
        f"""
        CREATE SCHEMA {SCHEMA};

        CREATE TABLE {SCHEMA}.orders (
          id      bigserial PRIMARY KEY,
          payload text      NOT NULL,
          tags    int[]     NOT NULL,
          amount  numeric   CHECK (amount >= 0)
        ) {am};
        CREATE INDEX orders_payload_btree ON {SCHEMA}.orders (payload);
        CREATE INDEX orders_id_hash ON {SCHEMA}.orders USING hash (id);
        CREATE INDEX orders_tags_gin ON {SCHEMA}.orders USING gin (tags);
        CREATE INDEX orders_big_amount ON {SCHEMA}.orders (amount) WHERE amount > 900;
        INSERT INTO {SCHEMA}.orders (payload, tags, amount)
          SELECT '{tde}-' || i, ARRAY[i % 7, i % 11], i % 1000
          FROM generate_series(1, 5000) i;

        -- 300 KB values, stored out of line and uncompressed so the canary
        -- would be visible in the TOAST relation if it were not encrypted
        CREATE TABLE {SCHEMA}.toasty (id int PRIMARY KEY, blob text) {am};
        ALTER TABLE {SCHEMA}.toasty ALTER COLUMN blob SET STORAGE EXTERNAL;
        INSERT INTO {SCHEMA}.toasty
          SELECT i, '{tde}' || string_agg(md5(i::text || g::text), '')
          FROM generate_series(1, 3) i, generate_series(1, 10000) g GROUP BY i;

        CREATE TABLE {SCHEMA}.measurements (id int, ts date, v text)
          PARTITION BY RANGE (ts);
        CREATE TABLE {SCHEMA}.measurements_2025 PARTITION OF {SCHEMA}.measurements
          FOR VALUES FROM ('2025-01-01') TO ('2026-01-01') {am};
        CREATE TABLE {SCHEMA}.measurements_2026 PARTITION OF {SCHEMA}.measurements
          FOR VALUES FROM ('2026-01-01') TO ('2027-01-01') {am};
        INSERT INTO {SCHEMA}.measurements
          SELECT i, date '2025-01-01' + (i % 700), '{tde}-m' || i
          FROM generate_series(1, 4000) i;

        CREATE MATERIALIZED VIEW {SCHEMA}.summary_mv {am} AS
          SELECT amount::int / 100 AS bucket, count(*) AS n, '{tde}' AS tag
          FROM {SCHEMA}.orders GROUP BY 1;

        CREATE UNLOGGED TABLE {SCHEMA}.scratch_unlogged (id int PRIMARY KEY, v text) {am};
        INSERT INTO {SCHEMA}.scratch_unlogged SELECT i, '{tde}-u' || i FROM generate_series(1, 500) i;

        -- control: a plain heap table in the same database
        CREATE TABLE {SCHEMA}.plain_control (id int PRIMARY KEY, v text) USING heap;
        INSERT INTO {SCHEMA}.plain_control SELECT i, '{plain}-' || i FROM generate_series(1, 500) i;

        -- key-slot churn (PG-2381): dropped and rewritten tde relations
        CREATE TABLE {SCHEMA}.churn (id int) {am};
        INSERT INTO {SCHEMA}.churn SELECT generate_series(1, 1000);
        DROP TABLE {SCHEMA}.churn;
        VACUUM FULL {SCHEMA}.orders;
        """,
        db,
    )


@stages("setup")
def test_setup_seed_dataset(check_dir):
    for db in TDE_DBS:
        psql(f"CREATE DATABASE {db};")
    psql("ALTER DATABASE tde_c SET default_table_access_method = tde_heap;")
    for db in TDE_DBS:
        _seed_keys(db, check_dir)
        _seed_data(db, check_dir)
    # Only after seeding: it would refuse tde_c's plain_control heap table.
    psql("ALTER DATABASE tde_c SET pg_tde.enforce_encryption = on;")
    # Rotate tde_a's principal key, so the upgrade carries rotation history.
    psql(
        "SELECT pg_tde_create_key_using_database_key_provider('upg_tde_a_key2', 'upg_tde_a_provider');"
        "SELECT pg_tde_set_key_using_database_key_provider('upg_tde_a_key2', 'upg_tde_a_provider');",
        "tde_a",
    )


@stages("setup")
def test_setup_key_provider_type(check_dir):
    """The KMS providers really are of the configured type (no silent file fallback)."""
    want = key_provider_config(check_dir)["type"]
    got_global = psql(
        f"SELECT type FROM pg_tde_list_all_global_key_providers() WHERE name = '{GLOBAL_PROVIDER}';"
    )
    got_tde_a = psql(
        "SELECT type FROM pg_tde_list_all_database_key_providers() WHERE name = 'upg_tde_a_provider';",
        "tde_a",
    )
    # pg_tde reports vault_v2 for the vault/openbao provider
    expect = {"file": "file", "vault": "vault-v2", "kmip": "kmip"}[want]
    assert (got_global, got_tde_a) == (expect, expect), (got_global, got_tde_a, want)


@stages("setup")
def test_setup_encryption_state():
    for db in TDE_DBS:
        for key, rel in relations(db).items():
            if key.startswith("plain_control"):
                assert not rel["encrypted"], f"{db}.{key} should be plain heap"
            elif not key.endswith("_seq"):
                assert rel["encrypted"], f"{db}.{key} is not encrypted on the FROM cluster"


@stages("setup")
def test_setup_ciphertext_on_disk(check_dir):
    assert_ciphertext_on_disk(check_dir)


@stages("setup")
def test_setup_write_state(check_dir):
    snapshot = {
        "wal_encrypt": psql("SHOW pg_tde.wal_encrypt;"),
        "key_provider": key_provider_config(check_dir)["type"],
        "server_key": server_key_info(),
        "from": {
            "server_version_num": psql("SHOW server_version_num;"),
            "pg_tde_version": psql("SELECT pg_tde_version();"),
            "extversion": psql("SELECT extversion FROM pg_extension WHERE extname = 'pg_tde';"),
        },
        "dbs": {},
    }
    for db in TDE_DBS:
        snapshot["dbs"][db] = {
            "tables": table_digests(db),
            "encrypted": {k: v["encrypted"] for k, v in relations(db).items()},
            "providers": providers(db),
            "key": key_info(db),
            "default_am": psql("SHOW default_table_access_method;", db),
            "enforce_encryption": psql("SHOW pg_tde.enforce_encryption;", db),
        }
    (check_dir / STATE_FILE).write_text(json.dumps(snapshot, indent=2, sort_keys=True))


# ── stages: verify-before-alter, verify ──────────────────────────────────────


@stages(*VERIFY)
def test_verify_wal_encryption(state):
    assert psql("SHOW pg_tde.wal_encrypt;") == state["wal_encrypt"]


@stages(*VERIFY)
@pytest.mark.parametrize("db", TDE_DBS)
def test_verify_table_data(state, db):
    assert table_digests(db) == state["dbs"][db]["tables"]


@stages(*VERIFY)
@pytest.mark.parametrize("db", TDE_DBS)
def test_verify_encryption_state(state, db):
    now = {k: v["encrypted"] for k, v in relations(db).items()}
    assert now == state["dbs"][db]["encrypted"]


@stages(*VERIFY)
@pytest.mark.parametrize("db", TDE_DBS)
def test_verify_providers_and_keys(state, db):
    want = state["dbs"][db]
    assert providers(db) == want["providers"]
    assert key_info(db) == want["key"]


@stages(*VERIFY)
def test_verify_server_key(state):
    assert server_key_info() == state["server_key"]


@stages(*VERIFY)
def test_verify_database_settings(state):
    for db in TDE_DBS:
        assert psql("SHOW default_table_access_method;", db) == state["dbs"][db]["default_am"]
        assert psql("SHOW pg_tde.enforce_encryption;", db) == state["dbs"][db]["enforce_encryption"]


@stages(*VERIFY)
def test_verify_ciphertext_on_disk(check_dir, state):
    assert_ciphertext_on_disk(check_dir)


# ── stage: verify only (after ALTER EXTENSION, may write) ───────────────────


@stages("verify")
@pytest.mark.parametrize("db", TDE_DBS)
def test_verify_extension_version(db):
    row = psql(
        "SELECT e.extversion || '|' || a.default_version FROM pg_extension e "
        "JOIN pg_available_extensions a ON a.name = e.extname WHERE e.extname = 'pg_tde';",
        db,
    )
    ext, default = row.split("|")
    assert ext == default, f"{db}: extversion {ext} != default_version {default}"


@stages("verify")
def test_verify_enforce_encryption_still_blocks_plain_tables():
    err = psql_fails(f"CREATE TABLE {SCHEMA}.must_fail (i int) USING heap;", "tde_c")
    assert err is not None, "tde_c: enforce_encryption no longer blocks heap tables"


@stages("verify")
@pytest.mark.parametrize("db", TDE_DBS)
def test_verify_cluster_still_usable(check_dir, db):
    am = "" if db == "tde_c" else "USING tde_heap"
    tde = canary_tde(check_dir)
    psql(
        f"""
        INSERT INTO {SCHEMA}.orders (payload, tags, amount)
          SELECT '{tde}-post-' || i, ARRAY[i], i FROM generate_series(1, 100) i;
        CREATE TABLE {SCHEMA}.post_upgrade (id int PRIMARY KEY, v text) {am};
        INSERT INTO {SCHEMA}.post_upgrade SELECT i, '{tde}-new' || i FROM generate_series(1, 100) i;
        REFRESH MATERIALIZED VIEW {SCHEMA}.summary_mv;
        """,
        db,
    )
    assert psql(f"SELECT pg_tde_is_encrypted('{SCHEMA}.post_upgrade'::regclass);", db) == "t"
    assert psql(f"SELECT count(*) FROM {SCHEMA}.orders WHERE payload LIKE '{tde}-post-%';", db) == "100"


@stages("verify")
def test_verify_key_rotation_after_upgrade(state):
    psql(
        f"SELECT pg_tde_create_key_using_global_key_provider('upg_server_key2', '{GLOBAL_PROVIDER}');"
        f"SELECT pg_tde_set_server_key_using_global_key_provider('upg_server_key2', '{GLOBAL_PROVIDER}');"
    )
    psql(
        "SELECT pg_tde_create_key_using_database_key_provider('upg_tde_a_key3', 'upg_tde_a_provider');"
        "SELECT pg_tde_set_key_using_database_key_provider('upg_tde_a_key3', 'upg_tde_a_provider');",
        "tde_a",
    )
    assert server_key_info().startswith("upg_server_key2|")
    assert key_info("tde_a").startswith("upg_tde_a_key3|")
    # Old data is still readable under the new keys.
    before = state["dbs"]["tde_a"]["tables"]["toasty"]
    assert table_digests("tde_a")["toasty"] == before


@stages("verify")
def test_verify_ciphertext_on_disk_after_writes(check_dir):
    assert_ciphertext_on_disk(check_dir)
