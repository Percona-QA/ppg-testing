"""EXPECTED_VERSIONS in the Docker image tests' settings.

OBS QA passes the versions OBS builds as package=version lines keyed by OBS
source package name (percona-pgbackrest=2.59.2). The Docker settings key the
packages installed in the image, whose names carry the PG major
(percona-pgaudit18, percona-postgis35_18-client); apply_expected_versions maps
one to the other. Covers the ppg-docker and ppg-docker-custom settings.
"""

import importlib.util
import pathlib

import pytest

DOCKER = pathlib.Path(__file__).resolve().parents[2] / "docker"
SETTINGS = {
    "ppg-docker": DOCKER / "ppg-docker" / "files" / "settings.py",
    "custom": DOCKER / "ppg-docker-custom" / "files" / "settings.py",
}
RELEASE = "18.6"

# OBS source package -> image package keys it must update for PG 18
EXPECTED_KEYS = {
    "percona-pgbackrest": ["percona-pgbackrest"],
    "percona-patroni": ["percona-patroni"],
    "percona-pgaudit": ["percona-pgaudit18"],
    "percona-pgaudit_set_user": ["percona-pgaudit18_set_user"],
    "percona-pg_repack": ["percona-pg_repack18"],
    "percona-wal2json": ["percona-wal2json18"],
    "percona-pg_stat_monitor": ["percona-pg_stat_monitor18"],
    "percona-pg_cron": ["percona-pg_cron_18"],
    "percona-pgvector": ["percona-pgvector_18", "percona-pgvector_18-llvmjit"],
    "percona-pg_oidc_validator": ["percona-pg_oidc_validator18"],
    "percona-postgis": ["percona-postgis35_18", "percona-postgis35_18-client",
                        "percona-postgis35_18-gui", "percona-postgis35_18-llvmjit",
                        "percona-postgis35_18-utils"],
}


def _load(path):
    spec = importlib.util.spec_from_file_location(f"docker_settings_{path.parent.parent.name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(params=sorted(SETTINGS))
def settings(request, monkeypatch):
    monkeypatch.delenv("EXPECTED_VERSIONS", raising=False)
    return _load(SETTINGS[request.param])


def _entry(settings):
    return dict(settings.ppg_versions[RELEASE])


def test_no_spec_changes_nothing(settings):
    entry = _entry(settings)
    assert settings.apply_expected_versions(entry, "", "18") is entry


def test_pgbackrest_bump_updates_derived_fields(settings):
    out = settings.apply_expected_versions(_entry(settings), "percona-pgbackrest=2.59.2", "18")
    assert out["percona-pgbackrest"]["version"] == "2.59.2"
    assert out["percona-pgbackrest"]["binary_version"] == "pgBackRest 2.59.2"


@pytest.mark.parametrize("package", sorted(EXPECTED_KEYS))
def test_every_mapped_package_reaches_its_image_keys(settings, package):
    entry = _entry(settings)
    keys = [k for k in EXPECTED_KEYS[package] if k in entry]
    assert keys, f"{package}: none of {EXPECTED_KEYS[package]} in the {RELEASE} entry"
    out = settings.apply_expected_versions(entry, f"{package}=99.9.9", "18")
    for key in keys:
        assert out[key]["version"] == "99.9.9", key


def test_other_majors_keys_are_untouched(settings):
    out = settings.apply_expected_versions(_entry(settings), "percona-pgaudit=99.9.9", "17")
    assert out["percona-pgaudit18"] == _entry(settings)["percona-pgaudit18"]


def test_unknown_packages_are_ignored(settings):
    entry = _entry(settings)
    assert settings.apply_expected_versions(entry, "etcd=3.5.33\npython3-psycopg2=2.9.13", "18") == entry


@pytest.mark.parametrize("spec", ["percona-pgbackrest", "percona-pgbackrest=", "=2.59.2"])
def test_malformed_lines_fail_loudly(settings, spec):
    with pytest.raises(ValueError, match="is not package=version"):
        settings.apply_expected_versions(_entry(settings), spec, "18")


def test_get_settings_applies_the_environment(settings, monkeypatch):
    monkeypatch.setenv("EXPECTED_VERSIONS", "percona-pgbackrest=2.59.2\npercona-patroni=4.1.5")
    out = settings.get_settings(RELEASE)
    assert out["percona-pgbackrest"]["binary_version"] == "pgBackRest 2.59.2"
    assert out["percona-patroni"]["version"] == "4.1.5"


def test_server_rpms_follow_percona_postgresql(settings):
    out = settings.apply_expected_versions(_entry(settings), "percona-postgresql=18.6.1", "18")
    server = [k for k in out["rpm_packages"] if k.startswith("percona-postgresql18")]
    assert server, "no server RPMs listed for the release"
    for key in server:
        assert out[key] == {"version": "18.6.1"}, key


def test_server_rpms_untouched_without_expected_versions(settings):
    entry = _entry(settings)
    assert not any(isinstance(entry.get(k), dict) for k in entry["rpm_packages"] if k.startswith("percona-postgresql18"))


# --- custom (extras) image -----------------------------------------------------

EXTRAS = ["percona-timescaledb", "percona-h3-pg", "percona-pgrouting", "percona-hll", "percona-ip4r",
          "percona-pg_partman", "percona-pgvectorscale", "percona-rum",
          "percona-postgresql-unit", "percona-postgresql_anonymizer"]


@pytest.fixture
def custom(monkeypatch):
    monkeypatch.delenv("EXPECTED_VERSIONS", raising=False)
    return _load(SETTINGS["custom"])


@pytest.mark.parametrize("package", EXTRAS)
def test_custom_extras_follow_obs(custom, package):
    entry = dict(custom.ppg_versions[RELEASE])
    key = f"{package}_18"
    assert key in entry, f"{key} not in the {RELEASE} table"
    out = custom.apply_expected_versions(entry, f"{package}=99.9.9", "18")
    assert out[key]["version"] == "99.9.9"


def test_custom_extras_take_what_obs_builds(custom, monkeypatch):
    # what OBS QA sends for ppg:staging:18:extras:containers (excerpt)
    monkeypatch.setenv("EXPECTED_VERSIONS", "percona-pgvectorscale=0.9.0\npercona-postgresql_anonymizer=3.1.1\n"
                       "percona-timescaledb=2.28.1\npercona-pgrouting=4.0.1\npercona-pg_partman=5.4.3")
    out = custom.get_settings(RELEASE)
    assert out["percona-pgvectorscale_18"]["version"] == "0.9.0"          # table: 0.9.1
    assert out["percona-postgresql_anonymizer_18"]["version"] == "3.1.1"  # table: 3.2.2
    assert out["percona-timescaledb_18"]["version"] == "2.28.1"


def test_every_package_the_custom_tests_read_is_mapped(custom):
    """A new extension test in test_docker.py needs its OBS package mapped too."""
    import re
    tests = (DOCKER / "ppg-docker-custom" / "files" / "test_docker.py").read_text()
    read = set(re.findall(r'pkg_key = f"(percona-[^"{]+)\{MAJOR_VER\}"', tests))
    entry = dict(custom.ppg_versions[RELEASE])
    mapped = set()
    for name in list(custom.EXPECTED_VERSION_PACKAGES) + ["percona-postgis", "percona-postgresql"]:
        mapped.update(custom._expected_version_keys(entry, name, "18"))
    # pg_similarity: the test checks the SQL extension version, not the package
    # version, so it deliberately keeps the table value (see settings.py).
    not_from_obs = {"percona-pg_similarity_18"}
    missing = sorted(prefix + "18" for prefix in read if prefix + "18" not in mapped | not_from_obs)
    assert read, "no pkg_key reads found in test_docker.py"
    assert not missing, f"read by test_docker.py but not mapped from EXPECTED_VERSIONS: {missing}"


def test_pg_similarity_keeps_the_table_value(custom, monkeypatch):
    # OBS QA sends the tag name for it; it must not reach the test
    monkeypatch.setenv("EXPECTED_VERSIONS", "percona-pg_similarity=pg_similarity_1_0")
    assert custom.get_settings(RELEASE)["percona-pg_similarity_18"]["version"] == "1.0"


def _load(path):
    spec = importlib.util.spec_from_file_location("settings_" + path.parent.parent.name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("role", sorted(SETTINGS))
def test_binary_version_contains_version(role):
    """apply_expected_versions updates binary_version by replacing the old
    version inside it; an entry whose binary_version does not contain its
    version (e.g. version 2.59.1, binary_version "pgBackRest 2.59.2") keeps
    the stale binary version and fails the image test against OBS builds."""
    bad = [
        f"{rel} {pkg}: version {v['version']!r}, binary_version {v['binary_version']!r}"
        for rel, entry in _load(SETTINGS[role]).ppg_versions.items()
        for pkg, v in entry.items()
        if isinstance(v, dict) and "version" in v and isinstance(v.get("binary_version"), str)
        and v["version"] not in v["binary_version"]
    ]
    assert not bad, "binary_version must contain version:\n  " + "\n  ".join(bad)


@pytest.mark.parametrize("role", sorted(SETTINGS))
def test_expected_versions_update_pgbackrest_binary_version(role):
    """The case that failed for PG 16: OBS builds pgBackRest 2.60.0."""
    mod = _load(SETTINGS[role])
    for rel in ("16.15", "17.11", "18.6"):
        entry = mod.apply_expected_versions(
            {k: dict(v) if isinstance(v, dict) else v for k, v in mod.ppg_versions[rel].items()},
            "percona-pgbackrest=2.60.0", rel.split(".")[0])
        assert entry["percona-pgbackrest"]["version"] == "2.60.0"
        if "binary_version" in entry["percona-pgbackrest"]:
            assert entry["percona-pgbackrest"]["binary_version"] == "pgBackRest 2.60.0", rel
