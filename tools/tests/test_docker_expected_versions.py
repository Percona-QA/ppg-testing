"""EXPECTED_VERSIONS in the Docker image tests' settings.

OBS QA passes the versions OBS builds as package=version lines keyed by OBS
source package name (percona-pgbackrest=2.59.2). The Docker settings key the
packages installed in the image, whose names carry the PG major
(percona-pgaudit18, percona-postgis35_18-client); apply_expected_versions maps
one to the other. Covers ppg-docker and the custom settings (shared by
ppg-docker-custom and ppg-docker-custom-upgrade, which must stay identical).
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


def test_custom_copies_are_identical():
    upgrade = DOCKER / "ppg-docker-custom-upgrade" / "files" / "settings.py"
    assert SETTINGS["custom"].read_text() == upgrade.read_text()


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
