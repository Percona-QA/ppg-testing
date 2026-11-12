"""EXPECTED_VERSIONS: expected component versions given at run time.

ppg/tests/settings.py normally takes expected component versions from the
tables in ppg/tests/versions/*.py, keyed by PPG release. percona-obs qa sends
every OBS QA job EXPECTED_VERSIONS: the versions OBS builds for the packages
under test, package=version per line keyed by OBS package name.
The tests use those instead, so a component bump does not need a manual edit.
"""

import importlib
import importlib.util
import pathlib
import sys

import pytest

PPG_DIR = pathlib.Path(__file__).resolve().parents[2] / "ppg"


@pytest.fixture
def settings(monkeypatch):
    """ppg/tests/settings.py, imported for VERSION=ppg-18.6."""
    monkeypatch.setenv("VERSION", "ppg-18.6")
    monkeypatch.delenv("EXPECTED_VERSIONS", raising=False)
    monkeypatch.syspath_prepend(str(PPG_DIR))
    for name in [m for m in sys.modules if m == "tests" or m.startswith("tests.")]:
        monkeypatch.delitem(sys.modules, name)
    return importlib.import_module("tests.settings")


ENTRY = {
    "version": "18.6",
    "pgbackrest": {"version": "2.59.1", "binary_version": "pgBackRest 2.59.1"},
    "pg_gather": {"version": "33", "sql_file_version": "33"},
    "pgvector": {"version": "0.8.6", "extension_version": "0.8.6"},
}

# What percona-obs qa sends: every package of the project, most unknown here.
FROM_OBS = "\n".join([
    "etcd=3.5.33",
    "percona-patroni=4.1.5",
    "percona-pg_gather=34",
    "percona-pgbackrest=2.59.2",
    "percona-postgresql=18.6.1",
    "python3-psycopg2=2.9.13",
])


def test_no_spec_changes_nothing(settings):
    assert settings.apply_expected_versions(ENTRY, "") is ENTRY
    assert settings.apply_expected_versions(ENTRY, "  \n") is ENTRY


def test_obs_values_override_the_tables(settings):
    out = settings.apply_expected_versions(ENTRY, FROM_OBS)
    assert out["pgbackrest"] == {"version": "2.59.2", "binary_version": "pgBackRest 2.59.2"}
    assert out["pg_gather"] == {"version": "34", "sql_file_version": "34"}
    assert out["pgvector"] == ENTRY["pgvector"]                 # not in the input
    assert ENTRY["pgbackrest"]["version"] == "2.59.1"           # input not modified


def test_unknown_macros_and_unshipped_components_are_ignored(settings):
    out = settings.apply_expected_versions(ENTRY, "python3-six=1.17.0\netcd=3.5.40")
    assert out == ENTRY


@pytest.mark.parametrize("spec", ["percona-pgbackrest=2.59.2, percona-pg_gather=34",
                                  "percona-pgbackrest=2.59.2 percona-pg_gather=34\n"])
def test_other_separators(settings, spec):
    out = settings.apply_expected_versions(ENTRY, spec)
    assert out["pgbackrest"]["version"] == "2.59.2" and out["pg_gather"]["version"] == "34"


@pytest.mark.parametrize("spec", ["percona-pgbackrest", "percona-pgbackrest=", "=2.59.2"])
def test_malformed_lines_fail_loudly(settings, spec):
    with pytest.raises(ValueError, match="is not package=version"):
        settings.apply_expected_versions(ENTRY, spec)


def test_every_mapped_key_exists_in_a_real_release(settings):
    current = settings.get_settings("rocky-9")["ppg-18.6"]
    for key in settings.EXPECTED_VERSION_PACKAGES.values():
        if key in settings.EXPECTED_VERSION_CREATE:
            continue  # absent from the tables by design, created on demand
        assert key in current, key


def test_get_settings_applies_only_to_the_release_under_test(settings, monkeypatch):
    monkeypatch.setenv("EXPECTED_VERSIONS", FROM_OBS)
    all_settings = settings.get_settings("rocky-9")
    assert all_settings["ppg-18.6"]["pgbackrest"]["binary_version"] == "pgBackRest 2.59.2"
    assert all_settings["ppg-18.4"]["pgbackrest"]["version"] != "2.59.2"


def test_credcheck_entry_is_created_only_when_given(settings):
    assert "credcheck" not in settings.apply_expected_versions(ENTRY, "percona-pgbackrest=2.59.2")
    out = settings.apply_expected_versions(ENTRY, "percona-credcheck=5.0")
    assert out["credcheck"] == {"version": "5.0"}


def test_flat_fields_follow(settings):
    entry = {**ENTRY, "PGSM_version": "2.4.0", "PGSM_package_version": "2.4.0", "PGSM_sql_version": "2.4.0",
             "postgis_version": "3.5.7", "postgis_package_version": "3.5.7", "postgis_major_version": "3.5"}
    out = settings.apply_expected_versions(entry, "percona-pg_stat_monitor=2.4.1 percona-postgis=3.6.0")
    assert (out["PGSM_version"], out["PGSM_package_version"]) == ("2.4.1", "2.4.1")
    assert out["PGSM_sql_version"] == "2.4.0"  # SQL version is not the package version
    assert (out["postgis_version"], out["postgis_major_version"]) == ("3.6.0", "3.6")


def test_flat_fields_absent_from_the_release_stay_absent(settings):
    out = settings.apply_expected_versions(ENTRY, "percona-postgis=3.6.0")
    assert "postgis_version" not in out


@pytest.mark.parametrize("version,percona_version,server_version", [
    ("19.0", "19.0.1~beta4", "19beta4"),
    ("19.0", "19.0.1~rc1", "19rc1"),
    ("20.0", "20.0.1~alpha2", "20alpha2"),
    ("19.0", "19.0.1", None),            # final release: no pre-release marker
    ("18.6", "18.6.1", None),
    ("19.1", "19.1.1~beta2", None),      # a marker is only valid on Major.0
    ("20.1", "20.1.1~rc1", None),
])
def test_prerelease_server_version_only_for_major_dot_zero(settings, version, percona_version, server_version):
    entry = {"version": version, "percona-version": percona_version}
    assert settings.prerelease_server_version(entry) == server_version


def test_is_prerelease_is_true_for_any_marker(settings):
    assert settings.is_prerelease({"percona-version": "19.0.1~beta4"})
    assert settings.is_prerelease({"percona-version": "19.1.1~rc1"})   # the tests then fail, 19.1 has no pre-release
    assert not settings.is_prerelease({"percona-version": "19.0.1"})
    assert not settings.is_prerelease({})


def test_postgresql_common_follows_obs(settings):
    """postgresql-common 293 -> 294 in OBS: both packages its source package
    builds must follow, or the package tests fail after every bump."""
    entry = {"percona-postgresql-common": "293", "percona-postgresql-client-common": "293"}
    out = settings.apply_expected_versions(entry, "percona-postgresql-common=294")
    assert out == {"percona-postgresql-common": "294", "percona-postgresql-client-common": "294"}
    assert entry["percona-postgresql-common"] == "293"  # the table itself is untouched


@pytest.mark.parametrize("role", ["ppg-docker", "ppg-docker-custom"])
def test_docker_postgresql_common_follows_obs(role, monkeypatch):
    path = PPG_DIR.parent / "docker" / role / "files" / "settings.py"
    monkeypatch.syspath_prepend(str(path.parent))
    spec = importlib.util.spec_from_file_location(f"docker_settings_{role}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    entry = {"percona-postgresql-common": "293", "percona-postgresql-client-common": "293",
             "percona-pgbackrest": {"version": "2.59.1"}}
    out = mod.apply_expected_versions(entry, "percona-postgresql-common=294\npercona-pgbackrest=2.60.0", "18")
    assert out["percona-postgresql-common"] == "294" and out["percona-postgresql-client-common"] == "294"
    assert out["percona-pgbackrest"]["version"] == "2.60.0"  # dict entries as before


def test_postgresql_common_updates_the_deb_package_list(settings):
    """The deb check takes postgresql-common's version from deb_pkg_ver, not
    from the flat fields: EXPECTED_VERSIONS must update both."""
    entry = {
        "percona-postgresql-common": "293",
        "percona-postgresql-client-common": "293",
        "deb_pkg_ver": ["3:18.6-1.bookworm", "1:293-1.bookworm", "293-1.bookworm", "1:293-1.noble"],
    }
    out = settings.apply_expected_versions(entry, "percona-postgresql-common=294")
    assert out["deb_pkg_ver"] == ["3:18.6-1.bookworm", "1:294-1.bookworm", "294-1.bookworm", "1:294-1.noble"]
    assert settings.deb_version_matches("1:294-1+1.1.bookworm", out["deb_pkg_ver"])
    assert entry["deb_pkg_ver"][1] == "1:293-1.bookworm"  # the table itself is untouched


def test_metapackage_versions_carry_the_major(settings):
    """obs-packaging 82a4e15a versions the metapackages (percona-postgresql,
    -client, -contrib, -doc, -all, -server-dev-all) as 2:<major>+<common>,
    e.g. 2:15+294-1, while the common packages stay 1:294-1."""
    entry = {
        "percona-postgresql-common": "293",
        "deb_pkg_ver": ["2:15.20-1.bookworm", "1:293-1.bookworm", "293-1.bookworm", "2:15+293-1.bookworm"],
    }
    out = settings.apply_expected_versions(entry, "percona-postgresql-common=294")
    assert out["deb_pkg_ver"] == ["2:15.20-1.bookworm", "1:294-1.bookworm", "294-1.bookworm", "2:15+294-1.bookworm"]
    assert settings.deb_version_matches("2:15+294-1+1.1.bookworm", out["deb_pkg_ver"])  # metapackage
    assert settings.deb_version_matches("1:294-1+1.1.bookworm", out["deb_pkg_ver"])  # common package
    # an old major's metapackage left behind by an upgrade must not pass
    assert not settings.deb_version_matches("2:14+294-1+1.1.bookworm", out["deb_pkg_ver"])
