"""EXPECTED_VERSIONS: expected component versions given at run time.

ppg/tests/settings.py normally takes expected component versions from the
tables in ppg/tests/versions/*.py, keyed by PPG release. percona-obs qa sends
every OBS QA job EXPECTED_VERSIONS: the versions OBS builds for the packages
under test, package=version per line keyed by OBS package name.
The tests use those instead, so a component bump does not need a manual edit.
"""

import importlib
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
        assert key in current, key


def test_get_settings_applies_only_to_the_release_under_test(settings, monkeypatch):
    monkeypatch.setenv("EXPECTED_VERSIONS", FROM_OBS)
    all_settings = settings.get_settings("rocky-9")
    assert all_settings["ppg-18.6"]["pgbackrest"]["binary_version"] == "pgBackRest 2.59.2"
    assert all_settings["ppg-18.4"]["pgbackrest"]["version"] != "2.59.2"
