"""EXPECTED_VERSIONS: expected component versions given at run time.

ppg/tests/settings.py normally takes expected component versions from the
tables in ppg/tests/versions/*.py, keyed by PPG release. percona-obs qa sends
every OBS QA job EXPECTED_VERSIONS: obs-packaging's *_VERSION macros
(NAME=value per line), the versions OBS builds for the project under test.
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

# What percona-obs qa sends: every *_VERSION macro, most unknown to the tests.
FROM_OBS = "\n".join([
    "PATRONI_VERSION=4.1.5",
    "PGBACKREST_VERSION=2.59.2",
    "PG_GATHER_VERSION=34",
    "PG_PREV_MAJOR_VERSION=17",
    "PG_VERSION=18.6",
    "TIMESCALEDB_VERSION=2.28.1",
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
    out = settings.apply_expected_versions(ENTRY, "TIMESCALEDB_VERSION=2.28.1\nETCD_VERSION=3.5.40")
    assert out == ENTRY


@pytest.mark.parametrize("spec", ["PGBACKREST_VERSION=2.59.2, PG_GATHER_VERSION=34",
                                  "PGBACKREST_VERSION=2.59.2 PG_GATHER_VERSION=34\n"])
def test_other_separators(settings, spec):
    out = settings.apply_expected_versions(ENTRY, spec)
    assert out["pgbackrest"]["version"] == "2.59.2" and out["pg_gather"]["version"] == "34"


@pytest.mark.parametrize("spec", ["PGBACKREST_VERSION", "PGBACKREST_VERSION=", "=2.59.2"])
def test_malformed_lines_fail_loudly(settings, spec):
    with pytest.raises(ValueError, match="is not NAME=value"):
        settings.apply_expected_versions(ENTRY, spec)


def test_every_mapped_key_exists_in_a_real_release(settings):
    current = settings.get_settings("rocky-9")["ppg-18.6"]
    for key in settings.EXPECTED_VERSION_MACROS.values():
        assert key in current, key


def test_get_settings_applies_only_to_the_release_under_test(settings, monkeypatch):
    monkeypatch.setenv("EXPECTED_VERSIONS", FROM_OBS)
    all_settings = settings.get_settings("rocky-9")
    assert all_settings["ppg-18.6"]["pgbackrest"]["binary_version"] == "pgBackRest 2.59.2"
    assert all_settings["ppg-18.4"]["pgbackrest"]["version"] != "2.59.2"
