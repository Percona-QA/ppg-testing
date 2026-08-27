import pathlib

import pytest

from tools import catalog, render
from tools.migrate_check import substituted_original

REPO = pathlib.Path(__file__).resolve().parent.parent.parent

SMALL_SCENARIO_YML = """
name_pattern: '{token}-{build}'
aws:
  size: large
  subnet: aws2
cleanup: none
verifier: ansible
sequences:
  destroy: [destroy]
  test: [destroy, create, prepare, converge, verify, destroy]
scenarios:
  debian-13: {os: debian-13}
  rocky-9: {os: rocky-9}
"""


@pytest.mark.parametrize("os_key", ["debian-13", "debian-13-arm", "rocky-9", "ubuntu-jammy"])
def test_tde_render_matches_git(os_key):
    rendered = render.render_one(REPO / "pg_tde/tde", os_key)
    assert rendered == substituted_original("pg_tde/tde", os_key)


def test_apply_overrides_rejects_unknown_key():
    desc = {"aws": {"size": "large"}, "overrides": {"foo": {"verifier": "ansible"}}}
    with pytest.raises(ValueError):
        render.apply_overrides(desc, "foo")


def test_apply_overrides_rejects_unknown_aws_key():
    desc = {"aws": {"size": "large"}, "overrides": {"foo": {"aws": {"ami": "bogus"}}}}
    with pytest.raises(ValueError):
        render.apply_overrides(desc, "foo")


def test_apply_overrides_aws_size_changes_output(tmp_path):
    group_dir = tmp_path / "group"
    group_dir.mkdir()
    (group_dir / "scenario.yml").write_text("""
name_pattern: '{token}-{build}'
aws:
  size: large
  subnet: aws2
cleanup: none
verifier: ansible
sequences:
  destroy: [destroy]
  test: [destroy, create, prepare, converge, verify, destroy]
overrides:
  debian-13:
    aws:
      size: small
""")
    rendered = render.render_one(group_dir, "debian-13")
    assert "instance_type: t3.small" in rendered
    assert "instance_type: t3.large" not in rendered


def test_apply_overrides_rejects_non_dict_aws():
    desc = {"aws": {"size": "large"}, "overrides": {"foo": {"aws": "bogus"}}}
    with pytest.raises(ValueError):
        render.apply_overrides(desc, "foo")


def test_expand_scenarios_explicit():
    desc = {"scenarios": {"debian-13": {"os": "debian-13"}, "rocky-9": {"os": "rocky-9"}}}
    assert render.expand_scenarios(desc) == ["debian-13", "rocky-9"]


def test_expand_scenarios_os_list_named():
    desc = {"os_list": "ssl35"}
    assert render.expand_scenarios(desc) == catalog.load("os-lists.yml")["ssl35"]


def test_expand_scenarios_os_list_exclude():
    desc = {"os_list": {"list": "ssl35", "exclude": ["debian-13"]}}
    got = render.expand_scenarios(desc)
    assert "debian-13" not in got
    assert got == [n for n in catalog.load("os-lists.yml")["ssl35"] if n != "debian-13"]


def _make_group(tmp_path, scenario_yml=SMALL_SCENARIO_YML):
    group_dir = tmp_path / "group"
    group_dir.mkdir()
    (group_dir / "scenario.yml").write_text(scenario_yml)
    return group_dir


def test_render_cmd_writes_header(tmp_path):
    group_dir = _make_group(tmp_path)
    rc = render.main(["--group", str(group_dir)])
    assert rc == 0

    mfile = group_dir / "molecule" / "debian-13" / "molecule.yml"
    text = mfile.read_text()
    assert text.startswith(render.HEADER)

    assert not (group_dir / "molecule" / "__init__.py").exists()
    assert (group_dir / "molecule" / "rocky-9" / "molecule.yml").exists()


def test_render_cmd_scenario_filter(tmp_path):
    group_dir = _make_group(tmp_path)
    rc = render.main(["--group", str(group_dir), "--scenario", "debian-13"])
    assert rc == 0
    assert (group_dir / "molecule" / "debian-13" / "molecule.yml").exists()
    assert not (group_dir / "molecule" / "rocky-9").exists()


def test_render_cmd_keeps_hand_written_file(tmp_path, capsys):
    group_dir = _make_group(tmp_path)
    handwritten = group_dir / "molecule" / "debian-13" / "molecule.yml"
    handwritten.parent.mkdir(parents=True)
    handwritten.write_text("dependency:\n  name: galaxy\n")

    rc = render.main(["--group", str(group_dir)])
    assert rc == 0
    assert handwritten.read_text() == "dependency:\n  name: galaxy\n"
    assert (group_dir / "molecule" / "rocky-9" / "molecule.yml").exists()
    assert "kept 1 hand-written" in capsys.readouterr().err


def test_render_cmd_overwrites_previously_generated_file(tmp_path):
    group_dir = _make_group(tmp_path)
    assert render.main(["--group", str(group_dir)]) == 0
    # regenerate: should succeed silently, no clobber error
    assert render.main(["--group", str(group_dir)]) == 0


def test_clean_removes_only_generated_files(tmp_path, capsys):
    group_dir = _make_group(tmp_path)
    assert render.main(["--group", str(group_dir)]) == 0

    # add a hand-written scenario that clean must not touch
    extra = group_dir / "molecule" / "ubuntu-jammy"
    extra.mkdir()
    (extra / "molecule.yml").write_text("dependency:\n  name: galaxy\n")

    rc = render.main(["--group", str(group_dir), "--clean"])
    assert rc == 0

    assert not (group_dir / "molecule" / "debian-13").exists()
    assert not (group_dir / "molecule" / "rocky-9").exists()
    # non-generated scenario survives
    assert (extra / "molecule.yml").exists()
    # group molecule dir survives too, since it's not empty
    assert (group_dir / "molecule").is_dir()

    err = capsys.readouterr().err
    assert "ubuntu-jammy" in err


def test_clean_removes_group_dir_when_fully_empty(tmp_path):
    group_dir = _make_group(tmp_path)
    assert render.main(["--group", str(group_dir)]) == 0
    assert render.main(["--group", str(group_dir), "--clean"]) == 0
    assert not (group_dir / "molecule").exists()


def test_clean_honors_scenario_filter(tmp_path):
    group_dir = _make_group(tmp_path)
    assert render.main(["--group", str(group_dir)]) == 0

    rc = render.main(["--group", str(group_dir), "--clean", "--scenario", "debian-13"])
    assert rc == 0

    assert not (group_dir / "molecule" / "debian-13").exists()
    # sibling scenario untouched
    assert (group_dir / "molecule" / "rocky-9" / "molecule.yml").exists()


def test_find_all_groups(tmp_path, monkeypatch):
    monkeypatch.setattr(render, "REPO", tmp_path)
    (tmp_path / "groupA").mkdir()
    (tmp_path / "groupA" / "scenario.yml").write_text(SMALL_SCENARIO_YML)
    (tmp_path / "groupB").mkdir()
    (tmp_path / "groupB" / "scenario.yml").write_text(SMALL_SCENARIO_YML)
    (tmp_path / "not_a_group").mkdir()
    (tmp_path / "not_a_group" / "readme.txt").write_text("hi")

    groups = render.find_all_groups()
    assert groups == [tmp_path / "groupA", tmp_path / "groupB"]


def test_render_cmd_all_flag(tmp_path, monkeypatch):
    monkeypatch.setattr(render, "REPO", tmp_path)
    (tmp_path / "groupA").mkdir()
    (tmp_path / "groupA" / "scenario.yml").write_text(SMALL_SCENARIO_YML)
    (tmp_path / "groupB").mkdir()
    (tmp_path / "groupB" / "scenario.yml").write_text(SMALL_SCENARIO_YML)
    (tmp_path / "not_a_group").mkdir()

    rc = render.main(["--all"])
    assert rc == 0
    assert (tmp_path / "groupA" / "molecule" / "debian-13" / "molecule.yml").exists()
    assert (tmp_path / "groupB" / "molecule" / "rocky-9" / "molecule.yml").exists()
    assert not (tmp_path / "not_a_group" / "molecule").exists()
