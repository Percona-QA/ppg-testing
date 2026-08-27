import pathlib

import pytest

from tools import gen_jenkins

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
GOLDEN = REPO / "tools" / "tests" / "golden"

GOLDEN_FILES = ["tde.groovy", "tde.yml", "tde-parallel.groovy", "tde-parallel.yml"]


@pytest.mark.parametrize("name", GOLDEN_FILES)
def test_generate_matches_golden(name):
    out = gen_jenkins.generate(REPO / "pg_tde/tde")
    assert out[name] == (GOLDEN / name).read_text()


def test_generate_returns_exactly_the_golden_filenames():
    out = gen_jenkins.generate(REPO / "pg_tde/tde")
    assert sorted(out) == sorted(GOLDEN_FILES)


def _populate(jenkins_repo):
    ppg = jenkins_repo / "ppg"
    ppg.mkdir(parents=True)
    for name in GOLDEN_FILES:
        (ppg / name).write_text((GOLDEN / name).read_text())


def test_check_clean_when_matching(tmp_path):
    _populate(tmp_path)
    rc = gen_jenkins.main(["--jenkins-repo", str(tmp_path), "--group", "pg_tde/tde", "--check"])
    assert rc == 0


def test_check_reports_drift_on_byte_diff(tmp_path, capsys):
    _populate(tmp_path)
    corrupted = tmp_path / "ppg" / "tde.groovy"
    corrupted.write_text(corrupted.read_text().replace("PLATFORM", "PLATFOOM"))

    rc = gen_jenkins.main(["--jenkins-repo", str(tmp_path), "--group", "pg_tde/tde", "--check"])
    assert rc == 1
    out = capsys.readouterr().out
    assert "DRIFT %s (differs)" % corrupted in out


def test_check_reports_drift_on_missing_file(tmp_path, capsys):
    _populate(tmp_path)
    (tmp_path / "ppg" / "tde-parallel.yml").unlink()

    rc = gen_jenkins.main(["--jenkins-repo", str(tmp_path), "--group", "pg_tde/tde", "--check"])
    assert rc == 1
    out = capsys.readouterr().out
    assert "DRIFT %s (missing)" % (tmp_path / "ppg" / "tde-parallel.yml") in out


def test_write_creates_files(tmp_path):
    rc = gen_jenkins.main(["--jenkins-repo", str(tmp_path), "--group", "pg_tde/tde"])
    assert rc == 0
    for name in GOLDEN_FILES:
        assert (tmp_path / "ppg" / name).read_text() == (GOLDEN / name).read_text()


def test_find_groups_with_jenkins_includes_pg_tde():
    groups = gen_jenkins.find_groups_with_jenkins()
    assert REPO / "pg_tde" / "tde" in groups


def test_generate_raises_clear_error_without_jenkins_section(tmp_path):
    group_dir = tmp_path / "group"
    group_dir.mkdir()
    (group_dir / "scenario.yml").write_text("name_pattern: '{token}'\n")

    with pytest.raises(gen_jenkins.GenJenkinsError, match="jenkins"):
        gen_jenkins.generate(group_dir)


def test_generate_raises_clear_error_for_unknown_flavor(tmp_path):
    group_dir = tmp_path / "group"
    group_dir.mkdir()
    (group_dir / "scenario.yml").write_text("""
jenkins:
  molecule_dir: x/y
  artifacts: "x/y/artifacts/**/*.tar.gz"
  jobs:
    nightly:
      job_name: x
      file: x
      display_name: "d"
""")

    with pytest.raises(gen_jenkins.GenJenkinsError, match="nightly"):
        gen_jenkins.generate(group_dir)


def test_slack_optional_single_flavor_never_needs_it():
    # single flavor has no slack key at all in pg_tde/tde/scenario.yml and must
    # still generate fine.
    out = gen_jenkins.generate(REPO / "pg_tde/tde")
    assert "sendSlackNotification" not in out["tde.groovy"]


def test_resolve_params_default_parallel_overrides_default():
    desc = {"params": [{
        "name": "VERSION", "kind": "string", "default": "ppg-18.4",
        "default_parallel": "pg-18.4", "description": "d",
    }]}
    single = gen_jenkins.resolve_params(desc, "single")
    parallel = gen_jenkins.resolve_params(desc, "parallel")
    assert single[0]["default"] == "ppg-18.4"
    assert parallel[0]["default"] == "pg-18.4"


def test_generate_without_slack_key_omits_notification(tmp_path):
    group_dir = tmp_path / "group"
    group_dir.mkdir()
    (group_dir / "scenario.yml").write_text("""
params: []
jenkins:
  molecule_dir: x/y
  artifacts: "x/y/artifacts/**/*.tar.gz"
  jobs:
    parallel:
      job_name: x-parallel
      file: x-parallel
      display_name: "d"
""")

    out = gen_jenkins.generate(group_dir)
    assert "sendSlackNotification" not in out["x-parallel.groovy"]
