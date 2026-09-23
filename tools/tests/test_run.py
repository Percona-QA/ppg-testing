import json
import os
import pathlib
import textwrap

import pytest

from tools import run

DESC = {
    "params": [
        {"name": "PLATFORM", "kind": "choice", "special": "platform_choice"},
        {"name": "REPO", "kind": "choice", "choices": ["testing", "experimental", "release"]},
        {"name": "TDE_BRANCH", "kind": "string", "default": "release-2.2.0"},
        {"name": "NO_DEFAULT", "kind": "string"},
        {"name": "DESTROY_ENV", "kind": "boolean", "default": True},
        {"name": "MAJOR_REPO", "kind": "boolean"},
    ],
    "sequences": {
        "destroy": ["destroy"],
        "test": ["destroy", "create", "prepare", "converge", "destroy"],
    },
    "scenarios": {"debian-13": {"os": "debian-13"}, "rocky-9": {"os": "rocky-9"}},
}


def test_resolve_params_defaults():
    env = run.resolve_params(DESC, {})
    assert env["REPO"] == "testing"          # first choice
    assert env["TDE_BRANCH"] == "release-2.2.0"
    assert env["MAJOR_REPO"] == "false"      # boolean, no default
    assert "NO_DEFAULT" not in env           # no default, not provided
    assert "PLATFORM" not in env             # fed from --os later
    assert "DESTROY_ENV" not in env          # replaced by --keep


def test_resolve_params_override_and_bool_render():
    env = run.resolve_params(DESC, {"REPO": "release", "MAJOR_REPO": "true", "NO_DEFAULT": "x"})
    assert env["REPO"] == "release"
    assert env["MAJOR_REPO"] == "true"
    assert env["NO_DEFAULT"] == "x"


def test_resolve_params_unknown_name():
    with pytest.raises(run.RunError, match="TYPO"):
        run.resolve_params(DESC, {"TYPO": "1"})


def test_resolve_params_bad_choice():
    with pytest.raises(run.RunError, match="REPO"):
        run.resolve_params(DESC, {"REPO": "prod"})


def test_sequence_actions():
    assert run.sequence_actions(DESC, "destroy") == ["destroy"]
    with pytest.raises(run.RunError, match="nosuch"):
        run.sequence_actions(DESC, "nosuch")


def test_validate_oses():
    run.validate_oses(DESC, ["debian-13"])
    with pytest.raises(run.RunError, match="ol-99"):
        run.validate_oses(DESC, ["debian-13", "ol-99"])


def test_resolve_params_platform_override_rejected():
    with pytest.raises(run.RunError, match="PLATFORM"):
        run.resolve_params(DESC, {"PLATFORM": "debian-13"})


def test_resolve_params_destroy_env_override_rejected():
    with pytest.raises(run.RunError, match="DESTROY_ENV"):
        run.resolve_params(DESC, {"DESTROY_ENV": "true"})


def test_resolve_params_bad_boolean_override():
    with pytest.raises(run.RunError, match="MAJOR_REPO"):
        run.resolve_params(DESC, {"MAJOR_REPO": "yes-please"})


def test_resolve_params_boolean_override_normalizes_case():
    env = run.resolve_params(DESC, {"MAJOR_REPO": "TRUE"})
    assert env["MAJOR_REPO"] == "true"


GROUP_YML = textwrap.dedent("""\
    name_pattern: '{token}-{build}'
    aws:
      size: large
      subnet: aws2
    cleanup: none
    verifier: ansible
    sequences:
      destroy: [destroy]
      test: [create, converge]
    params:
    - name: TDE_BRANCH
      kind: string
      default: main
    scenarios:
      debian-13: {os: debian-13}
      rocky-9: {os: rocky-9}
    """)


@pytest.fixture
def fake_group(tmp_path, monkeypatch):
    g = tmp_path / "grp"
    g.mkdir()
    (g / "scenario.yml").write_text(GROUP_YML)
    monkeypatch.setenv("driver", "delegated")
    monkeypatch.setattr(run.render, "main", lambda argv: 0)
    monkeypatch.setattr(run.shutil, "which", lambda name: "/usr/bin/molecule")
    return g


def _capture(monkeypatch, fail_on=None):
    calls = []

    def fake(cmd, cwd, env, log):
        calls.append((list(cmd), str(cwd), env.get("PLATFORM"), env.get("TDE_BRANCH")))
        return 1 if fail_on and cmd[1] == fail_on else 0

    monkeypatch.setattr(run, "_run", fake)
    return calls


def test_main_runs_sequence_and_safety_destroy(fake_group, tmp_path, monkeypatch):
    calls = _capture(monkeypatch)
    rc = run.main(["--group", str(fake_group), "--os", "debian-13",
                   "--artifacts-dir", str(tmp_path / "a")])
    assert rc == 0
    actions = [c[0][1] for c in calls]
    assert actions == ["create", "converge", "destroy"]   # safety-net destroy
    assert all(c[2] == "debian-13" for c in calls)         # PLATFORM injected
    assert all(c[3] == "main" for c in calls)              # param default in env
    summary = json.loads((tmp_path / "a" / "summary.json").read_text())
    assert summary["oses"]["debian-13"]["status"] == "passed"


def test_main_failure_still_destroys_and_exits_1(fake_group, tmp_path, monkeypatch):
    calls = _capture(monkeypatch, fail_on="converge")
    rc = run.main(["--group", str(fake_group), "--os", "debian-13",
                   "--artifacts-dir", str(tmp_path / "a")])
    assert rc == 1
    assert [c[0][1] for c in calls] == ["create", "converge", "destroy"]
    summary = json.loads((tmp_path / "a" / "summary.json").read_text())
    assert summary["oses"]["debian-13"]["failed_action"] == "converge"


def test_main_passed_has_no_failed_action(fake_group, tmp_path, monkeypatch):
    _capture(monkeypatch)
    rc = run.main(["--group", str(fake_group), "--os", "debian-13",
                   "--artifacts-dir", str(tmp_path / "a")])
    assert rc == 0
    summary = json.loads((tmp_path / "a" / "summary.json").read_text())
    assert "failed_action" not in summary["oses"]["debian-13"]


def test_main_keep_skips_safety_destroy(fake_group, tmp_path, monkeypatch):
    calls = _capture(monkeypatch)
    rc = run.main(["--group", str(fake_group), "--os", "debian-13", "--keep",
                   "--artifacts-dir", str(tmp_path / "a")])
    assert rc == 0
    assert [c[0][1] for c in calls] == ["create", "converge"]


def test_main_multi_os_continues_after_failure(fake_group, tmp_path, monkeypatch):
    calls = _capture(monkeypatch, fail_on="converge")
    rc = run.main(["--group", str(fake_group), "--os", "debian-13", "rocky-9",
                   "--artifacts-dir", str(tmp_path / "a")])
    assert rc == 1
    assert [c[2] for c in calls].count("rocky-9") > 0     # second os still ran
    summary = json.loads((tmp_path / "a" / "summary.json").read_text())
    assert set(summary["oses"]) == {"debian-13", "rocky-9"}


def test_main_requires_driver_env(fake_group, tmp_path, monkeypatch):
    monkeypatch.delenv("driver")
    rc = run.main(["--group", str(fake_group), "--os", "debian-13",
                   "--artifacts-dir", str(tmp_path / "a")])
    assert rc == 2


def test_main_requires_molecule_binary(fake_group, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(run.shutil, "which", lambda name: None)
    rc = run.main(["--group", str(fake_group), "--os", "debian-13",
                   "--artifacts-dir", str(tmp_path / "a")])
    assert rc == 2
    assert "molecule" in capsys.readouterr().err


def test_main_rejects_param_without_equals(fake_group, tmp_path, monkeypatch, capsys):
    _capture(monkeypatch)
    rc = run.main(["--group", str(fake_group), "--os", "debian-13",
                   "--param", "TDE_BRANCH",
                   "--artifacts-dir", str(tmp_path / "a")])
    assert rc == 2
    err = capsys.readouterr().err
    assert "TDE_BRANCH" in err
    assert "unknown param" not in err


def test_run_real_subprocess(tmp_path):
    log_path = tmp_path / "molecule.log"
    with open(log_path, "wb") as log:
        rc = run._run(["/bin/echo", "hello"], tmp_path, dict(os.environ), log)
    assert rc == 0
    text = log_path.read_text()
    assert "$ /bin/echo hello" in text
    assert "hello" in text


def test_collect_artifacts_picks_newest_and_skips_old(tmp_path, monkeypatch):
    group_dir = tmp_path / "grp"
    (group_dir / "a").mkdir(parents=True)
    (group_dir / "b").mkdir(parents=True)
    os_dir = tmp_path / "out"
    os_dir.mkdir()

    old = group_dir / "a" / "report.xml"
    old.write_text("old")
    os.utime(old, (1000, 1000))

    started = 2000
    fresher = group_dir / "b" / "report.xml"
    fresher.write_text("fresher")
    os.utime(fresher, (2500, 2500))

    artifact_dir = tmp_path / "art"
    artifact_dir.mkdir()
    artifact_file = artifact_dir / "junit.xml"
    artifact_file.write_text("art")
    os.utime(artifact_file, (2500, 2500))
    monkeypatch.setattr(run, "REPO", tmp_path)

    run.collect_artifacts(group_dir, os_dir, started, "art/*.xml")

    assert (os_dir / "report.xml").read_text() == "fresher"
    assert (os_dir / "junit.xml").read_text() == "art"


def test_collect_artifacts_newest_wins_over_alphabetical_first(tmp_path, monkeypatch):
    group_dir = tmp_path / "grp"
    (group_dir / "a").mkdir(parents=True)
    (group_dir / "z").mkdir(parents=True)
    os_dir = tmp_path / "out"
    os_dir.mkdir()

    started = 2000
    alpha_first = group_dir / "a" / "report.xml"
    alpha_first.write_text("alpha-first-but-older")
    os.utime(alpha_first, (2100, 2100))
    truly_newest = group_dir / "z" / "report.xml"
    truly_newest.write_text("truly-newest")
    os.utime(truly_newest, (2900, 2900))
    monkeypatch.setattr(run, "REPO", tmp_path)

    run.collect_artifacts(group_dir, os_dir, started, None)

    assert (os_dir / "report.xml").read_text() == "truly-newest"
