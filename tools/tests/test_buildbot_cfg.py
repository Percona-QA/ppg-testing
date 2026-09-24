import os
import pathlib
import shlex
import shutil
import subprocess
import sys

import pytest

try:
    from buildbot.process.results import FAILURE, SUCCESS, WARNINGS
except ImportError:  # skipped anyway, see needs_buildbot
    FAILURE = SUCCESS = WARNINGS = None

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
CFG = REPO / "local" / "buildbot" / "master.cfg"


def find_buildbot():
    # the venv running pytest is not necessarily on PATH
    local = pathlib.Path(sys.executable).parent / "buildbot"
    if local.exists():
        return str(local)
    return shutil.which("buildbot")


buildbot = find_buildbot()
needs_buildbot = pytest.mark.skipif(buildbot is None,
                                    reason="buildbot not installed")


@pytest.fixture(scope="module")
def cfg():
    ns = {"__file__": str(CFG)}
    exec(compile(CFG.read_text(), str(CFG), "exec"), ns)
    return ns


class FakeProps(dict):
    def getProperty(self, name, default=None):
        return self.get(name, default)


def runtime_step(step, **props):
    """The per-build step, not the config template: only that one accepts
    attribute assignment (BuildStepWrapperMixin guards the template)."""
    step = step.get_step_factory().buildStep()
    step.build = FakeProps(**props)
    return step


def scheduler_fields(sched):
    """ForceScheduler.forcedProperties only exists once the service has
    reconfigured, which needs a running master; getConfigDict is the public
    accessor at config time."""
    return {p.name: p for p in sched.getConfigDict()["kwargs"]["properties"]}


@needs_buildbot
def test_checkconfig(tmp_path):
    p = subprocess.run([buildbot, "checkconfig", str(CFG)],
                       cwd=str(tmp_path), capture_output=True, text=True)
    assert p.returncode == 0, p.stdout + p.stderr


@needs_buildbot
def test_builders_and_workers(cfg):
    c = cfg["BuildmasterConfig"]
    assert [b.name for b in c["builders"]] == ["molecule-run", "group-run",
                                               "sweep-run"]
    triggerable = [s for s in c["schedulers"]
                   if type(s).__name__ == "Triggerable"]
    assert [s.name for s in triggerable] == ["molecule-run-t"]

    slots = int(os.environ.get("PPG_LOCAL_SLOTS", "4"))
    mworkers = [w for w in c["workers"] if w.name.startswith("molecule-")]
    # capacity is one worker per slot: buildbot runs a single build per
    # (builder, worker) pair, max_builds on one worker would not parallelize
    assert len(mworkers) == slots
    assert {w.max_builds for w in mworkers} == {1}
    molecule_run = [b for b in c["builders"] if b.name == "molecule-run"][0]
    assert molecule_run.workernames == [w.name for w in mworkers]

    # the coordinator build waits for the whole fan out, so one per group-run
    # build too, or whole groups would queue behind each other
    coordinators = [w for w in c["workers"] if w.name.startswith("coordinator")]
    assert len(coordinators) > 1
    assert {type(w).__name__ for w in coordinators} == {"LocalWorker"}
    for name in ("group-run", "sweep-run"):
        builder = [b for b in c["builders"] if b.name == name][0]
        assert builder.workernames == [w.name for w in coordinators]


@needs_buildbot
def test_one_force_scheduler_per_group(cfg):
    c = cfg["BuildmasterConfig"]
    groups = cfg["GROUPS"]
    forced = [s for s in c["schedulers"] if type(s).__name__ == "ForceScheduler"]
    per_group = [s for s in forced if s.name.startswith("run-")]
    assert len(per_group) == len(groups) > 0
    assert {s.name for s in per_group} == {"run-" + cfg["slug"](g) for g in groups}
    for s in per_group:
        assert s.builderNames == ["group-run"]
    # the sweeps are the only extras
    assert {s.name for s in forced} - {s.name for s in per_group} == {
        "release-sweep", "destroy-sweep"}


@needs_buildbot
def test_force_fields_from_descriptor(cfg):
    groups = cfg["GROUPS"]
    for group, desc in groups.items():
        fields = {p.name: p for p in cfg["force_fields"](group, desc)}
        assert {"group", "oses", "sequence", "TESTING_BRANCH"} <= set(fields)
        assert fields["group"].default == group
        assert fields["oses"].multiple
        assert fields["oses"].choices == cfg["render"].expand_scenarios(desc)
        assert fields["oses"].default == cfg["local_oses"](
            cfg["render"].expand_scenarios(desc))
        assert not [o for o in fields["oses"].default
                    if o.endswith("-arm") or o.startswith("rhel-")]
        assert fields["sequence"].choices == sorted(desc.get("sequences", {}))
        for p in desc.get("params", []):
            name = p["name"]
            if name in ("PLATFORM", "DESTROY_ENV"):
                assert name not in fields
                continue
            kind = p.get("kind", "string")
            if name == "TESTING_BRANCH":
                kind = "string"
            expect = {"choice": "ChoiceStringParameter",
                      "boolean": "BooleanParameter",
                      "string": "StringParameter"}[kind]
            assert type(fields[name]).__name__ == expect, (group, name)


def make_fanout(cfg, **props):
    return runtime_step(
        cfg["FanOut"](schedulerNames=["molecule-run-t"], name="fan out"),
        **props)


@needs_buildbot
def test_fanout_one_build_per_os(cfg):
    fanout = make_fanout(cfg, group="pg_tde/tde", oses=["ol-9", "rocky-9"],
                         sequence="destroy", TDE_BRANCH="main", buildnumber=12)
    out = fanout.getSchedulersAndProperties()
    assert [e["props_to_set"]["os"] for e in out] == ["ol-9", "rocky-9"]
    assert [e["props_to_set"]["virtual_builder_name"] for e in out] == [
        "pg_tde/tde ol-9", "pg_tde/tde rocky-9"]
    for e in out:
        assert e["sched_name"] == "molecule-run-t"
        assert e["props_to_set"]["run_id"] == 12
        assert e["unimportant"] is False
        assert e["props_to_set"]["group"] == "pg_tde/tde"
        assert e["props_to_set"]["sequence"] == "destroy"
        assert e["props_to_set"]["TDE_BRANCH"] == "main"
        assert e["props_to_set"]["virtual_builder_tags"] == ["pg_tde-tde"]


@needs_buildbot
def test_fanout_accepts_comma_string(cfg):
    fanout = make_fanout(cfg, group="pg_tde/tde", oses="ol-9,rocky-9")
    out = fanout.getSchedulersAndProperties()
    assert [e["props_to_set"]["os"] for e in out] == ["ol-9", "rocky-9"]
    assert out[0]["props_to_set"]["sequence"] == "test"


@needs_buildbot
def test_run_command_renderer(cfg):
    props = FakeProps(group="pg_tde/tde", os="ol-9", sequence="destroy",
                      run_id=7, buildnumber=3, TDE_BRANCH="main", VERSION="")
    cmd = cfg["run_command"].fn(props)
    assert cmd.startswith(". local/env.sh && exec python3 tools/run.py ")
    assert "--group pg_tde/tde" in cmd
    assert "--os ol-9" in cmd
    assert "--sequence destroy" in cmd
    assert "--artifacts-dir /artifacts/pg_tde-tde/7" in cmd
    assert "--param TDE_BRANCH=main" in cmd
    # empty values fall through to the descriptor default
    assert "VERSION" not in cmd
    # never passed: PLATFORM comes from --os, DESTROY_ENV from --keep
    assert "PLATFORM" not in cmd
    assert "DESTROY_ENV" not in cmd


@needs_buildbot
def test_run_command_booleans(cfg):
    seen = False
    for group, desc in cfg["GROUPS"].items():
        for p in desc.get("params", []):
            name = p["name"]
            if p.get("kind") != "boolean" or name == "DESTROY_ENV":
                continue
            seen = True
            oses = cfg["render"].expand_scenarios(desc)
            base = dict(group=group, os=oses[0], buildnumber=1)
            cmd = cfg["run_command"].fn(FakeProps(base, **{name: True}))
            assert "--param %s=true" % name in cmd, (group, name)
            cmd = cfg["run_command"].fn(FakeProps(base, **{name: False}))
            assert "--param %s=false" % name in cmd, (group, name)
    assert seen, "no group with a boolean param"


@needs_buildbot
def test_run_command_quotes_param_values(cfg):
    nasty = "a b; touch /pwned"
    props = FakeProps(group="pg_tde/tde", os="ol-9", buildnumber=1,
                      TDE_BRANCH=nasty)
    cmd = cfg["run_command"].fn(props)
    tokens = shlex.split(cmd)
    assert "TDE_BRANCH=" + nasty in tokens
    assert ";" not in [t for t in tokens if t != "TDE_BRANCH=" + nasty]


@needs_buildbot
def test_run_command_rejects_bad_properties(cfg):
    with pytest.raises(ValueError):
        cfg["run_command"].fn(FakeProps(os="ol-9", buildnumber=1))
    with pytest.raises(ValueError):
        cfg["run_command"].fn(FakeProps(group="nope/nope", os="ol-9"))
    with pytest.raises(ValueError):
        cfg["run_command"].fn(FakeProps(group="pg_tde/tde", os=""))


@needs_buildbot
def test_build_identity_env(cfg):
    step = [s for s in cfg["run_factory"].steps
            if s.kwargs.get("name") == "molecule"][0]
    env = step.kwargs["env"]
    assert set(env) == {"BUILD_NUMBER", "JOB_NAME"}
    assert step.kwargs["sigtermTime"] == 60
    # feeds libvirt domain names, a slash there breaks the guest name
    assert cfg["job_name"].fn(FakeProps(group="ppg/pg-14")) == "ppg-pg-14"
    assert "/" not in cfg["job_name"].fn(FakeProps(group="ppg/pg-14"))


FAKE_GROUPS = {
    "fake/full": {
        "sequences": {"test": ["converge"], "destroy": ["destroy"]},
        "scenarios": {"ol-9": {"os": "ol-9"}, "rocky-9": {"os": "rocky-9"}},
        "params": [{"name": "VERSION", "kind": "string"}],
    },
    "fake/testonly": {
        "sequences": {"test": ["converge"]},
        "scenarios": {"debian-12": {"os": "debian-12"}},
    },
}


def make_sweep(cfg, monkeypatch, **props):
    for name, desc in FAKE_GROUPS.items():
        monkeypatch.setitem(cfg["GROUPS"], name, desc)
    return runtime_step(
        cfg["SweepFanOut"](schedulerNames=["molecule-run-t"], name="fan out"),
        **props)


@needs_buildbot
def test_sweep_schedulers(cfg):
    forced = {s.name: s for s in cfg["BuildmasterConfig"]["schedulers"]
              if type(s).__name__ == "ForceScheduler"}
    for name in ("release-sweep", "destroy-sweep"):
        s = forced[name]
        assert s.builderNames == ["sweep-run"]
        fields = scheduler_fields(s)
        assert {"groups", "sequence", "TESTING_BRANCH"} <= set(fields)
        groups = fields["groups"]
        assert groups.multiple
        assert groups.choices == sorted(cfg["GROUPS"])
        assert groups.default == cfg["SWEEP_DEFAULT"]
        assert groups.default and set(groups.default) <= set(groups.choices)
        assert all(g.startswith(cfg["SWEEP_DEFAULT_PREFIXES"])
                   for g in groups.default)
        # the generated psp groups live under ppg/, "psp/" alone misses them
        assert {"ppg/psp-16", "ppg/psp-16-minor-upgrade",
                "psp/server_tests"} <= set(groups.default)
        assert {"ppg/pg-17", "pg_tde/tde"} <= set(groups.default)
        assert not [g for g in groups.default if g.startswith("docker/")]

    release = scheduler_fields(forced["release-sweep"])
    assert {"VERSION", "FROM_VERSION", "REPO"} <= set(release)
    assert type(release["sequence"]).__name__ == "ChoiceStringParameter"
    # destroy without a BUILD_NUMBER field would destroy nothing and look green
    assert "destroy" not in release["sequence"].choices
    assert "test" in release["sequence"].choices
    assert release["sequence"].default == "test"

    destroy = scheduler_fields(forced["destroy-sweep"])
    assert type(destroy["sequence"]).__name__ == "FixedParameter"
    assert destroy["sequence"].default == "destroy"
    # nothing version-ish on a destroy, only which guests to remove
    assert not {"VERSION", "FROM_VERSION", "REPO"} & set(destroy)
    # digits only, a typo here would destroy nothing and look like success
    assert destroy["BUILD_NUMBER"].regex.pattern == r"^\d*$"
    assert destroy["BUILD_NUMBER"].regex.match("41")
    assert destroy["BUILD_NUMBER"].regex.match("")
    assert not destroy["BUILD_NUMBER"].regex.match("4 1")
    assert not destroy["BUILD_NUMBER"].regex.match("no41")

    builder = [b for b in cfg["BuildmasterConfig"]["builders"]
               if b.name == "sweep-run"][0]
    coordinators = [w.name for w in cfg["BuildmasterConfig"]["workers"]
                    if w.name.startswith("coordinator")]
    assert builder.workernames == coordinators


@needs_buildbot
def test_sweep_fanout_matrix(cfg, monkeypatch):
    sweep = make_sweep(cfg, monkeypatch, buildnumber=5, sequence="test",
                       groups=["fake/full", "fake/testonly"],
                       TESTING_BRANCH="topic", VERSION="18.4", FROM_VERSION="",
                       REPO="testing")
    out = sweep.getSchedulersAndProperties()
    assert [(e["props_to_set"]["group"], e["props_to_set"]["os"]) for e in out] == [
        ("fake/full", "ol-9"), ("fake/full", "rocky-9"),
        ("fake/testonly", "debian-12")]
    for e in out:
        p = e["props_to_set"]
        assert e["sched_name"] == "molecule-run-t"
        # namespaced: group-run numbers its builds independently
        assert p["run_id"] == "sweep-5"
        assert p["TESTING_BRANCH"] == "topic"
        assert p["sequence"] == "test"
        assert p["VERSION"] == "18.4"
        assert p["REPO"] == "testing"
        # empty shared params are not forwarded, the descriptor default wins
        assert "FROM_VERSION" not in p
        assert "TO_REPO" not in p
        assert p["virtual_builder_name"] == "%s %s" % (p["group"], p["os"])
        assert p["virtual_builder_tags"] == [cfg["slug"](p["group"]), "sweep"]


@needs_buildbot
def test_sweep_sequence_fallback(cfg, monkeypatch):
    # unknown sequence: keep the group in the sweep by running its tests
    sweep = make_sweep(cfg, monkeypatch, buildnumber=1, sequence="upgrade",
                       groups=["fake/full", "fake/testonly"])
    out = sweep.getSchedulersAndProperties()
    assert {e["props_to_set"]["sequence"] for e in out} == {"test"}
    assert len(out) == 3


@needs_buildbot
def test_sweep_destroy_never_falls_back(cfg, monkeypatch):
    # a group without a destroy sequence is skipped, not tested
    sweep = make_sweep(cfg, monkeypatch, buildnumber=1, sequence="destroy",
                       groups=["fake/full", "fake/testonly"])
    out = sweep.getSchedulersAndProperties()
    assert {e["props_to_set"]["group"] for e in out} == {"fake/full"}
    assert {e["props_to_set"]["sequence"] for e in out} == {"destroy"}


@needs_buildbot
def test_sweep_cleanup_never_falls_back(cfg, monkeypatch):
    # same rule as destroy: running the tests instead of a cleanup is wrong
    sweep = make_sweep(cfg, monkeypatch, buildnumber=1, sequence="cleanup",
                       groups=["fake/full", "fake/testonly"])
    assert sweep.getSchedulersAndProperties() == []
    # skipping everything must not read as a clean sweep
    assert sweep.sweep_triggered == 0
    assert sweep.sweep_skipped == [
        "fake/full: declares no 'cleanup' sequence",
        "fake/testonly: declares no 'cleanup' sequence"]
    assert cfg["sweep_result"](sweep.sweep_triggered, sweep.sweep_skipped,
                               SUCCESS) == FAILURE

    # and against real descriptors: only the ones declaring cleanup survive
    have = [g for g, d in cfg["GROUPS"].items() if "cleanup" in d["sequences"]]
    lack = [g for g, d in cfg["GROUPS"].items() if "cleanup" not in d["sequences"]]
    assert have and lack, "expected a mix of descriptors to test against"
    sweep = make_sweep(cfg, monkeypatch, buildnumber=1, sequence="cleanup",
                       groups=[have[0], lack[0]])
    out = sweep.getSchedulersAndProperties()
    assert {e["props_to_set"]["group"] for e in out} == {have[0]}
    assert {e["props_to_set"]["sequence"] for e in out} == {"cleanup"}
    # partial skip: the groups that were dropped are named, build goes orange
    assert sweep.sweep_skipped == ["%s: declares no 'cleanup' sequence" % lack[0]]
    assert cfg["sweep_result"](sweep.sweep_triggered, sweep.sweep_skipped,
                              SUCCESS) == WARNINGS


@needs_buildbot
def test_sweep_result_rules(cfg):
    sweep_result = cfg["sweep_result"]
    # nothing triggered: always a failure, whatever the trigger step said
    assert sweep_result(0, [], SUCCESS) == FAILURE
    assert sweep_result(0, ["a: skipped"], SUCCESS) == FAILURE
    # everything triggered: the trigger result stands
    assert sweep_result(3, [], SUCCESS) == SUCCESS
    assert sweep_result(3, [], FAILURE) == FAILURE
    # partial: never better than a warning, never hides a failure
    assert sweep_result(3, ["a: skipped"], SUCCESS) == WARNINGS
    assert sweep_result(3, ["a: skipped"], FAILURE) == FAILURE


@needs_buildbot
def test_sweep_destroy_over_real_groups(cfg, monkeypatch):
    # every descriptor declares destroy today, so nothing gets skipped
    real = sorted(cfg["GROUPS"])
    expected = sum(len(cfg["local_oses"](cfg["render"].expand_scenarios(cfg["GROUPS"][g])))
                   for g in real)
    sweep = make_sweep(cfg, monkeypatch, buildnumber=1, sequence="destroy",
                       groups=real, BUILD_NUMBER="41")
    out = sweep.getSchedulersAndProperties()
    assert {e["props_to_set"]["sequence"] for e in out} == {"destroy"}
    assert {e["props_to_set"]["BUILD_NUMBER"] for e in out} == {"41"}
    assert {e["props_to_set"]["group"] for e in out} == set(real)
    assert len(out) == expected


@needs_buildbot
def test_sweep_skips_unknown_group(cfg, monkeypatch):
    sweep = make_sweep(cfg, monkeypatch, buildnumber=1, sequence="test",
                       groups="fake/full nope/nope")
    out = sweep.getSchedulersAndProperties()
    assert {e["props_to_set"]["group"] for e in out} == {"fake/full"}


@needs_buildbot
def test_build_number_targets_other_builds(cfg):
    # own guests by default, another build's guests when asked
    assert cfg["build_number"].fn(FakeProps(buildnumber=9)) == "9"
    assert cfg["build_number"].fn(FakeProps(buildnumber=9, BUILD_NUMBER="")) == "9"
    assert cfg["build_number"].fn(FakeProps(buildnumber=9, BUILD_NUMBER="41")) == "41"


@needs_buildbot
def test_run_command_covers_every_group(cfg):
    for group, desc in cfg["GROUPS"].items():
        oses = cfg["render"].expand_scenarios(desc)
        props = FakeProps(group=group, os=oses[0], buildnumber=1)
        assert cfg["run_command"].fn(props)
