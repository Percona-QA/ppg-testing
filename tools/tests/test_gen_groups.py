import pathlib

import pytest
import yaml

from tools import gen_groups, render

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
DATA = gen_groups.load_versions()


def test_expected_group_names():
    names = sorted(gen_groups.group_name(i, t) for i, t in gen_groups.all_groups(DATA))
    assert len(names) == 30
    assert "pg-14" in names
    assert "pg-18-major-upgrade" in names
    assert "psp-16-meta-ha" in names


@pytest.mark.parametrize("instance,type_name", list(gen_groups.all_groups(DATA)))
def test_rendered_yaml_parses(instance, type_name):
    files = gen_groups.render_group(DATA, instance, type_name)
    for rel, content in files.items():
        if rel.endswith(".yml"):
            yaml.safe_load(content)


@pytest.mark.parametrize("instance,type_name", list(gen_groups.all_groups(DATA)))
def test_rendered_scenario_expands(instance, type_name):
    desc = yaml.safe_load(gen_groups.render_group(DATA, instance, type_name)["scenario.yml"])
    names = render.expand_scenarios(desc)
    assert "debian-13" in names


def test_gate_rendering_fail_variant():
    g = dict(name="End play on RedHat 10 and 17.5 and older versions", action="fail",
             msg="Stopping execution on rhel 10 because 17.5 and below are not supported.",
             family="RedHat", os_version="10", version="17.5", op="<=")
    text = gen_groups.render_gate(g)
    assert text.startswith("- name: End play on RedHat 10")
    assert "  fail:\n    msg:" in text
    assert 'ansible_os_family == "RedHat"' in text
    assert "version('17.5', '<=', strict=True)" in text


def test_gate_rendering_end_host_variant():
    g = dict(name="End play on Ubuntu 26 and versions older than 18.4", action="end_host",
             distribution="Ubuntu", os_version="26", version="18.4", op="<")
    text = gen_groups.render_gate(g)
    assert "  meta: end_host" in text
    assert 'ansible_distribution == "Ubuntu"' in text


def test_psp_flavor_delta():
    tasks = gen_groups.render_group(DATA, "psp-16", "server")["tasks/main.yml"]
    assert "replace('psp-','')" in tasks
    assert "install_psp16_tde.yml" in tasks
    assert "Percona Server for PostgreSQL 16" in tasks
    scenario = gen_groups.render_group(DATA, "psp-16", "server")["scenario.yml"]
    assert "tests_psp" in scenario


def test_write_header_marks_files(tmp_path, monkeypatch):
    monkeypatch.setattr(gen_groups, "REPO", tmp_path)
    (tmp_path / "ppg").mkdir()
    (tmp_path / "ppg" / "versions.yml").write_text(
        yaml.safe_dump({"instances": {k: v for k, v in DATA["instances"].items() if k == "pg-17"}}))
    # templates still come from the real repo (loader bound at import time)
    assert gen_groups.write_groups(gen_groups.load_versions()) == 0
    tasks = tmp_path / "ppg" / "pg-17" / "tasks" / "main.yml"
    assert tasks.read_text().startswith(gen_groups.HEADER)
    # second write over generated files succeeds, hand-written file refuses
    assert gen_groups.write_groups(gen_groups.load_versions()) == 0
    tasks.write_text("hand written\n")
    assert gen_groups.write_groups(gen_groups.load_versions()) == 2


def test_shared_tasks_render():
    files = gen_groups.render_shared_tasks(DATA)
    assert sorted(files) == sorted(
        ["tasks/install_ppg%d%s.yml" % (m, s) for m in range(14, 19) for s in ("", "_tools")])
    base18 = files["tasks/install_ppg18.yml"]
    assert "percona-postgresql-common-dev" in base18
    assert "Determine required PostgreSQL dev package" not in base18
    base17 = files["tasks/install_ppg17.yml"]
    assert "version('17.4', '<=', strict=True)" in base17
    tools14 = files["tasks/install_ppg14_tools.yml"]
    assert "pg_oidc_validator" not in tools14
    assert "base_extensions: ['pg_stat_monitor', 'pgaudit', 'set_user']" in tools14
    tools18 = files["tasks/install_ppg18_tools.yml"]
    assert "percona-pg_oidc_validator18" in tools18
    for content in files.values():
        yaml.safe_load(content)


def test_major_upgrade_from_defaults_track_the_from_major():
    """Every major-upgrade default_from_version is a copy of the previous
    major's default_version -- nothing in the file links the two, so a minor
    bump that misses the copies is exactly the drift this catches."""
    for name, inst in DATA["instances"].items():
        got = inst["major-upgrade"]["default_from_version"]
        from_name = gen_groups.from_instance(DATA, name)
        if from_name is None:
            # ppg-13 and older are gone from the file (EOL, no test fixtures
            # left either), so pg-14-major-upgrade has nothing to track: only
            # the flavor and major of its frozen FROM default are checked
            assert got.startswith("ppg-%d." % (inst["major"] - 1)), (
                "ppg/versions.yml: %s major-upgrade default_from_version is %r,"
                " expected a ppg-%d.<minor> (the previous major is EOL and no "
                "longer in this file, so this value is frozen)"
                % (name, got, inst["major"] - 1))
            continue
        want = DATA["instances"][from_name]["default_version"]
        assert got == want, (
            "ppg/versions.yml: %s major-upgrade default_from_version is %r but "
            "instance %s default_version is %r -- major-upgrade starts from the "
            "previous major, so set %s major-upgrade default_from_version to %r"
            % (name, got, from_name, want, name, want))


def test_minor_upgrade_from_defaults_stay_in_the_same_major():
    """minor-upgrade goes minor -> minor inside one major: same flavor, same
    major, and strictly older than the version it upgrades to."""
    for name, inst in DATA["instances"].items():
        to = inst["default_version"]
        got = inst["minor-upgrade"]["default_from_version"]
        prefix = to.rsplit(".", 1)[0] + "."
        assert got.startswith(prefix), (
            "ppg/versions.yml: %s minor-upgrade default_from_version is %r, "
            "expected an older minor of %r (i.e. %s<minor>)"
            % (name, got, to, prefix))
        assert int(got.rsplit(".", 1)[1]) < int(to.rsplit(".", 1)[1]), (
            "ppg/versions.yml: %s minor-upgrade default_from_version %r is not "
            "older than default_version %r -- an upgrade test needs an older "
            "FROM version" % (name, got, to))


def test_validate_rejects_missing_param_defaults():
    import copy
    data = copy.deepcopy(DATA)
    del data["instances"]["pg-17"]["default_version"]
    with pytest.raises(ValueError, match="pg-17 has no default_version"):
        gen_groups.validate(data)
