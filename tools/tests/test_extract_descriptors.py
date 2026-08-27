import pathlib
import shutil

import pytest
import yaml

from tools import extract_descriptors as ed

REPO = pathlib.Path(__file__).resolve().parent.parent.parent

# groups carrying hand-authored params/jenkins sections -- these are the ones
# that went stale before (extract --write re-serialized them on every run,
# dirtying a clean tree even though the data was unchanged).
JENKINS_GROUPS = [
    "pg_tde/tde",
    "pg_tde/auxiliary",
    "pg_stat_monitor/pgsm",
    "pg_stat_monitor/pgsm_pgdg",
    "psp/server_tests",
]


def group_canonical_text(group_dir):
    """what tools/extract_descriptors.py --write would write for group_dir,
    without touching disk. serialization itself comes from
    ed.canonical_text() -- the same function main() uses -- so this can
    never drift from the real writer."""
    notes = []
    desc = ed.process_group(group_dir, notes)
    target = group_dir / "scenario.yml"
    existing = yaml.safe_load(target.read_text()) or {}
    merged = ed.merge_preserved(desc, existing)
    return ed.canonical_text(merged)

MOLECULE_YML = """---
dependency:
  name: galaxy
driver:
  name: ${driver}
platforms:
  - name: fakegrp-debian13-${BUILD_NUMBER}
    region: ${region}
    image: ${ami_debian13_x86_64}
    vpc_subnet_id: ${vpc_subnet_id_aws2}
    instance_type: t3.xlarge
    ssh_user: admin
    root_device_name: /dev/xvda
    instance_tags:
      iit-billing-tag: jenkins-pg-molecule
provisioner:
  name: ansible
  log: True
  playbooks:
    create: ../../../../playbooks/create.yml
    destroy: ../../../../playbooks/destroy.yml
    prepare: ../../../../playbooks/prepare.yml
    converge: ../../playbooks/playbook.yml
verifier:
  name: ansible
scenario:
  destroy_sequence:
    - destroy
  test_sequence:
    - destroy
    - create
    - prepare
    - converge
    - destroy
"""


def test_merge_preserved_keeps_unknown_keys_extracted_keys_win():
    desc = {"os_list": "all", "cleanup": "none"}
    existing = {"cleanup": "shared", "params": [{"name": "X"}], "jenkins": {"molecule_dir": "x/y"}}
    merged = ed.merge_preserved(desc, existing)
    assert merged["cleanup"] == "none"  # extracted wins
    assert merged["os_list"] == "all"
    assert merged["params"] == [{"name": "X"}]
    assert merged["jenkins"] == {"molecule_dir": "x/y"}


@pytest.mark.parametrize("group", JENKINS_GROUPS)
def test_jenkins_group_scenario_yml_is_canonical(group):
    # regression test for: --write re-serializing a hand-authored (but
    # semantically unchanged) scenario.yml on every run, dirtying a clean
    # tree. this asserts the on-disk file already equals its own canonical
    # (re-)serialization, byte for byte -- a further --write is a no-op.
    group_dir = REPO / group
    on_disk = (group_dir / "scenario.yml").read_text()
    assert group_canonical_text(group_dir) == on_disk, (
        "%s/scenario.yml not canonical -- run tools/extract_descriptors.py --write "
        "and commit the result" % group)


def test_double_write_is_byte_stable_with_preserved_sections():
    # generalized idempotence check, independent of any specific group:
    # writing twice in a row must converge -- the second write must be a
    # byte-for-byte no-op given the first write's output as input.
    group_dir = REPO / "_test_fakegrp_idempotent"
    try:
        (group_dir / "molecule" / "debian-13").mkdir(parents=True)
        (group_dir / "molecule" / "debian-13" / "molecule.yml").write_text(MOLECULE_YML)

        fake_jenkins = {"molecule_dir": "fakegrp", "artifacts": "fakegrp/artifacts/**/*.tar.gz",
                         "jobs": {"single": {"job_name": "x", "file": "x", "display_name": "d"}}}
        # hand-authored-style flow lists/quoting, like a human would write --
        # exactly the shape that broke idempotence before.
        (group_dir / "scenario.yml").write_text(
            "jenkins:\n  molecule_dir: fakegrp\n  artifacts: \"fakegrp/artifacts/**/*.tar.gz\"\n"
            "  jobs:\n    single: {job_name: x, file: x, display_name: d}\n"
            "params: [{name: FOO, choices: [a, b, c]}]\n")

        first = group_canonical_text(group_dir)
        (group_dir / "scenario.yml").write_text(first)
        second = group_canonical_text(group_dir)

        assert first == second
        assert yaml.safe_load(first)["jenkins"] == fake_jenkins
    finally:
        shutil.rmtree(group_dir, ignore_errors=True)


def test_write_preserves_jenkins_section_on_rewrite():
    # process_group needs group_dir under REPO (it does group_dir.relative_to(REPO)
    # for its notes messages), so this fixture lives under REPO and is removed after.
    group_dir = REPO / "_test_fakegrp_extract"
    try:
        (group_dir / "molecule" / "debian-13").mkdir(parents=True)
        (group_dir / "molecule" / "debian-13" / "molecule.yml").write_text(MOLECULE_YML)

        fake_jenkins = {"molecule_dir": "fakegrp", "artifacts": "fakegrp/artifacts/**/*.tar.gz",
                         "jobs": {"single": {"job_name": "x", "file": "x", "display_name": "d"}}}
        (group_dir / "scenario.yml").write_text(
            yaml.safe_dump({"jenkins": fake_jenkins, "params": [{"name": "FOO"}]}, sort_keys=False))

        notes = []
        desc = ed.process_group(group_dir, notes)
        existing = yaml.safe_load((group_dir / "scenario.yml").read_text())
        merged = ed.merge_preserved(desc, existing)

        assert merged["jenkins"] == fake_jenkins
        assert merged["params"] == [{"name": "FOO"}]
        # render keys got (re)extracted, not just carried over untouched
        assert "os_list" in merged or "scenarios" in merged
    finally:
        shutil.rmtree(group_dir, ignore_errors=True)
