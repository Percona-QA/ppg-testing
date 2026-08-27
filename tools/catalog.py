import pathlib
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent

DEFAULT_CONVERGE = "../../playbooks/playbook.yml"
DEFAULT_BILLING_TAG = "jenkins-pg-molecule"

SKIP_NAMES = {"__init__.py", "__pycache__"}


def load(name):
    with open(ROOT / "catalog" / name) as f:
        return yaml.safe_load(f)


def is_hidden(rel):
    """paths under dot-dirs (.venv, .molecule, ...) are never groups"""
    return any(part.startswith(".") for part in rel.parts)


def find_groups():
    """groups with a hand-written molecule/ dir."""
    groups = set()
    for p in ROOT.rglob("molecule"):
        if not p.is_dir():
            continue
        rel = p.relative_to(ROOT)
        if rel.parts[0] == "tools" or is_hidden(rel):
            continue
        groups.add(p.parent)
    return sorted(groups, key=lambda p: str(p.relative_to(ROOT)))


def scenario_dirs(group_dir):
    """scenario dir names under group_dir/molecule/ that hold a molecule.yml."""
    mdir = group_dir / "molecule"
    if not mdir.is_dir():
        return []
    out = []
    for d in sorted(mdir.iterdir()):
        if d.name in SKIP_NAMES:
            continue
        if d.is_dir() and (d / "molecule.yml").exists():
            out.append(d.name)
    return out


def os_entry(os_key):
    if os_key.endswith("-arm"):
        base, arm = os_key[:-4], True
    else:
        base, arm = os_key, False
    entry = dict(load("os.yml")[base])
    entry["key"] = os_key
    entry["base"] = base
    entry["arm"] = arm
    return entry
