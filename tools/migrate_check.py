"""Render every group/scenario from scenario.yml and diff against git.

Usage:
  migrate_check.py                     -- full run, summary report
  migrate_check.py --show GROUP SCEN   -- unified diff for one scenario
"""
import argparse
import difflib
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import yaml

from tools import render
from tools.catalog import find_groups, scenario_dirs


def substituted_original(group, scenario_dir_name, os_key=None):
    """Read the hand-written original. No substitution needed any more --
    both the original and the rendered output carry the same molecule
    env-var placeholders (${ami_*}, ${region}, ${vpc_subnet_id_*})."""
    return (REPO / group / "molecule" / scenario_dir_name / "molecule.yml").read_text()


def check_one(group_dir, scenario_name, desc):
    rendered = render.render_one(group_dir, scenario_name)
    rel = str(group_dir.relative_to(REPO))
    original = substituted_original(rel, scenario_name)
    return rendered, original


def cmd_show(group, scenario):
    group_dir = REPO / group
    desc = yaml.safe_load((group_dir / "scenario.yml").read_text())
    rendered, original = check_one(group_dir, scenario, desc)
    diff = difflib.unified_diff(
        original.splitlines(keepends=True),
        rendered.splitlines(keepends=True),
        fromfile="git:%s/molecule/%s/molecule.yml" % (group, scenario),
        tofile="rendered:%s/%s" % (group, scenario),
    )
    sys.stdout.writelines(diff)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--show", nargs=2, metavar=("GROUP", "SCENARIO"))
    args = ap.parse_args()

    if args.show:
        cmd_show(*args.show)
        return 0

    groups = find_groups()
    total_files = 0
    mismatches = 0
    for g in groups:
        rel = str(g.relative_to(REPO))
        desc_path = g / "scenario.yml"
        names = scenario_dirs(g)
        if not desc_path.exists():
            print("%s: FAIL no-scenario-yml" % rel)
            mismatches += len(names)
            total_files += len(names)
            continue
        try:
            desc = yaml.safe_load(desc_path.read_text())
        except Exception as e:
            print("%s: FAIL scenario.yml-parse-error(%s)" % (rel, e))
            mismatches += len(names)
            total_files += len(names)
            continue

        results = []
        # the descriptor has to expand to exactly the committed scenario dirs,
        # a per-file diff alone would not notice a dropped or extra os
        expanded = set(render.expand_scenarios(desc))
        for s in sorted(expanded - set(names)):
            results.append("%s(NOT-IN-TREE)" % s)
            mismatches += 1
        for s in sorted(set(names) - expanded):
            results.append("%s(NOT-IN-DESCRIPTOR)" % s)
            mismatches += 1
        for s in names:
            total_files += 1
            try:
                rendered, original = check_one(g, s, desc)
            except Exception as e:
                results.append("%s(ERROR %s: %s)" % (s, type(e).__name__, e))
                mismatches += 1
                continue
            if rendered != original:
                results.append("%s(DIFF)" % s)
                mismatches += 1

        if results:
            print("%s: FAIL " % rel + " ".join(results))
        else:
            print("%s: ok" % rel)

    print()
    print("%d mismatches / %d files" % (mismatches, total_files))
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
