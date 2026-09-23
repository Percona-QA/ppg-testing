"""Run a molecule group locally: resolve params, render, execute, destroy, collect.

Single-OS unit of work; --os accepts several keys and runs them sequentially.
Parallelism belongs to the caller (buildbot). Does not source local/env.sh:
the caller prepares the environment (driver/image vars), keeping the
aws/libvirt seam outside this tool.
"""
import argparse
import datetime
import json
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import time

REPO = pathlib.Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from tools import gen_groups
from tools import render

SKIP_PARAMS = {"PLATFORM", "DESTROY_ENV"}


class RunError(Exception):
    pass


def resolve_params(desc, overrides):
    """Descriptor param declarations + CLI overrides -> env var dict."""
    declared = {p["name"]: p for p in desc.get("params", [])}
    unknown = sorted(set(overrides) - set(declared))
    if unknown:
        raise RunError("unknown param(s): %s (declared: %s)"
                       % (", ".join(unknown), ", ".join(sorted(declared))))
    env = {}
    for name, p in declared.items():
        if name in SKIP_PARAMS:
            if name in overrides:
                raise RunError("param %s is not settable here "
                               "(PLATFORM comes from --os, DESTROY_ENV from --keep)" % name)
            continue
        kind = p.get("kind", "string")
        if name in overrides:
            val = overrides[name]
            if kind == "choice" and p.get("choices") and val not in p["choices"]:
                raise RunError("param %s: %r not one of %r" % (name, val, p["choices"]))
            if kind == "boolean":
                if val.lower() not in ("true", "false"):
                    raise RunError("param %s: %r not a boolean (true/false)" % (name, val))
                val = val.lower()
        elif "default" in p:
            val = p["default"]
        # no explicit default: first choice wins
        elif kind == "choice" and p.get("choices"):
            val = p["choices"][0]
        elif kind == "boolean":
            val = False
        else:
            continue
        if isinstance(val, bool):
            val = "true" if val else "false"
        env[name] = str(val)
    return env


def sequence_actions(desc, name):
    seqs = desc.get("sequences", {})
    if name not in seqs:
        raise RunError("unknown sequence %r (have: %s)"
                       % (name, ", ".join(sorted(seqs))))
    return list(seqs[name])


def validate_oses(desc, oses):
    known = render.expand_scenarios(desc)
    bad = [o for o in oses if o not in known]
    if bad:
        raise RunError("unknown os for this group: %s (have: %s)"
                       % (", ".join(bad), ", ".join(known)))


def _run(cmd, cwd, env, log):
    log.write(("\n$ %s\n" % " ".join(cmd)).encode())
    log.flush()
    proc = subprocess.Popen(cmd, cwd=str(cwd), env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in proc.stdout:
        sys.stdout.buffer.write(line)
        sys.stdout.buffer.flush()
        log.write(line)
        log.flush()
    return proc.wait()


def collect_artifacts(group_dir, os_dir, started, artifact_glob):
    fresh = [rx for rx in group_dir.rglob("report.xml") if rx.stat().st_mtime >= started]
    if fresh:
        newest = max(fresh, key=lambda p: p.stat().st_mtime)
        shutil.copy2(newest, os_dir / "report.xml")
    if artifact_glob:
        for p in sorted(REPO.glob(artifact_glob)):
            if p.is_file() and p.stat().st_mtime >= started:
                shutil.copy2(p, os_dir / p.name)


def run_os(group_dir, os_key, actions, base_env, os_dir, keep, artifact_glob):
    os_dir.mkdir(parents=True, exist_ok=True)
    env = dict(base_env)
    env["PLATFORM"] = os_key
    started = time.time()
    status = "failed"
    failed_action = None
    with open(os_dir / "molecule.log", "wb") as log:
        try:
            for action in actions:
                rc = _run(["molecule", action, "-s", os_key], group_dir, env, log)
                if rc != 0:
                    print("error: molecule %s -s %s exited %d"
                          % (action, os_key, rc), file=sys.stderr)
                    failed_action = action
                    break
            else:
                status = "passed"
        finally:
            if not keep:
                _run(["molecule", "destroy", "-s", os_key], group_dir, env, log)
            collect_artifacts(group_dir, os_dir, started, artifact_glob)
    result = {"status": status, "seconds": round(time.time() - started, 1)}
    if failed_action:
        result["failed_action"] = failed_action
    return result


def list_cmd(group):
    gen_groups.ensure()
    if not group:
        for g in render.find_all_groups():
            print(g.relative_to(REPO))
        return 0
    group_dir = render.resolve_group(group)
    desc = render.load_desc(group_dir)
    print("oses: " + " ".join(render.expand_scenarios(desc)))
    print("sequences: " + " ".join(sorted(desc.get("sequences", {}))))
    for p in desc.get("params", []):
        if p["name"] in SKIP_PARAMS:
            continue
        default = resolve_params(desc, {}).get(p["name"], "")
        print("param %-28s %-8s default=%s" % (p["name"], p.get("kind", "string"), default))
    return 0


def build_argparser():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--group", help="group dir, e.g. pg_tde/tde")
    ap.add_argument("--os", nargs="+", default=[], metavar="OS")
    ap.add_argument("--sequence", default="test")
    ap.add_argument("--param", action="append", default=[], metavar="NAME=VALUE")
    ap.add_argument("--keep", action="store_true",
                    help="skip the safety-net destroy (debugging)")
    ap.add_argument("--artifacts-dir")
    ap.add_argument("--fail-fast", action="store_true")
    ap.add_argument("--list", action="store_true")
    return ap


def main(argv=None):
    ap = build_argparser()
    args = ap.parse_args(argv)
    if args.list:
        return list_cmd(args.group)
    if not args.group or not args.os:
        ap.error("--group and --os are required (or use --list)")
    if "driver" not in os.environ:
        print("error: driver is not set -- source local/env.sh first "
              "(or moleculeEnvPPG on jenkins)", file=sys.stderr)
        return 2
    if shutil.which("molecule") is None:
        print("error: molecule not found on PATH -- activate the ppg-molecule venv",
              file=sys.stderr)
        return 2
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))

    gen_groups.ensure()
    group_dir = render.resolve_group(args.group)
    if not (group_dir / "scenario.yml").exists():
        print("error: no scenario.yml in %s" % group_dir, file=sys.stderr)
        return 2
    desc = render.load_desc(group_dir)
    try:
        bad = [p for p in args.param if "=" not in p]
        if bad:
            raise RunError("--param needs NAME=VALUE, got: %s" % ", ".join(bad))
        overrides = dict(p.partition("=")[::2] for p in args.param)
        params = resolve_params(desc, overrides)
        actions = sequence_actions(desc, args.sequence)
        validate_oses(desc, args.os)
    except RunError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2

    rc = render.main(["--group", str(group_dir)])
    if rc != 0:
        return rc

    if args.artifacts_dir:
        artifacts_dir = pathlib.Path(args.artifacts_dir)
    else:
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
        slug = str(group_dir.relative_to(REPO)).replace("/", "_")
        artifacts_dir = REPO / "local" / "runs" / ("%s-%s" % (stamp, slug))
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    base_env = dict(os.environ)
    base_env.update(params)
    artifact_glob = desc.get("jenkins", {}).get("artifacts")

    results = {}
    try:
        for os_key in args.os:
            results[os_key] = run_os(group_dir, os_key, actions, base_env,
                                     artifacts_dir / os_key, args.keep, artifact_glob)
            if args.fail_fast and results[os_key]["status"] != "passed":
                break
    finally:
        (artifacts_dir / "summary.json").write_text(json.dumps({
            "group": str(group_dir.relative_to(REPO)) if group_dir.is_relative_to(REPO) else str(group_dir),
            "sequence": args.sequence,
            "params": params,
            "oses": results,
        }, indent=2) + "\n")

    for os_key, r in results.items():
        where = " at %s" % r["failed_action"] if "failed_action" in r else ""
        print("%-20s %s%s (%ss)" % (os_key, r["status"], where, r["seconds"]))
    all_passed = (len(results) == len(args.os)
                  and all(r["status"] == "passed" for r in results.values()))
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
