"""Bootstrap scenario.yml descriptors from existing molecule.yml files.

Reads every group's molecule/<scenario>/molecule.yml, reverse engineers a
scenario.yml descriptor for the group, and (with --write) writes it out.
Prints a variance report of anything it could not represent losslessly or
any inconsistency found across a group's scenarios.
"""
import argparse
import json
import pathlib
import re
import sys
from collections import Counter

REPO = pathlib.Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import yaml

from tools import catalog
from tools.catalog import DEFAULT_CONVERGE, DEFAULT_BILLING_TAG, find_groups, scenario_dirs


def is_catalog_os_key(name):
    try:
        catalog.os_entry(name)
        return True
    except KeyError:
        return False


def build_ami_var_map():
    oses = catalog.load("os.yml")
    out = {}
    for k, v in oses.items():
        out[v["ami_var"]] = k
    return out


AMI_RE = re.compile(r"\$\{ami_([a-z0-9]+)_(x86_64|arm64)\}")


def infer_os_from_image(image, ami_var_map):
    m = AMI_RE.match(image or "")
    if not m:
        return None
    var, arch = m.groups()
    base = ami_var_map.get(var)
    if base is None:
        return None
    return base + ("-arm" if arch == "arm64" else "")


def mode(values):
    """most common value; values must be hashable. deterministic tie break."""
    c = Counter(values)
    best = max(c.values())
    for v in values:
        if c[v] == best:
            return v
    return values[0]


def derive_name_pattern(scenarios, notes):
    """scenarios: list of dicts with keys name, token, dirname.
    Returns (pattern, ok) where ok is False if it doesn't round-trip for all.
    """
    def roundtrip(pattern, use_token, use_scenario):
        for s in scenarios:
            got = pattern.format(
                token=s["token"] if use_token else "{token}",
                build="${BUILD_NUMBER}",
                job="${JOB_NAME}",
                scenario=s["dirname"] if use_scenario else "{scenario}",
            )
            if got != s["name"]:
                return False
        return True

    # scheme A: token based
    pats_a = set()
    for s in scenarios:
        p = s["name"].replace(s["token"], "{token}")
        p = p.replace("${BUILD_NUMBER}", "{build}").replace("${JOB_NAME}", "{job}")
        pats_a.add(p)
    if len(pats_a) == 1:
        cand = pats_a.pop()
        if "{token}" in cand and roundtrip(cand, True, False):
            return cand, True

    # scheme B: scenario dirname based
    pats_b = set()
    for s in scenarios:
        p = s["name"].replace(s["dirname"], "{scenario}")
        p = p.replace("${BUILD_NUMBER}", "{build}").replace("${JOB_NAME}", "{job}")
        pats_b.add(p)
    if len(pats_b) == 1:
        cand = pats_b.pop()
        if "{scenario}" in cand and roundtrip(cand, False, True):
            return cand, True

    # scheme C: both token and scenario
    pats_c = set()
    for s in scenarios:
        p = s["name"].replace(s["token"], "{token}").replace(s["dirname"], "{scenario}")
        p = p.replace("${BUILD_NUMBER}", "{build}").replace("${JOB_NAME}", "{job}")
        pats_c.add(p)
    if len(pats_c) == 1:
        cand = pats_c.pop()
        if roundtrip(cand, True, True):
            return cand, True

    # give up: best effort, use reference scenario's own literal pattern
    ref = scenarios[0]
    p = ref["name"].replace("${BUILD_NUMBER}", "{build}").replace("${JOB_NAME}", "{job}")
    notes.append("name_pattern: could not derive a pattern that round-trips "
                 "for all scenarios, using reference-only best effort: %r" % p)
    return p, False


def derive_size(instance_type, arch, aws, notes, ctx):
    for key, arches in aws["sizes"].items():
        if arches.get(arch) == instance_type:
            return key
    notes.append("%s: unknown instance_type %r for arch %s" % (ctx, instance_type, arch))
    return None


SUBNET_RE = re.compile(r"\$\{vpc_subnet_id_([a-z0-9]+)\}")


def derive_subnet(subnet_literal, aws, notes, ctx):
    m = SUBNET_RE.match(subnet_literal or "")
    if not m:
        notes.append("%s: unrecognized vpc_subnet_id literal %r" % (ctx, subnet_literal))
        return None
    key = m.group(1)
    if key not in aws["subnets"]:
        notes.append("%s: subnet key %r not in catalog aws.yml" % (ctx, key))
        return None
    return key


def derive_cleanup(cleanup_path, family, notes, ctx):
    if cleanup_path is None:
        return "none"
    if cleanup_path == "../../playbooks/cleanup.yml":
        return "shared"
    if cleanup_path == "../../playbooks/cleanup-%s.yml" % family:
        return "per-family"
    notes.append("%s: unrecognized cleanup playbook %r" % (ctx, cleanup_path))
    return "none"


def derive_verifier(verifier_block, notes, ctx):
    name = verifier_block.get("name")
    if name == "ansible":
        return "ansible"
    if name != "testinfra":
        notes.append("%s: unknown verifier name %r" % (ctx, name))
        return "ansible"
    options = verifier_block.get("options", {})
    testinfra = {"directory": verifier_block.get("directory")}
    if "m" in options:
        testinfra["markers"] = str(options["m"]).split(" or ")
    if "junitxml" not in options:
        testinfra["junitxml"] = False
    return {"testinfra": testinfra}


def canon(value):
    return json.dumps(value, sort_keys=True)


def merge_preserved(desc, existing):
    """merge extracted render keys (desc) with unknown top-level keys from
    existing scenario.yml (params, jenkins, ...) -- extracted keys win."""
    out = dict(desc)
    for key, value in (existing or {}).items():
        if key not in out:
            out[key] = value
    return out


def canonical_text(desc):
    """the single serialization used everywhere a scenario.yml gets written,
    so --write output and idempotence checks can never drift apart."""
    return yaml.safe_dump(desc, sort_keys=False, default_flow_style=False)


def process_group(group_dir, notes):
    rel = str(group_dir.relative_to(REPO))
    names = scenario_dirs(group_dir)
    if not names:
        notes.append("%s: no scenario dirs with molecule.yml found" % rel)
        return None

    ami_var_map = build_ami_var_map()
    aws = catalog.load("aws.yml")

    parsed = {}
    for n in names:
        f = group_dir / "molecule" / n / "molecule.yml"
        try:
            parsed[n] = yaml.safe_load(f.read_text())
        except Exception as e:
            notes.append("%s/%s: yaml parse error: %s" % (rel, n, e))
    names = [n for n in names if n in parsed]
    if not names:
        notes.append("%s: no scenario could be parsed" % rel)
        return None

    standard_mode = all(is_catalog_os_key(n) for n in names)

    resolved_os = {}
    if standard_mode:
        for n in names:
            resolved_os[n] = n
    else:
        for n in names:
            image = parsed[n]["platforms"][0]["image"]
            os_key = infer_os_from_image(image, ami_var_map)
            if os_key is None:
                notes.append("%s/%s: could not infer os from image %r" % (rel, n, image))
            resolved_os[n] = os_key

    # sanity check standard mode: does the image actually match the catalog os for that key?
    if standard_mode:
        for n in names:
            e = catalog.os_entry(n)
            image = parsed[n]["platforms"][0]["image"]
            expected_var = "ami_%s_%s" % (e["ami_var"], "arm64" if e["arm"] else "x86_64")
            if ("${%s}" % expected_var) != image:
                notes.append("%s/%s: image %r does not match catalog token (expected %s) "
                              "-- possible wrong token in catalog/os.yml" % (rel, n, image, expected_var))

    desc = {}

    # os_list / scenarios
    if standard_mode:
        lists = catalog.load("os-lists.yml")
        scen_set = set(names)
        matched = None
        for lname, keys in lists.items():
            if set(keys) == scen_set:
                matched = lname
                break
        if matched:
            desc["os_list"] = matched
        else:
            all_set = set(lists["all"])
            if scen_set <= all_set:
                exclude = sorted(all_set - scen_set)
                desc["os_list"] = {"list": "all", "exclude": exclude}
            else:
                notes.append("%s: scenario set is not a subset of catalog 'all' list" % rel)
                desc["os_list"] = {"list": "all", "exclude": sorted(all_set - scen_set)}
    else:
        desc["scenarios"] = {n: {"os": resolved_os[n]} for n in names}

    # name_pattern
    name_infos = []
    for n in names:
        os_key = resolved_os[n]
        if os_key is None:
            continue
        e = catalog.os_entry(os_key)
        token = e["token"] + ("-arm" if e["arm"] else "")
        name_infos.append({
            "name": parsed[n]["platforms"][0]["name"],
            "token": token,
            "dirname": n,
        })
    if name_infos:
        pattern, ok = derive_name_pattern(name_infos, notes)
        desc["name_pattern"] = pattern
        if not ok:
            notes.append("%s: name_pattern does not round-trip for every scenario" % rel)
    else:
        notes.append("%s: no scenario had a resolvable os, cannot derive name_pattern" % rel)
        desc["name_pattern"] = "{token}-{build}"

    # per-scenario derived attributes, for mode + deviation detection
    sizes, subnets, cleanups, verifiers, sequences, converges, volume_sizes = (
        {}, {}, {}, {}, {}, {}, {})
    emit_name_scenarios = set()
    billing_tags = {}
    for n in names:
        p = parsed[n]
        os_key = resolved_os[n]
        platform = p["platforms"][0]
        arch = "arm" if (os_key and os_key.endswith("-arm")) else "x86"
        ctx = "%s/%s" % (rel, n)
        billing_tags[n] = platform.get("instance_tags", {}).get("iit-billing-tag", DEFAULT_BILLING_TAG)
        sizes[n] = derive_size(platform["instance_type"], arch, aws, notes, ctx)
        subnets[n] = derive_subnet(platform["vpc_subnet_id"], aws, notes, ctx)
        family = catalog.os_entry(os_key)["family"] if os_key else None
        cleanup_path = p["provisioner"]["playbooks"].get("cleanup")
        cleanups[n] = derive_cleanup(cleanup_path, family, notes, ctx)
        verifiers[n] = derive_verifier(p["verifier"], notes, ctx)
        seq = {"destroy": p["scenario"]["destroy_sequence"], "test": p["scenario"]["test_sequence"]}
        if "cleanup_sequence" in p["scenario"]:
            seq["cleanup"] = p["scenario"]["cleanup_sequence"]
        sequences[n] = seq
        converges[n] = p["provisioner"]["playbooks"].get("converge", DEFAULT_CONVERGE)
        volume_sizes[n] = platform.get("volume_size")

        extra_scenario_keys = set(p["scenario"]) - {"destroy_sequence", "cleanup_sequence", "test_sequence"}
        if extra_scenario_keys == {"name"} and p["scenario"]["name"] == n:
            emit_name_scenarios.add(n)
        elif extra_scenario_keys:
            notes.append("%s: scenario block has extra keys not representable: %s"
                         % (ctx, sorted(extra_scenario_keys)))

    def flag_deviations(label, mapping):
        vals = [v for v in mapping.values() if v is not None]
        if not vals:
            return None, {}
        m = mode([canon(v) for v in vals])
        deviants = {n: v for n, v in mapping.items() if v is not None and canon(v) != m}
        if deviants:
            notes.append("%s: %s differs across scenarios, using majority value; deviants: %s"
                         % (rel, label, ", ".join(sorted(deviants))))
        for n, v in mapping.items():
            if v is not None and canon(v) == m:
                return v, deviants
        return vals[0], deviants

    size_val, size_deviants = flag_deviations("aws.size", sizes)
    subnet_val, subnet_deviants = flag_deviations("aws.subnet", subnets)
    cleanup_val, cleanup_deviants = flag_deviations("cleanup", cleanups)
    verifier_val, verifier_deviants = flag_deviations("verifier", verifiers)
    sequences_val, sequences_deviants = flag_deviations("sequences", sequences)
    converge_val, converge_deviants = flag_deviations("playbooks.converge", converges)
    volume_val, volume_deviants = flag_deviations("aws.volume_size", volume_sizes)
    billing_val, billing_tag_deviants = flag_deviations("billing_tag", billing_tags)

    if verifier_deviants:
        notes.append("%s: verifier deviation has no overrides mechanism -- escalate" % rel)
    if converge_deviants:
        notes.append("%s: playbooks.converge deviation has no overrides mechanism -- escalate" % rel)

    desc["aws"] = {}
    if size_val:
        desc["aws"]["size"] = size_val
    if subnet_val:
        desc["aws"]["subnet"] = subnet_val
    if volume_val:
        desc["aws"]["volume_size"] = volume_val

    if billing_val != DEFAULT_BILLING_TAG:
        desc["billing_tag"] = billing_val
    desc["cleanup"] = cleanup_val or "none"
    desc["verifier"] = verifier_val if verifier_val is not None else "ansible"
    desc["sequences"] = sequences_val

    if converge_val and converge_val != DEFAULT_CONVERGE:
        desc["playbooks"] = {"converge": converge_val}

    # overrides: per-scenario deviations that the majority-value collapse above lost
    override_names = (set(emit_name_scenarios) | set(cleanup_deviants) | set(sequences_deviants)
                       | set(size_deviants) | set(subnet_deviants) | set(volume_deviants)
                       | set(billing_tag_deviants))
    overrides = {}
    for n in sorted(override_names):
        entry = {}
        if n in emit_name_scenarios:
            entry["emit_scenario_name"] = True
        if n in cleanup_deviants:
            entry["cleanup"] = cleanup_deviants[n]
        if n in billing_tag_deviants:
            entry["billing_tag"] = billing_tag_deviants[n]
        aws_entry = {}
        if n in size_deviants:
            aws_entry["size"] = size_deviants[n]
        if n in subnet_deviants:
            aws_entry["subnet"] = subnet_deviants[n]
        if n in volume_deviants:
            aws_entry["volume_size"] = volume_deviants[n]
        if aws_entry:
            entry["aws"] = aws_entry
        if n in sequences_deviants:
            entry["sequences"] = sequences_deviants[n]
        overrides[n] = entry
    if overrides:
        desc["overrides"] = overrides

    return desc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    groups = find_groups()
    total_notes = []
    written = 0
    for g in groups:
        rel = str(g.relative_to(REPO))
        notes = []
        desc = process_group(g, notes)
        total_notes.extend(notes)
        if desc is None:
            continue

        target = g / "scenario.yml"

        # preserve top-level keys the extractor doesn't know about (params,
        # jenkins, ...) -- it only owns the render keys.
        if target.exists():
            existing = yaml.safe_load(target.read_text()) or {}
            desc = merge_preserved(desc, existing)

        if args.write:
            target.write_text(canonical_text(desc))
            written += 1

    print()
    print("=== variance report (%d items) ===" % len(total_notes))
    for n in total_notes:
        print("- " + n)
    print()
    print("%d groups processed, %d scenario.yml written" % (len(groups), written))


if __name__ == "__main__":
    sys.exit(main())
