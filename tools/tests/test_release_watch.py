import datetime as dt
import functools
import gzip
import http.server
import json
import pathlib
import threading

import pytest
import yaml

from tools import release_watch as rw

NOW = dt.datetime(2026, 9, 26, 12, 0, tzinfo=dt.timezone.utc)
SETTINGS = {"settle_minutes": 60, "incomplete_alert_hours": 24,
            "stale_run_hours": 18}


def mins(n):
    return NOW + dt.timedelta(minutes=n)


# ------------------------------------------------------------ versions

@pytest.mark.parametrize("a,b,sign", [
    ("18.10-1", "18.9-1", 1),
    ("18.4-2", "18.4-1", 1),
    ("18.4~rc1-1", "18.4-1", -1),
    ("2:18.4-1", "1:19.0-1", 1),
    ("2.2.0-1", "2.2.0-1", 0),
])
def test_vercmp(a, b, sign):
    r = rw.vercmp(a, b)
    assert (r > 0) - (r < 0) == sign


@pytest.mark.parametrize("raw,want", [
    ("2:18.4-1.noble", "18.4-1"),
    ("0:18.4-1.el9", "18.4-1"),
    ("18.4-1.el9_6", "18.4-1"),
    ("1:4.0.6-2~deb12u1", "4.0.6-2"),
    ("0:2.2.0-0.1.rc1.el9", "2.2.0-0.1.rc1"),
    ("18.4", "18.4"),
])
def test_canonical(raw, want):
    assert rw.canonical(raw) == want


def test_parse_apt_keeps_highest():
    text = ("Package: a\nVersion: 1.0-1\n\nPackage: a\nVersion: 1.2-1\n\n"
            "Package: b\nArchitecture: all\nVersion: 2:3-1\n")
    assert rw.parse_apt_packages(text) == {"a": "1.2-1", "b": "2:3-1"}


def test_parse_rpm_primary_skips_src():
    assert rw.parse_rpm_primary(primary_xml({"x": "1.0-1.el9"}, src=True)) \
        == {"x": "0:1.0-1.el9"}


# ------------------------------------------------------------ decide

STREAM = {
    "name": "ppg-18", "version": "{repo}",
    "prev_version": "ppg-18.{minor_prev}",
    "jobs": [
        {"id": "server", "job": "ppg-multiOS-parallel", "on": ["*"],
         "params": {"VERSION": "{version}", "SCENARIO": "pg-18"}},
        {"id": "minor-upgrade", "job": "ppg-upgrade-parallel",
         "on": ["server"],
         "params": {"FROM_VERSION": "{prev_version}", "VERSION": "{version}"}},
        {"id": "major-upgrade", "job": "ppg-upgrade-parallel",
         "on": ["server"], "params": {"FROM_VERSION": "{verified[ppg-17]}"}},
        {"id": "pgsm", "job": "pgsm-parallel", "on": ["pgsm"],
         "params": {"PGSM_BRANCH": "{upstream[pgsm]}"}},
    ],
}


def obs(repo="ppg-18.5", minor=5, complete=True, **pkgs):
    pkgs = pkgs or {"server": "18.5-1", "pgsm": "2.3.2-1"}
    o = {"repo": repo, "minor": minor, "prev_minor": minor - 1,
         "platforms": ["noble/amd64"],
         "packages": pkgs, "missing": [] if complete else ["server@x"],
         "conflicts": [], "urls": {}, "complete": complete}
    o["fingerprint"] = repr(sorted(pkgs.items())) + repo + str(complete)
    return o


VERIFIED = {"verified": {"version": "ppg-18.4", "repo": "ppg-18.4",
                         "packages": {"server": "18.4-1", "pgsm": "2.3.2-1"}}}


def run(o, state, now, force=False, verified=None):
    return rw.decide(STREAM, o, state, verified or {"ppg-17": "ppg-17.10"},
                     now, SETTINGS, force=force)


def settled(o, state=VERIFIED):
    """First sighting starts the settle timer; a poll 61 min later decides."""
    st, launch, _, _ = run(o, state, NOW)
    assert launch is None
    return run(o, st, mins(61))


def test_new_version_launches_after_settle():
    st, launch, notes, summary = settled(obs())
    assert launch and summary.startswith("ppg-18: launching")
    assert st["attempt"]["status"] == "running"
    jobs = {j["id"]: j["params"] for j in launch["jobs"]}
    assert set(jobs) == {"server", "minor-upgrade", "major-upgrade"}
    assert jobs["minor-upgrade"] == {"FROM_VERSION": "ppg-18.4",
                                     "VERSION": "ppg-18.5"}
    assert jobs["major-upgrade"] == {"FROM_VERSION": "ppg-17.10"}
    assert launch["changed"] == {"server": ["18.4-1", "18.5-1"]}


def test_same_version_rebuilt_daily_does_not_launch():
    o = obs(repo="ppg-18.4", minor=4, server="18.4-1", pgsm="2.3.2-1")
    st, launch, _, summary = run(o, VERIFIED, NOW)
    assert launch is None and "up to date" in summary
    st, launch, _, _ = run(o, st, mins(24 * 60))
    assert launch is None


def test_release_bump_counts_unless_compare_upstream():
    o = obs(repo="ppg-18.4", minor=4, server="18.4-2", pgsm="2.3.2-1")
    assert settled(o)[1] is not None
    stream = dict(STREAM, compare="upstream")
    st, _, _, _ = rw.decide(stream, o, VERIFIED, {}, NOW, SETTINGS)
    _, launch, _, summary = rw.decide(stream, o, st, {}, mins(61), SETTINGS)
    assert launch is None and "up to date" in summary


def test_changes_during_settle_restart_the_timer():
    st, _, _, _ = run(obs(server="18.5-1"), VERIFIED, NOW)
    st, launch, _, _ = run(obs(server="18.5-1", pgsm="2.3.3-1"), st, mins(50))
    assert launch is None
    st, launch, _, s = run(obs(server="18.5-1", pgsm="2.3.3-1"), st, mins(100))
    assert launch is None and "settling" in s
    _, launch, _, _ = run(obs(server="18.5-1", pgsm="2.3.3-1"), st, mins(111))
    assert launch and {j["id"] for j in launch["jobs"]} == {
        "server", "minor-upgrade", "major-upgrade", "pgsm"}


def test_incomplete_waits_and_alerts_once():
    o = obs(complete=False)
    st, launch, notes, s = run(o, VERIFIED, NOW)
    assert launch is None and "incomplete" in s and not notes
    st, launch, notes, _ = run(o, st, mins(25 * 60))
    assert launch is None and len(notes) == 1
    st, launch, notes, _ = run(o, st, mins(26 * 60))
    assert not notes


def test_running_attempt_blocks_new_launch():
    st, launch, _, _ = settled(obs())
    st2, launch2, _, s = run(obs(server="18.5-2"), st, mins(200))
    assert launch2 is None and "in progress" in s


def test_stale_running_attempt_is_failed_and_reported():
    st, _, _, _ = settled(obs())
    st, launch, notes, _ = run(obs(), st, mins(61 + 19 * 60))
    assert st["attempt"]["status"] == "failed"
    assert notes and notes[0]["level"] == "danger"
    assert launch is None     # same packages already failed: no loop


def test_unresolvable_param_skips_job_with_warning():
    st, launch, notes, _ = rw.decide(STREAM, obs(), VERIFIED, {}, NOW,
                                     SETTINGS)
    st, launch, notes, _ = rw.decide(STREAM, obs(), st, {}, mins(61),
                                     SETTINGS)
    assert "major-upgrade" not in {j["id"] for j in launch["jobs"]}
    assert any("major-upgrade" in n["text"] for n in notes)


def test_prev_version_fallback_on_respin():
    o = obs(repo="ppg-18.4", minor=4, server="18.4-2", pgsm="2.3.2-1")
    _, launch, _, _ = settled(o)
    up = {j["id"]: j for j in launch["jobs"]}["minor-upgrade"]
    assert up["params"]["FROM_VERSION"] == "ppg-18.3"


def test_force_launches_everything_immediately():
    o = obs(repo="ppg-18.4", minor=4, server="18.4-1", pgsm="2.3.2-1")
    _, launch, _, _ = run(o, VERIFIED, NOW, force=True)
    assert {j["id"] for j in launch["jobs"]} == {
        "server", "minor-upgrade", "major-upgrade", "pgsm"}


def test_older_version_in_repo_blocks_and_alerts():
    o = obs(repo="ppg-18.4", minor=4, server="18.3-1", pgsm="2.3.2-1")
    _, launch, notes, s = run(o, VERIFIED, NOW)
    assert launch is None and "downgrade: server 18.3-1 (verified 18.4-1)" in s
    assert {n["to"] for n in notes} == {"qa", "release"}


# ------------------------------------------------------------ fake repo e2e

def _vs(v):
    """A package entry is 'version' or ('version', 'source package')."""
    return v if isinstance(v, tuple) else (v, None)


def primary_xml(pkgs, src=False):
    ns = "http://linux.duke.edu/metadata/common"
    items = []
    for name, entry in pkgs.items():
        ver, source = _vs(entry)
        v, r = ver.split("-", 1)
        srpm = "%s-%s-%s.src.rpm" % (source or name, v, r)
        for arch in ["x86_64"] + (["src"] if src else []):
            items.append(
                '<package type="rpm"><name>%s</name><arch>%s</arch>'
                '<version epoch="0" ver="%s" rel="%s"/>'
                '<format><rpm:sourcerpm>%s</rpm:sourcerpm></format></package>'
                % (name, arch, v, r, srpm))
    return ('<?xml version="1.0"?><metadata xmlns="%s" '
            'xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="%d">%s'
            '</metadata>' % (ns, len(items), "".join(items))).encode()


class FakeRepo:
    """Serves repo.percona.com-shaped apt and yum indexes from a temp dir."""

    def __init__(self, root):
        self.root = pathlib.Path(root)

    def publish(self, repo, deb, rpm):
        d = self.root / repo / "apt/dists/noble/testing/binary-amd64"
        d.mkdir(parents=True, exist_ok=True)
        text = ""
        for name, entry in deb.items():
            ver, source = _vs(entry)
            text += "Package: %s\n" % name
            if source:
                text += "Source: %s\n" % source
            text += "Version: %s\n\n" % ver
        (d / "Packages.gz").write_bytes(gzip.compress(text.encode()))
        y = self.root / repo / "yum/testing/9/RPMS/x86_64/repodata"
        y.mkdir(parents=True, exist_ok=True)
        (y / "primary.xml.gz").write_bytes(gzip.compress(primary_xml(rpm)))
        (y / "repomd.xml").write_text(
            '<?xml version="1.0"?><repomd xmlns="http://linux.duke.edu/'
            'metadata/repo"><data type="primary"><location '
            'href="repodata/primary.xml.gz"/></data></repomd>')


@pytest.fixture
def fake_repo(tmp_path):
    root = tmp_path / "www"
    root.mkdir()
    handler = functools.partial(http.server.SimpleHTTPRequestHandler,
                                directory=str(root))
    handler.log_message = lambda *a: None
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield FakeRepo(root), "http://127.0.0.1:%d" % srv.server_port
    srv.shutdown()


def write_config(tmp_path, base):
    cfg = {
        "settings": {"settle_minutes": 0},
        "slack": {"qa": "#qa", "release": "#build"},
        "streams": {"ppg-18": {
            "source": {"type": "repo", "repo": "ppg-18.{minor}",
                       "start_minor": 4, "minor_lookahead": 2,
                       "indexes": [
                {"format": "apt", "codename": ["noble"], "arch": ["amd64"],
                 "url": base + "/{repo}/apt/dists/{codename}/testing/"
                               "binary-{arch}/Packages"},
                {"format": "rpm", "rhel": [9], "arch": ["x86_64"],
                 "url": base + "/{repo}/yum/testing/{rhel}/RPMS/{arch}"}]},
            "packages": {
                "server": {"apt": "percona-postgresql-18",
                           "rpm": "percona-postgresql18-server",
                           "required": True},
                "patroni": "percona-patroni"},
            "jobs": [{"id": "server", "job": "ppg-multiOS-parallel",
                      "params": {"VERSION": "{version}", "MAJOR_REPO": False}}],
        }},
    }
    p = tmp_path / "config.yml"
    p.write_text(yaml.safe_dump(cfg))
    return p


def cli(cfg, state, *args):
    return rw.main(["--config", str(cfg), "--state", str(state)] + list(args))


def test_end_to_end_minor_discovery_record_and_rollback(fake_repo, tmp_path):
    repo, base = fake_repo
    cfg = write_config(tmp_path, base)
    state = tmp_path / "VERSIONS.yml"
    plan = tmp_path / "plan.json"
    builds = tmp_path / "builds.json"

    repo.publish("ppg-18.4",
                 {"percona-postgresql-18": "2:18.4-1.noble",
                  "percona-patroni": "1:4.0.6-1.noble"},
                 {"percona-postgresql18-server": "18.4-1.el9",
                  "percona-patroni": "4.0.6-1.el9"})
    cli(cfg, state, "baseline")
    assert rw.load_state(state)["streams"]["ppg-18"]["verified"]["packages"] \
        == {"server": "18.4-1", "patroni": "4.0.6-1"}

    # Daily rebuild, same versions: nothing launches.
    cli(cfg, state, "poll", "--plan", str(plan))
    assert json.loads(plan.read_text())["launches"] == []

    # ppg-18.5 appears but only the deb side is pushed: wait.
    repo.publish("ppg-18.5", {"percona-postgresql-18": "2:18.5-1.noble"}, {})
    cli(cfg, state, "poll", "--plan", str(plan))
    assert json.loads(plan.read_text())["launches"] == []

    # The yum directory for 18.5 does not even exist yet (404, not empty):
    # still incomplete because 9/x86_64 was in the verified set.
    import shutil
    shutil.rmtree(repo.root / "ppg-18.5" / "yum")
    cli(cfg, state, "poll", "--plan", str(plan))
    assert json.loads(plan.read_text())["launches"] == []
    obs_state = rw.load_state(state)["streams"]["ppg-18"]["observed"]
    assert any(m.startswith("platform") and "x86_64" in m
               for m in obs_state["missing"])

    # rpm side lands: first poll records the new fingerprint (settle=0) and
    # launches with the discovered minor.
    repo.publish("ppg-18.5",
                 {"percona-postgresql-18": "2:18.5-1.noble",
                  "percona-patroni": "1:4.0.6-1.noble"},
                 {"percona-postgresql18-server": "18.5-1.el9",
                  "percona-patroni": "4.0.6-1.el9"})
    cli(cfg, state, "poll", "--plan", str(plan))
    launches = json.loads(plan.read_text())["launches"]
    assert len(launches) == 1
    launch = launches[0]
    assert launch["version"] == "ppg-18.5"
    assert launch["jobs"][0]["params"] == {"VERSION": "ppg-18.5",
                                           "MAJOR_REPO": False}
    st = rw.load_state(state)["streams"]["ppg-18"]
    assert st["attempt"]["status"] == "running"

    # QA fails: verified stays at 18.4 (rollback), no relaunch loop.
    builds.write_text(json.dumps([{"id": "server", "result": "FAILURE",
                                   "url": "http://j/1"}]))
    msg = tmp_path / "msg.json"
    cli(cfg, state, "record", "--stream", "ppg-18", "--attempt-id",
        launch["attempt_id"], "--builds", str(builds), "--message", str(msg))
    st = rw.load_state(state)["streams"]["ppg-18"]
    assert st["verified"]["version"] == "ppg-18.4"
    assert st["attempt"]["status"] == "failed"
    assert json.loads(msg.read_text())["channel"] == "#qa"
    cli(cfg, state, "poll", "--plan", str(plan))
    assert json.loads(plan.read_text())["launches"] == []

    # Build team pushes a fixed 18.5-2: relaunch, pass, promote.
    repo.publish("ppg-18.5",
                 {"percona-postgresql-18": "2:18.5-2.noble",
                  "percona-patroni": "1:4.0.6-1.noble"},
                 {"percona-postgresql18-server": "18.5-2.el9",
                  "percona-patroni": "4.0.6-1.el9"})
    cli(cfg, state, "poll", "--plan", str(plan))
    launch = json.loads(plan.read_text())["launches"][0]
    builds.write_text(json.dumps([{"id": "server", "result": "SUCCESS"}]))
    cli(cfg, state, "record", "--stream", "ppg-18", "--attempt-id",
        launch["attempt_id"], "--builds", str(builds), "--message", str(msg))
    st = rw.load_state(state)["streams"]["ppg-18"]
    assert st["verified"]["version"] == "ppg-18.5"
    assert st["verified"]["packages"]["server"] == "18.5-2"
    m = json.loads(msg.read_text())
    assert m["channel"] == "#build" and "ready to be released" in m["text"]

    # Future probes start from the verified minor.
    cli(cfg, state, "poll", "--plan", str(plan))
    assert json.loads(plan.read_text())["launches"] == []


def test_retry_clears_failed_attempt(fake_repo, tmp_path):
    repo, base = fake_repo
    cfg = write_config(tmp_path, base)
    state = tmp_path / "VERSIONS.yml"
    plan = tmp_path / "plan.json"
    repo.publish("ppg-18.4", {"percona-postgresql-18": "18.4-1"},
                 {"percona-postgresql18-server": "18.4-1.el9"})
    cli(cfg, state, "poll", "--plan", str(plan))
    a = json.loads(plan.read_text())["launches"][0]["attempt_id"]
    b = tmp_path / "b.json"
    b.write_text("[]")
    cli(cfg, state, "record", "--stream", "ppg-18", "--attempt-id", a,
        "--builds", str(b), "--aborted", "agent lost")
    cli(cfg, state, "poll", "--plan", str(plan))
    assert json.loads(plan.read_text())["launches"] == []
    cli(cfg, state, "retry", "ppg-18")
    cli(cfg, state, "poll", "--plan", str(plan))
    assert len(json.loads(plan.read_text())["launches"]) == 1


def test_conditional_get_cache(fake_repo, tmp_path):
    repo, base = fake_repo
    repo.publish("ppg-18.4", {"a": "1-1"}, {"a": "1-1.el9"})
    f = rw.Fetcher(tmp_path / "cache")
    url = base + "/ppg-18.4/apt/dists/noble/testing/binary-amd64/Packages.gz"
    first = f.get(url)
    assert f.get(url) == first
    assert f.get(base + "/nope") is None


def test_shipped_config_loads():
    cfg = rw.load_config(rw.DEFAULT_CONFIG)
    s = cfg["streams"]["ppg-18"]
    assert s["source"]["repo"] == "ppg-18.{minor}"
    assert s["source"]["start_minor"] == 4
    assert "major-upgrade" not in {j["id"] for j in cfg["streams"]["ppg-14"]
                                   ["jobs"]}
    for name, st in cfg["streams"].items():
        for job in st["jobs"]:
            assert "<<" not in json.dumps(job), (name, job)


def test_forbidden_is_an_error_not_an_empty_repo(tmp_path):
    class Deny(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(403)
            self.send_header("x-deny-reason", "host_not_allowed")
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Deny)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = "http://127.0.0.1:%d" % srv.server_port
        cfg = write_config(tmp_path, base)
        state = tmp_path / "VERSIONS.yml"
        plan = tmp_path / "plan.json"
        cli(cfg, state, "poll", "--plan", str(plan))
        p = json.loads(plan.read_text())
        assert p["launches"] == []
        assert "host_not_allowed" in p["summary"][0]
        assert p["notifications"][0]["channel"] == "#qa"
        cli(cfg, state, "poll", "--plan", str(plan))   # same error: quiet
        assert json.loads(plan.read_text())["notifications"] == []
    finally:
        srv.shutdown()


# ------------------------------------------------------------ minor discovery

def _stream_with(start=3, look=3):
    return {"source": {"start_minor": start, "minor_lookahead": look}}


@pytest.mark.parametrize("existing,verified_minor,want", [
    ({3, 6}, 3, 6),          # the real ppg-18 layout: 18.4 and 18.5 absent
    ({3, 6}, None, 6),       # same, before any verified version (start_minor)
    ({4, 5, 6, 7}, 4, 7),
    ({3, 7}, 3, 7),          # gap of three, still inside minor_lookahead=3
    ({3, 8}, 3, 3),          # gap of four: stops, keeps the last hit
    ({10}, 3, None),         # nothing near the verified minor
    (set(), 3, None),
])
def test_discover_minor_tolerates_gaps(existing, verified_minor, want):
    state = {"verified": {"repo": "ppg-18.%d" % verified_minor}} \
        if verified_minor is not None else {}
    probed = []

    def probe(m):
        probed.append(m)
        return m in existing

    got = rw.discover_minor(_stream_with(), state, probe)
    assert (got[0] if got else None) == want
    assert len(probed) < 20


def test_lagging_verified_still_finds_newest_repo(fake_repo, tmp_path):
    """Reproduces the field report: verified says ppg-18.3, repos exist for
    18.3 and 18.6 only; the old fixed window (3..5) reported 'up to date'."""
    repo, base = fake_repo
    cfg = write_config(tmp_path, base)
    state = tmp_path / "VERSIONS.yml"
    plan = tmp_path / "plan.json"
    for minor in (3, 6):
        repo.publish("ppg-18.%d" % minor,
                     {"percona-postgresql-18": "2:18.%d-1.noble" % minor},
                     {"percona-postgresql18-server": "18.%d-1.el9" % minor})
    rw.save_state(state, {"streams": {"ppg-18": {"verified": {
        "version": "ppg-18.3", "repo": "ppg-18.3",
        "packages": {"server": "18.3-1"}}}}})
    cli(cfg, state, "poll", "--plan", str(plan))
    launch = json.loads(plan.read_text())["launches"][0]
    assert launch["version"] == "ppg-18.6"
    assert launch["changed"] == {"server": ["18.3-1", "18.6-1"]}


def test_head_not_allowed_falls_back_to_get(tmp_path):
    class NoHead(http.server.BaseHTTPRequestHandler):
        def do_HEAD(self):
            self.send_response(405)
            self.end_headers()

        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), NoHead)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        f = rw.Fetcher()
        assert f.get("http://127.0.0.1:%d/x" % srv.server_port,
                     method="HEAD") is not None
    finally:
        srv.shutdown()


def test_respin_upgrades_from_previous_existing_minor(fake_repo, tmp_path):
    """18.6-1 -> 18.6-2 respin with 18.4/18.5 absent: minor-upgrade must
    start from ppg-18.3, not the nonexistent ppg-18.5."""
    repo, base = fake_repo
    cfg_path = write_config(tmp_path, base)
    cfg = yaml.safe_load(cfg_path.read_text())
    s = cfg["streams"]["ppg-18"]
    s["prev_version"] = "ppg-18.{minor_prev}"
    s["jobs"].append({"id": "minor-upgrade", "job": "ppg-upgrade-parallel",
                      "params": {"FROM_VERSION": "{prev_version}"}})
    cfg_path.write_text(yaml.safe_dump(cfg))
    state = tmp_path / "VERSIONS.yml"
    plan = tmp_path / "plan.json"
    for minor in (3, 6):
        repo.publish("ppg-18.%d" % minor,
                     {"percona-postgresql-18": "18.%d-1" % minor},
                     {"percona-postgresql18-server": "18.%d-1.el9" % minor})
    cli(cfg_path, state, "baseline")
    repo.publish("ppg-18.6", {"percona-postgresql-18": "18.6-2"},
                 {"percona-postgresql18-server": "18.6-2.el9"})
    cli(cfg_path, state, "poll", "--plan", str(plan))
    jobs = {j["id"]: j for j in json.loads(plan.read_text())["launches"][0]
            ["jobs"]}
    assert jobs["minor-upgrade"]["params"]["FROM_VERSION"] == "ppg-18.3"


# ------------------------------------------------------------ components

def test_parsers_group_binaries_by_source_package():
    apt = rw.parse_apt_packages(
        "Package: percona-postgresql-18-repack\nSource: percona-pg-repack\n"
        "Version: 1.5.3-3.noble\n\n"
        "Package: percona-pg-repack-dbgsym\nSource: percona-pg-repack (1.5.3-3.noble)\n"
        "Version: 1.5.3-3.noble\n\n"
        "Package: psycopg2\nVersion: 2.9.5-1.noble\n")
    assert apt.sources == {"percona-pg-repack": "1.5.3-3.noble",
                           "psycopg2": "2.9.5-1.noble"}
    rpm = rw.parse_rpm_primary(primary_xml(
        {"percona-pg_repack18": ("1.5.3-3.el9", "percona-pg_repack18"),
         "percona-pg_repack18-debuginfo": ("1.5.3-3.el9", "percona-pg_repack18")}))
    assert rpm.sources == {"percona-pg_repack18": "0:1.5.3-3.el9"}


PPG18_COMPONENTS = [
    "percona-haproxy", "percona-patroni", "percona-pg-cron", "percona-pg-gather",
    "percona-pg-oidc-validator18", "percona-pg-repack", "percona-pg-stat-monitor",
    "percona-pg-tde18", "percona-pgaudit", "percona-pgaudit18-set-user",
    "percona-pgbackrest", "percona-pgbadger", "percona-pgbouncer",
    "percona-pgpool2", "percona-pgvector", "percona-postgis",
    "percona-postgresql-18", "percona-postgresql-common",
    "percona-ppg-server-18", "percona-ppg-server-ha-18", "percona-wal2json",
    "psycopg2", "python3-pysyncobj"]


def _repo_with(components, build, overrides=None, major=18):
    """deb and rpm contents where each component's binary name differs from
    its source name, as in the real repo."""
    overrides = overrides or {}
    srv = "percona-postgresql-%d" % major
    deb, rpm = {}, {}
    for c in components:
        ver = overrides.get(c, "1.0-%d" % build)
        deb["%s-bin" % c] = (ver + ".noble", c)
        rpm["%s-bin" % c] = (ver + ".el9", c)
    srv_ver = overrides.get(srv, "%d.4-%d" % (major, build))
    deb[srv] = (srv_ver + ".noble", srv)
    rpm["percona-postgresql%d-server" % major] = (srv_ver + ".el9", srv)
    return deb, rpm


def component_config(tmp_path, base):
    cfg = yaml.safe_load(write_config(tmp_path, base).read_text())
    s = cfg["streams"]["ppg-18"]
    s["source"]["track_sources"] = True
    s["jobs"] = [
        {"id": "server", "job": "ppg-multiOS-parallel", "on": ["*"],
         "params": {"VERSION": "{version}"}},
        {"id": "minor-upgrade", "job": "ppg-upgrade-parallel",
         "on": ["server"], "params": {"VERSION": "{version}"}}]
    p = tmp_path / "config.yml"
    p.write_text(yaml.safe_dump(cfg))
    return p


def test_all_23_components_are_tracked(fake_repo, tmp_path):
    repo, base = fake_repo
    cfg = component_config(tmp_path, base)
    deb, rpm = _repo_with(PPG18_COMPONENTS, 1)
    repo.publish("ppg-18.4", deb, rpm)
    state = tmp_path / "VERSIONS.yml"
    cli(cfg, state, "baseline")
    pkgs = rw.load_state(state)["streams"]["ppg-18"]["verified"]["packages"]
    for c in PPG18_COMPONENTS:
        assert "deb:" + c in pkgs and "rpm:" + c in pkgs, c
    assert pkgs["deb:percona-pgbadger"] == "1.0-1"     # build number kept


def test_scenario1_respin_in_same_repo_bumps_build_numbers(fake_repo, tmp_path):
    """ppg-18.4 is re-released: server 18.4-1 -> 18.4-2 and every
    server-dependent component rebuilt (-1 -> -2); psycopg2, pysyncobj,
    pgbadger and pgbouncer are not rebuilt. Both builds stay in the repo."""
    repo, base = fake_repo
    cfg = component_config(tmp_path, base)
    state, plan = tmp_path / "VERSIONS.yml", tmp_path / "plan.json"
    not_rebuilt = {"psycopg2": "2.9.5-1", "python3-pysyncobj": "0.3.15-1",
                   "percona-pgbadger": "13.2-2", "percona-pgbouncer": "1.25.2-1"}
    deb1, rpm1 = _repo_with(PPG18_COMPONENTS, 1, not_rebuilt)
    repo.publish("ppg-18.4", deb1, rpm1)
    cli(cfg, state, "baseline")

    # The re-release: old and new builds side by side, as in the pool dirs.
    deb2, rpm2 = _repo_with(PPG18_COMPONENTS, 2, not_rebuilt)
    both_deb = dict(deb1)
    both_deb.update({k + "-old": v for k, v in deb1.items()})
    both_deb.update(deb2)
    both_rpm = dict(rpm1)
    both_rpm.update({k + "-old": v for k, v in rpm1.items()})
    both_rpm.update(rpm2)
    repo.publish("ppg-18.4", both_deb, both_rpm)
    cli(cfg, state, "poll", "--plan", str(plan))

    launch = json.loads(plan.read_text())["launches"][0]
    changed = launch["changed"]
    assert changed["deb:percona-haproxy"] == ["1.0-1", "1.0-2"]
    assert changed["rpm:percona-haproxy"] == ["1.0-1", "1.0-2"]
    assert changed["server"] == ["18.4-1", "18.4-2"]
    for c in not_rebuilt:
        assert "deb:" + c not in changed and "rpm:" + c not in changed
    assert {j["id"] for j in launch["jobs"]} == {"server", "minor-upgrade"}


def test_scenario2_rebuild_only_component_in_new_minor(fake_repo, tmp_path):
    """pgbadger 13.2-2 was verified with ppg-18.4. ppg-18.6 ships the same
    code as 13.2-3: that build must be tested."""
    repo, base = fake_repo
    cfg = component_config(tmp_path, base)
    state, plan = tmp_path / "VERSIONS.yml", tmp_path / "plan.json"
    deb, rpm = _repo_with(PPG18_COMPONENTS, 1, {"percona-pgbadger": "13.2-2"})
    repo.publish("ppg-18.4", deb, rpm)
    cli(cfg, state, "baseline")
    deb, rpm = _repo_with(PPG18_COMPONENTS, 1, {"percona-pgbadger": "13.2-3",
                                                "percona-postgresql-18": "18.6-1"})
    repo.publish("ppg-18.6", deb, rpm)
    cli(cfg, state, "poll", "--plan", str(plan))
    launch = json.loads(plan.read_text())["launches"][0]
    assert launch["version"] == "ppg-18.6"
    assert launch["changed"]["deb:percona-pgbadger"] == ["13.2-2", "13.2-3"]


def test_single_component_build_bump_runs_only_its_jobs(fake_repo, tmp_path):
    """Only pgbadger is rebuilt (13.2-2 -> 13.2-3) in the same repo: QA runs,
    but not the upgrade suites, which are mapped to the server."""
    repo, base = fake_repo
    cfg = component_config(tmp_path, base)
    state, plan = tmp_path / "VERSIONS.yml", tmp_path / "plan.json"
    deb, rpm = _repo_with(PPG18_COMPONENTS, 1, {"percona-pgbadger": "13.2-2"})
    repo.publish("ppg-18.4", deb, rpm)
    cli(cfg, state, "baseline")
    deb, rpm = _repo_with(PPG18_COMPONENTS, 1, {"percona-pgbadger": "13.2-3"})
    repo.publish("ppg-18.4", deb, rpm)
    cli(cfg, state, "poll", "--plan", str(plan))
    launch = json.loads(plan.read_text())["launches"][0]
    assert set(launch["changed"]) == {"deb:percona-pgbadger",
                                      "rpm:percona-pgbadger"}
    assert [j["id"] for j in launch["jobs"]] == ["server"]


def test_shipped_config_on_lists_are_honoured():
    """YAML reads a bare `on:` as True; the loader must still see the lists."""
    cfg = rw.load_config(rw.DEFAULT_CONFIG)
    jobs = cfg["streams"]["ppg-18"]["jobs"]
    assert all(True not in j for j in jobs)
    on = {j["id"]: j["on"] for j in jobs}
    assert on["minor-upgrade"] == ["server", "common"]
    assert cfg["streams"]["ppg-18"]["source"]["track_sources"] is True

    def picks(key):
        return {j["id"] for j in rw.select_jobs(
            dict(cfg["streams"]["ppg-18"], name="ppg-18"), {key: [None, "1"]},
            {"version": "v", "prev_version": "p", "upstream": {"pgsm": "2"},
             "verified": {"ppg-17": "ppg-17.1"}})[0]}
    assert picks("deb:percona-pgbadger") == {"server"}
    assert picks("deb:percona-patroni") == {"server", "meta-ha"}
    # HA stack pieces that are not rebuilt with the server
    for dep in ("deb:etcd", "deb:ydiff", "deb:python3-pysyncobj", "deb:psycopg2"):
        assert picks(dep) == {"server", "meta-ha"}, dep
    assert picks("server") == {"server", "meta-server", "meta-ha",
                               "minor-upgrade", "major-upgrade", "pgsm"}


def test_slack_changed_list_is_capped():
    changed = {"deb:c%02d" % i: ["1-1", "1-2"] for i in range(40)}
    text = rw._fmt_changed(changed)
    assert "(+25 more)" in text and text.count("->") == 15


# ------------------------------------------------------------ added / removed

def test_other_majors_components_are_never_expected(fake_repo, tmp_path):
    """ppg-17 repos never contain percona-pg-oidc-validator18: the ppg-17
    stream only tracks what its own repos contain, so nothing is missing."""
    repo, base = fake_repo
    cfg_path = component_config(tmp_path, base)
    cfg = yaml.safe_load(cfg_path.read_text())
    s17 = json.loads(json.dumps(cfg["streams"]["ppg-18"]))
    s17["source"].update(repo="ppg-17.{minor}", start_minor=11)
    s17["packages"]["server"] = {"apt": "percona-postgresql-17",
                                 "rpm": "percona-postgresql17-server",
                                 "required": True}
    cfg["streams"] = {"ppg-17": s17, "ppg-18": cfg["streams"]["ppg-18"]}
    cfg_path.write_text(yaml.safe_dump(cfg))
    state, plan = tmp_path / "VERSIONS.yml", tmp_path / "plan.json"
    c17 = [c for c in PPG18_COMPONENTS if "oidc" not in c] + ["percona-pg-telemetry"]
    c18 = PPG18_COMPONENTS
    repo.publish("ppg-17.11", *_repo_with(c17, 1, major=17))
    repo.publish("ppg-18.4", *_repo_with(c18, 1))
    cli(cfg_path, state, "baseline")
    v = rw.load_state(state)["streams"]
    assert "deb:percona-pg-oidc-validator18" not in v["ppg-17"]["verified"]["packages"]
    assert "deb:percona-pg-telemetry" not in v["ppg-18"]["verified"]["packages"]
    cli(cfg_path, state, "poll", "--plan", str(plan))
    p = json.loads(plan.read_text())
    assert p["launches"] == [] and p["notifications"] == []
    assert all("up to date" in line for line in p["summary"])


def test_new_component_in_a_new_minor_is_tested(fake_repo, tmp_path):
    repo, base = fake_repo
    cfg = component_config(tmp_path, base)
    state, plan = tmp_path / "VERSIONS.yml", tmp_path / "plan.json"
    old = [c for c in PPG18_COMPONENTS if "oidc" not in c]
    repo.publish("ppg-18.4", *_repo_with(old, 1))
    cli(cfg, state, "baseline")
    repo.publish("ppg-18.6", *_repo_with(PPG18_COMPONENTS, 1,
                                         {"percona-postgresql-18": "18.6-1"}))
    cli(cfg, state, "poll", "--plan", str(plan))
    launch = json.loads(plan.read_text())["launches"][0]
    assert launch["changed"]["deb:percona-pg-oidc-validator18"] == [None, "1.0-1"]
    assert launch["removed"] == []


def test_component_not_pushed_yet_makes_the_stream_wait(fake_repo, tmp_path):
    """ppg-18.6 lands without haproxy: that is a push still in progress, not
    a removal, so QA waits instead of testing an incomplete release."""
    repo, base = fake_repo
    cfg = component_config(tmp_path, base)
    state, plan = tmp_path / "VERSIONS.yml", tmp_path / "plan.json"
    repo.publish("ppg-18.4", *_repo_with(PPG18_COMPONENTS, 1))
    cli(cfg, state, "baseline")
    partial = [c for c in PPG18_COMPONENTS if c != "percona-haproxy"]
    repo.publish("ppg-18.6", *_repo_with(partial, 1,
                                         {"percona-postgresql-18": "18.6-1"}))
    cli(cfg, state, "poll", "--plan", str(plan))
    p = json.loads(plan.read_text())
    assert p["launches"] == [] and "incomplete" in p["summary"][0]
    observed = rw.load_state(state)["streams"]["ppg-18"]["observed"]
    assert "component deb:percona-haproxy" in observed["missing"]
    # haproxy lands: QA starts
    repo.publish("ppg-18.6", *_repo_with(PPG18_COMPONENTS, 1,
                                         {"percona-postgresql-18": "18.6-1"}))
    cli(cfg, state, "poll", "--plan", str(plan))
    assert len(json.loads(plan.read_text())["launches"]) == 1


def test_stuck_missing_component_alert_explains_how_to_accept_removal():
    st = {"verified": {"version": "ppg-17.11", "repo": "ppg-17.11",
                       "packages": {"server": "17.11-1",
                                    "deb:percona-pg-telemetry": "1.1-1"}}}
    o = obs(repo="ppg-17.12", minor=12, server="17.12-1")
    stream = dict(STREAM, name="ppg-17")
    st, launch, notes, _ = rw.decide(stream, o, st, {}, NOW, SETTINGS)
    assert launch is None and not notes
    st, launch, notes, _ = rw.decide(stream, o, st, {}, mins(25 * 60), SETTINGS)
    assert launch is None and len(notes) == 1
    assert "component deb:percona-pg-telemetry" in notes[0]["text"]
    assert "allow_removed" in notes[0]["text"]


def test_allowed_removal_launches_and_is_reported(fake_repo, tmp_path):
    """percona-pg-telemetry dropped on purpose: listed in allow_removed, the
    new minor is tested and the result message says it was removed."""
    repo, base = fake_repo
    cfg_path = component_config(tmp_path, base)
    cfg = yaml.safe_load(cfg_path.read_text())
    cfg["streams"]["ppg-18"]["source"]["allow_removed"] = ["*pg-telemetry*"]
    cfg_path.write_text(yaml.safe_dump(cfg))
    state, plan = tmp_path / "VERSIONS.yml", tmp_path / "plan.json"
    repo.publish("ppg-18.4", *_repo_with(PPG18_COMPONENTS + ["percona-pg-telemetry"], 1))
    cli(cfg_path, state, "baseline")
    repo.publish("ppg-18.6", *_repo_with(PPG18_COMPONENTS, 1,
                                         {"percona-postgresql-18": "18.6-1"}))
    cli(cfg_path, state, "poll", "--plan", str(plan))
    launch = json.loads(plan.read_text())["launches"][0]
    assert launch["removed"] == ["deb:percona-pg-telemetry",
                                 "rpm:percona-pg-telemetry"]
    builds, msg = tmp_path / "b.json", tmp_path / "m.json"
    builds.write_text(json.dumps([{"id": "server", "result": "SUCCESS"},
                                  {"id": "minor-upgrade", "result": "SUCCESS"}]))
    cli(cfg_path, state, "record", "--stream", "ppg-18", "--attempt-id",
        launch["attempt_id"], "--builds", str(builds), "--message", str(msg))
    assert "Removed: deb:percona-pg-telemetry" in json.loads(msg.read_text())["text"]
    verified = rw.load_state(state)["streams"]["ppg-18"]["verified"]["packages"]
    assert "deb:percona-pg-telemetry" not in verified
    # and it is not expected again afterwards
    cli(cfg_path, state, "poll", "--plan", str(plan))
    assert json.loads(plan.read_text())["launches"] == []


# ------------------------------------------------------------ arrival order

RESPIN_STREAM = dict(STREAM, packages={
    "server": {"apt": "s", "rpm": "s", "required": True}, "haproxy": "h"})
RESPIN_SETTINGS = dict(SETTINGS, component_settle_minutes=180)
RESPIN_VERIFIED = {"verified": {"version": "ppg-18.4", "repo": "ppg-18.4",
                                "packages": {"server": "18.4-1",
                                             "haproxy": "2.8.23-1"}}}


def respin(server, haproxy):
    return obs(repo="ppg-18.4", minor=4, server=server, haproxy=haproxy)


def rdecide(o, st, t):
    return rw.decide(RESPIN_STREAM, o, st, {"ppg-17": "ppg-17.11"}, t,
                     RESPIN_SETTINGS)


def test_components_before_server_wait_for_the_server_build():
    """Re-release of ppg-18.4: haproxy 2.8.23-2 lands first, the server
    18.4-2 lands 90 minutes later. One QA run, with both."""
    st, launch, _, s = rdecide(respin("18.4-1", "2.8.23-2"), RESPIN_VERIFIED, NOW)
    assert launch is None
    st, launch, _, s = rdecide(respin("18.4-1", "2.8.23-2"), st, mins(89))
    assert launch is None and "waiting for a possible server build" in s
    st, launch, _, _ = rdecide(respin("18.4-2", "2.8.23-2"), st, mins(90))
    assert launch is None                      # server arrived: timer restarts
    st, launch, _, _ = rdecide(respin("18.4-2", "2.8.23-2"), st, mins(151))
    assert launch and launch["changed"] == {"server": ["18.4-1", "18.4-2"],
                                            "haproxy": ["2.8.23-1", "2.8.23-2"]}


def test_component_only_release_still_runs_after_the_longer_settle():
    st, _, _, _ = rdecide(respin("18.4-1", "2.8.23-2"), RESPIN_VERIFIED, NOW)
    st, launch, _, _ = rdecide(respin("18.4-1", "2.8.23-2"), st, mins(179))
    assert launch is None
    _, launch, _, _ = rdecide(respin("18.4-1", "2.8.23-2"), st, mins(181))
    assert launch and set(launch["changed"]) == {"haproxy"}


def test_server_change_keeps_the_normal_settle():
    st, _, _, _ = rdecide(respin("18.4-2", "2.8.23-1"), RESPIN_VERIFIED, NOW)
    _, launch, _, _ = rdecide(respin("18.4-2", "2.8.23-1"), st, mins(61))
    assert launch is not None


def test_new_minor_never_launches_before_the_server_arrives():
    """ppg-18.6 appears with components only: server is required, so the
    stream waits however long the server build takes."""
    o = obs(repo="ppg-18.6", minor=6, complete=False, haproxy="2.8.23-3")
    st, launch, _, s = rdecide(o, RESPIN_VERIFIED, NOW)
    assert launch is None and "incomplete" in s
    st, launch, _, _ = rdecide(o, st, mins(10 * 60))
    assert launch is None


def test_shipped_config_has_component_settle():
    cfg = rw.load_config(rw.DEFAULT_CONFIG)
    assert cfg["settings"]["component_settle_minutes"] == 180


# ------------------------------------------------------------ mis-pushes

GUARD_STREAM = dict(STREAM, version_check={"package": "server",
                                           "expect": "18.{minor}"})
GUARD_VERIFIED = {"verified": {"version": "ppg-18.6", "repo": "ppg-18.6",
                               "packages": {"server": "18.6-1",
                                            "pgbackrest": "2.59.1-1"}}}


def gdecide(o, st, t, stream=GUARD_STREAM, force=False):
    return rw.decide(stream, o, st, {"ppg-17": "ppg-17.11"}, t, SETTINGS,
                     force=force)


def pushed(server, pgbackrest="2.59.1-1", minor=7):
    return obs(repo="ppg-18.%d" % minor, minor=minor, server=server,
               pgbackrest=pgbackrest)


@pytest.mark.parametrize("server,why", [
    ("18.6-1", "same as last release"),
    ("18.6-2", "last release, new build"),
    ("18.5-1", "older release"),
])
def test_wrong_server_version_in_new_repo_is_blocked(server, why):
    st, launch, notes, s = gdecide(pushed(server), GUARD_VERIFIED, NOW)
    assert launch is None, why
    assert "should hold 18.7.x" in s
    assert {n["to"] for n in notes} == {"qa", "release"}
    assert "mis-pushed" in notes[0]["text"] and "18.6" in notes[0]["text"]
    # later polls stay blocked, but do not alert again
    st, launch, notes, _ = gdecide(pushed(server), st, mins(120))
    assert launch is None and notes == []


def test_component_downgrade_is_blocked():
    _, launch, notes, s = gdecide(pushed("18.7-1", "2.58.0-3"),
                                  GUARD_VERIFIED, NOW)
    assert launch is None
    assert "downgrade: pgbackrest 2.58.0-3 (verified 2.59.1-1)" in s
    assert len(notes) == 2


def test_correct_push_after_a_mistake_launches():
    st, _, _, _ = gdecide(pushed("18.6-1"), GUARD_VERIFIED, NOW)
    st, launch, _, _ = gdecide(pushed("18.7-1"), st, mins(10))   # fixed
    assert launch is None                                         # settling
    st, launch, notes, _ = gdecide(pushed("18.7-1"), st, mins(71))
    assert launch and launch["version"] == "ppg-18.7" and notes == []


def test_force_accepts_a_blocked_push():
    _, launch, _, _ = gdecide(pushed("18.7-1", "2.58.0-3"), GUARD_VERIFIED,
                              NOW, force=True)
    assert launch is not None


def test_allow_downgrade_accepts_listed_components():
    stream = dict(GUARD_STREAM, allow_downgrade=["pgbackrest"])
    st, _, notes, _ = gdecide(pushed("18.7-1", "2.58.0-3"), GUARD_VERIFIED,
                              NOW, stream=stream)
    assert notes == []
    _, launch, _, _ = gdecide(pushed("18.7-1", "2.58.0-3"), st, mins(61),
                              stream=stream)
    assert launch is not None


def test_mis_push_alert_goes_once_when_both_channels_are_the_same(fake_repo,
                                                                   tmp_path):
    repo, base = fake_repo
    cfg_path = component_config(tmp_path, base)
    cfg = yaml.safe_load(cfg_path.read_text())
    cfg["slack"] = {"qa": "#same", "release": "#same"}
    cfg["streams"]["ppg-18"]["source"]["version_check"] = {
        "package": "server", "expect": "18.{minor}"}
    cfg_path.write_text(yaml.safe_dump(cfg))
    state, plan = tmp_path / "VERSIONS.yml", tmp_path / "plan.json"
    repo.publish("ppg-18.6", *_repo_with(PPG18_COMPONENTS, 1,
                                         {"percona-postgresql-18": "18.6-1"}))
    cli(cfg_path, state, "baseline")
    # ppg-18.7 created, but it holds the 18.6 server
    repo.publish("ppg-18.7", *_repo_with(PPG18_COMPONENTS, 1,
                                         {"percona-postgresql-18": "18.6-1"}))
    cli(cfg_path, state, "poll", "--plan", str(plan))
    p = json.loads(plan.read_text())
    assert p["launches"] == [] and len(p["notifications"]) == 1
    assert rw.load_state(state)["streams"]["ppg-18"]["verified"]["version"] \
        == "ppg-18.6"


def test_shipped_config_has_version_check():
    cfg = rw.load_config(rw.DEFAULT_CONFIG)
    for major in (14, 15, 16, 17, 18):
        vc = cfg["streams"]["ppg-%d" % major]["source"]["version_check"]
        assert vc == {"package": "server", "expect": "%d.{minor}" % major}


# ------------------------------------------------------------ third-party deps

def _index(**sources):
    idx = rw.Index()
    for src, ver in sources.items():
        idx.add(src + "-bin", ver, src)
    return idx


def test_third_party_rpm_deps_differing_per_rhel_do_not_block():
    """Field report: CGAL is 4.14 on RHEL 8 and 5.4.2 on RHEL 9, geos312 has
    a PGDG build on 9/aarch64 only. That is normal, not a push in progress."""
    raw = {
        "8/x86_64": ("rpm", _index(CGAL="4.14-1.rh", geos312="3.12.2-1.rh",
                                   **{"percona-pgbackrest": "2.59.1-1.el8"})),
        "9/x86_64": ("rpm", _index(CGAL="5.4.2-1.rh", geos312="3.12.2-1.rh",
                                   **{"percona-pgbackrest": "2.59.1-1.el9"})),
        "9/aarch64": ("rpm", _index(CGAL="5.4.2-1.rh",
                                    geos312="3.12.2-1PGDG.rh",
                                    **{"percona-pgbackrest": "2.59.1-1.el9"})),
    }
    packages, conflicts, variants = {}, [], []
    rw._track_sources({"strict_sources": ["percona-*"]}, raw, packages,
                      conflicts, variants)
    assert conflicts == []
    assert any(v.startswith("rpm:CGAL: 4.14-1 vs 5.4.2-1") for v in variants)
    assert any(v.startswith("rpm:geos312:") for v in variants)
    assert packages["rpm:CGAL"] == "5.4.2-1"          # .rh stripped, max kept
    assert packages["rpm:percona-pgbackrest"] == "2.59.1-1"


def test_percona_component_differing_across_platforms_still_blocks():
    raw = {
        "8/x86_64": ("rpm", _index(**{"percona-pgbackrest": "2.59.1-1.el8"})),
        "9/x86_64": ("rpm", _index(**{"percona-pgbackrest": "2.60.0-1.el9"})),
    }
    packages, conflicts, variants = {}, [], []
    rw._track_sources({}, raw, packages, conflicts, variants)
    assert conflicts and conflicts[0].startswith("rpm:percona-pgbackrest")
    assert variants == []


def test_shipped_config_strict_sources_and_patroni_rpm_deps():
    cfg = rw.load_config(rw.DEFAULT_CONFIG)
    s = dict(cfg["streams"]["ppg-18"], name="ppg-18")
    assert s["source"]["strict_sources"] == ["percona-*"]

    def picks(key):
        return {j["id"] for j in rw.select_jobs(
            s, {key: [None, "1"]},
            {"version": "v", "prev_version": "p", "upstream": {"pgsm": "2"},
             "verified": {"ppg-17": "ppg-17.1"}})[0]}
    for dep in ("rpm:python3.12-kazoo", "rpm:python3.12-click",
                "rpm:py-consul", "rpm:python3-etcd"):
        assert picks(dep) == {"server", "meta-ha"}, dep
    for dep in ("rpm:gdal311", "rpm:CGAL", "rpm:llvm"):
        assert picks(dep) == {"server"}, dep
