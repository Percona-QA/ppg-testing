"""Watch staging (testing) repositories and decide which QA jobs to launch.

The Jenkins job ppg-release-watcher runs `poll` every few minutes. When a
package set in a watched stream (for example ppg-18) has a newer version than
the last one that passed QA, and the new set is complete and has stopped
changing, the stream is marked `running` in the state file and a launch plan is
written for Jenkins. ppg-release-qa runs the planned jobs and calls `record`,
which either promotes the attempt to `verified` (tests passed) or marks it
`failed`, leaving `verified` untouched (the rollback).

State lives in VERSIONS.yml on a dedicated git branch:

    streams:
      ppg-18:
        verified:  what last passed QA; the "released-from-QA" versions
        attempt:   the current or last attempt (running / failed / passed)
        observed:  what the repo showed last poll, for the settle timer

Subcommands: observe, poll, record, retry, baseline, show. See
release_watch/README.md.
"""
import argparse
import bz2
import copy
import datetime as dt
import fnmatch
import functools
import gzip
import hashlib
import io
import itertools
import json
import lzma
import pathlib
import re
import string
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = REPO_ROOT / "release_watch" / "config.yml"
STATE_HEADER = ("# Managed by tools/release_watch.py (ppg-release-watcher / "
                "ppg-release-qa).\n# verified = last versions that passed QA. "
                "Edit only via the tool.\n")
USER_AGENT = "ppg-release-watch/1.0"


# ---------------------------------------------------------------- versions

def _order(c):
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if not c:
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _cmp_fragment(a, b):
    """dpkg's verrevcmp: alternating non-digit and digit runs."""
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or \
                (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i]) if i < len(a) else 0
            bc = _order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _split_version(v):
    epoch = 0
    if ":" in v and v.split(":", 1)[0].isdigit():
        e, v = v.split(":", 1)
        epoch = int(e)
    if "-" in v:
        up, rev = v.rsplit("-", 1)
    else:
        up, rev = v, ""
    return epoch, up, rev


def vercmp(a, b):
    """Compare two version strings with dpkg semantics. Returns <0, 0, >0."""
    ea, ua, ra = _split_version(a)
    eb, ub, rb = _split_version(b)
    if ea != eb:
        return ea - eb
    return _cmp_fragment(ua, ub) or _cmp_fragment(ra, rb)


_DISTRO_TAG = re.compile(
    r"[.~+_-]?(el\d+|rhel\d*|rh|amzn\d+|fc\d+|deb\d+|ubuntu\d*|bookworm|trixie|bullseye|"
    r"buster|jammy|noble|resolute|focal|plucky|questing).*$")


def canonical(raw):
    """Normalize a deb or rpm version to 'upstream-release' without epoch or
    distro tag, so 2:18.4-1.noble and 18.4-1.el9 both become 18.4-1."""
    _, up, rev = _split_version(raw)
    rev = _DISTRO_TAG.sub("", rev)
    return "%s-%s" % (up, rev) if rev else up


def upstream(v):
    return _split_version(v)[1]


def major_minor(v):
    parts = re.split(r"[.]", upstream(v))
    return ".".join(parts[:2])


# ---------------------------------------------------------------- fetching

class Fetcher:
    """HTTP GET with retries and an optional on-disk conditional-GET cache,
    so unchanged indexes cost a 304 instead of a multi-MB download."""

    def __init__(self, cache_dir=None, timeout=60, retries=3,
                 missing_codes=(404, 410)):
        self.missing_codes = tuple(missing_codes)
        self.cache_dir = pathlib.Path(cache_dir) if cache_dir else None
        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.retries = retries

    def _cache_paths(self, url):
        key = hashlib.sha256(url.encode()).hexdigest()[:32]
        return self.cache_dir / (key + ".meta"), self.cache_dir / (key + ".body")

    def get(self, url, method="GET"):
        """Return bytes, b"" for HEAD success, or None when the URL does not
        exist (404/410). Anything else, e.g. a proxy's 403, is an error: a
        broken fetch must never look like an empty repository."""
        meta = None
        if self.cache_dir and method == "GET":
            mpath, bpath = self._cache_paths(url)
            if mpath.exists() and bpath.exists():
                meta = json.loads(mpath.read_text())
        last_err = None
        for attempt in range(self.retries):
            req = urllib.request.Request(url, method=method,
                                         headers={"User-Agent": USER_AGENT})
            if meta:
                if meta.get("etag"):
                    req.add_header("If-None-Match", meta["etag"])
                if meta.get("last_modified"):
                    req.add_header("If-Modified-Since", meta["last_modified"])
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    if method == "HEAD":
                        return b""
                    body = r.read()
                    if self.cache_dir:
                        mpath, bpath = self._cache_paths(url)
                        bpath.write_bytes(body)
                        mpath.write_text(json.dumps({
                            "url": url,
                            "etag": r.headers.get("ETag"),
                            "last_modified": r.headers.get("Last-Modified")}))
                    return body
            except urllib.error.HTTPError as e:
                if e.code == 304 and meta:
                    return self._cache_paths(url)[1].read_bytes()
                if e.code in self.missing_codes:
                    return None
                if method == "HEAD" and e.code in (405, 501):
                    return self.get(url, method="GET")
                last_err = "%s %s" % (e.code, e.headers.get("x-deny-reason")
                                      or e.reason)
                if 400 <= e.code < 500:
                    break
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                last_err = e
            time.sleep(2 ** attempt)
        raise RuntimeError("GET %s failed: %s" % (url, last_err))


def _decompress(url, data):
    if url.endswith(".gz"):
        return gzip.decompress(data)
    if url.endswith(".xz"):
        return lzma.decompress(data)
    if url.endswith(".bz2"):
        return bz2.decompress(data)
    if url.endswith(".zst"):
        try:
            import zstandard
        except ImportError:
            raise RuntimeError("%s is zstd compressed; pip install zstandard"
                               % url)
        return zstandard.ZstdDecompressor().stream_reader(
            io.BytesIO(data)).read()
    return data


class Index(dict):
    """{binary package: highest version}, plus .sources = {source package:
    highest version among its binaries}. Source names are what the pool
    directories are called (percona-haproxy/, percona-pg-repack/, ...)."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.sources = {}

    def add(self, name, ver, source=None):
        if name not in self or vercmp(ver, self[name]) > 0:
            self[name] = ver
        src = source or name
        if src not in self.sources or vercmp(ver, self.sources[src]) > 0:
            self.sources[src] = ver


def parse_apt_packages(text):
    """Packages index -> Index {name: highest version}, with .sources."""
    out = Index()
    name = ver = source = None
    for line in text.splitlines() + [""]:
        if not line.strip():
            if name and ver:
                out.add(name, ver, source)
            name = ver = source = None
        elif line.startswith("Package:"):
            name = line.split(":", 1)[1].strip()
        elif line.startswith("Version:"):
            ver = line.split(":", 1)[1].strip()
        elif line.startswith("Source:"):
            # "Source: percona-haproxy" or "Source: percona-x (1.2-3)"
            source = line.split(":", 1)[1].strip().split(" ")[0]
    return out


def _srpm_name(srpm):
    """percona-pg_repack18-1.5.3-3.el9.src.rpm -> percona-pg_repack18"""
    base = srpm[:-len(".src.rpm")] if srpm.endswith(".src.rpm") else srpm
    parts = base.rsplit("-", 2)
    return parts[0] if len(parts) == 3 else base


def parse_rpm_primary(data):
    """primary.xml -> Index {name: highest 'epoch:ver-rel'}, with .sources
    (source rpms skipped as packages)."""
    out = Index()
    for _, el in ET.iterparse(io.BytesIO(data)):
        if el.tag.rsplit("}", 1)[-1] != "package":
            continue
        name = arch = verel = srpm = None
        for child in el:
            tag = child.tag.rsplit("}", 1)[-1]
            if tag == "name":
                name = child.text
            elif tag == "arch":
                arch = child.text
            elif tag == "version":
                e = child.get("epoch") or "0"
                verel = "%s:%s-%s" % (e, child.get("ver"), child.get("rel"))
            elif tag == "format":
                for f in child:
                    if f.tag.rsplit("}", 1)[-1] == "sourcerpm" and f.text:
                        srpm = _srpm_name(f.text)
        el.clear()
        if not name or not verel or arch == "src":
            continue
        out.add(name, verel, srpm)
    return out


def fetch_index(fetcher, fmt, url):
    """Return {package: raw version} or None when the index does not exist."""
    if fmt == "apt":
        for suffix in (".xz", ".gz", ""):
            data = fetcher.get(url + suffix)
            if data is not None:
                return parse_apt_packages(
                    _decompress(url + suffix, data).decode("utf-8", "replace"))
        return None
    if fmt == "rpm":
        base = url.rstrip("/")
        repomd = fetcher.get(base + "/repodata/repomd.xml")
        if repomd is None:
            return None
        root = ET.fromstring(repomd)
        href = None
        for data_el in root:
            if data_el.tag.rsplit("}", 1)[-1] == "data" and \
                    data_el.get("type") == "primary":
                for child in data_el:
                    if child.tag.rsplit("}", 1)[-1] == "location":
                        href = child.get("href")
        if not href:
            raise RuntimeError("no primary data in %s/repodata/repomd.xml" % base)
        purl = base + "/" + href
        data = fetcher.get(purl)
        if data is None:
            raise RuntimeError("repomd points at missing %s" % purl)
        return parse_rpm_primary(_decompress(purl, data))
    raise ValueError("unknown index format %r" % fmt)


# ---------------------------------------------------------------- config

def _subst(obj, variables):
    """Replace <<name>> markers (load-time template vars) recursively."""
    if isinstance(obj, str):
        for k, v in variables.items():
            obj = obj.replace("<<%s>>" % k, str(v))
        return obj
    if isinstance(obj, list):
        return [_subst(x, variables) for x in obj]
    if isinstance(obj, dict):
        return {k: _subst(v, variables) for k, v in obj.items()}
    return obj


def _normalize_job(job):
    """YAML 1.1 reads a bare `on:` key as the boolean True (the GitHub Actions
    trap), which silently made every job run on every change. Accept it."""
    job = dict(job)
    if True in job:
        job["on"] = job.pop(True)
    return job


def load_config(path):
    raw = yaml.safe_load(pathlib.Path(path).read_text())
    templates = raw.get("templates", {})
    streams = {}
    for name, s in (raw.get("streams") or {}).items():
        s = dict(s or {})
        if "template" in s:
            base = copy.deepcopy(templates[s.pop("template")])
            base.update({k: v for k, v in s.items() if k != "vars"})
            base["vars"] = s.get("vars", {})
            s = base
        if "source_start_minor" in s:
            s["source"] = dict(s["source"],
                               start_minor=s.pop("source_start_minor"))
        variables = dict(s.get("vars", {}))
        variables["stream"] = name
        s = _subst(s, variables)
        skip = set(s.get("skip_jobs", []))
        s["jobs"] = [_normalize_job(j) for j in s.get("jobs", [])
                     if j["id"] not in skip]
        s.setdefault("enabled", True)
        streams[name] = s
    cfg = {k: v for k, v in raw.items() if k not in ("templates", "streams")}
    cfg["streams"] = streams
    cfg.setdefault("settings", {})
    cfg.setdefault("slack", {})
    return cfg


def expand_indexes(source, repo):
    """Cartesian-expand index entries whose values are lists."""
    out = []
    for entry in source.get("indexes", []):
        keys = [k for k, v in entry.items() if isinstance(v, list)]
        for combo in itertools.product(*(entry[k] for k in keys)):
            e = dict(entry)
            e.update(dict(zip(keys, combo)))
            e["repo"] = repo
            fields = {k: v for k, v in e.items() if k not in ("url", "format")}
            e["url"] = e["url"].format(**fields)
            e["platform"] = "/".join(str(e[k]) for k in keys) or e["url"]
            out.append(e)
    return out


# ---------------------------------------------------------------- observe

def _minor_of(version):
    m = re.search(r"\.(\d+)$", version or "")
    return int(m.group(1)) if m else None


def start_minor(stream, stream_state):
    start = _minor_of(((stream_state or {}).get("verified") or {}).get("repo"))
    if start is None:
        start = int(stream["source"].get("start_minor", 0))
    return start


MAX_MINOR_SCAN = 100


def discover_minor(stream, stream_state, probe):
    """Scan minors upward from the verified one and return (minor, probe
    result) for the highest that exists. Gaps are fine: the scan only stops
    after `minor_lookahead` + 1 consecutive misses past the last hit, so
    ppg-18.3 -> (18.4, 18.5 missing) -> ppg-18.6 is still found, however far
    the verified version lags behind."""
    look = int(stream["source"].get("minor_lookahead", 3))
    m = start_minor(stream, stream_state)
    best, misses, scanned = None, 0, 0
    while misses <= look and scanned < MAX_MINOR_SCAN:
        hit = probe(m)
        if hit:
            best, misses = (m, hit), 0
        else:
            misses += 1
        m += 1
        scanned += 1
    return best


def previous_minor(stream, minor, probe):
    """Highest existing minor below `minor`, with the same gap tolerance.
    Used for upgrade tests: with ppg-18.4/18.5 absent, before 18.6 is 18.3."""
    look = int(stream["source"].get("minor_lookahead", 3))
    m, misses = minor - 1, 0
    while m >= 0 and misses <= look:
        if probe(m):
            return m
        misses += 1
        m -= 1
    return None


def _index_exists(fetcher, idx):
    if idx["format"] == "rpm":
        urls = [idx["url"].rstrip("/") + "/repodata/repomd.xml"]
    else:
        urls = [idx["url"] + sfx for sfx in (".xz", ".gz", "")]
    return any(fetcher.get(u, method="HEAD") is not None for u in urls)


def repo_exists(src, repo, fetcher):
    """Cheap existence check (HEAD requests) before downloading indexes."""
    # rpm first: one request per index versus up to three for apt
    idxs = sorted(expand_indexes(src, repo), key=lambda i: i["format"] != "rpm")
    return any(_index_exists(fetcher, idx) for idx in idxs)


def _fetch_all(src, repo, fetcher, log):
    raw = {}
    for idx in expand_indexes(src, repo):
        pkgs = fetch_index(fetcher, idx["format"], idx["url"])
        if pkgs is None:
            log("  %s: %s not published" % (repo, idx["platform"]))
            continue
        raw[idx["platform"]] = (idx["format"], pkgs)
    return raw


def observe_repo_stream(stream, stream_state, fetcher, log):
    """Observe a stream backed by apt/yum indexes. With {minor} in the repo
    name, the highest existing minor repo (ppg-18.5 over ppg-18.4) wins."""
    src = stream["source"]
    template = src["repo"]
    if "{minor}" in template:
        found = discover_minor(
            stream, stream_state,
            lambda m: repo_exists(src, template.format(minor=m), fetcher))
        if not found:
            return None
        minor = found[0]
        repo = template.format(minor=minor)
        prev_minor = previous_minor(
            stream, minor,
            lambda m: repo_exists(src, template.format(minor=m), fetcher))
    else:
        repo, minor, prev_minor = template, None, None
    raw = _fetch_all(src, repo, fetcher, log)
    if not raw:
        return None
    platforms = sorted(raw)

    packages, missing, conflicts = {}, [], []
    for logical, spec in stream["packages"].items():
        names = spec if isinstance(spec, dict) else {"apt": spec, "rpm": spec}
        seen = {}
        for plat, (fmt, pkgs) in raw.items():
            pname = names.get(fmt)
            if not pname:
                continue
            if pname in pkgs:
                seen[plat] = (fmt, canonical(pkgs[pname]))
            elif isinstance(spec, dict) and spec.get("required"):
                missing.append("%s@%s" % (logical, plat))
        if not seen:
            continue
        packages[logical] = sorted({v for _, v in seen.values()},
                                   key=_cmpkey)[-1]
        # deb and rpm may carry different release numbers; within one
        # family every platform must agree, or the push is still in flight.
        for fmt in sorted({f for f, _ in seen.values()}):
            fam = {p: v for p, (f, v) in seen.items() if f == fmt}
            versions = sorted(set(fam.values()), key=_cmpkey)
            if len(versions) > 1:
                behind = sorted(p for p, v in fam.items() if v != versions[-1])
                conflicts.append("%s: %s on %s" % (
                    logical, " vs ".join(versions), ",".join(behind)))
    variants = []
    if src.get("track_sources", False):
        _track_sources(src, raw, packages, conflicts, variants)
    return {
        "repo": repo, "minor": minor, "prev_minor": prev_minor,
        "platforms": platforms,
        "packages": packages, "missing": missing, "conflicts": conflicts,
        "variants": variants,
        "urls": {},
    }


FAMILY = {"apt": "deb", "rpm": "rpm"}


def _track_sources(src, raw, packages, conflicts, variants):
    """Track every source package in the repo as 'deb:<source>' and
    'rpm:<source>', so any component's version or build bump is seen without
    listing binary package names.

    Only sources matching strict_sources (default percona-*) must agree
    across the platforms of a family: those are built and pushed together,
    so a disagreement means a push in progress. Third-party dependencies
    shipped in the repo (PostGIS's gdal/geos/proj, Patroni's python3.12-*)
    legitimately differ between RHEL 8/9/10 or architectures; their
    differences are reported as variants and never block."""
    ignore = src.get("ignore_sources", [])
    strict = src.get("strict_sources", ["percona-*"])
    seen = {}
    for plat, (fmt, pkgs) in raw.items():
        for source, ver in getattr(pkgs, "sources", {}).items():
            if any(fnmatch.fnmatch(source, pat) for pat in ignore):
                continue
            key = "%s:%s" % (FAMILY[fmt], source)
            seen.setdefault(key, {})[plat] = canonical(ver)
    for key, fam in sorted(seen.items()):
        versions = sorted(set(fam.values()), key=_cmpkey)
        packages[key] = versions[-1]
        if len(versions) > 1:
            behind = sorted(p for p, v in fam.items() if v != versions[-1])
            line = "%s: %s on %s" % (key, " vs ".join(versions),
                                     ",".join(behind))
            source = key.split(":", 1)[1]
            if any(fnmatch.fnmatch(source, pat) for pat in strict):
                conflicts.append(line)
            else:
                variants.append(line)


def observe_http_stream(stream, stream_state, fetcher, log):
    """Observe a stream of downloadable files (tarballs) by probing URLs."""
    src = stream["source"]
    packages, urls = {}, {}

    def probe(minor):
        found = {}
        for logical, url_t in stream["packages"].items():
            url = url_t.format(minor=minor)
            if fetcher.get(url, method="HEAD") is not None:
                found[logical] = url
        return found

    best = discover_minor(stream, stream_state, probe)
    if not best:
        return None
    minor, found = best
    version = src.get("file_version", "{minor}").format(minor=minor)
    missing = []
    for logical in stream["packages"]:
        if logical in found:
            packages[logical] = version
            urls[logical] = found[logical]
        elif logical in src.get("required", []):
            missing.append(logical)
    return {"repo": src["repo"].format(minor=minor), "minor": minor,
            "prev_minor": previous_minor(stream, minor, probe),
            "platforms": ["http"], "packages": packages, "missing": missing,
            "conflicts": [], "urls": urls}


def _cmpkey(v):
    return functools.cmp_to_key(vercmp)(v)


def observe(stream, stream_state, fetcher, log=lambda m: None):
    kind = stream["source"].get("type", "repo")
    if kind == "repo":
        obs = observe_repo_stream(stream, stream_state, fetcher, log)
    elif kind == "http":
        obs = observe_http_stream(stream, stream_state, fetcher, log)
    else:
        raise ValueError("unknown source type %r" % kind)
    if obs is None:
        return None
    obs["complete"] = not obs["missing"] and not obs["conflicts"]
    obs["fingerprint"] = hashlib.sha256(json.dumps(
        [obs["repo"], obs["packages"], sorted(obs["platforms"]),
         obs["missing"], obs["conflicts"]], sort_keys=True).encode()
    ).hexdigest()[:16]
    return obs


# ---------------------------------------------------------------- decide

class _StrictFormatter(string.Formatter):
    def get_value(self, key, args, kwargs):
        v = super().get_value(key, args, kwargs)
        if v is None:
            raise KeyError(key)
        return v

    def get_field(self, field_name, args, kwargs):
        obj, used = super().get_field(field_name, args, kwargs)
        if obj is None:
            raise KeyError(field_name)
        return obj, used


def _fmt(value, variables):
    if isinstance(value, str):
        return _StrictFormatter().vformat(value, (), variables)
    return value


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s):
    return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=dt.timezone.utc)


def changed_packages(stream, packages, verified_pkgs):
    """Packages whose version is newer than verified. With compare=upstream a
    release bump (18.4-1 -> 18.4-2) is not considered a change."""
    mode = stream.get("compare", "full")
    changed, older = {}, []
    for name, ver in packages.items():
        old = (verified_pkgs or {}).get(name)
        a, b = (upstream(ver), upstream(old)) if (mode == "upstream" and old) \
            else (ver, old)
        if old is None:
            changed[name] = [None, ver]
        elif vercmp(a, b) > 0:
            changed[name] = [old, ver]
        elif vercmp(a, b) < 0:
            older.append("%s %s (verified %s)" % (name, ver, old))
    return changed, older


def version_mismatch(stream, obs):
    """The repo name says which release it holds: ppg-18.7 must contain a
    18.7.x server. `version_check: {package: server, expect: "18.{minor}"}`."""
    check = stream.get("version_check") or \
        stream.get("source", {}).get("version_check")
    if not check or obs.get("minor") is None:
        return []
    pkg = check["package"]
    have = obs["packages"].get(pkg)
    if have is None:
        return []           # absent: the completeness check reports it
    want = check["expect"].format(minor=obs["minor"])
    if major_minor(have) != want:
        return ["%s is %s but %s should hold %s.x" % (pkg, have, obs["repo"],
                                                      want)]
    return []


def _matches(stream, key, name):
    pats = stream.get(key) or stream.get("source", {}).get(key) or []
    return any(fnmatch.fnmatch(name, pat) for pat in pats)


def removed_components(stream, verified_pkgs, packages):
    """Tracked names that the verified set had and the repo no longer has."""
    return sorted(set(verified_pkgs or {}) - set(packages))


def _allowed_removal(stream, key):
    pats = stream.get("allow_removed") or \
        stream.get("source", {}).get("allow_removed") or []
    return any(fnmatch.fnmatch(key, pat) for pat in pats)


def build_vars(stream, obs, stream_state, all_verified):
    verified = (stream_state or {}).get("verified") or {}
    base = {
        "stream": stream["name"],
        "repo": obs["repo"],
        "minor": obs["minor"],
        "minor_prev": obs.get("prev_minor"),
        "pkg": dict(obs["packages"]),
        "upstream": {k: upstream(v) for k, v in obs["packages"].items()},
        "mm": {k: major_minor(v) for k, v in obs["packages"].items()},
        "url": dict(obs.get("urls", {})),
        "verified": dict(all_verified),
    }
    base.update(stream.get("vars", {}))
    version = _fmt(stream.get("version", "{repo}"), base)
    base["version"] = version
    prev = verified.get("version")
    if not prev or prev == version:
        try:
            prev = _fmt(stream["prev_version"], base) \
                if stream.get("prev_version") else None
        except (KeyError, IndexError):
            prev = None
    base["prev_version"] = prev
    return base


def select_jobs(stream, changed, variables, force=False):
    jobs, skipped = [], []
    for job in stream.get("jobs", []):
        patterns = job.get("on", ["*"])
        hit = force or any(fnmatch.fnmatch(p, pat)
                           for p in changed for pat in patterns)
        if not hit:
            continue
        try:
            params = {k: _fmt(v, variables)
                      for k, v in (job.get("params") or {}).items()}
        except (KeyError, IndexError) as e:
            skipped.append("%s: unresolved %s" % (job["id"], e))
            continue
        jobs.append({"id": job["id"], "job": job["job"], "params": params,
                     "retries": int(job.get("retries", 0))})
    return jobs, skipped


def decide(stream, obs, stream_state, all_verified, now, settings,
           force=False):
    """Pure decision step for one stream. Returns (new_state, launch or None,
    notifications, summary)."""
    st = copy.deepcopy(stream_state or {})
    notes = []
    name = stream["name"]
    settle = int(settings.get("settle_minutes", 60))
    stale_h = float(settings.get("stale_run_hours", 18))
    incomplete_h = float(settings.get("incomplete_alert_hours", 24))

    # Every platform and every component the last verified set had must be
    # back before we test; otherwise a half-synced new minor repo, or one whose
    # last component build has not landed yet, would look complete. Intended
    # removals are listed in allow_removed (globs on the tracked names).
    removed = []
    if obs is not None:
        ver = st.get("verified") or {}
        gone = sorted(set(ver.get("platforms", [])) - set(obs["platforms"]))
        removed = removed_components(stream, ver.get("packages"),
                                     obs["packages"])
        waiting = [k for k in removed if not _allowed_removal(stream, k)]
        if gone or waiting:
            obs = dict(obs, complete=False,
                       missing=obs["missing"]
                       + ["platform %s" % p for p in gone]
                       + ["component %s" % k for k in waiting])
    if obs is not None and (st.get("observed") or {}).get("fingerprint") \
            != obs["fingerprint"]:
        st["observed"] = {"fingerprint": obs["fingerprint"],
                          "first_seen": iso(now), "repo": obs["repo"],
                          "packages": obs["packages"],
                          "complete": obs["complete"],
                          "missing": obs["missing"][:20],
                          "conflicts": obs["conflicts"][:20],
                          "incomplete_alerted": False}

    attempt = st.get("attempt")
    if attempt and attempt.get("status") == "running":
        age_h = (now - parse_iso(attempt["started"])).total_seconds() / 3600
        if age_h < stale_h:
            return st, None, notes, "%s: QA run %s in progress" % (
                name, attempt["id"])
        attempt.update(status="failed", finished=iso(now),
                       reason="no result after %.0fh (stale)" % age_h)
        notes.append({"to": "qa", "level": "danger", "text":
                      ":warning: %s: QA attempt %s never reported back after "
                      "%.0fh; marked failed. `retry` it or push a new build."
                      % (name, attempt["id"], age_h)})

    if obs is None:
        return st, None, notes, "%s: nothing published yet" % name
    observed = st["observed"]
    quiet_min = (now - parse_iso(observed["first_seen"])).total_seconds() / 60

    verified = st.get("verified") or {}
    changed, older = changed_packages(stream, obs["packages"],
                                      verified.get("packages"))

    # Guards against mis-pushed packages. They run before "up to date", so a
    # repo that silently holds last release's packages is reported too.
    problems = version_mismatch(stream, obs)
    blocked_older = [o for o in older
                     if not _matches(stream, "allow_downgrade", o.split(" ")[0])]
    problems += ["downgrade: %s" % o for o in blocked_older]
    if problems and not force:
        if not observed.get("anomaly_alerted"):
            observed["anomaly_alerted"] = True
            text = (":no_entry: %s: `%s` testing looks mis-pushed, QA not "
                    "started:\n%s\nPush the correct packages and QA starts by "
                    "itself. If this is intended, run the watcher once with "
                    "FORCE_STREAMS=%s." % (name, obs["repo"], "\n".join(
                        "• " + x for x in problems[:10]), name))
            for to in ("qa", "release"):
                notes.append({"to": to, "level": "danger", "text": text})
        return st, None, notes, "%s: blocked, %s" % (name, "; ".join(problems))

    if not changed and not removed and not force:
        return st, None, notes, "%s: up to date at %s" % (
            name, verified.get("version", obs["repo"]))

    if not obs["complete"] and not force:
        if quiet_min / 60 >= incomplete_h and \
                not observed.get("incomplete_alerted"):
            observed["incomplete_alerted"] = True
            notes.append({"to": "qa", "level": "warning", "text":
                          ":hourglass: %s: new packages in %s have been "
                          "incomplete for %.0fh. Missing: %s. Behind: %s%s" % (
                              name, obs["repo"], quiet_min / 60,
                              ", ".join(obs["missing"][:10]) or "-",
                              "; ".join(obs["conflicts"][:5]) or "-",
                              ("\nIf a component was removed on purpose, add "
                               "it to allow_removed in release_watch/"
                               "config.yml, or run the watcher once with "
                               "FORCE_STREAMS=%s." % name)
                              if any(m.startswith("component ")
                                     for m in obs["missing"]) else "")})
        return st, None, notes, "%s: waiting, incomplete (%d missing, %d " \
            "behind)" % (name, len(obs["missing"]), len(obs["conflicts"]))

    # Component-only changes wait longer: on a re-release the rebuilt
    # components often land before the server build, and testing them
    # against the old server would raise false failures.
    required = [k for k, v in (stream.get("packages") or {}).items()
                if isinstance(v, dict) and v.get("required")]
    component_only = bool(required) and not any(k in changed for k in required)
    if component_only:
        settle = int(settings.get("component_settle_minutes", settle))
    if quiet_min < settle and not force:
        return st, None, notes, "%s: settling, %d/%d min without changes%s" % (
            name, quiet_min, settle,
            " (components only; waiting for a possible server build)"
            if component_only else "")

    if attempt and attempt.get("status") == "failed" and \
            attempt.get("packages") == obs["packages"] and not force:
        return st, None, notes, "%s: %s already failed QA; waiting for a " \
            "new build or `retry`" % (name, attempt["version"])

    variables = build_vars(stream, obs, st, all_verified)
    jobs, skipped = select_jobs(stream, changed, variables, force=force)
    for s in skipped:
        notes.append({"to": "qa", "level": "warning",
                      "text": ":grey_question: %s: job skipped, %s" % (name, s)})
    attempt_id = "%s-%s" % (variables["version"], now.strftime("%Y%m%d%H%M"))
    new_attempt = {"id": attempt_id, "status": "running", "started": iso(now),
                   "version": variables["version"], "repo": obs["repo"],
                   "packages": obs["packages"], "changed": changed,
                   "removed": removed,
                   "platforms": obs["platforms"],
                   "jobs": [j["id"] for j in jobs]}
    st["attempt"] = new_attempt
    if not jobs:
        # Nothing maps to these packages: promote without running anything.
        new_attempt.update(status="passed", finished=iso(now), builds=[])
        st["verified"] = _verified_from(new_attempt, now)
        return st, None, notes, "%s: %s promoted, no jobs map to %s" % (
            name, variables["version"], ", ".join(changed))
    launch = {"stream": name, "attempt_id": attempt_id,
              "version": variables["version"], "repo": obs["repo"],
              "changed": changed, "removed": removed, "jobs": jobs,
              "max_parallel": int(stream.get("max_parallel",
                                             settings.get("max_parallel", 3)))}
    return st, launch, notes, "%s: launching %d job(s) for %s (%s)%s" % (
        name, len(jobs), variables["version"], _fmt_changed(changed),
        ("; removed: " + ", ".join(removed)) if removed else "")


def _fmt_changed(changed, limit=15):
    items = ["%s %s->%s" % (k, v[0] or "new", v[1])
             for k, v in sorted(changed.items())]
    more = len(items) - limit
    return ", ".join(items[:limit]) + (" (+%d more)" % more if more > 0 else "")


def _fmt_removed(attempt):
    rm = attempt.get("removed") or []
    return ("\nRemoved: " + ", ".join(rm)) if rm else ""


def _verified_from(attempt, now):
    return {"version": attempt["version"], "repo": attempt["repo"],
            "packages": attempt["packages"], "attempt": attempt["id"],
            "platforms": attempt.get("platforms", []), "at": iso(now)}


# ---------------------------------------------------------------- state

def load_state(path):
    p = pathlib.Path(path)
    if not p.exists() or not p.read_text().strip():
        return {"streams": {}}
    data = yaml.safe_load(p.read_text()) or {}
    data.setdefault("streams", {})
    return data


class _NoAliasDumper(yaml.SafeDumper):
    """Write shared dicts in full instead of &id001 anchors: people read
    VERSIONS.yml in git diffs."""

    def ignore_aliases(self, data):
        return True


def save_state(path, state):
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(STATE_HEADER + yaml.dump(state, Dumper=_NoAliasDumper,
                                          sort_keys=True,
                                          default_flow_style=False))


def all_verified_versions(state):
    return {n: (s.get("verified") or {}).get("version")
            for n, s in state["streams"].items()
            if (s.get("verified") or {}).get("version")}


def _selected(cfg, only):
    names = [n for n, s in cfg["streams"].items() if s["enabled"]]
    if only:
        unknown = set(only) - set(cfg["streams"])
        if unknown:
            raise SystemExit("unknown stream(s): %s" % ", ".join(sorted(unknown)))
        names = [n for n in names if n in only] + \
            [n for n in only if n not in names]
    return names


def _channel(cfg, key):
    return cfg["slack"].get(key) or cfg["slack"].get("qa")


def _stream(cfg, name):
    s = dict(cfg["streams"][name])
    s["name"] = name
    return s


# ---------------------------------------------------------------- commands

def make_fetcher(args, cfg):
    return Fetcher(args.cache, missing_codes=cfg["settings"].get(
        "missing_http_codes", (404, 410)))


def cmd_observe(args, cfg):
    fetcher = make_fetcher(args, cfg)
    state = load_state(args.state) if args.state else {"streams": {}}
    for name in _selected(cfg, args.stream):
        obs = observe(_stream(cfg, name), state["streams"].get(name),
                      fetcher, log=print)
        print(json.dumps({name: obs}, indent=2, sort_keys=True))
    return 0


def cmd_poll(args, cfg):
    fetcher = make_fetcher(args, cfg)
    state = load_state(args.state)
    now = dt.datetime.now(dt.timezone.utc)
    plan = {"generated": iso(now), "launches": [], "notifications": [],
            "summary": []}
    force = set(args.force or [])
    for name in _selected(cfg, args.stream):
        stream = _stream(cfg, name)
        sst = state["streams"].get(name, {})
        try:
            obs = observe(stream, sst, fetcher)
        except Exception as e:  # one broken repo must not stop the others
            err = str(e)
            plan["summary"].append("%s: ERROR %s" % (name, err))
            if sst.get("error") != err:  # alert once per distinct error
                plan["notifications"].append({"to": "qa", "level": "warning",
                    "text": ":x: %s: cannot read the testing repo, not "
                            "watching it until fixed: %s" % (name, err)})
            state["streams"][name] = dict(sst, error=err)
            continue
        if sst.get("error"):
            plan["notifications"].append({"to": "qa", "level": "good",
                "text": ":white_check_mark: %s: repo readable again" % name})
            sst = {k: v for k, v in sst.items() if k != "error"}
        new_st, launch, notes, summary = decide(
            stream, obs, sst, all_verified_versions(state), now,
            cfg["settings"], force=name in force)
        state["streams"][name] = new_st
        plan["summary"].append(summary)
        plan["notifications"].extend(notes)
        if launch:
            plan["launches"].append(launch)
            if cfg["settings"].get("notify_on_start"):
                plan["notifications"].append({"to": "qa", "level": "good",
                    "text": ":mag: %s: new packages in %s testing (%s). "
                    "Started %d QA job(s)." % (
                        name, launch["repo"], _fmt_changed(launch["changed"]),
                        len(launch["jobs"]))})
    seen, unique = set(), []
    for n in plan["notifications"]:
        n["channel"] = _channel(cfg, n.pop("to"))
        if (n["channel"], n["text"]) not in seen:
            seen.add((n["channel"], n["text"]))
            unique.append(n)
    plan["notifications"] = unique
    if not args.dry_run:
        save_state(args.state, state)
    out = json.dumps(plan, indent=2, sort_keys=True)
    if args.plan:
        pathlib.Path(args.plan).write_text(out)
    for line in plan["summary"]:
        print(line)
    if args.dry_run:
        print("(dry run: state not written)")
    return 0


def cmd_record(args, cfg):
    state = load_state(args.state)
    now = dt.datetime.now(dt.timezone.utc)
    builds = json.loads(pathlib.Path(args.builds).read_text()) \
        if args.builds else []
    sst = state["streams"].get(args.stream) or {}
    attempt = sst.get("attempt")
    msg = {"channel": _channel(cfg, "qa"), "level": "warning", "text": ""}
    if not attempt or attempt.get("id") != args.attempt_id:
        msg["text"] = (":warning: %s: result for %s ignored; current attempt "
                       "is %s" % (args.stream, args.attempt_id,
                                  (attempt or {}).get("id")))
        _emit(args, msg)
        return 0
    ok = bool(builds) and all(b.get("result") == "SUCCESS" for b in builds) \
        and not args.aborted
    attempt.update(finished=iso(now), builds=builds,
                   status="passed" if ok else "failed")
    changed = _fmt_changed(attempt.get("changed", {}))
    if ok:
        sst["verified"] = _verified_from(attempt, now)
        msg.update(channel=_channel(cfg, "release"), level="good", text=(
            ":white_check_mark: *%s* passed QA (%d job(s), `%s` testing "
            "repo). Packages are ready to be released.\nChanged: %s%s" % (
                attempt["version"], len(builds), attempt["repo"], changed,
                _fmt_removed(attempt))))
    else:
        bad = [b for b in builds if b.get("result") != "SUCCESS"]
        lines = ["• %s: %s %s" % (b.get("id"), b.get("result"),
                                  b.get("url", "")) for b in bad]
        if args.aborted:
            lines.append("• orchestration aborted: %s" % args.aborted)
            attempt["reason"] = args.aborted
        msg.update(level="danger", text=(
            ":x: *%s* failed QA (`%s` testing repo), not ready for release.\n"
            "Changed: %s%s\n%s\nVerified stays at %s. Re-runs automatically on "
            "a new build; or run the watcher with RETRY_STREAMS=%s." % (
                attempt["version"], attempt["repo"], changed,
                _fmt_removed(attempt),
                "\n".join(lines), (sst.get("verified") or {}).get("version",
                                                                  "none"),
                args.stream)))
    state["streams"][args.stream] = sst
    save_state(args.state, state)
    _emit(args, msg)
    return 0


def _emit(args, msg):
    out = json.dumps(msg, indent=2)
    if getattr(args, "message", None):
        pathlib.Path(args.message).write_text(out)
    print(out)


def cmd_retry(args, cfg):
    state = load_state(args.state)
    for name in args.stream:
        att = (state["streams"].get(name) or {}).get("attempt")
        if att and att.get("status") in ("failed", "running"):
            state["streams"][name]["attempt"] = None
            print("%s: cleared %s attempt %s" % (name, att["status"], att["id"]))
        else:
            print("%s: nothing to retry" % name)
    save_state(args.state, state)
    return 0


def cmd_baseline(args, cfg):
    """Record what is in the repos right now as verified, launching nothing.
    Run once when enabling the watcher so it does not re-test everything."""
    fetcher = make_fetcher(args, cfg)
    state = load_state(args.state)
    now = dt.datetime.now(dt.timezone.utc)
    for name in _selected(cfg, args.stream):
        stream = _stream(cfg, name)
        sst = state["streams"].setdefault(name, {})
        obs = observe(stream, sst, fetcher)
        if not obs:
            print("%s: nothing found, left empty" % name)
            continue
        variables = build_vars(stream, obs, sst, all_verified_versions(state))
        sst["verified"] = {"version": variables["version"], "repo": obs["repo"],
                           "packages": obs["packages"], "attempt": "baseline",
                           "platforms": obs["platforms"],
                           "at": iso(now)}
        sst["attempt"] = None
        print("%s: baseline %s %s" % (name, variables["version"],
                                      json.dumps(obs["packages"])))
    save_state(args.state, state)
    return 0


def cmd_show(args, cfg):
    state = load_state(args.state)
    for name, s in sorted(state["streams"].items()):
        v = s.get("verified") or {}
        a = s.get("attempt") or {}
        print("%-14s verified=%-12s attempt=%s %s" % (
            name, v.get("version", "-"), a.get("id", "-"), a.get("status", "")))
    return 0


def build_argparser():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--config", default=str(DEFAULT_CONFIG))
    ap.add_argument("--state", default="VERSIONS.yml")
    ap.add_argument("--cache", default=None,
                    help="directory for the conditional-GET cache")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("observe", help="print what the repos contain now")
    p.add_argument("stream", nargs="*")

    p = sub.add_parser("poll", help="observe, decide, update state, write plan")
    p.add_argument("stream", nargs="*")
    p.add_argument("--plan", help="write the launch plan JSON here")
    p.add_argument("--force", action="append",
                   help="launch all jobs of STREAM now (repeatable)")
    p.add_argument("--dry-run", action="store_true")

    p = sub.add_parser("record", help="store the result of a QA attempt")
    p.add_argument("--stream", required=True)
    p.add_argument("--attempt-id", required=True)
    p.add_argument("--builds", help="JSON list of {id, job, result, url}")
    p.add_argument("--aborted", help="reason, when the QA run itself broke")
    p.add_argument("--message", help="write the Slack message JSON here")

    p = sub.add_parser("retry", help="forget a failed attempt so it re-runs")
    p.add_argument("stream", nargs="+")

    p = sub.add_parser("baseline", help="mark current repo content as verified")
    p.add_argument("stream", nargs="*")

    sub.add_parser("show", help="one line per stream")
    return ap


def main(argv=None):
    args = build_argparser().parse_args(argv)
    cfg = load_config(args.config)
    return {"observe": cmd_observe, "poll": cmd_poll, "record": cmd_record,
            "retry": cmd_retry, "baseline": cmd_baseline,
            "show": cmd_show}[args.cmd](args, cfg)


if __name__ == "__main__":
    sys.exit(main())
