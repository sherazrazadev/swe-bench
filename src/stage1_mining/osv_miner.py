"""Stage 1 - OSV Miner.

Mines OSV.dev for PyPI / npm vulnerabilities that have a clean, extractable GitHub fix commit,
resolves the pre-patch commit (first parent of the fix) and merges the result into
`data/01_mined/osv_candidates.json`.

Data sources (--sources, interleaved round-robin so a small --limit mixes them)
  * osv    OSV bulk export  https://osv-vulnerabilities.storage.googleapis.com/<eco>/all.zip
           (OSV's /v1/query cannot enumerate an ecosystem; the export holds the same records as the API)
  * ghsa   GitHub Advisory Database REST API  GET /advisories (reviewed, newest first; optional severity/CWE filters)
  * huntr  huntr.com bug-bounty disclosures. huntr has no public API, so these are the OSV/GHSA records whose references
           point at a huntr.com/bounties page (their CVEs flow into OSV/GHSA); the bounty URL is kept as `report_url`.
  * GitHub REST API  GET /repos/{owner}/{repo}/commits/{sha}  (parent lookup; set GITHUB_TOKEN)

Cross-run behaviour (via StateManager)
  * A fix commit that was already mined (or permanently failed to resolve) is skipped *before* any
    GitHub call, so raising --limit from 50 to 400 only spends API calls on new candidates.
  * `--limit` counts NEW records per run; the output file is cumulative.
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import threading
import time
import zipfile
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Iterator, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from src.common.config import Config
from src.common.logging_setup import configure_logging
from src.common.state_manager import StateManager, Status

log = logging.getLogger(__name__)

STAGE = "stage1_mining"
OSV_EXPORT_URL = "https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"
GITHUB_API = "https://api.github.com"
SUPPORTED_ECOSYSTEMS = ("PyPI", "npm", "Go", "Packagist")
SOURCES = ("osv", "ghsa", "huntr")
GHSA_ECOSYSTEM = {"PyPI": "pip", "npm": "npm", "Go": "go", "Packagist": "composer"}
HUNTR_RE = re.compile(r"^https?://(?:www\.)?huntr\.(?:com|dev)/bounties/[0-9a-f-]{8,}", re.IGNORECASE)
OUTPUT_NAME = "osv_candidates.json"
MAX_RESOLVE_ATTEMPTS = 2

FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
GH_COMMIT_RE = re.compile(
    r"^https?://(?:www\.)?github\.com/(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+)"
    r"/commit/(?P<sha>[0-9a-f]{40})(?:\.patch|\.diff)?(?:[/?#].*)?$",
    re.IGNORECASE,
)
GH_REPO_RE = re.compile(
    r"^https?://(?:www\.)?github\.com/(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+?)(?:\.git)?/?$",
    re.IGNORECASE,
)


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class FixRef:
    owner: str
    repo: str
    sha: str

    @property
    def repo_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.repo}"

    def key(self) -> str:
        return f"{self.owner.lower()}/{self.repo.lower()}@{self.sha}"


@dataclass
class MinedVuln:
    osv_id: str
    cve_id: Optional[str]
    ecosystem: str
    package: Optional[str]
    repo_url: str
    pre_patch_commit: str
    fixed_commit: str
    summary: str
    published: Optional[str] = None
    aliases: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    severity: Optional[str] = None
    fix_commit_url: str = ""
    source_refs: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)     # which feeds produced it: osv / ghsa / huntr
    report_url: Optional[str] = None                      # huntr bounty page, when there is one
    description: str = ""                                  # advisory text (first 2000 chars) - used to stop the report copying it
    fix_commits: list[str] = field(default_factory=list)   # >1 = a consecutive fix series; the oracle is pre_patch..fixed
    # fix-bypass pair: {"original_id": <advisory or commit the bypass completes>, "original_fix": <full sha>}. Then
    # pre_patch = parent(original fix), fixed = the bypass fix, and the reference fix is the combined change.
    fix_pair: dict = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Fix-bypass pairs (2026-10-20 mining strategy). An advisory that fixes a bypass of an earlier fix documents a place
# the original human fixers missed - a real hidden sibling. The task is built before the ORIGINAL fix: the report shows
# the original symptom, and the bypass place is the part a careful repair must also find.
# --------------------------------------------------------------------------- #
BYPASS_RE = re.compile(
    r"incomplete fix|insufficient fix|bypass(es|ed|ing)? (of |for )?(the )?(previous|prior|earlier|original|initial)|"
    r"(previous|prior|earlier|original|initial) (fix|patch)|(fix|patch) for (CVE|GHSA)-|(still|remains) (vulnerable|"
    r"exploitable)|regression of (CVE|GHSA)-", re.I)
REF_ID_RE = re.compile(r"\b(GHSA(?:-[0-9a-z]{4}){3}|CVE-\d{4}-\d{4,}|PYSEC-\d{4}-\d+|GO-\d{4}-\d+)\b", re.I)
SHA_REF_RE = re.compile(r"incomplete fix (?:of|for) (?:commit )?`?([0-9a-f]{7,40})\b", re.I)


def find_fix_pairs(osv_by_eco: dict[str, list]) -> list[tuple[str, dict, "FixRef", list[str], dict]]:
    """(eco, bypass record, bypass fix, sources, pair) for every bypass advisory whose referenced original advisory
    (or commit) has a fix commit in the SAME repository. Records with a multi-commit fix series are skipped on either
    side (the one-sha original/bypass split would be wrong)."""
    idx: dict[str, tuple[str, dict, FixRef]] = {}
    for eco, items in osv_by_eco.items():
        for rec, fix, _ in items:
            if rec.get("_fix_series"):
                continue
            for k in [rec["id"], *(rec.get("aliases") or [])]:
                idx.setdefault(k.upper(), (eco, rec, fix))
    pairs = []
    for eco, items in osv_by_eco.items():
        for rec, fix, srcs in items:
            if rec.get("_fix_series"):
                continue
            text = f"{rec.get('summary') or ''}\n{rec.get('details') or ''}"
            if not BYPASS_RE.search(text):
                continue
            own = {k.upper() for k in [rec["id"], *(rec.get("aliases") or [])]}
            same_repo = lambda f: (f.owner.lower(), f.repo.lower()) == (fix.owner.lower(), fix.repo.lower())
            pair = None
            for ref in dict.fromkeys(m.upper() for m in REF_ID_RE.findall(text)):
                if ref in own or ref not in idx:
                    continue
                _, orig, ofix = idx[ref]
                if orig["id"].upper() in own or not same_repo(ofix) or ofix.sha == fix.sha:
                    continue
                pair = {"original_id": orig["id"], "original_fix": ofix.sha}
                break
            if not pair:
                m = SHA_REF_RE.search(text)
                if m and not fix.sha.startswith(m.group(1).lower()):
                    pair = {"original_id": f"commit {m.group(1)}", "original_fix": m.group(1).lower()}
            if pair:
                pairs.append((eco, rec, fix, srcs, pair))
    log.info("Fix-bypass pairs found", extra={"pairs": len(pairs)})
    return pairs


# --------------------------------------------------------------------------- #
# HTTP helpers
# --------------------------------------------------------------------------- #
class RateLimiter:
    """Thread-safe minimum-interval limiter."""

    def __init__(self, calls_per_second: float):
        self._interval = 1.0 / calls_per_second if calls_per_second > 0 else 0.0
        self._next = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        if not self._interval:
            return
        with self._lock:
            now = time.monotonic()
            delay = self._next - now
            self._next = max(now, self._next) + self._interval
        if delay > 0:
            time.sleep(delay)


def make_session(token: Optional[str] = None) -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=5, backoff_factor=1.5,
        status_forcelist=(500, 502, 503, 504),
        allowed_methods=frozenset({"GET"}),
        respect_retry_after_header=True,
    )
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.headers["User-Agent"] = "cwe-bench-osv-miner/1.1"
    s.headers["Accept"] = "application/vnd.github+json"
    if token:
        s.headers["Authorization"] = f"Bearer {token}"
    return s


# --------------------------------------------------------------------------- #
# OSV loading
# --------------------------------------------------------------------------- #
def download_ecosystem_zip(session: requests.Session, eco: str, cache_dir: Path,
                           max_age_hours: float = 24.0) -> Path:
    """Download (or reuse a fresh cached copy of) the ecosystem export."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_dir / f"{eco}.zip"
    if path.exists() and (time.time() - path.stat().st_mtime) < max_age_hours * 3600:
        log.info("Using cached %s export", eco, extra={"path": str(path)})
        return path

    url = OSV_EXPORT_URL.format(eco=eco)
    log.info("Downloading OSV export", extra={"url": url})
    tmp = path.with_suffix(".part")
    with session.get(url, stream=True, timeout=(10, 120),
                     headers={"Accept": "application/zip"}) as r:
        r.raise_for_status()
        with open(tmp, "wb") as f:
            for chunk in r.iter_content(chunk_size=1 << 20):
                f.write(chunk)
    tmp.replace(path)
    return path


def iter_osv_records(zip_path: Path) -> Iterator[dict]:
    with zipfile.ZipFile(zip_path) as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            try:
                yield json.loads(zf.read(name))
            except (json.JSONDecodeError, zipfile.BadZipFile) as e:
                log.warning("Skipping unreadable record", extra={"name": name, "error": str(e)})


# --------------------------------------------------------------------------- #
# Extraction
# --------------------------------------------------------------------------- #
def _fix_from_url(url: str) -> Optional[FixRef]:
    m = GH_COMMIT_RE.match(url.strip())
    return FixRef(m["owner"], m["repo"], m["sha"].lower()) if m else None


def extract_fix_refs(record: dict) -> tuple[list[FixRef], list[str]]:
    """Unique GitHub fix commits for a record, plus the source URLs/ranges they came from."""
    found: dict[str, FixRef] = {}
    sources: list[str] = []

    for ref in record.get("references", []):
        if ref.get("type") not in ("FIX", "WEB"):
            continue
        fix = _fix_from_url(ref.get("url", ""))
        if fix:
            found.setdefault(fix.key(), fix)
            sources.append(ref["url"])

    for aff in record.get("affected", []):
        for rng in aff.get("ranges", []):
            if rng.get("type") != "GIT":
                continue
            m = GH_REPO_RE.match(rng.get("repo", ""))
            if not m:
                continue
            for ev in rng.get("events", []):
                sha = (ev.get("fixed") or "").lower()
                if FULL_SHA_RE.match(sha):
                    fix = FixRef(m["owner"], m["repo"], sha)
                    found.setdefault(fix.key(), fix)
                    sources.append(f"{rng['repo']}@{sha}")

    return list(found.values()), sources


def first_package(record: dict, eco: str) -> Optional[str]:
    for aff in record.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem") == eco and pkg.get("name"):
            return pkg["name"]
    return None


def extract_cve(record: dict) -> Optional[str]:
    for candidate in [record.get("id", ""), *record.get("aliases", [])]:
        if candidate.startswith("CVE-"):
            return candidate
    return None


def extract_cwes(record: dict) -> list[str]:
    cwes = record.get("database_specific", {}).get("cwe_ids", [])
    return [c for c in cwes if isinstance(c, str)]


def build_summary(record: dict) -> str:
    summary = (record.get("summary") or "").strip()
    if summary:
        return summary
    details = (record.get("details") or "").strip()
    return details.split("\n\n", 1)[0][:500] if details else ""


# --------------------------------------------------------------------------- #
# GitHub parent resolution
# --------------------------------------------------------------------------- #
class GitHubResolver:
    """Resolves a fix commit to its single parent. `permanent_failure` distinguishes
    'this commit can never work' (merge commit, repo deleted) from transient trouble."""

    def __init__(self, session: requests.Session, rps: float):
        self.session = session
        self.limiter = RateLimiter(rps)
        self._cache: dict[str, Optional[str]] = {}
        self.commit_dates: dict[str, str] = {}      # fix key -> YYYY-MM-DD (earlier of author / committer date)
        self.last_failure_permanent = False

    def parent_of(self, fix: FixRef) -> Optional[str]:
        k = fix.key()
        if k in self._cache:
            return self._cache[k]
        result = self._fetch_parent(fix)
        self._cache[k] = result
        return result

    def _fetch_parent(self, fix: FixRef) -> Optional[str]:
        url = f"{GITHUB_API}/repos/{fix.owner}/{fix.repo}/commits/{fix.sha}"
        self.last_failure_permanent = False
        for attempt in range(4):
            self.limiter.wait()
            try:
                r = self.session.get(url, timeout=30)
            except requests.RequestException as e:
                log.warning("GitHub request failed", extra={"sha": fix.sha[:10], "error": str(e)})
                time.sleep(2 ** attempt)
                continue

            if r.status_code == 200:
                commit = r.json().get("commit") or {}
                # earlier of the two: a rebased or cherry-picked backport gets a fresh committer date only
                dates = [d for d in ((commit.get("author") or {}).get("date"), (commit.get("committer") or {}).get("date")) if d]
                if dates:
                    self.commit_dates[fix.key()] = min(dates)[:10]
                parents = r.json().get("parents", [])
                if len(parents) != 1:
                    log.info("Skip: not a single-parent commit",
                             extra={"repo": f"{fix.owner}/{fix.repo}", "sha": fix.sha[:10], "parents": len(parents)})
                    self.last_failure_permanent = True
                    return None
                return parents[0]["sha"]

            if r.status_code in (403, 429) and self._is_rate_limited(r):
                self._sleep_until_reset(r)
                continue
            if r.status_code in (404, 422, 451):
                log.info("Skip: repo/commit unavailable",
                         extra={"repo": f"{fix.owner}/{fix.repo}", "sha": fix.sha[:10], "http": r.status_code})
                self.last_failure_permanent = True
                return None
            log.warning("Unexpected GitHub response", extra={"url": url, "http": r.status_code})
            time.sleep(2 ** attempt)
        return None

    def _get_json(self, url: str) -> Optional[dict]:
        for attempt in range(4):
            self.limiter.wait()
            try:
                r = self.session.get(url, timeout=60)
            except requests.RequestException:
                time.sleep(2 ** attempt)
                continue
            if r.status_code == 200:
                return r.json()
            if r.status_code in (403, 429) and self._is_rate_limited(r):
                self._sleep_until_reset(r)
                continue
            if r.status_code in (404, 422, 451):
                return None
            time.sleep(2 ** attempt)
        return None

    def resolve_series(self, owner: str, repo: str, shas: list[str]) -> Optional[tuple[FixRef, str, list[str]]]:
        """Several fix commits for one advisory -> (fix commit to diff to, pre-patch commit, commits in the diff).
          consecutive series (each commit builds on the previous, nothing else in between) -> parent(first)..last
          backports of one fix on several branches -> the commit on the default branch, as a single-commit fix
        Anything else (unrelated commits in between, unreachable commits) -> None (skipped: the oracle would be wrong)."""
        fixes = [FixRef(owner, repo, s) for s in shas]
        parents = {f.sha: self.parent_of(f) for f in fixes}
        if not all(parents.values()):
            return None
        fixes.sort(key=lambda f: self.commit_dates.get(f.key(), ""))
        first, last = fixes[0], fixes[-1]
        cmp = self._get_json(f"{GITHUB_API}/repos/{owner}/{repo}/compare/{parents[first.sha]}...{last.sha}")
        if cmp and cmp.get("status") == "ahead":
            in_range = [c["sha"].lower() for c in cmp.get("commits", [])]
            if len(in_range) == len(fixes) and set(in_range) == {f.sha for f in fixes}:
                dates = [self.commit_dates[f.key()] for f in fixes if f.key() in self.commit_dates]
                if dates:            # the memorisation cutoff applies to the EARLIEST commit of the series
                    self.commit_dates[last.key()] = min(dates)
                return last, parents[first.sha], [f.sha for f in fixes]
        info = self._get_json(f"{GITHUB_API}/repos/{owner}/{repo}")
        branch = (info or {}).get("default_branch")
        if not branch:
            return None
        for f in reversed(fixes):                 # newest first: the default-branch copy of a backported fix
            on = self._get_json(f"{GITHUB_API}/repos/{owner}/{repo}/compare/{branch}...{f.sha}")
            if on and on.get("status") in ("behind", "identical"):
                return f, parents[f.sha], [f.sha]
        return None

    def resolve_pair(self, owner: str, repo: str, orig_sha: str, bypass_sha: str) -> tuple[Optional[tuple[str, str]], str]:
        """Fix-bypass pair -> ((full original sha, pre-patch = parent(original)), "") or (None, reason). The bypass fix
        must DESCEND from the original fix; a bypass on a separate backport line would make the combined diff
        meaningless. Pairs far apart in time pull in unrelated commits; stage 2's diff-size limits reject those."""
        c = self._get_json(f"{GITHUB_API}/repos/{owner}/{repo}/commits/{orig_sha}")      # also resolves short shas
        if not c or not c.get("sha"):
            return None, "original fix commit not found"
        full = c["sha"].lower()
        parents = c.get("parents") or []
        if len(parents) != 1:
            return None, "original fix is not a single-parent commit"
        dates = [d for d in (((c.get("commit") or {}).get(x) or {}).get("date") for x in ("author", "committer")) if d]
        if dates:
            self.commit_dates[FixRef(owner, repo, full).key()] = min(dates)[:10]
        cmp = self._get_json(f"{GITHUB_API}/repos/{owner}/{repo}/compare/{full}...{bypass_sha}")
        if not cmp or cmp.get("status") != "ahead":
            return None, f"bypass fix does not descend from the original fix (compare: {(cmp or {}).get('status')})"
        return (full, parents[0]["sha"]), ""

    @staticmethod
    def _is_rate_limited(r: requests.Response) -> bool:
        return (r.headers.get("X-RateLimit-Remaining") == "0"
                or "retry-after" in r.headers
                or "rate limit" in r.text.lower())

    @staticmethod
    def _sleep_until_reset(r: requests.Response) -> None:
        retry_after = r.headers.get("Retry-After")
        if retry_after and retry_after.isdigit():
            wait = int(retry_after)
        else:
            reset = int(r.headers.get("X-RateLimit-Reset", time.time() + 60))
            wait = max(reset - int(time.time()), 1)
        wait = min(wait + 2, 3700)
        log.warning("GitHub rate limit hit; sleeping (set GITHUB_TOKEN to avoid this)", extra={"seconds": wait})
        time.sleep(wait)


# --------------------------------------------------------------------------- #
# Extra sources
# --------------------------------------------------------------------------- #
def huntr_url(record: dict) -> Optional[str]:
    for ref in record.get("references", []):
        url = (ref.get("url") if isinstance(ref, dict) else ref) or ""
        if HUNTR_RE.match(url):
            return url
    return None


def ghsa_to_osv(adv: dict) -> Optional[dict]:
    """GitHub Advisory Database REST record -> OSV-shaped dict, so the same extraction code applies."""
    affected = []
    for v in adv.get("vulnerabilities") or []:
        pkg = v.get("package") or {}
        eco = {"pip": "PyPI", "npm": "npm", "go": "Go", "composer": "Packagist"}.get(pkg.get("ecosystem"))
        if eco and pkg.get("name"):
            affected.append({"package": {"ecosystem": eco, "name": pkg["name"]}})
    if not affected:
        return None
    return {
        "id": adv["ghsa_id"],
        "aliases": [adv["cve_id"]] if adv.get("cve_id") else [],
        "summary": adv.get("summary") or "",
        "details": adv.get("description") or "",
        "published": adv.get("published_at"),
        "references": [{"type": "WEB", "url": u} for u in adv.get("references") or []],
        "affected": affected,
        "database_specific": {"cwe_ids": [c["cwe_id"] for c in adv.get("cwes") or [] if c.get("cwe_id")],
                              "severity": (adv.get("severity") or "").upper() or None},
    }


def ghsa_candidates(session: requests.Session, eco: str, pages: int, severity: Optional[str],
                    cwes: Optional[list[str]], allow_multi_commit: bool) -> list[tuple[dict, FixRef, list[str]]]:
    params = {"type": "reviewed", "ecosystem": GHSA_ECOSYSTEM[eco], "per_page": 100,
              "sort": "published", "direction": "desc"}
    if severity:
        params["severity"] = severity
    if cwes:
        params["cwes"] = ",".join(cwes)
    url: Optional[str] = f"{GITHUB_API}/advisories"
    out, seen = [], 0
    for _ in range(pages):
        if not url:
            break
        try:
            r = session.get(url, params=params if url.endswith("/advisories") else None, timeout=60)
        except requests.RequestException as e:
            log.warning("GHSA request failed", extra={"error": str(e)})
            break
        if r.status_code in (403, 429) and GitHubResolver._is_rate_limited(r):
            GitHubResolver._sleep_until_reset(r)
            continue
        if r.status_code != 200:
            log.warning("GHSA unexpected response", extra={"http": r.status_code, "body": r.text[:150]})
            break
        for adv in r.json():
            seen += 1
            rec = ghsa_to_osv(adv)
            if not rec or adv.get("withdrawn_at"):
                continue
            fixes, sources = extract_fix_refs(rec)
            keep = keep_fixes(rec, fixes, allow_multi_commit) if fixes else None
            if keep:
                out.append((rec, keep, sources))
        url = r.links.get("next", {}).get("url")
    log.info("GHSA scanned", extra={"ecosystem": eco, "advisories": seen, "with_fix_commit": len(out)})
    return out


# --------------------------------------------------------------------------- #
# Pipeline
# --------------------------------------------------------------------------- #
def keep_fixes(rec: dict, fixes: list[FixRef], allow_multi_commit: bool) -> Optional[FixRef]:
    """The fix to process. Several fix commits in ONE repo are kept for series resolution (stage 1 later turns a
    consecutive series into one oracle diff, or picks the default-branch commit of a backported fix); fixes spread
    over several repos are skipped. Multi-file fixes often land as several commits, and those are the hard tasks."""
    if len(fixes) == 1:
        return fixes[0]
    if len({(f.owner.lower(), f.repo.lower()) for f in fixes}) == 1:
        rec["_fix_series"] = [f.sha for f in fixes]
        return fixes[0]
    return fixes[0] if allow_multi_commit else None


def candidates_for_ecosystem(session: requests.Session, eco: str, cache_dir: Path,
                             allow_multi_commit: bool) -> list[tuple[dict, FixRef, list[str]]]:
    zip_path = download_ecosystem_zip(session, eco, cache_dir)
    out, total = [], 0
    for rec in iter_osv_records(zip_path):
        total += 1
        if rec.get("withdrawn"):
            continue
        fixes, sources = extract_fix_refs(rec)
        if not fixes:
            continue
        keep = keep_fixes(rec, fixes, allow_multi_commit)
        if keep:
            out.append((rec, keep, sources))
    log.info("Ecosystem scanned", extra={"ecosystem": eco, "records": total, "with_fix_commit": len(out)})
    out.sort(key=lambda t: t[0].get("published", ""), reverse=True)  # newest first
    return out


def interleave(lists: list[list]) -> Iterator:
    """Round-robin across ecosystems so a small --limit samples all of them."""
    iters = [iter(l) for l in lists]
    while iters:
        for it in list(iters):
            try:
                yield next(it)
            except StopIteration:
                iters.remove(it)


def mine(ecosystems: list[str], limit: int, cache_dir: Path, github_token: Optional[str],
         github_rps: float, allow_multi_commit: bool, state: Optional[StateManager],
         sources: tuple[str, ...] = SOURCES, ghsa_pages: int = 3, ghsa_severity: Optional[str] = None,
         ghsa_cwes: Optional[list[str]] = None, batch_size: int = 10,
         on_batch: Optional[Callable[[list[MinedVuln]], None]] = None,
         published_after: str = "", fix_pairs: bool = True) -> list[MinedVuln]:
    osv_session = make_session()
    gh_session = make_session(github_token)
    resolver = GitHubResolver(gh_session, github_rps)

    feeds: list[tuple[str, list]] = []          # (source name, [(eco, rec, fix, srcs), ...]) in priority order
    tags: dict[str, set[str]] = {}
    osv_by_eco: dict[str, list] = {}
    if "osv" in sources or "huntr" in sources:
        for eco in ecosystems:
            try:
                osv_by_eco[eco] = candidates_for_ecosystem(osv_session, eco, cache_dir, allow_multi_commit)
            except (requests.RequestException, zipfile.BadZipFile, OSError) as e:
                log.error("Failed to load ecosystem export", extra={"ecosystem": eco, "error": str(e)})
    if "huntr" in sources:
        feeds.append(("huntr", [(eco, *c) for eco, cs in osv_by_eco.items() for c in cs if huntr_url(c[0])]))
        log.info("huntr-tagged records", extra={"count": len(feeds[-1][1])})
    if "ghsa" in sources:
        ghsa_all = []
        for eco in ecosystems:
            ghsa_all += [(eco, *c) for c in ghsa_candidates(gh_session, eco, ghsa_pages, ghsa_severity, ghsa_cwes,
                                                            allow_multi_commit)]
        feeds.append(("ghsa", ghsa_all))
    if "osv" in sources:
        feeds.append(("osv", [(eco, *c) for eco, cs in osv_by_eco.items() for c in cs]))
    for name, items in feeds:
        for _, _, fix, _ in items:
            tags.setdefault(fix.key(), set()).add(name)

    results: list[MinedVuln] = []
    seen_this_run: set[str] = set()
    skipped_known = 0

    # Fix-bypass pairs first: the strongest new source (2026-10-20). Keyed "pair:<repo>@<orig>..<bypass>" in the state so
    # the bypass advisory's own single-fix record (usually already mined) does not hide its pair.
    pair_stats: Counter = Counter()
    for eco, rec, fix, srcs, pair in (find_fix_pairs(osv_by_eco) if fix_pairs and osv_by_eco else []):
        if len(results) >= limit:
            break
        if published_after and (rec.get("published") or "")[:10] < published_after:
            pair_stats["bypass advisory before cutoff"] += 1
            continue
        key = f"pair:{fix.owner.lower()}/{fix.repo.lower()}@{pair['original_fix'][:12]}..{fix.sha}"
        if key in seen_this_run:
            continue
        seen_this_run.add(key)
        if state and not state.should_process(STAGE, key, MAX_RESOLVE_ATTEMPTS):
            pair_stats["known"] += 1
            continue
        if state and any(state.get(s, rec["id"]) for s in ("stage3_task_builder", "stage4_oracle_validator",
                                                           "stage5_evaluator")):
            state.mark(STAGE, key, Status.REJECTED, "bypass advisory already used by the pipeline", {"osv_id": rec["id"]})
            pair_stats["already used"] += 1
            continue
        resolved, why = resolver.resolve_pair(fix.owner, fix.repo, pair["original_fix"], fix.sha)
        if not resolved:
            state and state.mark(STAGE, key, Status.REJECTED, f"pair: {why}", {"osv_id": rec["id"]})
            pair_stats["unresolvable"] += 1
            continue
        orig_full, parent = resolved
        resolver.parent_of(fix)                                   # the bypass commit's date (the cutoff applies to it)
        fixed_on = resolver.commit_dates.get(fix.key(), "")
        if published_after and fixed_on and fixed_on < published_after:
            state and state.mark(STAGE, key, Status.REJECTED, f"bypass fix committed {fixed_on}, before {published_after}",
                                 {"osv_id": rec["id"]})
            pair_stats["bypass fix before cutoff"] += 1
            continue
        if state:   # the bypass advisory was screened as a single fix: re-screen it as the combined pair
            state.reset("stage2_screening", rec["id"])
        pair_stats["mined"] += 1
        results.append(MinedVuln(
            osv_id=rec["id"], cve_id=extract_cve(rec), ecosystem=eco,
            package=first_package(rec, eco), repo_url=fix.repo_url,
            pre_patch_commit=parent, fixed_commit=fix.sha, summary=build_summary(rec),
            published=rec.get("published"), aliases=rec.get("aliases", []),
            cwe_ids=extract_cwes(rec),
            severity=rec.get("database_specific", {}).get("severity"),
            fix_commit_url=f"{fix.repo_url}/commit/{fix.sha}",
            source_refs=sorted(set(srcs)), sources=sorted(tags.get(fix.key(), set()) | {"fix_pair"}),
            report_url=huntr_url(rec), description=(rec.get("details") or "")[:2000],
            fix_commits=[orig_full, fix.sha], fix_pair={"original_id": pair["original_id"], "original_fix": orig_full},
        ))
        if len(results) % batch_size == 0 and on_batch:
            on_batch(results[len(results) - batch_size:])
    if pair_stats:
        log.info("Fix-bypass pairs processed", extra=dict(pair_stats))

    for eco, rec, fix, srcs in interleave([items for _, items in feeds]):
        if len(results) >= limit:
            break
        if published_after and (rec.get("published") or "")[:10] < published_after:
            continue              # older than the memorisation cutoff: don't spend a GitHub call or a --limit slot on it
        key = fix.key()
        if key in seen_this_run:  # several advisories / sources can share one fix
            continue
        seen_this_run.add(key)
        if state and not state.should_process(STAGE, key, MAX_RESOLVE_ATTEMPTS):
            skipped_known += 1
            continue

        series = rec.get("_fix_series") or []
        fix_commits = [fix.sha]
        if len(series) > 1:
            resolved = resolver.resolve_series(fix.owner, fix.repo, series)
            if not resolved:
                if state:
                    state.mark(STAGE, key, Status.REJECTED, "fix commits are neither one consecutive series nor "
                               "backports of one default-branch fix", {"osv_id": rec["id"]})
                continue
            fix, parent, fix_commits = resolved
            if fix.key() != key:      # resolved to another commit: it may be a fix we already have
                if fix.key() in seen_this_run or (state and not state.should_process(STAGE, fix.key(), MAX_RESOLVE_ATTEMPTS)):
                    skipped_known += 1
                    continue
                seen_this_run.add(fix.key())
                tags.setdefault(fix.key(), set()).update(tags.get(key, set()))
                key = fix.key()
        else:
            parent = resolver.parent_of(fix)
        if not parent:
            if state:
                # Permanent problems are recorded as rejected so they are never retried.
                state.mark(STAGE, key, Status.REJECTED if resolver.last_failure_permanent else Status.FAILED,
                           "parent commit unresolved", {"osv_id": rec["id"]})
            continue
        fixed_on = resolver.commit_dates.get(key, "")
        if published_after and fixed_on and fixed_on < published_after:
            # The FIX date is what matters for memorisation (stage 2 rejected 75% of the pool for this): decide it here
            # with the commit we already fetched, so it never takes a --limit slot.
            if state:
                state.mark(STAGE, key, Status.REJECTED, f"fix committed {fixed_on}, before {published_after}",
                           {"osv_id": rec["id"]})
            continue

        results.append(MinedVuln(
            osv_id=rec["id"], cve_id=extract_cve(rec), ecosystem=eco,
            package=first_package(rec, eco), repo_url=fix.repo_url,
            pre_patch_commit=parent, fixed_commit=fix.sha, summary=build_summary(rec),
            published=rec.get("published"), aliases=rec.get("aliases", []),
            cwe_ids=extract_cwes(rec),
            severity=rec.get("database_specific", {}).get("severity"),
            fix_commit_url=f"{fix.repo_url}/commit/{fix.sha}",
            source_refs=sorted(set(srcs)),
            sources=sorted(tags.get(key, set())), report_url=huntr_url(rec),
            description=(rec.get("details") or "")[:2000], fix_commits=fix_commits,
        ))
        if len(results) % batch_size == 0:
            log.info("Mining progress", extra={"mined": len(results), "limit": limit})
            if on_batch:        # checkpoint: output + dedupe state are saved every batch, so a crash loses < batch_size
                on_batch(results[len(results) - batch_size:])
    if on_batch and len(results) % batch_size:
        on_batch(results[len(results) - len(results) % batch_size:])
    mix = {name: sum(1 for r in results if name in r.sources) for name, _ in feeds}
    log.info("Mining pass finished", extra={"new": len(results), "already_known": skipped_known, "by_source": mix})
    return results


def merge_output(path: Path, new: list[MinedVuln], ecosystems: list[str]) -> int:
    """Merge into the cumulative output file (dedupe by osv_id). Returns total record count."""
    existing: list[dict] = []
    if path.exists():
        try:
            existing = json.loads(path.read_text()).get("vulnerabilities", [])
        except (OSError, json.JSONDecodeError) as e:
            raise RuntimeError(f"existing output {path} is unreadable; refusing to overwrite: {e}") from e
    by_id = {v["osv_id"]: v for v in existing}
    for v in new:
        by_id[v.osv_id] = asdict(v)

    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "ecosystems": sorted(set(ecosystems) | set(
            json.loads(path.read_text()).get("ecosystems", []) if path.exists() else [])),
        "count": len(by_id),
        "vulnerabilities": list(by_id.values()),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
    tmp.replace(path)
    return len(by_id)


def parse_args(argv: Optional[list[str]], cfg: Config) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Stage 1: mine OSV for fixable GitHub-backed vulnerabilities")
    p.add_argument("--limit", type=int, default=50, help="NEW vulnerabilities to mine this run (default 50)")
    p.add_argument("--ecosystems", nargs="+", default=list(SUPPORTED_ECOSYSTEMS), choices=SUPPORTED_ECOSYSTEMS)
    p.add_argument("--sources", nargs="+", default=list(SOURCES), choices=SOURCES,
                   help="feeds to mine (default: osv ghsa huntr, interleaved)")
    p.add_argument("--ghsa-pages", type=int, default=3, help="GHSA pages of 100 advisories per ecosystem (default 3)")
    p.add_argument("--ghsa-severity", choices=("low", "medium", "high", "critical"))
    p.add_argument("--ghsa-cwes", nargs="+", help="restrict GHSA to these CWE numbers, e.g. 22 78 89")
    p.add_argument("--output", type=Path, default=cfg.stage_dir(1) / OUTPUT_NAME)
    p.add_argument("--cache-dir", type=Path, default=cfg.cache_dir / "osv")
    p.add_argument("--github-rps", type=float, default=None,
                   help="GitHub requests/sec (default 2 with token, 0.5 without)")
    p.add_argument("--batch-size", type=int, default=10, help="checkpoint output + state every N mined records (default 10)")
    p.add_argument("--allow-multi-commit", action="store_true",
                   help="keep advisories with several fix commits (uses the first)")
    p.add_argument("--ignore-state", action="store_true", help="do not consult or update the dedupe state")
    args = p.parse_args(argv)
    if args.limit < 1:
        p.error("--limit must be >= 1")
    if args.github_rps is None:
        args.github_rps = 2.0 if cfg.github_token else 0.5
    return args


def main(argv: Optional[list[str]] = None, cfg: Optional[Config] = None) -> int:
    cfg = cfg or Config.load()
    args = parse_args(argv, cfg)
    if not logging.getLogger().handlers:
        configure_logging()
    if not cfg.github_token:
        log.warning("No GITHUB_TOKEN: limited to 60 GitHub calls/hour; large runs will stall")

    state = None if args.ignore_state else StateManager(cfg.state_db)
    try:
        def checkpoint(batch: list[MinedVuln]) -> None:
            merge_output(args.output, batch, args.ecosystems)
            # Only after the output is safely on disk do we record the commits as done.
            if state:
                for v in batch:
                    repo = v.repo_url.removeprefix('https://github.com/').lower()
                    key = (f"pair:{repo}@{v.fix_pair['original_fix'][:12]}..{v.fixed_commit}" if v.fix_pair
                           else f"{repo}@{v.fixed_commit}")
                    state.mark(STAGE, key, Status.DONE, payload={"osv_id": v.osv_id})

        vulns = mine(args.ecosystems, args.limit, args.cache_dir, cfg.github_token,
                     args.github_rps, args.allow_multi_commit, state, tuple(args.sources), args.ghsa_pages,
                     args.ghsa_severity, args.ghsa_cwes, args.batch_size, checkpoint, cfg.published_after)
        total = len(json.loads(args.output.read_text()).get("vulnerabilities", [])) if args.output.exists() else 0
        log.info("Wrote output", extra={"new": len(vulns), "total": total, "path": str(args.output)})
    except KeyboardInterrupt:
        log.error("Interrupted")
        return 130
    except RuntimeError as e:
        log.error("%s", e)
        return 1
    finally:
        if state:
            state.close()
    if not vulns:      # nothing new is a normal state once the feeds are mined out; later stages must still run
        log.warning("No new vulnerabilities mined (feeds exhausted for the current filters)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
