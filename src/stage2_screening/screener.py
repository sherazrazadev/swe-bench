"""Stage 2 - Screener: drop junk fixes and repos we cannot build/test.

Input : data/01_mined/osv_candidates.json
Output: data/02_screened/screened.json  (cumulative; same record schema + a `screening` object)
        data/02_screened/rejected.json  {osv_id: [reasons]}

Rules (see skills/adversarial_research.md section 6)
  * fix commit must change >= 1 non-test SOURCE file in a language we can run (PyPI: .py; npm: js/ts family)
  * dependency-only, manifest/lock-only, docs-only and config/CI-only fixes are rejected
  * changed source lines must be within [--min-lines, --max-lines]
  * repo must have a root build manifest and at least one test file at the pre-patch commit
  * at most --max-per-repo tasks per repository (best score kept)

"Buildable" here is a structural check on the pre-patch file tree. A real Docker build happens in stage 4.
Everything is fetched through the GitHub REST API (cached under data/.cache/gh) - no cloning.
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Optional

import requests

from src.common.classify import TEST_PATH_RE, classify
from src.common import knowledge
from src.common.config import Config
from src.common.logging_setup import configure_logging
from src.common.state_manager import StateManager, Status
from src.stage1_mining.osv_miner import GitHubResolver, RateLimiter, make_session

log = logging.getLogger(__name__)

STAGE = "stage2_screening"
GITHUB_API = "https://api.github.com"
MAX_FILES_IN_COMMIT_API = 300   # GitHub truncates the files list at 300
MAX_ATTEMPTS = 3
# the generator condenses large patches (prompt_patch_view), and the widest fixes are the ones that break the models
MAX_TOTAL_CHANGED_LINES = int(__import__("os").environ.get("SCREEN_MAX_DIFF_LINES", "6000"))

ROOT_MANIFESTS = {
    "PyPI": {"pyproject.toml", "setup.py", "setup.cfg", "requirements.txt"},
    "npm": {"package.json"},
    "Go": {"go.mod"},
    "Packagist": {"composer.json"},
}
TEST_FILE_RE = {
    "PyPI": re.compile(r"(^|/)(test_[^/]+\.py|[^/]+_test\.py|conftest\.py)$"),
    "npm": re.compile(r"(\.(test|spec)\.[cm]?[jt]sx?$)|(^|/)__tests__/|(^|/)(test|tests)/[^/]+\.[cm]?[jt]sx?$"),
    "Go": re.compile(r"_test\.go$"),
    "Packagist": re.compile(r"(^|/)tests?/.+\.php$|[^/]+Tests?\.php$", re.I),
}


class TransientError(Exception):
    """GitHub trouble that may succeed on a later run."""


class PermanentError(Exception):
    """Commit/repo is gone or inaccessible."""


@dataclass
class Decision:
    accepted: bool
    reasons: list[str] = field(default_factory=list)
    info: dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# GitHub access (cached)
# --------------------------------------------------------------------------- #
class GitHubClient:
    def __init__(self, token: Optional[str], rps: float, cache_dir: Path):
        self.session = make_session(token)
        self.limiter = RateLimiter(rps)
        self.cache_dir = cache_dir
        cache_dir.mkdir(parents=True, exist_ok=True)

    def get_json(self, path: str, cache_key: str) -> Any:
        cache = self.cache_dir / f"{cache_key}.json"
        if cache.is_file():
            try:
                return json.loads(cache.read_text())
            except json.JSONDecodeError:
                cache.unlink(missing_ok=True)
        url = f"{GITHUB_API}{path}"
        for attempt in range(4):
            self.limiter.wait()
            try:
                r = self.session.get(url, timeout=45)
            except requests.RequestException as e:
                log.warning("GitHub request failed", extra={"path": path, "error": str(e)})
                time.sleep(2 ** attempt)
                continue
            if r.status_code == 200:
                data = r.json()
                tmp = cache.with_suffix(".tmp")
                tmp.write_text(json.dumps(data))
                tmp.replace(cache)
                return data
            if r.status_code in (403, 429) and GitHubResolver._is_rate_limited(r):
                GitHubResolver._sleep_until_reset(r)
                continue
            if r.status_code in (404, 409, 410, 422, 451):
                raise PermanentError(f"HTTP {r.status_code} for {path}")
            time.sleep(2 ** attempt)
        raise TransientError(f"gave up on {path}")


# --------------------------------------------------------------------------- #
# Decision logic (pure, unit-testable)
# --------------------------------------------------------------------------- #
TEMPLATE_RE = re.compile(r"\.(ejs|hbs|handlebars|mustache|jinja2?|j2|njk|tmpl|tpl|liquid|eta)$", re.IGNORECASE)


IMPORT_LINE_RE = re.compile(
    r"""^(import\b|from\s+[\w.]+\s+import\b|export\s+\*?\s*\{?.*\}?\s*from\s|const\s+\w+\s*=\s*require\(|"""
    r"""use\s+[\w\\]+(\s+as\s+\w+)?;|(\w+\s+)?"[\w.\-]+(/[\w.\-]+)+"$|[()]$)""")


def summarize_files(files: list[dict], ecosystem: str) -> dict[str, Any]:
    cats: dict[str, list[str]] = defaultdict(list)
    src_lines = 0
    src_dirs: set[str] = set()
    for f in files:
        name = f["filename"]
        cat = classify(name, ecosystem)
        cats[cat].append(name)
        if cat == "source":
            src_lines += int(f.get("additions", 0)) + int(f.get("deletions", 0))
            src_dirs.add(str(PurePosixPath(name).parent))
    return {
        "counts": {k: len(v) for k, v in cats.items()},
        "source_files": cats.get("source", []),
        "test_files": cats.get("test", []),
        "source_lines": src_lines,
        "source_dirs": sorted(src_dirs),
    }


def evaluate_diff(files: list[dict], ecosystem: str, min_lines: int, max_lines: int) -> Decision:
    if len(files) >= MAX_FILES_IN_COMMIT_API:
        return Decision(False, ["diff too large (>= 300 files)"])
    if not files:
        return Decision(False, ["empty diff"])
    s = summarize_files(files, ecosystem)
    counts: Counter = Counter(s["counts"])
    reasons = []
    # Whole-diff size (tests, fixtures, generated files included): the oracle patch must stay reviewable and fit the
    # generation prompt (stage 3 rejects patches over ~80k characters). e.g. a 40-line source fix with a 450k-char diff.
    total_changes = sum(int(f.get("changes", 0) or (int(f.get("additions", 0)) + int(f.get("deletions", 0)))) for f in files)
    s["total_changed_lines"] = total_changes
    if total_changes > MAX_TOTAL_CHANGED_LINES:
        reasons.append(f"whole fix diff too large ({total_changes} changed lines incl. tests/fixtures > {MAX_TOTAL_CHANGED_LINES})")
    if not s["source_files"]:
        non_code = set(counts) <= {"manifest", "docs", "config", "generated", "test"}
        only = set(counts) - {"test"}
        if only and only <= {"manifest"}:
            reasons.append("dependency/manifest-only change")
        elif only and only <= {"docs"}:
            reasons.append("documentation-only change")
        elif non_code:
            reasons.append("non-code change (config/CI/docs/manifest/generated/tests only)")
        else:
            reasons.append(f"no source file in a supported language for {ecosystem}")
    else:
        # A code generator's fix that mostly edits the TEMPLATES of generated code (e.g. EJS producing Java) cannot be
        # exercised through a real entry point offline - only implementation-bound text checks would be possible.
        tmpl = sum(int(f.get("additions", 0)) + int(f.get("deletions", 0)) for f in files
                   if TEMPLATE_RE.search(f["filename"]))
        s["template_lines"] = tmpl
        if tmpl > s["source_lines"]:
            reasons.append(f"fix lives mostly in code-generation templates ({tmpl} template lines > "
                           f"{s['source_lines']} source lines)")
        # A dependency swap (fork / bumped library + import-path rewrites) has no project logic to repair; the real fix
        # lives in an external module the agent cannot see (nuclei GHSA-vxg7: forked goja, rubric-rejected).
        if s["counts"].get("manifest"):
            changed = [l for f in files if classify(f["filename"], ecosystem) == "source"
                       for l in (f.get("patch") or "").splitlines()
                       if l[:1] in "+-" and not l.startswith(("+++", "---")) and l[1:].strip()]
            imports = [l for l in changed if IMPORT_LINE_RE.match(l[1:].strip())]
            if changed and len(imports) >= 0.8 * len(changed):
                reasons.append(f"dependency swap: {len(imports)}/{len(changed)} changed source lines are imports "
                               "(the fix is in an external module)")
        if s["source_lines"] < min_lines:
            reasons.append(f"trivial fix ({s['source_lines']} source lines < {min_lines})")
        if s["source_lines"] > max_lines:
            reasons.append(f"fix too large ({s['source_lines']} source lines > {max_lines})")
    return Decision(not reasons, reasons, s)


def evaluate_tree(tree: dict, ecosystem: str) -> Decision:
    paths = [e["path"] for e in tree.get("tree", []) if e.get("type") == "blob"]
    root_files = {p for p in paths if "/" not in p}
    reasons, info = [], {"truncated": bool(tree.get("truncated"))}
    manifests = sorted(m for m in root_files if m.lower() in ROOT_MANIFESTS[ecosystem]
                       or (ecosystem == "PyPI" and re.match(r"requirements.*\.txt$", m)))
    info["root_manifests"] = manifests
    if not manifests:
        reasons.append(f"no root build manifest for {ecosystem} (monorepo or unusual layout)")
    n_tests = sum(1 for p in paths if TEST_FILE_RE[ecosystem].search(p))
    info["test_files_in_repo"] = n_tests
    if n_tests == 0 and not info["truncated"]:
        reasons.append("no test files found in repo")
    info["has_dockerfile"] = any(p.lower() == "dockerfile" for p in root_files)
    return Decision(not reasons, reasons, info)


# --------------------------------------------------------------------------- #
# Lessons from 41 evaluated tasks (2026-10-20): candidate shapes that never produced a usable task. Applied to every
# newly screened candidate and, with --prune, to the existing lake (screened.json). Evidence in skills/lessons_learned.md
# and data/knowledge/solved_profile.md.
# --------------------------------------------------------------------------- #
REQUIRE_CWE = __import__("os").environ.get("REQUIRE_CWE", "1") != "0"   # CWE-bench: a candidate must carry a CWE
SMALL_FIX_FILES, SMALL_FIX_LINES = 4, 60   # <=4 src files AND <=60 src lines: 0 usable of 14; no <=5-file fix broke both
DOS_ONLY_CWES = {"400", "407", "409", "674", "770", "1284", "1333"}   # resource-exhaustion only: 0 usable (family: 0 of 7)
DEAD_MONOREPO_RE = re.compile(   # never built or never validated here (payload: 5 failures)
    r"github\.com/(payloadcms/payload|pydantic/pydantic-ai|vllm-project/vllm|flowiseai/flowise|[^/]+/reactpress|"
    r"mermaid-js/mermaid|vitest-dev/vitest)/?$", re.I)
# A producer (schema / serializer / loader / parser / config resolver) changed together with the check it feeds: the
# measured second-strongest sibling kind (29% missed). Matched on the changed source files' names.
PRODUCER_FILE_RE = re.compile(r"(schema|serializ|marshal|loader|(^|[/_.-])load|pars(e|er)|decod|codec|config|resolv|"
                              r"normaliz|transform|convert|import|deserializ)", re.I)

# --------------------------------------------------------------------------- #
# CWE weakness-class scope + No-AI difficulty weight (the "CWE-bench category").
# Source: others/cwe-bench/sourcer/weights.json `weakness_class` map (research-grounded prior: all models are weakest on
# auth/session, access-control, integrity and insecure-design; strongest on single-sink injection, open redirect and
# path traversal). We do NOT hard-reject the easy classes - we down-weight them so they rank last and get less priority
# next cycle (user rule 2026-10-21). DoS-only CWEs are still rejected in lesson_rejects (0 usable measured).
# --------------------------------------------------------------------------- #
CWE_CLASS = {   # CWE number (no "CWE-") -> weakness class
    "863": "access_control", "862": "access_control", "285": "access_control", "639": "access_control",
    "732": "access_control", "1259": "access_control", "441": "access_control", "552": "access_control",
    "284": "access_control", "266": "access_control", "267": "access_control", "268": "access_control",
    "269": "access_control", "276": "access_control", "749": "access_control", "1220": "access_control",
    "287": "auth_session", "306": "auth_session", "384": "auth_session", "613": "auth_session",
    "620": "auth_session", "640": "auth_session", "798": "auth_session", "319": "auth_session",
    "290": "auth_session", "291": "auth_session", "293": "auth_session", "302": "auth_session",
    "303": "auth_session", "304": "auth_session", "305": "auth_session", "307": "auth_session",
    "288": "auth_session", "294": "auth_session", "521": "auth_session", "522": "auth_session",
    "523": "auth_session", "549": "auth_session", "592": "auth_session", "1390": "auth_session",
    "345": "integrity", "347": "integrity", "353": "integrity", "354": "integrity", "494": "integrity",
    "565": "integrity", "829": "integrity", "924": "integrity", "346": "integrity", "350": "integrity",
    "349": "integrity", "357": "integrity", "471": "integrity", "913": "integrity",
    "840": "insecure_design", "693": "insecure_design", "807": "insecure_design", "664": "insecure_design",
    "670": "insecure_design", "691": "insecure_design", "1188": "insecure_design", "453": "insecure_design",
    "295": "crypto", "326": "crypto", "327": "crypto", "330": "crypto", "916": "crypto", "331": "crypto",
    "335": "crypto", "338": "crypto", "340": "crypto", "323": "crypto", "760": "crypto",
    "918": "ssrf", "1385": "ssrf",
    "502": "deserialization", "915": "deserialization", "470": "deserialization",
    # parser differentials / interpretation conflicts: request smuggling and friends are strong, hidden-path material
    "444": "logic", "436": "logic", "115": "logic", "138": "logic", "150": "logic", "179": "logic",
    "180": "logic", "182": "logic", "41": "logic", "172": "logic", "173": "logic", "176": "logic",
    "362": "logic", "367": "logic", "841": "logic", "662": "logic", "833": "logic", "248": "logic",
    "208": "logic", "385": "logic",
    "200": "info_exposure", "201": "info_exposure", "209": "info_exposure", "215": "info_exposure",
    "359": "info_exposure", "497": "info_exposure", "532": "info_exposure", "538": "info_exposure",
    "540": "info_exposure", "548": "info_exposure", "668": "info_exposure", "212": "info_exposure",
    "352": "csrf", "1275": "csrf",
    "434": "file_upload", "616": "file_upload", "646": "file_upload",
    "79": "xss", "80": "xss", "116": "xss", "83": "xss", "87": "xss",
    "89": "injection_sql", "564": "injection_sql",
    "22": "path_traversal", "23": "path_traversal", "35": "path_traversal", "59": "path_traversal",
    "61": "path_traversal", "73": "path_traversal", "36": "path_traversal", "98": "path_traversal",
    "377": "path_traversal", "378": "path_traversal", "379": "path_traversal",
    "601": "open_redirect",
    "1321": "prototype_pollution", "1325": "prototype_pollution",
    "77": "injection_single_sink", "78": "injection_single_sink", "88": "injection_single_sink",
    "90": "injection_single_sink", "917": "injection_single_sink", "943": "injection_single_sink",
    "94": "injection_single_sink", "95": "injection_single_sink", "1336": "injection_single_sink",
    "74": "injection_single_sink", "93": "injection_single_sink", "113": "injection_single_sink",
    "20": "validation", "129": "validation", "190": "validation", "191": "validation",
    "1286": "validation", "184": "validation", "625": "validation",
}
# Score delta per class, scaled from weights.json's 0-10 map (×~1.4, favoured classes up, easy classes pushed negative so
# they sink below in-scope candidates without being dropped).
# info_exposure is rated high on measured evidence, not the prior: the accepted apprise task is CWE-200 + CWE-601, and it
# broke BOTH models. csrf/file_upload sit with the auth/design family; "validation" (CWE-20/74 and friends) is a vague
# label that says nothing about depth, so it stays neutral.
CLASS_WEIGHT = {
    "auth_session": 14, "access_control": 12, "integrity": 12, "insecure_design": 12, "deserialization": 11,
    "info_exposure": 11, "crypto": 9, "ssrf": 9, "logic": 9, "csrf": 9, "file_upload": 8,
    "xss": 6, "injection_sql": 6, "validation": 4,
    "path_traversal": 2, "open_redirect": -2, "injection_single_sink": -2, "prototype_pollution": -4,
    "other": 4,
}


def cwe_class(rec: Optional[dict]) -> str:
    """Best (hardest) weakness class among the candidate's CWEs; 'other' if none are mapped."""
    cwes = {c.upper().removeprefix("CWE-") for c in (rec or {}).get("cwe_ids") or []}
    classes = [CWE_CLASS[c] for c in cwes if c in CWE_CLASS]
    return max(classes, key=lambda cl: CLASS_WEIGHT.get(cl, 0)) if classes else "other"


def lesson_rejects(rec: dict, diff: Optional[dict] = None) -> list[str]:
    """Static dead-end rules (no pipeline state needed). A fix-bypass PAIR (original fix + its bypass fix, mined by
    stage 1) is exempt from the small-fix rule: its combined change is the task, and the bypass place is one human
    fixers already missed."""
    from src.stage3_task_builder.task_generator import OFFENSIVE_REPO_RE
    out = []
    cwes = {c.upper().removeprefix("CWE-") for c in rec.get("cwe_ids") or []}
    # This is CWE-bench: a task is delivered against a CWE (task.toml cwe_ids, keywords, the weakness-class ranking and
    # every report). A candidate with no confirmed CWE cannot be classified or reported, so it is out of scope.
    # scripts/backfill_cwe.py recovers the label from the GHSA/CVE alias first (OSV's Go and PyPI records rarely carry
    # one); only candidates GHSA cannot classify either are dropped here. REQUIRE_CWE=0 disables the gate.
    if not cwes and REQUIRE_CWE:
        out.append("no confirmed CWE (CWE-bench needs one; not in OSV and not recoverable from the GHSA/CVE alias)")
    if cwes and cwes <= DOS_ONLY_CWES:
        out.append(f"resource-exhaustion-only CWE ({', '.join(sorted(cwes))}): 0 usable tasks measured")
    if DEAD_MONOREPO_RE.search(rec.get("repo_url") or ""):
        out.append("monorepo that never built or validated here")
    if OFFENSIVE_REPO_RE.search(rec.get("repo_url") or ""):
        out.append("offensive-security tool repository (generation is safeguards-flagged; flagged candidates are retired)")
    if diff and not rec.get("fix_pair"):
        files, lines = (diff.get("counts") or {}).get("source", len(diff.get("source_files") or [])), diff.get("source_lines", 0)
        if files <= SMALL_FIX_FILES and lines <= SMALL_FIX_LINES:
            out.append(f"small one-place fix ({files} src files / {lines} src lines; <= {SMALL_FIX_FILES} files and "
                       f"<= {SMALL_FIX_LINES} lines gave 0 usable tasks of 14)")
    return out


def score(diff: dict[str, Any], tree: dict[str, Any], rec: Optional[dict] = None, fix_date: str = "") -> int:
    """Higher = better candidate for a hard, fair task. Calibrated on the measured results (skills/lessons_learned.md):
    every fix of <= 5 source files was solved by DeepSeek, the only task both models failed spans 8 files / 174 lines /
    4 dirs, and none of the 8 fixes of <= 3 files and <= 35 lines gave a usable task. So: reward breadth (files, dirs =
    layers crossed) up to ~8 files, prefer 100-400 changed lines, and push tiny local fixes to the bottom."""
    files, lines = len(diff["source_files"]), diff["source_lines"]
    dirs = len(diff["source_dirs"]) if diff["source_dirs"] else 0
    sc = 8 * min(files, 8)
    sc += 6 * min(max(dirs - 1, 0), 4)
    sc += 10 if 100 <= lines <= 400 else (5 if 40 <= lines < 100 else 0)
    sc -= 25 if files <= 3 and lines <= 35 else 0
    sc += 3 if tree.get("test_files_in_repo", 0) >= 5 else 0
    # Parallel-implementation shape (measured 2026-10-19 over 37 evaluated tasks): raw width did NOT separate the 5
    # model-breaking tasks from the 31 solved ones (10-21-file fixes were solved on the first attempt), but every
    # breaker hid part of the root cause in a sibling place. The strongest static proxy: the fix changes a file of
    # the SAME NAME in two different directories (two providers/renderers/strategies re-implementing one control).
    by_name: dict[str, set] = {}
    generic = {"index", "init", "__init__", "main", "mod", "utils", "util", "helpers", "types", "config", "constants"}
    for p in diff["source_files"]:
        parts = p.rsplit("/", 1)
        stem = parts[-1].rsplit(".", 1)[0]
        if stem.lower() in generic:   # index.js / __init__.py etc. recur in every directory and prove nothing
            continue
        by_name.setdefault(parts[-1], set()).add(parts[0] if len(parts) == 2 else "")
    sc += 14 if any(len(ds) >= 2 for ds in by_name.values()) else 0
    # the upstream fix also changed tests: pinned behaviour next to the fix = compatibility-contract material (tech 11)
    sc += 4 if diff.get("test_files") else 0
    # Structural pre-screen (2026-10-20 mining strategy): shapes that put part of the root cause in a REAL place.
    srcs = diff.get("source_files") or []
    producers = [p for p in srcs if PRODUCER_FILE_RE.search(PurePosixPath(p).name)]
    if producers and len({str(PurePosixPath(p).parent) for p in srcs}) >= 2 and len(srcs) > len(producers):
        sc += 10          # a producer changed together with the check it feeds, in different places
    if rec:
        if len(rec.get("fix_commits") or []) > 1:
            sc += 8       # a multi-commit fix series: multi-place fixes often land as several commits
        if rec.get("fix_pair"):
            sc += 40      # fix-bypass pair: the bypass place is one the original human fixers demonstrably missed
    # No-AI weakness-class weight (the CWE-bench category): favoured classes up, easy single-sink/redirect/proto-pollution
    # down - so easy classes rank last and get less priority next cycle, without being rejected. See CLASS_WEIGHT.
    sc += CLASS_WEIGHT.get(cwe_class(rec), 4)
    # Memorization penalty (weights.json): a fix close to the recency cutoff is less likely memorised. All candidates
    # already pass PUBLISHED_AFTER, so this only separates within the kept pool - a small bonus for the most recent fixes.
    if fix_date and fix_date >= "2026-09-01":
        sc += 4
    return sc


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def screen_one(rec: dict, gh: GitHubClient, min_lines: int, max_lines: int, published_after: str = "",
               prior: Callable[[dict], int] = lambda r: 0, max_repo_mb: int = 0) -> Decision:
    owner_repo = rec["repo_url"].removeprefix("https://github.com/")
    eco = rec["ecosystem"]
    early = lesson_rejects(rec)          # the rules that need no diff: decided before any GitHub call
    if early:
        return Decision(False, early)
    if len(rec.get("fix_commits") or []) > 1:
        # A consecutive fix series: judge the combined change (pre-patch..last fix) and the EARLIEST commit's date.
        commit = gh.get_json(f"/repos/{owner_repo}/compare/{rec['pre_patch_commit']}...{rec['fixed_commit']}",
                             f"compare_{rec['pre_patch_commit'][:12]}_{rec['fixed_commit'][:12]}")
        cms = commit.get("commits", [])
        if rec.get("fix_pair"):
            # A fix-bypass pair: the hidden place is the BYPASS fix, so the recency cutoff applies to it. The original
            # fix may be older; it is the reported route the agent is shown anyway.
            cms = [cm for cm in cms if (cm.get("sha") or "").lower() == rec["fixed_commit"].lower()] or cms[-1:]
        dates = [d for cm in cms for x in ("author", "committer")
                 for d in [((cm.get("commit") or {}).get(x) or {}).get("date")] if d]
    else:
        commit = gh.get_json(f"/repos/{owner_repo}/commits/{rec['fixed_commit']}", f"commit_{rec['fixed_commit']}")
        c = commit.get("commit") or {}   # earlier of author/committer date: a cherry-picked backport keeps its age
        dates = [d for d in ((c.get("author") or {}).get("date"), (c.get("committer") or {}).get("date")) if d]
    commit_date = min(dates or [""])[:10]
    if published_after and commit_date and commit_date < published_after:
        return Decision(False, [f"fix committed {commit_date}, before {published_after} (could be in the models' training data)"])
    d = evaluate_diff(commit.get("files", []), eco, min_lines, max_lines)
    if not d.accepted:
        return d
    dead = lesson_rejects(rec, d.info)
    if dead:
        return Decision(False, dead, {"diff": d.info})
    repo_info = gh.get_json(f"/repos/{owner_repo}", f"repo_{owner_repo.replace('/', '__')}")
    size_mb = int(repo_info.get("size", 0)) / 1024          # GitHub reports KB (repo incl. history)
    if max_repo_mb and size_mb > max_repo_mb:
        return Decision(False, [f"repo too large for local runs ({size_mb:.0f} MB > {max_repo_mb} MB)"], {"diff": d.info})
    tree = gh.get_json(f"/repos/{owner_repo}/git/trees/{rec['pre_patch_commit']}?recursive=1",
                       f"tree_{rec['pre_patch_commit']}")
    t = evaluate_tree(tree, eco)
    if not t.accepted:
        return Decision(False, t.reasons, {"diff": d.info, "repo": t.info})
    bonus = prior(rec)
    return Decision(True, [], {"diff": d.info, "repo": t.info,
                               "score": score(d.info, t.info, rec, fix_date=commit_date) + bonus,
                               "prior": bonus, "fix_commit_date": commit_date, "weakness_class": cwe_class(rec)})


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise RuntimeError(f"{path} is unreadable; refusing to overwrite: {e}") from e


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
    tmp.replace(path)


def apply_repo_cap(records: list[dict], cap: int) -> tuple[list[dict], dict[str, list[str]]]:
    kept, dropped, per_repo = [], {}, Counter()
    for rec in sorted(records, key=lambda r: -r["screening"].get("score", 0)):
        repo = rec["repo_url"].lower()
        if per_repo[repo] >= cap:
            dropped[rec["osv_id"]] = [f"repo cap reached ({cap} per repository)"]
            continue
        per_repo[repo] += 1
        kept.append(rec)
    return kept, dropped


def screen(cfg: Config, args: argparse.Namespace, state: Optional[StateManager]) -> int:
    candidates = load_json(args.input, {}).get("vulnerabilities", [])
    if not candidates:
        log.error("No candidates in %s; run stage 1 first", args.input)
        return 2
    gh = GitHubClient(cfg.github_token, args.github_rps, cfg.cache_dir / "gh")

    todo = [r for r in candidates if not state or state.should_process(STAGE, r["osv_id"], MAX_ATTEMPTS)]
    log.info("Screening", extra={"candidates": len(candidates), "to_screen": len(todo)})

    cutoff = args.published_after or cfg.published_after
    priors = knowledge.load_priors(cfg)
    if cutoff:
        log.info("Recency filter active", extra={"fix_committed_after": cutoff})

    def work(rec: dict) -> tuple[dict, Optional[Decision], Optional[str], bool]:
        if cutoff and (rec.get("published") or "9999")[:10] < cutoff:   # advisory older than cutoff => fix older too
            return rec, Decision(False, [f"advisory published {(rec.get('published') or '?')[:10]}, before {cutoff} "
                                         "(models may remember older CVEs)"]), None, False
        try:
            return rec, screen_one(rec, gh, args.min_lines, args.max_lines, cutoff, lambda r: knowledge.prior_bonus(priors, r),
                                   args.max_repo_mb), None, False
        except PermanentError as e:
            return rec, None, str(e), True
        except TransientError as e:
            return rec, None, str(e), False
        except Exception as e:  # never let one record kill the batch
            log.exception("screen error", extra={"osv_id": rec["osv_id"]})
            return rec, None, f"unexpected: {e!r}", False

    accepted, rejected = [], {}
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for rec, dec, err, permanent in pool.map(work, todo):
            oid = rec["osv_id"]
            if err:
                rejected_reason = [f"github: {err}"]
                if permanent:
                    rejected[oid] = rejected_reason
                    state and state.mark(STAGE, oid, Status.REJECTED, err)
                else:
                    state and state.mark(STAGE, oid, Status.FAILED, err)
                    log.warning("Transient failure; will retry next run", extra={"osv_id": oid, "error": err})
            elif dec.accepted:
                accepted.append({**rec, "screening": dec.info})
            else:
                rejected[oid] = dec.reasons
                state and state.mark(STAGE, oid, Status.REJECTED, "; ".join(dec.reasons))

    prior = load_json(args.output, {}).get("vulnerabilities", [])
    by_id = {r["osv_id"]: r for r in prior if r["osv_id"] not in rejected}   # a re-screen can revoke earlier passes
    by_id.update({r["osv_id"]: r for r in accepted})
    kept, dropped = apply_repo_cap(list(by_id.values()), args.max_per_repo)

    rejected_all = load_json(args.rejected, {})
    rejected_all.update(rejected)
    rejected_all.update(dropped)
    for oid in dropped:
        state and state.mark(STAGE, oid, Status.REJECTED, dropped[oid][0])
    for r in kept:
        state and state.mark(STAGE, r["osv_id"], Status.DONE, payload={"score": r["screening"].get("score")})

    write_json(args.output, {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                             "count": len(kept), "vulnerabilities": kept})
    write_json(args.rejected, rejected_all)
    reasons = Counter(x.split(" (")[0] for rs in rejected.values() for x in rs)
    log.info("Screening finished", extra={"accepted_total": len(kept), "newly_rejected": len(rejected),
                                          "top_reasons": dict(reasons.most_common(5))})
    return 0 if kept else 1


def history_rejects(cfg: Config, state: StateManager, by_id: dict[str, dict]) -> dict[str, str]:
    """repo_url -> reason, for repos the pipeline's own history ruled out (needs state; not a screening-time rule)."""
    from src.stage3_task_builder.task_generator import flagged_repos
    out = {repo: "repo has a safeguards-flagged candidate (flagged candidates are retired)"
           for repo in flagged_repos(cfg.stage_dir(3), by_id)}
    for k in state.keys("stage3_task_builder", Status.REJECTED):
        det = (state.get("stage3_task_builder", k).detail or "").lower()
        if k in by_id and ("docker build" in det or "build timed out" in det or "unbuildable" in det):
            out.setdefault(by_id[k]["repo_url"].lower().rstrip("/"), f"repo proven unbuildable here ({k})")
    return out


def prune_lake(cfg: Config, args: argparse.Namespace, state: StateManager, dry_run: bool = False) -> dict[str, list[str]]:
    """Re-apply the lessons to the existing lake: move dead-end candidates from screened.json to rejected.json (with the
    reason) and re-score the rest. Candidates the pipeline already used (stage 3+) are never touched."""
    lake = load_json(args.output, {}).get("vulnerabilities", [])
    by_id = {r["osv_id"]: r for r in lake}
    used = set().union(*(state.keys(s) for s in ("stage3_task_builder", "stage4_oracle_validator", "stage5_evaluator")))
    repos = history_rejects(cfg, state, by_id)
    removed: dict[str, list[str]] = {}
    kept = []
    for r in lake:
        diff = (r.get("screening") or {}).get("diff") or {}
        why = [] if r["osv_id"] in used else lesson_rejects(r, diff)
        repo_why = repos.get(r["repo_url"].lower().rstrip("/"))
        if repo_why and r["osv_id"] not in used:
            why.append(repo_why)
        if why:
            removed[r["osv_id"]] = why
            continue
        scr = r.get("screening") or {}
        if diff.get("source_files") is not None:
            scr["score"] = score(diff, scr.get("repo") or {}, r, fix_date=scr.get("fix_commit_date", "")) \
                + int(scr.get("prior", 0) or 0)
            scr["weakness_class"] = cwe_class(r)
        kept.append(r)
    if dry_run:
        return removed
    rejected_all = load_json(args.rejected, {})
    for oid, why in removed.items():
        rejected_all[oid] = ["pruned 2026-10-20: " + w for w in why]
        state.mark(STAGE, oid, Status.REJECTED, "pruned: " + "; ".join(why)[:300])
    write_json(args.output, {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                             "count": len(kept), "vulnerabilities": kept})
    write_json(args.rejected, rejected_all)
    reasons = Counter(w.split(" (")[0] for ws in removed.values() for w in ws)
    log.info("Lake pruned", extra={"before": len(lake), "removed": len(removed), "kept": len(kept),
                                   "used_untouched": len(used & set(by_id)), "reasons": dict(reasons)})
    return removed


def parse_args(argv: Optional[list[str]], cfg: Config) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Stage 2: screen mined candidates")
    p.add_argument("--input", type=Path, default=cfg.data_dir / "01_mined" / "osv_candidates.json")
    p.add_argument("--output", type=Path, default=cfg.data_dir / "02_screened" / "screened.json")
    p.add_argument("--rejected", type=Path, default=cfg.data_dir / "02_screened" / "rejected.json")
    p.add_argument("--min-lines", type=int, default=4)
    p.add_argument("--max-lines", type=int, default=int(__import__("os").environ.get("SCREEN_MAX_SOURCE_LINES", "1200")))
    p.add_argument("--max-per-repo", type=int, default=int(__import__("os").environ.get("SCREEN_MAX_PER_REPO", "5")))
    p.add_argument("--max-repo-mb", type=int, default=int(__import__("os").environ.get("MAX_REPO_MB", "150")),
                   help="reject repositories larger than this (GitHub size incl. history); 0 = no limit (default 150)")
    p.add_argument("--published-after", metavar="YYYY-MM-DD",
                   help="reject advisories published before this date (older CVEs may be memorised by the target models)")
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--github-rps", type=float, default=None)
    p.add_argument("--ignore-state", action="store_true")
    p.add_argument("--prune", action="store_true",
                   help="re-apply the dead-end lessons to the existing lake (screened.json -> rejected.json); no GitHub calls")
    p.add_argument("--dry-run", action="store_true", help="with --prune: report what would be removed, change nothing")
    args = p.parse_args(argv)
    if args.github_rps is None:
        args.github_rps = 3.0 if cfg.github_token else 0.5
    return args


def main(argv: Optional[list[str]] = None, cfg: Optional[Config] = None) -> int:
    cfg = cfg or Config.load()
    args = parse_args(argv, cfg)
    if not logging.getLogger().handlers:
        configure_logging()
    if not cfg.github_token:
        log.warning("No GITHUB_TOKEN: 60 GitHub calls/hour; screening will stall on large inputs")
    state = None if args.ignore_state else StateManager(cfg.state_db)
    if args.prune:
        if state is None:
            log.error("--prune needs the pipeline state (to leave used candidates untouched)")
            return 2
        try:
            removed = prune_lake(cfg, args, state, dry_run=args.dry_run)
            print(f"{'would remove' if args.dry_run else 'removed'} {len(removed)} candidates")
            return 0
        finally:
            state.close()
    try:
        return screen(cfg, args, state)
    except KeyboardInterrupt:
        log.error("Interrupted")
        return 130
    except RuntimeError as e:
        log.error("%s", e)
        return 1
    finally:
        if state:
            state.close()


if __name__ == "__main__":
    sys.exit(main())
