"""Injected "parallel path" tasks (see docs/INJECTED_TASKS.md).

Every task that broke a model had one shape: a security control enforced in SEVERAL places (parallel implementations,
a second public API, a save/reload path), where the models fix the obvious place and miss the others. Mined advisories
with that shape are rare, so this module builds it on purpose in real repositories:

  1. clone a real repo we already screened (it builds here and has tests) at its recent default-branch HEAD;
  2. shortlist source files that hold security controls (escaping, containment, origin/credential checks, ...);
  3. ask the generation model to pick ONE control enforced in >= 2 places (>= 1 in another module) and return
     search/replace edits that REMOVE it everywhere - removal only, never new attack code;
  4. apply the edits, record the reverse diff as oracle_solution.patch (the project's own original code is the fix),
     and replace .git with a single snapshot commit of the injected state (the original is unreachable);
  5. register the candidate in data/02_screened/injected.json (source = "injected").

Stage 3 generation, stage 4 validation, stage 5 evaluation and stage 6 packaging then run unchanged.

    python -m src.stage3_task_builder.injector --repos 5            # pick 5 screened repos
    python -m src.stage3_task_builder.injector --repo-url https://github.com/o/r --ecosystem npm
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional

from src.common.config import Config
from src.common.classify import classify

log = logging.getLogger(__name__)

INJECTED_FILE = "injected.json"
CONTROL_RE = re.compile(
    r"escape|sanitiz|validat|allowlist|whitelist|denylist|blocklist|realpath|normpath|is_relative_to|startswith\(|"
    r"traversal|symlink|origin|issuer|audience|csrf|nonce|permission|authoriz|is_admin|has_perm|owner|tenant|"
    r"redirect|safe_url|trusted|max_?depth|max_?size|limit|quota|timing_safe|compare_digest|htmlspecialchars|"
    r"encodeURI|DOMPurify|filepath\.Clean|filepath\.Rel|strings\.HasPrefix", re.IGNORECASE)
EXT = {"PyPI": (".py",), "npm": (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"), "Go": (".go",),
       "Packagist": (".php",)}
MAX_FILES, MAX_FILE_CHARS, MAX_PROMPT_CHARS = 14, 9000, 110_000

SYSTEM = """You are a senior application-security engineer building a DEFENSIVE benchmark that measures whether AI coding
agents can repair security bugs completely. You are given real source files of an open-source project. Your job is to
choose one existing security control that the project enforces in SEVERAL places, and describe how to remove it in
every place, so a benchmark task can check whether an agent restores it everywhere. You only DELETE or bypass existing
checks with minimal search/replace edits on the given files; you never write exploit code. The removal is applied to a
throwaway copy in an offline container; the project's original code is the reference fix."""

PROMPT = """# Project
- Repository: {repo_url}
- Ecosystem: {ecosystem}

# Source files with security-relevant code (path, then content)
{files}

# Your job
Pick ONE security control (input escaping, path containment, origin/credential binding, authorization, size/depth
limit, ...) that this project enforces in AT LEAST TWO places reachable from different public entry points, with at
least one place in a different module/directory than the others (a parallel implementation, a lower-level API, or a
save/reload path). Then give minimal search/replace edits that remove or bypass that control in EVERY place, so the
project still builds and its normal features still work, but the protection is gone everywhere.

Rules:
- Edit only the files shown above; each "search" must appear EXACTLY ONCE in its file, copied verbatim (indentation
  included); "replace" is the new text. Keep the code natural: no comments mentioning the removal, no dead helpers.
- Removal or bypass only; never add attack code, payloads or new functionality.
- The control must protect a real entry point (public API, HTTP route, CLI) that untrusted input reaches.

Reply with ONLY this JSON:
{{"control": "<one sentence: the security property>",
  "cwe": "CWE-<id>",
  "vulnerability": "<one sentence: what becomes possible after the removal, user-visible>",
  "places": [{{"file": "<path>", "role": "<which entry point / implementation this is>"}}],
  "entry_points": ["<public entry point 1>", "<public entry point 2>"],
  "edits": [{{"file": "<path>", "search": "<exact existing text>", "replace": "<new text>"}}]}}"""


def git(args: list[str], cwd: Path, timeout: int = 900) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True, timeout=timeout).stdout


def shortlist(repo: Path, ecosystem: str) -> list[tuple[str, str]]:
    """Source files ranked by security-control keywords; files named in several places rank higher."""
    scored = []
    for p in repo.rglob("*"):
        if not p.is_file() or not p.name.endswith(EXT.get(ecosystem, ())):
            continue
        rel = p.relative_to(repo).as_posix()
        if classify(rel, ecosystem) != "source" or ".git/" in rel:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if len(text) > 120_000:
            continue
        hits = len(CONTROL_RE.findall(text))
        if hits:
            scored.append((hits, rel, text))
    scored.sort(key=lambda x: -x[0])
    out, size = [], 0
    for _, rel, text in scored[:MAX_FILES * 2]:
        chunk = text[:MAX_FILE_CHARS]
        if size + len(chunk) > MAX_PROMPT_CHARS:
            break
        out.append((rel, chunk))
        size += len(chunk)
        if len(out) >= MAX_FILES:
            break
    return out


def apply_edits(repo: Path, edits: list[dict]) -> list[str]:
    """Apply search/replace edits; every search must match exactly once. Returns the changed files."""
    changed = []
    for e in edits:
        f = repo / e["file"]
        text = f.read_text(encoding="utf-8")
        if text.count(e["search"]) != 1:
            raise ValueError(f"search text matches {text.count(e['search'])} times in {e['file']}")
        f.write_text(text.replace(e["search"], e["replace"], 1), encoding="utf-8")
        changed.append(e["file"])
    return sorted(set(changed))


def validate_proposal(prop: dict, shown: set[str]) -> list[str]:
    problems = []
    edits = prop.get("edits") or []
    files = {e.get("file") for e in edits}
    if len(prop.get("places") or []) < 2 or len(files) < 2:
        problems.append("the control must be removed in at least 2 places / files")
    if len({str(Path(f).parent) for f in files if f}) < 2:
        problems.append("at least one place must be in a different directory")
    if not files <= shown:
        problems.append(f"edits touch files that were not shown: {sorted(files - shown)}")
    if not re.match(r"CWE-\d+$", str(prop.get("cwe", ""))):
        problems.append("cwe must look like CWE-<id>")
    return problems


TARGET_OVERCORRECTION = """

# Extra requirement for this run (over-correction trap)
Prefer a control whose surrounding legitimate behaviour HUGS the attack boundary: inputs that look like the attack
(same characters, same feature, same code path) but are allowed, and that the project's OWN existing tests pin.
The removal must leave that legitimate behaviour untouched (those tests still pass), so the benchmark can catch a
repair that over-blocks. In "places", note for each place which existing test file pins the nearby legitimate
behaviour."""


def inject(cfg: Config, repo_url: str, ecosystem: str, package: str, backend, model: str,
           target: str = "sibling") -> Optional[str]:
    """Create one injected candidate. Returns its id, or None when no valid injection was produced."""
    slug = re.sub(r"[^a-z0-9]+", "-", repo_url.lower().split("github.com/")[-1]).strip("-")
    osv_id = f"INJ-{slug}-{time.strftime('%Y%m%d%H%M')}"
    env_dir = cfg.stage_dir(3) / osv_id
    repo = env_dir / "repo"
    env_dir.mkdir(parents=True, exist_ok=True)
    git(["clone", "--depth", "1", repo_url, str(repo)], cwd=env_dir, timeout=1800)
    head = git(["rev-parse", "HEAD"], cwd=repo).strip()
    files = shortlist(repo, ecosystem)
    if len(files) < 2:
        log.warning("Too few candidate files for an injection: %s", repo_url)
        shutil.rmtree(env_dir, ignore_errors=True)
        return None
    prompt = PROMPT.format(repo_url=repo_url, ecosystem=ecosystem,
                           files="\n\n".join(f"## {rel}\n```\n{text}\n```" for rel, text in files))
    if target == "overcorrection":
        prompt += TARGET_OVERCORRECTION
    from src.common.llm import SafeguardsFlagged, extract_json_object
    try:
        text, _ = backend.complete(model, SYSTEM, [{"role": "user", "content": prompt}], 16000)
        prop = extract_json_object(text)
    except SafeguardsFlagged:
        (env_dir / "safeguards_flagged.txt").write_text("injection proposal flagged; not retried\n")
        log.warning("Injection retired: safeguards flagged the session: %s", repo_url)
        return None
    except Exception as e:
        log.warning("Injection proposal failed: %s (%s)", repo_url, repr(e)[:200])
        shutil.rmtree(env_dir, ignore_errors=True)
        return None
    problems = validate_proposal(prop, {rel for rel, _ in files})
    if not problems:
        try:
            changed = apply_edits(repo, prop["edits"])
        except (ValueError, OSError, KeyError) as e:
            problems = [str(e)]
    if problems:
        log.warning("Injection proposal rejected: %s %s", repo_url, problems)
        (env_dir / "injection_rejected.json").write_text(json.dumps({"problems": problems, "proposal": prop}, indent=2))
        shutil.rmtree(repo, ignore_errors=True)
        return None
    # the reference fix restores the original code: reverse of the injection diff
    oracle = subprocess.run(["git", "diff", "-R", "--binary"], cwd=repo, capture_output=True, text=True).stdout
    (env_dir / "oracle_solution.patch").write_text(oracle)
    # single snapshot commit of the injected state: the original code is unreachable from inside the task
    shutil.rmtree(repo / ".git")
    for a in (["init", "-q"], ["add", "-A", "--force"],
              ["-c", "user.name=env-builder", "-c", "user.email=env-builder@localhost", "-c", "commit.gpgsign=false",
               "commit", "-q", "--allow-empty", "-m", "Snapshot"]):
        git(a, cwd=repo)
    snap = git(["rev-parse", "HEAD"], cwd=repo).strip()
    dirs = sorted({str(Path(f).parent) for f in changed})
    lines = sum(1 for l in oracle.splitlines() if l[:1] in "+-" and not l.startswith(("+++", "---")))
    record: dict[str, Any] = {
        "osv_id": osv_id, "cve_id": None, "ecosystem": ecosystem, "package": package, "repo_url": repo_url,
        "pre_patch_commit": snap, "fixed_commit": head, "summary": prop.get("vulnerability", ""),
        "description": prop.get("control", ""), "cwe_ids": [prop["cwe"]], "published": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "aliases": [], "severity": None, "source": "injected", "sources": ["injected"],
        "injection": {"control": prop.get("control"), "places": prop.get("places"),
                      "entry_points": prop.get("entry_points"), "upstream_head": head},
        "screening": {"diff": {"source_files": changed, "source_dirs": dirs, "source_lines": lines, "test_files": []},
                      "score": 0, "prior": 0},
    }
    (env_dir / "injection_meta.json").write_text(json.dumps(record, indent=2))
    reg = cfg.data_dir / "02_screened" / INJECTED_FILE
    data = json.loads(reg.read_text()) if reg.is_file() else {"vulnerabilities": []}
    data["vulnerabilities"] = [r for r in data["vulnerabilities"] if r["osv_id"] != osv_id] + [record]
    reg.write_text(json.dumps(data, indent=2))
    log.info("Injected candidate created", extra={"osv_id": osv_id, "files": changed, "cwe": prop.get("cwe")})
    return osv_id


def pick_repos(cfg: Config, n: int) -> list[dict]:
    """Screened repos that build here and have tests, widest-fix repos first, one candidate per repo."""
    recs = json.loads((cfg.data_dir / "02_screened" / "screened.json").read_text())["vulnerabilities"]
    by_id = {r["osv_id"]: r for r in recs}
    from src.common.state_manager import StateManager, Status
    bad = set()              # repos that cannot be built here or whose generation was safety-flagged
    used = set()             # repos that already produced a task: keep the injection pilot on fresh repos
    with StateManager(cfg.state_db) as state:
        for k in state.keys("stage3_task_builder", Status.REJECTED):
            det = (state.get("stage3_task_builder", k).detail or "").lower()
            if k in by_id and ("safeguards" in det or "docker build" in det or "build timed out" in det
                               or "unbuildable" in det):
                bad.add(by_id[k]["repo_url"].rstrip("/").lower())
        for k in state.keys("stage3_task_builder", Status.DONE):
            if k in by_id:
                used.add(by_id[k]["repo_url"].rstrip("/").lower())
    seen, out = set(bad) | used, []
    nf = lambda r: len(((r.get("screening") or {}).get("diff") or {}).get("source_files") or [])
    for r in sorted(recs, key=lambda r: -nf(r)):
        url = r["repo_url"].rstrip("/")
        if url.lower() in seen:
            continue
        seen.add(url.lower())
        out.append({"repo_url": url, "ecosystem": r["ecosystem"], "package": r.get("package") or ""})
        if len(out) >= n:
            break
    return out


def main(argv: Optional[list[str]] = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    p = argparse.ArgumentParser(description="Create injected 'parallel path' candidates")
    p.add_argument("--repos", type=int, default=0, help="pick N screened repos automatically")
    p.add_argument("--repo-url")
    p.add_argument("--ecosystem", choices=["PyPI", "npm", "Go", "Packagist"])
    p.add_argument("--package", default="")
    p.add_argument("--backend", choices=["claude", "deepseek"], default="claude",
                   help="deepseek = DeepSeek's Anthropic-compatible API (no Anthropic safeguards exposure)")
    p.add_argument("--target", choices=["sibling", "overcorrection"], default="sibling",
                   help="which measured model-failure shape to build: unnamed sibling path (default) or "
                        "over-correction trap (legit boundary behaviour pinned by existing repo tests)")
    args = p.parse_args(argv)
    if os.environ.get("INJECTOR_ENABLED") != "1":
        # Retired 2026-10-20 (user): 3 of 4 Claude injection sessions were safeguards-flagged, injected siblings were
        # measured too easy (5% miss rate; the filament injection was declared unsuitable by the trap gate), and the
        # benchmark wants real vulnerabilities in real code paths. INJECTOR_ENABLED=1 re-enables it.
        print("injector retired (2026-10-20); set INJECTOR_ENABLED=1 to run it anyway")
        return 1
    cfg = Config.load(None)
    from src.common.llm import CliBackend
    if args.backend == "deepseek":
        from types import SimpleNamespace
        from src.stage3_task_builder.task_generator import deepseek_client
        ds = deepseek_client(SimpleNamespace(claude_bin=cfg.claude_bin, timeout=1800.0))
        if ds is None:
            print("DEEPSEEK_API_KEY is not set")
            return 1
        backend, model = ds
    else:
        backend, model = CliBackend(cfg.claude_bin, 1800.0), cfg.anthropic_model
    targets = ([{"repo_url": args.repo_url, "ecosystem": args.ecosystem, "package": args.package}] if args.repo_url
               else pick_repos(cfg, args.repos))
    made = [i for t in targets if (i := inject(cfg, t["repo_url"], t["ecosystem"], t["package"] or t["repo_url"].split("/")[-1],
                                              backend, model, target=args.target))]
    print("injected:", " ".join(made) or "none")
    return 0


if __name__ == "__main__":
    sys.exit(main())
