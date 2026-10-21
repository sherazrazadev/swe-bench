#!/usr/bin/env python3
"""Stage 2 - Pre-Patch Isolator.

For every entry in the Stage 1 JSON, builds:

    <environments>/<OSV-ID>/
        repo/                    the repository checked out at the pre-patch commit
        oracle_solution.patch    `git diff pre..fixed` (the human fix)

Design notes
  * Idempotent: an entry is skipped if <OSV-ID>/oracle_solution.patch exists.
  * Atomic: work happens in a hidden staging dir and is renamed into place only
    on success, so a crash never leaves a half-built environment that looks done.
  * No answer-key leak: by default the repo's .git is rebuilt as a single
    "pre-patch snapshot" commit, so the fix commit is not reachable via
    `git show <sha>` / `git log --all`. The patch lives outside repo/.
    Use --keep-git-history to retain the real history (fix object included).
  * Only the two needed commits are fetched (shallow, by SHA) which is far
    faster than a full clone; falls back to a full clone if the server
    refuses fetch-by-SHA.

Usage
  python -m src.stage3_task_builder.environment_builder data/02_screened/screened.json --environments data/03_environments
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from src.common.classify import GENERATED_RE
from src.common.git_tools import GitError, fetch_commits, run_git as git, with_retries

log = logging.getLogger(__name__)

PATCH_NAME = "oracle_solution.patch"
REPO_DIRNAME = "repo"
OSV_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
GITHUB_URL_RE = re.compile(r"^https://github\.com/[\w.-]+/[\w.-]+?(?:\.git)?/?$")

IsolatorError = GitError  # per-entry failure (bad input, missing repo, empty diff, ...)


@dataclass(frozen=True)
class Entry:
    osv_id: str
    repo_url: str
    pre_patch: str
    fixed: str


# --------------------------------------------------------------------------- #
# Input
# --------------------------------------------------------------------------- #
def load_entries(path: Path) -> tuple[list[Entry], int]:
    """Accepts the Stage 1 payload ({"vulnerabilities": [...]}) or a bare list."""
    data = json.loads(path.read_text())
    items = data.get("vulnerabilities", []) if isinstance(data, dict) else data
    entries, invalid = [], 0
    seen: set[str] = set()
    for i, item in enumerate(items):
        try:
            e = Entry(
                osv_id=str(item["osv_id"]),
                repo_url=str(item["repo_url"]).strip(),
                pre_patch=str(item["pre_patch_commit"]).lower(),
                fixed=str(item["fixed_commit"]).lower(),
            )
            validate_entry(e)
        except (KeyError, TypeError, IsolatorError) as ex:
            log.warning("Skipping invalid input item #%d: %s", i, ex)
            invalid += 1
            continue
        if e.osv_id in seen:
            log.debug("Duplicate osv_id %s in input; ignoring later copy", e.osv_id)
            continue
        seen.add(e.osv_id)
        entries.append(e)
    return entries, invalid


def validate_entry(e: Entry) -> None:
    # osv_id becomes a directory name, so it must not allow path traversal.
    if not OSV_ID_RE.match(e.osv_id):
        raise IsolatorError(f"unsafe osv_id {e.osv_id!r}")
    if not GITHUB_URL_RE.match(e.repo_url):
        raise IsolatorError(f"{e.osv_id}: unsupported repo_url {e.repo_url!r}")
    for label, sha in (("pre_patch_commit", e.pre_patch), ("fixed_commit", e.fixed)):
        if not SHA_RE.match(sha):
            raise IsolatorError(f"{e.osv_id}: {label} is not a 40-char SHA: {sha!r}")
    if e.pre_patch == e.fixed:
        raise IsolatorError(f"{e.osv_id}: pre-patch and fixed commits are identical")


# --------------------------------------------------------------------------- #
# Git helpers
# --------------------------------------------------------------------------- #
def sanitize_history(repo: Path, pre_patch: str) -> None:
    """Replace .git with a single snapshot commit so the fix is unreachable."""
    shutil.rmtree(repo / ".git")
    git(["init", "-q"], cwd=repo)
    git(["add", "-A", "--force"], cwd=repo)
    git(["-c", "user.name=env-builder", "-c", "user.email=env-builder@localhost",
         "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty",
         "-m", "Snapshot"], cwd=repo)          # no commit id: nothing that points at the upstream history


# --------------------------------------------------------------------------- #
# Per-entry build
# --------------------------------------------------------------------------- #
def already_done(env_dir: Path) -> bool:
    patch = env_dir / PATCH_NAME
    return patch.is_file() and patch.stat().st_size > 0


def strip_generated(diff: bytes) -> bytes:
    """Drop per-file chunks for generated build artifacts (dist/, *.min.js, source maps, vendored bundles): the human fix
    is in the sources; maintainers' rebuilt bundles would bloat the oracle (e.g. a 450k-char minified line) and are
    never something an agent should hand-edit."""
    chunks = re.split(rb"(?m)^(?=diff --git )", diff)
    kept = []
    for chunk in chunks:
        m = re.match(rb"diff --git a/(.+?) b/(.+)", chunk)
        if m and GENERATED_RE.search(m.group(2).decode("utf-8", "replace")):
            continue
        kept.append(chunk)
    return b"".join(kept)


def build_environment(e: Entry, envs_root: Path, keep_history: bool,
                      timeout: int, retries: int) -> Path:
    env_dir = envs_root / e.osv_id
    staging = envs_root / f".{e.osv_id}.partial"
    for stale in (staging,):
        if stale.exists():
            shutil.rmtree(stale, ignore_errors=True)
    staging_repo = staging / REPO_DIRNAME
    staging_repo.mkdir(parents=True)

    try:
        with_retries(lambda: _fetch_clean(staging_repo, e, timeout), retries, f"fetch {e.osv_id}")

        # Oracle diff: exact change from vulnerable state to the human fix.
        diff = git(["diff", "--binary", "--full-index", "--no-color", "--no-ext-diff",
                    e.pre_patch, e.fixed], cwd=staging_repo, timeout=timeout).stdout
        diff = strip_generated(diff)
        if not diff.strip():
            raise IsolatorError("diff between pre-patch and fixed commit is empty (after removing build artifacts)")

        git(["checkout", "-q", "--force", e.pre_patch], cwd=staging_repo, timeout=timeout)
        (staging / PATCH_NAME).write_bytes(diff)

        if not keep_history:
            sanitize_history(staging_repo, e.pre_patch)

        # Promote atomically. A leftover incomplete env_dir (no patch) is replaced.
        if env_dir.exists():
            shutil.rmtree(env_dir)
        os.replace(staging, env_dir)
        return env_dir
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _fetch_clean(repo: Path, e: Entry, timeout: int) -> None:
    # Reset between retries so a half-initialised .git can't poison the next attempt.
    for child in repo.iterdir():
        shutil.rmtree(child, ignore_errors=True) if child.is_dir() else child.unlink()
    fetch_commits(repo, e.repo_url, [e.pre_patch, e.fixed], timeout)


def process(e: Entry, envs_root: Path, keep_history: bool, timeout: int, retries: int) -> tuple[str, str, str]:
    """Returns (osv_id, status, detail). Never raises for per-entry problems."""
    env_dir = envs_root / e.osv_id
    if already_done(env_dir):
        return e.osv_id, "skipped", "already built"
    try:
        build_environment(e, envs_root, keep_history, timeout, retries)
        return e.osv_id, "ok", str(env_dir)
    except IsolatorError as ex:
        log.warning("[%s] FAILED (%s): %s", e.osv_id, e.repo_url, ex)
        return e.osv_id, "failed", str(ex)
    except OSError as ex:
        log.warning("[%s] FILESYSTEM ERROR: %s", e.osv_id, ex)
        return e.osv_id, "failed", f"os error: {ex}"
    except Exception as ex:  # one bad entry must never kill the batch
        log.exception("[%s] unexpected error", e.osv_id)
        return e.osv_id, "failed", f"unexpected: {ex!r}"


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("input_json", type=Path, help="Stage 1 output (osv_candidates.json)")
    p.add_argument("--environments", type=Path, default=Path("environments"),
                   help="output root (default ./environments)")
    p.add_argument("--workers", type=int, default=4, help="parallel entries (default 4)")
    p.add_argument("--timeout", type=int, default=900, help="per git command timeout, seconds")
    p.add_argument("--retries", type=int, default=3, help="attempts for transient network errors")
    p.add_argument("--keep-git-history", action="store_true",
                   help="keep the real .git (WARNING: fix commit remains reachable to the agent)")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)
    if args.workers < 1:
        p.error("--workers must be >= 1")
    return args


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    try:
        entries, invalid = load_entries(args.input_json)
    except (OSError, json.JSONDecodeError) as ex:
        log.error("Cannot read %s: %s", args.input_json, ex)
        return 2

    args.environments.mkdir(parents=True, exist_ok=True)
    log.info("%d entries to process (%d invalid in input) -> %s",
             len(entries), invalid, args.environments.resolve())

    counts = {"ok": 0, "skipped": 0, "failed": 0}
    failures: list[tuple[str, str]] = []
    try:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = [pool.submit(process, e, args.environments, args.keep_git_history,
                                   args.timeout, args.retries) for e in entries]
            for n, fut in enumerate(as_completed(futures), 1):
                osv_id, status, detail = fut.result()
                counts[status] += 1
                if status == "failed":
                    failures.append((osv_id, detail))
                elif status == "ok":
                    log.info("[%d/%d] %s built", n, len(entries), osv_id)
    except KeyboardInterrupt:
        log.error("Interrupted; partial staging dirs (.*.partial) are cleaned on next run")
        return 130

    log.info("Done: %d built, %d skipped, %d failed", counts["ok"], counts["skipped"], counts["failed"])
    for osv_id, detail in failures:
        log.info("  failed: %s - %s", osv_id, detail[:200])
    return 0


if __name__ == "__main__":
    sys.exit(main())
