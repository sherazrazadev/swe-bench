"""Shared git helpers (subprocess based, non-interactive, with timeouts and retries)."""
from __future__ import annotations

import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Callable, Optional, TypeVar

log = logging.getLogger(__name__)
T = TypeVar("T")

# Never prompt for credentials: deleted/private GitHub repos otherwise hang on a username prompt.
GIT_ENV = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "echo",
           "GCM_INTERACTIVE": "never", "GIT_LFS_SKIP_SMUDGE": "1"}

_PERMANENT_MARKERS = ("not found", "repository not found", "could not read username",
                      "does not exist", "access denied", "dmca", "disabled")


class GitError(Exception):
    """A git command failed, timed out, or its input was invalid."""


def run_git(args: list[str], cwd: Optional[Path] = None, timeout: int = 900,
            capture: bool = True) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            ["git", *args], cwd=cwd, env=GIT_ENV, timeout=timeout, check=True,
            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or b"").decode(errors="replace").strip()
        raise GitError(f"git {args[0]} failed: {stderr[-500:] or e}") from e
    except subprocess.TimeoutExpired as e:
        raise GitError(f"git {args[0]} timed out after {timeout}s") from e
    except FileNotFoundError as e:
        raise SystemExit("git executable not found on PATH") from e


def with_retries(fn: Callable[[], T], attempts: int, what: str) -> T:
    """Retry transient failures with exponential backoff; permanent ones raise immediately."""
    for n in range(1, attempts + 1):
        try:
            return fn()
        except GitError as e:
            permanent = any(m in str(e).lower() for m in _PERMANENT_MARKERS)
            if permanent or n == attempts:
                raise
            delay = 2 ** n
            log.info("%s failed (attempt %d/%d), retrying in %ds: %s", what, n, attempts, delay, e)
            time.sleep(delay)
    raise AssertionError("unreachable")


def fetch_commits(repo: Path, url: str, shas: list[str], timeout: int) -> None:
    """Init `repo` and shallow-fetch just the given commits; falls back to a full fetch."""
    run_git(["init", "-q"], cwd=repo)
    run_git(["remote", "add", "origin", url], cwd=repo)
    try:
        for sha in shas:
            run_git(["fetch", "-q", "--depth", "1", "--no-tags", "origin", sha], cwd=repo, timeout=timeout)
    except GitError as e:
        msg = str(e).lower()
        if "not our ref" not in msg and "couldn't find remote ref" not in msg:
            raise
        log.info("Server refused fetch-by-SHA for %s; falling back to full fetch", url)
        run_git(["fetch", "-q", "--no-tags", "origin", "+refs/heads/*:refs/remotes/origin/*",
                 "+refs/tags/*:refs/tags/*"], cwd=repo, timeout=timeout * 2)
        for sha in shas:
            run_git(["cat-file", "-e", f"{sha}^{{commit}}"], cwd=repo)
