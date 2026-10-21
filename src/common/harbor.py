"""Thin wrapper around the Harbor CLI (flags verified against harbor 0.24.0) and its result files.

Trial directory layout produced by `harbor run -o <jobs_dir> --job-name <name>`:
    <jobs_dir>/<name>/<trial>/{config.json, result.json, agent/, verifier/{reward.txt, ctrf.json, test-stdout.txt}}
"""
from __future__ import annotations

import json
import logging
import re
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Mapping, Optional

log = logging.getLogger(__name__)


SENSITIVE_ENV = {"CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
                 "GITHUB_TOKEN", "GH_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
                 "AWS_BEARER_TOKEN_BEDROCK", "OPENAI_API_KEY", "OPENAI_API_BASE", "OPENAI_BASE_URL"}


class HarborUnavailable(Exception):
    """Harbor or Docker is not usable; a stage cannot make progress."""


@dataclass(frozen=True)
class Trial:
    path: Path
    reward: Optional[float]            # None when the verifier produced no reward
    exception: Optional[str]           # "Type: message" if Harbor recorded an exception
    ctrf: Optional[dict[str, str]]     # hidden tests: test name -> "passed"/"failed"/... when ctrf.json exists
    ctrf_existing: Optional[dict[str, str]] = None  # the repo's existing tests (ctrf_existing.json)
    agent_secs: Optional[float] = None  # wall time of the agent phase
    timeout_budget: Optional[float] = None  # the agent time limit, when the run hit it

    @property
    def exception_type(self) -> Optional[str]:
        return self.exception.split(":", 1)[0] if self.exception else None

    @property
    def timed_out(self) -> bool:
        return self.exception_type == "AgentTimeoutError"

    @property
    def outcome(self) -> str:
        """pass / fail / error. `error` = no verdict (infra, build, harness) and must not count as a model fail."""
        if self.reward is None:
            return "error"
        return "pass" if self.reward >= 1.0 else "fail"


def preflight(harbor_bin: str, need_docker: bool = True) -> None:
    if not shutil.which(harbor_bin):
        raise HarborUnavailable(f"`{harbor_bin}` not found on PATH (pip install harbor / uv tool install harbor)")
    if need_docker:
        if not shutil.which("docker"):
            raise HarborUnavailable("docker not found on PATH")
        try:
            subprocess.run(["docker", "info"], check=True, capture_output=True, timeout=30)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            raise HarborUnavailable("docker daemon is not running / reachable") from e


DISK_PRUNE_BELOW_GB, DISK_STOP_BELOW_GB, BUILD_CACHE_MAX = 15, 8, "60gb"
_last_cache_prune = 0.0


def disk_guard() -> None:
    """Never let Docker run the host disk full (that corrupts its image store: I/O errors on every call). Cap the build
    cache every 10 minutes; below 15 GB free prune now; below 8 GB after pruning stop with HarborUnavailable."""
    global _last_cache_prune
    free_gb = lambda: shutil.disk_usage("/").free / 1e9
    if time.time() - _last_cache_prune > 600 or free_gb() < DISK_PRUNE_BELOW_GB:
        _last_cache_prune = time.time()
        subprocess.run(["docker", "builder", "prune", "-f", "--max-used-space", BUILD_CACHE_MAX],
                       capture_output=True, timeout=900)
        if free_gb() < DISK_PRUNE_BELOW_GB:
            subprocess.run(["docker", "image", "prune", "-f"], capture_output=True, timeout=600)
            subprocess.run(["docker", "builder", "prune", "-f"], capture_output=True, timeout=900)
    if free_gb() < DISK_STOP_BELOW_GB:
        raise HarborUnavailable(f"host disk nearly full ({free_gb():.1f} GB free): free space before continuing")
    # hard cap on Docker Desktop's own disk file (it never shrinks on its own): prune, then stop above the cap
    import os
    cap = float(os.environ.get("DOCKER_DISK_MAX_GB", "150"))
    raw = Path.home() / "Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw"
    used_gb = lambda: raw.stat().st_blocks * 512 / 1e9 if raw.exists() else 0.0
    if cap and used_gb() > cap:
        subprocess.run(["docker", "image", "prune", "-f"], capture_output=True, timeout=600)
        subprocess.run(["docker", "builder", "prune", "-a", "-f", "--max-used-space", BUILD_CACHE_MAX],
                       capture_output=True, timeout=900)
        if used_gb() > cap:
            raise HarborUnavailable(f"Docker disk at {used_gb():.0f} GB, over DOCKER_DISK_MAX_GB={cap:.0f}: "
                                    "remove unused images before continuing")


def run_harbor(harbor_bin: str, task_dir: Path, agent: str, jobs_dir: Path, job_name: str,
               attempts: int = 1, concurrent: int = 1, model: Optional[str] = None,
               agent_kwargs: Optional[Mapping[str, str]] = None, extra_env: Optional[Mapping[str, str]] = None,
               agent_env: Optional[Mapping[str, str]] = None,
               timeout: int = 7200, log_path: Optional[Path] = None,
               cancel: Optional[threading.Event] = None) -> Path:
    """Run `harbor run` on one task directory. Returns the job directory.
    Raises subprocess.TimeoutExpired / HarborUnavailable; a non-zero exit is logged, not raised, because
    Harbor reports per-trial problems in result files that the caller must inspect.
    `cancel`: when set (e.g. the other model already solved the task), Harbor is interrupted like Ctrl-C - running
    trials end as CancelledError (ungraded) - and any of the job's task containers left behind are removed."""
    import os
    import tempfile
    jobs_dir.mkdir(parents=True, exist_ok=True)
    cmd = [harbor_bin, "run", "-p", str(task_dir), "-a", agent, "-o", str(jobs_dir),
           "--job-name", job_name, "-k", str(attempts), "-n", str(concurrent), "-y", "-q"]
    if model:
        cmd += ["-m", model]
    for k, v in (agent_kwargs or {}).items():
        cmd += ["--ak", f"{k}={v}"]
    for k, v in (agent_env or {}).items():          # non-secret only; secrets go through `extra_env`
        cmd += ["--ae", f"{k}={v}"]
    # Credentials never leak into a task container by inheritance: Harbor's claude-code agent forwards e.g.
    # CLAUDE_CODE_OAUTH_TOKEN / ANTHROPIC_* from its own environment into the container, where the evaluated model could
    # read them. Only what this run passes explicitly in `extra_env` (its own endpoint's key) reaches Harbor.
    env = {k: v for k, v in os.environ.items() if k not in SENSITIVE_ENV and not k.endswith(("_API_KEY", "_AUTH_TOKEN"))}
    env.update(extra_env or {})
    disk_guard()
    log.info("harbor run", extra={"task": task_dir.name, "agent": agent, "job": job_name, "k": attempts})
    cancelled = False
    with tempfile.TemporaryFile("w+") as out, tempfile.TemporaryFile("w+") as err:
        try:
            proc = subprocess.Popen(cmd, env=env, stdout=out, stderr=err, text=True)
        except FileNotFoundError as e:
            raise HarborUnavailable(f"`{harbor_bin}` not found") from e
        deadline = time.monotonic() + timeout
        interrupted = False
        try:
            while proc.poll() is None:
                if cancel is not None and cancel.is_set():
                    cancelled = True
                    break
                if time.monotonic() > deadline:
                    raise subprocess.TimeoutExpired(cmd, timeout)
                time.sleep(5)
        finally:      # cancel, timeout, or an exception in this thread (e.g. Ctrl-C): never leave Harbor running
            if proc.poll() is None:
                interrupted = True
                _interrupt(proc)
            # Harbor leaves sidecars (the egress proxy, the separate verifier's) running even after a normal finish
            remove_job_containers(jobs_dir / job_name)
        out.seek(0)
        err.seek(0)
        stdout, stderr = out.read(), err.read()
    if log_path:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        # Keys are passed via env, never argv, so the command line is safe to log.
        log_path.write_text(f"$ {' '.join(cmd)}\nexit={proc.returncode}{' (cancelled)' if cancelled else ''}\n"
                            f"--- stdout\n{stdout}\n--- stderr\n{stderr}\n")
    if cancelled:
        log.info("harbor run cancelled", extra={"job": job_name})
    elif proc.returncode != 0:
        log.warning("harbor exited non-zero", extra={"rc": proc.returncode, "tail": stderr[-300:]})
    return jobs_dir / job_name


def _interrupt(proc: subprocess.Popen, grace: float = 120.0) -> None:
    """Ctrl-C first (Harbor cancels its trials and stops their containers), then terminate, then kill."""
    for sig, wait in ((signal.SIGINT, grace), (signal.SIGTERM, 30.0)):
        try:
            proc.send_signal(sig)
            proc.wait(timeout=wait)
            return
        except subprocess.TimeoutExpired:
            continue
        except ProcessLookupError:
            return
    proc.kill()
    proc.wait()


def remove_job_containers(job_dir: Path) -> None:
    """Remove the containers and networks Harbor leaves behind for the trials of a job: every compose project named
    after a trial (lower-cased trial name, plus `__env`, `__verifier__trial`, ...). Call only once the job has ended."""
    if not job_dir.is_dir():
        return
    prefixes = tuple(d.name.lower() for d in job_dir.iterdir() if d.is_dir())
    if not prefixes:
        return
    try:
        def owned(kind: str) -> list[str]:
            rows = subprocess.run(["docker", kind, "ls", "-a", "--format",
                                   '{{.ID}} {{.Label "com.docker.compose.project"}}'] if kind == "container" else
                                  ["docker", kind, "ls", "--format", '{{.ID}} {{.Label "com.docker.compose.project"}}'],
                                  capture_output=True, text=True, timeout=30).stdout.splitlines()
            return [r.split()[0] for r in rows if len(r.split()) == 2 and r.split()[1].startswith(prefixes)]
        ids = owned("container")
        if ids:
            subprocess.run(["docker", "rm", "-f", *ids], capture_output=True, timeout=120)
            log.info("Removed leftover task containers", extra={"job": job_dir.name, "n": len(ids)})
        nets = owned("network")
        if nets:      # Docker has a small fixed number of address pools: never leave networks behind
            subprocess.run(["docker", "network", "rm", *nets], capture_output=True, timeout=60)
        # per-trial image tags (<trial>__env-main, <trial>__verifier__trial-main): layers stay in the build cache, so a
        # rebuild is fast, but the tags would otherwise pin gigabytes per task
        rows = subprocess.run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"], capture_output=True, text=True,
                              timeout=60).stdout.splitlines()
        imgs = [r for r in rows if r.split(":")[0].startswith(prefixes)]
        if imgs:
            subprocess.run(["docker", "rmi", *imgs], capture_output=True, timeout=300)
    except (OSError, subprocess.TimeoutExpired):
        pass


def read_trial(trial_dir: Path) -> Trial:
    reward = None
    rp = trial_dir / "verifier" / "reward.txt"
    if rp.is_file():
        try:
            reward = float(rp.read_text().strip())
        except ValueError:
            reward = None
    result: dict = {}
    if (trial_dir / "result.json").is_file():
        try:
            result = json.loads((trial_dir / "result.json").read_text())
        except json.JSONDecodeError:
            result = {}
    if reward is None:  # reward.json / structured result fallback
        rewards = (result.get("verifier_result") or {}).get("rewards") or {}
        if "reward" in rewards:
            reward = float(rewards["reward"])
    exc = result.get("exception_info")
    exception = f"{exc.get('exception_type')}: {str(exc.get('exception_message'))[:300]}" if exc else None
    budget = None
    if exc and exc.get("exception_type") == "AgentTimeoutError":
        m = re.search(r"after ([\d.]+) seconds", str(exc.get("exception_message")))
        budget = float(m.group(1)) if m else None
    return Trial(trial_dir, reward, exception, read_ctrf(trial_dir / "verifier" / "ctrf.json"),
                 read_ctrf(trial_dir / "verifier" / "ctrf_existing.json"),
                 agent_secs=_phase_secs(result.get("agent_execution")), timeout_budget=budget)


def _phase_secs(phase: Optional[dict]) -> Optional[float]:
    try:
        return (datetime.fromisoformat(phase["finished_at"]) - datetime.fromisoformat(phase["started_at"])).total_seconds()
    except (TypeError, KeyError, ValueError):
        return None


def read_ctrf(path: Path) -> Optional[dict[str, str]]:
    if not path.is_file():
        return None
    try:
        tests = json.loads(path.read_text())["results"]["tests"]
        return {t["name"]: t["status"] for t in tests}
    except (json.JSONDecodeError, KeyError, TypeError):
        return None


def read_trials(job_dir: Path) -> list[Trial]:
    """One Trial per trial directory (a subdirectory holding result.json or verifier/)."""
    if not job_dir.is_dir():
        return []
    dirs = sorted(d for d in job_dir.iterdir()
                  if d.is_dir() and ((d / "result.json").is_file() or (d / "verifier").is_dir()))
    return [read_trial(d) for d in dirs]


def docker_disk_report() -> str:
    """`docker system df` summary (images + build cache are what fill a laptop disk during a 100-task run)."""
    try:
        return subprocess.run(["docker", "system", "df"], capture_output=True, text=True, timeout=60).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""
