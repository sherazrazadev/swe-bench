#!/usr/bin/env python3
"""Hand stage 5 to GitHub Actions in batches while scripts/run_cycles.py --no-eval generates and validates locally.

One tick (safe to run any time; the 30-minute check-in runs it):
  1. every in-flight batch whose workflow run finished is collected: artifacts downloaded, verdicts recorded through
     --reverdict (never a hand-edit), accepted tasks packaged (scripts/ci_collect_trial_batch.sh);
  2. if fewer than CI_MAX_INFLIGHT batches are running and at least CI_BATCH_SIZE validated tasks wait for a trial,
     the oldest CI_BATCH_SIZE are pushed (scripts/ci_push_trial_batch.sh) and the workflow is triggered.
Batches are recorded in data/ci_batches.json.

    CI_REMOTE=swe-bench .venv/bin/python scripts/ci_tick.py            # tick
    CI_REMOTE=swe-bench .venv/bin/python scripts/ci_tick.py --status   # report only
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from src.common.config import Config  # noqa: E402
from src.common.state_manager import StateManager, Status  # noqa: E402

LEDGER = ROOT / "data" / "ci_batches.json"
REMOTE = os.environ.get("CI_REMOTE", "swe-bench")
BATCH = int(os.environ.get("CI_BATCH_SIZE", "6"))
MAX_INFLIGHT = int(os.environ.get("CI_MAX_INFLIGHT", "3"))     # 3 x 6 jobs stays under the 20-job concurrency cap
WORKFLOW = "stage5-trial.yml"


def sh(*args: str, check: bool = True) -> str:
    p = subprocess.run(list(args), cwd=ROOT, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(args[:3])}... failed: {(p.stderr or p.stdout).strip()[-600:]}")
    return p.stdout


def repo() -> str:
    return re.sub(r".*github\.com[:/]|\.git$", "", sh("git", "remote", "get-url", REMOTE).strip())


def load() -> list[dict]:
    return json.loads(LEDGER.read_text()) if LEDGER.is_file() else []


def save(batches: list[dict]) -> None:
    LEDGER.write_text(json.dumps(batches, indent=2))


def stock(cfg: Config, busy: set[str]) -> list[str]:
    """Validated tasks with no stage-5 record, oldest validation first, not in a batch, not flagged."""
    env = cfg.stage_dir(3)
    with StateManager(cfg.state_db) as s:
        recs = [(s.get("stage4_oracle_validator", k), k) for k in s.keys("stage4_oracle_validator", Status.DONE)
                if not s.get("stage5_evaluator", k)]
    ok = [(r.updated_at if r else "", k) for r, k in recs
          if k not in busy and (env / k / "harbor_task").is_dir() and not (env / k / "safeguards_flagged.txt").is_file()]
    return [k for _, k in sorted(ok)]


def collect(b: dict) -> None:
    out = sh("bash", "scripts/ci_collect_trial_batch.sh", str(b["run_id"]), *b["ids"], check=False)
    b["collect_log_tail"] = out.strip().splitlines()[-12:]


def tick(report_only: bool) -> None:
    cfg = Config.load()
    r = repo()
    batches = load()
    lines = []
    for b in batches:
        if b.get("state") != "running":
            continue
        info = json.loads(sh("gh", "run", "view", str(b["run_id"]), "--repo", r, "--json", "status,conclusion"))
        if info.get("status") != "completed":
            lines.append(f"running: run {b['run_id']} ({len(b['ids'])} tasks, pushed {b['pushed_at']})")
            continue
        b["conclusion"] = info.get("conclusion")
        if report_only:
            lines.append(f"finished, not collected yet: run {b['run_id']} ({b['conclusion']})")
            continue
        collect(b)
        b["state"], b["collected_at"] = "collected", time.strftime("%Y-%m-%d %H:%M")
        lines.append(f"collected run {b['run_id']} ({b['conclusion']}): {', '.join(b['ids'])}")
    save(batches)

    busy = {i for b in batches if b.get("state") == "running" for i in b["ids"]}
    waiting = stock(cfg, busy)
    inflight = sum(1 for b in batches if b.get("state") == "running")
    lines.append(f"validated tasks waiting for a trial: {len(waiting)} {waiting[:12]}; batches running: {inflight}")
    while not report_only and inflight < MAX_INFLIGHT and len(waiting) >= BATCH:
        ids, waiting = waiting[:BATCH], waiting[BATCH:]
        out = sh("bash", "scripts/ci_push_trial_batch.sh", *ids)
        branch = re.search(r"Pushed branch: (\S+)", out).group(1)
        sh("gh", "workflow", "run", WORKFLOW, "--repo", r, "--ref", branch,
           "-f", f"candidates={','.join(ids)}", "-f", f"max_parallel={len(ids)}")
        run_id = None
        for _ in range(20):
            time.sleep(3)
            runs = json.loads(sh("gh", "run", "list", "--repo", r, "--workflow", WORKFLOW, "--branch", branch,
                                 "--json", "databaseId", "--limit", "1"))
            if runs:
                run_id = runs[0]["databaseId"]
                break
        batches.append({"branch": branch, "run_id": run_id, "ids": ids, "state": "running" if run_id else "trigger_unknown",
                        "pushed_at": time.strftime("%Y-%m-%d %H:%M")})
        save(batches)
        inflight += 1
        lines.append(f"pushed batch {branch} -> run {run_id}: {', '.join(ids)}")
    print("\n".join(lines))


if __name__ == "__main__":
    tick("--status" in sys.argv)
