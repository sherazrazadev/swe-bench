#!/usr/bin/env python3
"""Unattended cycle queue: wait for the cycle already running, then run N more cycles back to back.

One cycle = generate -> validate -> evaluate -> package -> rewrite rounds -> results report, on
`--size` tasks. The knowledge loop is rebuilt after every cycle (C_RESULTS.md, model failure map,
technique scoreboard, solved profile; stage 5 also refreshes failure analyses and lessons), and the
next cycle's candidate ranking and generation prompt read it. So runs are sequential on purpose.

Stops safely on any of:
  * data/STOP_CYCLES (checked while waiting and between cycles)
  * host free disk below --min-free-gb
  * Docker not healthy after --docker-wait-min
  * --cycles reached
  * --max-empty-cycles cycles that produced no new cycle folder
  * --max-failed-cycles cycles that crashed without producing a folder

    source .venv/bin/activate && source scripts/use_deepseek_claude.sh
    python scripts/run_queue.py --cycles 3 --size 6
"""
from __future__ import annotations

import argparse
import os
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = str(ROOT / ".venv" / "bin" / "python")
STOP = ROOT / "data" / "STOP_CYCLES"
LOGS = ROOT / "data" / "logs" / "runs"


def now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class Log:
    def __init__(self, path: Path):
        self.path = path
        self.fh = path.open("a", buffering=1)

    def __call__(self, msg: str) -> None:
        line = f"{now()} {msg}"
        print(line, flush=True)
        self.fh.write(line + "\n")

    def close(self) -> None:
        self.fh.close()


def drivers() -> list[int]:
    try:
        out = subprocess.run(["pgrep", "-f", "scripts/run_cycles.py"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired):
        return []
    return [int(x) for x in out.split() if x.isdigit()]


def docker_ok() -> bool:
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def free_gb() -> float:
    return shutil.disk_usage(str(ROOT)).free / 1e9


def cycle_dirs() -> set[Path]:
    return set(LOGS.glob("*cycle*_*tasks"))


def wait_for_current(log: Log, wait_min: float) -> bool:
    """Wait until no run_cycles.py is alive. Returns False when the user asks to stop."""
    start = time.time()
    announced = 0.0
    while True:
        if STOP.exists():
            log("STOP_CYCLES found while waiting for the current cycle - exiting")
            return False
        pids = [p for p in drivers() if p != os.getpid()]
        if not pids:
            log("no cycle is running - queue is free to start")
            return True
        if time.time() - announced > 300:
            announced = time.time()
            log(f"waiting for the current cycle (pid {','.join(map(str, pids))}, "
                f"{(time.time() - start) / 60:.0f} min)")
        if wait_min and time.time() - start > wait_min * 60:
            log(f"waited {wait_min:.0f} min for the current cycle; leaving it alone and exiting")
            return False
        time.sleep(30)


def wait_docker(log: Log, wait_min: float) -> bool:
    start = time.time()
    while not docker_ok():
        if STOP.exists():
            log("STOP_CYCLES found while waiting for Docker - exiting")
            return False
        if time.time() - start > wait_min * 60:
            log(f"Docker did not become healthy within {wait_min:.0f} min - exiting")
            return False
        log("Docker is not healthy; waiting 30 s")
        time.sleep(30)
    return True


def cleanup_after_timeout(log: Log) -> None:
    """A killed stage can leave Harbor containers behind; only touch our own prefixes."""
    for prefix in ("hb__", "cwe-"):
        try:
            ids = subprocess.run(["docker", "ps", "-q", "--filter", f"name={prefix}"],
                                 capture_output=True, text=True, timeout=30).stdout.split()
        except (OSError, subprocess.TimeoutExpired):
            continue
        if ids:
            subprocess.run(["docker", "rm", "-f", *ids], capture_output=True, timeout=300)
            log(f"timeout cleanup: removed {len(ids)} leftover container(s) with prefix {prefix}")


def run_cycle(log: Log, size: int, timeout_h: float) -> int:
    cmd = [PY, "scripts/run_cycles.py", "--cycles", "1", "--size", str(size)]
    log(f"starting cycle: {' '.join(cmd)}")
    with log.path.open("a") as fh:
        proc = subprocess.Popen(cmd, cwd=ROOT, stdout=fh, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            rc = proc.wait(timeout=timeout_h * 3600 or None)
        except subprocess.TimeoutExpired:
            log(f"cycle exceeded {timeout_h:.0f} h - killing its process group")
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                proc.wait(timeout=120)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    pass
                proc.wait()
            cleanup_after_timeout(log)
            rc = 124
    log(f"cycle finished with rc={rc}")
    return rc


def summary_line(folder: Path) -> str:
    p = folder / "SUMMARY.md"
    try:
        return (p.read_text(errors="replace").splitlines() or ["(empty summary)"])[0][:200]
    except OSError:
        return "(no SUMMARY.md)"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--cycles", type=int, default=3, help="number of cycles to run in this queue (default 3)")
    p.add_argument("--size", type=int, default=6, help="tasks per cycle (default 6)")
    p.add_argument("--docker-wait-min", type=float, default=30)
    p.add_argument("--cycle-timeout-hours", type=float, default=12)
    p.add_argument("--wait-current-min", type=float, default=0, help="0 = wait for the current cycle indefinitely")
    p.add_argument("--min-free-gb", type=float, default=15)
    p.add_argument("--max-empty-cycles", type=int, default=2)
    p.add_argument("--max-failed-cycles", type=int, default=2)
    a = p.parse_args()

    run_dir = LOGS / f"{datetime.now():%Y-%m-%d_%H%M}_queue_{a.cycles}cycles"
    run_dir.mkdir(parents=True, exist_ok=True)
    log = Log(run_dir / "00_queue.log")
    rows: list[list[str]] = []
    empty = failed = 0
    status = "completed"

    log(f"queue start: {a.cycles} cycle(s) x {a.size} tasks; min free {a.min_free_gb:.0f} GB; "
        f"step/cycle timeout {a.cycle_timeout_hours:.0f} h")
    if not wait_for_current(log, a.wait_current_min):
        status = "stopped while waiting for the current cycle"
    for i in range(1, a.cycles + 1):
        if status != "completed":
            break
        if STOP.exists():
            status = "stopped by data/STOP_CYCLES"
            break
        if free_gb() < a.min_free_gb:
            status = f"stopped: only {free_gb():.1f} GB free"
            break
        if not wait_docker(log, a.docker_wait_min):
            status = "stopped: Docker unavailable"
            break
        before = cycle_dirs()
        log(f"=== queue cycle {i}/{a.cycles} ===")
        rc = run_cycle(log, a.size, a.cycle_timeout_hours)
        new = sorted(cycle_dirs() - before)
        if rc == 3:
            status = "stopped by data/STOP_CYCLES"
            rows.append([str(i), new[0].name if new else "-", str(rc), "stopped by user"])
            break
        if new:
            empty = 0
            folder = new[-1]
            line = summary_line(folder)
            rows.append([str(i), folder.name, str(rc), line])
            log(f"cycle {i} -> {folder.name}: {line}")
            if rc not in (0,):
                failed = 0   # it produced a folder, so the cycle ran; rc may reflect a partial stage
        else:
            empty += 1
            if rc != 0:
                failed += 1
            rows.append([str(i), "-", str(rc), "no cycle folder produced"])
            log(f"cycle {i} produced no folder (empty={empty}, failed={failed})")
            if empty >= a.max_empty_cycles or failed >= a.max_failed_cycles:
                status = "stopped: repeated cycles with no output"
                break
    log(f"queue done: {status}")

    lines = [f"# Queue summary - {now()}", "", f"Status: **{status}**",
             f"Requested: {a.cycles} cycle(s) x {a.size} tasks", "",
             "| # | Cycle folder | rc | Summary |", "|---|---|---|---|"]
    lines += [f"| {r[0]} | {r[1]} | {r[2]} | {r[3].replace('|', '/')} |" for r in rows]
    (run_dir / "QUEUE_SUMMARY.md").write_text("\n".join(lines) + "\n")
    try:
        with (LOGS.parent / "README.md").open("a") as fh:
            fh.write(f"| {run_dir.name} | Queue runner: {a.cycles} sequential cycles x {a.size} tasks | {status} |\n")
    except OSError:
        pass
    log.close()
    return 0 if status == "completed" else 1


if __name__ == "__main__":
    sys.exit(main())
