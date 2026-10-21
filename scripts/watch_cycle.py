#!/usr/bin/env python3
"""Live watcher for one run_cycles.py cycle (read-only; never touches pipeline state).

Emits a small number of high-signal lines for the Monitor tool:
  START / STAGE / GEN / VALIDATE / MODEL / PATTERN / VERDICT / PACKAGED / RETIRED / ERROR / EXIT
  ALIVE    every --heartbeat-min (so silence is distinguishable from a hang)
  STALL    when there is no log activity AND no active worker/container
  COMPLETE / DRIVER GONE

The per-file offsets live in <cycle-dir>/.watch_state.json, so a restarted watcher resumes where it
stopped instead of replaying old events.

    .venv/bin/python scripts/watch_cycle.py                 # watch the newest cycle
    .venv/bin/python scripts/watch_cycle.py --once          # one snapshot, then exit
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ID = r"((?:GHSA|PYSEC|GO|INJ)-[A-Za-z0-9._-]+)"

RE = {
    "stage_start": re.compile(r"=== Stage (\d): ([^=]+?) ==="),
    "stage_done": re.compile(r"Stage (\d) done\s*(.*)"),
    "gen_ok": re.compile(rf"\[{ID}\] generated \((.*)\)\s*$"),
    "gen_fail": re.compile(rf"\[{ID}\] FAILED validation: (.*)"),
    "gen_api_fail": re.compile(rf"\[{ID}\] API FAILURE \(([^)]*)\): (.*)"),
    "gen_sum": re.compile(r"Done: (\d+) generated, (\d+) skipped, (\d+) failed"),
    "build_sum": re.compile(r"Build check\s+buildable=(\d+)\s+rejected=(\d+)"),
    "val_ok": re.compile(rf"Validated\s+osv_id={ID}\s*(?:detail=(.*))?"),
    "val_fail": re.compile(rf"FAILED_ORACLE\s+osv_id={ID}\s*reason=(.*)"),
    "val_rework": re.compile(rf"archived for regeneration.*?osv_id={ID}"),
    "model": re.compile(rf"Model finished\s+osv_id={ID} model=(\w+) pass=(\d+) fail=(\d+) error=(\d+) best=(\S+)"),
    "pattern": re.compile(rf"Pattern\s+osv_id={ID} pattern=(\S+)"),
    "verdict": re.compile(rf"Verdict\s+osv_id={ID} status=(\w+)"),
    "packaged": re.compile(rf"[Pp]ackaged\s+osv_id={ID}"),
    "exit": re.compile(r"EXIT (\d+)"),
    "retired": re.compile(r"Retired:\s*(.*)"),
    "error": re.compile(r"(?:ERROR|CRITICAL)\s+\S+:|Traceback \(most recent call last\)"),
    "safety": re.compile(r"safeguards|safety filter|classifier", re.I),
}
TS_RE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)")
STATE_NAME = ".watch_state.json"


def now_iso() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def short(text: str, n: int = 170) -> str:
    text = " ".join(str(text).split())
    return text[:n] + ("..." if len(text) > n else "")


def find_cycle_dir() -> Path:
    dirs = sorted((ROOT / "data" / "logs" / "runs").glob("*cycle*_*tasks"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not dirs:
        sys.exit("no cycle log folder under data/logs/runs/")
    return dirs[0]


def pgrep(pattern: str) -> list[str]:
    try:
        out = subprocess.run(["pgrep", "-fl", pattern], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.TimeoutExpired):
        return []
    return [l for l in out.splitlines() if "watch_cycle" not in l]


def driver_pid_from_proc() -> int | None:
    for line in pgrep("scripts/run_cycles.py"):
        m = re.match(r"(\d+)", line)
        if m:
            return int(m.group(1))
    return None


def alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def containers() -> int:
    try:
        out = subprocess.run(["docker", "ps", "--format", "{{.Names}}"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return -1
    names = [n for n in out.stdout.splitlines() if n]
    return sum(1 for n in names if n.startswith("hb__") or "harbor_task__" in n or "cwe-" in n)


def counts() -> dict:
    return {"generated": set(), "gen_failed": set(), "validated": set(), "failed_oracle": set(),
            "rework": set(), "models": {}, "patterns": {}, "verdicts": {}, "packaged": set(), "stage": "?",
            "buildable": 0, "build_rejected": 0}


def extend(c: dict, key: str, value) -> None:
    if key == "models":
        i, model = value
        c["models"].setdefault(i, set()).add(model)
    elif key == "patterns":
        c["patterns"][value[0]] = value[1]
    elif key == "verdicts":
        c["verdicts"][value[0]] = value[1]
    else:
        c[key].add(value)


def parse_line(line: str) -> list[str]:
    """Return printable event lines. Counter updates happen in the caller."""
    out = []
    if m := RE["stage_start"].search(line):
        out.append(f"STAGE {m.group(1)} START  {short(m.group(2), 90)}")
    elif m := RE["stage_done"].search(line):
        out.append(f"STAGE {m.group(1)} DONE  {short(m.group(2), 120)}")
    elif m := RE["gen_ok"].search(line):
        out.append(f"GEN OK  {m.group(1)}  ({short(m.group(2), 80)})")
    elif m := RE["gen_fail"].search(line):
        out.append(f"GEN FAIL  {m.group(1)}  {short(m.group(2), 140)}")
    elif m := RE["gen_api_fail"].search(line):
        out.append(f"GEN API FAIL  {m.group(1)}  ({m.group(2)})  {short(m.group(3), 120)}")
    elif m := RE["gen_sum"].search(line):
        out.append(f"GEN DONE  ok={m.group(1)} skipped={m.group(2)} failed={m.group(3)}")
    elif m := RE["build_sum"].search(line):
        out.append(f"BUILD GATE  buildable={m.group(1)} rejected={m.group(2)}")
    elif m := RE["val_fail"].search(line):
        out.append(f"VALIDATE FAIL_ORACLE  {m.group(1)}  {short(m.group(2), 140)}")
    elif m := RE["val_ok"].search(line):
        out.append(f"VALIDATE OK  {m.group(1)}  {short(m.group(2) or '', 120)}")
    elif m := RE["val_rework"].search(line):
        out.append(f"VALIDATE REWORK  {m.group(1)}")
    elif m := RE["model"].search(line):
        out.append(f"MODEL  {m.group(1)}  {m.group(2)}  pass={m.group(3)} fail={m.group(4)} "
                   f"err={m.group(5)} best={m.group(6)}")
    elif m := RE["pattern"].search(line):
        out.append(f"PATTERN  {m.group(1)}  {m.group(2)}")
    elif m := RE["verdict"].search(line):
        out.append(f"VERDICT  {m.group(1)}  {m.group(2)}")
    elif m := RE["packaged"].search(line):
        out.append(f"PACKAGED  {m.group(1)}")
    elif m := RE["retired"].search(line):
        out.append(f"RETIRED  {short(m.group(1), 140)}")
    elif RE["error"].search(line):
        out.append(f"ERROR  {short(line, 170)}")
    elif RE["safety"].search(line):
        out.append(f"SAFETY  {short(line, 150)}")
    elif m := RE["exit"].search(line):
        out.append(f"STEP EXIT  {m.group(1)}")
    return out


def update(c: dict, line: str) -> None:
    if m := RE["stage_start"].search(line):
        c["stage"] = m.group(1)
    if m := RE["build_sum"].search(line):
        c["buildable"], c["build_rejected"] = int(m.group(1)), int(m.group(2))
    if m := RE["gen_ok"].search(line):
        extend(c, "generated", m.group(1))
    elif m := RE["gen_fail"].search(line):
        extend(c, "gen_failed", m.group(1))
    elif m := RE["gen_api_fail"].search(line):
        extend(c, "gen_failed", m.group(1))
    elif m := RE["val_ok"].search(line):
        extend(c, "validated", m.group(1))
    elif m := RE["val_fail"].search(line):
        extend(c, "failed_oracle", m.group(1))
    elif m := RE["val_rework"].search(line):
        extend(c, "rework", m.group(1))
    elif m := RE["model"].search(line):
        extend(c, "models", (m.group(1), m.group(2)))
    elif m := RE["pattern"].search(line):
        extend(c, "patterns", (m.group(1), m.group(2)))
    elif m := RE["verdict"].search(line):
        extend(c, "verdicts", (m.group(1), m.group(2)))
    elif m := RE["packaged"].search(line):
        extend(c, "packaged", m.group(1))


def snapshot(c: dict, driver: bool, active: dict, target: int) -> str:
    # rewrite rounds reset the build-gate count; never show a denominator smaller than what was generated
    den = max(c.get("buildable") or 0, len(c["generated"])) or target
    build = f"build_rej={c['build_rejected']} " if c.get("build_rejected") else ""
    return (f"ALIVE {now_iso()} stage={c['stage']} gen={len(c['generated'])}/{den or '?'} " + build +
            f"val_ok={len(c['validated'])} failed_oracle={len(c['failed_oracle'])} rework={len(c['rework'])} "
            f"models={sum(len(v) for v in c['models'].values())} accepted={sum(v == 'accepted' for v in c['verdicts'].values())} "
            f"containers={active['containers']} claude={active['claude']} builds={active['builds']} "
            f"compose={active['compose']} "
            f"driver={'up' if driver else 'DOWN'} idle={active['idle']}m")


def save_state(path: Path, offsets: dict, counters: dict, last_event: float) -> None:
    data = {"offsets": offsets, "last_event": last_event,
            "counters": {k: (sorted(v) if isinstance(v, set) else
                             {i: sorted(s) for i, s in v.items()} if k == "models" else v)
                         for k, v in counters.items()}}
    try:
        path.write_text(json.dumps(data))
    except OSError:
        pass


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--cycle-dir", type=Path)
    p.add_argument("--driver-pid", type=int)
    p.add_argument("--heartbeat-min", type=float, default=15)
    p.add_argument("--stall-min", type=float, default=20)
    p.add_argument("--poll-sec", type=float, default=5)
    p.add_argument("--once", action="store_true", help="print one snapshot and exit")
    a = p.parse_args()

    run_dir = a.cycle_dir or find_cycle_dir()
    state_path = run_dir / STATE_NAME
    driver = a.driver_pid or driver_pid_from_proc()
    c = counts()
    offsets: dict[str, int] = {}
    last_event = time.time()
    last_heartbeat = time.time()
    last_stall = 0.0
    last_activity_check = 0.0
    active = {"containers": 0, "claude": 0, "harbor": 0, "builds": 0, "compose": 0, "idle": 0}
    try:
        target = len([l for l in (run_dir / "00_selection.txt").read_text().splitlines() if l.strip()])
    except OSError:
        target = 0

    if state_path.is_file():
        try:
            st = json.loads(state_path.read_text())
            offsets = st.get("offsets") or {}
            last_event = st.get("last_event") or time.time()
        except (OSError, ValueError):
            pass

    # Startup: rebuild counters from ALL existing lines, and emit what was missed since the last watcher
    # run (cold start: only the last 15 minutes). Tailing always resumes at EOF.
    first = not offsets
    startup_cutoff = time.time() - 900 if first else last_event
    for f in sorted(run_dir.glob("*.log")):
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            update(c, line)
            m = TS_RE.match(line)
            try:
                ts = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").timestamp() if m else 0
            except ValueError:
                ts = 0
            if ts > startup_cutoff:
                for ev in parse_line(line):
                    print(ev, flush=True)
        offsets[str(f)] = f.stat().st_size

    print(f"START {now_iso()} watching {run_dir.name} driver_pid={driver}", flush=True)
    if (run_dir / "SUMMARY.md").is_file():
        print(f"COMPLETE cycle already has SUMMARY.md: {short((run_dir / 'SUMMARY.md').read_text(), 200)}", flush=True)
        return 0
    active["idle"] = 0
    active["containers"] = containers()
    active["claude"] = len(pgrep("claude -p"))
    active["builds"] = len(pgrep("docker build"))
    active["compose"] = len(pgrep("docker compose"))
    print(snapshot(c, alive(driver), active, target), flush=True)
    last_activity_check = time.time()
    if a.once:
        return 0

    last_event = max(last_event, max((f.stat().st_mtime for f in run_dir.glob("*.log")), default=time.time()))
    save_state(state_path, offsets, c, last_event)

    while True:
        new_lines = []
        for f in sorted(run_dir.glob("*.log")):
            try:
                size = f.stat().st_size
            except OSError:
                continue
            off = offsets.get(str(f), 0)
            if size < off:          # truncated/rotated
                off = 0
            if size == off:
                continue
            try:
                with f.open("rb") as fh:
                    fh.seek(off)
                    chunk = fh.read(size - off)
            except OSError:
                continue
            offsets[str(f)] = size
            for raw in chunk.decode("utf-8", "replace").splitlines():
                new_lines.append(raw)
                update(c, raw)
                for ev in parse_line(raw):
                    print(ev, flush=True)

        if new_lines:
            last_event = time.time()
            last_stall = 0.0
            save_state(state_path, offsets, c, last_event)

        t = time.time()
        if t - last_activity_check > 30 or a.once:
            last_activity_check = t
            active["containers"] = containers()
            active["claude"] = len(pgrep("claude -p"))
            active["harbor"] = len(pgrep("harbor run"))
            active["builds"] = len(pgrep("docker build"))
            active["compose"] = len(pgrep("docker compose"))
            active["idle"] = int((t - last_event) / 60)
            driver_up = alive(driver)
            if a.once:
                print(snapshot(c, driver_up, active, target), flush=True)
                return 0
            if not driver_up and not (run_dir / "SUMMARY.md").is_file():
                print(f"DRIVER GONE {now_iso()} no run_cycles process and no SUMMARY.md "
                      f"(stage={c['stage']}, idle={active['idle']}m) - inspect {run_dir.name}", flush=True)
                return 2

        if (run_dir / "SUMMARY.md").is_file() and not alive(driver):
            print(f"COMPLETE {now_iso()} {short((run_dir / 'SUMMARY.md').read_text(), 240)}", flush=True)
            return 0

        if t - last_heartbeat >= a.heartbeat_min * 60:
            last_heartbeat = t
            print(snapshot(c, alive(driver), active, target), flush=True)

        working = (active["claude"] > 0 or active["harbor"] > 0 or active["containers"] > 0
                   or active["builds"] > 0 or active["compose"] > 0)
        idle_min = (t - last_event) / 60
        if idle_min >= a.stall_min and not working and t - last_stall >= a.stall_min * 60:
            last_stall = t
            print(f"STALL {now_iso()} no log activity for {idle_min:.0f}m and no active worker/container "
                  f"(stage={c['stage']}) - possible hang", flush=True)

        time.sleep(a.poll_sec)


if __name__ == "__main__":
    sys.exit(main())
