#!/usr/bin/env python3
"""Handoff autopilot: one deterministic "tick" of the pipeline side of the Grok/Cursor handoff loop (2026-10-20).

Run every ~30 min (Claude Code /loop). Each tick:
  1. rebuilds data/handoff/STATE.json + STATE.md (scripts/handoff.py);
  2. answered-but-unconsumed requests -> runs stage 3 (handoff backend) for those candidates: answers are validated, the
     next requests (tests phase, retries) are written, finished tasks get instruction.md, unsuitable ones are retired;
  3. generated tasks with no stage-4 verdict -> launches stage 4 then stages 5-6 for them in the BACKGROUND (never a second
     copy of a stage that is already running; the trial waits for any running trial to finish);
  4. writes results, alerts (every safeguards flag is surfaced - project rule) and next actions into STATE.md.
It never edits verdicts, never touches flagged candidates (the pipeline retires them), and never calls a model itself.
Logs: data/logs/<date>_handoff-autopilot/ (tick.log + one log per launched step).
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))
import handoff  # noqa: E402

PY = str(ROOT / ".venv" / "bin" / "python")
LOGDIR_FILE = ROOT / "data" / "handoff" / "autopilot_logdir.txt"
HANDOFF_ENV = {"TASK_GEN_BACKEND": "handoff", "HANDOFF_MODEL": os.environ.get("HANDOFF_MODEL", "grok-4.7-high")}


def logdir() -> Path:
    if LOGDIR_FILE.is_file():
        d = ROOT / LOGDIR_FILE.read_text().strip()
        if d.is_dir():
            return d
    d = ROOT / "data" / "logs" / f"{time.strftime('%Y-%m-%d_%H%M')}_handoff-autopilot"
    d.mkdir(parents=True, exist_ok=True)
    (d / "README.md").write_text(
        "# Handoff autopilot\n\nscripts/handoff_tick.py run every ~30 min: consumes Grok answers (stage 3), launches stage 4 "
        "+ trial (stages 5-6) for finished tasks, writes data/handoff/STATE.md.\n\n- tick.log: one line per tick\n"
        "- stage3_*.log, chain_*.log: the steps it launched\n")
    readme = ROOT / "data" / "logs" / "README.md"
    if readme.is_file():
        with readme.open("a") as fh:
            fh.write(f"| {d.name} | Handoff autopilot: 30-min ticks (stage 3 consume, stage 4 + trial launch, STATE.md) | running |\n")
    LOGDIR_FILE.write_text(str(d.relative_to(ROOT)))
    return d


def running(stage: str) -> bool:
    """A real pipeline process for this stage - not a shell whose command text merely mentions it (a "stage 4; then
    stage 5" chain contains "--stage 5" long before stage 5 starts; the Claude Code Bash tool wraps commands in zsh)."""
    ps = subprocess.run(["ps", "-axo", "args="], capture_output=True, text=True).stdout.splitlines()
    shell = re.compile(r"(/bin/|/usr/bin/)?(ba|z|k|da)?sh\b")
    return any(f"run_pipeline.py --stage {stage}" in a for a in ps if not shell.match(a.strip()))


QUEUE_TARGET = int(os.environ.get("HANDOFF_QUEUE_TARGET", "10"))       # candidates in Grok generation at once
TRIAL_BATCH = int(os.environ.get("HANDOFF_TRIAL_BATCH", "6"))           # validated tasks per trial batch
TRIAL_MAX_WAIT_H = float(os.environ.get("HANDOFF_TRIAL_MAX_WAIT_H", "1.5"))  # a partial batch goes after this wait
# While Grok is being measured (2026-10-20 overnight, autonomous decision): every Grok task that passes validation is
# trialled; the plan probe still runs and records its prediction (advisory), so it gets calibrated on Grok's tasks.
STAGE4_PLAN_PROBE = os.environ.get("HANDOFF_PLAN_PROBE", "advisory")
PICK_STALE_H = 2.0                    # a pick with no request after this long (e.g. a transient build failure) is dropped
PICKED = ROOT / "data" / "handoff" / "picked.json"


def launch(cmd: str, log: Path, env: dict | None = None) -> None:
    """A pipeline step in the background, in its own session (survives this tick), output to `log`."""
    subprocess.Popen(["bash", "-c", f"{cmd} > '{log}' 2>&1"], cwd=ROOT, start_new_session=True,
                     env={**os.environ, **(env or {})}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _db(sql: str, args: tuple = ()) -> list:
    import sqlite3
    con = sqlite3.connect(handoff.STATE_DB)
    try:
        return con.execute(sql, args).fetchall()
    finally:
        con.close()


def trial_queue(st: dict) -> list[tuple[str, float]]:
    """(candidate, hours since it passed stage 4) for Grok tasks validated but not yet trialled, oldest first."""
    out = []
    for k, v in st["candidates"].items():
        if v["stage4"] == "done" and not v["stage5"]:
            row = _db("select updated_at from items where stage='stage4_oracle_validator' and key=?", (k,))
            try:
                import calendar          # the state DB stores UTC
                t = calendar.timegm(time.strptime(row[0][0][:19], "%Y-%m-%dT%H:%M:%S"))
            except (IndexError, ValueError, TypeError):
                t = time.time()
            out.append((k, max(0.0, (time.time() - t) / 3600)))
    return sorted(out, key=lambda x: -x[1])


def _retired(k: str) -> bool:
    env = handoff.ENVS / k
    return (env / "generation_unsuitable.txt").is_file() or bool(
        _db("select 1 from items where stage='stage3_task_builder' and key=? and status='rejected'", (k,)))


def open_candidates(st: dict) -> set[str]:
    """Candidates still in Grok generation: they have requests but no finished task, or were picked recently and are
    still building their environment."""
    out = {k for k, v in st["candidates"].items() if not v["generated"] and not v["retired"]}
    book = json.loads(PICKED.read_text()) if PICKED.is_file() else {}
    for k, t in book.items():
        if (k not in st["candidates"] and time.time() - t < PICK_STALE_H * 3600 and not _retired(k)
                and not (handoff.ENVS / k / "instruction.md").is_file()):
            out.add(k)
    return out


def pick_new(st: dict, n: int) -> list[str]:
    """Up to n new candidates, diverse against what is already in generation: one per repo, <= 3 per ecosystem and
    <= 2 per vulnerability family (relaxed only if the lake cannot fill the slots otherwise). Same exclusions as the
    hand-picked batches: no fix-bypass pairs (their range diffs drag in unrelated commits), no resource exhaustion
    (0 usable of 7), nothing already in the handoff, the normal picker's filters (flagged/unbuildable repos, decided
    candidates)."""
    import logging
    from collections import Counter
    logging.disable(logging.CRITICAL)
    try:
        from src.common.config import Config
        from src.common.results_report import task_type
        from src.stage3_task_builder import _input_file, _limit_to_top_n, current_score
        cfg = Config.load()
        book = json.loads(PICKED.read_text()) if PICKED.is_file() else {}
        taken = set(st["candidates"]) | set(book)
        pool = json.loads(_limit_to_top_n(cfg, _input_file(cfg, False), cfg.stage_dir(3), 400, None,
                                          exclude=taken).read_text())["vulnerabilities"]
        fam = lambda r: task_type(cfg, r["osv_id"], r)["family"]
        pool = [r for r in pool if r["osv_id"] not in taken and not r.get("fix_pair") and not _retired(r["osv_id"])
                and "resource exhaustion" not in fam(r)]
        meta = {}
        for f in ("data/01_mined/osv_candidates.json", "data/02_screened/screened.json"):
            meta.update({r["osv_id"]: r for r in json.loads((ROOT / f).read_text())["vulnerabilities"]})
        busy = [m for m in (meta.get(k) for k in open_candidates(st)) if m]
        repos = {r["repo_url"].lower() for r in busy}
        eco_n, fam_n = Counter(r["ecosystem"] for r in busy), Counter(fam(r).split(" + ")[0] for r in busy)
        picks: list[str] = []
        for strict in (True, False):
            for r in sorted(pool, key=lambda r: -current_score(r)):
                if len(picks) >= n:
                    break
                f = fam(r).split(" + ")[0]
                if r["osv_id"] in picks or r["repo_url"].lower() in repos or eco_n[r["ecosystem"]] >= 3 or \
                        (strict and fam_n[f] >= 2):
                    continue
                picks.append(r["osv_id"]); repos.add(r["repo_url"].lower())
                eco_n[r["ecosystem"]] += 1; fam_n[f] += 1
        return picks
    finally:
        logging.disable(logging.NOTSET)


def tick() -> dict:
    D = logdir()
    stamp = time.strftime("%H%M%S")
    did, alerts = [], []
    st = handoff.build_state()

    # 2. consume answers
    to_consume = {v["candidate"] for v in st["requests"].values() if v["status"] == "answered"}
    # stage 4 archived an attempt for regeneration and no request exists yet for the new round: stage 3 writes it
    regen = sorted(k for k, v in st["candidates"].items() if not v["generated"] and not v["retired"]
                   and (r := handoff._rounds(k)) and not any((handoff.HANDOFF / "requests").glob(f"{k}__r{r}__c*.md")))
    if regen:
        did.append(f"regeneration round requested for {regen} (stage 4 feedback goes to Grok as a new request)")
    to_consume = sorted(to_consume | set(regen))
    if to_consume and running(3):
        did.append(f"stage 3 already running; {len(to_consume)} answered candidates wait for the next tick")
    elif to_consume:
        log = D / f"stage3_{stamp}.log"
        with log.open("w") as fh:
            rc = subprocess.run([PY, "run_pipeline.py", "--stage", "3", "--workers", str(min(8, len(to_consume))),
                                 "--only", ",".join(to_consume)], cwd=ROOT, env={**os.environ, **HANDOFF_ENV},
                                stdout=fh, stderr=subprocess.STDOUT, timeout=3600).returncode
        text = log.read_text(errors="replace")
        gen = re.findall(r"\[([\w-]+)\] generated \(", text)
        retired = re.findall(r"Retired: unsuitable candidate\s+osv_id=([\w-]+)", text)
        rejected = re.findall(r"\[([\w-]+)\] (?:design|tests) attempt \d+/\d+ rejected", text)
        did.append(f"stage 3 consumed {len(to_consume)} candidates (rc={rc}): generated {gen or 'none'}, "
                   f"retired {retired or 'none'}, answers sent back for retry {sorted(set(rejected)) or 'none'}")
        st = handoff.build_state()

    # 3. stage 4 (validation + plan probe) for every finished task, as soon as it is finished
    ready = sorted(k for k, v in st["candidates"].items()
                   if v["generated"] and not v["retired"] and v["stage4"] in (None, "failed"))
    if ready and running(4):
        did.append(f"stage 4 already running; {len(ready)} generated tasks wait: {ready}")
    elif ready:
        launch(f"{PY} run_pipeline.py --stage 4 --workers {min(4, len(ready))} --only {','.join(ready)}",
               D / f"stage4_{stamp}.log", env={"PLAN_PROBE": STAGE4_PLAN_PROBE})
        did.append(f"launched stage 4 for {ready}")

    # 4. the trial in batches: TRIAL_BATCH validated tasks, or fewer once the oldest waited TRIAL_MAX_WAIT_H hours
    validated = trial_queue(st)
    oldest_h = max((h for _, h in validated), default=0.0)
    if validated and running(5):
        did.append(f"trial already running; {len(validated)} validated tasks queued for the next batch")
    elif len(validated) >= TRIAL_BATCH or (validated and oldest_h >= TRIAL_MAX_WAIT_H):
        batch = [k for k, _ in validated][:TRIAL_BATCH]
        launch(f"{PY} run_pipeline.py --stage 5 6 --workers {len(batch)} --only {','.join(batch)}",
               D / f"stage5_{stamp}.log")
        why = "full batch" if len(validated) >= TRIAL_BATCH else f"oldest waited {oldest_h:.1f} h"
        did.append(f"launched the TRIAL for {len(batch)} tasks ({why}): {batch}")
    elif validated:
        did.append(f"{len(validated)}/{TRIAL_BATCH} validated tasks queued for the trial (oldest {oldest_h:.1f} h, "
                   f"partial batch goes at {TRIAL_MAX_WAIT_H:g} h)")

    # 5. keep Grok's queue full: QUEUE_TARGET candidates in generation at once
    st = handoff.build_state()
    open_now = open_candidates(st)
    want = QUEUE_TARGET - len(open_now)
    if want > 0 and running(3):
        did.append(f"queue top-up waits (stage 3 running); {len(open_now)}/{QUEUE_TARGET} in generation")
    elif want > 0:
        picks = pick_new(st, want)
        if picks:
            PICKED.parent.mkdir(parents=True, exist_ok=True)
            book = json.loads(PICKED.read_text()) if PICKED.is_file() else {}
            book.update({k: time.time() for k in picks})
            PICKED.write_text(json.dumps(book, indent=2))
            launch(f"{PY} run_pipeline.py --stage 3 --workers {min(6, len(picks))} --only {','.join(picks)}",
                   D / f"stage3_topup_{stamp}.log", env=HANDOFF_ENV)
            did.append(f"queue top-up: picked {len(picks)} new candidates (env build + Grok requests): {picks}")
        else:
            did.append("queue top-up: no eligible candidate left in the lake")

    # 4. alerts: safeguards flags in anything this autopilot launched (every flag is reported - project rule)
    for f in sorted(D.glob("*.log")):
        for line in f.read_text(errors="replace").splitlines():
            if "safeguards flagged" in line.lower() and "flagged this candidate earlier" not in line:
                alerts.append(f"{f.name}: {line[:220]}")

    st = handoff.build_state()
    handoff_tasks = {k: v for k, v in st["candidates"].items() if v["generator"] == "handoff"}
    results = [f"{k}: stage4={v['stage4'] or '-'}, stage5={v['stage5'] or '-'}" for k, v in handoff_tasks.items()]
    pend = [n for n, v in st["requests"].items() if v["status"] == "pending"]
    stale = [n for n, v in st["requests"].items() if v["stale_claim"]]
    nxt = []
    if pend:
        nxt.append(f"CURSOR: answer {len(pend)} pending request(s) (list above)")
    if stale:
        nxt.append(f"CURSOR: {len(stale)} stale claim(s) - re-take them")
    if not pend and not stale and not to_consume and not ready:
        nxt.append("nothing for Cursor; pipeline steps are running or the batch is finished")
    pipeline = {s: ("running" if running(s) else "idle") for s in ("3", "4", "5")}
    out = handoff.write_state({"pipeline": {f"stage {k}": v for k, v in pipeline.items()}, "next_actions": nxt,
                               "results": results, "alerts": alerts, "last_tick": did})
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {out['counts']} | did: {'; '.join(did) or 'nothing'} | alerts: {len(alerts)}"
    with (D / "tick.log").open("a") as fh:
        fh.write(line + "\n")
    print(line)
    for a in alerts:
        print("ALERT", a)
    return out


if __name__ == "__main__":
    tick()
