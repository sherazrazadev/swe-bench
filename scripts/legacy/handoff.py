#!/usr/bin/env python3
"""Handoff queue for stage 3 when the generator model is only reachable through the Cursor IDE (TASK_GEN_BACKEND=handoff).

  python scripts/handoff.py status        # requests still waiting for a response
  python scripts/handoff.py pending       # one request path per line (feed these to Cursor subagents)
  python scripts/handoff.py worker-prompt <request.md>   # the exact prompt for the agent that answers one request
  python scripts/handoff.py claim <request.md>           # AGENT: before working on a request
  python scripts/handoff.py done <request.md>            # AGENT: after the response file is written
  python scripts/handoff.py state         # rebuild data/handoff/STATE.json + STATE.md (the shared status board)

Shared state (2026-10-20). The pipeline OWNS STATE.json / STATE.md and rebuilds them from the filesystem and the pipeline
database; nobody edits them by hand. The Cursor agent only signals through `claim` / `done`, which write one small file per
request under data/handoff/claims/ - so two writers can never corrupt one shared file. Request life cycle:
  pending      request written, nobody working on it            -> Cursor agent should take it
  in_progress  claimed by an agent, no response yet              -> wait (a claim older than 2 h is shown as stale)
  answered     response file written, pipeline not yet read it   -> the autopilot runs stage 3
  consumed     stage 3 used the answer (next step written, task complete, or candidate retired)

Request names are <osv_id>__c<n>.md: the n-th model call for that candidate (design, then tests, then any retries).
After stage 4 archives an attempt for regeneration, the next round is <osv_id>__r<k>__c<n>.md (k = archived rounds),
so the new prompt with the reviewer's feedback gets a fresh request instead of replaying the old answers.
"""
from __future__ import annotations

import json
import re
import sqlite3
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HANDOFF = ROOT / "data" / "handoff"
CLAIMS = HANDOFF / "claims"
ENVS = ROOT / "data" / "03_environments"
STATE_DB = ROOT / "data" / "pipeline_state.sqlite3"
STALE_CLAIM_SEC = 2 * 3600

WORKER_PROMPT = """You are the task-generation model for a security benchmark pipeline. Answer ONE handoff request.

0. Claim it first:  python scripts/handoff.py claim {req}
1. Read the request file: {req}
   It contains a SYSTEM section and a REQUEST section. Follow them exactly, including every constraint and the strict
   output format (the XML-style blocks such as <instruction_md>, <task_metadata_json>, <check_patches_json>,
   <hidden_tests_py>; return ONLY the blocks the request asks for).
2. You may read the candidate repository under data/03_environments/<osv_id>/repo (read-only) to check facts. Do not edit
   any repo file, do not run the tests, do not touch other candidates, never edit data/handoff/STATE.*.
3. Write your complete answer, and nothing else (no commentary, no code fences around the blocks), to:
   {resp}
4. If the request says the candidate cannot yield a valid task, answer with <unsuitable>one-sentence reason</unsuitable>.
5. Mark it done:  python scripts/handoff.py done {req}
Reply with just "done <file name>" when the response file is written and marked done.
"""


def requests() -> list[Path]:
    return sorted((HANDOFF / "requests").glob("*.md"))


def response_of(req: Path) -> Path:
    return HANDOFF / "responses" / req.name


def answered(req: Path) -> bool:
    r = response_of(req)
    return r.is_file() and r.stat().st_size > 0


def pending() -> list[Path]:
    return [r for r in requests() if not answered(r)]


def _parse(name: str) -> tuple[str, int, int, str]:
    """<osv_id>[__r<k>]__c<n>.md -> (osv_id, k, n, prefix); legacy <osv_id>__<hash>.md -> (osv_id, 0, 0, stem)."""
    stem = name.removesuffix(".md")
    prefix, _, call = stem.rpartition("__c")
    if not (prefix and call.isdigit()):
        return stem.rpartition("__")[0] or stem, 0, 0, stem
    m = re.fullmatch(r"(.+)__r(\d+)", prefix)
    return (m.group(1), int(m.group(2)), int(call), prefix) if m else (prefix, 0, int(call), prefix)


def _split(name: str) -> tuple[str, int]:
    osv_id, _, n, _ = _parse(name)
    return osv_id, n


def _rounds(osv_id: str) -> int:
    attempts = ENVS / osv_id / "attempts"
    return len(list(attempts.glob("round_*"))) if attempts.is_dir() else 0


def _atomic_write(path: Path, text: str) -> None:
    tmp = path.with_name(f".{path.name}.{__import__('os').getpid()}.tmp")
    tmp.write_text(text)
    tmp.replace(path)      # several agents may run `done` at once: never leave a half-written file


def _db_status(osv_id: str) -> dict[str, str]:
    out = {}
    if not STATE_DB.is_file():
        return out
    con = sqlite3.connect(STATE_DB)
    for stage, status in con.execute("select stage, status from items where key = ?", (osv_id,)):
        out[stage] = status
    con.close()
    return out


def consumed(req: Path) -> bool:
    """Stage 3 already used this answer: the candidate moved past this call, finished, or was retired."""
    osv_id, rnd, n, prefix = _parse(req.name)
    if (HANDOFF / "requests" / f"{prefix}__c{n + 1}.md").is_file() or rnd < _rounds(osv_id):
        return True     # moved past this call, or stage 4 archived this round for regeneration
    env = ENVS / osv_id
    if (env / "instruction.md").is_file() or (env / "generation_unsuitable.txt").is_file():
        return True
    return _db_status(osv_id).get("stage3_task_builder") == "rejected"


def build_state() -> dict:
    now = time.time()
    reqs, candidates = {}, {}
    for r in requests():
        if r.name.startswith("_"):
            continue
        osv_id, n = _split(r.name)
        claim = CLAIMS / (r.name + ".json")
        c = json.loads(claim.read_text()) if claim.is_file() else {}
        if answered(r):
            status = "consumed" if consumed(r) else "answered"
        elif c:
            status = "in_progress"
        else:
            status = "pending"
        reqs[r.name] = {"candidate": osv_id, "call": n, "status": status,
                        "claimed_at": c.get("claimed_at"), "claimed_by": c.get("by"),
                        "stale_claim": bool(c) and not answered(r) and now - c.get("ts", now) > STALE_CLAIM_SEC,
                        "size_kb": r.stat().st_size // 1024}
        candidates.setdefault(osv_id, None)
    for osv_id in candidates:
        env = ENVS / osv_id
        db = _db_status(osv_id)
        gen = env / "generation_meta.json"
        meta = json.loads(gen.read_text()) if gen.is_file() else {}
        candidates[osv_id] = {
            "generated": (env / "instruction.md").is_file(),
            "generator": meta.get("generator"), "model": meta.get("model"),
            "retired": (env / "generation_unsuitable.txt").is_file() or db.get("stage3_task_builder") == "rejected",
            "stage4": db.get("stage4_oracle_validator"), "stage5": db.get("stage5_evaluator"),
        }
    counts: dict[str, int] = {}
    for v in reqs.values():
        counts[v["status"]] = counts.get(v["status"], 0) + 1
    return {"updated_at": time.strftime("%Y-%m-%d %H:%M:%S"), "counts": counts, "requests": reqs,
            "candidates": candidates}


def write_state(extra: dict | None = None) -> dict:
    st = build_state()
    if extra:
        st.update(extra)
    HANDOFF.mkdir(parents=True, exist_ok=True)
    _atomic_write(HANDOFF / "STATE.json", json.dumps(st, indent=2))
    lines = [f"# Handoff state — {st['updated_at']}", "",
             "Rebuilt by the pipeline from the filesystem; do not edit. Agents signal with "
             "`python scripts/handoff.py claim|done <request>`.", "",
             "**Counts:** " + ", ".join(f"{k} {v}" for k, v in sorted(st["counts"].items())), ""]
    todo = [n for n, v in st["requests"].items() if v["status"] == "pending"]
    stale = [n for n, v in st["requests"].items() if v["stale_claim"]]
    lines += ["## For the Cursor agent (Grok)", ""]
    lines += ([f"- answer: `data/handoff/requests/{n}`" for n in todo] or ["- nothing pending"])
    if stale:
        lines += ["", "Stale claims (claimed > 2 h ago, no answer) - re-take them:"] + [f"- `{n}`" for n in stale]
    for k in ("alerts", "next_actions", "pipeline", "results", "last_tick"):
        if st.get(k):
            lines += ["", f"## {k.replace('_', ' ').capitalize()}", ""]
            v = st[k]
            lines += [f"- {x}" for x in v] if isinstance(v, list) else [f"- {a}: {b}" for a, b in v.items()]
    lines += ["", "## Requests", "", "| request | status | claimed |", "|---|---|---|"]
    lines += [f"| {n} | {v['status']}{' (stale)' if v['stale_claim'] else ''} | {v['claimed_at'] or ''} |"
              for n, v in st["requests"].items()]
    lines += ["", "## Candidates", "", "| candidate | generated | retired | stage 4 | stage 5 |", "|---|---|---|---|---|"]
    lines += [f"| {k} | {'yes' if v['generated'] else ''} | {'yes' if v['retired'] else ''} | {v['stage4'] or ''} | "
              f"{v['stage5'] or ''} |" for k, v in st["candidates"].items()]
    _atomic_write(HANDOFF / "STATE.md", "\n".join(lines) + "\n")
    return st


def main(argv: list[str]) -> int:
    cmd = argv[0] if argv else "status"
    if cmd == "pending":
        for r in pending():
            print(r)
    elif cmd == "status":
        allr, pend = requests(), pending()
        print(f"requests={len(allr)} answered={len(allr) - len(pend)} pending={len(pend)}")
        for r in pend:
            print(f"  {r.name}  ({r.stat().st_size // 1024} KB)")
    elif cmd == "worker-prompt" and len(argv) > 1:
        req = Path(argv[1]).resolve()
        print(WORKER_PROMPT.format(req=req, resp=response_of(req)))
    elif cmd in ("claim", "done") and len(argv) > 1:
        req = Path(argv[1])
        req = req if req.is_file() else HANDOFF / "requests" / req.name
        if not req.is_file():
            print(f"no such request: {argv[1]}")
            return 2
        CLAIMS.mkdir(parents=True, exist_ok=True)
        claim = CLAIMS / (req.name + ".json")
        if cmd == "claim":
            claim.write_text(json.dumps({"by": "cursor-agent", "ts": time.time(),
                                         "claimed_at": time.strftime("%Y-%m-%d %H:%M:%S")}))
            print(f"claimed {req.name}")
        else:
            if not answered(req):
                print(f"NOT done: {response_of(req)} is missing or empty - write the response first")
                return 1
            c = json.loads(claim.read_text()) if claim.is_file() else {}
            c.update({"done_at": time.strftime("%Y-%m-%d %H:%M:%S")})
            claim.write_text(json.dumps(c))
            print(f"done {req.name}")
        write_state()
    elif cmd == "state":
        st = write_state()
        print(f"STATE.md written: {st['counts']}")
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
