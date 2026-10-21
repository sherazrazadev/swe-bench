"""Results ledger in the shared format (same metrics as the cwe-bench repo's ledger), rebuilt from raw trials.

    python -m src.common.ledger            # writes data/knowledge/ledger.md and prints the summary

Every trial under data/04_eval_runs/<task>/<model>/<job>/<trial>/ is classified:
  graded    the verifier produced a reward (a timed-out run is graded on the code as it stood, as CWE-bench does)
  ungraded  no reward (cancelled, crashed, API/network error) - left out of the counts
A model "SOLVED" a task if any graded run scored 1.0. Breaker = no graded run solved, on both models, AND the
deterministic stage-5 verdict accepted it (the state DB is the authority; this file never disagrees with it).
Timed-out failures follow the one shared rule in Config (TIMEOUT_POLICY / FULL_BUDGET_SEC).
"""
from __future__ import annotations

import json
import re
import statistics
from datetime import datetime
from pathlib import Path

from src.common.config import Config

MODELS = ("deepseek", "mimo")
LANG = {"PyPI": "Python", "npm": "JavaScript/TypeScript"}


def _secs(t: dict | None) -> float | None:
    try:
        a = datetime.fromisoformat(t["started_at"]); b = datetime.fromisoformat(t["finished_at"])
        return (b - a).total_seconds()
    except (TypeError, KeyError, ValueError):
        return None


def _trial(tdir: Path) -> dict:
    res = json.loads((tdir / "result.json").read_text()) if (tdir / "result.json").is_file() else {}
    reward = None
    rp = tdir / "verifier" / "reward.txt"
    if rp.is_file():
        try:
            reward = float(rp.read_text().strip())
        except ValueError:
            pass
    exc = (res.get("exception_info") or {}).get("exception_type")
    budget = ((res.get("config") or {}).get("agent") or {}).get("override_timeout_sec")
    return {"reward": reward, "exception": exc, "timed_out": exc == "AgentTimeoutError",
            "setup_s": _secs(res.get("environment_setup")), "agent_s": _secs(res.get("agent_execution")),
            "budget": budget}


def collect(cfg: Config) -> list[dict]:
    from src.common.state_manager import StateManager
    full = cfg.full_budget_sec if cfg.timeout_policy == "count" else float("inf")   # exclude: no timeout ever counts
    with StateManager(cfg.state_db) as state:
        stage5 = {k: state.get("stage5_evaluator", k) for k in state.keys("stage5_evaluator")}
    meta = {}
    p = cfg.data_dir / "01_mined" / "osv_candidates.json"
    if p.is_file():
        meta = {v["osv_id"]: v for v in json.loads(p.read_text()).get("vulnerabilities", [])}
    rows = []
    for tdir in sorted((cfg.data_dir / "04_eval_runs").glob("*/")):
        oid = tdir.name
        per = {}
        for m in MODELS:
            # judge each model on its LATEST run only (phases -a/-b share one run id); older budgets are history
            jobs = sorted(j for j in (tdir / m).glob("*/") if j.is_dir())
            run_id = re.sub(r"-[ab]$", "", jobs[-1].name) if jobs else None
            trials = [_trial(t) for j in jobs if re.sub(r"-[ab]$", "", j.name) == run_id
                      for t in sorted(j.glob("*/")) if (t / "result.json").is_file()]
            graded = [t for t in trials if t["reward"] is not None]
            per[m] = {"graded": len(graded), "ungraded": len(trials) - len(graded),
                      "solved": sum(t["reward"] >= 1.0 for t in graded),
                      # a timeout only needs a re-run if the run had less than the full 2-hour budget
                      "timeouts_failed": sum(t["timed_out"] and t["reward"] < 1.0 and (t["agent_s"] or 0) < full
                                             for t in graded),
                      "clean_failed": sum(t["reward"] < 1.0 and not (t["timed_out"] and (t["agent_s"] or 0) < full)
                                          for t in graded),
                      "best": max((t["reward"] for t in graded), default=None),
                      "setup": [t["setup_s"] for t in trials if t["setup_s"]]}
        if not any(per[m]["graded"] or per[m]["ungraded"] for m in MODELS):
            continue
        v = meta.get(oid, {})
        rec = stage5.get(oid)
        rows.append({"task": oid, "repo": (v.get("repo_url") or "").split("github.com/")[-1],
                     "state": rec.status.value if rec else None, "state_detail": rec.detail if rec else "",
                     "language": LANG.get(v.get("ecosystem"), v.get("ecosystem") or "?"),
                     "cwe": ", ".join(v.get("cwe_ids") or []), "per": per})
    return rows


def cell(p: dict) -> str:
    if not p["graded"]:
        return "not run" if not p["ungraded"] else f"no graded run ({p['ungraded']} ungraded)"
    return f"SOLVED {p['solved']}/{p['graded']}" if p["solved"] else f"failed 0/{p['graded']}"


def verdict(r: dict) -> str:
    solved = [m for m in MODELS if r["per"][m]["solved"]]
    if len(solved) == 2:
        return "rejected (both solved)"
    if solved:
        return f"rejected ({'DeepSeek' if solved[0] == 'deepseek' else 'MiMo'} solved)"
    if all(r["per"][m]["graded"] for m in MODELS):
        if r.get("state") == "accepted":
            return "BREAKER"
        if r.get("state") in ("needs_review", "rejected"):
            return f"{r['state'].replace('_', ' ')}: {r.get('state_detail', '')[:90]}"
        pending = [m for m in MODELS if r["per"][m]["timeouts_failed"] and not r["per"][m]["clean_failed"]]
        return ("breaker candidate (timeouts do not count yet: " + ", ".join(pending) + ")" if pending
                else "breaker candidate (awaiting the stage-5 verdict)")
    return "in progress"


def build_time(r: dict) -> str:
    s = [x for m in MODELS for x in r["per"][m]["setup"]]
    if not s:
        return "not measured"
    return f"{statistics.median(s):.0f} s / {max(s) / 60:.1f} min"


def render(rows: list[dict]) -> str:
    graded = sum(r["per"][m]["graded"] for r in rows for m in MODELS)
    ungraded = sum(r["per"][m]["ungraded"] for r in rows for m in MODELS)
    breakers = [r for r in rows if verdict(r) == "BREAKER"]
    split = [r for r in rows if sum(bool(r["per"][m]["solved"]) for m in MODELS) == 1]
    out = [f"*Rebuilt {datetime.now():%Y-%m-%d %H:%M} from all {graded + ungraded} raw trials "
           f"({graded} graded, {ungraded} ungraded). Regenerate with `python -m src.common.ledger`.*", "",
           f"**{len(breakers)} breakers out of {len(rows)} trialed tasks.** In {len(split)} tasks one model failed "
           "and the other solved.", "",
           "| Track | Task | Repo | Language | CWE | DeepSeek | MiMo | Verdict | Image build (cached / longest) |",
           "|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        out.append(f"| mined | {r['task']} | {r['repo']} | {r['language']} | {r['cwe']} | {cell(r['per']['deepseek'])} | "
                   f"{cell(r['per']['mimo'])} | {verdict(r)} | {build_time(r)} |")
    return "\n".join(out) + "\n"


def main() -> None:
    cfg = Config.load()
    text = render(collect(cfg))
    out = cfg.data_dir / "knowledge" / "ledger.md"
    out.write_text("# Results ledger (generated)\n\n" + text)
    print(text)


if __name__ == "__main__":
    main()
