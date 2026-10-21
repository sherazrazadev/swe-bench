"""Per-task, per-model results from the raw trials - deterministic, no LLM. Rebuilt after every stage-5 run.

    python -m src.common.results_report

Writes
  C_RESULTS.md                          two tables: (1) every trialed task with its FINAL verdict, task type and how each
                                        model failed; (2) model-by-model failures: which TYPE of task broke which model,
                                        and whether the other model solved it. New tasks are new rows, never new tables.
  data/knowledge/model_failure_map.md   the same per-model facts as guidance; the task generator reads it every round,
                                        so even a task that broke only one model teaches the next generation round.

Counting (the agreed rule): a run is SOLVED at reward 1.0. A run that hit the agent time limit is "timed out" and is NOT
counted as a failure. Any other graded run below 1.0 is a failure: a partial fix (some attack variants still open) or a
fix that broke legitimate behaviour. Each model is judged on its latest evaluation run (the one the verdict used).
"""
from __future__ import annotations

import json
import statistics
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from src.common.config import Config
from src.common.harbor import read_trial

MODELS = (("deepseek", "DeepSeek"), ("mimo", "MiMo"))
LANG = {"PyPI": "Python", "npm": "JavaScript/TypeScript", "Go": "Go", "Packagist": "PHP"}

CWE_FAMILIES: list[tuple[str, set[str]]] = [
    ("auth / session / credentials", {"287", "290", "306", "307", "345", "346", "347", "384", "522", "613", "620", "640",
                                      "862", "863", "285", "639", "352", "1390", "294", "565"}),
    ("injection (code / command / markup)", {"74", "77", "78", "79", "88", "89", "94", "95", "116", "917", "1336", "184"}),
    ("path / file handling", {"22", "23", "35", "59", "61", "73", "434"}),
    ("parsing / type confusion", {"20", "436", "696", "697", "704", "843", "1284", "1287", "115"}),
    ("resource exhaustion (DoS)", {"400", "401", "407", "409", "674", "770", "772", "834", "1333", "1050"}),
    ("information exposure", {"200", "201", "209", "226", "532", "359"}),
    ("deserialization / prototype pollution", {"502", "915", "1321"}),
    ("SSRF / redirect", {"918", "601"}),
    ("cryptography", {"326", "327", "328", "330", "338", "347"}),
]


def cwe_family(cwes: list[str]) -> str:
    nums = {c.upper().removeprefix("CWE-") for c in cwes or []}
    hits = [name for name, ids in CWE_FAMILIES if nums & ids]
    return " + ".join(dict.fromkeys(hits)) or "other"


def _meta(cfg: Config) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for rel in ("01_mined/osv_candidates.json", "02_screened/screened.json", "02_screened/injected.json"):
        p = cfg.data_dir / rel
        if p.is_file():
            try:
                out.update({v["osv_id"]: v for v in json.loads(p.read_text()).get("vulnerabilities", [])})
            except (OSError, json.JSONDecodeError, KeyError):
                pass
    return out


def task_type(cfg: Config, osv_id: str, rec: Optional[dict] = None) -> dict[str, Any]:
    """What kind of task this is: vulnerability family (CWE), fix shape (files / dirs / lines) and entry point."""
    rec = rec if rec is not None else _meta(cfg).get(osv_id, {})
    diff = (rec.get("screening") or {}).get("diff") or {}
    files, dirs, lines = len(diff.get("source_files") or []), len(diff.get("source_dirs") or []), diff.get("source_lines")
    entry = ""
    tm = cfg.stage_dir(3) / osv_id / "task_metadata.json"
    if tm.is_file():
        try:
            entry = json.loads(tm.read_text()).get("entry_point", "")
        except json.JSONDecodeError:
            pass
    shape = f"{files} files / {dirs} dir{'s' if dirs != 1 else ''} / {lines} lines" if files else "fix size unknown"
    breadth = "wide multi-layer fix" if files >= 6 or dirs >= 4 else ("multi-file fix" if files >= 3 else "local fix")
    return {"family": cwe_family(rec.get("cwe_ids") or []), "shape": shape, "breadth": breadth, "entry_point": entry,
            "label": f"{cwe_family(rec.get('cwe_ids') or [])}; {breadth} ({shape})"}


def language(rec: dict) -> str:
    """Python / TypeScript / JavaScript from the fix's own source files (npm covers both JS and TS)."""
    if rec.get("ecosystem") == "PyPI":
        return "Python"
    files = ((rec.get("screening") or {}).get("diff") or {}).get("source_files") or []
    if any(f.endswith((".ts", ".tsx", ".mts", ".cts")) and not f.endswith(".d.ts") for f in files):
        return "TypeScript"
    return "JavaScript" if rec.get("ecosystem") == "npm" else LANG.get(rec.get("ecosystem"), rec.get("ecosystem") or "?")


def _short(text: str, n: int = 90) -> str:
    return text if len(text) <= n else text[:n].rsplit(" ", 1)[0] + " …"


def _latest_trials(model_dir: Path) -> list[Path]:
    from src.stage5_evaluator.trial_analysis import latest_trials
    return [t for _, t in latest_trials(model_dir)] if model_dir.is_dir() else []


AGENT_LABEL = {"claude-code": "Claude Code", "terminus-2": "terminus-2"}


def _agent_name(trial_dir: Path) -> str:
    try:
        return (json.loads((trial_dir / "result.json").read_text()).get("agent_info") or {}).get("name", "")
    except (OSError, json.JSONDecodeError):
        return ""


def _readable(test: str) -> str:
    return test.split("::")[-1].removeprefix("test_security_").removeprefix("test_functional_")


def model_result(model_dir: Path, enforced: Optional[set[str]] = None) -> dict[str, Any]:
    """Verdict + deterministic 'how' for one model's latest run on one task. `enforced`: the existing repo tests the
    grader counts (pass->pass on the reference fix); others (e.g. runtimes the image lacks) are not a regression."""
    runs = []
    for tdir in _latest_trials(model_dir):
        t = read_trial(tdir)
        sec = {n: s for n, s in (t.ctrf or {}).items() if n.split("::")[-1].startswith("test_security_")}
        existing = {n: s for n, s in (t.ctrf_existing or {}).items() if enforced is None or n in enforced}
        fun = {n: s for n, s in {**(t.ctrf or {}), **existing}.items()
               if not n.split("::")[-1].startswith("test_security_")}
        steps = 0
        traj = tdir / "agent" / "trajectory.json"
        if traj.is_file():
            try:
                steps = sum(s.get("source") == "agent" for s in json.loads(traj.read_text()).get("steps", []))
            except json.JSONDecodeError:
                pass
        if t.reward is not None and t.reward >= 1.0:
            kind = "solved"
        elif t.reward is None or (t.exception and not t.timed_out):
            kind = "ungraded"
        elif t.timed_out:
            kind = "timed_out"
        else:
            kind = "failed"
        runs.append({"kind": kind, "reward": t.reward, "sec": sec, "fun": fun, "steps": steps, "agent_s": t.agent_secs,
                     "budget": t.timeout_budget, "exception": t.exception})
    graded = [r for r in runs if r["kind"] != "ungraded"]
    kinds = [r["kind"] for r in graded]
    agents = sorted({a for a in (_agent_name(t) for t in _latest_trials(model_dir)) if a})
    out: dict[str, Any] = {"runs": len(runs), "graded": len(graded), "solved": kinds.count("solved"),
                           "failed": kinds.count("failed"), "timed_out": kinds.count("timed_out"),
                           "agent": ", ".join(AGENT_LABEL.get(a, a) for a in agents)}
    if not graded:
        out.update(verdict="not graded", cell="stopped early (not graded)" if runs else "not run", how="")
        return out
    rewards = [r["reward"] for r in graded]
    each = (f"{rewards[0]:.2f}" if len(rewards) == 1 else f"{rewards[0]:.2f} each" if len(set(rewards)) == 1
            else "/".join(f"{x:.2f}" for x in rewards))
    if out["solved"]:
        win = next(r for r in graded if r["kind"] == "solved")
        mins = f", {win['agent_s'] / 60:.0f} min" if win["agent_s"] else ""
        out.update(verdict="solved", cell=f"SOLVED {out['solved']}/{len(graded)}",
                   how=f"solved in {win['steps']} steps{mins}")
        return out
    # Not solved: failures (counted) and/or timeouts (not counted).
    open_all = sorted(set.intersection(*[{n for n, s in r["sec"].items() if s != "passed"} for r in graded]) or set())
    n_sec = max(len(r["sec"]) for r in graded) or 0
    broke = sorted({_readable(n) for r in graded for n, s in r["fun"].items() if s != "passed"})
    parts = []
    fails = [r for r in graded if r["kind"] == "failed"]
    if fails:
        stopped = "stopped on its own"
        n_broke = sum(any(s != "passed" for s in r["fun"].values()) for r in fails)
        broke_runs = f" in {n_broke} of {len(fails)} runs" if broke and n_broke < len(fails) else ""
        if broke and all(sum(s == "passed" for s in r["sec"].values()) == len(r["sec"]) for r in fails):
            what = f"closed the hole but broke legitimate behaviour ({', '.join(broke[:3])}){broke_runs}"
        elif broke:
            what = f"partial fix (and broke legitimate behaviour{broke_runs}: {', '.join(broke[:3])})"
        else:
            got = [sum(s == "passed" for s in r["sec"].values()) for r in fails]
            what = (f"partial fix: closed {got[0]} of {n_sec} attack variants" if len(set(got)) == 1
                    else f"partial fix: closed {'/'.join(map(str, got))} of {n_sec} attack variants")
        runs_txt = f"in all {len(fails)} runs" if len(fails) > 1 else "in its run"
        parts.append(f"{what} {runs_txt} and {stopped} (it thought it was done)")
    tos = [r for r in graded if r["kind"] == "timed_out"]
    if tos:
        b = max(r["budget"] or 0 for r in tos)
        got = sorted({sum(s == "passed" for s in r["sec"].values()) for r in tos})
        closed_txt = f"{got[0]}" if len(got) == 1 else f"{got[0]}-{got[-1]}"
        parts.append(f"ran out of the {b / 60:.0f}-min limit in {len(tos)}/{len(graded)} runs with {closed_txt} of "
                     f"{n_sec} attack variants closed; not counted as a failure")
    if open_all and fails:
        parts.append(f"left open every time: {', '.join(_readable(n) for n in open_all[:3])}")
    out["verdict"] = "failed" if fails and not tos else ("timed_out" if tos and not fails else "failed+timed_out")
    if out["verdict"] == "failed":
        out["cell"] = f"failed 0/{len(graded)} ({each}, stopped on its own)"
    elif out["verdict"] == "timed_out":
        out["cell"] = f"timed out {len(tos)}/{len(graded)} ({each})"
    else:
        out["cell"] = f"failed {len(fails)}, timed out {len(tos)} of {len(graded)} ({each})"
    out["how"] = "; ".join(parts)
    out["open_in_all"] = [_readable(n) for n in open_all]
    return out


def final_verdict(state_rec, per: dict[str, dict]) -> str:
    status = state_rec.status.value if state_rec else ""
    solved = [name for tag, name in MODELS if per[tag]["verdict"] == "solved"]
    if status == "accepted":
        return "**ACCEPTED**: both models failed every run"
    if solved:
        return f"REJECTED: {' and '.join(solved)} solved" if len(solved) < 2 else "REJECTED: both solved"
    timed = [name for tag, name in MODELS if "timed_out" in per[tag]["verdict"]]
    if status == "rejected" and timed:
        return f"REJECTED: {' and '.join(timed)} timed out, which is not counted as a failure"
    if status == "needs_review":
        return f"NEEDS REVIEW: {state_rec.detail[:80]}"
    if status in ("", "done", "failed"):
        return "IN PROGRESS"
    return f"REJECTED: {state_rec.detail[:80]}"


def withdrawn_tasks(cfg: Config) -> dict[str, str]:
    """osv_id -> reason for tasks the user acknowledged as defective (data/knowledge/withdrawn_tasks.json). Their runs
    stay in C_RESULTS.md (marked WITHDRAWN) but never teach the generator. A state reset cannot un-withdraw them."""
    p = cfg.data_dir / "knowledge" / "withdrawn_tasks.json"
    try:
        return {k: str(v) for k, v in json.loads(p.read_text()).items() if not k.startswith("_")}
    except (OSError, ValueError, AttributeError):
        return {}


def learning_rows(cfg: Config, rows: list[dict]) -> list[dict]:
    """The rows the generator's knowledge files may learn from."""
    return [r for r in rows if not r.get("withdrawn")]


def collect(cfg: Config) -> list[dict]:
    from src.common.state_manager import StateManager
    withdrawn = withdrawn_tasks(cfg)
    meta = _meta(cfg)
    with StateManager(cfg.state_db) as state:
        recs = {k: state.get("stage5_evaluator", k) for k in state.keys("stage5_evaluator")}
    rows = []
    for tdir in sorted(d for d in cfg.stage_dir(5).glob("*/") if d.is_dir() and not d.name.startswith(".")):
        exp = cfg.stage_dir(3) / tdir.name / "harbor_task" / "tests" / "existing_expected.txt"
        enforced = {l.strip() for l in exp.read_text().splitlines() if l.strip()} if exp.is_file() else None
        per = {tag: model_result(tdir / tag, enforced) for tag, _ in MODELS}
        if not any(p["runs"] for p in per.values()):
            continue
        m = meta.get(tdir.name, {})
        setups = []
        for tag, _ in MODELS:
            for t in _latest_trials(tdir / tag):
                try:
                    r = json.loads((t / "result.json").read_text())
                    a, b = r["environment_setup"]["started_at"], r["environment_setup"]["finished_at"]
                    setups.append((datetime.fromisoformat(b) - datetime.fromisoformat(a)).total_seconds())
                except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
                    pass
        rows.append({"task": tdir.name, "package": m.get("package") or tdir.name, "language": language(m),
                     "cwe": ", ".join(c.removeprefix("CWE-") for c in m.get("cwe_ids") or []),
                     "type": task_type(cfg, tdir.name, m), "per": per, "state": recs.get(tdir.name),
                     "build": f"{statistics.median(setups):.0f} s / {max(setups) / 60:.1f} min" if setups else "not measured"})
    for r in rows:
        r["withdrawn"] = withdrawn.get(r["task"], "")
        r["verdict"] = (f"WITHDRAWN: {r['withdrawn'][:80]}" if r["withdrawn"]
                        else final_verdict(r["state"], r["per"]))
    return rows


def _how(r: dict) -> str:
    bits = [f"{name}: {r['per'][tag]['how']}" for tag, name in MODELS
            if r["per"][tag]["verdict"] not in ("solved", "not graded") and r["per"][tag]["how"]]
    return " — ".join(bits) or "—"


def render_results(rows: list[dict]) -> str:
    accepted = sum(r["verdict"].startswith("**ACCEPTED") for r in rows)
    graded = sum(r["per"][t]["graded"] for r in rows for t, _ in MODELS)
    runs = sum(r["per"][t]["runs"] for r in rows for t, _ in MODELS)
    one_model = [r for r in rows if any(r["per"][t]["verdict"] != "solved" and r["per"][t]["graded"] for t, _ in MODELS)]
    out = [
        "# CWE-Bench — Results Ledger (internal)", "",
        f"_Generated {datetime.now():%Y-%m-%d %H:%M} from the latest evaluation run of each model on each task "
        f"({runs} attempts, {graded} graded) in `data/04_eval_runs/` and the pipeline state. Regenerate with "
        "`python -m src.common.results_report` (stage 5 does it after every run)._", "",
        "**Breaker** = pass@3 = 0 on **both** DeepSeek V4.1 Flash (max) and MiMo-V2.6-Pro. A run is solved at reward 1.0. "
        "A partial fix (some attack variants still open) and a fix that breaks legitimate behaviour are failures. "
        "A run that hit the 2-hour agent limit is **timed out and not counted as a failure**. Runs that were never graded "
        "(stopped early, crashed, lost to a connection drop) are left out. Each model is judged on its latest evaluation "
        "run; the agent harness (terminus-2 or Claude Code) is shown next to each result.", "",
        "## Executive summary", "",
        f"**{accepted} accepted out of {len(rows)} trialed tasks.** In {len(one_model)} task(s) at least one model did "
        "not solve it (see the second table for which task type broke which model).", "",
        "## All trialed tasks", "",
        "| # | Task | Language | CWE | Task type | DeepSeek | MiMo | Final verdict | How it failed | Image build (cached / longest) |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for i, r in enumerate(rows, 1):
        cells = [f"{r['per'][t]['cell']}" + (f" — {r['per'][t]['agent']}" if r['per'][t].get('agent') else "")
                 for t, _ in MODELS]
        out.append(f"| {i} | {r['package']} ({r['task']}) | {r['language']} | {r['cwe']} | {r['type']['label']} | "
                   f"{cells[0]} | {cells[1]} | {r['verdict']} | {_how(r)} | {r['build']} |")
    out += ["", "## What breaks which model", "",
            "Every task where a model did not solve it. A task that breaks only one model is still evidence: it shows "
            "which task type that model cannot handle. The task generator reads this as `data/knowledge/model_failure_map.md`.", "",
            "| Task | Task type | Entry point | Model | Result | How it failed | Other model |",
            "|---|---|---|---|---|---|---|"]
    for r in rows:
        for tag, name in MODELS:
            p = r["per"][tag]
            if p["verdict"] in ("solved", "not graded"):
                continue
            other_tag, other = next((t, n) for t, n in MODELS if t != tag)
            o = r["per"][other_tag]
            other_txt = {"solved": f"{other} solved it ({o['how']})", "not graded": f"{other}: not graded"}.get(
                o["verdict"], f"{other} also did not solve it ({o['cell']})")
            res = {"failed": "FAILED", "timed_out": "timed out (not counted)", "failed+timed_out": "failed + timed out"}[p["verdict"]]
            out.append(f"| {r['package']} ({r['task']}) | {r['type']['label']} | {_short(r['type']['entry_point']) or '—'} | "
                       f"{name} | {res} | {p['how']} | {other_txt} |")
    return "\n".join(out) + "\n"


ANALYSES_DIR = "failure_analyses"     # data/knowledge/failure_analyses/<osv_id>.md - curated "why it failed" write-ups


def _is_test(path: str) -> bool:
    low = path.lower()
    return any(k in low for k in ("test", "spec", "__snapshots__", "fixture")) or low.endswith((".md", ".changeset"))


def attempt_rows(model_dir: Path, enforced: Optional[set[str]]) -> list[dict]:
    """Every attempt of a model's latest run, in start order, with what the grader saw."""
    out = []
    for tdir in _latest_trials(model_dir):
        t = read_trial(tdir)
        try:
            r = json.loads((tdir / "result.json").read_text())
        except (OSError, json.JSONDecodeError):
            r = {}
        started = str((r.get("agent_execution") or {}).get("started_at") or r.get("started_at") or "")
        hidden = t.ctrf or {}
        sec = {n: s for n, s in hidden.items() if n.split("::")[-1].startswith("test_security_")}
        fun = {n: s for n, s in hidden.items() if n.split("::")[-1].startswith("test_functional_")}
        ex = {n: s for n, s in (t.ctrf_existing or {}).items() if enforced and n in enforced}   # only what was scored
        files = []
        pf = tdir / "verifier" / "agent_patch_files.txt"
        if pf.is_file():
            files = [l.strip() for l in pf.read_text().splitlines() if l.strip() and not _is_test(l.strip())]
        steps = 0
        traj = tdir / "agent" / "trajectory.json"
        if traj.is_file():
            try:
                steps = sum(s.get("source") == "agent" for s in json.loads(traj.read_text()).get("steps", []))
            except json.JSONDecodeError:
                pass
        if t.reward is not None and t.reward >= 1.0:
            ended = "SOLVED"
        elif t.timed_out:
            ended = "timed out (not counted)"
        elif t.reward is None:
            ended = "cancelled (not graded)" if t.exception_type == "CancelledError" else f"not graded ({t.exception_type})"
        else:
            ended = "failed - stopped on its own"
        out.append({"started": started, "reward": t.reward, "ended": ended, "files": files, "steps": steps,
                    "mins": round((t.agent_secs or 0) / 60),
                    "sec": (sum(s == "passed" for s in sec.values()), len(sec)),
                    "fun": (sum(s == "passed" for s in fun.values()), len(fun)),
                    "ex": (sum(s == "passed" for s in ex.values()), len(ex)),
                    "open": [_readable(n) for n, s in sorted(sec.items()) if s != "passed"],
                    "broke": [_readable(n) for n, s in sorted({**fun, **ex}.items()) if s != "passed"]})
    return sorted(out, key=lambda a: a["started"])


def _ref_files(cfg: Config, osv_id: str) -> list[str]:
    p = cfg.stage_dir(3) / osv_id / "oracle_solution.patch"
    if not p.is_file():
        return []
    import re
    return [f for f in dict.fromkeys(re.findall(r"^\+\+\+ b/(\S+)", p.read_text(errors="replace"), re.M)) if not _is_test(f)]


def render_failure_details(cfg: Config, rows: list[dict]) -> str:
    """One section per task that a model FAILED (counted failures, not only timeouts): every attempt of both models,
    what was left open or broken, and the curated analysis of why (data/knowledge/failure_analyses/<id>.md)."""
    def rank(r):
        v = [r["per"][t]["verdict"] for t, _ in MODELS]
        return (0 if r["verdict"].startswith("**ACCEPTED") else 1 if "solved" not in v else 2, r["task"])
    failing = sorted((r for r in rows if any(r["per"][t]["verdict"] in ("failed", "failed+timed_out") for t, _ in MODELS)),
                     key=rank)
    out = ["", "## Failure details", "",
           "Every task a model FAILED (a counted failure: graded, below 1.0, not a timeout), most important first. "
           "Solved tasks are only in the tables above. Each attempt is listed in the order it ran; *left open* = hidden "
           "security tests still failing, *broke* = functional or enforced existing repo tests that failed.", ""]
    for r in failing:
        exp = cfg.stage_dir(3) / r["task"] / "harbor_task" / "tests" / "existing_expected.txt"
        enforced = {l.strip() for l in exp.read_text().splitlines() if l.strip()} if exp.is_file() else None
        out += [f"### {r['package']} ({r['task']}) - {r['verdict'].replace('**', '')}", "",
                f"- **Task type:** {r['type']['label']}; CWE {r['cwe']}; {r['language']}",
                f"- **Entry point:** {r['type']['entry_point'] or '-'}",
                f"- **Reference fix (source files):** {', '.join(f'`{f}`' for f in _ref_files(cfg, r['task'])) or '-'}", "",
                "| Model | # | Score | Security | Functional | Existing | Left open | Broke | Source files changed | Time | Turns | Ended |",
                "|---|---|---|---|---|---|---|---|---|---|---|---|"]
        for tag, name in MODELS:
            for i, a in enumerate(attempt_rows(cfg.stage_dir(5) / r["task"] / tag, enforced), 1):
                score = f"{a['reward']:.2f}" if a["reward"] is not None else "-"
                frac = lambda p: f"{p[0]}/{p[1]}" if p[1] else "-"
                out.append(f"| {name} | {i} | {score} | {frac(a['sec'])} | {frac(a['fun'])} | {frac(a['ex'])} | "
                           f"{', '.join(a['open']) or '-'} | {', '.join(a['broke'][:3]) or '-'} | "
                           f"{', '.join(f'`{f}`' for f in a['files'][:8]) or '-'} | {a['mins']} min | {a['steps'] or '-'} | {a['ended']} |")
        note = cfg.data_dir / "knowledge" / ANALYSES_DIR / f"{r['task']}.md"
        if note.is_file():
            out += ["", note.read_text(encoding="utf-8").strip()]
        out.append("")
    return "\n".join(out) + "\n"


def technique_names(cfg: Config) -> dict[int, str]:
    """Numbered techniques of the curated guide (skills/task_design_techniques.md): `N. **Name.** ...`."""
    import re
    p = cfg.root / "skills" / "task_design_techniques.md"
    text = p.read_text(encoding="utf-8") if p.is_file() else ""
    return {int(n): name.strip().rstrip(".") for n, name in re.findall(r"(?m)^(\d+)\. \*\*(.+?)\*\*", text)}


def task_techniques(cfg: Config, osv_id: str) -> list[int]:
    """Techniques the generator says it applied (task_metadata.json `techniques`), else the inferred backfill."""
    tm = cfg.stage_dir(3) / osv_id / "task_metadata.json"
    try:
        meta = json.loads(tm.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    return [int(t) for t in (meta.get("techniques") or meta.get("techniques_inferred") or [])]


def outcome_class(r: dict) -> str:
    v = {t: r["per"][t]["verdict"] for t, _ in MODELS}
    failed = {t for t, x in v.items() if x in ("failed", "failed+timed_out")}
    if failed == {t for t, _ in MODELS}:
        return "broke_both"
    if failed:
        return "broke_" + next(iter(failed))
    return "solved" if any(x == "solved" for x in v.values()) else "no_result"


def render_technique_scoreboard(cfg: Config, rows: list[dict]) -> str:
    """Which curated techniques were in tasks that broke a model, and which were always solved - rebuilt every run."""
    names = technique_names(cfg)
    stats: dict[int, dict[str, list[str]]] = {n: {} for n in names}
    untagged = 0
    for r in rows:
        techs = task_techniques(cfg, r["task"])
        if not techs:
            untagged += 1
        for t in techs:
            stats.setdefault(t, {}).setdefault(outcome_class(r), []).append(r["package"])
    out = ["## Technique scoreboard (measured, rebuilt after every evaluation)",
           "How often each curated technique was used in an evaluated task, and the outcome. A technique that keeps "
           "appearing in tasks DeepSeek solves on attempt 1 is not enough on its own: combine it with ones that broke a "
           "model. Counts are per task.", "",
           "| # | Technique | Tasks | Broke both | Broke only DeepSeek | Broke only MiMo | Solved | Read |",
           "|---|---|---|---|---|---|---|---|"]
    n_tasks = sum(1 for r in rows if task_techniques(cfg, r["task"]))
    n_breaks = sum(1 for r in rows if task_techniques(cfg, r["task"]) and outcome_class(r).startswith("broke"))
    base = n_breaks / n_tasks if n_tasks else 0.0
    out.insert(3, f"Baseline: {n_breaks} of {n_tasks} tagged tasks broke at least one model ({base:.0%}). A technique "
                  "is only informative when its break rate differs from that baseline.")
    out.insert(4, "")
    for n in sorted(stats):
        st = stats[n]
        total = sum(len(v) for v in st.values())
        both, ds, mm, sv = (len(st.get(k, [])) for k in ("broke_both", "broke_deepseek", "broke_mimo", "solved"))
        breaks = both + ds + mm
        rate = breaks / total if total else 0.0
        if total and n_tasks and total >= 0.8 * n_tasks:
            read = f"BASELINE (in {total}/{n_tasks} tasks): necessary, not sufficient"
        elif total < 3:
            read = "too few uses to judge" + (" (but broke both models)" if both else "")
        elif breaks == 0:
            read = "WEAK alone: never broke a model - combine with a USE technique"
        elif rate >= 1.5 * base:
            read = f"USE: {rate:.0%} break rate vs {base:.0%} baseline"
        else:
            read = f"neutral: {rate:.0%} break rate"
        ex = ", ".join(dict.fromkeys(st.get("broke_both", []) + st.get("broke_deepseek", []) + st.get("broke_mimo", [])))
        out.append(f"| {n} | {names.get(n, '?')} | {total} | {both} | {ds} | {mm} | {sv} | {read}{f' ({ex})' if ex else ''} |")
    out.append("")
    out.append(f"_{untagged} evaluated task(s) have no technique record._")
    return "\n".join(out) + "\n"


PASS_RULES = {
    "coverage gap": "list every place the reference fix hardens and reach EACH one from its own security test - a "
                    "repair that skips one place must fail",
    "small fix": "a one-place fix is solved whatever the report says; skip it unless the code has a real second place "
                 "the fix must also reach (fix width alone does not help: 10-21-file fixes were solved on attempt 1)",
    "report points at the code": "never name the file, function, option or parameter the fix changes, and never state "
                                 "how far the bug reaches ('every provider', 'on every route')",
    "no hidden path": "put part of the root cause in a REAL place the report never leads to - a second implementation, "
                      "a producer feeding the check, a defaults/merge route - and reach it with its own test "
                      "(techniques 1, 2, 3, 7, 12-15)",
    "few security tests": "write one security test per fix place, each through its own entry point (spelling and "
                          "encoding variants of one input do not count: models always catch them)",
}


def _report_leaks(cfg: Config, osv_id: str, ref: list[str]) -> list[str]:
    """Code names from the reference fix (changed file stems, functions in hunk headers) that the report spells out."""
    import re
    env = cfg.stage_dir(3) / osv_id
    try:
        report = (env / "instruction.md").read_text(errors="replace")
        patch = (env / "oracle_solution.patch").read_text(errors="replace")
    except OSError:
        return []
    names = {Path(f).stem for f in ref if len(Path(f).stem) > 5 and Path(f).stem not in ("index", "__init__", "utils")}
    names |= {m for m in re.findall(r"^@@[^@]*@@.*?\b(?:def|function|func|class)\s+([A-Za-z_]\w{5,})", patch, re.M)}
    return sorted(n for n in names if re.search(rf"(?<![\w/]){re.escape(n)}(?!\w)", report))


def pass_reasons(x: dict) -> list[str]:
    """Deterministic reasons a solved task was too easy, each mapped to a PASS_RULES fix."""
    out = []
    if x["files"] and x["known"] and x["touched"] < x["files"]:      # older trials did not record the agent's files
        out.append("coverage gap")
    if x["files"] and x["files"] <= 3:
        out.append("small fix")
    if x["leaks"]:
        out.append("report points at the code")
    if not set(x["techs"]) & {1, 2, 3, 7}:
        out.append("no hidden path")
    if x["sec"] and x["sec"] <= 5:
        out.append("few security tests")
    return out


def render_solved_profile(cfg: Config, rows: list[dict]) -> str:
    """Deterministic profile of the tasks a model SOLVED: the shapes that do not work, so every cycle's generator learns
    from solved tasks as well as from failures. Rebuilt after every evaluation."""
    import statistics as st
    names = technique_names(cfg)
    solved = []
    for r in rows:
        for tag, name in MODELS:
            if r["per"][tag]["verdict"] != "solved":
                continue
            atts = attempt_rows(cfg.stage_dir(5) / r["task"] / tag, None)
            win = next((i for i, a in enumerate(atts, 1) if a["ended"] == "SOLVED"), None)
            if win is None:
                continue
            a = atts[win - 1]
            ref_list = _ref_files(cfg, r["task"])
            ref = set(ref_list)
            touched = len(ref & set(a["files"]))
            x = {"pkg": r["package"], "family": r["type"]["family"], "shape": r["type"]["shape"],
                 "files": len(ref), "sec": a["sec"][1], "solver": name, "attempt": win, "mins": a["mins"],
                 "touched": touched, "known": bool(a["files"]), "techs": task_techniques(cfg, r["task"]),
                 "leaks": _report_leaks(cfg, r["task"], ref_list)}
            x["why"] = pass_reasons(x)
            solved.append(x)
            break
    if not solved:
        return "## Solved-task profile\n(no solved tasks yet)\n"
    first = [x for x in solved if x["attempt"] == 1]
    fams: dict[str, int] = {}
    for x in solved:
        for f in x["family"].split(" + "):
            fams[f] = fams.get(f, 0) + 1
    out = ["## Solved-task profile (deterministic, rebuilt after every evaluation)",
           f"{len(solved)} evaluated tasks were solved by at least one model; {len(first)} on the FIRST attempt. "
           f"Median solve time {st.median(x['mins'] for x in solved):.0f} min. These are the shapes to avoid or to "
           "combine with the techniques that broke a model (see the technique scoreboard).",
           f"- Median reference-fix size of solved tasks: {st.median(x['files'] for x in solved):.0f} source files; "
           f"median number of security tests: {st.median(x['sec'] for x in solved):.0f}.",
           "- Solved by vulnerability family: " + ", ".join(f"{k} x{v}" for k, v in sorted(fams.items(), key=lambda kv: -kv[1])),
           f"- In {sum(1 for x in solved if x['files'] and x['touched'] >= x['files'])} of {len(solved)} solves the agent "
           "changed every source file of the reference fix: the report led it to all affected places."]
    counts: dict[str, int] = {}
    for x in solved:
        for w in x["why"]:
            counts[w] = counts.get(w, 0) + 1
    out += ["", "### Why solved tasks were too easy (measured; fix the most common first)"]
    for w, c in sorted(counts.items(), key=lambda kv: -kv[1]):
        out.append(f"- **{w}** in {c} of {len(solved)} solved tasks -> {PASS_RULES[w]}.")
    out += ["", "| Task | Family | Fix | Security tests | Techniques used | Solved by | Attempt | Minutes | Why it passed |",
            "|---|---|---|---|---|---|---|---|---|"]
    for x in sorted(solved, key=lambda x: x["mins"]):
        why = "; ".join(f"{w} ({x['touched']}/{x['files']} fix files changed)" if w == "coverage gap" else
                        f"{w}: {', '.join(x['leaks'][:3])}" if w == "report points at the code" else w for w in x["why"])
        out.append(f"| {x['pkg']} | {x['family']} | {x['shape']} | {x['sec']} | "
                   f"{', '.join(str(t) for t in x['techs']) or '-'} | {x['solver']} | {x['attempt']} | {x['mins']} | "
                   f"{why or '-'} |")
    return "\n".join(out) + "\n"


def render_failure_map(rows: list[dict]) -> str:
    """Per-model guidance for the task generator: task types each model failed, timed out on, or solved."""
    out = ["## Model failure map (deterministic, rebuilt after every evaluation)",
           "Task type = vulnerability family; fix breadth (files / dirs / lines). Timeouts are not failures."]
    for tag, name in MODELS:
        fails = [r for r in rows if r["per"][tag]["verdict"] in ("failed", "failed+timed_out")]
        tos = [r for r in rows if r["per"][tag]["verdict"] == "timed_out"]
        wins = [r for r in rows if r["per"][tag]["verdict"] == "solved"]
        out.append(f"### {name}")
        out.append(f"- FAILED on ({len(fails)}): " + (" | ".join(
            f"{r['type']['label']} - {r['per'][tag]['how']}" for r in fails) or "none yet"))
        out.append(f"- Timed out on ({len(tos)}): " + (" | ".join(r["type"]["label"] for r in tos) or "none"))
        fams = {}
        for r in wins:
            fams[r["type"]["family"]] = fams.get(r["type"]["family"], 0) + 1
        out.append(f"- Solved ({len(wins)}), by vulnerability family: "
                   + (", ".join(f"{k} x{v}" for k, v in sorted(fams.items(), key=lambda kv: -kv[1])) or "none"))
    both = [r for r in rows if all(r["per"][t]["verdict"] in ("failed", "failed+timed_out") for t, _ in MODELS)]
    out.append("### Broke BOTH (replicate this shape): " + (" | ".join(r["type"]["label"] for r in both) or "none yet"))
    return "\n".join(out) + "\n"


def main() -> None:
    cfg = Config.load()
    rows = collect(cfg)
    (cfg.root / "C_RESULTS.md").write_text(render_results(rows) + render_failure_details(cfg, rows))
    learn = learning_rows(cfg, rows)      # the generator's knowledge never learns from withdrawn (defective) tasks
    (cfg.data_dir / "knowledge" / "model_failure_map.md").write_text(render_failure_map(learn))
    (cfg.data_dir / "knowledge" / "technique_scoreboard.md").write_text(render_technique_scoreboard(cfg, learn))
    (cfg.data_dir / "knowledge" / "solved_profile.md").write_text(render_solved_profile(cfg, learn))
    print(render_failure_map(learn))


if __name__ == "__main__":
    main()
