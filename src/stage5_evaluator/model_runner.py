"""Stage 5 - Evaluator: the pass@3 = 0 gate on DeepSeek V4.1 Flash and Xiaomi MiMo-V2.6-Pro.

STAGED, to waste no compute: phase A runs attempt 1 of BOTH models concurrently. The moment a model scores 1.0, pass@3 = 0
is impossible and THAT MODEL's remaining attempts are cancelled - but the OTHER model keeps running all its attempts
(2026-10-19: a task one model solves and the other fails is the best pattern data the knowledge loop gets; the old
cross-model cancel threw it away as CancelledError). Phase B (the remaining EVAL_ATTEMPTS-1 attempts) runs for every
model that neither solved nor errored in phase A. The task's verdict is unchanged: any clean solve by any model still
rejects it. Several tasks run in parallel, bounded by a
container budget (--max-containers / $MAX_CONTAINERS). Everything lands under
data/04_eval_runs/<OSV-ID>/<model-tag>/<job>/<trial>/ (agent trajectory, logs, verifier output).

Both models use the same harness by default: Harbor's `claude-code` agent pointed at each vendor's Anthropic-compatible API
(DeepSeek with --effort max). WebSearch/WebFetch are disabled and the container's network is an allowlist containing ONLY the
two vendor API hosts, so the model cannot browse or fetch anything. (EVAL_AGENT=terminus-2 = host-side agent, fully offline.)

Decision (StateManager, stage "stage5_evaluator")
  REJECTED_TOO_EASY   any attempt on any model scored 1.0 (full reward; partial scores do not count as solved)
  FAILED              could not obtain the full set of valid attempts (errors/missing trials); retried
  DONE                all attempts on every model scored < 1.0 - awaiting trial analysis (separate, resumable step)
  then a DETERMINISTIC verdict (no AI judge, trial_analysis.attribute_attempt) decides the final status:
    ACCEPTED              every attempt of every model is a counted model failure: graded with every hidden test reported,
                          no harness/API exception, timeouts only under TIMEOUT_POLICY=count at the full budget, the agent
                          really worked, no tampering with the grading files
    NEEDS_REVIEW          anything else (the reason is recorded) - a human decides
  A partial fix is a failure (e.g. 5 of 6 attack variants closed), and so is a fix that breaks a legitimate behaviour.
  Failure classes come from the verifier's score breakdown: hole_still_open / over_correction / hole_open_and_broke_features.
  An attempt that ended in a non-timeout exception is ungraded for the verdict (an `error`, retried), even if a score exists.
  (Optional LLM notes on WHY a task was solved/split feed the lessons file only; they never decide acceptance.)

Every outcome is also written to data/knowledge/ (task_outcomes.jsonl, results.md) and, at the end of a run, the lessons
file skills/lessons_learned.md is refreshed so the next generation round knows what the models solve.
"""
from __future__ import annotations

import argparse
import json
import os
import logging
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional

import requests

from src.common import knowledge
from src.common.config import Config, ConfigError, ModelEndpoint
from src.common.harbor import HarborUnavailable, Trial, docker_disk_report, preflight, read_trials, run_harbor
from src.common.llm import CliBackend, QuotaExhausted
from src.common.logging_setup import configure_logging
from src.common.state_manager import StateManager, Status
from src.stage4_oracle_validator.oracle_runner import STAGE as STAGE4
from src.stage5_evaluator.trial_analysis import (TIMEOUT_NOT_COUNTED, agent_steps, analyze_solved, analyze_split,
                                                 attribute_attempt, tamper_signals)
from src.stage6_packager.harbor_packager import TASK_DIRNAME, VERIFY_BUDGET_SEC

log = logging.getLogger(__name__)

STAGE = "stage5_evaluator"
MAX_EVAL_TRIES = 3


class ContainerBudget:
    """Counting semaphore with all-or-nothing acquisition: a phase takes the slots for ALL its containers at once, so
    concurrent tasks can never deadlock each other while holding partial allocations."""

    def __init__(self, total: int):
        self.total, self._free, self._cv = total, total, threading.Condition()

    def acquire(self, n: int) -> None:
        n = min(n, self.total)
        with self._cv:
            while self._free < n:
                self._cv.wait()
            self._free -= n

    def release(self, n: int) -> None:
        with self._cv:
            self._free = min(self.total, self._free + min(n, self.total))
            self._cv.notify_all()


def check_endpoint(ep: ModelEndpoint) -> None:
    """One tiny chat completion with the Bearer key; fails fast on a bad key / model id. Skipped when the vendor's
    endpoint is built into the Harbor agent (e.g. MiMo's own CLI) and therefore unknown to us."""
    if not ep.check_url:
        log.info("Endpoint not pre-checked (built into the %s agent)", ep.agent, extra={"endpoint": ep.masked()})
        return
    model = ep.model.split("/")[-1]
    try:
        r = requests.post(f"{ep.check_url}/chat/completions", timeout=90,
                          headers={"Authorization": f"Bearer {ep.api_key}", "Content-Type": "application/json"},
                          json={"model": model, "messages": [{"role": "user", "content": "ping"}], "max_tokens": 8})
    except requests.RequestException as e:
        raise ConfigError(f"{ep.tag}: cannot reach {ep.check_url}: {e}") from e
    if r.status_code == 401:
        raise ConfigError(f"{ep.tag}: HTTP 401 - API key rejected by {ep.check_url}")
    if r.status_code != 200:
        raise ConfigError(f"{ep.tag}: HTTP {r.status_code} from {ep.check_url}: {r.text[:200]}")


def attempt_outcome(t: Trial) -> str:
    """pass / fail / error for the verdict. A full reward is a solve however the run ended; a lower score only counts as
    a failure if the run ended normally or by the agent time limit (an API/harness crash mid-run is not the model's fault)."""
    if t.reward is not None and t.reward >= 1.0:
        return "pass"
    if t.reward is None or (t.exception and not t.timed_out):
        return "error"
    return "fail"


def summarize_attempts(trials: list[Trial], expected: int) -> dict:
    rewards = [t.reward for t in trials if t.reward is not None]
    outcomes = [attempt_outcome(t) for t in trials]
    return {
        "expected": expected,
        "attempts": [{"trial": t.path.name, "outcome": o, "reward": t.reward, "exception": t.exception,
                      "timed_out": t.timed_out, "timeout_budget": t.timeout_budget, "agent_s": t.agent_secs}
                     for t, o in zip(trials, outcomes)],
        "passes": outcomes.count("pass"),
        "fails": outcomes.count("fail"),
        "errors": outcomes.count("error") + max(0, expected - len(trials)),
        "rewards": rewards,
        "best_reward": max(rewards) if rewards else None,
    }


def decide(per_model: dict[str, dict]) -> tuple[Status, str]:
    solved = [tag for tag, s in per_model.items() if s["passes"] > 0]
    if solved:
        return Status.REJECTED_TOO_EASY, f"solved by {', '.join(solved)}"
    incomplete = {tag: s["errors"] for tag, s in per_model.items() if s["errors"] or s["fails"] < s["expected"]}
    if incomplete:
        return Status.FAILED, f"incomplete attempts (errors per model): {incomplete}"
    return Status.DONE, "all attempts failed on every model; awaiting trial analysis"


def _models_brief(per_model: dict[str, dict]) -> dict:
    return {t: {"rewards": s["rewards"], "best": s["best_reward"], "passes": s["passes"], "errors": s["errors"]}
            for t, s in per_model.items()}


def evaluate_task(env_dir: Path, cfg: Config, endpoints: list[ModelEndpoint], backend: Optional[CliBackend],
                  model: str, state: StateManager, budget: ContainerBudget) -> Status:
    osv_id = env_dir.name
    task = env_dir / TASK_DIRNAME
    out = cfg.stage_dir(5) / osv_id
    stamp = time.strftime("%Y%m%d-%H%M%S")

    def run_phase(ep: ModelEndpoint, suffix: str, k: int, cancel: threading.Event) -> tuple[str, list[Trial], str]:
        conc = max(1, min(k, budget.total // max(1, len(endpoints))))
        waves = -(-k // conc)                       # attempts run in ceil(k / concurrent) waves
        job = run_harbor(
            cfg.harbor_bin, task, ep.agent, out / ep.tag, f"{ep.tag}-{stamp}-{suffix}",
            attempts=k, concurrent=conc, model=ep.harbor_model, agent_kwargs=ep.agent_kwargs,
            # Key travels via the child environment only (never argv, never the log file).
            extra_env=ep.env, agent_env=ep.agent_env, timeout=waves * (cfg.agent_timeout_sec + VERIFY_BUDGET_SEC) + 1800,
            log_path=out / ep.tag / f"harbor_stdout_{suffix}.log", cancel=cancel)
        return ep.tag, read_trials(job), job.name

    def phase(suffix: str, k: int, eps: Optional[list[ModelEndpoint]] = None) -> dict[str, tuple[list[Trial], str]]:
        eps = eps if eps is not None else endpoints
        slots = len(eps) * max(1, min(k, budget.total // max(1, len(endpoints))))
        budget.acquire(slots)                       # wait until this phase's containers fit in the budget
        cancels = {ep.tag: threading.Event() for ep in eps}
        done = threading.Event()

        def watch() -> None:
            """A model reaching 1.0 settles ITS OWN remaining attempts (pass@3 > 0 is decided for it) - the other
            model keeps running, so the knowledge loop still learns whether the task defeats it."""
            jobs_ = {ep.tag: out / ep.tag / f"{ep.tag}-{stamp}-{suffix}" for ep in eps}
            while not done.wait(15):
                for tag, j in jobs_.items():
                    if cancels[tag].is_set():
                        continue
                    solved = [t for t in read_trials(j) if t.reward is not None and t.reward >= 1.0]
                    if solved:
                        log.info("Solved - cancelling this model's remaining attempts (other models keep running)",
                                 extra={"osv_id": osv_id, "model": tag, "trial": solved[0].path.name})
                        cancels[tag].set()
                if all(c.is_set() for c in cancels.values()):
                    return

        watcher = threading.Thread(target=watch, daemon=True)
        watcher.start()
        try:
            with ThreadPoolExecutor(max_workers=len(eps)) as pool:      # the target models at once
                return {tag: (trials, job)
                        for tag, trials, job in pool.map(lambda ep: run_phase(ep, suffix, k, cancels[ep.tag]), eps)}
        finally:
            done.set()
            budget.release(slots)

    trials: dict[str, list[Trial]] = {ep.tag: [] for ep in endpoints}
    jobs: dict[str, list[str]] = {ep.tag: [] for ep in endpoints}

    def absorb(res: dict[str, tuple[list[Trial], str]]) -> None:
        for tag, (trs, job) in res.items():
            trials[tag] += trs
            jobs[tag].append(job)

    def stats_for(expected) -> dict[str, dict]:
        out_ = {}
        for ep in endpoints:
            st = summarize_attempts(trials[ep.tag], expected[ep.tag] if isinstance(expected, dict) else expected)
            st.update({"model": ep.model, "jobs": jobs[ep.tag]})
            out_[ep.tag] = st
        return out_

    absorb(phase("a", 1))                                   # phase A: attempt 1 of each model
    per_model = stats_for(1)
    status, detail = decide(per_model)
    if status in (Status.DONE, Status.REJECTED_TOO_EASY) and cfg.eval_attempts > 1:
        # Remaining attempts for every model that neither solved nor errored - ALSO when another model already solved
        # the task: the task stays rejected, but the full per-model record ("only_<model>" pattern) feeds the
        # knowledge loop with what defeats the model that failed (user decision 2026-10-19).
        rest = [ep for ep in endpoints if per_model[ep.tag]["passes"] == 0 and per_model[ep.tag]["errors"] == 0]
        if rest:
            absorb(phase("b", cfg.eval_attempts - 1, rest))
            kept = {ep.tag for ep in rest}
            per_model = stats_for({ep.tag: (cfg.eval_attempts if ep.tag in kept else 1) for ep in endpoints})
            status, detail = decide(per_model)
    if status is Status.REJECTED_TOO_EASY:
        # A solve that came from editing the grading inputs is reward hacking, not a solve: a human looks at it.
        hacked = {f"{tag}/{t.path.name}": sig for tag, trs in trials.items() for t in trs if attempt_outcome(t) == "pass"
                  for sig in [tamper_signals(t.path, agent_steps(t.path)[0])] if sig}
        solved_clean = [tag for tag, trs in trials.items()
                        if any(attempt_outcome(t) == "pass" and f"{tag}/{t.path.name}" not in hacked for t in trs)]
        if hacked and not solved_clean:
            status, detail = Status.NEEDS_REVIEW, f"every solve shows tampering with grading files: {hacked}"[:600]
    for tag, st in per_model.items():
        log.info("Model finished", extra={"osv_id": osv_id, "model": tag, "pass": st["passes"], "fail": st["fails"],
                                          "error": st["errors"], "best": st["best_reward"], "phases": len(st["jobs"])})

    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.json").write_text(json.dumps(
        {"osv_id": osv_id, "status": status.value, "detail": detail, "models": per_model}, indent=2))
    state.mark(STAGE, osv_id, status, detail, payload={"models": _models_brief(per_model)})

    verdicts = knowledge.model_verdicts(per_model, cfg.timeout_policy)
    pattern = knowledge.pattern_of(verdicts)
    extra: dict = {"models": _models_brief(per_model), "model_verdicts": verdicts, "pattern": pattern,
                   **knowledge.task_profile(cfg, osv_id, out)}
    if backend is not None and (pattern.startswith("only_") or "_timed_out_" in pattern):
        # One model failed, the other solved: record WHAT defeated the failing one (a reusable technique).
        failed_tag = next((t for t, v in verdicts.items() if v == "failed"), None) or \
            next(t for t, v in verdicts.items() if v == "timed_out")
        solved_tag = next((t for t, v in verdicts.items() if v == "solved"), None) or \
            next(t for t in verdicts if t != failed_tag)
        try:
            extra["technique"] = analyze_split(env_dir, out, backend, model, failed_tag, solved_tag)
        except QuotaExhausted:
            raise
        except Exception as e:
            log.warning("Split analysis failed", extra={"osv_id": osv_id, "error": repr(e)})
    elif backend is not None and pattern == "both_solve":
        try:
            extra["why_easy"] = analyze_solved(env_dir, out, backend, model)
        except QuotaExhausted:
            raise
        except Exception as e:
            log.warning("Could not analyse why the task was solved", extra={"osv_id": osv_id, "error": repr(e)})
    log.info("Pattern", extra={"osv_id": osv_id, "pattern": pattern, "verdicts": verdicts})
    knowledge.record_outcome(cfg, osv_id, STAGE, status.value, detail, **extra)
    return status


def deterministic_verdict(eval_dir: Path, task_dir: Path, cfg: Config) -> tuple[Status, str, dict]:
    """ACCEPTED only if, on every model, exactly the expected number of attempts exist and EVERY one is a counted model
    failure (trial_analysis.attribute_attempt: graded with all hidden tests reported, no harness/API exception, timeout
    only under TIMEOUT_POLICY=count at the full budget, agent really worked, no tampering). If the only non-failures are
    timeouts under TIMEOUT_POLICY=exclude -> REJECTED (pass@3 = 0 not proven). Anything else -> NEEDS_REVIEW with the
    reasons. No LLM is involved in this decision."""
    summary = json.loads((eval_dir / "summary.json").read_text())
    problems: list[str] = []
    reports: dict[str, dict] = {}
    for tag, st in summary["models"].items():
        trials_ = [t for job in st.get("jobs", []) if (eval_dir / tag / job).is_dir()
                   for t in sorted(d for d in (eval_dir / tag / job).iterdir() if d.is_dir())]
        counted = 0
        for trial in trials_:
            rep = attribute_attempt(trial, task_dir, cfg.timeout_policy, cfg.full_budget_sec)
            reports[f"{tag}/{trial.parent.name}/{trial.name}"] = rep
            if rep["solved"]:
                problems.append(f"{tag}/{trial.name}: solved (reward {rep['reward']})")
            elif rep["counted"]:
                counted += 1
            else:
                problems.append(f"{tag}/{trial.name}: " + "; ".join(rep["problems"]))
        if counted < st.get("expected", cfg.eval_attempts):
            problems.insert(0, f"{tag}: {counted}/{st.get('expected', cfg.eval_attempts)} attempts are counted model failures")
    classes = {k: ("timed_out" if r["timed_out"] and not r["solved"] else r["class"]) for k, r in reports.items()}
    (eval_dir / "attribution.json").write_text(json.dumps(
        {"timeout_policy": cfg.timeout_policy, "full_budget_sec": cfg.full_budget_sec, "attempts": reports}, indent=2))
    uncounted = [r for r in reports.values() if not r["counted"] and not r["solved"]]
    if uncounted and all(r["problems"] == [TIMEOUT_NOT_COUNTED] for r in uncounted):
        # The agreed rule: a timeout is not a failure, so pass@3 = 0 is not proven -> the task is rejected (not a review).
        who = sorted({k.split("/")[0] for k, r in reports.items() if r in uncounted})
        return (Status.REJECTED, f"{', '.join(who)} timed out in {len(uncounted)} attempt(s); a timeout is not counted "
                                 f"as a model failure, so pass@3 = 0 is not proven", classes)
    if problems:
        return Status.NEEDS_REVIEW, "; ".join(problems)[:600], classes
    dist: dict[str, int] = {}
    for c in classes.values():
        dist[c] = dist.get(c, 0) + 1
    return Status.ACCEPTED, f"every attempt is a counted model failure on every model {dist}", classes


def finalize(osv_id: str, cfg: Config, state: StateManager) -> Optional[Status]:
    """Deterministic final verdict for a task whose attempts all failed (no AI judge)."""
    eval_dir = cfg.stage_dir(5) / osv_id
    try:
        status, detail, classes = deterministic_verdict(eval_dir, cfg.stage_dir(3) / osv_id / TASK_DIRNAME, cfg)
    except (OSError, json.JSONDecodeError, KeyError) as e:
        log.warning("Verdict failed; will retry next run", extra={"osv_id": osv_id, "error": repr(e)})
        return None
    state.mark(STAGE, osv_id, status, detail)
    knowledge.record_outcome(cfg, osv_id, STAGE, status.value, detail, failure_classes=classes,
                             pattern=_pattern_from_classes(classes), **knowledge.task_profile(cfg, osv_id, eval_dir))
    log.info("Verdict", extra={"osv_id": osv_id, "status": status.value, "detail": detail})
    return status


def _pattern_from_classes(classes: dict[str, str]) -> str:
    """both_fail only when no model's runs are all timeouts (a timeout is not a failure)."""
    per: dict[str, set[str]] = {}
    for k, c in classes.items():
        per.setdefault(k.split("/")[0], set()).add(c)
    timed = sorted(t for t, cs in per.items() if cs == {"timed_out"})
    if not timed:
        return "both_fail"
    failed = sorted(t for t in per if t not in timed)
    return f"{'_'.join(failed)}_fails_{'_'.join(timed)}_timed_out" if failed else "both_timed_out"


def reverdict(cfg: Config, osv_id: str, apply: bool = False) -> tuple[Status, str]:
    """Re-run the deterministic verdict on a task's recorded attempts (e.g. after the timeout rule changed) instead of
    editing the state DB by hand. Without `apply` it only reports. With `apply`, an ACCEPTED task is (re)queued for
    stage 6 packaging and a non-accepted one is removed from 05_accepted_harbor and provenance.json."""
    from src.stage6_packager.harbor_packager import STAGE as STAGE6, unpublish
    eval_dir = cfg.stage_dir(5) / osv_id
    status, detail, classes = deterministic_verdict(eval_dir, cfg.stage_dir(3) / osv_id / TASK_DIRNAME, cfg)
    if apply:
        with StateManager(cfg.state_db) as state:
            state.mark(STAGE, osv_id, status, f"re-verdict ({cfg.timeout_policy}): {detail}")
            state.reset(STAGE6, osv_id)
        if status is not Status.ACCEPTED:
            unpublish(cfg, osv_id)
        knowledge.record_outcome(cfg, osv_id, STAGE, status.value, f"re-verdict ({cfg.timeout_policy}): {detail}",
                                 failure_classes=classes, pattern=_pattern_from_classes(classes),
                                 **knowledge.task_profile(cfg, osv_id, eval_dir))
    return status, detail


def write_global_summary(cfg: Config) -> None:
    root = cfg.stage_dir(5)
    rows = {}
    for p in sorted(root.glob("*/summary.json")):
        try:
            rows[p.parent.name] = json.loads(p.read_text())
        except json.JSONDecodeError:
            continue
    (root / "summary.json").write_text(json.dumps(rows, indent=2))


def parse_args(argv: Optional[list[str]]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Stage 5: run target models against validated tasks")
    p.add_argument("--only", nargs="+")
    p.add_argument("--workers", type=int, default=None, help="task threads (default: max(2, budget)); containers are bounded by --max-containers")
    p.add_argument("--max-containers", type=int, default=None,
                   help="concurrent task containers allowed (default $MAX_CONTAINERS, 4). Phase A needs 2 per task, phase B needs 2 x (attempts-1)")
    p.add_argument("--skip-api-check", action="store_true", help="skip the 1-token endpoint ping")
    p.add_argument("--skip-analysis", action="store_true", help="skip the optional LLM learning notes (why solved / split); the verdict is always deterministic")
    p.add_argument("--skip-lessons", action="store_true", help="do not refresh skills/lessons_learned.md at the end")
    p.add_argument("--model", default=None, help="Claude model for analysis/lessons (default $ANTHROPIC_MODEL)")
    p.add_argument("--dry-run", action="store_true", help="list tasks and endpoints, run nothing")
    p.add_argument("--follow", action="store_true",
                   help="keep running while a generation/validation run (stages 3-4) is active: start each task as soon "
                        "as it is validated, up to --workers at once")
    p.add_argument("--follow-poll", type=int, default=60, help="seconds between checks for newly validated tasks")
    return p.parse_args(argv)


def upstream_running() -> bool:
    """True while a pipeline run that still generates/validates tasks (stage 3 or 4) is alive."""
    import os
    import subprocess as sp
    out = sp.run(["pgrep", "-fl", "run_pipeline.py"], capture_output=True, text=True).stdout
    return any(("--to-stage 4" in l or "--stage 3" in l or "--stage 4" in l) and str(os.getpid()) not in l.split()[0]
               for l in out.splitlines())


def refresh_knowledge(cfg: Config, osv_id: str) -> None:
    """After a task's evaluation ends: the automatic failure write-up (if a model had a counted failure), then the
    results report, failure map and technique scoreboard - so the generation running in parallel learns from it at once.
    Knowledge only; the verdict is already decided."""
    try:
        from src.stage5_evaluator import failure_analyst
        failure_analyst.analyse(cfg, osv_id)
    except Exception as e:
        log.warning("Failure analysis failed", extra={"osv_id": osv_id, "error": repr(e)[:200]})
    try:
        from src.common import results_report
        results_report.main()
    except Exception as e:
        log.warning("Results report rebuild failed", extra={"error": repr(e)[:200]})
    try:
        from src.common import knowledge
        knowledge.generator_canary(cfg)
    except Exception as e:
        log.warning("Generator canary rebuild failed", extra={"error": repr(e)[:200]})


def main(argv: Optional[list[str]] = None, cfg: Optional[Config] = None) -> int:
    cfg = cfg or Config.load()
    args = parse_args(argv)
    if not logging.getLogger().handlers:
        configure_logging()

    with StateManager(cfg.state_db) as state:
        ids = sorted(state.keys(STAGE4, Status.DONE))
        if args.only:
            ids = [i for i in ids if i in set(args.only)]
        todo = [i for i in ids if state.should_process(STAGE, i, MAX_EVAL_TRIES)]
        if args.dry_run:
            print("\n".join(todo))
            return 0
        pending = sorted(i for i in state.keys(STAGE, Status.DONE) if not args.only or i in set(args.only))
        if not todo and not pending and not (args.follow and upstream_running()):
            log.info("Nothing to evaluate")
            return 0

        endpoints: list[ModelEndpoint] = []
        if todo or args.follow:   # only touch Docker / the vendor APIs when there is real work to do
            try:
                endpoints = cfg.eval_endpoints()
                preflight(cfg.harbor_bin)
                if not args.skip_api_check:
                    for ep in endpoints:
                        check_endpoint(ep)
                        log.info("Endpoint OK", extra={"endpoint": ep.masked()})
            except (ConfigError, HarborUnavailable) as e:
                log.error("Stage 5 cannot run: %s", e)
                return 1
        n_models = len(endpoints) or 2
        peak_per_task = n_models * max(1, cfg.eval_attempts - 1)       # phase B is the widest
        budget = args.max_containers or cfg.max_containers
        workers = args.workers or max(2, budget)           # threads; the ContainerBudget is what bounds containers
        container_budget = ContainerBudget(budget)
        log.info("Evaluating", extra={"validated": len(ids), "to_evaluate": len(todo), "pending_analysis": len(pending),
                                      "attempts": cfg.eval_attempts, "parallel_tasks": workers,
                                      "container_budget": budget, "peak_containers_per_task": peak_per_task})
        from src.common.llm import reviewer_backend, review_vendor
        # only when notes or lessons need it: GitHub Actions runners have no `claude` binary, and CliBackend exits
        # when it is missing (the trial itself never needs it)
        backend, review_model = (None, "") if (args.skip_analysis and args.skip_lessons) else reviewer_backend(cfg, 900.0)
        analysis_backend = None if args.skip_analysis else backend   # learning notes only, never the verdict
        model = args.model or (review_model if review_vendor() != "claude" else cfg.anthropic_model)

        counts: dict[str, int] = {}
        failed_ids: list[str] = []

        def work(osv_id: str) -> tuple[str, Status]:
            env_dir = cfg.stage_dir(3) / osv_id
            try:
                return osv_id, evaluate_task(env_dir, cfg, endpoints, analysis_backend, model, state, container_budget)
            except (HarborUnavailable, QuotaExhausted):
                raise
            except Exception as e:
                log.exception("evaluation crashed", extra={"osv_id": osv_id})
                state.mark(STAGE, osv_id, Status.FAILED, f"unexpected: {e!r}")
                return osv_id, Status.FAILED

        def tally(osv_id: str, st: Status) -> None:
            counts[st.value] = counts.get(st.value, 0) + 1
            if st is Status.FAILED:
                failed_ids.append(osv_id)

        try:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                if not args.follow:
                    for osv_id, st in pool.map(work, todo):
                        tally(osv_id, st)
                else:
                    # Follow mode: start each task as soon as stage 4 validates it (up to `workers` at once) while the
                    # generation/validation run is still going; stop when that run has ended and nothing is left.
                    in_flight: dict = {}
                    started: list[str] = []
                    from concurrent.futures import ThreadPoolExecutor as _TPE
                    kpool = _TPE(max_workers=1)
                    while True:
                        # a task started earlier in this process runs again only after an operator reset its stage-5
                        # record (e.g. a cancelled run), never automatically
                        ready = [i for i in sorted(state.keys(STAGE4, Status.DONE))
                                 if (not args.only or i in set(args.only)) and i not in in_flight
                                 and (i not in started or state.get(STAGE, i) is None)
                                 and state.should_process(STAGE, i, MAX_EVAL_TRIES)]
                        for i in ready[: max(0, workers - len(in_flight))]:
                            log.info("Starting evaluation", extra={"osv_id": i, "in_flight": len(in_flight) + 1})
                            in_flight[i] = pool.submit(work, i)
                            started.append(i)
                        for i, fut in list(in_flight.items()):
                            if fut.done():
                                osv_id, st = fut.result()
                                tally(osv_id, st)
                                del in_flight[i]
                                if st is Status.DONE:          # all attempts failed: deterministic verdict now
                                    final = finalize(osv_id, cfg, state)
                                    if final:
                                        tally(osv_id, final)
                                kpool.submit(refresh_knowledge, cfg, osv_id)   # learn from it while the run goes on
                        if not in_flight and not ready and not upstream_running():
                            break
                        time.sleep(args.follow_poll)
                    kpool.shutdown(wait=True)
                    todo = started
            for osv_id in sorted(i for i in state.keys(STAGE, Status.DONE) if not args.only or i in set(args.only)):
                final = finalize(osv_id, cfg, state)
                if final:
                    counts[final.value] = counts.get(final.value, 0) + 1
                    counts["done"] = max(0, counts.get("done", 0) - 1)
            if not args.follow:          # follow mode already refreshed after each task
                for osv_id in todo:
                    refresh_knowledge(cfg, osv_id)
        except HarborUnavailable as e:
            log.error("Harbor unavailable mid-run: %s", e)
            return 1
        except QuotaExhausted as e:
            log.error("Claude quota exhausted - rerun later to resume: %s", e)
            return 1
        except KeyboardInterrupt:
            log.error("Interrupted")
            return 130
        finally:
            write_global_summary(cfg)

        log.info("Stage 5 done", extra=counts)
        disk = docker_disk_report()
        if disk:
            log.info("Docker disk usage:\n%s", disk)
        rows = []
        for oid in todo + [i for i in pending if i not in todo]:
            sj = cfg.stage_dir(5) / oid / "summary.json"
            if sj.is_file():
                d = json.loads(sj.read_text())
                st = state.get(STAGE, oid)
                models = " ; ".join(f"{t}: {s['rewards']}" for t, s in d["models"].items())
                rows.append([oid, st.status.value if st else d["status"], models, st.detail if st else d["detail"]])
        knowledge.append_results(cfg, "Stage 5 - DeepSeek / MiMo evaluation", ["task", "status", "rewards per model", "detail"],
                                 rows, notes="counts: " + json.dumps(counts))
        try:      # shared-format ledger (same metrics as the cwe-bench repo), rebuilt from raw trials
            from src.common import ledger
            ledger.main()
        except Exception as e:
            log.warning("Ledger rebuild failed", extra={"error": repr(e)})
        try:      # C_RESULTS.md + the per-model failure map the generator reads (which task type breaks which model)
            from src.common import results_report
            results_report.main()
        except Exception as e:
            log.warning("Results report rebuild failed", extra={"error": repr(e)})

        if not args.skip_lessons and (todo or pending):
            try:
                knowledge.update_lessons(cfg, backend, model)
            except QuotaExhausted:
                log.warning("Quota exhausted - lessons not refreshed this run")
            except Exception as e:
                log.warning("Lessons refresh failed", extra={"error": repr(e)})
    return 0


if __name__ == "__main__":
    sys.exit(main())
