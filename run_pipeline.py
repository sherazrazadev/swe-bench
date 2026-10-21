#!/usr/bin/env python3
"""CWE-Bench data factory entry point.

  python run_pipeline.py --stage 1 --limit 50
  python run_pipeline.py --stage 1 2 3
  python run_pipeline.py --from-stage 3 --to-stage 4
  python run_pipeline.py --status
  python run_pipeline.py --stage 1 --reset-state          # forget stage-1 dedupe state, then re-run
  python run_pipeline.py --reverdict GHSA-xxxx [--apply]  # re-run the deterministic stage-5 verdict
"""
from __future__ import annotations

import argparse
import importlib
import logging
import sys
from pathlib import Path
from typing import Optional

from src.common.config import Config
from src.common.logging_setup import configure_logging
from src.common.state_manager import StateManager

log = logging.getLogger("pipeline")

STAGES: dict[int, tuple[str, str, str]] = {
    # number: (module, state key, title)
    1: ("src.stage1_mining", "stage1_mining", "Mining"),
    2: ("src.stage2_screening", "stage2_screening", "Screening"),
    3: ("src.stage3_task_builder", "stage3_task_builder", "Task builder"),
    4: ("src.stage4_oracle_validator", "stage4_oracle_validator", "Oracle validator"),
    5: ("src.stage5_evaluator", "stage5_evaluator", "Evaluator"),
    6: ("src.stage6_packager", "stage6_packager", "Packager"),
}
EXIT_NOT_IMPLEMENTED = 3


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="CWE-Bench task factory", formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=__doc__)
    sel = p.add_argument_group("stage selection")
    sel.add_argument("--stage", type=int, nargs="+", choices=sorted(STAGES), metavar="N", help="stage number(s) 1-6")
    sel.add_argument("--from-stage", type=int, choices=sorted(STAGES))
    sel.add_argument("--to-stage", type=int, choices=sorted(STAGES))
    sel.add_argument("--batch", type=int, metavar="N",
                     help="one-command run: stages 1-6 for the N best candidates (mines max(30, 10*N), pilot N tasks)")
    sel.add_argument("--watch", action="store_true", help="live status board (refreshes every 15s; --once prints it once)")
    sel.add_argument("--once", action="store_true", help=argparse.SUPPRESS)
    sel.add_argument("--status", action="store_true", help="print state counts per stage and exit")
    sel.add_argument("--reset-state", action="store_true", help="clear dedupe state for the selected stage(s) first")

    gen = p.add_argument_group("common")
    gen.add_argument("--data-dir", type=Path, help="override data root (default ./data or $CWE_DATA_DIR)")
    gen.add_argument("--only", nargs="+", help="restrict to these OSV IDs (where supported)")
    gen.add_argument("--dry-run", action="store_true", help="no side effects / API calls where supported")
    gen.add_argument("--workers", type=int, default=4)
    gen.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    gen.add_argument("--json-logs", action="store_true")

    s1 = p.add_argument_group("stage 1")
    s1.add_argument("--limit", type=int, default=50, help="new vulnerabilities to mine (default 50, scale to 400)")
    s1.add_argument("--ecosystems", nargs="+", choices=["PyPI", "npm", "Go", "Packagist"])
    s1.add_argument("--sources", nargs="+", choices=["osv", "ghsa", "huntr"],
                    help="stage 1 feeds (default: osv ghsa huntr, interleaved)")
    s1.add_argument("--ignore-state", action="store_true")

    s2 = p.add_argument_group("stage 2")
    s2.add_argument("--published-after", metavar="YYYY-MM-DD", help="stage 2: skip advisories older than this (memorisation risk)")

    s3 = p.add_argument_group("stage 3")
    s3.add_argument("--pilot", "--max-tasks", dest="max_tasks", type=int, metavar="N",
                    help="stage 3: only build the N best-scored candidates (start with 3-4 before scaling)")
    s3.add_argument("--skip-build-check", action="store_true", help="stage 3: skip the Docker fail-fast install check")
    s3.add_argument("--model", help="Anthropic model for task generation (default $ANTHROPIC_MODEL)")
    s3.add_argument("--allow-unscreened", action="store_true", help="build from stage 1 output when stage 2 is absent")

    s4 = p.add_argument_group("stage 4/5")
    s4.add_argument("--skip-rubric", action="store_true", help="stage 4: skip the LLM task-quality rubric")
    s4.add_argument("--skip-probe", action="store_true", help="stage 4: skip the text-only recall probe")
    s4.add_argument("--probe-reject", action=argparse.BooleanOptionalAction, default=True,
                    help="stage 4: reject tasks where both models name the fix location from the report alone (default on)")
    s4.add_argument("--require-existing", action="store_true", help="stage 4: reject tasks without existing repo tests")
    s4.add_argument("--skip-fix-checks", action="store_true",
                    help="stage 4: do not run the shallow / feature-removal / alternative check patches (not recommended)")
    s4.add_argument("--skip-image-scan", action="store_true", help="stage 4: do not scan the built image for the fix's code")
    s4.add_argument("--skip-analysis", action="store_true", help="stage 5: skip optional LLM learning notes (verdict is always deterministic)")
    s4.add_argument("--max-containers", type=int, help="stage 5: concurrent task containers (default $MAX_CONTAINERS)")
    s4.add_argument("--follow", action="store_true",
                    help="stage 5: run alongside a stages 3-4 run and start each task as soon as it is validated "
                         "(--workers tasks at once)")
    s4.add_argument("--skip-lessons", action="store_true", help="stage 5: do not refresh skills/lessons_learned.md")
    s4.add_argument("--update-lessons", action="store_true", help="refresh skills/lessons_learned.md from recorded outcomes and exit")
    s4.add_argument("--reverdict", nargs="+", metavar="OSV_ID",
                    help="re-run the deterministic stage-5 verdict on recorded attempts (uses $TIMEOUT_POLICY); report only")
    s4.add_argument("--apply", action="store_true", help="with --reverdict: write the new verdict (state, outcomes, packaging)")

    s6 = p.add_argument_group("stage 6")
    s6.add_argument("--skip-final-oracle", action="store_true", help="package without re-running the oracle on the final copy")

    args = p.parse_args(argv)
    if args.only:      # accept "A B" / "A,B" in one argument too (zsh does not word-split an unquoted $IDS)
        import re as _re
        args.only = [x for v in args.only for x in _re.split(r"[\s,]+", v) if x]
    if args.batch:
        args.from_stage, args.to_stage = args.from_stage or 1, args.to_stage or 6
        args.max_tasks = args.max_tasks or args.batch
        args.limit = max(args.limit, 10 * args.batch, 30)
    if not (args.stage or args.from_stage or args.to_stage or args.status or args.update_lessons or args.watch
            or args.reverdict):
        p.error("choose --stage N [N ...], --from-stage/--to-stage, --status, --update-lessons or --reverdict")
    return args


def select_stages(args: argparse.Namespace) -> list[int]:
    if args.stage:
        return sorted(set(args.stage))
    lo, hi = args.from_stage or 1, args.to_stage or max(STAGES)
    if lo > hi:
        raise SystemExit("--from-stage must be <= --to-stage")
    return list(range(lo, hi + 1))


IMPORTANT = ("=== Stage", "Pilot subset", "Build check", "generated", "declined", "FAILED", "Rubric", "Recall probe",
             "Validated", "No verdict", "isolation", "Endpoint", "Model finished", "Pattern", "Verdict", "Packaged",
             "Stage 4 done", "Stage 5 done", "Screening finished", "Wrote output", "cannot run", "exited with code")


def status_board(cfg: Config) -> str:
    """One screen: per-stage counts, what is running right now, recent important events."""
    import json as _json
    import subprocess as _sp
    import time as _time
    lines = [f"CWE-Bench pipeline status   {_time.strftime('%Y-%m-%d %H:%M:%S')}", "=" * 72, "STAGES (task counts by status)"]
    with StateManager(cfg.state_db) as state:
        for n, (_, key, title) in STAGES.items():
            counts = state.counts(key)
            lines.append(f"  {n}. {title:<18} " + (", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "-"))

    def docker_ps(flt: str) -> list[str]:
        try:
            out = _sp.run(["docker", "ps", "--filter", f"name={flt}", "--format", "{{.Names}}  ({{.Status}})"],
                          capture_output=True, text=True, timeout=20).stdout.strip()
            return out.splitlines() if out else []
        except (OSError, _sp.TimeoutExpired):
            return ["(docker not reachable)"]

    lines += ["", "RUNNING NOW"]
    pipe = docker_ps("cwe-")
    lines.append("  pipeline containers: " + (", ".join(p.split()[0] for p in pipe) if pipe else "none"))
    tasks = docker_ps("hb__")
    lines.append(f"  task containers (oracle / DeepSeek / MiMo runs): {len(tasks)}")
    lines += [f"    - {t[:90]}" for t in tasks[:8]]

    log_file = cfg.data_dir / "logs" / "pipeline.jsonl"
    events = []
    if log_file.is_file():
        with open(log_file, "rb") as f:
            f.seek(0, 2)
            f.seek(max(0, f.tell() - 400_000))
            for raw in f.read().decode("utf-8", "ignore").splitlines()[1:]:
                try:
                    e = _json.loads(raw)
                except _json.JSONDecodeError:
                    continue
                if any(k in e.get("msg", "") for k in IMPORTANT) or e.get("level") in ("ERROR", "CRITICAL"):
                    extra = {k: v for k, v in e.items() if k in ("osv_id", "model", "pass", "fail", "best", "status", "risk", "ok", "pattern")}
                    events.append(f"  {e['ts'][11:19]} {e['level'][:4]} {e['msg'][:70]} {extra if extra else ''}")
    lines += ["", "RECENT EVENTS"] + (events[-12:] or ["  (none yet)"])
    res = cfg.data_dir / "knowledge" / "results.md"
    lines += ["", f"RESULTS: {res.relative_to(cfg.root) if res.is_file() else 'none yet'}   |   "
              f"accepted tasks: {cfg.data_dir.relative_to(cfg.root) / '05_accepted_harbor'}"]
    return "\n".join(lines)


def print_status(cfg: Config) -> None:
    with StateManager(cfg.state_db) as state:
        for n, (_, key, title) in STAGES.items():
            counts = state.counts(key)
            print(f"stage {n} {title:<18} {counts or '-'}")


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    cfg = Config.load(args.data_dir)
    configure_logging(args.log_level, args.json_logs, cfg.data_dir / "logs" / "pipeline.jsonl")

    if args.status:
        print_status(cfg)
        return 0
    if args.watch:
        import time as _time
        while True:
            board = status_board(cfg)
            print(board if args.once else "\033[2J\033[H" + board, flush=True)
            if args.once:
                return 0
            _time.sleep(15)
    if args.reverdict:
        from src.stage5_evaluator.model_runner import reverdict
        for osv_id in args.reverdict:
            status, detail = reverdict(cfg, osv_id, apply=args.apply)
            print(f"{osv_id}: {status.value}{' (applied)' if args.apply else ' (not applied; add --apply)'}"
                  f"  [TIMEOUT_POLICY={cfg.timeout_policy}, full budget {cfg.full_budget_sec}s]\n  {detail}")
        return 0
    if args.update_lessons:
        from src.common import knowledge
        from src.common.llm import CliBackend
        ok = knowledge.update_lessons(cfg, CliBackend(cfg.claude_bin, 900.0), cfg.anthropic_model)
        print("lessons updated" if ok else "nothing to update (no outcomes recorded yet)")
        return 0

    stages = select_stages(args)
    if args.reset_state:
        with StateManager(cfg.state_db) as state:
            for n in stages:
                removed = state.reset(STAGES[n][1])
                log.info("State reset", extra={"stage": n, "removed": removed})

    for n in stages:
        module, _, title = STAGES[n]
        log.info("=== Stage %d: %s ===", n, title)
        try:
            rc = importlib.import_module(module).run(cfg, args)
        except NotImplementedError as e:
            log.error("%s", e)
            return EXIT_NOT_IMPLEMENTED
        except KeyboardInterrupt:
            log.error("Interrupted")
            return 130
        except Exception:
            log.exception("Stage %d crashed", n)
            return 1
        if rc != 0:
            log.error("Stage %d exited with code %d; stopping", n, rc)
            return rc
    return 0


if __name__ == "__main__":
    sys.exit(main())
