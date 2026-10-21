"""Stage 5 - Evaluator: pass@3 = 0 gate on DeepSeek and MiMo (see model_runner.py)."""
from __future__ import annotations

import argparse

from src.common.config import Config


def run(cfg: Config, args: argparse.Namespace) -> int:
    from src.stage5_evaluator.model_runner import main

    argv = []
    if args.only:
        argv += ["--only", *args.only]
    if args.dry_run:
        argv.append("--dry-run")
    if args.skip_analysis:
        argv.append("--skip-analysis")
    if args.skip_lessons:
        argv.append("--skip-lessons")
    if args.max_containers:
        argv += ["--max-containers", str(args.max_containers)]
    if getattr(args, "follow", False):
        argv += ["--follow", "--workers", str(args.workers)]
    return main(argv, cfg)
