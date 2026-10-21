"""Stage 4 - Oracle validator: prove generated tests against the historical fix (see oracle_runner.py)."""
from __future__ import annotations

import argparse
import os

from src.common.config import Config


def run(cfg: Config, args: argparse.Namespace) -> int:
    from src.stage4_oracle_validator.oracle_runner import main

    # heavy Docker builds: cap from STAGE4_MAX_WORKERS (default 6 = one cycle; 3 builds used < 2 GB of the Docker VM)
    argv = ["--workers", str(min(args.workers, int(os.environ.get("STAGE4_MAX_WORKERS", "6"))))]
    if args.skip_rubric:
        argv.append("--skip-rubric")
    if args.skip_probe:
        argv.append("--skip-probe")
    if args.probe_reject is False:
        argv.append("--no-probe-reject")
    if args.require_existing:
        argv.append("--require-existing")
    if getattr(args, "skip_fix_checks", False):
        argv.append("--skip-fix-checks")
    if getattr(args, "skip_image_scan", False):
        argv.append("--skip-image-scan")
    if args.only:
        argv += ["--only", *args.only]
    return main(argv, cfg)
