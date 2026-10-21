"""Stage 2 - Screening: data/01_mined -> data/02_screened (see screener.py)."""
from __future__ import annotations

import argparse

from src.common.config import Config


def run(cfg: Config, args: argparse.Namespace) -> int:
    from src.stage2_screening.screener import main

    argv = ["--workers", str(args.workers)]
    if args.published_after:
        argv += ["--published-after", args.published_after]
    if args.ignore_state:
        argv.append("--ignore-state")
    return main(argv, cfg)
