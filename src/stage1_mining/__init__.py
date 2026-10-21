"""Stage 1 - Miner: OSV -> data/01_mined/osv_candidates.json."""
from __future__ import annotations

import argparse

from src.common.config import Config


def run(cfg: Config, args: argparse.Namespace) -> int:
    from src.stage1_mining.osv_miner import main

    argv = ["--limit", str(args.limit)]
    if args.ecosystems:
        argv += ["--ecosystems", *args.ecosystems]
    if args.sources:
        argv += ["--sources", *args.sources]
    if args.ignore_state:
        argv.append("--ignore-state")
    return main(argv, cfg)
