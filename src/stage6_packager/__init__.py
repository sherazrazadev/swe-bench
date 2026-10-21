"""Stage 6 - Packager: tasks accepted by stage 5 -> data/05_accepted_harbor/<task>/ (strict Harbor layout)."""
from __future__ import annotations

import argparse

from src.common.config import Config


def run(cfg: Config, args: argparse.Namespace) -> int:
    from src.stage6_packager.harbor_packager import main

    argv = []
    if args.only:
        argv += ["--only", *args.only]
    if args.skip_final_oracle:
        argv.append("--skip-final-oracle")
    return main(argv, cfg)
