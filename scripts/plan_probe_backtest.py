#!/usr/bin/env python3
"""Plan-probe BACKTEST (2026-10-20): would a cheap pre-trial check have told the hard tasks from the easy ones?

For every evaluated task with a known outcome, each target model (DeepSeek, MiMo) gets the task's report plus the
repository's source-file LIST (no file contents) and is asked for a repair plan: every file it would change to fix the
problem completely. Coverage = share of the real fix places (task_metadata fix_places, else the reference fix's source
files that exist before the fix) named in the plan. Hypothesis: if both models' plans already cover every fix place,
nothing is hidden and the task is easy; tasks that broke a model should show lower coverage.

Only the target models' own APIs are called (never Claude). Nothing in the pipeline changes.

    .venv/bin/python scripts/plan_probe_backtest.py --out data/logs/<run dir>
"""
from __future__ import annotations

import argparse
import json
import os
import re
import statistics
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.common.classify import classify  # noqa: E402
from src.common.config import Config  # noqa: E402
from src.common.llm import extract_json_object  # noqa: E402
from src.common.results_report import MODELS, collect, learning_rows  # noqa: E402
from src.stage4_oracle_validator.plan_probe import PROMPT, ask, coverage, fix_places, source_files  # noqa: E402,F401

MAX_LIST_CHARS = 60_000           # larger file lists are skipped, not truncated (truncation could bias the result)
SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "third_party"}











def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--workers", type=int, default=6)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    cfg = Config.load()
    eps = [ep for ep in cfg.eval_endpoints() if ep.check_url]
    meta = {}
    for f in ("data/01_mined/osv_candidates.json", "data/02_screened/screened.json"):
        for r in json.loads((ROOT / f).read_text())["vulnerabilities"]:
            meta.setdefault(r["osv_id"], r)

    jobs, skipped = [], []
    for row in learning_rows(cfg, collect(cfg)):
        k = row["task"]
        env = cfg.stage_dir(3) / k
        broke = any(row["per"][t]["verdict"].startswith("failed") for t, _ in MODELS)
        if not (env / "repo").is_dir() or not (env / "instruction.md").is_file():
            skipped.append((k, broke, "repo or report not on disk"))
            continue
        files = source_files(env / "repo", (meta.get(k) or {}).get("ecosystem", ""))
        listing = "\n".join(files)
        places = fix_places(env, set(files))
        if len(listing) > MAX_LIST_CHARS:
            skipped.append((k, broke, f"file list {len(listing)} chars > {MAX_LIST_CHARS}"))
            continue
        if not places:
            skipped.append((k, broke, "no fix place that exists before the fix"))
            continue
        prompt = PROMPT.format(report=(env / "instruction.md").read_text(), n=len(files), files=listing)
        jobs.append((k, broke, places, prompt))

    def run(job):
        k, broke, places, prompt = job
        res = {"task": k, "broke": broke, "places": places, "models": {}}
        for ep in eps:
            try:
                ans = ask(ep, prompt)
                cov, hit = coverage(ans, places)
                res["models"][ep.tag] = {"coverage": round(cov, 3), "hit": hit, "answer": ans[:3000]}
            except Exception as e:     # one failed call must not sink the backtest; it is reported below
                res["models"][ep.tag] = {"error": repr(e)[:300]}
        return res

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = list(pool.map(run, jobs))
    (args.out / "plan_probe_results.json").write_text(json.dumps({"results": results, "skipped": skipped}, indent=2))

    ok = [r for r in results if all("coverage" in m for m in r["models"].values()) and len(r["models"]) == len(eps)]
    lines = [f"tasks probed: {len(results)} (both models answered: {len(ok)}); skipped: {len(skipped)}"]
    lines += [f"  skipped {k} ({'BREAKER' if b else 'solved'}): {why}" for k, b, why in skipped]
    lines += [f"  call errors {r['task']}: {[t for t, m in r['models'].items() if 'error' in m]}"
              for r in results if r not in ok]
    both_cov = {r["task"]: min(m["coverage"] for m in r["models"].values()) for r in ok}
    B = [r for r in ok if r["broke"]]
    S = [r for r in ok if not r["broke"]]
    if B and S:
        bs, ss = [both_cov[r["task"]] for r in B], [both_cov[r["task"]] for r in S]
        lines.append(f"min-coverage of the two models  - breakers (n={len(B)}): {sorted(bs)}")
        lines.append(f"                                  - solved   (n={len(S)}): mean {statistics.mean(ss):.2f}, "
                     f"median {statistics.median(ss):.2f}")
        # lower coverage should mean harder: AUC = P(breaker coverage < solved coverage)
        auc = sum((b < s) + 0.5 * (b == s) for b in bs for s in ss) / (len(bs) * len(ss))
        lines.append(f"AUC {auc:.2f} (0.50 = chance, 1.00 = perfect; lower coverage predicting a breaker)")
        for thr in (1.0, 0.75, 0.5):
            rej_s = sum(1 for s in ss if s >= thr)
            rej_b = sum(1 for b in bs if b >= thr)
            lines.append(f"rule 'skip the trial if both models cover >= {thr:.0%} of fix places': rejects "
                         f"{rej_s}/{len(ss)} solved ({100 * rej_s // len(ss)}%), {rej_b}/{len(bs)} breakers")
        for r in B:
            lines.append(f"  breaker {r['task']}: " + ", ".join(f"{t} {m['coverage']:.2f}" for t, m in r["models"].items())
                         + f" of {len(r['places'])} places")
    (args.out / "SUMMARY.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
