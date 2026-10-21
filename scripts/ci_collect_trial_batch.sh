#!/usr/bin/env bash
# Download the results of a stage5-trial.yml run and record them through the normal, local
# deterministic-verdict code path (never a hand-edit of state).
#
# Usage: scripts/ci_collect_trial_batch.sh <run-id> <candidate-id> [candidate-id ...]
# Find <run-id> with: gh run list --workflow=stage5-trial.yml
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

[ $# -ge 2 ] || { echo "usage: $0 <run-id> <candidate-id> [candidate-id ...]"; exit 2; }
run_id="$1"; shift
ids=("$@")

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

for id in "${ids[@]}"; do
  echo "== downloading trial-$id artifact =="
  gh run download "$run_id" -n "trial-$id" -D "$tmp/$id"
  mkdir -p "data/04_eval_runs/$id"
  cp -R "$tmp/$id/." "data/04_eval_runs/$id/"
done

for id in "${ids[@]}"; do
  echo "== recomputing the stage-5 verdict for $id from the downloaded attempts =="
  .venv/bin/python run_pipeline.py --reverdict "$id" --apply
done
