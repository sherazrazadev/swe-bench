#!/usr/bin/env bash
# Download the results of a stage5-trial.yml run and record them through the normal, local
# deterministic-verdict code path (never a hand-edit of state), then package accepted tasks (stage 6).
#
# Usage: CI_REMOTE=swe-bench scripts/ci_collect_trial_batch.sh <run-id> <candidate-id> [candidate-id ...]
# Find <run-id> with: gh run list --repo <owner/repo> --workflow=stage5-trial.yml
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

[ $# -ge 2 ] || { echo "usage: CI_REMOTE=<remote> $0 <run-id> <candidate-id> [candidate-id ...]"; exit 2; }
run_id="$1"; shift
ids=("$@")
remote="${CI_REMOTE:-origin}"
repo="$(git remote get-url "$remote" | sed -E 's#.*github.com[:/]##; s#\.git$##')"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

got=()
for id in "${ids[@]}"; do
  echo "== downloading trial-$id from $repo run $run_id =="
  if gh run download "$run_id" --repo "$repo" -n "trial-$id" -D "$tmp/$id" 2>/dev/null \
      && [ -f "$tmp/$id/summary.json" ]; then
    mkdir -p "data/04_eval_runs/$id"
    cp -R "$tmp/$id/." "data/04_eval_runs/$id/"
    got+=("$id")
  else
    echo "   no usable trial artifact for $id (job failed or ran nothing) - left for the next batch"
  fi
done

for id in "${got[@]}"; do
  echo "== recording the stage-5 verdict for $id from the downloaded attempts =="
  .venv/bin/python run_pipeline.py --reverdict "$id" --apply
done
[ ${#got[@]} -gt 0 ] && .venv/bin/python run_pipeline.py --stage 6 --only "$(IFS=,; echo "${got[*]}")" || true
