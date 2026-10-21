#!/usr/bin/env bash
# Push a small batch of already stage-4-validated candidates to a throwaway branch so
# .github/workflows/stage5-trial.yml can run their stage-5 trial on GitHub Actions.
#
# Usage: scripts/ci_push_trial_batch.sh GHSA-aaaa-... GHSA-bbbb-... [...]
#
# What it does, for each candidate:
#   1. Renames every .git/ found inside its data/03_environments/<id>/harbor_task/ to .git.bak
#      (a plain `git add` would otherwise silently collapse a real repo snapshot into a content-less
#      gitlink; the workflow renames it back on the runner before building).
#   2. git add -f's just that harbor_task/ directory (data/03_environments/ is gitignored).
# Then commits everything to a new branch, renames the .git.bak dirs back to .git locally (so the
# local tree is left exactly as it was), and pushes the branch.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

[ $# -ge 1 ] || { echo "usage: $0 <candidate-id> [candidate-id ...]"; exit 2; }
ids=("$@")
branch="ci/trial-batch-$(date +%Y%m%d-%H%M)"

for id in "${ids[@]}"; do
  dir="data/03_environments/$id/harbor_task"
  [ -d "$dir" ] || { echo "no harbor_task dir for $id ($dir)"; exit 1; }
done

echo "== renaming .git -> .git.bak under each candidate's harbor_task =="
for id in "${ids[@]}"; do
  find "data/03_environments/$id/harbor_task" -depth -name ".git" -type d -print -exec sh -c 'mv "$1" "$1.bak"' _ {} \;
done

restore() {
  echo "== restoring .git.bak -> .git locally =="
  for id in "${ids[@]}"; do
    find "data/03_environments/$id/harbor_task" -depth -name ".git.bak" -type d -print -exec sh -c 'mv "$1" "${1%.bak}"' _ {} \;
  done
}
trap restore EXIT

git checkout -b "$branch"
for id in "${ids[@]}"; do
  git add -f "data/03_environments/$id/harbor_task"
done
git add -f .github/workflows/stage5-trial.yml scripts/ci_push_trial_batch.sh scripts/ci_collect_trial_batch.sh 2>/dev/null || true
git commit -m "CI trial batch: ${ids[*]}

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"

# restore runs now (EXIT trap) before we leave the branch, so the working tree is clean either way
restore
trap - EXIT

git push -u origin "$branch"
git checkout -

echo
echo "Pushed branch: $branch"
echo "Trigger the trial with:"
echo "  gh workflow run stage5-trial.yml --ref $branch -f candidates=$(IFS=,; echo "${ids[*]}") -f max_parallel=3"
