#!/usr/bin/env bash
# Push a batch of stage-4-validated candidates to a throwaway branch of the CI repo, so
# .github/workflows/stage5-trial.yml can run their stage-5 trials on GitHub Actions.
#
# Usage: CI_REMOTE=swe-bench scripts/ci_push_trial_batch.sh GHSA-aaaa-... GHSA-bbbb-... [...]
#
# The batch is built in a temporary git worktree of <remote>/main, never in this working tree: the pipeline runs live
# from here (scripts/run_cycles.py), and switching branches under it would swap its code mid-run.
# For each candidate it copies data/03_environments/<id>/harbor_task/ and renames every .git/ inside the COPY to
# .git.bak (a plain `git add` would collapse a repo snapshot into a content-less gitlink; the workflow renames it
# back on the runner). It also copies a consistent snapshot of data/pipeline_state.sqlite3: stage 5 reads it to know
# a candidate passed stage 4, and without it the runner logs "Nothing to evaluate".
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
here="$(pwd)"

remote="${CI_REMOTE:-origin}"
[ $# -ge 1 ] || { echo "usage: CI_REMOTE=<remote> $0 <candidate-id> [candidate-id ...]"; exit 2; }
ids=("$@")
branch="ci/trial-batch-$(date +%Y%m%d-%H%M%S)"

for id in "${ids[@]}"; do
  [ -d "data/03_environments/$id/harbor_task" ] || { echo "no harbor_task dir for $id"; exit 1; }
done

git fetch -q "$remote" main
wt="$(mktemp -d)"
cleanup() { cd "$here"; git worktree remove --force "$wt" >/dev/null 2>&1 || rm -rf "$wt"; }
trap cleanup EXIT
git worktree add -q --detach "$wt" "$remote/main"

for id in "${ids[@]}"; do
  mkdir -p "$wt/data/03_environments/$id"
  cp -R "data/03_environments/$id/harbor_task" "$wt/data/03_environments/$id/"
  find "$wt/data/03_environments/$id/harbor_task" -depth -name ".git" -type d -exec sh -c 'mv "$1" "$1.bak"' _ {} \;
done
sqlite3 data/pipeline_state.sqlite3 ".backup '$wt/data/pipeline_state.sqlite3'"

cd "$wt"
git checkout -q -b "$branch"
for id in "${ids[@]}"; do git add -f "data/03_environments/$id/harbor_task"; done
git add -f data/pipeline_state.sqlite3
git commit -q -m "CI trial batch: ${ids[*]}

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push -q -u "$remote" "$branch"
cd "$here"

repo="$(git remote get-url "$remote" | sed -E 's#.*github.com[:/]##; s#\.git$##')"
echo "Pushed branch: $branch (remote: $remote, repo: $repo)"
echo "Trigger the trial with:"
echo "  gh workflow run stage5-trial.yml --repo $repo --ref $branch -f candidates=$(IFS=,; echo "${ids[*]}") -f max_parallel=${#ids[@]}"
