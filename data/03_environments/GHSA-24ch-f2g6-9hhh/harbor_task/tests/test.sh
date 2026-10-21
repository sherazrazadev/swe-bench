#!/bin/bash
# Partial-score grading. Reward = mean of the fractions of passing (a) hidden security tests,
# (b) hidden functional tests, (c) the repo's existing tests that stage 4 proved pass before AND after the fix.
# Reward is exactly 1.0 only if everything passes. Written on every code path.
set -uo pipefail
mkdir -p /logs/verifier
cd /app || { echo 0 > /logs/verifier/reward.txt; exit 0; }
export PYTHONPATH="/app:${PYTHONPATH:-}" REPO_ROOT=/app

# 1. This is a FRESH container from the task image (separate grader), so the agent's environment is gone. Apply only
#    its source patch, collected from its container when it stopped - never its test-runner config or manifests.
for f in agent_changes.txt outside_changes.txt dependency_changes.txt collect_error.txt; do
  [ -f /logs/artifacts/$f ] && cp /logs/artifacts/$f /logs/verifier/$f
done
if [ -s /logs/artifacts/agent.patch ]; then
  cp /logs/artifacts/agent.patch /logs/verifier/agent.diff
  grep -E '^diff --git ' /logs/artifacts/agent.patch | sed 's|^diff --git a/[^ ]* b/||' > /logs/verifier/agent_patch_files.txt
  git -c safe.directory=/app apply --binary --whitespace=nowarn --exclude='conftest.py' --exclude='*/conftest.py' --exclude='pytest.ini' --exclude='*/pytest.ini' --exclude='tox.ini' --exclude='*/tox.ini' --exclude='setup.cfg' --exclude='*/setup.cfg' --exclude='pyproject.toml' --exclude='*/pyproject.toml' --exclude='package.json' --exclude='*/package.json' --exclude='package-lock.json' --exclude='*/package-lock.json' --exclude='yarn.lock' --exclude='*/yarn.lock' --exclude='pnpm-lock.yaml' --exclude='*/pnpm-lock.yaml' --exclude='bun.lock' --exclude='*/bun.lock' --exclude='bun.lockb' --exclude='*/bun.lockb' --exclude='sitecustomize.py' --exclude='*/sitecustomize.py' --exclude='usercustomize.py' --exclude='*/usercustomize.py' --exclude='*.pth' --exclude='*/*.pth' --exclude='vitest.config.*' --exclude='*/vitest.config.*' --exclude='vite.config.*' --exclude='*/vite.config.*' --exclude='jest.config.*' --exclude='*/jest.config.*' --exclude='jest.setup.*' --exclude='*/jest.setup.*' --exclude='karma.conf.*' --exclude='*/karma.conf.*' --exclude='.mocharc*' --exclude='*/.mocharc*' /logs/artifacts/agent.patch \
      > /logs/verifier/agent_patch_apply.log 2>&1 || { echo "APPLY FAILED" >> /logs/verifier/agent_patch_apply.log;
    git -c safe.directory=/app apply --binary --whitespace=nowarn --reject --exclude='conftest.py' --exclude='*/conftest.py' --exclude='pytest.ini' --exclude='*/pytest.ini' --exclude='tox.ini' --exclude='*/tox.ini' --exclude='setup.cfg' --exclude='*/setup.cfg' --exclude='pyproject.toml' --exclude='*/pyproject.toml' --exclude='package.json' --exclude='*/package.json' --exclude='package-lock.json' --exclude='*/package-lock.json' --exclude='yarn.lock' --exclude='*/yarn.lock' --exclude='pnpm-lock.yaml' --exclude='*/pnpm-lock.yaml' --exclude='bun.lock' --exclude='*/bun.lock' --exclude='bun.lockb' --exclude='*/bun.lockb' --exclude='sitecustomize.py' --exclude='*/sitecustomize.py' --exclude='usercustomize.py' --exclude='*/usercustomize.py' --exclude='*.pth' --exclude='*/*.pth' --exclude='vitest.config.*' --exclude='*/vitest.config.*' --exclude='vite.config.*' --exclude='*/vite.config.*' --exclude='jest.config.*' --exclude='*/jest.config.*' --exclude='jest.setup.*' --exclude='*/jest.setup.*' --exclude='karma.conf.*' --exclude='*/karma.conf.*' --exclude='.mocharc*' --exclude='*/.mocharc*' /logs/artifacts/agent.patch \
      >> /logs/verifier/agent_patch_apply.log 2>&1; }
  git -c safe.directory=/app diff --name-only > /logs/verifier/agent_patch_applied.txt 2>/dev/null
  git -c safe.directory=/app ls-files --others --exclude-standard >> /logs/verifier/agent_patch_applied.txt 2>/dev/null
  sort -u /logs/verifier/agent_patch_files.txt | comm -23 - <(sort -u /logs/verifier/agent_patch_applied.txt) \
      > /logs/verifier/agent_patch_dropped.txt
else
  echo "no agent changes" > /logs/verifier/agent_patch_apply.log
fi

# 2. Compiled (TypeScript/bundled) projects: rebuild so the code under test is what is in /app/src right now
#    (the agent's or the oracle's edits), not what was compiled when the image was built.
if [ -f /tests/node_build.sh ]; then timeout 600 bash /tests/node_build.sh > /logs/verifier/build.log 2>&1 || true; fi

# 3. Hidden tests. No plugin auto-loading (only the ctrf reporter) and no ini/conftest from the repo or / can take effect.
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 timeout 900 python3 -m pytest /tests/test_outputs.py -p ctrf.main \
    -p no:cacheprovider -q --rootdir=/app -c /dev/null --confcutdir=/tests --ctrf /logs/verifier/ctrf.json
HIDDEN_RC=$?

# 4. The repo's existing tests, from pristine copies (the agent cannot edit them, or their conftest/ini, to pass).
if [ -s /tests/existing_files.txt ]; then
  [ -d /tests/existing_snapshot ] && cp -a /tests/existing_snapshot/. /app/
  if [ -f /tests/existing_node.py ]; then
    timeout 900 python3 /tests/existing_node.py
  else
    mapfile -t EXISTING < /tests/existing_files.txt
    timeout 900 python3 -m pytest "${EXISTING[@]}" -p no:cacheprovider -q --rootdir=/app \
        --continue-on-collection-errors --ctrf /logs/verifier/ctrf_existing.json
  fi
fi

python3 /tests/score.py "$HIDDEN_RC"
exit 0
