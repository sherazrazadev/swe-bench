#!/usr/bin/env bash
# Oracle: overlay the reference fix (solution/workspace/: the upstream maintainers' source changes, their test changes
# excluded) onto the workspace. The verifier grades it exactly like any submission, so there is no bypass to find, and a
# passing oracle also proves that the build and the suite fit together.
set -euo pipefail
cp -a /solution/workspace/. /workspace/
