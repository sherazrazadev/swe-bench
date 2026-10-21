#!/bin/bash
# Oracle: apply the historical human fix (source files only; its test changes are excluded).
set -euo pipefail
cd /app
git apply --whitespace=nowarn "$(dirname "$0")/oracle_solution.patch"
