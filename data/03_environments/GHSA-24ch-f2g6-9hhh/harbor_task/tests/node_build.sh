#!/bin/bash
cd /app
if [ -f bun.lock ] || [ -f bun.lockb ]; then bun run --if-present build 2>/dev/null || bun run build; elif [ -f pnpm-lock.yaml ]; then pnpm -r --if-present run build; elif [ -f yarn.lock ]; then yarn run build; else npm run build --if-present; fi
