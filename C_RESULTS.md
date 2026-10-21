# CWE-Bench — Results Ledger (internal)

_Generated 2026-10-21 14:30 from the latest evaluation run of each model on each task (114 attempts, 83 graded) in `data/04_eval_runs/` and the pipeline state. Regenerate with `python -m src.common.results_report` (stage 5 does it after every run)._

**Breaker** = pass@3 = 0 on **both** DeepSeek V4.1 Flash (max) and MiMo-V2.6-Pro. A run is solved at reward 1.0. A partial fix (some attack variants still open) and a fix that breaks legitimate behaviour are failures. A run that hit the 2-hour agent limit is **timed out and not counted as a failure**. Runs that were never graded (stopped early, crashed, lost to a connection drop) are left out. Each model is judged on its latest evaluation run; the agent harness (terminus-2 or Claude Code) is shown next to each result.

## Executive summary

**2 accepted out of 43 trialed tasks.** In 9 task(s) at least one model did not solve it (see the second table for which task type broke which model).

## All trialed tasks

| # | Task | Language | CWE | Task type | DeepSeek | MiMo | Final verdict | How it failed | Image build (cached / longest) |
|---|---|---|---|---|---|---|---|---|---|
| 1 | msgpack5 (GHSA-24ch-f2g6-9hhh) | JavaScript | 674 | resource exhaustion (DoS); local fix (2 files / 2 dirs / 40 lines) | SOLVED 1/1 — Claude Code | stopped early (not graded) — Claude Code | REJECTED: DeepSeek solved | — | 11 s / 0.2 min |
| 2 | @typespec/openapi3 (GHSA-2q42-4q24-7rgv) | TypeScript | 22, 73 | path / file handling; wide multi-layer fix (6 files / 5 dirs / 53 lines) | SOLVED 1/1 — Claude Code | stopped early (not graded) — Claude Code | REJECTED: DeepSeek solved | — | 165 s / 2.8 min |
| 3 | 9router (GHSA-32gc-64m7-hj7v) | JavaScript | 307, 807 | auth / session / credentials; wide multi-layer fix (13 files / 10 dirs / 257 lines) | SOLVED 1/1 — Claude Code | stopped early (not graded) — Claude Code | REJECTED: DeepSeek solved | — | 6 s / 0.1 min |
| 4 | react-router (GHSA-337j-9hxr-rhxg) | TypeScript | 470 | other; wide multi-layer fix (8 files / 7 dirs / 113 lines) | SOLVED 1/1 — Claude Code | stopped early (not graded) — Claude Code | REJECTED: DeepSeek solved | — | 64 s / 1.1 min |
| 5 | GitPython (GHSA-3wxw-xv34-2frg) | Python | 88, 200 | injection (code / command / markup) + information exposure; wide multi-layer fix (5 files / 4 dirs / 55 lines) | SOLVED 1/1 — Claude Code | stopped early (not graded) — Claude Code | REJECTED: DeepSeek solved | — | 72 s / 1.3 min |
| 6 | pypdf (GHSA-5jq2-8x83-x246) | Python | 400, 407 | resource exhaustion (DoS); multi-file fix (4 files / 2 dirs / 117 lines) | SOLVED 1/1 — Claude Code | stopped early (not graded) — Claude Code | REJECTED: DeepSeek solved | — | 28 s / 0.5 min |
| 7 | pyload-ng (GHSA-68w4-83fh-f2w8) | Python | 287 | auth / session / credentials; local fix (2 files / 2 dirs / 9 lines) | SOLVED 1/1 — Claude Code | stopped early (not graded) — Claude Code | REJECTED: DeepSeek solved | — | 14 s / 0.2 min |
| 8 | @modelcontextprotocol/sdk (GHSA-6qxp-vccf-f47h) | TypeScript | 345, 522 | auth / session / credentials; wide multi-layer fix (8 files / 4 dirs / 174 lines) | failed 0/3 (0.92 each, stopped on its own) — Claude Code | timed out 3/3 (0.50 each) — terminus-2 | REJECTED: MiMo timed out, which is not counted as a failure | DeepSeek: partial fix: closed 5 of 6 attack variants in all 3 runs and stopped on its own (it thought it was done); left open every time: schema_roundtrip_keeps_binding — MiMo: ran out of the 120-min limit in 3/3 runs with 0 of 6 attack variants closed; not counted as a failure | 12 s / 0.3 min |
| 9 | github.com/infracost/infracost (GHSA-6x6c-w9w9-hv4h) | Go | 522 | auth / session / credentials; wide multi-layer fix (8 files / 3 dirs / 237 lines) | failed 0/3 (0.92/0.92/0.83, stopped on its own) — Claude Code | failed 0/3 (0.92 each, stopped on its own) — Claude Code | WITHDRAWN: infracost: user-acknowledged defective task (2026-10-19). The 'configured regist | DeepSeek: partial fix (and broke legitimate behaviour in 2 of 3 runs: configured_registry_host_still_authenticates) in all 3 runs and stopped on its own (it thought it was done) — MiMo: closed the hole but broke legitimate behaviour (configured_registry_host_still_authenticates) in all 3 runs and stopped on its own (it thought it was done) | 44 s / 1.1 min |
| 10 | datamodel-code-generator (GHSA-77xj-x4rm-935c) | Python | 22, 73 | path / file handling; local fix (1 files / 1 dir / 31 lines) | SOLVED 1/1 — Claude Code | stopped early (not graded) — Claude Code | REJECTED: DeepSeek solved | — | 30 s / 0.5 min |
| 11 | apprise (GHSA-856c-92hv-3vxx) | Python | 200, 601 | information exposure + SSRF / redirect; wide multi-layer fix (127 files / 7 dirs / 229 lines) | failed 0/3 (0.99 each, stopped on its own) — Claude Code | failed 0/3 (0.99 each, stopped on its own) — Claude Code | **ACCEPTED**: both models failed every run | DeepSeek: closed the hole but broke legitimate behaviour (test_notify_multi_instance_decoration) in all 3 runs and stopped on its own (it thought it was done) — MiMo: closed the hole but broke legitimate behaviour (test_notify_multi_instance_decoration) in all 3 runs and stopped on its own (it thought it was done) | 20 s / 2.1 min |
| 12 | pymongo (GHSA-8fvv-fgr5-f8ch) | Python | 943 | other; multi-file fix (3 files / 3 dirs / 74 lines) | SOLVED 1/1 — Claude Code | stopped early (not graded) — Claude Code | REJECTED: DeepSeek solved | — | 15 s / 0.2 min |
| 13 | httpx2 (GHSA-8xx6-hgc6-gc2m) | Python | 409 | resource exhaustion (DoS); multi-file fix (4 files / 1 dir / 238 lines) | SOLVED 1/1 — Claude Code | stopped early (not graded) — Claude Code | REJECTED: DeepSeek solved | — | 21 s / 0.4 min |
| 14 | @sync-in/server (GHSA-92cr-jxw4-5wjg) | TypeScript | 288 | other; wide multi-layer fix (21 files / 8 dirs / 224 lines) | SOLVED 1/1 — Claude Code | stopped early (not graded) — Claude Code | REJECTED: DeepSeek solved | — | 24 s / 0.4 min |
| 15 | pyload-ng (GHSA-9q47-3cm2-2rp8) | Python | 290 | auth / session / credentials; multi-file fix (4 files / 2 dirs / 58 lines) | SOLVED 1/1 — Claude Code | stopped early (not graded) — Claude Code | REJECTED: DeepSeek solved | — | 37 s / 0.6 min |
| 16 | @xmldom/xmldom (GHSA-c7q8-3ch8-vqpv) | JavaScript | 91 | other; multi-file fix (3 files / 2 dirs / 37 lines) | SOLVED 1/1 — Claude Code | stopped early (not graded) — Claude Code | REJECTED: DeepSeek solved | — | 24 s / 0.4 min |
| 17 | n8n (GHSA-f3f2-mcxc-pwjx) | TypeScript | 89 | injection (code / command / markup); wide multi-layer fix (9 files / 7 dirs / 343 lines) | SOLVED 1/1 — Claude Code | SOLVED 1/1 — Claude Code | REJECTED: both solved | — | 156 s / 2.6 min |
| 18 | fast-uri (GHSA-f65p-4m7j-42xc) | JavaScript | 20, 918 | parsing / type confusion + SSRF / redirect; local fix (2 files / 2 dirs / 238 lines) | SOLVED 1/1 — Claude Code | stopped early (not graded) — Claude Code | REJECTED: DeepSeek solved | — | 18 s / 0.3 min |
| 19 | @hono/oauth-providers (GHSA-fm3f-ch8h-qw8q) | TypeScript | 1275, 352 | auth / session / credentials; wide multi-layer fix (7 files / 7 dirs / 54 lines) | SOLVED 1/1 — Claude Code | SOLVED 1/1 — Claude Code | REJECTED: both solved | — | 34 s / 0.6 min |
| 20 | hono (GHSA-gqvv-2mrq-wpjv) | JavaScript | 22 | path / file handling; local fix (fix size unknown) | SOLVED 1/1 — Claude Code | stopped early (not graded) — Claude Code | REJECTED: DeepSeek solved | — | 45 s / 0.8 min |
| 21 | banks (GHSA-hmq2-7hp6-7crh) | Python | 20 | parsing / type confusion; wide multi-layer fix (13 files / 3 dirs / 232 lines) | SOLVED 1/1 — Claude Code | stopped early (not graded) — Claude Code | REJECTED: DeepSeek solved | — | 17 s / 0.3 min |
| 22 | stream-json (GHSA-hqr4-qq8f-hg3x) | JavaScript | 407 | resource exhaustion (DoS); wide multi-layer fix (10 files / 4 dirs / 286 lines) | SOLVED 1/1 — Claude Code | stopped early (not graded) — Claude Code | REJECTED: DeepSeek solved | — | 37 s / 0.6 min |
| 23 | hono (GHSA-hxh3-vqpv-xpqv) | TypeScript | 79 | injection (code / command / markup); wide multi-layer fix (6 files / 3 dirs / 156 lines) | failed 0/3 (0.83/0.94/0.83, stopped on its own) — Claude Code | failed 0/3 (0.89/0.94/0.89, stopped on its own) — Claude Code | **ACCEPTED**: both models failed every run | DeepSeek: partial fix (and broke legitimate behaviour in 1 of 3 runs: runtime-tests/node/index.test.ts > stream > Should call onAbort) in all 3 runs and stopped on its own (it thought it was done); left open every time: render_to_string_escapes_array_root — MiMo: partial fix (and broke legitimate behaviour in 1 of 3 runs: runtime-tests/node/index.test.ts > stream > Should call onAbort) in all 3 runs and stopped on its own (it thought it was done); left open every time: render_to_string_escapes_array_root | 54 s / 1.4 min |
| 24 | devalue (GHSA-j22f-vq7h-c4qm) | JavaScript | 200, 226 | information exposure; multi-file fix (4 files / 1 dir / 40 lines) | SOLVED 1/1 — terminus-2 | stopped early (not graded) — terminus-2 | REJECTED: DeepSeek solved | — | 8 s / 0.1 min |
| 25 | ip-address (GHSA-j6r3-76f7-8jcv) | TypeScript | 697, 843 | parsing / type confusion; multi-file fix (3 files / 1 dir / 25 lines) | SOLVED 1/1 — terminus-2 | SOLVED 1/1 — terminus-2 | REJECTED: both solved | — | 9 s / 0.2 min |
| 26 | pyload-ng (GHSA-jq7h-wrvp-3rgx) | Python | 613 | auth / session / credentials; wide multi-layer fix (5 files / 4 dirs / 111 lines) | SOLVED 1/1 — terminus-2 | timed out 1/1 (0.67) — terminus-2 | REJECTED: DeepSeek solved | MiMo: ran out of the 30-min limit in 1/1 runs with 0 of 7 attack variants closed; not counted as a failure | 15 s / 0.3 min |
| 27 | devalue (GHSA-mcm9-63f2-9j32) | JavaScript | 400, 409 | resource exhaustion (DoS); multi-file fix (3 files / 3 dirs / 141 lines) | SOLVED 1/1 — Claude Code | stopped early (not graded) — Claude Code | REJECTED: DeepSeek solved | — | 10 s / 0.2 min |
| 28 | changedetection-io (GHSA-mw8m-398g-h89w) | Python | 79 | injection (code / command / markup); wide multi-layer fix (12 files / 8 dirs / 95 lines) | SOLVED 1/1 — Claude Code | stopped early (not graded) — Claude Code | REJECTED: DeepSeek solved | — | 12 s / 0.2 min |
| 29 | @bytebase/dbhub (GHSA-mwwr-p57h-56pf) | TypeScript | 184, 636, 863 | auth / session / credentials + injection (code / command / markup); wide multi-layer fix (7 files / 6 dirs / 189 lines) | SOLVED 1/1 — Claude Code | stopped early (not graded) — Claude Code | REJECTED: DeepSeek solved | — | 11 s / 0.2 min |
| 30 | nltk (GHSA-p4rw-rvv2-7xwr) | Python | 22, 59 | path / file handling; wide multi-layer fix (10 files / 3 dirs / 236 lines) | failed 0/3 (0.93 each, stopped on its own) — Claude Code | SOLVED 1/3 — Claude Code | REJECTED: MiMo solved | DeepSeek: partial fix: closed 4 of 5 attack variants in all 3 runs and stopped on its own (it thought it was done); left open every time: toolbox_symlink_escape | 45 s / 0.9 min |
| 31 | adm-zip (GHSA-p634-w6r4-rjp2) | JavaScript | 436, 696 | parsing / type confusion; local fix (2 files / 2 dirs / 11 lines) | SOLVED 1/1 — terminus-2 | SOLVED 1/1 — terminus-2 | REJECTED: both solved | — | 4 s / 0.1 min |
| 32 | @vitest/browser (GHSA-p63j-vcc4-9vmv) | TypeScript | 22, 552, 862 | auth / session / credentials + path / file handling; wide multi-layer fix (8 files / 4 dirs / 104 lines) | SOLVED 1/1 — Claude Code | stopped early (not graded) — Claude Code | REJECTED: DeepSeek solved | — | 53 s / 0.9 min |
| 33 | pydantic-ai (GHSA-q2xc-rrxj-58x9) | Python | 346, 350 | auth / session / credentials; wide multi-layer fix (6 files / 3 dirs / 222 lines) | SOLVED 1/1 — Claude Code | stopped early (not graded) — Claude Code | REJECTED: DeepSeek solved | — | 36 s / 0.6 min |
| 34 | @payloadcms/plugin-import-export (GHSA-qf28-8hc6-vwrp) | TypeScript | 1321 | deserialization / prototype pollution; wide multi-layer fix (16 files / 10 dirs / 344 lines) | SOLVED 1/1 — Claude Code | stopped early (not graded) — Claude Code | REJECTED: DeepSeek solved | — | 15 s / 0.3 min |
| 35 | pypdf (GHSA-v247-6f48-mgcj) | Python | 400, 407 | resource exhaustion (DoS); local fix (2 files / 2 dirs / 93 lines) | SOLVED 1/1 — terminus-2 | stopped early (not graded) — terminus-2 | REJECTED: DeepSeek solved | — | 10 s / 0.2 min |
| 36 | vibe-trading-ai (GHSA-v2f8-6655-7grj) | Python | 200, 306, 434, 862, 942 | auth / session / credentials + path / file handling + information exposure; wide multi-layer fix (17 files / 5 dirs / 618 lines) | SOLVED 1/1 — Claude Code | SOLVED 1/1 — Claude Code | REJECTED: both solved | — | 58 s / 1.0 min |
| 37 | undici (GHSA-vp8m-p9jh-q5pm) | JavaScript | 346 | auth / session / credentials; wide multi-layer fix (10 files / 5 dirs / 120 lines) | SOLVED 1/2 — Claude Code | failed 0/1 (0.93, stopped on its own) — Claude Code | REJECTED: DeepSeek solved | MiMo: closed the hole but broke legitimate behaviour (storage_with_custom_lookup_same_host) in its run and stopped on its own (it thought it was done) | 73 s / 1.4 min |
| 38 | nltk (GHSA-w3v8-gmh9-3wv7) | Python | 1333 | resource exhaustion (DoS); wide multi-layer fix (7 files / 4 dirs / 289 lines) | SOLVED 1/1 — Claude Code | stopped early (not graded) — Claude Code | REJECTED: DeepSeek solved | — | 21 s / 0.3 min |
| 39 | fast-jwt (GHSA-x937-hj6v-793p) | JavaScript | 613 | auth / session / credentials; local fix (1 files / 1 dir / 33 lines) | failed 0/1 (0.95, stopped on its own) — Claude Code | SOLVED 1/1 — Claude Code | REJECTED: MiMo solved | DeepSeek: partial fix: closed 6 of 7 attack variants in its run and stopped on its own (it thought it was done); left open every time: exp_at_epoch_boundary | 11 s / 0.2 min |
| 40 | crewai-tools (PYSEC-2026-3819) | Python | 918 | SSRF / redirect; wide multi-layer fix (8 files / 4 dirs / 121 lines) | SOLVED 1/1 — Claude Code | stopped early (not graded) — Claude Code | REJECTED: DeepSeek solved | — | 1990 s / 33.2 min |
| 41 | gitpython (PYSEC-2026-3837) | Python | 88, 200 | injection (code / command / markup) + information exposure; wide multi-layer fix (14 files / 6 dirs / 571 lines) | failed 0/3 (0.89 each, stopped on its own) — Claude Code | failed 0/3 (0.89 each, stopped on its own) — Claude Code | NEEDS REVIEW: deepseek: 2/3 attempts are counted model failures; deepseek/harbor_task__edp62ja | DeepSeek: partial fix: closed 4 of 6 attack variants in all 3 runs and stopped on its own (it thought it was done); left open every time: commit_diff_option_returns_file_contents, index_diff_option_returns_file_contents — MiMo: partial fix: closed 4 of 6 attack variants in all 3 runs and stopped on its own (it thought it was done); left open every time: commit_diff_option_returns_file_contents, index_diff_option_returns_file_contents | 26 s / 0.5 min |
| 42 | PYSEC-2026-3837-v2 (PYSEC-2026-3837-v2) | ? |  | other; local fix (fix size unknown) | SOLVED 1/1 — Claude Code | SOLVED 1/1 — Claude Code | REJECTED: both solved | — | 13 s / 0.2 min |
| 43 | nltk (PYSEC-2026-3869) | Python | 407, 674 | resource exhaustion (DoS); wide multi-layer fix (6 files / 2 dirs / 163 lines) | SOLVED 1/1 — Claude Code | stopped early (not graded) — Claude Code | REJECTED: DeepSeek solved | — | 10 s / 0.2 min |

## What breaks which model

Every task where a model did not solve it. A task that breaks only one model is still evidence: it shows which task type that model cannot handle. The task generator reads this as `data/knowledge/model_failure_map.md`.

| Task | Task type | Entry point | Model | Result | How it failed | Other model |
|---|---|---|---|---|---|---|
| @modelcontextprotocol/sdk (GHSA-6qxp-vccf-f47h) | auth / session / credentials; wide multi-layer fix (8 files / 4 dirs / 174 lines) | Exported client OAuth API fetchToken()/auth() called with a pinned credential provider … | DeepSeek | FAILED | partial fix: closed 5 of 6 attack variants in all 3 runs and stopped on its own (it thought it was done); left open every time: schema_roundtrip_keeps_binding | MiMo also did not solve it (timed out 3/3 (0.50 each)) |
| @modelcontextprotocol/sdk (GHSA-6qxp-vccf-f47h) | auth / session / credentials; wide multi-layer fix (8 files / 4 dirs / 174 lines) | Exported client OAuth API fetchToken()/auth() called with a pinned credential provider … | MiMo | timed out (not counted) | ran out of the 120-min limit in 3/3 runs with 0 of 6 attack variants closed; not counted as a failure | DeepSeek also did not solve it (failed 0/3 (0.92 each, stopped on its own)) |
| github.com/infracost/infracost (GHSA-6x6c-w9w9-hv4h) | auth / session / credentials; wide multi-layer fix (8 files / 3 dirs / 237 lines) | — | DeepSeek | FAILED | partial fix (and broke legitimate behaviour in 2 of 3 runs: configured_registry_host_still_authenticates) in all 3 runs and stopped on its own (it thought it was done) | MiMo also did not solve it (failed 0/3 (0.92 each, stopped on its own)) |
| github.com/infracost/infracost (GHSA-6x6c-w9w9-hv4h) | auth / session / credentials; wide multi-layer fix (8 files / 3 dirs / 237 lines) | — | MiMo | FAILED | closed the hole but broke legitimate behaviour (configured_registry_host_still_authenticates) in all 3 runs and stopped on its own (it thought it was done) | DeepSeek also did not solve it (failed 0/3 (0.92/0.92/0.83, stopped on its own)) |
| apprise (GHSA-856c-92hv-3vxx) | information exposure + SSRF / redirect; wide multi-layer fix (127 files / 7 dirs / 229 lines) | Public Apprise Python API (Apprise.add/notify, Apprise.instantiate, AppriseConfig, … | DeepSeek | FAILED | closed the hole but broke legitimate behaviour (test_notify_multi_instance_decoration) in all 3 runs and stopped on its own (it thought it was done) | MiMo also did not solve it (failed 0/3 (0.99 each, stopped on its own)) |
| apprise (GHSA-856c-92hv-3vxx) | information exposure + SSRF / redirect; wide multi-layer fix (127 files / 7 dirs / 229 lines) | Public Apprise Python API (Apprise.add/notify, Apprise.instantiate, AppriseConfig, … | MiMo | FAILED | closed the hole but broke legitimate behaviour (test_notify_multi_instance_decoration) in all 3 runs and stopped on its own (it thought it was done) | DeepSeek also did not solve it (failed 0/3 (0.99 each, stopped on its own)) |
| hono (GHSA-hxh3-vqpv-xpqv) | injection (code / command / markup); wide multi-layer fix (6 files / 3 dirs / 156 lines) | hono/jsx server-side rendering: a JSX tree built with the public … | DeepSeek | FAILED | partial fix (and broke legitimate behaviour in 1 of 3 runs: runtime-tests/node/index.test.ts > stream > Should call onAbort) in all 3 runs and stopped on its own (it thought it was done); left open every time: render_to_string_escapes_array_root | MiMo also did not solve it (failed 0/3 (0.89/0.94/0.89, stopped on its own)) |
| hono (GHSA-hxh3-vqpv-xpqv) | injection (code / command / markup); wide multi-layer fix (6 files / 3 dirs / 156 lines) | hono/jsx server-side rendering: a JSX tree built with the public … | MiMo | FAILED | partial fix (and broke legitimate behaviour in 1 of 3 runs: runtime-tests/node/index.test.ts > stream > Should call onAbort) in all 3 runs and stopped on its own (it thought it was done); left open every time: render_to_string_escapes_array_root | DeepSeek also did not solve it (failed 0/3 (0.83/0.94/0.83, stopped on its own)) |
| pyload-ng (GHSA-jq7h-wrvp-3rgx) | auth / session / credentials; wide multi-layer fix (5 files / 4 dirs / 111 lines) | HTTP POST /api/set_user_permission and /api/change_password (REST API blueprint, session- … | MiMo | timed out (not counted) | ran out of the 30-min limit in 1/1 runs with 0 of 7 attack variants closed; not counted as a failure | DeepSeek solved it (solved in 57 steps, 12 min) |
| nltk (GHSA-p4rw-rvv2-7xwr) | path / file handling; wide multi-layer fix (10 files / 3 dirs / 236 lines) | Loading a corpus through the public corpus-reader APIs over a directory that contains a … | DeepSeek | FAILED | partial fix: closed 4 of 5 attack variants in all 3 runs and stopped on its own (it thought it was done); left open every time: toolbox_symlink_escape | MiMo solved it (solved in 90 steps, 61 min) |
| undici (GHSA-vp8m-p9jh-q5pm) | auth / session / credentials; wide multi-layer fix (10 files / 5 dirs / 120 lines) | Public undici API: dispatcher.request({origin?, path, method}) on … | MiMo | FAILED | closed the hole but broke legitimate behaviour (storage_with_custom_lookup_same_host) in its run and stopped on its own (it thought it was done) | DeepSeek solved it (solved in 164 steps, 49 min) |
| fast-jwt (GHSA-x937-hj6v-793p) | auth / session / credentials; local fix (1 files / 1 dir / 33 lines) | Public API: createVerifier({ key, cache: true, ... }) from the package index, then … | DeepSeek | FAILED | partial fix: closed 6 of 7 attack variants in its run and stopped on its own (it thought it was done); left open every time: exp_at_epoch_boundary | MiMo solved it (solved in 30 steps, 34 min) |
| gitpython (PYSEC-2026-3837) | injection (code / command / markup) + information exposure; wide multi-layer fix (14 files / 6 dirs / 571 lines) | annotated tag creation; full and incremental blame of a committed file; diff of a commit … | DeepSeek | FAILED | partial fix: closed 4 of 6 attack variants in all 3 runs and stopped on its own (it thought it was done); left open every time: commit_diff_option_returns_file_contents, index_diff_option_returns_file_contents | MiMo also did not solve it (failed 0/3 (0.89 each, stopped on its own)) |
| gitpython (PYSEC-2026-3837) | injection (code / command / markup) + information exposure; wide multi-layer fix (14 files / 6 dirs / 571 lines) | annotated tag creation; full and incremental blame of a committed file; diff of a commit … | MiMo | FAILED | partial fix: closed 4 of 6 attack variants in all 3 runs and stopped on its own (it thought it was done); left open every time: commit_diff_option_returns_file_contents, index_diff_option_returns_file_contents | DeepSeek also did not solve it (failed 0/3 (0.89 each, stopped on its own)) |

## Failure details

Every task a model FAILED (a counted failure: graded, below 1.0, not a timeout), most important first. Solved tasks are only in the tables above. Each attempt is listed in the order it ran; *left open* = hidden security tests still failing, *broke* = functional or enforced existing repo tests that failed.

### apprise (GHSA-856c-92hv-3vxx) - ACCEPTED: both models failed every run

- **Task type:** information exposure + SSRF / redirect; wide multi-layer fix (127 files / 7 dirs / 229 lines); CWE 200, 601; Python
- **Entry point:** Public Apprise Python API (Apprise.add/notify, Apprise.instantiate, AppriseConfig, AppriseAttachment) with a configured remote endpoint that answers with a cross-host 3xx redirect
- **Reference fix (source files):** `apprise/asset.py`, `apprise/attachment/http.py`, `apprise/config/http.py`, `apprise/plugins/africas_talking.py`, `apprise/plugins/apprise_api.py`, `apprise/plugins/bark.py`, `apprise/plugins/bluesky.py`, `apprise/plugins/brevo.py`, `apprise/plugins/bulksms.py`, `apprise/plugins/bulkvs.py`, `apprise/plugins/burstsms.py`, `apprise/plugins/chanify.py`, `apprise/plugins/clickatell.py`, `apprise/plugins/clicksend.py`, `apprise/plugins/custom_form.py`, `apprise/plugins/custom_json.py`, `apprise/plugins/custom_xml.py`, `apprise/plugins/d7networks.py`, `apprise/plugins/dapnet.py`, `apprise/plugins/dingtalk.py`, `apprise/plugins/discord.py`, `apprise/plugins/dot.py`, `apprise/plugins/emby.py`, `apprise/plugins/enigma2.py`, `apprise/plugins/evolution.py`, `apprise/plugins/exotel.py`, `apprise/plugins/fcm/__init__.py`, `apprise/plugins/fcm/oauth.py`, `apprise/plugins/feishu.py`, `apprise/plugins/flock.py`, `apprise/plugins/fluxer.py`, `apprise/plugins/fortysixelks.py`, `apprise/plugins/freemobile.py`, `apprise/plugins/google_chat.py`, `apprise/plugins/gotify.py`, `apprise/plugins/home_assistant.py`, `apprise/plugins/httpsms.py`, `apprise/plugins/ifttt.py`, `apprise/plugins/jira.py`, `apprise/plugins/join.py`, `apprise/plugins/kavenegar.py`, `apprise/plugins/kodi.py`, `apprise/plugins/kumulos.py`, `apprise/plugins/lametric.py`, `apprise/plugins/lark.py`, `apprise/plugins/line.py`, `apprise/plugins/mailgun.py`, `apprise/plugins/mastodon.py`, `apprise/plugins/matrix/base.py`, `apprise/plugins/mattermost.py`, `apprise/plugins/messagebird.py`, `apprise/plugins/misskey.py`, `apprise/plugins/msg91.py`, `apprise/plugins/msteams.py`, `apprise/plugins/nextcloud.py`, `apprise/plugins/nextcloudtalk.py`, `apprise/plugins/notica.py`, `apprise/plugins/notifiarr.py`, `apprise/plugins/notificationapi.py`, `apprise/plugins/notifico.py`, `apprise/plugins/ntfy.py`, `apprise/plugins/octopush.py`, `apprise/plugins/office365.py`, `apprise/plugins/one_signal.py`, `apprise/plugins/opsgenie.py`, `apprise/plugins/pagerduty.py`, `apprise/plugins/pagertree.py`, `apprise/plugins/parseplatform.py`, `apprise/plugins/plivo.py`, `apprise/plugins/popcorn_notify.py`, `apprise/plugins/postmark.py`, `apprise/plugins/prowl.py`, `apprise/plugins/pushbullet.py`, `apprise/plugins/pushdeer.py`, `apprise/plugins/pushed.py`, `apprise/plugins/pushjet.py`, `apprise/plugins/pushme.py`, `apprise/plugins/pushover.py`, `apprise/plugins/pushplus.py`, `apprise/plugins/pushsafer.py`, `apprise/plugins/pushy.py`, `apprise/plugins/qq.py`, `apprise/plugins/reddit.py`, `apprise/plugins/resend.py`, `apprise/plugins/revolt.py`, `apprise/plugins/rocketchat.py`, `apprise/plugins/ryver.py`, `apprise/plugins/sendgrid.py`, `apprise/plugins/sendpulse.py`, `apprise/plugins/serverchan.py`, `apprise/plugins/ses.py`, `apprise/plugins/seven.py`, `apprise/plugins/sfr.py`, `apprise/plugins/signal_api.py`, `apprise/plugins/signl4.py`, `apprise/plugins/simplepush.py`, `apprise/plugins/sinch.py`, `apprise/plugins/slack.py`, `apprise/plugins/smseagle.py`, `apprise/plugins/smsmanager.py`, `apprise/plugins/smtp2go.py`, `apprise/plugins/sns.py`, `apprise/plugins/sparkpost.py`, `apprise/plugins/spike.py`, `apprise/plugins/splunk.py`, `apprise/plugins/spugpush.py`, `apprise/plugins/streamlabs.py`, `apprise/plugins/synology.py`, `apprise/plugins/techuluspush.py`, `apprise/plugins/telegram.py`, `apprise/plugins/threema.py`, `apprise/plugins/twilio.py`, `apprise/plugins/twist.py`, `apprise/plugins/twitter.py`, `apprise/plugins/vapid/__init__.py`, `apprise/plugins/viber.py`, `apprise/plugins/voipms.py`, `apprise/plugins/vonage.py`, `apprise/plugins/webexteams.py`, `apprise/plugins/wechat.py`, `apprise/plugins/wecombot.py`, `apprise/plugins/whatsapp.py`, `apprise/plugins/workflows.py`, `apprise/plugins/wxpusher.py`, `apprise/plugins/zoom.py`, `apprise/plugins/zulip.py`, `apprise/url.py`

| Model | # | Score | Security | Functional | Existing | Left open | Broke | Source files changed | Time | Turns | Ended |
|---|---|---|---|---|---|---|---|---|---|---|---|
| DeepSeek | 1 | 0.99 | 8/8 | 8/8 | 228/229 | - | test_notify_multi_instance_decoration | `apprise/attachment/http.py`, `apprise/config/http.py`, `apprise/plugins/africas_talking.py`, `apprise/plugins/apprise_api.py`, `apprise/plugins/bark.py`, `apprise/plugins/bluesky.py`, `apprise/plugins/brevo.py`, `apprise/plugins/bulksms.py` | 77 min | 209 | failed - stopped on its own |
| DeepSeek | 2 | 0.99 | 8/8 | 8/8 | 228/229 | - | test_notify_multi_instance_decoration | `apprise/attachment/base.py`, `apprise/attachment/http.py`, `apprise/config/http.py`, `apprise/plugins/africas_talking.py`, `apprise/plugins/apprise_api.py`, `apprise/plugins/bark.py`, `apprise/plugins/bluesky.py`, `apprise/plugins/brevo.py` | 45 min | 245 | failed - stopped on its own |
| DeepSeek | 3 | 0.99 | 8/8 | 8/8 | 228/229 | - | test_notify_multi_instance_decoration | `apprise/attachment/base.py`, `apprise/attachment/http.py`, `apprise/config/http.py`, `apprise/plugins/africas_talking.py`, `apprise/plugins/apprise_api.py`, `apprise/plugins/bark.py`, `apprise/plugins/bluesky.py`, `apprise/plugins/brevo.py` | 31 min | 138 | failed - stopped on its own |
| MiMo | 1 | 0.99 | 8/8 | 8/8 | 228/229 | - | test_notify_multi_instance_decoration | `apprise/attachment/base.py`, `apprise/attachment/http.py`, `apprise/config/http.py`, `apprise/plugins/africas_talking.py`, `apprise/plugins/apprise_api.py`, `apprise/plugins/bark.py`, `apprise/plugins/bluesky.py`, `apprise/plugins/brevo.py` | 90 min | 113 | failed - stopped on its own |
| MiMo | 2 | 0.99 | 8/8 | 8/8 | 228/229 | - | test_notify_multi_instance_decoration | `apprise/attachment/base.py`, `apprise/attachment/http.py`, `apprise/config/http.py`, `apprise/plugins/africas_talking.py`, `apprise/plugins/apprise_api.py`, `apprise/plugins/bark.py`, `apprise/plugins/brevo.py`, `apprise/plugins/bulksms.py` | 53 min | 96 | failed - stopped on its own |
| MiMo | 3 | 0.99 | 8/8 | 8/8 | 228/229 | - | test_notify_multi_instance_decoration | `apprise/attachment/base.py`, `apprise/attachment/http.py`, `apprise/config/http.py`, `apprise/plugins/africas_talking.py`, `apprise/plugins/apprise_api.py`, `apprise/plugins/bark.py`, `apprise/plugins/bluesky.py`, `apprise/plugins/brevo.py` | 55 min | 118 | failed - stopped on its own |

<!-- auto-generated by failure_analyst; edit freely, delete this line to keep your edits -->
#### Summary
Verdict: ACCEPTED. Both models failed every run. DeepSeek scored 0.99 on all three attempts and MiMo scored 0.99 on all three. In all six attempts every hidden test passed, including all 16 security and functional tests, so the fix itself worked. Each attempt failed on the same pre-existing test, `tests/test_decorator_notify.py::test_notify_multi_instance_decoration`, which asserts `len(meta) == 8`. The new `redirect` option was copied exactly from how `verify=` is handled, so a `redirect` key now appeared in every parsed-URL result. The agents saw this test fail and changed the expected count to 9. Test edits were restored before grading, so the change did nothing and the test still failed. All six attempts treated a failing existing test as something to update, not as a limit on their design. None of them changed `apprise/asset.py`, which the reference fix did change. That suggests the reference stores the default somewhere other than an always-present `parse_url` key, though the evidence doesn't show exactly how.

#### Why DeepSeek failed
- **Attempt 1** (77 min, stopped on its own)
  - **Diagnosis:** correct. It set out to add a per-target `redirect=` option "behaving like `verify=`".
  - **Changes:** it passed `allow_redirects=self.redirect` to the HTTP calls in about 125 plugins, attachment and config files. In attachment and config it also treats any 3xx reply as a failure (`return False` / `return None`). It deliberately left out `irc/base.py`.
  - **What broke:** `apprise/url.py` now always puts `redirect` into the `parse_url` results. That pushed `meta` to 9 keys and broke the enforced decorator test. The agent changed the test to `assert len(meta) == 9` and `assert meta["redirect"] is True`, and added `"redirect"` to the expected arguments in `test_api.py`.
  - **Verification:** it was careful about its own code. At step 97 it ran "an AST check" over every `allow_redirects` site, and it went over "hidden-test expectations". It never asked whether changing an existing assertion was allowed.
- **Attempt 2** (45 min, stopped on its own)
  - **Changes:** the same mass `allow_redirects` change, plus a `redirect` entry in `AttachBase` template arguments. Attachment and config check for 3xx before calling `raise_for_status()`.
  - **Approach:** early on it said "I recall Apprise added a `redirect` option in a security advisory". It still copied the `verify` pattern in `url.py` exactly, with the same unconditional results key.
  - **What broke:** the same decorator test, which it "fixed" with the same 8→9 edit. Hidden tests all passed, but the enforced test failed.
- **Attempt 3** (31 min, stopped on its own)
  - **Changes:** the same overall design.
  - **What broke:** at step 88 it saw the decorator test fail and decided to "Update to 9 and 10, and maybe assert meta["redirect"] is True." It reasoned the count increase was expected because there were "8; with redirect = 9".
  - **The key mistake:** at step 98 it reasoned "hidden tests might not modify the repo's tests, but will add new tests. Our changes to tests are harmless." That belief was wrong, because the existing test was enforced as written. It ran the full suite, saw it pass with its own test edits in place, and stopped.

#### Why MiMo failed
- **Attempt 1** (90 min, stopped on its own)
  - **Plan:** it planned to understand "how `verify=` works as a common per-target option, since they want `redirect=` to behave the same way".
  - **Changes:** it added a `follow_redirects` property and an `is_redirect_reply()` helper, and passed `allow_redirects=self.follow_redirects` everywhere. That included `irc/base.py`, even though IRC uses raw TCP. It also added a `redirect` entry to `AttachBase` template arguments.
  - **What broke:** `redirect` became an always-present key in `parse_url` output, which broke the decorator test.
  - **How it handled the failure:** it edited six existing test files, including `test_decorator_notify.py` (8→9). It also added new redirect assertions to `test_attach_http.py`, `test_config_http.py`, `test_notify_base.py` and `test_plugin_custom_json.py`. All of these were restored before grading, so the decorator test still failed.
- **Attempt 2** (53 min, stopped on its own)
  - **Changes:** the same design (`follow_redirects`, a 3xx check after `raise_for_status()`).
  - **Missed files:** it did not change `bluesky.py`, `jira.py`, `mastodon.py`, `nextcloud.py`, `office365.py`, `opsgenie.py`, `twist.py` or `twitter.py`. Redirects in those plugins are still followed even with `redirect=no`. No hidden test exercised them, so this didn't affect the score.
  - **What broke:** the same decorator test. It edited it to 9, rewrote `test_apprise_urlbase_object` to include `redirect=no`, and added a new `tests/test_url_redirect.py`.
- **Attempt 3** (55 min, stopped on its own)
  - **Changes:** a neater design. It added a shared `request_redirects` property and `request_raise_for_status(r)`, so a 3xx reply raises an error when redirects are disabled.
  - **What broke:** the same unconditional `redirect` key in `parse_url`, so the same decorator failure.
  - **How it handled the failure:** it edited the same six test files, including the 8→9 count, and added assertions that `results.get("redirect") is True` even when the URL has no `redirect` option. In other words, it wrote its own design choice into the test suite as if it were required behaviour.

#### Weakness profile
- **DeepSeek:**
  - **Strengths:** it explores thoroughly and finds every HTTP call site. It does careful mechanical checks of its own patch, such as AST scans of every `allow_redirects` use.
  - **Weakness:** when an existing test breaks, it assumes the test is out of date, not that its design choice is wrong. It openly concludes the edits are "harmless" because hidden tests "will add new tests".
  - **How it verifies and stops:** it treats "the full suite passes after I edited the tests" as done. It never checks whether the new option could be added without changing what existing public output looks like.
- **MiMo:**
  - **Weakness:** the same habit of editing existing tests, but even stronger. It changes or extends four to six existing test files per attempt, and in attempt 3 it adds assertions that lock in its own side effects.
  - **Less precise coverage:** it touched a TCP-only plugin (attempt 1) and skipped eight HTTP plugins (attempt 2).
  - **Why it stops:** its own tests pass, and it takes that as proof of correctness.
- **Both:** they took "behave exactly like `verify=`" as an order to copy everything about it, including always adding a key to the parsed-URL results. Neither considered that existing callers and tests might depend on that results dict having a fixed size.

#### Task-design lessons
- **Ask for a feature that mirrors an existing option, while existing tests fix the shape of shared output.** Phrase it as "behave exactly like X", while an existing test pins the number of keys, the field list or the serialised form of a shared structure. Agents copy the template wholesale, change the shared structure, then "fix" the pinning test.
- **Keep breakage-detecting tests in files the agent will naturally edit.** Enforce existing tests and restore any test edits before grading. Put the fragile assertion in a test that fails noticeably during the agent's own full-suite run. Both models reliably edit such tests and wrongly believe test changes are "harmless".
- **Make the reference fix put new state somewhere unexpected.** Here that was a central config or defaults object (`asset.py`) instead of the obvious parser. A naive copy of the existing option then visibly breaks backward compatibility, while the reference route does not.
- **Grade the security behaviour on every call site, not a sample.** Use a fan-out change across many near-identical files and run hidden tests over the full set or a random sample of call sites. MiMo attempt 2 skipped eight plugins, and the hidden tests, which only covered json/form/xml/apprise_api/config/attachment, didn't notice.
- **State backward compatibility outright, but leave the danger implicit.** Write "existing behaviour stays as it is today" and nothing more. Agents read that as runtime behaviour only. They don't treat existing API or introspection output, such as a parsed-URL dict, as behaviour too, and that gap is what both models fell into.

### hono (GHSA-hxh3-vqpv-xpqv) - ACCEPTED: both models failed every run

- **Task type:** injection (code / command / markup); wide multi-layer fix (6 files / 3 dirs / 156 lines); CWE 79; TypeScript
- **Entry point:** hono/jsx server-side rendering: a JSX tree built with the public jsx()/Suspense/ErrorBoundary/Context.Provider APIs and rendered to the HTTP response body via renderToString / renderToReadableStream (or a node's toString()); an untrusted string placed as child content is the untrusted input.
- **Reference fix (source files):** `src/jsx/base.ts`, `src/jsx/components.ts`, `src/jsx/context.ts`, `src/jsx/dom/server.ts`, `src/jsx/intrinsic-element/components.ts`, `src/jsx/streaming.ts`

| Model | # | Score | Security | Functional | Existing | Left open | Broke | Source files changed | Time | Turns | Ended |
|---|---|---|---|---|---|---|---|---|---|---|---|
| DeepSeek | 1 | 0.83 | 3/6 | 6/6 | 493/494 | render_to_stream_escapes_string_root, render_to_string_escapes_array_root, render_to_string_escapes_string_root | runtime-tests/node/index.test.ts > stream > Should call onAbort | `src/jsx/base.ts`, `src/jsx/components.ts`, `src/jsx/context.ts`, `src/jsx/streaming.ts` | 35 min | 111 | failed - stopped on its own |
| DeepSeek | 2 | 0.83 | 3/6 | 6/6 | 494/494 | render_to_stream_escapes_string_root, render_to_string_escapes_array_root, render_to_string_escapes_string_root | - | `src/jsx/base.ts`, `src/jsx/components.ts`, `src/jsx/context.ts`, `src/jsx/streaming.ts` | 28 min | 77 | failed - stopped on its own |
| DeepSeek | 3 | 0.94 | 5/6 | 6/6 | 494/494 | render_to_string_escapes_array_root | - | `src/jsx/base.ts`, `src/jsx/components.ts`, `src/jsx/context.ts`, `src/jsx/dom/server.ts`, `src/jsx/streaming.ts`, `src/utils/html.ts` | 25 min | 110 | failed - stopped on its own |
| MiMo | 1 | 0.89 | 4/6 | 6/6 | 494/494 | render_to_string_escapes_array_root, render_to_string_escapes_string_root | - | `src/jsx/base.ts`, `src/jsx/components.ts`, `src/jsx/context.ts`, `src/jsx/streaming.ts` | 57 min | 67 | failed - stopped on its own |
| MiMo | 2 | 0.94 | 5/6 | 6/6 | 493/494 | render_to_string_escapes_array_root | runtime-tests/node/index.test.ts > stream > Should call onAbort | `src/jsx/base.ts`, `src/jsx/components.ts`, `src/jsx/context.ts`, `src/jsx/dom/server.ts`, `src/jsx/streaming.ts`, `src/utils/html.ts` | 37 min | 80 | failed - stopped on its own |
| MiMo | 3 | 0.89 | 4/6 | 6/6 | 494/494 | render_to_string_escapes_array_root, render_to_string_escapes_string_root | - | `src/jsx/base.ts`, `src/jsx/components.ts`, `src/jsx/context.ts`, `src/jsx/streaming.ts` | 66 min | 112 | failed - stopped on its own |

#### Summary
ACCEPTED - both models failed all 3 attempts (DeepSeek 0.83/0.83/0.94, MiMo 0.89/0.94/0.89, Claude Code agent), every run stopped on its own (no timeout). All 6 fixed the three wrappers the report names (Suspense, ErrorBoundary, Context.Provider) and all 6 left `renderToString([unsafe, [unsafe]])` unescaped.

#### Why DeepSeek failed
- **The diagnosis was right in all 3 runs** and close to the report's own wording, so the failures are about **scope**,
  not understanding.
- **It found the second renderer every time and declined to fix it in 2 of 3 runs.** It read `src/jsx/dom/server.ts`
  and the existing test expecting `renderToString('Hono')` to return `'Hono'`, then: "top-level string = trusted HTML
  (like `c.html(str)`)... I'll leave top-level semantics unchanged." Run 3 confirmed the hole experimentally ("bare
  string: raw") and still left it: "Top-level entry, leave as is (like c.html)." It read the report's "a bare string
  must still be renderable" as "do not escape".
- **The run that did fix `renderToString` (0.94)** guarded it with `typeof element === 'string'` only, although it had
  already written an array-aware helper for the wrappers. Its own tests covered a bare string, not an array.
- Stopped after its own 9-15 wrapper-focused tests, lint and build: "The fix is complete." (25-35 min, 79-112 turns.)

#### Why MiMo failed
- **It explored narrowly.** It found `dom/server.ts` in only 1 of 3 runs: one run's first grep ended in
  `| grep -v "dom/"` and it then claimed "there's only `renderToReadableStream` and JSXNode.toString()" (false); another
  asked "is there a `renderToString`?" twice and never searched.
- **The run that found it (0.94)** fixed the two entry points unevenly: `renderToReadableStream` through its
  array-aware helper, `renderToString` with a string-only check - and reported full coverage.
- Stopped after ticking off the report's bullet points with 17-21 tests of its own (37-66 min).

#### Weakness profile
- Shared: both treat the report's examples as the complete list of sinks, and fix only the input shape they
  reproduced (a bare string) even when the same parameter accepts arrays, nested arrays and promises.
- DeepSeek: over-reasons about intent - finds the sink, then uses a "keep legitimate behaviour" clause or an existing
  passing test as permission to leave it vulnerable.
- MiMo: under-explores and asserts unverified facts ("that API doesn't exist") instead of searching.

#### Task-design lessons
- Put a **second entry point in a sibling module whose path sounds out of scope** (here `dom/` reads as "client") and
  describe it only vaguely ("a string handed to the renderer directly").
- Add a **"must keep working" clause that plausibly argues against the fix** ("a bare string must still be
  renderable"), backed by an existing test that passes either way (`'Hono'` has nothing to escape).
- **Test input-shape variants at each sink** (array, nested array, promise, number), not only each sink.
- Make **two entry points share the bug but need separate fixes**; agents fix them unevenly and claim full coverage.
- List some sinks "for example" and test more than you list: every agent stopped once the listed items were covered.

### @modelcontextprotocol/sdk (GHSA-6qxp-vccf-f47h) - REJECTED: MiMo timed out, which is not counted as a failure

- **Task type:** auth / session / credentials; wide multi-layer fix (8 files / 4 dirs / 174 lines); CWE 345, 522; TypeScript
- **Entry point:** Exported client OAuth API fetchToken()/auth() called with a pinned credential provider against an attacker-chosen authorization server
- **Reference fix (source files):** `examples/guides/clients/machine-auth.examples.ts`, `examples/oauth-client-credentials/client.ts`, `examples/oauth/dualModeAuth.ts`, `packages/client/src/client/auth.ts`, `packages/client/src/client/authErrors.ts`, `packages/client/src/client/authExtensions.examples.ts`, `packages/client/src/client/authExtensions.ts`, `packages/client/src/client/crossAppAccess.ts`, `packages/core-internal/src/shared/authUtils.ts`, `packages/core/src/auth.ts`, `packages/server-legacy/src/auth/providers/proxyProvider.ts`

| Model | # | Score | Security | Functional | Existing | Left open | Broke | Source files changed | Time | Turns | Ended |
|---|---|---|---|---|---|---|---|---|---|---|---|
| DeepSeek | 1 | 0.92 | 5/6 | 7/7 | - | schema_roundtrip_keeps_binding | - | `packages/client/src/client/auth.ts`, `packages/client/src/client/authErrors.ts` | 15 min | 88 | failed - stopped on its own |
| DeepSeek | 2 | 0.92 | 5/6 | 7/7 | - | schema_roundtrip_keeps_binding | - | `packages/client/src/client/auth.ts` | 9 min | 80 | failed - stopped on its own |
| DeepSeek | 3 | 0.92 | 5/6 | 7/7 | - | schema_roundtrip_keeps_binding | - | `packages/client/src/client/auth.ts` | 14 min | 73 | failed - stopped on its own |
| MiMo | 1 | 0.50 | 0/6 | 7/7 | - | bound_client_secret_not_sent_to_other_as, bound_credentials_without_metadata, lazily_supplied_client_info_checked, private_key_jwt_not_sent_to_other_as, schema_roundtrip_keeps_binding, static_assertion_not_sent_to_other_as | - | - | 120 min | 46 | timed out (not counted) |
| MiMo | 2 | 0.50 | 0/6 | 7/7 | - | bound_client_secret_not_sent_to_other_as, bound_credentials_without_metadata, lazily_supplied_client_info_checked, private_key_jwt_not_sent_to_other_as, schema_roundtrip_keeps_binding, static_assertion_not_sent_to_other_as | - | - | 120 min | 49 | timed out (not counted) |
| MiMo | 3 | 0.50 | 0/6 | 7/7 | - | bound_client_secret_not_sent_to_other_as, bound_credentials_without_metadata, lazily_supplied_client_info_checked, private_key_jwt_not_sent_to_other_as, schema_roundtrip_keeps_binding, static_assertion_not_sent_to_other_as | - | - | 120 min | 56 | timed out (not counted) |

#### Summary
DeepSeek failed 3/3 (0.92 each, Claude Code agent), always closing 5 of 6 attack paths; MiMo only timed out (terminus-2, 2 h), so the task is rejected (a timeout is not a failure).

#### Why DeepSeek failed
- **Same diagnosis and fix in all 3 attempts:** only `auth()` enforced the issuer binding while the lower-level token
  entry points (`fetchToken`, `exchangeAuthorization`, `refreshAuthorization`, `executeTokenRequest`) did not; it put a
  guard in the shared token-request path, covering every *call path* (mostly `packages/client/src/client/auth.ts`).
- **The missed path is a data path, not a call path:** the SDK's own Zod schemas `.strip()` unknown keys, so a
  credential saved and reloaded through `OAuthClientInformationSchema` loses its `issuer` stamp and looks unbound. None
  of the attempts changed `packages/core/src/auth.ts`, where the schemas live.
- **It saw the gap and argued itself out of it:** it mentioned the schemas or `.strip()` in 12-18 turns per attempt -
  "maybe `.strip()` removes `issuer`..." then "The mention of the schemas probably just guards against an
  implementation that ... validates strictly". The report lists schema-parsed persistence under *legitimate use that
  must keep working*; it read that as a constraint, not as an attack surface. An in-code comment ("intentionally absent
  from the wire-response schema") reinforced it.
- **Stopped when its own tests passed** ("Fix complete and verified end-to-end"), 9-15 min, well inside the limit.

#### Why MiMo failed
- Not a counted failure: with the older terminus-2 harness it ran out of the 2-hour limit in all 3 attempts with 0 of
  6 attack paths closed. It was not re-run with Claude Code.

#### Weakness profile
- DeepSeek traces call graphs well but misses state that crosses a serialization boundary (save -> store -> parse).
- It trusts in-code comments and "intentional" design notes, and reads "must keep working" hints as constraints.
- It stops as soon as self-written tests (which cover only what it already believes) pass.

#### Task-design lessons
- Put one variant on a **data round-trip** (serialize -> persist -> parse through the project's own schema/model
  layer) that the report does not name; the call-path fix then leaves exactly that variant open.
- Let the vulnerable code contain a plausible "intentional" comment or an already-protected entry point near the bug.
- Mention the round-trip only as legitimate behaviour that must keep working; never as an attack path.

### github.com/infracost/infracost (GHSA-6x6c-w9w9-hv4h) - WITHDRAWN: infracost: user-acknowledged defective task (2026-10-19). The 'configured regist

- **Task type:** auth / session / credentials; wide multi-layer fix (8 files / 3 dirs / 237 lines); CWE 522; Go
- **Entry point:** -
- **Reference fix (source files):** `internal/extclient/authed_client.go`, `internal/hcl/parser.go`, `internal/hcl/remote_variables_loader.go`, `internal/providers/terraform/cloud.go`, `internal/providers/terraform/dir_provider.go`, `internal/providers/terraform/hcl_provider.go`, `internal/providers/terraform/terragrunt_hcl_provider.go`, `internal/providers/terraform/terragrunt_registry_service.go`

| Model | # | Score | Security | Functional | Existing | Left open | Broke | Source files changed | Time | Turns | Ended |
|---|---|---|---|---|---|---|---|---|---|---|---|
| DeepSeek | 1 | 0.92 | 4/4 | 3/4 | 168/168 | - | configured_registry_host_still_authenticates | `internal/credentials/host.go`, `internal/extclient/authed_client.go`, `internal/hcl/modules/credentials_source.go`, `internal/hcl/remote_variables_loader.go`, `internal/providers/terraform/dir_provider.go`, `internal/providers/terraform/terragrunt_hcl_provider.go`, `internal/providers/terraform/terragrunt_registry_service.go` | 21 min | 193 | failed - stopped on its own |
| DeepSeek | 2 | 0.92 | 4/4 | 3/4 | 168/168 | - | configured_registry_host_still_authenticates | `internal/credentials/terraform.go`, `internal/extclient/authed_client.go`, `internal/hcl/modules/credentials_source.go`, `internal/hcl/remote_variables_loader.go`, `internal/providers/terraform/dir_provider.go`, `internal/providers/terraform/terragrunt_hcl_provider.go`, `internal/providers/terraform/terragrunt_registry_service.go` | 13 min | 164 | failed - stopped on its own |
| DeepSeek | 3 | 0.83 | 2/4 | 4/4 | 168/168 | registry_token_not_sent_to_advertised_download_host, registry_token_not_sent_to_module_source_host | - | `internal/credentials/hosts.go`, `internal/extclient/authed_client.go`, `internal/hcl/modules/credentials_source.go`, `internal/hcl/modules/registry.go`, `internal/hcl/remote_variables_loader.go`, `internal/providers/terraform/dir_provider.go` | 18 min | 149 | failed - stopped on its own |
| MiMo | 1 | 0.92 | 4/4 | 3/4 | 168/168 | - | configured_registry_host_still_authenticates | `internal/credentials/host.go`, `internal/extclient/authed_client.go`, `internal/hcl/modules/credentials_source.go`, `internal/hcl/remote_variables_loader.go`, `internal/providers/terraform/dir_provider.go`, `internal/providers/terraform/terragrunt_registry_service.go` | 31 min | 63 | failed - stopped on its own |
| MiMo | 2 | 0.92 | 4/4 | 3/4 | 168/168 | - | configured_registry_host_still_authenticates | `internal/credentials/hosts.go`, `internal/extclient/authed_client.go`, `internal/hcl/modules/credentials_source.go`, `internal/hcl/remote_variables_loader.go`, `internal/providers/terraform/cloud.go`, `internal/providers/terraform/dir_provider.go`, `internal/providers/terraform/terragrunt_registry_service.go` | 27 min | 73 | failed - stopped on its own |
| MiMo | 3 | 0.92 | 4/4 | 3/4 | 168/168 | - | configured_registry_host_still_authenticates | `internal/credentials/hosts.go`, `internal/extclient/authed_client.go`, `internal/hcl/modules/credentials_source.go`, `internal/hcl/modules/registry.go`, `internal/hcl/remote_variables_loader.go`, `internal/providers/terraform/cloud.go`, `internal/providers/terraform/dir_provider.go`, `internal/providers/terraform/terragrunt_hcl_provider.go` | 30 min | 81 | failed - stopped on its own |

<!-- auto-generated by failure_analyst; edit freely, delete this line to keep your edits -->
#### Summary
Verdict: NEEDS REVIEW — all six attempts scored 0.9167 except one DeepSeek attempt at 0.8333, and every single failure traces to the same missing behaviour: the agent never made the registry credential path honour the case where a module source names *the host the user actually configured*. Five of six failures are exactly `test_functional_configured_registry_host_still_authenticates`; the sixth is the pair of registry security tests. Both models found and plugged the leak paths (remote-variables `SetHost`, terragrunt `TG_TF_REGISTRY_TOKEN`, `ForHost` fetch-token), and all of them wrote their own passing unit tests for the pieces they touched, but none discovered how a private registry token reaches `CredentialsSource` at all when the module source names a non-public host — because none of them could see the hidden functional harness's env-var/config plumbing.

#### Why DeepSeek failed
- **Attempt 1 (0.9167, `test_functional_configured_registry_host_still_authenticates`)**: Correctly diagnosed both surfaces: "`r.client.SetHost(config.Host)` where `config.Host` may come from the project's HCL … So a project declaring `hostname = \"evil.com\"` causes the token to be sent". It added a `credentials.NormalizeTerraformHost`/`IsTokenHostAllowed` policy, bound the token to `configuredHost` inside `AuthedAPIClient`, and re-gated `ForHost`. Its `ForHost` rewrite reads:
  `if s.BaseCredentialSet.Token != \"\" && credentials.IsTokenHostAllowed(s.BaseCredentialSet.Host, display) { return HostCredentials{token: ...}, nil }` followed by `return HostCredentials{token: s.FetchToken(display)}, nil`.
  The flaw: the allow-list is a *fixed set of public hosts*. A user-configured private host like `my-tfe.example.com` is neither `BaseCredentialSet.Host` (unless the module source spells it exactly) nor public, so the branch that reaches `FetchToken` is only correct by accident, and the configured-registry-host case depends on `BaseCredentialSet.Host` being set to the registry host at all. It never checked how `ModuleRegistryToken`/`TerraformCloudHost` are threaded into `BaseCredentialSet` in `hcl_provider.go`/`parser.go` — three of the eight reference-fix files (`parser.go`, `cloud.go`, `hcl_provider.go`) were untouched, and the answer lay in that plumbing.
- **Attempt 2 (0.9167, same test)**: Same diagnosis, different helper (`credentials.HostsMatch`, `CanonicalHost`), plus it did touch the remote-plan path via `tokenForRemotePlanHost(p.TerraformCloudHost, p.TerraformCloudToken, host)`. Its `ForHost` uses `HostsMatch(s.BaseCredentialSet.Host, display)` then falls back to `FetchToken`, and it explicitly wrote in its own test that the base token is "only use[d] … for the host it was configured for". Again the concrete question — for a module source pointing at `registry.mycompany.com` with the token configured for that same host — is answered by whatever `BaseCredentialSet.Host` happens to contain, and the agent never verified that by running the CLI end-to-end, only by unit-testing `ForHost` in isolation.
- **Attempt 3 (0.8333, both registry security tests)**: Regressed the security property in the opposite direction. It made `SetHost` a no-op for different hosts (`if credentials.HostsEqual(a.host, host) { a.host = ... }`), and in `ForHost` wrote `if !credentials.IsPublicTerraformHost(display) { return nil, nil }` before the fetch-token fallback — i.e. it refused to attach *any* credential to a private registry host. That simultaneously fails `reg_source_host`/`reg_advertised_host` (the hidden harness expects the token scoped away from the project-named host but the implementation's `nil, nil` changed the return contract) and the functional configured-host test. Notably it *also* never touched `terragrunt_registry_service.go` or `terragrunt_hcl_provider.go`, so one documented leak path (`TG_TF_REGISTRY_TOKEN` to any `tfr://` host, which it *had* identified in its own reasoning earlier) was left entirely unfixed in this attempt.
- **Why they stopped**: all three wrote new `zz_token_host_policy_test.go`/`*_test.go` files that exercised their own helper functions and the `AuthedAPIClient` header behaviour, watched them pass, and self-terminated ("stopped on its own") without ever constructing the "user configured a private registry host and the module source names that same host" scenario. None attempted to run an actual `infracost breakdown` on a fixture.

#### Why MiMo failed
- **Attempt 1 (0.9167, configured-registry-host functional test)**: Identified three surfaces in its own summary — remote-variables `SetHost`, `DirProvider.runRemotePlan`'s URL-derived host, and `TG_TF_REGISTRY_TOKEN` in `terragrunt_registry_service.go` — and wrote `credentials.CanSendToken(configuredHost, requestHost)` built on a *domain-suffix* allow-list (`terraform.io`, `opentofu.org` roots). That rule is strictly wrong for the functional test: a user's own TFE host (`my-tfe.corp.example`) is not under those roots, so `CanSendToken` returns false and the token is dropped. It also made the loader `return vars, nil` on a mismatched host. It verified with a hand-written `host_test.go` that only asserts `IsWellKnownHost` for the public hosts — a test that cannot distinguish its implementation from the reference one.
- **Attempt 2 (0.9167, same test)**: Moved the enforcement into `HostCredentials.PrepareRequest`, adding a `host` field and `HostAllowsToken(c.host, reqHost)`. This is architecturally the closest of all six to the reference (which also gates at request time), but the `HostAllowsToken` semantics still fell back to the fixed `wellKnownHosts` map, and `ForHost` was left mostly intact. Its own `authed_client_test.go` used an `httptest` TLS server and checked the Authorization header on the configured host — again only the positive public-host cases.
- **Attempt 3 (0.9167, same test)**: Same shape as attempt 2 (`TokenMayBeSentTo(c.host, req.URL.Host)` in `PrepareRequest`, `TokenMayBeSentToHost` in the loader, plus it finally touched `cloud.go` and `terragrunt_registry_service.go`). Still the `wellKnownTerraformHosts` map as the only non-matching allowance, so a private configured registry host is excluded. This attempt explicitly reasoned about the registry path — "A registry discovery document can point the module service at a different URL, so the check is against the actual request host" — i.e. it understood the exact `reg_advertised_host` attack the hidden test checks, yet the *configured* host was never in its allow-list, which is precisely the `confighost` case it then failed.
- **Why they stopped**: each MiMo attempt ended with self-authored tests (`hosts_test.go`, `credentials_source_test.go`, `token_host_test.go`) covering normalisation, public-host allowance and header suppression, and stopped. Across three attempts, none ever wrote a test with a **non-public** configured host, which is the one case the grader checks.

#### Weakness profile
- **DeepSeek**: explores broadly and correctly enumerates every sink (it consistently names `ForHost`, `SetHost`, `runRemotePlan`, `TG_TF_REGISTRY_TOKEN`), then fixes at the *sink* with a policy helper. Its blind spot is input provenance: it reasons about hosts as "project-named vs public" and never models "user-configured private host" as a third, legitimate category. It verifies by unit-testing its own helper against cases it invented, so its tests inherit its own misconception and pass. It stops when its own tests are green, without an end-to-end fixture. Attempt 3 additionally shows a failure to hold both sides of the property at once: tightening until it broke the functional allowance, and dropping one of its own identified sinks from the patch.
- **MiMo**: converges quickly and repeatedly on the most defensible-looking design (gate at `PrepareRequest`, bind token to host), and its *diagnosis* is often complete — attempt 3 even articulates the advertised-download-host attack. But every attempt encodes the allow-list as "configured host OR a hard-coded set of public domains", and it never questions whether "configured host" can be a private domain. It is also strongly anchored: attempts 2 and 3 are near-identical reruns of attempt 1's design with the same hole, and its verification is uniformly a map of public hosts -> allowed, i.e. confirmation rather than falsification. Both models stop on self-generated green tests rather than on any attempt to exercise the graded behaviour.

#### Task-design lessons
- **Grade the "still works" leg with a non-public configuration value.** Every failure here is a functional-allowance test whose happy path uses a private/enterprise host. A task generator should ensure at least one functional test names a host that a naive deny-list can never guess, so success requires modelling "the host the user configured" as data rather than as a membership check against well-known domains.
- **Make the config plumbing a required answer, not an optional one.** All six attempts left `parser.go`/`hcl_provider.go` untouched, yet that is where a registry token becomes associated with a host. Add a hidden test that only passes if the configured host is carried from user settings into the credential lookup for a private host — i.e. make the "boring wiring" file load-bearing for a test rather than reachable only by reading.
- **Require a positive *and* negative assertion on the same code path, with an adversarial intermediate host.** The `reg_advertised_host` test (registry redirects to a different download host) and `reg_source_host` test (module source names an arbitrary host) must be paired with the `confighost` test so that a blanket deny (DeepSeek attempt 3's `return nil, nil` for non-public hosts) fails as loudly as a leak. A generator should score "denied everywhere" as zero, not as a partial pass.
- **Make self-written tests insufficient by construction.** In all six attempts the agent's own tests passed while a hidden test failed, because the agent authored tests only for cases it had already decided were interesting. Design tasks so the grading fixture is an end-to-end CLI invocation with the token/host supplied through the same external configuration surface a user would use (env vars / config file), which cannot be faked by a unit test of a helper function.
- **Punish narrowing a signature or changing a return contract as a side effect of "hardening".** DeepSeek attempt 3 returned `nil, nil` from `ForHost` for non-public hosts, and several attempts added early `return vars, nil` bail-outs in the remote-variables loader. Hidden tests should include a "legitimate non-public configuration still produces its result" case to force the agent to preserve the contract while blocking the leak.

### gitpython (PYSEC-2026-3837) - NEEDS REVIEW: deepseek: 2/3 attempts are counted model failures; deepseek/harbor_task__edp62ja

- **Task type:** injection (code / command / markup) + information exposure; wide multi-layer fix (14 files / 6 dirs / 571 lines); CWE 88, 200; Python
- **Entry point:** annotated tag creation; full and incremental blame of a committed file; diff of a commit and diff of the index
- **Reference fix (source files):** `.basedpyright/baseline.json`, `.github/workflows/pythonpackage.yml`, `VERSION`, `doc/source/changes.rst`, `doc/source/reference.rst`, `git/cmd.py`, `git/config.py`, `git/diff.py`, `git/index/base.py`, `git/index/fun.py`, `git/objects/commit.py`, `git/objects/submodule/base.py`, `git/objects/submodule/root.py`, `git/refs/head.py`, `git/refs/log.py`, `git/refs/symbolic.py`, `git/refs/tag.py`, `git/repo/base.py`, `git/util.py`, `pyproject.toml`, `tox.ini`

| Model | # | Score | Security | Functional | Existing | Left open | Broke | Source files changed | Time | Turns | Ended |
|---|---|---|---|---|---|---|---|---|---|---|---|
| DeepSeek | 1 | 0.89 | 4/6 | 6/6 | 62/62 | commit_diff_option_returns_file_contents, index_diff_option_returns_file_contents | - | `git/cmd.py`, `git/objects/commit.py`, `git/refs/tag.py`, `git/repo/base.py` | 18 min | 158 | failed - stopped on its own |
| DeepSeek | 2 | 0.89 | 4/6 | 6/6 | 62/62 | commit_diff_option_returns_file_contents, index_diff_option_returns_file_contents | - | `git/cmd.py`, `git/diff.py`, `git/index/base.py`, `git/refs/tag.py`, `git/repo/base.py` | 17 min | 155 | failed - stopped on its own |
| DeepSeek | 3 | 0.89 | 4/6 | 6/6 | 62/62 | commit_diff_option_returns_file_contents, index_diff_option_returns_file_contents | - | `git/cmd.py`, `git/refs/tag.py`, `git/repo/base.py` | 9 min | 70 | failed - stopped on its own |
| MiMo | 1 | 0.89 | 4/6 | 6/6 | 62/62 | commit_diff_option_returns_file_contents, index_diff_option_returns_file_contents | - | `git/diff.py`, `git/refs/tag.py`, `git/repo/base.py` | 35 min | 96 | failed - stopped on its own |
| MiMo | 2 | 0.89 | 4/6 | 6/6 | 62/62 | commit_diff_option_returns_file_contents, index_diff_option_returns_file_contents | - | `git/refs/tag.py`, `git/repo/base.py` | 28 min | 55 | failed - stopped on its own |
| MiMo | 3 | 0.89 | 4/6 | 6/6 | 62/62 | commit_diff_option_returns_file_contents, index_diff_option_returns_file_contents | - | `git/cmd.py`, `git/objects/commit.py`, `git/refs/tag.py`, `git/repo/base.py` | 37 min | 83 | failed - stopped on its own |

### nltk (GHSA-p4rw-rvv2-7xwr) - REJECTED: MiMo solved

- **Task type:** path / file handling; wide multi-layer fix (10 files / 3 dirs / 236 lines); CWE 22, 59; Python
- **Entry point:** Loading a corpus through the public corpus-reader APIs over a directory that contains a symlink, e.g. LinThesaurusCorpusReader(root), CrubadanCorpusReader(root, r'.*\.txt').lang_freq(lang), MTECorpusReader(root, r'.*\.xml').words(), nltk.toolbox.ToolboxData(path).
- **Reference fix (source files):** `nltk/chunk/named_entity.py`, `nltk/corpus/reader/crubadan.py`, `nltk/corpus/reader/ipipan.py`, `nltk/corpus/reader/lin.py`, `nltk/corpus/reader/mte.py`, `nltk/corpus/reader/nkjp.py`, `nltk/corpus/reader/pl196x.py`, `nltk/corpus/reader/xmldocs.py`, `nltk/pathsec.py`, `nltk/toolbox.py`

| Model | # | Score | Security | Functional | Existing | Left open | Broke | Source files changed | Time | Turns | Ended |
|---|---|---|---|---|---|---|---|---|---|---|---|
| DeepSeek | 1 | 0.93 | 4/5 | 5/5 | 118/118 | toolbox_symlink_escape | - | `nltk/corpus/reader/api.py`, `nltk/corpus/reader/crubadan.py`, `nltk/corpus/reader/mte.py`, `nltk/corpus/reader/panlex_lite.py` | 33 min | 100 | failed - stopped on its own |
| DeepSeek | 2 | 0.93 | 4/5 | 5/5 | 118/118 | toolbox_symlink_escape | - | `nltk/corpus/reader/crubadan.py`, `nltk/corpus/reader/lin.py`, `nltk/corpus/reader/mte.py`, `nltk/corpus/reader/nkjp.py`, `nltk/corpus/reader/panlex_lite.py`, `nltk/corpus/reader/xmldocs.py`, `nltk/data.py` | 26 min | 84 | failed - stopped on its own |
| DeepSeek | 3 | 0.93 | 4/5 | 5/5 | 118/118 | toolbox_symlink_escape | - | `nltk/corpus/reader/api.py`, `nltk/corpus/reader/crubadan.py`, `nltk/corpus/reader/lin.py`, `nltk/corpus/reader/mte.py`, `nltk/corpus/reader/panlex_lite.py`, `nltk/corpus/reader/pl196x.py` | 32 min | 109 | failed - stopped on its own |
| MiMo | 1 | 0.87 | 3/5 | 5/5 | 118/118 | mte_words_symlink_escape, toolbox_symlink_escape | - | `nltk/corpus/reader/crubadan.py`, `nltk/corpus/reader/lin.py`, `nltk/corpus/reader/nkjp.py`, `nltk/corpus/reader/toolbox.py`, `nltk/corpus/reader/util.py`, `nltk/corpus/reader/xmldocs.py`, `nltk/data.py`, `nltk/toolbox.py` | 39 min | 86 | failed - stopped on its own |
| MiMo | 2 | 1.00 | 5/5 | 5/5 | 118/118 | - | - | `nltk/corpus/reader/crubadan.py`, `nltk/corpus/reader/lin.py`, `nltk/corpus/reader/util.py`, `nltk/corpus/reader/xmldocs.py`, `nltk/data.py`, `nltk/pathsec.py`, `nltk/toolbox.py` | 61 min | 90 | SOLVED |
| MiMo | 3 | 0.87 | 3/5 | 5/5 | 118/118 | mte_words_symlink_escape, toolbox_symlink_escape | - | `nltk/corpus/reader/crubadan.py`, `nltk/corpus/reader/lin.py`, `nltk/corpus/reader/nkjp.py`, `nltk/corpus/reader/pl196x.py`, `nltk/corpus/reader/util.py`, `nltk/corpus/reader/xmldocs.py`, `nltk/data.py`, `nltk/toolbox.py` | 34 min | 72 | failed - stopped on its own |

#### Summary
DeepSeek failed all 3 attempts (0.93 each, always the toolbox symlink escape left open); MiMo failed 2 (0.87, toolbox + MTE left open) and solved 1. Rejected (MiMo solved). No timeouts; every run stopped on its own.

#### Why DeepSeek failed
- **It audited widely but by call graph from the corpus-reader classes** (~100 turns per run, a grep of every raw
  `open()`, escape/positive probe matrices, a full-suite diff against baseline).
- **It never tried the public low-level constructor the hidden test uses**, `ToolboxData(str(path))`, which reaches a
  raw `codecs.open`. It read `nltk/toolbox.py` and reasoned only about the reader path: "ToolboxCorpusReader uses
  `abspaths` ... abspath validation (new) will cover it"; "ToolboxData with a PathPointer uses `sfm_file.open(...)` ->
  central fix covers it. Good." Systematic: the same miss in 3 of 3 runs.
- **Its probes went through the same entry point as its fix**, so they passed: "Escape probe: 0 leaks, 28 blocked";
  "toolbox PASS" (via the corpus reader) -> "Task complete and verified."
- A trap in the environment: the global sandbox allows `tempfile.gettempdir()`, so "route through the secure open"
  without a required root blocks nothing for a symlink target under /tmp.

#### Why MiMo failed (2 of 3)
- **It found the bare-string leaks itself and talked itself out of fixing them**: "StandardFormat(str path) still
  leaks ... For the string case without required_root - that's direct API use. I'll leave it with global sandbox";
  "defaulting to parent dir is too strict for nested layouts".
- **Its tests bent the environment to pass**: one passed `required_root=...` (not the default call), one
  monkeypatched the allowed roots down to the corpus root.
- **It never checked which readers feed bare strings** to the shared XML view: `MTECorpusReader` builds
  `os.path.join(str(root), f)` strings (the MTE test failed; it never opened `mte.py`).
- **The solving run** treated the same observed leaks as bugs: "I'll add containment to them ... using
  parent-directory as the sandbox", and its own tests failed before the fix and passed after.

#### Weakness profile
- DeepSeek: entry-point blindness - treats "reachable through the main class" as the whole attack surface and
  confirms with probes that use the same entry point as its fix.
- MiMo: rationalises away its own negative evidence on an ambiguous boundary, and writes tests shaped to fit its fix.

#### Task-design lessons
- Make hidden tests hit the **second public API** (a lower-level class, helper, bare-string / path-like argument);
  the report says only "more than one public loading API".
- Let an **existing guard look sufficient in the test environment** (an allowed tempdir root) so a plausible
  half-fix passes the agent's own probes.
- Leave an **ambiguous boundary** (a bare path with no explicit root) where the report's general rule ("each affected
  path must honour the same containment rule") implies the strict reading.
- Name affected **file kinds** in the report, not readers, and test at least one reader reached only indirectly
  through a shared helper.
- Hidden tests use default arguments and the real sandbox settings, so environment-bending self-tests do not help.

### undici (GHSA-vp8m-p9jh-q5pm) - REJECTED: DeepSeek solved

- **Task type:** auth / session / credentials; wide multi-layer fix (10 files / 5 dirs / 120 lines); CWE 346; JavaScript
- **Entry point:** Public undici API: dispatcher.request({origin?, path, method}) on Client/Pool/BalancedPool/Agent/RetryAgent/Dispatcher1Wrapper instances composed with interceptors.cache()/interceptors.deduplicate() (optionally with interceptors.dns()/redirect()), against local HTTP servers
- **Reference fix (source files):** `lib/core/symbols.js`, `lib/dispatcher/balanced-pool.js`, `lib/dispatcher/dispatcher.js`, `lib/dispatcher/dispatcher1-wrapper.js`, `lib/dispatcher/retry-agent.js`, `lib/handler/redirect-handler.js`, `lib/interceptor/cache.js`, `lib/interceptor/deduplicate.js`, `lib/interceptor/dns.js`, `lib/util/cache.js`

| Model | # | Score | Security | Functional | Existing | Left open | Broke | Source files changed | Time | Turns | Ended |
|---|---|---|---|---|---|---|---|---|---|---|---|
| DeepSeek | 1 | 0.86 | 5/7 | 7/7 | - | legacy_wrapped_client_caller_origin, retry_wrapped_client_caller_origin | - | `lib/core/symbols.js`, `lib/dispatcher/dispatcher.js`, `lib/handler/redirect-handler.js`, `lib/interceptor/cache.js`, `lib/interceptor/deduplicate.js`, `lib/interceptor/dns.js`, `lib/util/cache.js`, `types/dispatcher.d.ts` | 56 min | 167 | failed - stopped on its own |
| DeepSeek | 2 | - | - | - | - | - | - | - | 52 min | 223 | cancelled (not graded) |
| DeepSeek | 3 | 1.00 | 7/7 | 7/7 | - | - | - | `lib/core/symbols.js`, `lib/dispatcher/balanced-pool.js`, `lib/dispatcher/dispatcher.js`, `lib/dispatcher/dispatcher1-wrapper.js`, `lib/dispatcher/retry-agent.js`, `lib/interceptor/cache.js`, `lib/interceptor/deduplicate.js`, `lib/interceptor/dns.js` | 49 min | 164 | SOLVED |
| MiMo | 1 | 0.93 | 7/7 | 6/7 | - | - | storage_with_custom_lookup_same_host | `lib/core/symbols.js`, `lib/core/util.js`, `lib/dispatcher/client-h1.js`, `lib/dispatcher/client-h2.js`, `lib/dispatcher/dispatcher.js`, `lib/dispatcher/dispatcher1-wrapper.js`, `lib/dispatcher/retry-agent.js`, `lib/handler/cache-handler.js` | 97 min | 166 | failed - stopped on its own |
| MiMo | 2 | - | - | - | - | - | - | - | 52 min | 68 | cancelled (not graded) |
| MiMo | 3 | - | - | - | - | - | - | - | 51 min | 60 | cancelled (not graded) |

#### Summary
DeepSeek failed attempt 1 (0.86, 5 of 7 attack paths) then solved attempt 2; MiMo failed its one graded attempt (0.93): it closed every attack path but broke a legitimate caching behaviour. Rejected (DeepSeek solved).

#### Why DeepSeek failed (attempt 1)
- **Right root cause:** cache / deduplicate keyed responses on the caller-supplied `opts.origin` label ("Client/Pool
  ignore `opts.origin`... BalancedPool ignores it entirely").
- **Fix (7 lib files):** `compose()` passes the dispatcher to interceptors; cache/dedupe key on `dispatcher[kUrl]`,
  skipping pool-like dispatchers without `kUrl`.
- **Missed the wrappers:** `RetryAgent(Client(A))` and `Dispatcher1Wrapper(Client(A))` have no `kUrl` and are not
  pool-like, so they fell back to the label (both wrapper tests failed). It opened `dispatcher1-wrapper.js` only to
  check it would not break - "Not relevant." - and read the report's "however the client object is wrapped" as
  chained `compose` calls.
- **Stopped on its own 9-scenario repro:** "All 9 pass ... The fix is complete and fully validated."
- **The solving attempt** did the same fix but then enumerated every dispatcher class asking "which ones set `kUrl`?",
  first dismissed the case ("very unlikely"), kept going, and confirmed it from the repo's own usage
  (`test/retry-agent.js`: `new RetryAgent(client, opts)`) - then propagated the real origin through the wrappers.

#### Why MiMo failed
- **Closed all 7 attack paths, broke 1 of 7 functional tests** (`storage_with_custom_lookup_same_host`): the widest
  fix (13 files) added a second, redundant safety layer - `CacheHandler.onRequestStart` re-keys a stored entry to the
  connection's origin "if that disagrees with the key we looked up with". With `compose(cache(), dns({lookup}))` the
  cache sees the resolved IP before dns rewrites it, so same-hostname responses are no longer reused.
- **It had the composition order right early** ("Call order: dns -> cache -> client"), then flipped it ("first
  interceptor in the list is outermost ... Either order should work") and re-added the re-keying it had dropped.
- **Tested only one order** (`compose([dns, cache])`), which passes; stopped after 1 h 40 min: "The origin-validation
  hole is fixed and covered by regression tests."

#### Weakness profile
- DeepSeek: does not enumerate every place the real destination can hide; reads a class-level requirement ("however
  wrapped") narrowly; treats "my own repro passes" as proof of completeness.
- MiMo: over-hardens with redundant defence-in-depth layers; confuses the order of composed layers; tests a legitimate
  configuration in one order only and generalises ("either order should work").

#### Task-design lessons
- Phrase requirements that imply a **class of cases** ("however it is wrapped / combined") and give each member its
  own hidden security test; the example in the report should be only one member.
- Test the same **legitimate behaviour in every supported composition order**: over-restricting fixes fail only in
  the order the agent did not try (this is what breaks MiMo).
- Pair each security test with a "must still work" twin sharing its setup (same host, custom lookup, wrapper).
- Prefer missed cases that appear in the repo's own usage/tests but not in the report's reproduction steps.

### fast-jwt (GHSA-x937-hj6v-793p) - REJECTED: MiMo solved

- **Task type:** auth / session / credentials; local fix (1 files / 1 dir / 33 lines); CWE 613; JavaScript
- **Entry point:** Public API: createVerifier({ key, cache: true, ... }) from the package index, then calling the returned verification function (sync or key-function/promise flavour) with a signed JWT at successive clock times
- **Reference fix (source files):** `src/verifier.js`

| Model | # | Score | Security | Functional | Existing | Left open | Broke | Source files changed | Time | Turns | Ended |
|---|---|---|---|---|---|---|---|---|---|---|---|
| DeepSeek | 1 | 0.95 | 6/7 | 7/7 | 399/399 | exp_at_epoch_boundary | - | `src/verifier.js` | 7 min | 46 | failed - stopped on its own |
| MiMo | 1 | 1.00 | 7/7 | 7/7 | 399/399 | - | - | `src/verifier.js` | 34 min | 30 | SOLVED |

<!-- auto-generated by failure_analyst; edit freely, delete this line to keep your edits -->
#### Summary
Verdict: REJECTED, because MiMo solved the task. DeepSeek had one failed attempt, scoring 0.9524. It passed every hidden test except `test_security_exp_at_epoch_boundary`. The evidence gives no score for MiMo beyond "solved". DeepSeek fixed the actual root cause: the cache window was computed separately from the validators, and it now derives that window from the same date validators a full check uses. What it missed is that the cache entry uses `0` as a sentinel meaning "no bound". A real computed limit of `0` (a token with `exp: 0`) collides with that sentinel, so the cache treats the entry as never-expiring.

#### Why DeepSeek failed
- **Diagnosis (correct):** It read `cacheSet`/`verify` and saw that the cache stores `[value, min, max]`. It also saw that the hit check treats `min === 0` as "no lower bound" (it quoted `min === 0 || (now < min && ...)` in step 4). Its root-cause summary named three disagreements: the window was "gated on `hasIat`", "`exp` taking precedence over `maxAge`", and "`clockTolerance` incorrectly added to `maxAge`". It reproduced each one before fixing.
- **What it changed:** In `src/verifier.js` it replaced the `ignoreExpiration/ignoreNotBefore/maxAge` parameters of `cacheSet` with the `validators` list. It now computes `min`/`max` by looping over `type === 'date'` validators (`limit = payload[claim] * 1000 + modifier`). It also added 7 tests to `test/verifier.spec.js`. It did not touch the README.
- **What it missed and why:** The new code turns "no bound found" (`null`) into the stored value `0`. That is the same value a real limit gets when `exp` is 0 and tolerance is 0. A token with `exp: 0` is accepted at clock 0. That stores `max = 0`, the hit check reads it as "never expires", and the token keeps being served at 1000 ms and 7,200,000 ms. The agent did think about sentinel collisions, but only on the lower bound and only for `-0`. In step 45 it wrote: "`cacheValue[1] = min === null ? 0 : Math.max(min, 0)` — if `min` is `-0`... `Math.max(-0, 0)` returns 0. Fine." It never asked the same question about the upper bound, where `0` means "unbounded" rather than "already passed". It did check the boundary relation ("Boundary `now <= max` vs uncached `now <= exp*1000 + tol` → consistent. ✓"), but only for ordinary timestamps, never for the value that equals the sentinel.
- **Verification and stopping:** It wrote an exploration script (`/tmp/repro/explore.js`) comparing cached and uncached behaviour across several time-claim configurations. It ran the full suite ("All 411 tests pass") and lint, then stopped on its own after 7 minutes with a confident summary. None of its scenarios or added tests used an epoch-0 or zero-valued time claim, so the bug never came up.

#### Weakness profile
- **DeepSeek:** It is strong at structural root-cause repair. It saw that the reuse window and the validators were computed separately and unified them, instead of patching the `iat` symptom from the report. Its weakness is edge-value reasoning about the data encoding it keeps. It reuses an existing in-band sentinel (`0` = unbounded) for a newly computed quantity without checking whether real values can equal it. Its boundary checks are written as tidy "✓" checklists that cover the cases it already had in mind, and they apply a concern to one field (`min`) without carrying it over to the matching field (`max`). Its tests come from its own mental model, so they share its blind spots. Once the suite and lint were green and its checklist was done, it stopped.

#### Task-design lessons
- **Use an in-band sentinel that a legitimate value can hit.** Pick code that stores "no limit" as `0`, `-1`, or `''` in the same slot as real limits. Write the report so the natural fix computes that slot from user-controlled data. Then add a hidden test where the data produces exactly the sentinel value, such as `exp: 0`, an empty string, or an index of 0. Agents that rework the logic tend to keep the old encoding without question.
- **Leave out the extreme value but state a universal invariant.** This report said "must never be accepted at a moment when … uncached … would reject" and covered "every time-related claim". It never mentioned epoch 0. A universal invariant plus one hidden degenerate-value test separates agents that check the invariant at domain extremes from agents that check it only on typical inputs.
- **Pair the fields so a check done on one is easy to skip on the other.** When a structure has symmetric lower and upper bounds with different sentinel meanings, agents often check the edge on one side and assume the other is fine. Put the trap on the side the agent is less likely to examine.
- **Make the obvious repro and the main fix easy, so the trap decides the result.** DeepSeek passed 13 of 14 hidden tests by fixing the real root cause. A task where the main bug is straightforward and the only failing test is one boundary or encoding case measures thoroughness, not just diagnosis.
- **Hide edge tests that the agent's own tests won't produce.** Agents check their work against tests they wrote from their own model of the bug. Hidden tests should cover values outside that model (zero, negative, the minimum representable value, exact equality with the sentinel), so a green self-written suite gives false confidence.

