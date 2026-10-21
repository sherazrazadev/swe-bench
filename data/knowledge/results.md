# CWE-Bench task factory: results

*Status as of 2026-10-15 12:55 (America/New_York). Pilot phase. Every number below comes from the recorded run artifacts listed under "Provenance".*

## Summary

- **5 tasks evaluated against the target models so far: 4 solved by at least one model, 1 still in play.**
  - **pyload, CWE-613: DeepSeek solved it and MiMo failed.** The task is rejected as too easy and recorded as a "breaks only MiMo" pattern.
  - **Batch 2 (devalue, ip-address, pypdf): DeepSeek solved all 3 on its first attempt.** MiMo also solved ip-address. MiMo's attempts on devalue and pypdf were stopped early, because DeepSeek's solve had already decided the verdict.
  - **MCP TypeScript SDK, CWE-345/522: both models failed all 3 attempts (pass@3 = 0) in the first run.** It is not accepted yet. 5 of the 6 attempts hit the 30-minute time limit. A 60-minute re-run was lost to a network outage on our side. In the **2-hour** re-run, DeepSeek has failed attempt 1 again (0.92), finishing on its own well inside the limit. MiMo's attempt 1 is still running. The final verdict will be in the next-day update.
- **1 task accepted: the MCP TypeScript SDK (GHSA-6qxp-vccf-f47h).** In the 2-hour run both models failed all 3 attempts (pass@3 = 0). Packaged in `data/05_accepted_harbor/ghsa-6qxp-vccf-f47h/`, and the final oracle check on the packaged copy passed.
  - **DeepSeek:** 0.92 on all 3 attempts, finishing on its own each time (79–127 steps). It left one security variant open every time.
  - **MiMo:** 0.50 on all 3 attempts. All 3 hit the 2-hour limit (47–57 steps) with no security hole closed. Under the agreed rule a scored timeout counts as a failure, as CWE-bench grades it. Even so, MiMo's result partly reflects its speed (about 2 minutes per step).
- **Observation (small sample):** the one task DeepSeek has failed spans 8 files and 174 changed lines. The 4 tasks it solved were smaller fixes (2–5 files, 25–111 lines).

**Ledger:** per-task, per-model graded counts in the shared format are in `ledger.md`. It is rebuilt from the raw trials after every model run (`python -m src.common.ledger`).

## Setup

| Item | Value |
|---|---|
| Target models | DeepSeek V4.1 Flash (`deepseek-flash`, reasoning effort `max`); Xiaomi MiMo-V2.6-Pro (`mimo-v2.6-pro`) |
| Agent harness | Harbor `terminus-2` for both models. Model calls are made from the host; the agent gets a shell inside the task container. |
| Isolation | Task container has no network (`network_mode: none`) and no web tools. Hidden tests are uploaded only after the agent finishes. |
| Attempts | 3 per model. Attempt 1 runs on both models first. If either model solves it, the task is rejected and attempts 2–3 are skipped, because pass@3 = 0 is no longer possible. |
| Grading | Deterministic partial score: mean of (security tests passed, functional tests passed, the repo's existing tests that passed before and after the fix). **1.0 = solved.** |
| Time budget | 30 minutes per attempt in the completed evaluations below. Re-runs use 2 hours, so timeouts no longer decide results. |
| Task sources | OSV.dev, GitHub Advisory Database, huntr disclosures (PyPI + npm). Batch 1: fixes committed after 2026-09-23, which is after both models were released. Batch 2: fixes committed after 2026-09-11, which is after DeepSeek V4.1 Flash's release (2026-09-10) and before MiMo-V2.6's (2026-09-21/22). The cutoff was relaxed because the stricter pool ran out. |

## Evaluation results

### 1. pyload — GHSA-jq7h-wrvp-3rgx (CWE-613, Python)
*Password change and privilege revocation through the REST API do not invalidate the user's existing sessions.*

| Model | Attempt | Score | Security | Functional | Existing tests (29) | Notes |
|---|---|---|---|---|---|---|
| DeepSeek | 1 | **1.00 (solved)** | 1.00 | 1.00 | 1.00 | finished in 58 steps |
| MiMo | 1 | 0.67 | 0.00 | 1.00 | 1.00 | none of the stale-session probes were blocked; hit the time limit (26 steps) |

**Verdict:** rejected as too easy. Attempts 2–3 were not run because DeepSeek had already solved it.
**Pattern:** breaks only MiMo.

### 2. MCP TypeScript SDK — GHSA-6qxp-vccf-f47h (CWE-345, CWE-522, TypeScript)
*The OAuth client could send credentials to an authorization server chosen by the resource being accessed.*

| Model | Attempt | Score | Security | Functional | Notes |
|---|---|---|---|---|---|
| DeepSeek | 1 | 0.83 | 0.67 | 1.00 | hit the time limit (105 steps) |
| DeepSeek | 2 | 0.92 | 0.83 | 1.00 | **finished on its own** (97 steps) and left one attack variant open |
| DeepSeek | 3 | 0.92 | 0.83 | 1.00 | hit the time limit (96 steps) |
| MiMo | 1 | 0.50 | 0.00 | 1.00 | hit the time limit (32 steps) |
| MiMo | 2 | 0.50 | 0.00 | 1.00 | hit the time limit (37 steps) |
| MiMo | 3 | 0.50 | 0.00 | 1.00 | hit the time limit (28 steps) |

**Verdict:** pass@3 = 0 on both models, but it is **not accepted yet**.
- **DeepSeek:** the failure is a clear capability failure. It declared the fix finished while one attack variant was still open (incomplete remediation).
- **MiMo:** we can't tell capability from time pressure. It took about 1 minute per step and hit the limit on all 3 attempts.

**Evaluation history for this task**

| Run | Agent time limit | Date | Outcome |
|---|---|---|---|
| 1 | 30 min | 2026-10-14 | All 6 attempts failed (table above). 5 of 6 hit the time limit, so the result is inconclusive for acceptance. |
| 2 | 60 min | 2026-10-14 evening | **No valid result.** The network on our machine dropped about 50 minutes in, so both models' attempts ended with connection errors before they could finish. Excluded (see below). |
| 3 | **2 hours** | 2026-10-15 | **ACCEPTED.** DeepSeek failed 3/3 (0.92 each; security 0.83, functional 1.0) and stopped on its own each time. MiMo failed 3/3 (0.50 each; security 0.00, functional 1.00), each attempt reaching the 2-hour limit. |

### 3–5. Batch 2 (2026-10-15)

| Task | Bug | DeepSeek attempt 1 | MiMo attempt 1 | Verdict |
|---|---|---|---|---|
| devalue — GHSA-j22f-vq7h-c4qm (npm; CWE-200, CWE-226) | Serializer exposes shared memory contents | **1.00 solved** (68 steps) | stopped early (24 steps) | rejected: too easy |
| ip-address — GHSA-j6r3-76f7-8jcv (npm; CWE-697, CWE-843) | Subnet checks compare addresses of different families | **1.00 solved** (31 steps) | **1.00 solved** (38 steps) | rejected: too easy (both solve) |
| pypdf — GHSA-v247-6f48-mgcj (Python; CWE-400, CWE-407) | Very long runtimes with many embedded files | **1.00 solved** (33 steps; all 231 existing tests kept passing) | stopped early (19 steps) | rejected: too easy |

These fixes were small (2–4 files, 25–93 changed lines), and DeepSeek solved each one on its first attempt in 31–68 steps.

## Pipeline funnel (cumulative)

| Step | Count | Notes |
|---|---|---|
| Advisories mined | 437 | OSV, GHSA, huntr (PyPI + npm) |
| Passed screening | 42 | Real source-code fix, fix committed after the cutoff (see Setup), repo ≤ 150 MB, repo has tests |
| Selected for task building | 15 | Highest screening scores, at most one task per repository per batch |
| Could not be built | 1 | pydantic-ai: install failed |
| Generation blocked by the safety filter | 3 | handlebars (code injection), source-map-js, smol-toml. Also one pyload rewrite. |
| Oracle patch too large | 1 | msgpack5: the fix commit included a rebuilt minified bundle. Fixed: build artifacts are now removed from oracle patches, and the task is queued for generation. |
| Tasks generated | 10 | |
| Rejected by quality review, waiting for a rewrite | 3 | 2 pyload advisories, adm-zip |
| Filtered by the recall probe | 1 | shell-quote: both models named the fix location from the report alone |
| Test harness never ran correctly (4 rounds) | 1 | simple-git: a TypeScript monorepo whose internal packages only its own test runner can load |
| Passed quality review and oracle validation | 5 | pyload, MCP SDK, devalue, ip-address, pypdf |
| Evaluated against the models | 5 | Results above |
| Solved by at least one model | 4 | pyload, devalue, ip-address, pypdf |
| Still in play | 0 | |
| Accepted | 1 | MCP SDK (GHSA-6qxp-vccf-f47h) |

## Quality gates: what they caught

- **Quality review before any model run.** In batch 1, 4 of the 5 first drafts were rejected. In batch 2, after the review's rules were given to the generator up front, 1 of 5 first drafts was rejected. In each rejected draft, the hidden tests accepted only the original developers' exact fix design, so a different but correct fix would have failed. The rejection reasons are sent back to the generator. Every rewrite that was re-checked passed the review (pyload and simple-git on their second draft; the MCP SDK on its first draft).
- **Oracle validation (running the real fix against the tests).** It caught one broken test harness: the pyload tests re-created the web app for every test, which the project does not allow. That task was rewritten using the real test output, and the rewrite validated.
- **No AI judge decides acceptance.** Pass or fail comes only from the automatic tests. A task is accepted only if every attempt failed cleanly.

## Excluded from this report (problems on our side, all fixed)

These runs failed because of our pipeline or our machine, not because of the tasks or the models, so their records were removed from the results above. The raw records are kept for audit (see Provenance).

| Date | Issue | Fix |
|---|---|---|
| 2026-10-14 | Harbor's network restriction modes are not supported by Docker Desktop on macOS, so validation runs could not start | The task container is now isolated with Docker's own `network_mode: none` |
| 2026-10-14 | The task image did not support pnpm workspaces | The package manager is detected from the lockfile |
| 2026-10-14 | TypeScript packages were not compiled in the task image, so the tests could not load the library | The image builds the project, and grading rebuilds it first so the agent's edits are what get tested |
| 2026-10-14/15 | The Node 20 image was too old for a repository's pnpm 11 build | Switched to Node 22 |
| 2026-10-15 | One fix commit included a rebuilt minified JavaScript bundle (a 453,000-character diff) | Generated build artifacts are now removed from oracle patches |
| 2026-10-14/15 | Network outage on our machine interrupted the 60-minute MCP SDK re-run. No attempt finished, so no result was recorded. | Re-run with a 2-hour limit started 2026-10-15 |

## Next steps

1. **In progress:** the MCP SDK 2-hour re-run, waiting on MiMo's attempts. It is accepted if pass@3 = 0 holds.
2. **Task difficulty:** DeepSeek solves small, local fixes on its first attempt. Screening will rank candidates higher when the real fix spans more files and directories, which is the shape of the only task it failed.
3. **Candidate pool:** 42 screened candidates are available under the current cutoff. The next batch includes msgpack5 and the 3 tasks waiting for a rewrite.

## Provenance

- **Per-attempt artifacts:** `data/04_eval_runs/<ID>/<model>/<job>/<trial>/`. Each trial folder holds:
  - `agent/trajectory.json`: every step the model took
  - `verifier/score_breakdown.json`: the score parts
  - `verifier/test-stdout.txt`: the full test output
- **Validation runs:** `data/03_environments/<ID>/validation/`
- **Outcome log (machine-readable):** `data/knowledge/task_outcomes.jsonl`
- **Raw run log and the excluded records:** `data/knowledge/archive/`

---

## Run log (appended automatically by the pipeline)
## 2026-10-15T12:47:14Z - Stage 4 - rubric + oracle validation

counts: {"ok": 1, "failed_oracle": 1, "rejected": 0, "regenerate": 0, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-6qxp-vccf-f47h | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 0 (from 0 candidate files) |
| GHSA-x6jw-m9v5-85vh | REJECTED | oracle does not pass its own tests (reward [0.0, 0.0], failing: ['::test_functional_interpret_trailers_with_inline_key', '::test_functional_interpret_trailers_w |

## 2026-10-15T13:33:18Z - Stage 4 - rubric + oracle validation

counts: {"ok": 3, "failed_oracle": 2, "rejected": 0, "regenerate": 1, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-j22f-vq7h-c4qm | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 0 (from 0 candidate files) |
| GHSA-j6r3-76f7-8jcv | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 0 (from 0 candidate files) |
| GHSA-p634-w6r4-rjp2 | REJECTED | rubric: The oracle fails test_functional_object_property_like_names. The `in` check on the plain-object entryTable matches inherited properties ('constructor',  |
| GHSA-pqg4-j6r4-53mv | REJECTED | recall probe: both models name the fix location from the report alone |
| GHSA-v247-6f48-mgcj | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 231 (from 4 candidate files) |
| GHSA-x6jw-m9v5-85vh | REJECTED | oracle does not pass its own tests (reward [0.0, 0.0], failing: ['::test_functional_interpret_trailers_with_inline_key', '::test_functional_interpret_trailers_w |

## 2026-10-15T15:57:06Z - Stage 4 - rubric + oracle validation

counts: {"ok": 1, "failed_oracle": 1, "rejected": 0, "regenerate": 2, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-mcm9-63f2-9j32 | REJECTED | functional tests failing on vulnerable code (not pass->pass): ['test_functional_output_is_script_safe'] |
| GHSA-p634-w6r4-rjp2 | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 0 (from 0 candidate files) |
| GHSA-x33g-cr3x-6449 | REJECTED | recall probe: both models name the fix location from the report alone |
| GHSA-x937-hj6v-793p | REJECTED | rubric: The functional tests cannot tell a working cache from a disabled one: removing caching entirely passes every hidden test, even though the report require |

## 2026-10-15T16:49:09Z - Stage 5 - DeepSeek / MiMo evaluation

counts: {"done": 0, "accepted": 1}

| task | status | rewards per model | detail |
|---|---|---|---|
| GHSA-6qxp-vccf-f47h | accepted | deepseek: [0.9167, 0.9167, 0.9167] ; mimo: [0.5, 0.5, 0.5] | all attempts failed cleanly on every model {'hole_still_open': 6} |

## 2026-10-15T17:58:43Z - Stage 5 - DeepSeek / MiMo evaluation

counts: {"rejected_too_easy": 1}

| task | status | rewards per model | detail |
|---|---|---|---|
| GHSA-p634-w6r4-rjp2 | rejected_too_easy | deepseek: [1.0] ; mimo: [1.0] | solved by deepseek, mimo |

## 2026-10-16T01:09:43Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 0, "rejected": 0, "regenerate": 1, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-vp8m-p9jh-q5pm | REJECTED | rubric: test_functional_origins_allow_list fails on the vulnerable code: an allow-list on a Client with no per-request origin never cached before, yet the repor |

## 2026-10-16T01:11:06Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 0, "rejected": 0, "regenerate": 1, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-68fv-2mgg-jv7q | REJECTED | rubric: The hidden test needs a line-offset cap somewhere between 1,000,000 (must work) and 50,000,000 (must be refused, with output capped at 1,000,000 bytes). |

## 2026-10-16T01:30:41Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 1, "rejected": 0, "regenerate": 0, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-68fv-2mgg-jv7q | REJECTED | oracle does not pass its own tests (reward [0.6667, 0.6667], failing: ['::test_functional_copy_small_indexed_into_generator', '::test_functional_copy_small_inde |

## 2026-10-16T01:35:39Z - Stage 4 - rubric + oracle validation

counts: {"ok": 1, "failed_oracle": 0, "rejected": 0, "regenerate": 0, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-vp8m-p9jh-q5pm | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 0 (from 15 candidate files); fix checks: shallow leaves 5/7 security tests open, removal bre |

## 2026-10-16T02:04:09Z - Stage 4 - rubric + oracle validation

counts: {"ok": 1, "failed_oracle": 0, "rejected": 0, "regenerate": 0, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-hqr4-qq8f-hg3x | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 0 (from 15 candidate files); fix checks: shallow leaves 3/7 security tests open, removal bre |

## 2026-10-16T02:05:48Z - Stage 4 - rubric + oracle validation

counts: {"ok": 4, "failed_oracle": 0, "rejected": 0, "regenerate": 9, "failed": 3}

| task | verdict | detail |
|---|---|---|
| GHSA-24ch-f2g6-9hhh | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 0 (from 15 candidate files); fix checks: shallow leaves 6/7 security tests open, removal bre |
| GHSA-2q42-4q24-7rgv | REJECTED | rubric: The security tests require at least one emitted file (`confined()` returns False on an empty file list), so fixes that reject hostile specs with a diagn |
| GHSA-3wxw-xv34-2frg | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 42 (from 13 candidate files); fix checks: shallow leaves 3/5 security tests open, removal br |
| GHSA-5jq2-8x83-x246 | REJECTED | rubric: Hidden tests require an undisclosed, arbitrary length cutoff (accept 60-character IDs, reject 200-character ones) that matches the oracle's internal _MA |
| GHSA-68fv-2mgg-jv7q | REJECTED | oracle does not pass its own tests (reward [0.6667, 0.6667], failing: ['::test_functional_copy_small_indexed_into_generator', '::test_functional_copy_small_inde |
| GHSA-68w4-83fh-f2w8 | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 8 (from 2 candidate files); fix checks: shallow leaves 3/4 security tests open, removal brea |
| GHSA-77xj-x4rm-935c | REJECTED | oracle does not pass its own tests (reward [0.0, 0.0], failing: unknown) |
| GHSA-8r5x-fm3f-whwj | REJECTED | rubric: Every hidden-test AST leaves out `loc`. On the vulnerable code, helper/ambiguous invocation likely emits `"loc":` with no value (JSON.stringify(undefine |
| GHSA-9q47-3cm2-2rp8 | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 28 (from 1 candidate files); fix checks: shallow leaves 3/7 security tests open, removal bre |
| GHSA-hmq2-7hp6-7crh | REJECTED | oracle does not pass its own tests (reward [0.7857, 0.7857], failing: ['::test_functional_nested_model_call_with_function_filter', '::test_functional_nested_mod |
| GHSA-hqr4-qq8f-hg3x | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 0 (from 15 candidate files); fix checks: shallow leaves 3/7 security tests open, removal bre |
| GHSA-hxh3-vqpv-xpqv | REJECTED | oracle run had no verdict: RuntimeError: Docker compose command failed for environment ghsa-hxh3-vqpv-xpqv. Command: docker compose --project-name harbor_task__ |
| GHSA-jggr-w7fw-pc2j | REJECTED | oracle run had no verdict: RuntimeError: Docker compose command failed for environment ghsa-jggr-w7fw-pc2j. Command: docker compose --project-name harbor_task__ |
| GHSA-p4rw-rvv2-7xwr | REJECTED | oracle run had no verdict: RuntimeError: Docker compose command failed for environment ghsa-p4rw-rvv2-7xwr. Command: docker compose --project-name harbor_task__ |
| GHSA-qf28-8hc6-vwrp | REJECTED | rubric: Security tests call the patched internal utilities getSelect/setNestedValue directly instead of going through the export/preview HTTP entry point; Tests |
| GHSA-r4xh-jqrq-34v2 | REJECTED | rubric: Security tests depend on a 30s wall-clock limit that includes vitest startup, and the vulnerable code's runtime (~9e11 bytes of memchr scanning) may com |

## 2026-10-16T02:10:48Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 0, "rejected": 0, "regenerate": 0, "failed": 1}

| task | verdict | detail |
|---|---|---|
| GHSA-hmq2-7hp6-7crh | REJECTED | check patch 'shallow' produced no per-test verdict: RuntimeError: Docker compose command failed for environment ghsa-hmq2-7hp6-7crh. Command: docker compose --p |

## 2026-10-16T02:14:20Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 0, "rejected": 0, "regenerate": 1, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-qf28-8hc6-vwrp | REJECTED | rubric: The functional tests never check the content of the preview docs, so a fix that ignores or drops all `fields` (removing field selection) still passes. T |

## 2026-10-16T02:21:58Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 0, "rejected": 0, "regenerate": 0, "failed": 1}

| task | verdict | detail |
|---|---|---|
| GHSA-77xj-x4rm-935c | REJECTED | oracle fails once the existing-test set is enforced: oracle run had no verdict: RuntimeError: Docker compose command failed for environment ghsa-77xj-x4rm-935c. |

## 2026-10-16T02:23:32Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 0, "rejected": 0, "regenerate": 0, "failed": 1}

| task | verdict | detail |
|---|---|---|
| GHSA-r4xh-jqrq-34v2 | REJECTED | oracle run produced 0/2 trials |

## 2026-10-16T02:31:01Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 0, "rejected": 0, "regenerate": 0, "failed": 1}

| task | verdict | detail |
|---|---|---|
| GHSA-2q42-4q24-7rgv | REJECTED | oracle run had no verdict: RuntimeError: Docker compose command failed for environment ghsa-2q42-4q24-7rgv. Command: docker compose --project-name harbor_task__ |

## 2026-10-16T02:31:27Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 0, "rejected": 0, "regenerate": 1, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-jggr-w7fw-pc2j | REJECTED | oracle does not pass its own tests (reward [0.5, 0.5], failing: ['::test_security_custom_prototypes_and_symbol_keys', '::test_security_custom_prototypes_and_sym |

## 2026-10-16T02:44:06Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 0, "rejected": 0, "regenerate": 1, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-5jq2-8x83-x246 | REJECTED | fix checks: ALTERNATIVE correct fix scores 0 |

## 2026-10-16T03:09:48Z - Stage 4 - rubric + oracle validation

counts: {"ok": 2, "failed_oracle": 0, "rejected": 0, "regenerate": 0, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-hxh3-vqpv-xpqv | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 494 (from 15 candidate files); fix checks: shallow leaves 5/6 security tests open, removal b |
| GHSA-p4rw-rvv2-7xwr | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 118 (from 13 candidate files); fix checks: shallow leaves 4/5 security tests open, removal b |

## 2026-10-16T03:36:58Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 0, "rejected": 0, "regenerate": 0, "failed": 1}

| task | verdict | detail |
|---|---|---|
| GHSA-qf28-8hc6-vwrp | REJECTED | pre-patch run had no verdict: RuntimeError: Docker compose command failed for environment ghsa-qf28-8hc6-vwrp. Command: docker compose --project-name harbor_tas |

## 2026-10-16T03:38:14Z - Stage 4 - rubric + oracle validation

counts: {"ok": 1, "failed_oracle": 0, "rejected": 0, "regenerate": 0, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-5jq2-8x83-x246 | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 319 (from 7 candidate files); fix checks: shallow leaves 2/5 security tests open, removal br |

## 2026-10-16T04:50:56Z - Stage 4 - rubric + oracle validation

counts: {"ok": 2, "failed_oracle": 0, "rejected": 0, "regenerate": 2, "failed": 1}

| task | verdict | detail |
|---|---|---|
| GHSA-2q42-4q24-7rgv | REJECTED | oracle does not pass its own tests (reward [0.375, 0.375], failing: ['::test_functional_json_schema_basic_and_dotted_names', '::test_functional_json_schema_basi |
| GHSA-77xj-x4rm-935c | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 238 (from 11 candidate files); fix checks: shallow leaves 3/6 security tests open, removal b |
| GHSA-hmq2-7hp6-7crh | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 74 (from 15 candidate files); fix checks: shallow leaves 6/7 security tests open, removal br |
| GHSA-jggr-w7fw-pc2j | REJECTED | oracle does not pass its own tests (reward [0.5, 0.5], failing: ['::test_security_custom_prototypes_and_symbol_keys', '::test_security_custom_prototypes_and_sym |
| GHSA-r4xh-jqrq-34v2 | REJECTED | oracle run produced 0/2 trials |

## 2026-10-16T04:58:57Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 0, "rejected": 0, "regenerate": 1, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-r4xh-jqrq-34v2 | REJECTED | oracle does not pass its own tests (reward [0.875, 0.875], failing: ['::test_security_many_single_quoted_key_entries', '::test_security_many_table_headers', 'te |

## 2026-10-16T05:02:02Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 1, "rejected": 0, "regenerate": 0, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-jggr-w7fw-pc2j | REJECTED | oracle does not pass its own tests (reward [0.5, 0.5], failing: ['::test_security_custom_prototypes_and_symbol_keys', '::test_security_custom_prototypes_and_sym |

## 2026-10-16T05:18:53Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 1, "rejected": 0, "regenerate": 0, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-r4xh-jqrq-34v2 | REJECTED | security tests that already pass on vulnerable code: ['test_security_many_table_headers'] |

## 2026-10-16T06:08:08Z - Stage 4 - rubric + oracle validation

counts: {"ok": 1, "failed_oracle": 1, "rejected": 0, "regenerate": 0, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-2q42-4q24-7rgv | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 28 (from 3 candidate files); fix checks: shallow leaves 5/7 security tests open, removal bre |
| GHSA-qf28-8hc6-vwrp | REJECTED | oracle fails once the existing-test set is enforced: oracle does not pass its own tests (reward [0.9867], failing: ['test/access-control/getConfig.ts::(no resul |

## 2026-10-16T06:38:16Z - Stage 4 - rubric + oracle validation

counts: {"ok": 1, "failed_oracle": 0, "rejected": 0, "regenerate": 0, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-qf28-8hc6-vwrp | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 24 (from 7 candidate files); fix checks: shallow leaves 3/5 security tests open, removal bre |

## 2026-10-16T08:16:19Z - Stage 4 - rubric + oracle validation

counts: {"ok": 1, "failed_oracle": 1, "rejected": 0, "regenerate": 5, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-2q76-m6w6-qgc6 | REJECTED | rubric: Tests require owner binding to be done with field-level `access` on the `user` field; valid hook-based fixes, or rules that allow only assigning yoursel |
| GHSA-376h-93r7-7g6f | REJECTED | oracle does not pass its own tests (reward [0.0, 0.0], failing: ['::test_functional_admin_under_base_served', '::test_functional_admin_under_base_served', '::te |
| GHSA-8fvv-fgr5-f8ch | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 72 (from 13 candidate files); fix checks: shallow leaves 4/6 security tests open, removal br |
| GHSA-8xx6-hgc6-gc2m | REJECTED | isolation audit: fix code is readable inside the image: /usr/local/lib/python3.11/site-packages/httpx2/_content.py contains 3 of the fix's added lines; fix code |
| GHSA-mcm9-63f2-9j32 | REJECTED | functional tests failing on vulnerable code (not pass->pass): ['test_functional_output_is_script_safe'] |
| GHSA-w3v8-gmh9-3wv7 | REJECTED | rubric: Hidden tests require the pathological call to end within 25s (including subprocess spawn/import), but the report only demands 'bounded time'; a fix usin |
| GHSA-x78j-v8h9-3j2q | REJECTED | rubric: test_security_prompt_line_break requires collapsing Unicode line separators (U+2028/U+0085/U+2029). cmd.exe does not treat these as line breaks and the  |

## 2026-10-16T08:21:51Z - Stage 4 - rubric + oracle validation

counts: {"ok": 1, "failed_oracle": 0, "rejected": 0, "regenerate": 0, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-8xx6-hgc6-gc2m | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 53 (from 2 candidate files); fix checks: shallow leaves 6/8 security tests open, removal bre |

## 2026-10-16T08:43:55Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 1, "rejected": 0, "regenerate": 1, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-q238-5cxm-5c9h | REJECTED | rubric: The security tests don't tell vulnerable code from fixed code. Nesting a Multi* inside a Multi* of the same kind breaks GEOS's child-type check, so on t |
| GHSA-q2xc-rrxj-58x9 | REJECTED | isolation audit: fix code is readable inside the image: /usr/local/lib/python3.11/site-packages/starlette/middleware/cors.py contains 2 of the fix's added lines |

## 2026-10-16T09:10:37Z - Stage 4 - rubric + oracle validation

counts: {"ok": 1, "failed_oracle": 0, "rejected": 0, "regenerate": 0, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-q2xc-rrxj-58x9 | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 0 (from 15 candidate files); fix checks: shallow leaves 7/8 security tests open, removal bre |

## 2026-10-16T10:18:33Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 0, "rejected": 0, "regenerate": 0, "failed": 1}

| task | verdict | detail |
|---|---|---|
| GHSA-q2xc-rrxj-58x9 | REJECTED | check patch 'removal' produced no per-test verdict: no trial |

## 2026-10-16T10:27:45Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 0, "rejected": 0, "regenerate": 1, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-376h-93r7-7g6f | REJECTED | oracle does not pass its own tests (reward [0.0, 0.0], failing: ['::test_functional_adapter_path_serves_real_admin', '::test_functional_adapter_path_serves_real |

## 2026-10-16T11:09:16Z - Stage 4 - rubric + oracle validation

counts: {"ok": 1, "failed_oracle": 0, "rejected": 0, "regenerate": 3, "failed": 1}

| task | verdict | detail |
|---|---|---|
| GHSA-2q76-m6w6-qgc6 | REJECTED | oracle does not pass its own tests (reward [0.0, 0.0], failing: ['::test_functional_owner_can_create_own', '::test_functional_owner_can_create_own', '::test_fun |
| GHSA-376h-93r7-7g6f | REJECTED | oracle does not pass its own tests (reward [0.0, 0.0], failing: ['::test_functional_adapter_path_serves_real_admin', '::test_functional_adapter_path_serves_real |
| GHSA-mcm9-63f2-9j32 | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 0 (from 6 candidate files); fix checks: shallow leaves 2/6 security tests open, removal brea |
| GHSA-w3v8-gmh9-3wv7 | REJECTED | check patch 'shallow' produced no per-test verdict: EnvironmentStartTimeoutError: Environment start timed out after 1200.0 seconds |
| GHSA-x78j-v8h9-3j2q | REJECTED | rubric: The tests treat raising an exception from generate() as a failure, although erroring out on an unsafe value is a reasonable way to block and the report  |

## 2026-10-16T11:23:51Z - Stage 4 - rubric + oracle validation

counts: {"ok": 1, "failed_oracle": 0, "rejected": 0, "regenerate": 0, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-q2xc-rrxj-58x9 | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 406 (from 15 candidate files); fix checks: shallow leaves 7/8 security tests open, removal b |

## 2026-10-16T11:43:16Z - Stage 4 - rubric + oracle validation

counts: {"ok": 1, "failed_oracle": 0, "rejected": 0, "regenerate": 0, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-w3v8-gmh9-3wv7 | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 38 (from 4 candidate files); fix checks: shallow leaves 3/6 security tests open, removal bre |

## 2026-10-16T12:49:46Z - Stage 5 - DeepSeek / MiMo evaluation

counts: {"rejected_too_easy": 2}

| task | status | rewards per model | detail |
|---|---|---|---|
| GHSA-q2xc-rrxj-58x9 | rejected_too_easy | deepseek: [1.0] ; mimo: [] | solved by deepseek |
| GHSA-w3v8-gmh9-3wv7 | rejected_too_easy | deepseek: [1.0] ; mimo: [] | solved by deepseek |

## 2026-10-16T15:06:45Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 1, "rejected": 0, "regenerate": 0, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-f65p-4m7j-42xc | REJECTED | out of spec: no usable existing tests of the affected code (candidate files: 15; repos whose test runner we cannot run yet end here too) |

## 2026-10-16T15:22:36Z - Stage 4 - rubric + oracle validation

counts: {"ok": 1, "failed_oracle": 0, "rejected": 0, "regenerate": 0, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-f65p-4m7j-42xc | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 883 (from 15 candidate files); fix checks: shallow leaves 6/8 security tests open, removal b |

## 2026-10-16T15:41:45Z - Stage 4 - rubric + oracle validation

counts: {"ok": 2, "failed_oracle": 4, "rejected": 1, "regenerate": 2, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-376h-93r7-7g6f | REJECTED | out of spec: no usable existing tests of the affected code (candidate files: 15; repos whose test runner we cannot run yet end here too) |
| GHSA-c4c3-pg64-4m4v | REJECTED | oracle fails once the existing-test set is enforced: oracle does not pass its own tests (reward [0.99], failing: ['packages/mermaid/src/config.spec.ts::packages |
| GHSA-c7q8-3ch8-vqpv | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 254 (from 15 candidate files); fix checks: shallow leaves 6/10 security tests open, removal  |
| GHSA-f65p-4m7j-42xc | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 883 (from 15 candidate files); fix checks: shallow leaves 6/8 security tests open, removal b |
| GHSA-gqvv-2mrq-wpjv | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 59 (from 4 candidate files); fix checks: shallow leaves 1/4 security tests open, removal bre |
| GHSA-hwr6-493r-vm6h | REJECTED | oracle does not pass its own tests (reward [0.0, 0.0], failing: ['::test_functional_custom_compiler_object_schema', '::test_functional_custom_compiler_object_sc |
| GHSA-pfvf-fwfp-25mp | REJECTED | out of spec: no usable existing tests of the affected code (candidate files: 15; repos whose test runner we cannot run yet end here too) |
| GHSA-x78j-v8h9-3j2q | REJECTED | rubric: Prompt security tests catch only `Exception`, so a parse-time rejection through argparse (`SystemExit`) fails the test even though the docstring claims  |
| PYSEC-2026-3869 | REJECTED | rubric: test_functional_self_referential_but_noncyclic_units_converts uses the mixed rule `S -> S 'a'`, which chomsky_normal_form rejects with ValueError ('Cann |

## 2026-10-16T16:28:17Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 0, "rejected": 0, "regenerate": 0, "failed": 1}

| task | verdict | detail |
|---|---|---|
| GHSA-pfvf-fwfp-25mp | REJECTED | oracle run had no verdict: EnvironmentStartTimeoutError: Environment start timed out after 1200.0 seconds |

## 2026-10-16T16:32:48Z - Stage 4 - rubric + oracle validation

counts: {"ok": 1, "failed_oracle": 1, "rejected": 0, "regenerate": 0, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-hwr6-493r-vm6h | REJECTED | out of spec: no usable existing tests of the affected code (candidate files: 6; repos whose test runner we cannot run yet end here too) |
| PYSEC-2026-3869 | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 42 (from 5 candidate files); fix checks: shallow leaves 3/5 security tests open, removal bre |

## 2026-10-16T16:38:14Z - Stage 5 - DeepSeek / MiMo evaluation

counts: {"rejected_too_easy": 4}

| task | status | rewards per model | detail |
|---|---|---|---|
| GHSA-c7q8-3ch8-vqpv | rejected_too_easy | deepseek: [1.0] ; mimo: [] | solved by deepseek |
| GHSA-gqvv-2mrq-wpjv | rejected_too_easy | deepseek: [1.0] ; mimo: [] | solved by deepseek |
| GHSA-f65p-4m7j-42xc | rejected_too_easy | deepseek: [1.0] ; mimo: [] | solved by deepseek |
| PYSEC-2026-3869 | rejected_too_easy | deepseek: [1.0] ; mimo: [] | solved by deepseek |

## 2026-10-16T18:56:45Z - Stage 4 - rubric + oracle validation

counts: {"ok": 1, "failed_oracle": 1, "rejected": 0, "regenerate": 0, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-pfvf-fwfp-25mp | REJECTED | out of spec: no usable existing tests of the affected code (candidate files: 15; repos whose test runner we cannot run yet end here too) |
| GHSA-x937-hj6v-793p | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 399 (from 8 candidate files); fix checks: shallow leaves 3/7 security tests open, removal br |

## 2026-10-16T20:34:02Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 0, "rejected": 0, "regenerate": 0, "failed": 1}

| task | verdict | detail |
|---|---|---|
| GHSA-337j-9hxr-rhxg | REJECTED | oracle run had no verdict: RuntimeError: Docker compose command failed for environment ghsa-337j-9hxr-rhxg. Command: docker compose --project-name harbor_task__ |

## 2026-10-16T23:50:36Z - Stage 4 - rubric + oracle validation

counts: {"ok": 2, "failed_oracle": 1, "rejected": 0, "regenerate": 6, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-3753-m2x2-q623 | REJECTED | rubric: The oracle blocks external links by default ('externalLinkPolicy' defaults to blocked, and its own test asserts the https URL is absent from the blocked |
| GHSA-5vf6-jrqr-78fj | REJECTED | oracle does not pass its own tests (reward [0.0, 0.0], failing: ['::test_functional_public_ip', '::test_functional_public_ip', '::test_functional_public_ip_othe |
| GHSA-856c-92hv-3vxx | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 229 (from 15 candidate files); fix checks: shallow leaves 6/8 security tests open, removal b |
| GHSA-92cr-jxw4-5wjg | REJECTED | rubric: Tests require the undisclosed JWT claim name `tokenType` and the oracle's exact string values ('access', 'refresh', 'collabora_online', 'only_office', . |
| GHSA-p63j-vcc4-9vmv | REJECTED | rubric: The security tests call the patched handler functions directly with fabricated contexts instead of going through the browser RPC command entry point.; T |
| GHSA-rf44-j88r-hh8c | REJECTED | isolation audit: 1 added fix block(s) already present in the vulnerable tree, e.g. 'wantStatus:         http.StatusBadRequest,\nwantReachedBackend: false,\n},\n |
| GHSA-wmw4-mw6x-6vfm | REJECTED | rubric: The tests call the patched service `findAll` methods directly instead of going through the HTTP route or controller, so a valid fix at the controller or |
| GHSA-x3hf-7cj6-3r4m | REJECTED | rubric: Tests require rejecting `extra: {"foo": "bar"}`, a benign option that neither loads code nor overrides the connection target. The report gives no basis  |
| PYSEC-2026-3819 | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 211 (from 15 candidate files); fix checks: shallow leaves 4/6 security tests open, removal b |

## 2026-10-17T00:29:40Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 2, "rejected": 0, "regenerate": 1, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-32gc-64m7-hj7v | REJECTED | out of spec: no usable existing tests of the affected code (candidate files: 15; repos whose test runner we cannot run yet end here too) |
| GHSA-337j-9hxr-rhxg | REJECTED | out of spec: no usable existing tests of the affected code (candidate files: 10; repos whose test runner we cannot run yet end here too) |
| PYSEC-2026-3569 | REJECTED | oracle does not pass its own tests (reward [0.0, 0.0], failing: ['::test_functional_graphql_permitted', '::test_functional_graphql_permitted', '::test_functiona |

## 2026-10-17T03:01:20Z - Stage 5 - DeepSeek / MiMo evaluation

counts: {"done": 0, "failed": 1, "accepted": 1}

| task | status | rewards per model | detail |
|---|---|---|---|
| GHSA-856c-92hv-3vxx | accepted | deepseek: [0.99, 0.99, 0.99] ; mimo: [0.99, 0.99, 0.99] | every attempt is a counted model failure on every model {'over_correction': 6} |
| PYSEC-2026-3819 | failed | deepseek: [] ; mimo: [] | incomplete attempts (errors per model): {'deepseek': 1, 'mimo': 1} |

## 2026-10-17T05:07:28Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 1, "rejected": 0, "regenerate": 4, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-3753-m2x2-q623 | REJECTED | oracle does not pass its own tests (reward [0.5, 0.5], failing: ['::test_functional_bold_formatting_rendered', '::test_functional_bold_formatting_rendered', ':: |
| GHSA-92cr-jxw4-5wjg | REJECTED | oracle does not pass its own tests (reward [0.0, 0.0], failing: ['::test_functional_valid_collabora_editor_accepted', '::test_functional_valid_collabora_editor_ |
| GHSA-p63j-vcc4-9vmv | REJECTED | oracle does not pass its own tests (reward [0.5, 0.5], failing: ['::test_functional_screenshot_saves_to_nested_permitted_path', '::test_functional_screenshot_sa |
| GHSA-x3hf-7cj6-3r4m | REJECTED | rubric: Security tests check the node's stored config (result.config[...]) rather than what actually reaches the DataSource, so a correct fix that sanitizes at  |
| PYSEC-2026-3569 | REJECTED | oracle does not pass its own tests (reward [0.0, 0.0], failing: ['::test_functional_graphql_permitted', '::test_functional_graphql_permitted', '::test_functiona |

## 2026-10-17T06:10:12Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 1, "rejected": 2, "regenerate": 1, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-3753-m2x2-q623 | REJECTED | rubric: The harness waits only one microtask (`await Promise.resolve()`) and falls back to the last posted message, so results depend on timing and can attribut |
| GHSA-92cr-jxw4-5wjg | REJECTED | oracle does not pass its own tests (reward [0.75, 0.75], failing: ['::test_functional_valid_collabora_editor_accepted', '::test_functional_valid_collabora_edito |
| GHSA-x3hf-7cj6-3r4m | REJECTED | rubric: Security tests check whether the key exists (hasOwnProperty) instead of what value reaches the connection layer, so a valid fix that sets entities/subsc |
| PYSEC-2026-3569 | REJECTED | oracle does not pass its own tests (reward [0.0, 0.0], failing: ['::test_functional_graphql_mutation_permitted', '::test_functional_graphql_mutation_permitted', |

## 2026-10-17T06:47:53Z - Stage 4 - rubric + oracle validation

counts: {"ok": 1, "failed_oracle": 0, "rejected": 0, "regenerate": 0, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-92cr-jxw4-5wjg | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 171 (from 15 candidate files); fix checks: shallow leaves 3/6 security tests open, removal b |

## 2026-10-17T07:03:47Z - Stage 5 - DeepSeek / MiMo evaluation

counts: {"rejected_too_easy": 1}

| task | status | rewards per model | detail |
|---|---|---|---|
| GHSA-92cr-jxw4-5wjg | rejected_too_easy | deepseek: [1.0] ; mimo: [] | solved by deepseek |

## 2026-10-17T08:13:11Z - Stage 4 - rubric + oracle validation

counts: {"ok": 2, "failed_oracle": 3, "rejected": 1, "regenerate": 0, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-32gc-64m7-hj7v | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 133 (from 15 candidate files); fix checks: shallow leaves 5/6 security tests open, removal b |
| GHSA-337j-9hxr-rhxg | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 485 (from 10 candidate files); fix checks: shallow leaves 3/5 security tests open, removal b |
| GHSA-376h-93r7-7g6f | REJECTED | out of spec: no usable existing tests of the affected code (candidate files: 15; repos whose test runner we cannot run yet end here too) |
| GHSA-5vf6-jrqr-78fj | REJECTED | rubric: The runtime test reaches the bug via a test-only Addon subclass calling fetchRetry directly, not a real provider or AddonService's dispatch path.; The r |
| GHSA-p63j-vcc4-9vmv | REJECTED | out of spec: no usable existing tests of the affected code (candidate files: 3; repos whose test runner we cannot run yet end here too) |
| GHSA-rf44-j88r-hh8c | REJECTED | isolation audit: 1 added fix block(s) already present in the vulnerable tree, e.g. 'wantStatus:         http.StatusBadRequest,\nwantReachedBackend: false,\n},\n |

## 2026-10-18T15:30:26Z - Stage 5 - DeepSeek / MiMo evaluation

counts: {"rejected_too_easy": 1}

| task | status | rewards per model | detail |
|---|---|---|---|
| GHSA-32gc-64m7-hj7v | rejected_too_easy | deepseek: [1.0] ; mimo: [] | solved by deepseek |

## 2026-10-18T16:22:05Z - Stage 5 - DeepSeek / MiMo evaluation

counts: {"rejected_too_easy": 1}

| task | status | rewards per model | detail |
|---|---|---|---|
| PYSEC-2026-3819 | rejected_too_easy | deepseek: [1.0] ; mimo: [] | solved by deepseek |

## 2026-10-18T19:34:45Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 0, "rejected": 0, "regenerate": 0, "failed": 1}

| task | verdict | detail |
|---|---|---|
| GHSA-wmw4-mw6x-6vfm | REJECTED | rubric: The tests call the patched service `findAll` methods directly instead of going through the HTTP route or controller, so a valid fix at the controller or |

## 2026-10-18T20:08:53Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 0, "rejected": 0, "regenerate": 1, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-wmw4-mw6x-6vfm | REJECTED | oracle does not pass its own tests (reward [0.0, 0.0], failing: ['::test_functional_article_title_filter', '::test_functional_article_title_filter', '::test_fun |

## 2026-10-18T22:45:26Z - Stage 4 - rubric + oracle validation

counts: {"ok": 1, "failed_oracle": 0, "rejected": 0, "regenerate": 1, "failed": 1}

| task | verdict | detail |
|---|---|---|
| GHSA-6x6c-w9w9-hv4h | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 168 (from 11 candidate files); fix checks: shallow leaves 3/4 security tests open, removal b |
| GHSA-g53w-w6mj-hrpp | REJECTED | oracle does not pass its own tests (reward [0.9167, 0.9167], failing: ['::test_functional_custom_client_headers_still_forwarded', '::test_functional_custom_clie |

## 2026-10-18T23:57:40Z - Stage 5 - DeepSeek / MiMo evaluation

counts: {"done": 0, "needs_review": 1}

| task | status | rewards per model | detail |
|---|---|---|---|
| GHSA-6x6c-w9w9-hv4h | needs_review | deepseek: [0.9167, 0.9167, 0.8333] ; mimo: [0.9167, 0.9167, 0.9167] | deepseek: 1/3 attempts are counted model failures; deepseek/harbor_task__h6xwkEn: step 114: command touches grading files ('command": "ls /; ls /opt 2>/dev/null |

## 2026-10-19T00:24:53Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 0, "rejected": 0, "regenerate": 1, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-g53w-w6mj-hrpp | REJECTED | rubric: `_SESSION_SEC` calls `JWTManager.Validate` directly instead of using the declared `RouteMCPRequest` entry point.; `_SESSION_SEC` hardcodes the oracle-ad |

## 2026-10-19T02:25:52Z - Stage 4 - rubric + oracle validation

counts: {"ok": 1, "failed_oracle": 1, "rejected": 0, "regenerate": 0, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-g53w-w6mj-hrpp | REJECTED | oracle does not pass its own tests (reward [0.75, 0.75], failing: ['::test_functional_client_headers_forwarded_on_backend_init', '::test_functional_client_heade |
| GHSA-mwwr-p57h-56pf | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 273 (from 7 candidate files); fix checks: shallow leaves 7/8 security tests open, removal br |

## 2026-10-19T02:47:39Z - Stage 5 - DeepSeek / MiMo evaluation

counts: {"rejected_too_easy": 1}

| task | status | rewards per model | detail |
|---|---|---|---|
| GHSA-mwwr-p57h-56pf | rejected_too_easy | deepseek: [1.0] ; mimo: [] | solved by deepseek |

## 2026-10-19T09:44:44Z - Stage 4 - rubric + oracle validation

counts: {"ok": 1, "failed_oracle": 1, "rejected": 0, "regenerate": 1, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-376h-93r7-7g6f | REJECTED | fix checks: FEATURE-REMOVAL fix passes every functional test: over-blocking is not caught |
| GHSA-p63j-vcc4-9vmv | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 1 (from 3 candidate files); fix checks: shallow leaves 3/4 security tests open, removal brea |
| GHSA-rf44-j88r-hh8c | REJECTED | coverage: reference fix minus pkg/config/static/static_config.go still scores 1.0 |

## 2026-10-19T09:58:07Z - Stage 5 - DeepSeek / MiMo evaluation

counts: {"rejected_too_easy": 1}

| task | status | rewards per model | detail |
|---|---|---|---|
| GHSA-p63j-vcc4-9vmv | rejected_too_easy | deepseek: [1.0] ; mimo: [] | solved by deepseek |

## 2026-10-19T12:49:51Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 0, "rejected": 0, "regenerate": 2, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-fm3f-ch8h-qw8q | REJECTED | fix checks: ALTERNATIVE correct fix scores 0 |
| GHSA-vxg7-f2jj-jmqm | REJECTED | rubric: The oracle fix is a dependency swap to forked goja/goja_nodejs modules with only import-path rewrites; no project logic changes, and the fix lives in an |

## 2026-10-19T13:10:47Z - Stage 4 - rubric + oracle validation

counts: {"ok": 1, "failed_oracle": 0, "rejected": 0, "regenerate": 0, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-fm3f-ch8h-qw8q | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 43 (from 1 candidate files); fix checks: shallow leaves 5/6 security tests open, removal bre |

## 2026-10-19T14:12:52Z - Stage 5 - DeepSeek / MiMo evaluation

counts: {"done": 0, "accepted": 1}

| task | status | rewards per model | detail |
|---|---|---|---|
| GHSA-fm3f-ch8h-qw8q | accepted | deepseek: [0.9845, 0.9845, 0.9845] ; mimo: [0.9845, 0.99, 0.9845] | every attempt is a counted model failure on every model {'over_correction': 6} |

## 2026-10-19T15:37:24Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 0, "rejected": 0, "regenerate": 4, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-54mm-6729-r5wp | REJECTED | rubric: Hidden test requires RequiresPermission(global: true) gates on six company-wide project, user and plugin listing methods that the report never mentions; |
| GHSA-8gr3-5j6f-25gp | REJECTED | rubric: Four of six security tests (both API-mapper tests, the schema test and the navigate test) call code the patch edits directly (mapToDto, inAppControlZodS |
| GHSA-8rgj-vrfr-6hqr | REJECTED | rubric: The security assertions can never pass. The harness replaces DashboardAPIError and RestAPIError with plain Error subclasses that Effect cannot run as er |
| GHSA-mw8m-398g-h89w | REJECTED | oracle does not pass its own tests (reward [0.0, 0.0], failing: ['::test_functional_api_tag_lookup_by_identifier_still_works', '::test_functional_api_tag_lookup |

## 2026-10-19T16:28:57Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 1, "rejected": 0, "regenerate": 2, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-8gr3-5j6f-25gp | REJECTED | rubric: The hidden harness stubs `@novu/application-generic` and mocks the inbox utils barrel with only the exports the oracle needs. A reasonable fix that expo |
| GHSA-8rgj-vrfr-6hqr | REJECTED | isolation audit: 1 added fix block(s) already present in the vulnerable tree, e.g. "import {\ntype AvailablePermissionRanks,\navailablePermissionRanks,\n} from  |
| GHSA-mw8m-398g-h89w | REJECTED | oracle does not pass its own tests (reward [0.8333, 0.8333], failing: ['::test_functional_api_tag_lookup_still_works', '::test_functional_api_tag_lookup_still_w |

## 2026-10-19T17:52:46Z - Stage 4 - rubric + oracle validation

counts: {"ok": 1, "failed_oracle": 1, "rejected": 0, "regenerate": 0, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-8gr3-5j6f-25gp | REJECTED | oracle does not pass its own tests (reward [0.0, 0.0], failing: ['::test_functional_control_schema_accepts_web_and_local_destinations', '::test_functional_contr |
| GHSA-mw8m-398g-h89w | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 41 (from 15 candidate files); fix checks: shallow leaves 3/6 security tests open, removal br |

## 2026-10-19T18:18:04Z - Stage 5 - DeepSeek / MiMo evaluation

counts: {"rejected_too_easy": 1}

| task | status | rewards per model | detail |
|---|---|---|---|
| GHSA-mw8m-398g-h89w | rejected_too_easy | deepseek: [1.0] ; mimo: [] | solved by deepseek |

## 2026-10-19T19:21:21Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 0, "rejected": 0, "regenerate": 1, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-8rgj-vrfr-6hqr | REJECTED | oracle does not pass its own tests (reward [0.0, 0.0], failing: ['::test_functional_admin_can_invite_editor', '::test_functional_admin_can_invite_editor', '::te |

## 2026-10-19T20:41:06Z - Stage 4 - rubric + oracle validation

counts: {"ok": 1, "failed_oracle": 0, "rejected": 0, "regenerate": 1, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-6x6c-w9w9-hv4h | REJECTED | rubric: Registry security/functional tests instantiate `TerraformRegistryGetter` directly, which the oracle diff indicates was unwired dead code before the fix  |
| GHSA-fm3f-ch8h-qw8q | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 41 (from 1 candidate files); fix checks: shallow leaves 5/6 security tests open, removal bre |

## 2026-10-19T20:46:42Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 2, "rejected": 0, "regenerate": 4, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-54mm-6729-r5wp | REJECTED | rubric: Self-contradictory hidden tests: scenario 2 of _TICKETS_EDIT_BODY has identical setup (caller only in project 1, parent ticket 5 in project 9) but the s |
| GHSA-6h7w-v2xr-mqvw | REJECTED | isolation audit: Dockerfile copies something other than repo/: ['COPY --from=composer:2 /usr/bin/composer /usr/local/bin/composer'] |
| GHSA-8rgj-vrfr-6hqr | REJECTED | oracle does not pass its own tests (reward [0.0, 0.0], failing: ['::test_functional_admin_can_invite_editor', '::test_functional_admin_can_invite_editor', '::te |
| GHSA-f3f2-mcxc-pwjx | REJECTED | oracle does not pass its own tests (reward [0.9167, 0.9167], failing: ['::test_functional_mysql_select_keeps_supported_operators', '::test_functional_mysql_sele |
| GHSA-v2f8-6655-7grj | REJECTED | tests bound to the reference design (names that exist only in the reference fix: ['VIBE_TRADING_ALLOWED_FILE_ROOTS', 'VIBE_TRADING_ALLOWED_RUN_ROOTS', 'VIBE_TRA |
| GHSA-w3rp-4cm2-4wgc | REJECTED | tests bound to the reference design (names that exist only in the reference fix: ['SECURITY']) |

## 2026-10-19T21:46:19Z - Stage 5 - DeepSeek / MiMo evaluation

counts: {"rejected_too_easy": 1}

| task | status | rewards per model | detail |
|---|---|---|---|
| GHSA-fm3f-ch8h-qw8q | rejected_too_easy | deepseek: [1.0] ; mimo: [1.0] | solved by deepseek, mimo |

## 2026-10-19T22:37:14Z - Stage 4 - rubric + oracle validation

counts: {"ok": 2, "failed_oracle": 0, "rejected": 1, "regenerate": 1, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-54mm-6729-r5wp | REJECTED | rubric: test_security_company_wide_listings_require_entitlement and the app-only probe are static docblock/source-grep heuristics (zz_blocked) rather than behav |
| GHSA-f3f2-mcxc-pwjx | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 286 (from 15 candidate files); fix checks: shallow leaves 4/6 security tests open, removal b |
| GHSA-v2f8-6655-7grj | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 133 (from 10 candidate files); fix checks: shallow leaves 5/6 security tests open, removal b |
| GHSA-w3rp-4cm2-4wgc | REJECTED | rubric: Hidden Go source does not compile: `[]sdk.Msg{authz.NewMsgExec(signerAddr, inner)}` and `[]sdk.Msg{inner}` use the value returned by authz.NewMsgExec, b |

## 2026-10-19T23:38:37Z - Stage 5 - DeepSeek / MiMo evaluation

counts: {"rejected_too_easy": 2}

| task | status | rewards per model | detail |
|---|---|---|---|
| GHSA-f3f2-mcxc-pwjx | rejected_too_easy | deepseek: [1.0] ; mimo: [1.0] | solved by deepseek, mimo |
| GHSA-v2f8-6655-7grj | rejected_too_easy | deepseek: [1.0] ; mimo: [1.0] | solved by deepseek, mimo |

## 2026-10-20T00:02:12Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 0, "rejected": 1, "regenerate": 0, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-w3rp-4cm2-4wgc | REJECTED | rubric: Security assertions are inverted: `_expect_refused` requires `returncode != 0` and `--- FAIL: <case>`, yet each Go security case fails only when the att |

## 2026-10-20T00:55:01Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 1, "rejected": 0, "regenerate": 1, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-6h7w-v2xr-mqvw | REJECTED | out of spec: no usable existing tests of the affected code (candidate files: 0; repos whose test runner we cannot run yet end here too) |
| GHSA-hfvx-25r5-qc3w | REJECTED | tests bound to the reference design (probing for guessed fields/attributes: ['returncode']) |

## 2026-10-20T01:33:27Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 0, "rejected": 0, "regenerate": 1, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-hfvx-25r5-qc3w | REJECTED | fix checks: SHALLOW fix: no security test passes, so it does not even block the reported trigger |

## 2026-10-20T02:18:37Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 0, "rejected": 1, "regenerate": 0, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-hfvx-25r5-qc3w | REJECTED | rubric: F6 (`test_functional_save_reload_export`) expects the object id 'panel & frame' to survive canvas.toObject() -> loadFromJSON() -> toSVG(); FabricObject. |

## 2026-10-20T03:59:40Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 0, "rejected": 0, "regenerate": 1, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-9m84-wc28-w895 | REJECTED | rubric: Security tests never go through the declared HTTP entry points; they instantiate the internal session service with a hand-rolled DI container and call t |

## 2026-10-20T04:06:16Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 0, "rejected": 0, "regenerate": 1, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-9m84-wc28-w895 | REJECTED | tests bound to the reference design (probing for guessed fields/attributes: ['returncode']) |

## 2026-10-20T04:29:35Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 0, "rejected": 0, "regenerate": 0, "failed": 1}

| task | verdict | detail |
|---|---|---|
| GHSA-9m84-wc28-w895 | REJECTED | tests bound to the reference design (probing for guessed fields/attributes: ['returncode']) |

## 2026-10-20T05:27:34Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 1, "rejected": 0, "regenerate": 1, "failed": 1}

| task | verdict | detail |
|---|---|---|
| GHSA-9m84-wc28-w895 | REJECTED | tests bound to the reference design (probing for guessed fields/attributes: ['returncode']) |
| GHSA-c78m-c52x-jgwp | REJECTED | rubric: PHP probe harness instantiates ZzHiddenArrayBackend and TransientMemoryBackend with zero constructor arguments; AbstractBackend::__construct($context, a |
| GHSA-m382-6jw4-fmp6 | REJECTED | isolation audit: 3 added fix block(s) already present in the vulnerable tree, e.g. '"@internal/cfg-typescript": "workspace:*",\n"@internal/cfg-vitest": "workspa |

## 2026-10-20T05:47:56Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 0, "rejected": 0, "regenerate": 1, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-c78m-c52x-jgwp | REJECTED | oracle does not pass its own tests (reward [0.3333, 0.3333], failing: ['::test_functional_cache_miss_tags_lifetime_and_removal', '::test_functional_cache_miss_t |

## 2026-10-20T06:05:30Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 1, "rejected": 0, "regenerate": 0, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-c78m-c52x-jgwp | REJECTED | out of spec: no usable existing tests of the affected code (candidate files: 15; repos whose test runner we cannot run yet end here too) |

## 2026-10-20T07:24:39Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 1, "rejected": 0, "regenerate": 0, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-2q76-m6w6-qgc6 | REJECTED | oracle does not pass its own tests (reward [0.8333, 0.8333], failing: ['::test_functional_api_key_auth_on_other_collections_still_works', '::test_functional_api |

## 2026-10-20T22:27:51Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 1, "rejected": 1, "regenerate": 0, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-jmg2-rcxh-w8q3 | REJECTED | out of spec: no usable existing tests of the affected code (candidate files: 7; repos whose test runner we cannot run yet end here too) |
| PYSEC-2026-3837 | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 62 (from 15 candidate files); fix checks: shallow leaves 5/6 security tests open, removal br |

## 2026-10-21T00:00:26Z - Stage 4 - rubric + oracle validation

counts: {"ok": 1, "failed_oracle": 0, "rejected": 0, "regenerate": 0, "failed": 0}

| task | verdict | detail |
|---|---|---|
| PYSEC-2026-3837 | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 62 (from 15 candidate files); fix checks: shallow leaves 5/6 security tests open, removal br |

## 2026-10-21T01:14:16Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 1, "rejected": 0, "regenerate": 2, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-36fc-7wjg-mfvj | REJECTED | rubric: Two of the four security tests (store-root, store-nested) target Asset\WebDAV\Service::getDeleteLog(), a file-backed WebDAV delete-history sink the inst |
| GHSA-59w7-v8rr-pr4p | REJECTED | out of spec: no usable existing tests of the affected code (candidate files: 15; repos whose test runner we cannot run yet end here too) |
| PYSEC-2026-4200 | REJECTED | oracle does not pass its own tests (reward [0.9167, 0.9167], failing: ['::test_functional_reprinted_address_adds_no_extra_switch', '::test_functional_reprinted_ |

## 2026-10-21T01:22:12Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 0, "rejected": 0, "regenerate": 2, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-5p3m-vhh6-9236 | REJECTED | rubric: test_security_delivery_dns_rebind can only observe the URL passed to the mocked httpx.Client.post, so it demands the oracle's specific URL-rewrite-to-pi |
| GHSA-rqx4-3f6q-3x2v | REJECTED | rubric: no_hints: not answered by reviewer; accurate_report: not answered by reviewer; solvable_from_report: not answered by reviewer; real_entry_point: not ans |

## 2026-10-21T01:26:37Z - Stage 5 - DeepSeek / MiMo evaluation

counts: {"done": 0, "needs_review": 1}

| task | status | rewards per model | detail |
|---|---|---|---|
| PYSEC-2026-3837 | needs_review | deepseek: [0.8889, 0.8889, 0.8889] ; mimo: [0.8889, 0.8889, 0.8889] | deepseek: 2/3 attempts are counted model failures; deepseek/harbor_task__edp62ja: step 84: command touches grading files ('ls -la /logs/artifacts /logs/verifier |

## 2026-10-21T01:51:37Z - Stage 4 - rubric + oracle validation

counts: {"ok": 0, "failed_oracle": 0, "rejected": 0, "regenerate": 1, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-7w8c-qgxg-m7jx | REJECTED | rubric: Report describes only the syslog program-name sink, but hidden tests require escaping fixes in ~8 unrelated pages/functions (alert details, BGP peer row |

## 2026-10-21T16:01:40Z - Stage 4 - rubric + oracle validation

counts: {"ok": 1, "failed_oracle": 0, "rejected": 0, "regenerate": 2, "failed": 0}

| task | verdict | detail |
|---|---|---|
| GHSA-36fc-7wjg-mfvj | REJECTED | oracle does not pass its own tests (reward [0.0, 0.0], failing: ['::test_functional_delete_history_round_trip', '::test_functional_delete_history_round_trip', ' |
| GHSA-rqx4-3f6q-3x2v | REJECTED | oracle does not pass its own tests (reward [0.0, 0.0], failing: ['::test_functional_admin_disabled_mock_answers', '::test_functional_admin_disabled_mock_answers |
| PYSEC-2026-3837-v2 | ok | oracle 1.0, pre-patch fails as required; existing pass->pass tests: 62 (from 15 candidate files); fix checks: shallow leaves 5/6 security tests open, removal br |

## 2026-10-21T16:40:46Z - Stage 5 - DeepSeek / MiMo evaluation

counts: {"rejected_too_easy": 1}

| task | status | rewards per model | detail |
|---|---|---|---|
| PYSEC-2026-3837-v2 | rejected_too_easy | deepseek: [1.0] ; mimo: [1.0] | solved by deepseek, mimo |

