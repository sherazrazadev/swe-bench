# Pipeline: stage by stage

**Goal:** Harbor security-fix tasks that both DeepSeek V4.1 Flash (effort max) and MiMo-V2.6-Pro fail in all 3
attempts, where the failure is the model's fault and not the task's.
Run with `python run_pipeline.py` (see the [README](../README.md)). The state of each task is kept in
`data/pipeline_state.sqlite3`, so finished work is never repeated.

## Stage 1 - Mining

- **Sources:** OSV (bulk export), the GitHub Advisory Database (GHSA) and huntr. Python (PyPI), JavaScript/TypeScript (npm), Go and PHP (Packagist).
- **Fix commit:** taken from the advisory's commit links. A series of fix commits is merged; for a backport the
  default-branch copy is used. The commit before the fix is the vulnerable state.
- **Cutoff:** the advisory and the fix commit must be after `PUBLISHED_AFTER` (2026-08-01), so the fix is not in the
  models' training data.
- **Dedupe:** an advisory or commit already seen is never mined again.
- **Stored in:** `data/01_mined/osv_candidates.json`.

## Stage 2 - Screening

- **Rejected:**
  - dependency-bump, config, CI, docs and generated-only fixes;
  - template-dominated fixes;
  - no source change in Python or JS/TS;
  - fixes outside 4-400 source lines or over 300 files;
  - no root build manifest or no tests in the repo;
  - repos over 400 MB;
  - more than 3 candidates from one repo.
- **Score (No AI):** fix breadth `8 × files (max 8) + 6 × (directories - 1, max 4)` + a line-band bonus, −25 for tiny
  fixes, +3 if the repo has 5+ tests, +14 for a parallel implementation (same file name in two directories), +10 for a
  producer changed with the check it feeds, +8 for a multi-commit fix, +40 for a fix-bypass pair, plus a small prior from
  how often the CWE broke both models before.
- **CWE-bench category (weakness class, No AI):** each CWE maps to a class from `others/cwe-bench/sourcer/weights.json`;
  favoured classes rank up (auth/session +14, access control / integrity / insecure design +12, deserialization +11,
  crypto / SSRF / logic +9), easy ones rank down (path traversal +2, open redirect and single-sink injection −2,
  prototype pollution −4). Easy classes are **down-weighted, not rejected**: they get less priority next cycle. Unmapped
  or missing CWEs are neutral (+4). Fixes committed after 2026-09-01 get +4 (memorisation). Stored as
  `screening.weakness_class`.
- **Stored in:** `data/02_screened/screened.json` (passed) and `rejected.json`.

## Stage 3 - Task builder

- **Picking candidates:**
  - screening score + a **learned adjustment** from results so far: vulnerability families that never broke a model
    rank lower, and so do packages already solved;
  - repos that cannot be built here or were safety-flagged are skipped;
  - one candidate per repo per batch; languages balanced (at most ceil(6 / #languages) per batch);
  - wide fixes first: only fixes of >= 6 source files while any are left (`MIN_PICK_SOURCE_FILES`); no fix of
    <= 5 files ever broke a model.
- **Environment:** the repo is checked out at the vulnerable commit as a single snapshot commit, with no fix history.
  It is stored in `data/03_environments/<id>/repo/`, with the fix saved as `oracle_solution.patch`.
- **Build check:**
  - a Docker install of the project; the Python version comes from `requires-python` (3.11-3.13), and uv workspaces
    install from `uv.lock`;
  - network errors are retried;
  - a candidate whose build times out twice is retired.
- **Pre-build plan gate** (`plan_gate.py`, after checkout, before the Docker build check; `PLAN_GATE=gate|advisory|off`):
  1. heuristic (No AI): rejects only the cwe-bench "control" profile - an easy class fixed in one compact place - or a
     fix that only adds new files;
  2. plan draft (DeepSeek): report sketch, hidden places with their mechanism (M4/M6/M2/M10/M5/M11), coupled contract,
     and a self-attack (the repair DeepSeek itself would write; a hidden place must lie outside it);
  3. self-solve probe (DeepSeek + MiMo, file list only): if every target names every hidden place from the sketch, the
     trap is visible - too easy;
  4. review (Claude, a non-target model): proceed / too easy / unfair on fixed criteria; the verdict follows from the
     criteria. A safeguards flag retires the candidate.
  Model errors fail open. The verdict is cached in `plan_gate.json`; an approved plan is fed to the generator.
- **Generation:** DeepSeek (`TASK_GEN_BACKEND=deepseek`, Claude Code CLI against DeepSeek's Anthropic-compatible API,
  no Claude fallback) gets the fix, the vulnerable source, its callers, a repo map, test examples, the design contract,
  the knowledge base, the approved plan and the **self-break protocol**: DeepSeek is also a target, so it writes down
  its own first repair (`self_attack.naive_fix`) and the over-broad one, keeps a trap outside the naive fix, and makes
  the `shallow` and `removal` check patches exactly those two repairs - stage 4 then executes them. Always two calls:
  design + check patches, then the test suite. It writes:
- **Output checks:** no changed file or function names in the report, no copied advisory text, the minimum test
  counts, no skips (`skip`, `xfail`, `importorskip`), check patches that apply, output not truncated.
  Since 2026-10-21 also, at generation time: the self-attack is present, a trap path lies outside `naive_fix_files`
  and the shallow patch only edits those files; every test quotes, verbatim, the `instruction.md` sentence that requires
  its assertion (`test_justifications`); and the tests use no name that exists only in the reference fix (stage 4's
  design-bound check, run early so call 2 cannot ship a suite only the reference design passes).
- **Safety:** a safeguards (AUP) flag on any Claude call (plan review, rubric) retires the candidate with no retry. A patch that is too large retires the candidate.

## Stage 4 - Validation

A task must pass all of these before any model sees it:

0. **Design-bound tests** (deterministic, before anything else): hidden tests may not use names that exist only in
   the reference fix (new fields, functions, env vars) or probe for guessed members; such a task goes back to
   stage 3 with the names. The generator also declares a candidate `<unsuitable>` when the upstream fix leaves an
   identical vulnerable path unfixed.
1. **Rubric:** 10 criteria, all blocking: accurate report, report doesn't prescribe the fix, solvable from the
   report, real entry point, variants share the root cause, implementation-agnostic, functional tests meaningful,
   deterministic and offline, realistic, not a config or dependency change.
2. **Recall probe:** both models get the report only; rejected if both name the file to fix.
3. **Leak checks:** the task files are audited, and the whole built image is scanned for copies of the fix's code
   (for example a released, already-fixed copy of the package in `node_modules`).
4. **Reference fix** scores 1.0 twice; the **vulnerable code** fails every security test.
5. **Existing repo tests** of the affected code pass before and after the fix. They are required, and enforced in
   grading. They run the way the project's CI runs them: from the nearest folder with its own jest/vitest config,
   with the env and `--config` its `test` script chain sets, `node --test` for `node:test` files; the image installs
   nested test packages, a Playwright browser when needed, and copies `*.dist.*` config templates.
6. **Check patches:** the *shallow* fix still fails a security test, the *removal* fix fails a functional test, and
   the *alternative* fix scores 1.0.
7. **Coverage (leave-one-file-out):** the reference fix runs without its change to each `fix_places` file (up to 4);
   a test must fail each time, or an agent that skips that file would pass. Sent back while rewrites remain, then
   only a warning.

On failure the task goes back to stage 3 with the reviewer's or pytest's feedback (at most 2 rewrites). Docker or
infrastructure errors give "no verdict" and are retried. Records are kept in `data/03_environments/<id>/validation/`.

## Stage 5 - Evaluation (model runner)

- **Harness:** Harbor CLI 0.24 runs each task with the **Claude Code agent** (version pinned and baked into the task
  image). DeepSeek is reached through its Anthropic-compatible API with reasoning effort `max`, and MiMo through its
  own API.
- **Task image:** a `node:22` or `python:3.x-slim` base, the project installed (and built for TypeScript), the repo at
  the vulnerable commit, and Claude Code.
- **Blocked:**
  - **Network:** the agent container sits on an internal network; an egress proxy allows only the model API hosts.
    No GitHub, npm, PyPI or web search.
  - **Answer key:** no hidden tests, fix, fix history or advisory in the container.
  - **Credentials:** our Anthropic and GitHub keys are stripped from what Harbor passes into the container. Note:
    Harbor's claude-code agent forwards the target model's key with `docker compose exec -e KEY=VALUE`, so it is
    visible in the host process list during a run. A local one-line patch to Harbor's `_compose_exec` (`-e KEY`, value
    taken from the host environment) removes it from argv; it is not applied by default.
- **Grading in a separate container:** after the agent stops, only its source patch is collected (test configs and
  manifests excluded) and applied in a **fresh container** from the same image, where the hidden tests and the
  existing tests run. Nothing else the agent changed can reach the grader.
- **Score:** the mean of the security, functional and existing-test pass rates. Solved = 1.0; anything less is a
  failure (a partial fix or a broken feature).
- **Runs:** 3 attempts per model, 2 hours each, up to 5 tasks in parallel. Attempt 1 runs alone, then attempts 2-3
  together. Once either model solves, the remaining attempts are cancelled and the task is rejected.
- **Verdict (deterministic, no LLM judge):** **accepted** only if every attempt of both models is a counted failure
  (graded, below 1.0, no harness error, the agent really worked, no tampering). A **timeout is not a failure**.
  A read-only `ls`/`find` of the empty grading mount points is recorded as a **probe**, not tampering; only reading or
  writing grading files (or a direct file-tool call on those paths) disqualifies the attempt.
- **Stored in:** `data/04_eval_runs/<id>/<model>/…`: each attempt's trajectory, patch and per-test results, plus
  `attribution.json`.

## Stage 6 - Packaging

- The reference fix runs one last time on the final task (it must score 1.0).
- **Harbor layout** written to `data/05_accepted_harbor/<id>/`: `instruction.md`, `task.toml` (CWE, language, repo,
  source, entry point, timeouts, network policy), `environment/` (Dockerfile + repo), `solution/` (reference fix),
  `tests/` (hidden tests, existing-test list, grader scripts).
- Run it with `harbor run -p data/05_accepted_harbor/<id> -a oracle`.

## Knowledge loop (after every verdict)

- **Rebuilt automatically:** `C_RESULTS.md` (all results and per-attempt failure details) and
  `data/knowledge/model_failure_map.md`.
- **Failure analyses:** `failure_analyses/<id>.md`, why each model failed, written from its trajectories.
- **Technique scoreboard:** `technique_scoreboard.md`, how often each design technique broke a model compared with
  the baseline.
- **Contamination canary:** `generator_canary.md` - DeepSeek's solve rate on its own (self-break protocol) designs vs
  on other generators' tasks; alarm at a 20-point excess over >= 5 tasks. Measurement only, never a verdict.
- The **generator reads all of these** in the next round, and **candidate ranking** uses the same results.
