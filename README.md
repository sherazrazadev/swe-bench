# CWE-Bench task factory

A pipeline that turns real, recently fixed vulnerabilities in open-source projects into **Harbor-format security-fix
tasks** for [CWE-Bench](task/CWE-Bench%20Task%20Project.pdf). A task is **accepted** only when both target models fail
it in every attempt (pass@3 = 0):

- **DeepSeek V4.1 Flash** (reasoning effort `max`)
- **Xiaomi MiMo-V2.6-Pro**

A failure counts only if the task is sound (it passes the rubric and validation) and the deterministic trial analysis
attributes the failure to the model, not to a task defect.

> **Start here:** [docs/PIPELINE.md](docs/PIPELINE.md) (pipeline on one page); why the models fail is tracked live in
> [C_RESULTS.md](C_RESULTS.md) and `data/knowledge/` (failure map, technique scoreboard, per-task failure analyses).
>
> **Results:** see **[C_RESULTS.md](C_RESULTS.md)**, rebuilt automatically after every evaluation. It has every
> evaluated task with its final verdict, which task type broke which model, and per-attempt failure details.

---

## Contents

1. [Results so far](#results-so-far)
2. [Documentation](#documentation)
3. [How the pipeline works](#how-the-pipeline-works)
4. [Task generation rules](#task-generation-rules)
5. [How a task is graded](#how-a-task-is-graded-and-why-it-cannot-be-gamed)
6. [The learning loop](#the-learning-loop-knowledge-base)
7. [Repository structure](#repository-structure)
8. [Requirements](#requirements)
9. [Installation](#installation)
10. [Running the pipeline](#running-the-pipeline)
11. [Configuration](#configuration-env)
12. [Outputs](#outputs-where-to-look)
13. [Rules and policies](#rules-and-policies)
14. [Troubleshooting](#troubleshooting)
15. [What is not in git](#what-is-not-in-git)

---

## Results so far

Snapshot of 2026-10-16: **24 tasks evaluated, 1 accepted**. Full and current numbers are in
[C_RESULTS.md](C_RESULTS.md).

| Task | Vulnerability | DeepSeek V4.1 Flash | MiMo-V2.6-Pro | Verdict |
|---|---|---|---|---|
| **hono** GHSA-hxh3-vqpv-xpqv | XSS in the JSX server renderer (CWE-79, 6-file fix) | **failed 3/3** (0.83 / 0.83 / 0.94) | **failed 3/3** (0.89 / 0.94 / 0.89) | **ACCEPTED** |
| MCP TypeScript SDK GHSA-6qxp-vccf-f47h | OAuth credential pinning (CWE-345/522, 8 files) | **failed 3/3** (0.92 each) | timed out 3/3 (not counted) | rejected |
| nltk GHSA-p4rw-rvv2-7xwr | Symlink escape in corpus readers (CWE-22/59, 10 files) | **failed 3/3** (0.93 each) | solved 1 of 3 | rejected |
| undici GHSA-vp8m-p9jh-q5pm | Cache/origin confusion (CWE-346, 10 files) | failed 1, then solved | failed 1 (broke legitimate caching) | rejected |

The other 20 tasks were solved, most of them by DeepSeek on attempt 1 in 4 to 42 minutes.

What we have learned about the two models (details in
[`data/knowledge/failure_analyses/`](data/knowledge/failure_analyses/)):

- **Both** treat the report's examples as the complete list of affected code paths. They fix only the input shape
  they reproduced, and they stop once the report's bullet points are covered.
- **DeepSeek** misses:
  - state that crosses a save/reload boundary;
  - a second, lower-level public API;
  - sinks a "must keep working" clause can be read as protecting.
  It stops as soon as its own tests pass.
- **MiMo** under-explores and asserts things it has not checked. It rationalises away leaks it observed, and it
  over-hardens fixes in ways that break legitimate behaviour.
- **Techniques that break the models:**

  | # | Technique | Break rate |
  |---|---|---|
  | 1 | Unnamed sibling path | 50% |
  | 7 | Parallel implementation | 40% |
  | 9 | A "must keep working" clause that argues against the fix | 25% |

  The baseline break rate is 17%. Live numbers are in
  [`technique_scoreboard.md`](data/knowledge/technique_scoreboard.md).

---

## Documentation

| Doc | What it is |
|---|---|
| [docs/PIPELINE.md](docs/PIPELINE.md) | Every stage on one page: sources and storage, rules, generation logic, validation checks, evaluation (image, Claude Code agent, what is blocked, grading, verdict), packaging and paths |

---

## How the pipeline works

```
 1 Mining ─► 2 Screening ─► 3 Task builder ─► 4 Validator ─► 5 Model runner ─► 6 Packager
 (OSV/GHSA)   (filters,      (repo + Opus      (rubric, real   (DeepSeek + MiMo,  (Harbor task in
               ranking)       writes the task)  runs, checks)   3 attempts each)   05_accepted_harbor)
                                    ▲                                  │
                                    └──── knowledge base ◄─────────────┘
                                          (updated after every verdict)
```

| Stage | Module | What it does |
|---|---|---|
| 1 Mining | `src/stage1_mining` | Pulls PyPI/npm advisories from OSV and GHSA. Resolves the fix commit (or fix series). Never re-mines a known advisory. |
| 2 Screening | `src/stage2_screening` | Keeps fixes committed after `PUBLISHED_AFTER`, in a supported language, with real source changes and a test suite, in repos under `MAX_REPO_MB`. Rejects dependency-bump, config-only, docs-only and template-only fixes. Scores candidates by fix breadth (files, directories, lines). |
| 3 Task builder | `src/stage3_task_builder` | Ranks candidates by screening score plus a **learned adjustment** from past results. Checks out the vulnerable commit, runs the **pre-build plan gate** (No-AI heuristic, DeepSeek plan draft, self-solve probe by both targets, Claude review), then a Docker build check. **DeepSeek** (self-break protocol: it predicts and defeats its own first repair) then writes `instruction.md` (a behavioural report with no fix, file or function hints), hidden security and functional tests, metadata (entry point, techniques used) and three check patches. |
| 4 Validator | `src/stage4_oracle_validator` | See the checks below. |
| 5 Model runner | `src/stage5_evaluator` | Runs DeepSeek and MiMo through Harbor's **Claude Code** agent: 3 attempts each, a 2-hour limit, up to 5 tasks in parallel. Stops early once a model solves. Gives a deterministic verdict and attribution. |
| 6 Packager | `src/stage6_packager` | Re-runs the reference fix one last time, then writes the final Harbor task to `data/05_accepted_harbor/<id>/`. |

Stage 4 accepts a task only if it passes all of these:

- an LLM **rubric**, all criteria blocking: an accurate report, solvable from the report, a real entry point, variants
  that share the root cause, implementation-agnostic tests, deterministic and offline tests, a realistic scenario,
  and not a config or dependency bump;
- a **recall probe**: rejected if both models name the fix location from the report alone;
- an **isolation audit** and a **scan of the whole image** for any copy of the fix's code;
- the **reference fix** scoring 1.0 twice, and the **vulnerable code** failing the security tests;
- **existing repo tests** of the affected code that pass before and after the fix;
- three **check patches**: a *shallow* fix must still fail a security test, a *feature-removal* fix must fail a
  functional test, and an *alternative* correct fix must score 1.0.

Each stage can run on its own. A task moves forward only when the previous stage marked it done, and the state lives
in `data/pipeline_state.sqlite3`.

## Task generation rules

Every generated task must satisfy these rules. Most are enforced by code: the generator's output validators, stage 4
checks and the rubric. The rest are instructions in the generation prompt and the technique guide. Details:
[docs/PIPELINE.md](docs/PIPELINE.md).

**What a task is**

1. **A real vulnerability in a real repo.** A mined advisory whose fix was committed after `PUBLISHED_AFTER`, with the
   repo pinned at the vulnerable commit and the historical fix as the oracle. No synthetic snippets, no
   dependency-bump or config-only fixes, no unreachable code.
2. **Three artifacts from the generator:** the report (`instruction.md`), the hidden tests (`hidden_tests.py`) and
   three check patches (shallow, removal, alternative).

**The report (`instruction.md`)**

3. Behaviour only: the impact and how the issue is triggered, as a user or researcher would file it, in 150-400
   words.
4. No localisation: no changed file names, no module, function or class names the fix touches, no line numbers, no
   hint of where or how to fix it. A validator rejects names of changed files and edited identifiers.
5. No fix prescription. The expected behaviour may state only the security property and the legitimate behaviour that
   must keep working.
6. Written in the generator's own words: no advisory phrases, no CVE or GHSA id, and no description of the hidden
   variants.

**The hidden tests (`hidden_tests.py`)**

7. Naming and counts: at least 3 `test_security_*` tests (fail on the vulnerable code, pass after a fix) and at least
   3 `test_functional_*` tests (pass on both). No `skip`, `skipif`, `xfail` or `importorskip`.
8. They go through a real entry point (public API, HTTP route, CLI, exported function), never the internal helper the
   fix edits.
9. They are implementation-agnostic. They observe only what a caller can see, never import or assert anything the fix
   adds, never assert exact error text, and accept any reasonable way of blocking the attack.
10. They include variants beyond the report that share the same root cause, one test per variant: another entry
    point, encoding, casing, nested input, round-trip or repeated call. A fix that closes only some variants still
    fails.
11. Functional tests sit close to the attack boundary, so a fix that over-blocks or removes the feature fails.
12. Fairness:
    - the reference fix passes every test;
    - no test requires a number the report does not state;
    - variants share the reported root cause;
    - "must keep working" behaviour already works on the vulnerable code.
13. They are deterministic and offline: no network, no timing races, no randomness. They use harmless sentinel
    values.

**Proof that the tests tell good fixes from bad ones** (run in stage 4)

14. The reference fix scores 1.0 twice, and the vulnerable code fails every security test.
15. The **shallow** patch (blocks only the reported trigger) still fails a security test. The **removal** patch
    (disables the feature) fails a functional test. The **alternative** patch (a correct fix of a different design)
    scores 1.0.
16. The repo's existing tests of the affected code pass before and after the fix and are enforced in grading.

**Design techniques that make the models fail** (curated in
[`skills/task_design_techniques.md`](skills/task_design_techniques.md); live break rates in
[`technique_scoreboard.md`](data/knowledge/technique_scoreboard.md))

17. An unnamed sibling path to the same root cause, a parallel implementation of the same feature, a second public
    API, input-shape variants at each sink, a "must keep working" clause that argues against the fix,
    already-protected-looking code nearby, a fix across a layer boundary, and big multi-file fixes.
18. The generator records which techniques each task applies. The scoreboard and the automatic failure analyses feed
    back into the next round.

**Safety**

19. Generation runs on DeepSeek with no Claude fallback. Claude is used only to review (plan gate, rubric); if
    Anthropic's safeguards flag a session, the candidate is retired with no retry and no fallback, and its repo is not
    tried again. Because DeepSeek is also a target, `data/knowledge/generator_canary.md` watches for it solving its
    own designs disproportionately.

## How a task is graded (and why it cannot be gamed)

- **Partial score:** the mean of the security pass rate, the functional pass rate and the enforced existing-test pass
  rate. A solve means exactly 1.0, so a partial fix (5 of 6 attack variants) or a fix that breaks a feature is a
  **failure**.
- **No answer key in reach:** the agent container holds only the repo at the vulnerable commit (one snapshot commit,
  no fix history) and the report. The hidden tests, the fix and the advisory are never inside it.
- **Network isolation:** the agent runs on an internal Docker network. An egress proxy (`docker/egress`) allows only
  the model API hosts, so the agent has no GitHub, npm or web search.
- **Separate grader:** grading happens in a **fresh container** built from the same image. Only the agent's source
  patch crosses over (test configs and manifests are excluded), so nothing the agent changed in its own environment
  can influence grading.
- **Deterministic verdict, no LLM judge:** pass, fail, timeout and error come from the test results and Harbor's
  records. An attempt that hit the 2-hour limit is **not** counted as a failure. LLMs are used only to write tasks,
  review task design and write failure analyses; they never decide a verdict.

## The learning loop (knowledge base)

The task generator reads the knowledge base every round. After every verdict it is updated **automatically**:

| File | Content | Maintained by |
|---|---|---|
| [`C_RESULTS.md`](C_RESULTS.md) | All tasks, which task type broke which model, per-attempt failure details | generated |
| [`data/knowledge/model_failure_map.md`](data/knowledge/model_failure_map.md) | Per model: task types it failed, timed out on, or solved | generated |
| [`data/knowledge/failure_analyses/<id>.md`](data/knowledge/failure_analyses/) | Why each model failed, from its trajectories (quotes, missed paths, task-design lessons) | `failure_analyst.py` (LLM, knowledge only). Hand-written files are never overwritten. |
| [`data/knowledge/technique_scoreboard.md`](data/knowledge/technique_scoreboard.md) | Break rate of each task-design technique against the baseline | generated |
| [`skills/task_design_techniques.md`](skills/task_design_techniques.md) | Curated techniques, failure contract and fairness rules | curated |
| [`skills/lessons_learned.md`](skills/lessons_learned.md) | Lessons from all outcomes | LLM, guarded against truncation |

Candidate selection learns too:

- vulnerability families that never broke a model rank lower (for example DoS, 0 of 7);
- packages or repos already solved rank lower;
- repos whose image cannot be built here, or whose generation was safety-flagged, are skipped;
- a candidate whose build times out twice is retired.

---

## Repository structure

```
cwe-bench-task/
├── README.md                    this file
├── C_RESULTS.md                 results ledger (generated)
├── run_pipeline.py              entry point for all stages
├── requirements.txt
├── .env.example                 configuration template (copy to .env)
├── docker-compose.yml           optional: run the pipeline itself in containers (see scripts/pipeline)
├── docker/
│   ├── Dockerfile.pipeline      image for the containerised pipeline
│   └── egress/                  allowlist egress proxy for the agent network (image cwe-egress:2, built automatically)
├── scripts/pipeline             helper for the containerised pipeline
├── skills/                      prompt knowledge: techniques, lessons, adversarial research guide, project context
├── task/                        the project specification (PDF)
├── src/
│   ├── common/                  config, Harbor wrapper, LLM backend, state, knowledge, results report, ledger
│   ├── stage1_mining/           osv_miner.py
│   ├── stage2_screening/        screener.py
│   ├── stage3_task_builder/     environment_builder.py, build_check.py, task_generator.py
│   ├── stage4_oracle_validator/ oracle_runner.py, rubric_check.py, recall_probe.py
│   ├── stage5_evaluator/        model_runner.py, trial_analysis.py, failure_analyst.py
│   └── stage6_packager/         harbor_packager.py (task layout, Dockerfiles, grader scripts, image scan)
└── data/
    ├── 01_mined/                mined advisories (in git: no re-mining needed)
    ├── 02_screened/             screened candidates (in git)
    ├── 03_environments/         per-candidate repo checkout + generated task + validation runs   (not in git)
    ├── 04_eval_runs/            per-task model attempts: trajectories, patches, test results      (not in git)
    ├── 05_accepted_harbor/      accepted Harbor tasks (in git, without the repo snapshot)
    ├── knowledge/               the learning loop (in git)
    ├── logs/                    one folder per run, see data/logs/README.md                       (not in git)
    └── pipeline_state.sqlite3   pipeline state                                                    (not in git)
```

---

## Requirements

| What | Version / notes |
|---|---|
| macOS or Linux | developed on macOS (Apple Silicon) |
| Python | 3.12 |
| [Harbor](https://pypi.org/project/harbor/) CLI | 0.24 (`pip install harbor`) |
| Docker | Docker Desktop. Give it **≥ 12 GB memory, ≥ 8 CPUs** and **≥ 100 GB free disk** (task images are 1 to 6 GB each). Set larger network address pools (below). |
| Claude Code CLI | for task generation (stage 3). Log in with a Claude subscription (`claude login`) or use `claude setup-token`. |
| API keys | DeepSeek and Xiaomi MiMo (stage 5), and a GitHub token (stages 1 and 2) |
| Network | GitHub, OSV, the package registries (npm, PyPI) and the model APIs |

**Docker address pools.** Each attempt needs its own networks, and Docker's default pools run out ("all predefined
address pools have been fully subnetted"). Add this to `~/.docker/daemon.json` (Docker Desktop: Settings → Docker
Engine), then restart Docker:

```json
{ "default-address-pools": [ { "base": "10.200.0.0/16", "size": 24 } ] }
```

## Installation

```bash
git clone https://github.com/aamiralidsinc/cwe-bench.git
cd cwe-bench && git checkout cwe-bench-sheraz

python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt          # includes the harbor CLI

cp .env.example .env                     # then fill in GITHUB_TOKEN, DEEPSEEK_API_KEY, MIMO_API_KEY
claude login                             # once, for task generation (or set CLAUDE_CODE_OAUTH_TOKEN in .env)

# sanity checks
docker info > /dev/null && echo docker ok
harbor --version
python run_pipeline.py --status
```

The egress proxy image (`cwe-egress:2`) and its shared network are created automatically the first time stage 4
runs.

---

## Running the pipeline

```bash
source .venv/bin/activate

# overview
python run_pipeline.py --status                 # counts per stage and status
python run_pipeline.py --watch                  # live status board (refreshes every 15 s)

# one command, end to end: mine, screen, then build/validate/evaluate/package the N best candidates
python run_pipeline.py --batch 10

# or stage by stage
python run_pipeline.py --stage 1 2 --limit 100                    # mine + screen new advisories
python run_pipeline.py --from-stage 3 --to-stage 4 --pilot 10 \
       --workers 3                                                 # generate + validate the 10 best candidates
python run_pipeline.py --stage 5 6 --follow --workers 5            # evaluate (5 tasks in parallel) + package;
                                                                   # --follow picks up tasks as stage 4 validates them
```

Typical batch: run stages 3 and 4 in one terminal and the follow-mode runner (`--stage 5 6 --follow`) in another.
Each task is evaluated as soon as it validates.

Useful extras:

```bash
python run_pipeline.py --stage 4 --only GHSA-xxxx-xxxx-xxxx        # (re)validate specific tasks
python run_pipeline.py --reverdict GHSA-xxxx [--apply]             # recompute a deterministic verdict
python -m src.common.results_report                                # rebuild C_RESULTS.md + knowledge files
python -m src.stage5_evaluator.failure_analyst GHSA-xxxx           # (re)write a failure analysis
python -m src.common.technique_backfill                            # infer techniques for older tasks
```

**Logs.** Give each run its own folder `data/logs/YYYY-MM-DD_HHMM_<what>/` with numbered step logs
(`01_build-generate-validate.log`, `02_model-runner.log`, …) and add a row to `data/logs/README.md`.

## Configuration (`.env`)

See [`.env.example`](.env.example) for all keys. The important ones:

| Key | Meaning |
|---|---|
| `PUBLISHED_AFTER` | Only fixes committed after this date (avoids the models' training data). Currently `2026-08-01`. |
| `MAX_REPO_MB` | Skip repos larger than this (400). |
| `TASK_GEN_BACKEND`, `DEEPSEEK_GEN_MODEL` | Task generator: `deepseek` (default, model `deepseek-flash[1m]`); `cli`/`api` = Claude. |
| `PLAN_GATE` | Pre-build plan gate: `gate` (default), `advisory`, `off`. |
| `ANTHROPIC_MODEL`, `GEN_FALLBACK_MODEL` | Claude reviewer for the plan gate and rubric, and its fallback on a malformed reply. |
| `EVAL_AGENT`, `CLAUDE_CODE_VERSION` | Agent harness for the evaluated models (`claude-code`, baked into each task image). |
| `DEEPSEEK_*`, `MIMO_*` | Evaluated models: keys, model ids, DeepSeek reasoning effort `max`. |
| `EVAL_ATTEMPTS`, `AGENT_TIMEOUT_SEC` | 3 attempts per model, 2 hours each. |
| `MAX_CONTAINERS` | Concurrent task containers in stage 5. |
| `TIMEOUT_POLICY` | `exclude`: a timed-out attempt is not a model failure. |
| `REQUIRE_EXISTING_TESTS` | `1`: a task must include existing repo tests of the affected code (task spec). |

Secrets stay in `.env`, which is never committed. The pipeline strips Anthropic and other credentials from the
environment it gives Harbor, so they never reach a task container.

## Outputs: where to look

| You want | Look at |
|---|---|
| Results and verdicts | [`C_RESULTS.md`](C_RESULTS.md) |
| Why a model failed a task | `data/knowledge/failure_analyses/<id>.md` and the "Failure details" section of `C_RESULTS.md` |
| An accepted task | `data/05_accepted_harbor/<id>/` (`instruction.md`, `task.toml`, `environment/`, `solution/`, `tests/`) |
| A model's attempt (patch, test results, trajectory) | `data/04_eval_runs/<id>/<model>/<job>/<trial>/` (local only) |
| Generated task drafts, validation runs | `data/03_environments/<id>/` (local only) |
| Run logs | `data/logs/<run>/` (local only) |

Run an accepted task directly with Harbor:

```bash
harbor run -p data/05_accepted_harbor/ghsa-hxh3-vqpv-xpqv -a oracle      # reference fix: must score 1.0
```

The task needs its `environment/repo/` snapshot, which is not in git. Rebuild it with the pipeline, or ask for the
zip.

## Rules and policies

- **Acceptance:** both models fail all 3 attempts. Every failure must be counted: graded, below 1.0, not a timeout, no
  harness error, the agent really worked, and no tampering.
- **Timeouts** (2-hour limit) are not failures. A task whose only non-failures are timeouts is rejected.
- **Scope** (from the task PDF):
  - real repos and real advisories only;
  - no build-from-scratch, detection-only or exploit-only tasks;
  - no dependency-bump or config-only fixes;
  - no contrived or unreachable code;
  - no LLM judge.
- **Fairness rules for tests:**
  - every hidden test passes on the reference fix;
  - tests never require numbers the report does not state;
  - variants share the reported root cause;
  - "must keep working" behaviour already works on the vulnerable code.
- **Safety:** if Anthropic's safeguards flag a generation session, the candidate is retired with no retry and no
  fallback, and generation for that run stops. Repos with a flagged candidate are not tried again.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `all predefined address pools have been fully subnetted` | Set `default-address-pools` (see Requirements) and restart Docker. Leftover containers and networks are removed after every job. |
| Docker returns 500 errors or `Docker daemon is not running` mid-run | Usually a full disk. Check `df -h` and `docker system df`, and remove old images. The affected task gets "no verdict" and is retried. |
| `adding embedded git repository: …/environment/repo` on `git add` | Expected: task repo snapshots carry their own `.git` and are excluded in `.gitignore`. Run `git rm --cached -f <path>` if one was staged. |
| A candidate's build check keeps timing out | It is retired after 2 timeouts (for example projects that compile torch or CUDA). |
| `safeguards flagged` in a stage-3 log | The candidate is retired automatically. Report it, and do not retry the same repo. |
| Python repo needs Python ≥ 3.12, or is a uv workspace | Handled: the image uses the repo's `requires-python` (3.11 to 3.13) and installs uv workspaces from `uv.lock`. |

## What is not in git

Excluded by [`.gitignore`](.gitignore):

- `.env` (secrets);
- `.venv/`, caches and `.DS_Store`;
- `.backup/` (state backups);
- `share/` (Slack bundles) and `others/` (other repos);
- `data/03_environments/`, `data/04_eval_runs/`, `data/logs/` and `data/archive/` (large, regenerable);
- the state database;
- the repo snapshots inside accepted tasks.

To continue exactly where someone else stopped, without redoing finished work, get their
`data/pipeline_state.sqlite3` and put it in `data/`.
