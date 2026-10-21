# Adversarial Research Guide (read before changing any stage)

Persistent operating principles for the CWE-Bench data factory. Every stage must be consistent with this file.
Where a stage has a documented hook (screening rules, generator prompts, validator gates), update this file
and the code together.

> Provenance: the "frontier models solve hard-looking tasks" finding and the three-condition paradigm come from
> the project brief (internal research summary), not from sources re-verified here. Treat measured pass@3
> results from Stage 5 as the ground truth and revise this guide when they contradict it.

---

## 1. Goal and acceptance contract

Produce 100-200 Harbor-format security-fix tasks. A task is **accepted** only if ALL hold:

| # | Gate | Enforced in |
|---|------|-------------|
| 1 | Task passes the quality rubric (no hints / no fix design in the report, accurate, solvable from the report, real entry point, variants share the root cause, tests implementation-agnostic, functional tests meaningful, deterministic) | Stage 4 (`rubric_check.py`, up to 2 regenerate-with-feedback rounds) |
| 2 | Oracle (historical human fix) scores exactly 1.0 in every trial | Stage 4 |
| 3 | Pre-patch: every security test FAILS, every hidden functional test PASSES, reward < 1.0 | Stage 4 |
| 4 | The repo's own tests for the affected code that pass both pre-patch and on the oracle are enforced as pass -> pass (derived set `existing_expected.txt`) | Stage 4 (Python: pytest; npm: the project's vitest/jest/mocha/node --test) |
| 5 | Tests are deterministic (oracle repeated; the existing-test set must be stable) | Stage 4 |
| 5a | **Fix checks, by execution:** a shallow fix (blocks only the reported trigger) still fails a security test; a feature-removal fix fails a functional/existing test; an alternative correct fix of a different design scores 1.0 | Stage 4 (`run_fix_checks`, patches written by stage 3) |
| 5b | **No answer key in reach:** only `repo/` enters the image, single snapshot commit, the fix's lines and the upstream regression tests are not in the tree or the report, offline container, and a scan of the BUILT image's whole filesystem finds no fix code | Stage 4 (`audit_task`, `scan_image_for_fix`) |
| 6 | pass@3 = 0 on DeepSeek V4.1 Flash AND Xiaomi MiMo-V2.6-Pro: no attempt reaches reward 1.0 (grading is partial: mean of security / functional / existing fractions, 1.0 only if all pass). A partial fix (e.g. 5 of 6 variants closed) and a fix that breaks a legitimate behaviour are both failures | Stage 5 |
| 7 | **Deterministic attribution (no AI judge):** every attempt is graded with all hidden tests reported, ended without an API/harness exception, timed out only under `TIMEOUT_POLICY=count` at the full budget (`FULL_BUDGET_SEC`), really worked (>= 3 turns), and did not touch the grading files (`/tests`, `/logs/verifier`, test-runner config, site-packages) | Stage 5 (`trial_analysis.attribute_attempt`) |
| 8 | Package passes `harbor run -a oracle` with reward 1.0 | Stage 6 |

**Gates 1, 5a and 7 are the ones that are easy to forget.** pass@3 = 0 is *also* produced by broken tests, ambiguous
reports and crashing environments. A task is only valuable if a competent engineer could solve it from the
report. Never accept on pass@3 = 0 alone: that is exactly what the rubric and fix checks (before) and the
deterministic attribution (after) are for. The LLM rubric can only reject; acceptance is decided by executed tests and
deterministic checks alone. Task-design techniques: `skills/task_design_techniques.md`.

## 2. Anti-patterns: what NOT to build

1. **Synthetic toy snippets and puzzles.** Hand-written 30-line functions, math riddles, algorithmic
   gotchas. Frontier models solve these. Only real repositories at real historical commits.
2. **Dependency-only or config-only fixes.** Version bumps in lockfiles/manifests, CI, Dockerfile, docs,
   `.gitignore`, settings flips. No localization or reasoning is required.
3. **Hints in the instruction.** No file names, paths, module names the patch touches, function/class names the patch
   changes, line numbers, "look at the X handler", or description of the fix. The Stage 3 validator rejects the
   mechanical cases (changed paths, line numbers); reviewers must catch the rest.
4. **Answer-key leakage.** The agent must not be able to read the fix:
   - `oracle_solution.patch`, `instruction.md`, `hidden_tests.py` live OUTSIDE `repo/`.
   - `repo/.git` is rebuilt as one snapshot commit (fix commit unreachable). Never use `--keep-git-history` for shipped tasks.
   - Hidden tests are uploaded by the harness only after the agent finishes (Harbor behaviour; verify per release).
   - Package CHANGELOGs/release notes in the repo that mention the fix: check during screening.
5. **Tests that encode the oracle's implementation.** Importing a helper the patch adds, asserting an exact
   error string, requiring a new parameter name. This fails valid alternative fixes and is *unfair*.
6. **Unfair specificity.** If a test demands behaviour the report never implied and a good engineer could not
   infer, the task measures guessing. Hidden variants must follow from the root cause.
7. **Trivial local fixes.** One-line guard next to the sink, found by grepping a keyword from the report.
8. **Non-deterministic or networked tests**, sleeps for races, wall-clock assertions.
9. **Giant patches.** Huge refactor-style fixes are unreliable oracles and unreadable reports. Keep fixes reviewable.
10. **Duplicate roots.** Several tasks from the same repo and same root cause (state manager de-dupes by fix commit;
    also cap tasks per repository).

## 3. The Silent Failure paradigm

We want agents to fail *silently*: produce a plausible, compiling, even test-passing patch that is wrong,
with no error to alert them. Three conditions must all hold:

1. **No Answer Key.** The agent sees only the report and the repo. Hidden tests (including variants beyond the
   report) are never visible, so it cannot iterate against them. Self-written tests only prove what the agent
   already believes.
2. **Real-World Variety.** Messy production code: layered abstractions, legacy paths, multiple entry points to one sink,
   inconsistent conventions. A model assumes a simpler data model than reality and patches the obvious path.
   Synthetic code removes the mess that makes it fail.
3. **Undisputed Truth.** The historical human fix is the objective reference. We do not argue about whether the
   hidden tests are "reasonable": each security test is something the oracle provably satisfies.

Corollary - **fairness constraint:** silent failure is *not* impossibility. Every hidden test must be (a) passed by
the oracle and (b) inferable from the report plus a careful reading of the code.

## 4. Targeted vulnerability heuristics (what to select for)

### 4.1 Inter-procedural data flow
Entry point and sink are several calls and often several files apart; validation exists on one path but not another.
- Prefer diffs touching >= 2 non-test files, or a validator added far from where the input is first received.
- The report describes the externally visible symptom only; finding the call chain is the task.
- Hidden variants: other entry points that reach the same sink; same input via a different API/format/transport.

### 4.2 Business-logic and state-tracking flaws
Race conditions, order-of-operation checks (check-then-use, authenticate-then-authorize), multi-step state machines,
cache/session invalidation, partial failure and rollback.
- Prefer fixes that add/reorder checks, introduce state, or change when something is validated.
- Hidden variants: repeated/interleaved calls, different ordering, replays, boundary state transitions.
- Races must be tested deterministically (inject ordering, mock the scheduler); never rely on timing.

### 4.3 Over-blocking traps (functional tests)
The cheap "fix" is to remove or disable the feature, reject broad input classes, or catch-all deny.
- Every task needs >= 2 `test_functional_*` that exercise legitimate use *close to the attack boundary*:
  valid inputs that look suspicious, documented options, nested-but-safe paths, unusual-but-legal encodings.
- A fix that disables the feature, returns early, or wraps everything in try/except must fail them.
- These must pass on pre-patch AND on the oracle (otherwise they are testing the wrong thing).

### 4.4 Incomplete remediation traps (security variants)
Test the reported scenario plus >= 2 variants sharing the root cause: alternate encodings/normalisation,
case/Unicode/whitespace, alternate entry points, chained or nested inputs, second code path with the same defect.
Only variants the oracle itself blocks.

## 5. CWE-Bench failure taxonomy

Classify every failed Stage 5 attempt into exactly one primary class (matches PROJECT_CONTEXT.md; Incomplete remediation and Wrong invariant are one family there but kept separate here because they need different test designs). This is how we distinguish *silent
failures* (valuable) from noise.

| Class | Definition | Typical signal | Design lever |
|-------|-----------|----------------|--------------|
| **Localization failure** | Agent edits the wrong place (symptom site, not root cause) or cannot find the faulty code | Patch touches files disjoint from the oracle's; reported scenario may even pass | Multi-file flows, no hints, several plausible sites |
| **Missed detection** | Agent inspects the vulnerable code but judges it safe, or leaves it unchanged | Patch does not touch the vulnerable path although the agent read it | Flows that look sanitized but are not (validation on only one path) |
| **Incomplete remediation** | Agent band-aids the specific trigger in the report; sibling exploit paths/variants stay open | Reported-case test passes; variant security tests fail | Variant tests across entry points/encodings/orderings |
| **Wrong invariant** | Agent enforces an incorrect rule (wrong check, wrong order, wrong scope, TOCTOU left open) | Plausible-looking validation; fails state/order tests; may pass naive cases | Business-logic and state-tracking flaws |
| **Over-correction** | Agent blocks legitimate behaviour (disables feature, broad deny, breaks existing tests) | Functional tests fail; security tests may pass | `test_functional_*` near the boundary; existing test suite |

Not model failures (exclude from pass@k, fix the pipeline instead): environment build errors, test flakiness,
OOM, API/provider errors, agent-harness crashes (any attempt with no verifier verdict is an `error`, never a
fail - Stage 5 retries the task instead), tests that the oracle fails, instructions that are unanswerable.
An agent timeout that still produced a verifier verdict follows ONE rule for every verdict and report
(`TIMEOUT_POLICY` in `.env`): `count` = a model failure only with the full budget (>= `FULL_BUDGET_SEC`), `exclude` =
never counted (the task goes to needs_review). Re-decide a recorded task with `run_pipeline.py --reverdict <id>`;
never edit the state DB by hand. If more than ~20 % of a model's failures on a task are of these kinds, the task is suspect.

Record the class per attempt in `data/04_eval_runs/summary.json`; use the distribution to steer Stage 2 selection.

## 6. Screening rules (Stage 2 hooks)

Reject if any hold:
- changed files (excluding tests) are only: lockfiles, manifests (`package.json`, `requirements*.txt`, `pyproject.toml`
  dependency tables), `*.md`, CI config, Dockerfiles, `.github/**`, generated code, vendored/minified files;
- no non-test source file changed; or > ~400 changed source lines; or binary changes in the fix;
- repo has no automated tests runnable offline, or cannot be built in Docker within the time budget;
- the pre-patch tree contains the fix (changelog, duplicate vendored copy);
- merge-commit fix, force-pushed/deleted commit, or repo unavailable.

Prefer (score up): >= 2 source files; a validation or state check added away from the entry point; touches
auth, path, parsing, deserialisation, or concurrency logic; existing tests nearby (they feed functional tests);
languages we can run offline (Python, Node).

## 7. Test-authoring rules (Stage 3/4 hooks)

- Naming is contract: `test_security_*` (fail -> pass), `test_functional_*` (pass -> pass).
- Black-box through public/entry-point APIs; define one `assert_blocked()` helper that accepts any rejection style.
- Harmless canary values only; offline; deterministic; no reliance on error message text.
- Stage 4 is the arbiter. A generated test that disagrees with the oracle is wrong; regenerate with the failure log, or drop the task.

## 8. Checklist before a task enters `05_accepted_harbor`

- [ ] Real repo, real historical fix, source change (not config/deps)
- [ ] Instruction: no paths/names/lines/fix hints; accurate and reproducible at behaviour level
- [ ] No answer key reachable from the agent's filesystem
- [ ] Oracle passes all tests; pre-patch fails all security tests, passes all functional tests; stable across reruns
- [ ] >= 2 security variants beyond the report; >= 2 over-blocking functional tests
- [ ] pass@3 = 0 on both models, and failures classified as model failures
- [ ] A human has read the instruction and one failed trajectory and agrees the failure is the model's
- [ ] Harbor oracle run scores 1.0
