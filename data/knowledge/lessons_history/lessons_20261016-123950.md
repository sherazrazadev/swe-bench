## Breaks BOTH models (replicate)
- **hxh3, hono, npm, CWE-79 (accepted; tentative n=1):** 6 files / 3 dirs / 156 lines.
  - Both models stopped on their own at 0.83–0.94 in 3/3 runs.
  - Both left `render_to_string_escapes_array_root` open every run. Escaping covered the usual root but not an array root passed to render-to-string.
  - Check `stream > Should call onAbort` for flakiness. Both models "broke" it.
- **Combine in one task:**
  1. A sink reachable through ≥3 input shapes or entry points, where the obvious fix point misses one. This beat DeepSeek (n=3).
  2. One security test per shape, so closing 5 of 6 still fails.
  3. A preserved-behaviour test across a composition or ordering boundary. This beat MiMo (tentative, n=1).
  4. One path that is already correctly protected, which invites MiMo to over-verify (tentative, n=1).
  5. Fast verifier and repo suites. MiMo timeouts are not counted (6qxp).

## Breaks only DeepSeek (MiMo solves)
**Pattern (n=3: 6qxp, p4rw, hxh3).** DeepSeek patches the first layer it finds and closes every variant but one, scoring 0.92–0.94. It then declares itself done. The variant left open always bypasses the layer it patched:
- **6qxp (CWE-345/522, 8 files):** the credential binding is lost through a round-trip via the exported schemas. DeepSeek noticed this and stopped anyway. MiMo timed out 3/3, so this was too slow, not a counted pair.
- **p4rw, nltk (CWE-22/59, 10 files / 236 lines):**
  - DeepSeek put the root check in `CorpusReader.abspath`. It missed the bare-string entry points `toolbox.StandardFormat.open`, `XMLCorpusView` and `load_ace_file`, and it broke the downloader tests.
  - MiMo fixed the shared I/O layer (`FileSystemPathPointer`) and solved 1/3.
- **hxh3:** the array-root render path.

DeepSeek named the fix location in 0 of ~24 recall probes, yet solved 14 tasks. Obscurity doesn't beat it; a missed bypass path does.

## Breaks only MiMo (DeepSeek solves)
- **vp8m, undici (CWE-346, 10 files / 5 dirs; tentative n=1):**
  - MiMo closed the hole but broke reuse in `compose(cache(), dns())`. It restored the hostname only on the response side, so the lookup key and the store key diverged.
  - Its second run hung on slow suites and was not graded.
  - DeepSeek threaded a hidden real-origin field through dns, redirect and retry, and solved 1/2.
- **jq7h, pyload (CWE-613; tentative n=1):** MiMo spent its budget verifying the webui path, which was already correct. It never edited the REST entry point.
- MiMo also failed hxh3, for 3 counted failures in total.
- **MiMo is slow:** p90 step ≈400 s vs ≈40 s for DeepSeek. It timed out on 6qxp with no edits.

## Solved by both (avoid)
- **p634 (adm-zip) and j6r3 (ip-address):** the report gave the root cause, a repro and the API names, and the fix was one local check.
- **pqg4 and x33g:** both models named the fix location from the report alone.
- **DeepSeek solved on its first attempt (MiMo then skipped), n=10:** j22f, v247, 24ch, 68w4, 9q47, 77xj, 5jq2, 3wxw, hqr4 (10 files / 286 lines) and hmq2 (13 files / 232 lines).
  - This drops the old rule that "breadth beats DeepSeek". Wide fixes with a single consistent choke point were solved.

## Task-quality pitfalls (rubric / oracle failures)
- **Run every test on the vulnerable code (n=4):** security tests must fail there and functional tests must pass.
  - 8r5x: ASTs without `loc` crashed before the injection ran.
  - r4xh: a security test already passed.
  - mcm9 and vp8m: functional tests demanded new behaviour.
- **Undisclosed thresholds or required behaviour (n=3):**
  - 5jq2: a length cutoff of 64.
  - 68fv: a cap somewhere between 1M and 50M, refusal only by exception, and a hidden second root cause.
  - 2q42: had to sanitize and still emit; rejecting failed.
  - Fix: state limits in the report or use ≥100× margins, and accept both reject and sanitize.
- **Tests tied to internals (n=4):** pyload 68w4, 9q47 and jq7h, and payload qf28, which called `getSelect` directly. Test through the public or HTTP entry point.
- **Weak tests (n=4):**
  - x937 and 6qxp: weak functional tests.
  - qf28: no assertion on output content.
  - r4xh: swallowed exceptions let a forbidden size-cap fix pass.
- **Wall-clock asserts (tentative, n=1, r4xh):** use operation counts instead.
- **Oracle fails its own tests (n=7):** x6jw, p634, jggr (0.5 ×3, never fixed), 68fv, hmq2, 2q42 and hqr4.
- **Bad existing-test files (n=4):** 68fv, hqr4, r4xh and qf28 included helper, manual or DB-integration files ("no runnable test runner", "(no results)"). Exclude them.
- **Docker-compose "no verdict" (n=7):** this is infrastructure, not the task, and 5 of these tasks were validated on retry. Retry before rejecting.
- **Report names the code (n=3):** j22f, j6r3 and pqg4.
- **Classifier or safeguard blocks (n=7):** GitPython and pypdf passed on retry. Handlebars was retired.

## Selection hints
- **Prefer:**
  - Sinks reachable through several input types or entry points, where a tempting high-level choke point misses some of them (n=3; 6–10 files, 120–236 lines).
  - CWE-79, CWE-22/59 and CWE-345/522.
- **Width is not sufficient:** wide fixes have been solved (hqr4, hmq2).
- **Skip:**
  - Fixes of ≤4 files and ≤60 lines (0 usable of 11).
  - DoS and resource CWEs 400/407/674/1284 (0 usable of 8).
  - Code generators that emit another language (jhipster).
  - Heavy monorepos: payload (4 rubric/oracle failures), jhipster and pydantic-ai.
  - PyPI repos where `pip install -e .` fails or the build takes >30 min (winml-cli, sentence-transformers).
- **pyload:** keep only if the tests use the real app's test client.
- **Recall:**
  - Reject if both models name the fix location (n=2).
  - Otherwise recall does not predict difficulty. hxh3 had low recall from both and both failed; MiMo recalled vp8m yet failed; MiMo recalled p4rw and solved it.
