## Breaks BOTH models (replicate)
- **GHSA-6qxp-vccf-f47h is the only case (tentative, n=1). It is marked needs_review.** Repo: modelcontextprotocol/typescript-sdk (npm, CWE-345+522). The fix spans 8 files, 174 lines and 4 dirs.
  - pass@3 = 0, and all 6 attempts were `hole_still_open`.
  - DeepSeek scored 0.833/0.917/0.917. MiMo scored 0.5 on every attempt.
  - 5 of 6 attempts hit the 1800 s timeout (DeepSeek 2/3, MiMo 3/3). Rule out a hanging test or server before you copy this task.
- **Why it was hard (n=1):**
  - The trust/credential check is spread across several dirs.
  - There is no single sink.
  - It is an SDK, so there is no obvious single route handler.
- **Give each attack variant its own security test** (origin, credential, transport). DeepSeek failed only because it missed one variant (n=1).
- **Add real pass→pass regression tests.** 6qxp was validated with 0 of them.
- **COMBINE in one task (tentative):**
  - a multi-dir credential/trust fix
  - one entry point already patched, with a sibling entry point still open
  - a fix that has to cross a layer boundary
  - at least 5 independent security tests
  - real regression tests

## Breaks only DeepSeek (MiMo solves)
- **No cases (n=0).**
  - DeepSeek solved the cross-layer jq7h fix on its first attempt.
  - Its closest miss was 6qxp, where it was one variant short (n=1).
  - The best lever to test next is more independent attack variants per task.

## Breaks only MiMo (DeepSeek solves)
- **GHSA-jq7h-wrvp-3rgx** (pyload, CWE-613, 5 files, 4 dirs). Tentative (n=1), and only 1 MiMo attempt was recorded because evaluation stopped once DeepSeek solved it.
  - MiMo scored 0.667: security was 0 (7/7 stale-session probes returned 200) because it changed no code.
  - It found the right diagnosis but never wrote a fix.
- **Techniques that broke it:**
  - **Partly fixed vuln.** `json_blueprint` already invalidates sessions, but REST `/api/<func>` does not. Code that looks handled pulls MiMo into verifying instead of fixing.
  - **Boundary crossing.** Core `Api` has no access to Flask sessions, so the fix needs callback injection or a dispatcher hook.
  - **Deep dependency stack.** flask_session → cachelib → serializer gave it rabbit holes.
- **MiMo tends to stall (n=2 tasks, 4 attempts).** It ran out of effort on jq7h and timed out 3/3 on 6qxp with the same 0.5 each time. A large reading surface plus code that looks handled uses up its budget.
- **Recall did not predict the outcome.** MiMo named the fix location in 2/3 jq7h probes and still failed.

## Solved by both (avoid)
- **No `both_solve` rows yet (n=0).**
- **Boundary crossing alone does not stop DeepSeek** (jq7h solved in one attempt, n=1). Always layer another technique on top.

## Task-quality pitfalls (rubric / oracle failures)
- **4 rubric rejections (n=4).**
- **Tests tied to one fix layer or to internal state (n=3):**
  - 68w4 accepted only an `is_authorized`/`perm_map` fix.
  - 9q47 used a bare `flask.Flask` app with a MagicMock API.
  - jq7h checked `session_transaction()` instead of sending a request.

  Fix: send the attack through the real app factory, routes and config, and assert that it is refused. Accept a fix at any layer, including an in-method check copied from a sibling method. Run functional tests inside a real request context.
- **A test required behaviour the report never states and the real tool ignores** (x6jw, tokenless `trailer.cmd`; tentative, n=1). Map every security test to a sentence in the report and to a real exploit.
- **Oracle failures:**
  - "No reward file" (n=2): retry before discarding.
  - The reference patch failed its own functional tests (n=1): run the reference fix against the functional tests before submitting.
- **Build failures (n=2)** with pydantic-ai `pip install -e .` and MCP `npm ci`. 6qxp later built, so fix the install step instead of dropping the advisory.
- **Timeouts:**
  - If more than half the attempts time out, mark the task needs_review.
  - Put a time limit on every test and server.
- **Record the score a no-op patch gets** (0.667 on jq7h; probably 0.5 on 6qxp). That makes "did nothing" easy to tell apart from "partial fix".

## Selection hints
- **Prefer ≥4 dirs and ≥100 lines.** Both tasks that reached evaluation had this shape: 111 and 174 lines (n=2, tentative).
- **Prefer trust/credential/session CWEs** (345, 522, 613) in code with several entry points.
- **npm SDKs** gave the only both_fail so far (n=1).
- **Prefer advisories where a sibling path is already patched** (n=1).
- **Deprioritize pyload/pyload.** 4 advisories gave 3 rubric rejections and 1 DeepSeek solve. If you do pick it, build tests on the real app factory.
- **Skip tiny fixes.** The 9-line and 20-line advisories were both rubric-rejected (n=2, tentative).
- **Pre-check installs** for npm monorepos and Python editable installs (n=2).
- **Don't screen on recall probes.** Across 8 probes, DeepSeek named the location 0 times and still solved jq7h. MiMo named it 3 times and still failed.
