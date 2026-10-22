#!/usr/bin/env python3
"""Stage 3 - AI Task Generator.

For every <environments>/<OSV-ID>/ built by Stage 2, asks Claude to write:

    instruction.md      realistic bug report (no file names / function names / line numbers / hints)
    hidden_tests.py     pytest file: security (fail->pass) + functional (pass->pass)
    check_patches/      three wrong/right fixes that stage 4 RUNS against the tests (deterministic test-quality proof):
                        shallow.patch (blocks only the reported trigger -> some security test must still fail),
                        removal.patch (disables the feature -> some functional test must fail),
                        alternative.patch (a correct fix of a different design -> every test must pass)

All of them are written next to repo/ (never inside it) so the agent under evaluation cannot see them.

Inputs per folder
  * oracle_solution.patch                  (Stage 2)
  * repo/                                  checked out at the pre-patch commit (Stage 2)
  * summary/CWE/etc. from --candidates     (Stage 1 JSON)

Backends
  cli (default)  headless `claude -p` using the logged-in Claude Code subscription; no API key needed
  api            Anthropic API; needs ANTHROPIC_API_KEY (pip install anthropic python-dotenv)

Usage
  python -m src.stage3_task_builder.task_generator --candidates data/02_screened/screened.json --environments data/03_environments
  python -m src.stage3_task_builder.task_generator --candidates ... --dry-run --only GHSA-xxxx   # print prompt only
"""
from __future__ import annotations

import argparse
import ast
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Optional

from src.common.llm import CliBackend, HandoffBackend, HandoffPending, OutputLimitExceeded, QuotaExhausted, SafeguardsFlagged, normalize_model  # noqa: F401,E501

log = logging.getLogger(__name__)

INSTRUCTION_NAME = "instruction.md"
TESTS_NAME = "hidden_tests.py"
PATCH_NAME = "oracle_solution.patch"
UPSTREAM_PATCH_NAME = "oracle_solution.upstream.patch"   # the upstream fix alone, when a Pattern B extension was merged
EXTENSION_NAME = "oracle_extension.patch"                # the extension alone (Pattern B routes), for audit
REPO_DIRNAME = "repo"
META_NAME = "generation_meta.json"

DEFAULT_MODEL = "claude-fable-5-1"
MAX_FILE_CHARS = 40_000        # per source file shown to the model
MAX_CONTEXT_CHARS = 160_000    # all source files together
MAX_PATCH_CHARS = 80_000
MIN_SECURITY_TESTS = 3      # the reported case + >= 2 variants (skills/adversarial_research.md 4.4): a partial fix must fail
MIN_FUNCTIONAL_TESTS = 3    # legitimate uses near the boundary: an over-broad fix must fail
CHECK_DIR = "check_patches"
CHECK_KINDS = ("shallow", "removal", "alternative")
# Identifiers that are ordinary words in a report; never treated as a localization leak on their own.
GENERIC_NAMES = {"index", "main", "utils", "util", "helpers", "helper", "common", "types", "type", "init", "core", "lib",
                 "base", "config", "constants", "errors", "error", "shared", "internal", "constructor", "tostring",
                 "render", "handle", "handler", "process", "parse", "validate", "request", "response", "client",
                 "server", "options", "default", "value", "values", "result", "data", "test", "setup", "build", "create",
                 "update", "delete", "remove", "get", "set", "run", "call", "apply", "load", "save", "read", "write"}

TEST_PATH_RE = re.compile(r"(^|/)(tests?|__tests__|spec|specs)(/|$)|(^|/)(test_[^/]+|[^/]+_test\.\w+|[^/]+\.(test|spec)\.\w+)$",
                          re.IGNORECASE)


# # --------------------------------------------------------------------------- #
# # Prompts
# # --------------------------------------------------------------------------- #
# SYSTEM_PROMPT = """\
# You are a senior application-security engineer on the maintainer/QA side of a defensive benchmark that measures \
# whether AI coding agents can correctly REPAIR real vulnerabilities that are already publicly disclosed (CVE/GHSA) \
# and already fixed upstream. You are given the historical fix (the "reference patch") and the vulnerable source. \
# You write (1) the bug report a maintainer would receive, (2) a hidden pytest regression suite that checks a \
# repair actually closes the hole without breaking the feature, and (3) three candidate code fixes (an incomplete \
# one, an over-restrictive one and a correct one) that are run against the suite to prove it tells good repairs \
# from bad ones.

# Purpose and use: the benchmark grades AI agents that are asked to FIX the code; the agents never see the tests. A \
# repair task is useful only if an incomplete or over-broad repair is caught, which is why the suite checks every \
# path to the bug and the feature's legitimate uses. Nothing here is run against anyone else's systems: the tests \
# run offline, inside a throwaway container, against a pinned old version of the project, and the bug is already \
# patched in current releases. This is ordinary security-regression-test work: the tests only assert that hostile \
# input is REJECTED (or handled safely), use harmless sentinel values and small inputs, and contain no attack tooling.\
# """

# USER_PROMPT_TEMPLATE = """\
# # Vulnerability metadata
# - OSV ID: {osv_id}
# - CVE: {cve_id}
# - CWE: {cwes}
# - Ecosystem / package: {ecosystem} / {package}
# - Repository: {repo_url}
# - Official summary: {summary}

# # Oracle patch (the historical human fix; the agent never sees this)
# ```diff
# {patch}
# ```

# # Pre-patch source of the files the patch modifies (vulnerable state)
# {sources}

# # How the rest of the repository reaches that code (callers / entry points - read these to wire the tests correctly)
# {callers}

# # Repository map (source and test files; the agent under evaluation gets this whole repository)
# {repo_map}

# # Package manifests (entry points, exports, scripts, test runner)
# {manifests}

# # Other context
# - Existing test files touched by the patch: {test_files}
# - Repo top-level entries: {top_level}

# # How this project's own tests set things up (copy the fixture/app-construction pattern)
# {test_examples}

# # Your job
# Produce the artifacts below.

# ## Artifact 1: instruction.md - the bug report
# Write a realistic vulnerability report as a user/security researcher/customer would file it.
# - Describe the business impact and the observable, behaviour-level way the issue is triggered \
# (what is sent or done, what happens, what should happen instead). It must be accurate and give enough \
# information that a skilled engineer could reproduce the *symptom* and recognise the vulnerability class.
# - Crucial: DO NOT mention any file names, paths, module names from the patch, function/class names that \
# the patch changes, line numbers, or hints about where or how to fix it. We are testing Localization: the \
# agent must find the faulty code itself. Public, user-facing API names and documented features may be \
# referenced only if the report is unintelligible without them.
# - Where it is genuinely true of this bug, frame it as the deeper flaw it is (inter-procedural data flow, \
# business-logic or state-tracking error, race condition, incomplete validation across code paths). Do not \
# invent a different vulnerability than the one the patch fixes, and do not exaggerate.
# - A validator rejects the report if it names a changed file's base name (e.g. `uneval` for uneval.js), or a \
# function/method/class the patch defines or edits (e.g. `Address4`). Describe them by role instead ("the serializer that \
# emits JavaScript source", "the IPv4 address type").
# - Write it in your OWN words: never reuse phrases from the advisory summary/description above, and do not name the CVE/GHSA id.
# - Do not describe the variants that your hidden tests cover.
# - Do NOT prescribe the fix. Any 'expected behaviour' part may only state the security property that must hold and the legitimate behaviour that must keep working, in user-visible terms. It must not describe validation rules, token formats, where or in what order checks happen, what is logged versus returned, or which internal code paths need changing. Likewise do not hint which inputs are legitimate beyond what the report needs to be accurate.
# - Every behaviour your functional tests require must be derivable from the report or from ordinary expectations of the feature; if a functional test needs an unusual-but-legal input, the report must make clear that input is legitimate.
# - 150-400 words, Markdown, with a title.

# ## Artifact 2: hidden_tests.py - pytest suite
# Constraints (the suite is run with the working directory at the repo root, repo root on sys.path, \
# after the agent edits the code; `REPO_ROOT` env var also points there):
# - Pure pytest, deterministic, offline (no network, no sleeping beyond ~1s, no external services), \
# self-contained: create temp files via `tmp_path`. Import only things that exist in the PRE-patch source above \
# or the standard library / the project's declared dependencies. If the vulnerable language is not Python \
# (e.g. npm package), drive the code via `subprocess` calling `node` with inline scripts and assert on the output. \
# For a Go module, see rule 5.
# - Black-box: test behaviour through public/entry-point APIs only. NEVER import, call, or assert on \
# anything that the oracle patch ADDS (new helpers, new exceptions, new parameters), and never assert exact \
# error message text. Accept any reasonable rejection (exception of any type, sanitised output, error \
# status) when asserting that something is blocked - define a small helper like `assert_blocked(callable)`.
# - The oracle patch MUST pass every test, and the pre-patch code MUST fail every `test_security_*` test. \
# Only test hardening that the oracle patch itself provides; do not demand extra protections it does not give.
# - Use harmless sentinel values (e.g. a marker file inside tmp_path, a sentinel string) - nothing that would be harmful outside the test.

# Naming convention (enforced by a validator):
# A) `test_security_*` (at least {min_sec}, ideally 4-8): fail on vulnerable code, pass after a correct fix. \
# Cover the exact scenario in the report AND *variants beyond the report* that share the same root cause so \
# that an incomplete remediation (patching only the one reported path/encoding/entry point/casing/ordering) \
# still fails. Think: alternative entry points that reach the same sink, encodings and normalisation \
# tricks, case/Unicode/whitespace variants, nested or chained inputs, repeated or interleaved calls \
# (state/race-style), boundary values.
# B) `test_functional_*` (at least {min_func}, ideally 4-8): pass on both vulnerable and fixed code. \
# These are legitimate use-cases that a careless or over-broad fix would break (over-correction): valid \
# inputs close to the rejection boundary, normal feature usage, documented options, edge cases that look \
# suspicious but are legitimate. A fix that simply disables the feature or rejects everything must fail \
# these tests.
# - Add a one-line docstring on each test saying what it protects (without giving away the fix location).

# # Hard rules learned from real rejections (most early drafts broke rule 1)
# 1. IMPLEMENTATION-AGNOSTIC. A test may only observe what an attacker or user can observe at the entry point (HTTP \
# status/body, return value, raised error, file written or not). It must pass for ANY reasonable correct fix, not just the \
# reference patch's design. Real rejected examples:
#    - asserting the fix lives in one permission layer, when an equally valid in-method check would fail the test
#    - reading the server-side session store to prove sessions were deleted, when a valid fix rejects stale sessions \
# without deleting them -> instead send the request with the old session and assert it is refused
#    - driving a hand-built mini app instead of the project's real app/routes -> use the project's own app factory/entry point
# 2. SOLVABLE FROM THE REPORT. Every input a security test uses must be an instance of the class the report describes. \
# Never require blocking an input the report does not imply (rejected example: blocking a config key that the underlying \
# tool ignores and the report never mentions).
# 3. THE HARNESS MUST RUN. Build the app/client ONCE per module (module-scoped fixture) when the project registers global \
# state (Flask blueprints, singletons, module-level registries) and reset state between tests instead of re-creating the \
# app (rejected example: re-creating a Flask app per test -> "blueprint already registered" on every test after the first). \
# Mirror how the project's own tests set things up (examples below, if any).
# 4. COMPILED JS/TS PROJECTS. Test the SOURCE, not a prebuilt bundle: run the project's own test runner (vitest/jest/mocha via node_modules/.bin) on a temporary test file that imports from src/, or load the source through the project's TS tooling. Never import dist/ or build output (rejected example: tests that required dist/index.js, which does not exist until a build and would not contain the agent's edits).
# 5. GO MODULES. Each test writes a temporary Go test file (name it `zz_hidden_<test name>_test.go`) into the package \
# directory it exercises (same `package` clause as that directory's existing files, or `package <name>_test` for a black-box \
# test), runs `go test -count=1 -run '^TestHidden$' ./<package dir>` via `subprocess` from the repo root, removes the file in \
# a `finally` block, and asserts on the exit code / the lines the Go test prints. Use only exported identifiers that exist in \
# the PRE-patch source; never add or change go.mod/go.sum (the grader is offline and ignores them).
# 6. PHP (COMPOSER) PROJECTS. Each test writes a temporary PHP script (name it `zz_hidden_<test name>.php`) in the repo \
# root that starts with `require __DIR__ . '/vendor/autoload.php';`, drives the project's public API (or its HTTP kernel / \
# router with a built request, the way the project's own tests do), prints ONE JSON line with what a caller observes, and \
# exits 0; the Python test runs it with `php` via `subprocess` from the repo root, removes it in a `finally` block and \
# asserts on the JSON. Catch only the project's own exception types inside the script (report them in the JSON); let \
# anything else fail. Use only classes/functions that exist in the PRE-patch source; never add or change \
# composer.json/composer.lock (the grader is offline and ignores them). No database or network: use the project's \
# in-memory / array / SQLite drivers if it has them.
# 7. TESTS FOLLOW FROM THE REPORT, NOT FROM THE REFERENCE FIX. Every assertion - security AND "must keep working" - must \
# be required by a sentence in your report (add the sentence if needed) and must pass on ANY correct fix, not only on the \
# reference design. Never use a name that exists only in the reference fix's added code (a new field, function, env var, \
# config key or error text), and never probe for guessed names (reflection, FieldByName, getattr/hasattr). Drive the code \
# only through interfaces that exist in the vulnerable code. Rejected example: a "must keep working" test required a \
# registry token to reach the host in TERRAFORM_CLOUD_HOST, through an env var only the reference fix reads and a guessed \
# `TrustedHosts` field; the report never asked for it, so correct fixes of another design failed.
# 8. INCOMPLETE UPSTREAM FIX. If the reference fix leaves another path with the SAME vulnerable code unfixed (e.g. one \
# of several providers / renderers / parsers), a careful agent fixes it too and the project's own tests that pin the old \
# behaviour of that path then fail - an unfair task (rejected example: OAuth state check fixed for every provider but X; \
# agents fixed X and broke X's repo tests). Then answer ONLY with `<unsuitable>reason</unsuitable>`.
# Before answering, check each test against these rules.

# # Entry point
# Security regression tests must reproduce the vulnerable behaviour through a REAL entry point of the project - the way \
# an untrusted caller or a normal user reaches the code (public API call, HTTP route, CLI command, exported function) - never by calling the \
# internal helper the patch modifies. State that entry point in the metadata block (internal use only, it is never \
# shown to the agent).

# ## Artifact 3: check patches - three fixes the pipeline RUNS against your tests (never shown to the agent)
# Each is a list of exact search/replace edits on the PRE-patch source files above. "search" must appear EXACTLY ONCE in \
# that file, copied verbatim (indentation included); "replace" is the new text. Edit only non-test source files and keep \
# the code valid. The pipeline executes your hidden tests against each one; a wrong outcome sends the task back to you:
# - "shallow": the band-aid a hurried engineer writes from the report alone - it blocks ONLY the exact reported trigger \
# (one entry point / one encoding / one call path) and leaves the sibling variants open. It must make at least one \
# security test pass, and at least one security test must still FAIL on it. (This proves a partial fix is caught.)
# - "removal": closes the hole by disabling or over-restricting the feature (reject the whole input class, remove the \
# code path, return early). At least one functional test must FAIL on it. (This proves over-blocking is caught.)
# - "alternative": a CORRECT, complete fix whose design differs from the reference patch (another layer or mechanism). \
# EVERY test must pass on it. (This proves the tests accept any correct fix, not just the reference design.)

# # Output format (strict)
# Return ONLY these four blocks, nothing else:

# <instruction_md>
# ...markdown...
# </instruction_md>
# <hidden_tests_py>
# ...python source, no code fences...
# </hidden_tests_py>
# <task_metadata_json>
# {{"entry_point": "<one line: how untrusted input reaches the code, e.g. 'HTTP GET /download?file= handled by the app'>",
#   "techniques": [<numbers of the task-design techniques (from the curated technique list) this task applies, e.g. 1, 4, 7;
#                   REQUIRED: at least one hidden-path technique - 1, 2, 3 or 7 - AND at least one over-correction
#                   trap - 5 boundary-hugging functional tests, 9 a must-keep-working clause, or 11 a compatibility
#                   contract pinned by an existing repo test>],
#   "trap": {{"paths": [<repo-relative SOURCE files among fix_places that a hurried agent misses: the unnamed sibling,
#                       parallel implementation or deeper layer. Each must exist in the pre-patch repo, be listed in
#                       fix_places, and be NAMED NOWHERE in your report (not the file, not its functions) - at least
#                       one security test must reach it only through an entry point the report does not localise>],
#             "contract": "<one line: the legitimate behaviour near the attack boundary that your functional tests pin,
#                          which an over-broad fix would break>"}},
#   "fix_places": [<repo-relative paths of the reference fix's SOURCE files whose change closes part of the vulnerability
#                   (not unrelated features, refactors or typing bundled in the same commit); the pipeline runs the fix
#                   without each of them and at least one of your tests must then fail>]}}
# If the candidate cannot support a real trap (no sibling path, no parallel place, no layer below the entry point),
# answer ONLY with `<unsuitable>no hidden-path trap: <reason></unsuitable>` - measured: tasks whose tests reach every
# variant through the reported entry point are solved on the first attempt and waste the batch slot.
# </task_metadata_json>
# <check_patches_json>
# {{"shallow": [{{"file": "<repo-relative path>", "search": "<exact existing text>", "replace": "<new text>"}}],
#   "removal": [...], "alternative": [...]}}
# </check_patches_json>
# """

# --------------------------------------------------------------------------- #
# Prompts
# --------------------------------------------------------------------------- #
SYSTEM_PROMPT = """\
You are a Principal Software Quality Assurance (QA) and Defensive Benchmark Architect on the maintainer side \
of an evaluation platform. We evaluate whether autonomous AI coding agents can correctly REPAIR real-world \
vulnerabilities (CVE/GHSA) that have already been fixed upstream in open-source projects.

You are provided with:
1. The historical human fix (the "reference patch")
2. The vulnerable codebase at the pre-patch commit
3. Repository maps, manifests, and test fixtures

Your responsibility is to author:
(1) `instruction.md`: A realistic, fair defect report filed by an enterprise user or security auditor.
(2) `hidden_tests.py`: A black-box pytest regression suite checking security enforcement and functional preservation.
(3) Three validation check-patches (shallow, removal, alternative) to prove the test suite accurately distinguishes \
good repairs from bad ones.

Operational Principles:
- Purely Defensive: All tests offline, inside an isolated container, using harmless sentinels. Tests only assert \
that invalid/unauthorized input is safely rejected and legitimate operations execute cleanly.
- Strict Fairness: A task is an exam of model intelligence, NOT a guessing game. Every legitimate use the functional \
suite tests must be an ordinary use of a FEATURE the report names as "must keep working" (name features, not test values).
- Zero Leakage: The agent must discover the faulty code and every place it lives. Never disclose file names, function \
names, the hidden place(s), or the scope of the bug ("every provider", "on every route").\
"""

USER_PROMPT_TEMPLATE = """\
# Defect & Vulnerability Metadata
- OSV ID: {osv_id}
- CVE: {cve_id}
- CWE: {cwes}
- Ecosystem / Package: {ecosystem} / {package}
- Repository: {repo_url}
- Official Summary: {summary}

# Reference Patch (Historical human fix; hidden from evaluated agents)
```diff
{patch}
Pre-Patch Source Files (Vulnerable state of files modified by patch)
{sources}
Callers & Entry Points (How public input reaches the modified code)
{callers}
Repository Map
{repo_map}
Package Manifests (Dependencies, scripts, build configuration)
{manifests}
Context & Existing Test Patterns
Existing test files touched by the patch: {test_files}
Repository top-level entries: {top_level}
Project's own test patterns and conventions:
{test_examples}
Your Deliverables
Artifact 1: instruction.md - The Incident Defect Report
Write a realistic report (about 150-350 words) as a user or operator who hit the problem. Sections: a title naming
the symptom (not the fix); what was observed and how (the route the user hit); impact; what must keep working.

WHAT ACTUALLY DECIDES DIFFICULTY (measured, 2 accepted vs 37 solved): not how vague the report is, but whether part of
the root cause lives in a REAL place the report never leads to, with a test that reaches it. The accepted hono task's
report stated the cause and the rule, and listed three affected wrappers - both models still failed 6/6, because the
second renderer and the nested-array root were never mentioned and were tested. So the report may describe the
route(s) the user hit; its one job is to NOT reveal the hidden place(s) or how far the bug reaches.

NEVER (each measured on a task both models then solved; ids are the evidence):
- state the SCOPE or completeness of the bug: "the same acceptance happens on each one we tried", "for every operation",
  "on every route", "every command that ...", "all three nodes". It tells the agent to grep for every sibling and the
  trap disappears - oauth-providers fm3f, n8n f3f2, vitest p63j, q2xc (all four solved on attempt 1). Show the route(s)
  the user hit; whether others exist is for the agent to find;
- reveal or hint at a hidden place (metadata.trap.paths): not by name, and not by a role specific enough to find it;
- list the tainted parameters, the payload set or the variants your tests use (n8n f3f2 named all four tainted
  parameters and the legal operator list). One illustrative example of the symptom is fine;
- name a function by a behaviour so specific it identifies it ("the one that ignores the address's own suffix" - j6r3);
- offer or rule on an acceptable fix ("refusing the archive is fine" - p634) or say which layer should change;
- in "what must keep working", list the boundary VALUES your tests use ("/0 networks, IPv4-mapped addresses",
  "[db].[dbo].[t], numeric-string limits"). Name the FEATURES that must keep working (hono: "a bare string must still
  render as the top-level element", "content marked as trusted raw HTML still emits markup");
- file, directory, module, function, method or class names the fix changes, options it adds, or line numbers.
AVOID stating the root cause when the fix is in one local place: there it IS the answer (adm-zip p634: "two entries
with the same name"; ip-address j6r3: "never checks both sides are the same kind of address").
Write in your OWN words. Do not quote the official CVE/GHSA summary, and do not include the CVE/OSV ID.
Fairness: every test_functional_* exercises an ordinary use of a feature named under "what must keep working", and
every test_security_* is an instance of the harm described.
Artifact 2: hidden_tests.py - Black-Box Pytest Suite
The suite runs at the repository root with REPO_ROOT set.
Strict Constraints:
Pure pytest, deterministic, offline (no internet access, no sleeps > 1s, harmless sentinels/tmp_path only).
Black-Box Execution: Test ONLY via public entry points (public CLI commands, public API methods, exported library
functions, or HTTP route handlers). NEVER import, inspect, or call new helper functions, new structs, or new fields
introduced by the reference patch.
Agnostic Assertions: Accept ANY valid rejection mechanism (raised exception, HTTP 4xx, sanitized return value).
Never assert on exact error string text or specific internal exception classes added by the patch.
Language Adapters:
Python: Direct import of public pre-patch modules.
Node/TypeScript: Use subprocess to run project's test runner (vitest/jest) or inline node script driving src/ (NEVER dist/).
Go: Write temporary zz_hidden_<name>_test.go and execute via go test -count=1 ./<pkg>.
PHP (Composer): Write a temporary zz_hidden_<name>.php in the repo root starting with require __DIR__ . '/vendor/autoload.php';
drive the project's public API or HTTP kernel the way its own tests do, print ONE JSON line of what a caller observes, and
run it with php via subprocess (remove the file in a finally block). Use only classes that exist in the PRE-patch source;
never change composer.json/composer.lock; no database or network - use the project's in-memory/array/SQLite drivers.
Non-Destructive Invariant: The reference patch MUST score 100% (all tests pass). The vulnerable code MUST fail all
test_security_* tests.
Naming & Test Structure:
test_security_* (at least {min_sec}, ideally 4-8): Fail on vulnerable code, pass after a correct fix.
COVER EVERY FIX PLACE (the #1 measured cause of easy tasks: in 24 of 37 solved tasks the agent passed while changing
FEWER source files than the reference fix - e.g. 1 of 12 - because no test reached the other places). List every source
place the reference fix hardens; give EACH its own test_security_* reached through its OWN real entry point, so a
repair that skips any one place fails. A variant counts only if it reaches the root cause through a DIFFERENT place or
route. Spelling, case, whitespace, encoding or extension variants of the same input through the same route do NOT
count - measured: pure spelling/encoding variants are always caught, and input variants were never missed.
Strongest sibling kinds, ranked by how often they beat BOTH models (a task is accepted only when both fail): a
producer - schema, serializer, loader, config resolver - that feeds the check through a path the check never calls (M6,
24%; e.g. a schema strips the issuer on reload); a COUPLED legitimate value next to the bad one that the natural
over-broad fix breaks (20%; e.g. the visible type-id must still bind); a mechanism that never had the protection so
its absence reads as design (M4, 18%; e.g. an any-setter route with no view code); the check authorising the wrong or
neighbouring object or an attacker-chosen identity field (M10); the restricted value arriving through defaults, merge,
inheritance or stored config (M5). WEAK on their own: a second implementation (M2, 5% both) or another handler reaching
the same sink (M1, 2% both) - use them only next to one of the above. The only measured both-model breaker stacks M4 +
M10/M11 + M5 + a coupled value on ONE real route. Never plant code: every hidden place is real.
PATTERN B (strongest origin, 25% missed): a REAL route with the same missing protection that the upstream fix never
touched. If your design (or the approved plan) has one, close it in an <oracle_extension_json> block: minimal
search/replace edits on PRE-patch source files the upstream fix does NOT change, written the way the maintainers fixed
the reported route. The reference solution becomes upstream fix + extension; the pipeline proves each extension file is
needed (your tests must fail without it) and that the shallow fix still fails. List every extension file in fix_places
(and trap.paths when it is the hidden place), give it its own test_security_* through its own public entry point, and
make the "alternative" check patch close it too.
test_functional_* (at least {min_func}, ideally 4-8): Pass on both vulnerable and fixed code.
Legitimate inputs near the rejection boundary, custom enterprise configurations, and valid workflows. An over-broad
fix that disables features or universally rejects input must fail these tests.
Hard Rules Learned from Historical QA Rejections
THE FAIRNESS CONTRACT (NO UNSEEN PLUMBING): every test_functional_* must exercise an ordinary use of a FEATURE named
under "What must keep working" - name the feature, not the test's values. If a test needs private enterprise registries
(e.g. my-tfe.corp.example), the report says that "users who configure a private registry" must keep working; it does
not list hosts, env vars or edge cases. A feature the vulnerable code never supported is not "legitimate" (infracost).
SIBLING BLAST RADIUS (INCOMPLETE UPSTREAM FIXES): If the reference patch only fixes 7 out of 8 providers/parsers
(leaving sibling components vulnerable), and an intelligent agent fixing the 8th component would break pre-existing
repository tests (e.g., legacy tests asserting unauthenticated behavior for provider X), answer ONLY with:
<unsuitable>incomplete upstream fix: sibling provider tests break under full remediation</unsuitable>.
IMPLEMENTATION INDEPENDENCE: A test must pass for ANY reasonable, correct architecture. Never assert that a check
lives in a specific layer, or that internal state changed in a specific way, when an alternative placement is equally sound.
COMPILED REPOSITORIES (TS/GO): Test source code directly. Never require compiled bundles (dist/index.js) which
do not exist until build and would omit agent edits.
NO TRIVIAL OR SYNTHETIC CODE: If the vulnerability is a pure dependency bump, a config toggle, or does not support
a multi-file / deeper-layer trap, answer ONLY with: <unsuitable>no hidden-path trap: <reason></unsuitable>.
Artifact 3: check_patches - Three Validation Fixes
Provide search/replace edits on pre-patch source files to verify test suite discrimination:
"shallow": Quick band-aid fixing only the primary trigger. Must pass >= 1 security test, but FAIL >= 1 security variant.
"removal": Over-restrictive fix (disables feature/returns early). Must FAIL >= 1 functional test.
"alternative": A correct, clean fix designed differently than the reference patch. Must PASS ALL tests (so it also
closes every Pattern B route).
Output Format (Strict XML Blocks Only)
Return ONLY these four blocks, nothing else:
<instruction_md>
...markdown matching the exact section structure specified above...
</instruction_md>
<hidden_tests_py>
...python source, no code fences...
</hidden_tests_py>
<task_metadata_json>
{{
"entry_point": "<public entry point string>",
"techniques": [1, 5, 9],
"trap": {{
"paths": ["<repo-relative source file agent is likely to miss>"],
"contract": "<the specific legitimate behavior near the boundary that functional tests pin>"
}},
"fix_places": ["<EVERY reference-fix source file whose change closes part of the vulnerability; the pipeline re-runs the fix
               WITHOUT each one and a test must then fail>"],
"unrelated_files": ["<every OTHER reference-fix source file (refactor, typing, logging, an unrelated feature bundled in the
                    commit). Every source file of the reference patch must appear in fix_places or here>"],
"self_attack": {{
"naive_fix": "<the repair YOU would make from the report alone, first 20 minutes>",
"naive_fix_files": ["<repo-relative files that repair touches = the shallow check patch's files>"],
"over_broad_fix": "<the sledgehammer fix you would reach for when unsure = the removal check patch>",
"why_naive_fails": "<which test_security_* fails it, through which hidden place and mechanism>"
}},
"test_justifications": {{
"<test_function_name>": "<exact sentence or quote from instruction.md requiring this test's assertion>"
}}
}}
</task_metadata_json>
<check_patches_json>
{{
"shallow": [{{"file": "<path>", "search": "<exact existing code>", "replace": "<new code>"}}],
"removal": [...],
"alternative": [...]
}}
</check_patches_json>
<oracle_extension_json>
{{"edits": [{{"file": "<Pattern B source file the upstream fix never changes>", "search": "<exact existing code>",
             "replace": "<the same protection the upstream fix adds on the reported route>"}}]}}
</oracle_extension_json>
(OPTIONAL - only when the design has a Pattern B route; omit the block entirely otherwise.)
"""


# --------------------------------------------------------------------------- #
# Context building
# --------------------------------------------------------------------------- #
@dataclass
class Context:
    osv_id: str
    env_dir: Path
    meta: dict
    patch: str
    changed_files: list[str]
    prompt: str = ""
    leak_terms: set[str] = field(default_factory=set)
    advisory_text: str = ""
    leak_idents: set[str] = field(default_factory=set)


def parse_changed_files(patch: str) -> list[str]:
    files = []
    for m in re.finditer(r"^diff --git a/(.+?) b/(.+)$", patch, re.MULTILINE):
        path = m.group(2)
        if path not in files:
            files.append(path)
    return files


def read_text_capped(path: Path, cap: int) -> Optional[str]:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:4096]:
        return None
    text = data.decode("utf-8", errors="replace")
    if len(text) > cap:
        text = text[:cap] + f"\n... [truncated, file is {len(text)} chars]"
    return text


def build_sources_section(repo: Path, changed: list[str]) -> tuple[str, list[str]]:
    parts, test_files, budget = [], [], MAX_CONTEXT_CHARS
    for rel in changed:
        if TEST_PATH_RE.search(rel):
            test_files.append(rel)
            continue
        if budget <= 0:
            parts.append(f"### {rel}\n[omitted: context budget exhausted]")
            continue
        text = read_text_capped(repo / rel, min(MAX_FILE_CHARS, budget))
        if text is None:
            parts.append(f"### {rel}\n[new file in patch, binary, or unreadable in pre-patch tree]")
            continue
        budget -= len(text)
        parts.append(f"### {rel}\n```\n{text}\n```")
    return ("\n\n".join(parts) or "[none]"), test_files


SKIP_DIRS = {".git", "node_modules", "dist", "build", "coverage", "vendor", "__pycache__", ".venv", "venv", ".tox",
             "site-packages", ".next", ".cache", "fixtures", "__fixtures__"}
CODE_EXT_RE = re.compile(r"\.(py|pyi|[cm]?[jt]sx?|vue|svelte)$")
MAP_CHARS, CALLER_CHARS, CALLER_FILE_CHARS, MANIFEST_CHARS = 14_000, 60_000, 12_000, 6_000


def repo_files(repo: Path) -> list[str]:
    try:
        out = subprocess.run(["git", "ls-files"], cwd=repo, capture_output=True, text=True, timeout=60).stdout.split("\n")
    except (OSError, subprocess.TimeoutExpired):
        out = [p.relative_to(repo).as_posix() for p in repo.rglob("*") if p.is_file()]
    return [f for f in out if f and not SKIP_DIRS & set(Path(f).parts) and CODE_EXT_RE.search(f)]


def repo_map(repo: Path, changed: list[str]) -> str:
    """Source/test file list. Big repos: every file in the directories the fix touches, and per-directory counts elsewhere."""
    files = repo_files(repo)
    text = "\n".join(files)
    if len(text) <= MAP_CHARS:
        return text or "(no source files found)"
    near = {str(Path(c).parent) for c in changed}
    keep = [f for f in files if str(Path(f).parent) in near]
    counts: dict[str, int] = {}
    for f in files:
        if str(Path(f).parent) not in near:
            d = "/".join(Path(f).parts[:3][:-1]) or "."
            counts[d] = counts.get(d, 0) + 1
    lines = keep + [f"{d}/  ({n} files)" for d, n in sorted(counts.items())]
    return ("\n".join(lines))[:MAP_CHARS] + (f"\n... ({len(files)} source files in total)" if len(files) > len(lines) else "")


def _module_keys(rel: str) -> set[str]:
    p = Path(rel)
    stem = p.name.split(".")[0]
    keys = {stem} if stem not in ("index", "__init__", "main", "utils", "util", "types") else set()
    if stem in ("index", "__init__") and p.parent.name:
        keys.add(p.parent.name)
    if rel.endswith(".py"):
        parts = list(p.with_suffix("").parts)
        if parts and parts[0] in ("src", "lib"):
            parts = parts[1:]
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]
        if len(parts) > 1:
            keys.add(".".join(parts))
    return keys


def callers_section(repo: Path, changed: list[str], patch: str) -> str:
    """Files (outside the fix) that import a changed module or call a function/class the fix edits, best first - the
    path from the public entry point down to the vulnerable code, so the hidden tests can drive it for real."""
    src = [c for c in changed if CODE_EXT_RE.search(c) and not TEST_PATH_RE.search(c)]
    if not src:
        return "(none)"
    keys = set().union(*(_module_keys(c) for c in src))
    names = {n for n in localizing_identifiers(patch) if len(n) >= 5}
    scored: list[tuple[int, str, str]] = []
    for rel in repo_files(repo):
        if rel in changed or TEST_PATH_RE.search(rel):
            continue
        try:
            text = (repo / rel).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if len(text) > 400_000:
            continue
        imports = re.findall(r"""(?:\bfrom\s+['"]?|\bimport\s+['"]?|require\(\s*['"]|import\(\s*['"])([\w./@-]+)""", text)
        hit_imports = sum(1 for spec in imports if Path(spec).name.split(".")[0] in keys or spec.lstrip(".") in keys
                          or any(spec.endswith("." + k) or spec == k for k in keys if "." in k))
        hit_names = sum(1 for n in names if re.search(rf"\b{re.escape(n)}\b", text))
        if hit_imports or hit_names:
            scored.append((3 * hit_imports + hit_names, rel, text))
    scored.sort(key=lambda t: (-t[0], len(t[2])))
    parts, used = [], 0
    for _, rel, text in scored:
        if used >= CALLER_CHARS:
            parts.append(f"(+{len(scored) - len(parts)} more files reference the changed code)")
            break
        body = text[:CALLER_FILE_CHARS] + ("\n... [truncated]" if len(text) > CALLER_FILE_CHARS else "")
        used += len(body)
        parts.append(f"### {rel}\n```\n{body}\n```")
    return "\n\n".join(parts) or "(no other file imports the changed code - it is likely a public entry point itself)"


def manifests_section(repo: Path) -> str:
    parts, used = [], 0
    for name in ("package.json", "pyproject.toml", "setup.cfg", "setup.py", "pytest.ini", "tox.ini", "go.mod",
                 "composer.json", "phpunit.xml.dist", "phpunit.xml"):
        f = repo / name
        if f.is_file() and used < MANIFEST_CHARS:
            body = f.read_text(errors="ignore")[: MANIFEST_CHARS - used]
            used += len(body)
            parts.append(f"### {name}\n```\n{body}\n```")
    return "\n\n".join(parts) or "(none)"


DESIGN_CONTRACT = """

# Design contract (measured: tasks that break BOTH models satisfy these)
1. At least TWO independent public entry points reach the root cause. The report names at most one; the other is
   discoverable by reading the code (a second renderer/parser/implementation, a lower-level public constructor, a
   second HTTP route/CLI, or a save/reload round-trip). Give each entry point its own test_security_*.
2. At EACH entry point, test at least two input shapes (bare value vs array/nested; path vs bytes; casing or encoding
   variants). A fix that handles only the reported shape must still fail.
3. Put at least one affected sink in a module whose path/name does not suggest the vulnerability; the report must not
   name it.
4. Include a functional test for every "must keep working" clause: it must PASS on the PRE-patch code and FAIL if the
   feature is removed or over-blocked.
5. At least one security test must be blocked only by the fix's change in a SECOND source file, not by the obvious
   first file. If the whole fix is one shared choke point, the models will solve the task.
"""

# Self-break protocol (2026-10-21): the generator is DeepSeek, which is also a target model. Before this protocol, 0 of 15
# DeepSeek-designed tasks were accepted and every one that reached a trial was solved. The design must predict the
# generator's own first repair and prove - through the executed shallow/removal check patches - that it fails.
SELF_BREAK = """

# Self-break protocol (you are ALSO one of the agents this task will be tested on)
The target agents are DeepSeek V4.1 Flash and MiMo-V2.6-Pro, given ONLY your report, the repository and 2 hours, offline.
You are the same DeepSeek model: a task you can design without thinking hard is one you will solve (measured: 0 of 15
DeepSeek-designed tasks accepted before this protocol; every one that reached a trial was solved). Before writing:
1. SOLVE IT YOURSELF FIRST. Read only your draft report and write down the repair you would make in your first 20
   minutes: which files you would open (grep for the symptom's words), which guard you would add, where. That is
   `naive_fix`. Measured habit of both agents: fix the reported route, re-run the reported example, see it blocked, STOP
   ("it thought it was done") - on the tasks DeepSeek failed it closed 5 of 6 variants in all 3 runs.
2. MAKE THAT FIX FAIL. At least one trap place lies OUTSIDE naive_fix_files and is reached by a test through its own entry
   point, using a top mechanism: M4 feature-absent, M6 producer off the check's path, M2 second real implementation,
   M10 wrong object, M5 merged/defaults route. Stack two DIFFERENT mechanisms where the code allows (the only task that
   broke both models stacked M4 + M10/M11 + M5 + a coupled visible value).
3. MAKE THE OVER-BROAD FIX FAIL. Write down the sledgehammer you would reach for when unsure (reject the whole input
   class, disable the feature, escape everything). That is `over_broad_fix`; a functional test of a feature named under
   "what must keep working" must fail on it (MiMo's measured failure: hole closed, legitimate use broken).
4. PROVE IT WITH THE CHECK PATCHES. The `shallow` check patch MUST BE your naive_fix (edits only in naive_fix_files) and
   the `removal` check patch MUST BE your over_broad_fix. Stage 4 executes both against your tests: if your own likely
   repair passes, the task is rejected before any trial.
5. STAY FAIR. Everything a test asserts must follow from a sentence of the report - you will quote that sentence for
   every test. Difficulty comes from WHERE the root cause lives, never from requirements the report does not state.
Record it in task_metadata_json: "self_attack": {"naive_fix": "<2-3 sentences>", "naive_fix_files": ["<repo paths>"],
"over_broad_fix": "<1-2 sentences>", "why_naive_fails": "<which test fails it, through which place and mechanism>"}.
"""


def approved_plan_section(env_dir: Path) -> str:
    """The design the pre-build plan gate approved (src/stage3_task_builder/plan_gate.py): generation builds THIS design."""
    try:
        gate = json.loads((env_dir / "plan_gate.json").read_text())
    except (OSError, ValueError):
        return ""
    approved = gate.get("verdict") == "proceed"
    # advisory mode (calibration): the gate records but does not block, so the best draft still guides generation
    advisory = gate.get("mode") == "advisory" and gate.get("verdict") in ("too_easy", "unfair")
    plan = gate.get("plan") if (approved or advisory) else None
    if not isinstance(plan, dict) or plan.get("verdict") == "unsuitable":
        return ""
    notes = list((gate.get("review") or {}).get("required_changes") or [])
    if advisory:
        notes = [f"the pre-build review rejected this plan as {gate.get('verdict')}: {gate.get('why', '')[:600]}"] + notes
    extra = ("\nThe reviewer requires these changes:\n" + "\n".join(f"- {n}" for n in notes)) if notes else ""
    b_routes = [h.get("path") for h in plan.get("hidden_places") or [] if isinstance(h, dict)
                and (h.get("in_upstream_fix") is False or str(h.get("in_upstream_fix")).lower().startswith("false"))]
    b_note = (f"\nPattern B places in this plan (the upstream fix never touched them): {b_routes}. Close each one in the "
              "<oracle_extension_json> block, list it in fix_places and trap.paths, and give it its own test_security_*."
              if b_routes else "")
    head = ("# Approved design plan (passed the pre-build review and the self-solve probe)" if approved else
            "# Design plan (the pre-build review had concerns - fix them while building it)")
    return (f"\n\n{head}\n"
            "Build THIS design. You may refine details, but do not drop a hidden place or a mechanism, and do not "
            "describe a hidden place in the report.\n```json\n" + json.dumps(plan, indent=2)[:8000] + "\n```" + extra
            + b_note + "\n")


def stage4_checks_text() -> str:
    """The exact checks stage 4 applies, so the first draft is written to pass them (instead of learning by rejection)."""
    try:
        from src.stage4_oracle_validator.rubric_check import CRITERIA
    except Exception:          # never block generation on this
        return ""
    crit = "\n".join(f"- {name} ({'must pass' if c else 'advisory'}): {d}" for name, (c, d) in CRITERIA.items())
    return f"""

# The checks your task will face (write it to pass all of them the first time)
An independent reviewer scores the task on these criteria; any failed "must pass" criterion sends it back:
{crit}
Then the task is EXECUTED: the reference fix must score 1.0 twice; the vulnerable code must fail every test_security_*
and pass every test_functional_*; the repo's own related tests must pass before and after the fix; your three check
patches run against your tests (shallow must still fail a security test, removal must fail a functional test,
alternative must pass everything); and if both target models can name the fix location from your report alone, the
task is rejected (so describe behaviour, never location).
"""


def regeneration_feedback(env_dir: Path) -> str:
    """If stage 4's rubric rejected earlier rounds, show the reviewer's issues and the rejected artifacts."""
    rounds = sorted((env_dir / "attempts").glob("round_*")) if (env_dir / "attempts").is_dir() else []
    if not rounds:
        return ""
    last = rounds[-1]
    try:
        prev_md = (last / "instruction.md").read_text()
        prev_tests = (last / "hidden_tests.py").read_text()
    except OSError:
        return ""
    issues: list[str] = []
    rubric = last / "rubric_check.json"
    if rubric.is_file():
        try:
            rj = json.loads(rubric.read_text())
            if not rj.get("passed", True):
                issues += rj.get("blocking_issues", [])
        except json.JSONDecodeError:
            pass
    exe = last / "execution_feedback.txt"
    if exe.is_file():
        body = exe.read_text()
        if body.startswith("FIX-CHECK"):     # stage 4 ran the check patches; the message says what to change
            issues.append(body[:4000])
        else:
            issues.append("Your tests were EXECUTED in the real environment and misbehaved. Real pytest output:\n"
                          + body[:3500]
                          + "\nFix the test harness itself (e.g. build the app ONCE per module with a module-scoped "
                            "fixture if the project registers global state/blueprints, reset state between tests "
                            "instead of re-creating the app).")
    if not issues:
        return ""
    bullets = "\n".join(f"- {i}" for i in issues)
    return f"""

# REVISION REQUIRED - an independent reviewer rejected your previous attempt
Blocking issues (fix ALL of them; do not just rephrase):
{bullets}

Previous instruction.md:
```
{prev_md}
```
Previous hidden_tests.py:
```python
{prev_tests}
```
Produce a corrected, complete set of the four blocks. Remember: every tested behaviour must be derivable from the report, \
and tests must accept any reasonable correct fix, not only the reference patch's design.
"""


LESSONS_TEXT = ""   # set in main() from skills/lessons_learned.md


def project_test_examples(repo: Path, changed: list[str], budget: int = 12_000) -> str:
    """conftest.py files + the most related existing test file, so the generated harness mirrors the project's own."""
    picks: list[Path] = []
    for conf in sorted(repo.rglob("conftest.py")):
        if ".git" not in conf.parts and "node_modules" not in conf.parts and conf.stat().st_size < 40_000:
            picks.append(conf)
        if len(picks) >= 2:
            break
    stems = {Path(c).stem.lower() for c in changed if not TEST_PATH_RE.search(c)}
    best, best_hits = None, 0
    for t in repo.rglob("*"):
        if (not t.is_file() or ".git" in t.parts or "node_modules" in t.parts or t.stat().st_size > 60_000
                or not TEST_PATH_RE.search(t.relative_to(repo).as_posix()) or t.suffix not in (".py", ".js", ".ts", ".mjs", ".go", ".php") or "vendor" in t.parts):
            continue
        try:
            text = t.read_text(errors="ignore").lower()
        except OSError:
            continue
        hits = sum(1 for st in stems if len(st) >= 4 and st in text)
        if hits > best_hits:
            best, best_hits = t, hits
    if best:
        picks.append(best)
    out, used = [], 0
    for p in picks:
        body = p.read_text(errors="ignore")[: max(0, budget - used)]
        if not body:
            break
        used += len(body)
        out.append(f"### {p.relative_to(repo).as_posix()}\n```\n{body}\n```")
    return "\n\n".join(out) or "(no existing tests found)"


MAX_PATCH_HARD_CHARS = 400_000     # beyond this the fix is a mass rewrite, not a security fix: retired


def prompt_patch_view(patch: str) -> str:
    """What the generator SEES of a large reference fix (validation always uses the complete patch). Wide fixes are the
    ones that break the models, so they are condensed, not retired: (1) drop the upstream test/doc hunks, (2) if still
    too long, keep the largest source hunks in full and list the remaining files with their change size and first
    added line (e.g. apprise: the core redirect fix in 2 files + the same 3-line change in ~125 plugins)."""
    if len(patch) <= MAX_PATCH_CHARS:
        return patch
    chunks = [c for c in re.split(r"(?m)^(?=diff --git )", patch) if c.strip()]
    def name(c):
        m = re.match(r"diff --git a/(\S+)", c)
        return m.group(1) if m else ""
    src = [c for c in chunks if not TEST_PATH_RE.search(name(c)) and not re.search(r"\.(md|rst|txt)$|(^|/)docs?/", name(c))]
    dropped = len(chunks) - len(src)
    note = f"\n# ({dropped} test/doc file(s) of the upstream fix omitted here)\n" if dropped else ""
    view = "".join(src)
    if len(view) <= MAX_PATCH_CHARS:
        return view + note
    budget, size, keep = int(MAX_PATCH_CHARS * 0.85), 0, set()
    for c in sorted(src, key=len, reverse=True):
        if size + len(c) > budget:
            continue
        keep.add(id(c)); size += len(c)
    shown = [c for c in src if id(c) in keep]
    rest = [c for c in src if id(c) not in keep]
    lines = []
    for c in rest:
        add = [l[1:].strip() for l in c.splitlines() if l.startswith("+") and not l.startswith("+++")]
        rem = sum(1 for l in c.splitlines() if l.startswith("-") and not l.startswith("---"))
        first = next((a for a in add if a), "")
        lines.append(f"- {name(c)}: +{len(add)} -{rem}; first added line: {first[:140]}")
    return ("".join(shown) + note + f"\n# ... {len(rest)} more source file(s) changed in this fix, listed instead of shown "
            f"to save space (the same kind of change unless the line says otherwise):\n" + "\n".join(lines[:400]) + "\n")


UNSUITABLE_MARKER = "generation_unsuitable.txt"   # candidate can never yield a task (e.g. oversized patch)


def build_context(env_dir: Path, candidates: dict[str, dict]) -> Context:
    osv_id = env_dir.name
    patch_path = env_dir / PATCH_NAME
    repo = env_dir / REPO_DIRNAME
    if not patch_path.is_file() or not repo.is_dir():
        raise ValueError(f"missing {PATCH_NAME} or {REPO_DIRNAME}/")
    patch = patch_path.read_text(encoding="utf-8", errors="replace")
    if len(patch) > MAX_PATCH_HARD_CHARS:
        raise ValueError(f"oracle patch too large ({len(patch)} chars); too big to be a good task")
    meta = candidates.get(osv_id, {})
    changed = parse_changed_files(patch)
    sources, test_files = build_sources_section(repo, changed)
    top = sorted(p.name for p in repo.iterdir() if p.name != ".git")[:60]

    feedback = regeneration_feedback(env_dir) + LESSONS_TEXT
    prompt = USER_PROMPT_TEMPLATE.format(
        osv_id=osv_id,
        cve_id=meta.get("cve_id") or "n/a",
        cwes=", ".join(meta.get("cwe_ids") or []) or "unknown",
        ecosystem=meta.get("ecosystem") or "unknown",
        package=meta.get("package") or "unknown",
        repo_url=meta.get("repo_url") or "unknown",
        summary=meta.get("summary") or "(no summary available - infer from the patch)",
        patch=prompt_patch_view(patch), sources=sources,
        test_files=", ".join(test_files) or "none",
        top_level=", ".join(top),
        test_examples=project_test_examples(repo, changed),
        callers=callers_section(repo, changed, patch), repo_map=repo_map(repo, changed), manifests=manifests_section(repo),
        min_sec=MIN_SECURITY_TESTS, min_func=MIN_FUNCTIONAL_TESTS,
    ) + stage4_checks_text() + DESIGN_CONTRACT + SELF_BREAK + approved_plan_section(env_dir) + feedback

    leak = set()
    for f in changed:
        leak.add(f.lower())
        if len(Path(f).name) >= 4:
            leak.add(Path(f).name.lower())
    return Context(osv_id, env_dir, meta, patch, changed, prompt, leak,
                   advisory_text=f"{meta.get('summary') or ''} {meta.get('description') or ''}",
                   leak_idents=localizing_identifiers(patch))


DEF_RE = re.compile(r"\b(?:def|class|function|func|fn|interface|struct)\s+([A-Za-z_$][\w$]{3,})"
                    r"|^\s*(?:export\s+)?(?:async\s+)?(?:static\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]{3,})\s*=\s*(?:async\s*)?(?:function\b|\()"
                    r"|^\s*(?:public\s+|private\s+|protected\s+|static\s+|async\s+)*([A-Za-z_$][\w$]{3,})\s*\([^)]*\)\s*(?::[^{=]+)?\{\s*$",
                    re.MULTILINE)
JS_KEYWORDS = {"if", "for", "while", "switch", "catch", "return", "function", "else", "__init__", "__call__"}
SOURCE_EXT_RE = re.compile(r"\.(py|pyx|[cm]?[jt]sx?|vue|svelte|go|rb|rs|java|kt|php|cs|c|cc|cpp|h|hpp|swift|scala)$")


def localizing_identifiers(patch: str) -> set[str]:
    """Names that point straight at the fix: base names of changed source files and the functions/classes/methods the
    patch defines or edits (hunk-header context + definitions on changed lines). Generic words are excluded."""
    names: set[str] = set()
    for chunk in re.split(r"(?m)^(?=diff --git )", patch):
        m = re.match(r"diff --git a/.+? b/(.+)", chunk)
        if not m or TEST_PATH_RE.search(m.group(1)) or not SOURCE_EXT_RE.search(m.group(1)):
            continue          # docs, changesets, manifests: their names do not localize the fix
        stem = Path(m.group(1)).name.split(".")[0]
        if len(stem) >= 4:
            names.add(stem)
        changed = "\n".join(l[1:] for l in chunk.splitlines()
                            if l[:1] in "+-" and not l.startswith(("+++", "---")))
        headers = "\n".join(h for h in re.findall(r"(?m)^@@[^@]*@@(.*)$", chunk))
        for text in (changed, headers):
            for g in DEF_RE.findall(text):
                names.update(x for x in g if x and x not in JS_KEYWORDS)
    return {n for n in names if n.lower() not in GENERIC_NAMES}


TRAP_GENERIC_STEMS = {"index", "init", "__init__", "main", "mod", "utils", "util", "helpers", "types", "config",
                      "constants"}


def names_hidden_place(text: str, paths: list[str], product: frozenset[str] = frozenset()) -> list[str]:
    """Hidden places a report (or a plan's report sketch) names. A file name with its extension, or its directory/stem,
    always counts; a code-like stem (camelCase, snake_case, digits) counts as a word; a plain-word stem (`http`, `file`,
    `server`, `proxy`) only when written as code - in backticks or as a call. The old bare-word match rejected apprise's
    report 3 times for the word "http" and 12 plan sketches for words like "server" and "confluence" (2026-10-21/22)."""
    low = text.lower()
    out = []
    for p in paths:
        pp = PurePosixPath(p)
        explicit = pp.name.lower() in low or str(pp).lower() in low or f"{pp.parent.name}/{pp.stem}".lower() in low
        plain = not re.search(r"[a-z][A-Z]|_|\d|^[A-Z][a-z]+[A-Z]", pp.stem)
        if explicit or (pp.stem.lower() not in TRAP_GENERIC_STEMS and not (plain and pp.stem.lower() in product)
                        and identifier_leaks(text, {pp.stem})):
            out.append(p)
    return out


def identifier_leaks(md: str, idents: set[str]) -> list[str]:
    """Code-like names (camelCase, snake_case, digits, Pascal with an inner capital) leak when they appear as words; a
    plain lowercase word (e.g. `quote`) only when written as code - in backticks or as a call."""
    out = []
    for name in sorted(idents):
        code_like = bool(re.search(r"[a-z][A-Z]|_|\d|^[A-Z][a-z]+[A-Z]", name))
        if code_like and re.search(rf"(?<![\w$]){re.escape(name)}(?![\w$])", md):
            out.append(name)
        elif not code_like and re.search(rf"`[^`]*\b{re.escape(name)}\b[^`]*`|\b{re.escape(name)}\s*\(", md, re.IGNORECASE):
            out.append(name)
    return out


def extract_check_patches(text: str, repo: Path) -> dict[str, str]:
    """<check_patches_json> -> {kind: unified diff}. Every edit must hit exactly one place in a non-test source file;
    the diff is produced by git on a scratch copy and must `git apply --check` cleanly on the real repo."""
    m = re.search(r"<check_patches_json>\s*(.*?)\s*</check_patches_json>", text, re.DOTALL)
    if not m:
        raise GenerationInvalid("Output must also contain a <check_patches_json> block (shallow, removal, alternative).")
    raw = m.group(1).strip()
    fence = re.match(r"^```(?:json)?\s*\n(.*?)\n```$", raw, re.DOTALL)
    try:
        spec = json.loads(fence.group(1) if fence else raw)
    except json.JSONDecodeError as e:
        raise GenerationInvalid(f"<check_patches_json> is not valid JSON: {e}")
    out = {}
    for kind in CHECK_KINDS:
        edits = spec.get(kind) if isinstance(spec, dict) else None
        if not isinstance(edits, list) or not edits:
            raise GenerationInvalid(f"check_patches.{kind} must be a non-empty list of {{file, search, replace}} edits.")
        out[kind] = edits_to_patch(kind, edits, repo)
    if len(set(out.values())) < len(out):
        raise GenerationInvalid("The three check patches must differ from each other.")
    return out


def extract_oracle_extension(text: str, repo: Path, upstream_files: list[str]) -> str:
    """Optional <oracle_extension_json> -> unified diff closing Pattern B routes (real routes with the same gap that the
    upstream fix never touched). The reference solution becomes upstream fix + extension. It may only edit source files
    the upstream fix does NOT change, so the two diffs stack without conflict. "" when the block is absent."""
    m = re.search(r"<oracle_extension_json>\s*(.*?)\s*</oracle_extension_json>", text, re.DOTALL)
    if not m:
        return ""
    raw = m.group(1).strip()
    fence = re.match(r"^```(?:json)?\s*\n(.*?)\n```$", raw, re.DOTALL)
    try:
        spec = json.loads(fence.group(1) if fence else raw)
    except json.JSONDecodeError as e:
        raise GenerationInvalid(f"<oracle_extension_json> is not valid JSON: {e}")
    edits = spec.get("edits") if isinstance(spec, dict) else spec
    if edits in (None, []):
        return ""
    if not isinstance(edits, list):
        raise GenerationInvalid("<oracle_extension_json> must be {\"edits\": [{file, search, replace}, ...]}.")
    clash = sorted({str(e.get("file", "")).strip().lstrip("/") for e in edits if isinstance(e, dict)} & set(upstream_files))
    if clash:
        raise GenerationInvalid(f"<oracle_extension_json> edits files the upstream fix already changes: {clash}. The "
                                "extension is only for Pattern B routes the upstream fix never touched; a file the "
                                "upstream fix changes is already covered by the reference patch.")
    return edits_to_patch("oracle_extension", edits, repo)


def merge_oracle_extension(env_dir: Path, ext_diff: str) -> None:
    """Reference solution = upstream fix + extension, written to oracle_solution.patch so every consumer (stage 4 oracle
    runs, the leave-one-file-out coverage check, packaging) uses it unchanged. The upstream-only patch is kept in
    oracle_solution.upstream.patch and restored before a regeneration (restore_upstream_patch)."""
    upstream_path = env_dir / UPSTREAM_PATCH_NAME
    if not upstream_path.is_file():
        shutil.copy2(env_dir / PATCH_NAME, upstream_path)
    upstream = upstream_path.read_text(encoding="utf-8", errors="replace")
    combined = upstream if upstream.endswith("\n") else upstream + "\n"
    combined += ext_diff
    chk = subprocess.run(["git", "apply", "--check", "-"], cwd=env_dir / REPO_DIRNAME, input=combined,
                         capture_output=True, text=True)
    if chk.returncode != 0:
        raise GenerationInvalid(f"upstream fix + oracle extension do not apply together: {chk.stderr.strip()[:300]}")
    write_atomic(env_dir / EXTENSION_NAME, ext_diff)
    write_atomic(env_dir / PATCH_NAME, combined)


def restore_upstream_patch(env_dir: Path) -> None:
    """A regenerated design starts from the upstream fix again (an old extension must not stack on a new design)."""
    upstream_path = env_dir / UPSTREAM_PATCH_NAME
    if upstream_path.is_file():
        shutil.copy2(upstream_path, env_dir / PATCH_NAME)
        (env_dir / EXTENSION_NAME).unlink(missing_ok=True)


def edits_to_patch(kind: str, edits: list, repo: Path) -> str:
    with tempfile.TemporaryDirectory(prefix="checkpatch_") as tmp:
        work = Path(tmp)
        files = {}
        for i, e in enumerate(edits):
            if not isinstance(e, dict) or not all(isinstance(e.get(k), str) for k in ("file", "search", "replace")):
                raise GenerationInvalid(f"check_patches.{kind}[{i}] needs string fields file, search, replace.")
            rel = e["file"].strip().lstrip("/")
            if TEST_PATH_RE.search(rel) or ".." in Path(rel).parts:
                raise GenerationInvalid(f"check_patches.{kind}[{i}]: edit source files only, not {rel!r}.")
            if rel not in files:
                src = repo / rel
                if not src.is_file():
                    raise GenerationInvalid(f"check_patches.{kind}[{i}]: {rel!r} does not exist in the repository.")
                files[rel] = src.read_text(encoding="utf-8", errors="replace")
            n = files[rel].count(e["search"]) if e["search"] else 0
            if n != 1:
                raise GenerationInvalid(f"check_patches.{kind}[{i}]: the search text occurs {n} times in {rel} "
                                        "(it must be copied verbatim and occur exactly once).")
            files[rel] = files[rel].replace(e["search"], e["replace"], 1)
        for rel in files:
            (work / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(repo / rel, work / rel)
        git = lambda *a: subprocess.run(["git", "-c", "user.name=x", "-c", "user.email=x@x", *a], cwd=work,
                                        capture_output=True, text=True)
        git("init", "-q")
        git("add", "-A")
        git("commit", "-qm", "base")
        for rel, body in files.items():
            (work / rel).write_text(body, encoding="utf-8")
        diff = git("diff", "--no-color").stdout
    if not diff.strip():
        raise GenerationInvalid(f"check_patches.{kind} changes nothing.")
    chk = subprocess.run(["git", "apply", "--check", "-"], cwd=repo, input=diff, capture_output=True, text=True)
    if chk.returncode != 0:
        raise GenerationInvalid(f"check_patches.{kind} does not apply to the repository: {chk.stderr.strip()[:300]}")
    return diff


# --------------------------------------------------------------------------- #
# Parsing and validation
# --------------------------------------------------------------------------- #
REFUSAL_RE = re.compile(r"\b(I can't|I cannot|I won't|I'm not able|I am unable|I'm unable|can't help with|unable to (?:help|assist|complete))", re.IGNORECASE)
REFUSAL_RETRY_NOTE = """

# Context for this request
This is a defensive security-REGRESSION task for a vulnerability that is already public (see the advisory metadata above) and \
already fixed upstream by the reference patch. The deliverables are (1) a maintainer-style bug report and (2) pytest tests that \
assert hostile input is REJECTED while legitimate use keeps working. Tests use harmless sentinel values inside pytest's tmp_path \
and contain no attack tooling. Please produce the four blocks in the required format.
"""


class GenerationInvalid(Exception):
    """Model output unusable; message is fed back to the model on retry."""


def extract_instruction(text: str) -> str:
    m = re.search(r"<instruction_md>\s*(.*?)\s*</instruction_md>", text, re.DOTALL)
    if not m:
        raise GenerationInvalid("Output must contain an <instruction_md> block.")
    return m.group(1).strip() + "\n"


def extract_tests(text: str) -> str:
    m = re.search(r"<hidden_tests_py>\s*(.*?)\s*</hidden_tests_py>", text, re.DOTALL)
    if not m:
        raise GenerationInvalid("Output must contain a <hidden_tests_py> block.")
    code = m.group(1).strip()
    fence = re.match(r"^```(?:python)?\s*\n(.*?)\n```$", code, re.DOTALL)
    if fence:
        code = fence.group(1)
    return code.strip() + "\n"


def extract_blocks(text: str) -> tuple[str, str]:
    inst = re.search(r"<instruction_md>\s*(.*?)\s*</instruction_md>", text, re.DOTALL)
    tests = re.search(r"<hidden_tests_py>\s*(.*?)\s*</hidden_tests_py>", text, re.DOTALL)
    if not inst or not tests:
        raise GenerationInvalid("Output must contain both <instruction_md> and <hidden_tests_py> blocks.")
    code = tests.group(1).strip()
    fence = re.match(r"^```(?:python)?\s*\n(.*?)\n```$", code, re.DOTALL)
    if fence:
        code = fence.group(1)
    return inst.group(1).strip() + "\n", code.strip() + "\n"


# 12-15: the measured top sibling breakers (skills/task_design_techniques.md catalogue, 2026-10-20)
HIDDEN_PATH_TECHNIQUES = {1, 2, 3, 7, 12, 13, 14, 15}
CONTRACT_TECHNIQUES = {5, 9, 11}   # over-correction traps: the other half of the measured model failures
MAX_COVERED_SOURCE_FILES = 40      # beyond this (apprise: 127 plugin files) completeness is not enforceable per file


def patch_source_files(changed: list[str], ecosystem: str) -> list[str]:
    """The reference patch's source files (tests, docs, configs, type stubs excluded)."""
    from src.common.classify import classify
    return [f for f in changed if classify(f, ecosystem) == "source"]


def validate_trap(md: str, task_meta: dict, repo_dir: Path, patch_sources: Optional[list[str]] = None) -> None:
    """Deterministic trap evidence (2026-10-19: 32 of 37 evaluated tasks were solved on the first attempt; the 5 that
    broke a model all hid part of the root cause in a place the report never names, and half the measured failures
    were over-corrections). The declared techniques alone are gameable, so the trap must be concrete: real files,
    inside fix_places (the leave-one-file-out coverage check then proves the tests need them), spread over more than
    one directory, and invisible in the report."""
    techs = set(task_meta.get("techniques") or [])
    if not techs & HIDDEN_PATH_TECHNIQUES:
        raise GenerationInvalid(
            "Apply at least one hidden-path technique (1 unnamed sibling path, 2 already-protected-looking "
            "code, 3 fix across a layer boundary, 7 parallel implementation, 12 feature-absent, 13 producer off the "
            "check's path, 14 wrong object, 15 merged/defaults route): a security test must reach the root cause "
            "through a path the report does not name. List it in metadata.techniques.")
    # Completeness (the #1 measured cause of easy tasks: in 24 of 37 solved tasks the agent passed while changing fewer
    # source files than the reference fix). Every patch source file is either a fix place - then leave-one-file-out
    # proves a test needs it - or declared unrelated; nothing may silently drop out of the coverage check.
    if patch_sources and len(patch_sources) <= MAX_COVERED_SOURCE_FILES:
        declared = set(task_meta.get("fix_places") or []) | set(task_meta.get("unrelated_files") or [])
        missing = [f for f in patch_sources if f not in declared]
        if missing:
            raise GenerationInvalid(
                f"metadata must account for every source file of the reference patch; not listed in fix_places or "
                f"unrelated_files: {missing}. Put each file whose change closes part of the vulnerability in "
                "fix_places (and give it its own security test reached through its own entry point); put refactors, "
                "typing or bundled unrelated changes in unrelated_files.")
    if not techs & CONTRACT_TECHNIQUES:
        raise GenerationInvalid(
            "Apply at least one over-correction trap (5 boundary-hugging functional tests, 9 a must-keep-working "
            "clause, 11 a compatibility contract pinned by an existing repo test) and list it in "
            "metadata.techniques: the functional tests must be able to catch a fix that breaks legitimate use.")
    trap = task_meta.get("trap") or {}
    paths, contract = trap.get("paths") or [], trap.get("contract") or ""
    if not paths or not contract:
        raise GenerationInvalid(
            "metadata.trap is required: trap.paths = the fix's source files an agent only finds through a path your "
            "report never names, and trap.contract = the one-line legitimate behaviour your functional tests pin. "
            "If the candidate offers no such place, answer <unsuitable>no hidden-path trap: reason</unsuitable>.")
    missing = [p for p in paths if not (repo_dir / p).is_file()]
    if missing:
        raise GenerationInvalid(f"metadata.trap.paths not found in the pre-patch repo: {missing} "
                                "(repo-relative source paths, copied exactly).")
    places = task_meta.get("fix_places") or []
    outside = [p for p in paths if p not in places]
    if outside:
        raise GenerationInvalid(f"every metadata.trap.paths entry must also be listed in metadata.fix_places, so the "
                                f"coverage check can prove the tests need it; missing from fix_places: {outside}")
    named = names_hidden_place(md, paths)
    if named:
        raise GenerationInvalid(f"the report names or hints at the trap file(s) {named}: the trap only works when "
                                "the report localises nothing beyond the reported entry point. Rewrite the report "
                                "without those names, or pick a different trap path.")
    if len({str(Path(p).parent) for p in set(paths) | set(places)}) < 2:
        raise GenerationInvalid("fix_places + trap.paths sit in a single directory: the trap needs at least one "
                                "place in another module/directory (techniques 1/7). If this candidate cannot "
                                "support that, answer <unsuitable>no hidden-path trap: single directory</unsuitable>.")


def extract_metadata(text: str) -> dict:
    m = re.search(r"<task_metadata_json>\s*(.*?)\s*</task_metadata_json>", text, re.DOTALL)
    if not m:
        raise GenerationInvalid("Output must also contain a <task_metadata_json> block with an entry_point.")
    try:
        meta = json.loads(m.group(1))
    except json.JSONDecodeError as e:
        raise GenerationInvalid(f"<task_metadata_json> is not valid JSON: {e}")
    ep = meta.get("entry_point") if isinstance(meta, dict) else None
    if isinstance(ep, str):
        ep = " ".join(ep.split())[:600]          # a long or wrapped description is fine; only its absence is not
    if not isinstance(ep, str) or len(ep) < 5:
        raise GenerationInvalid("metadata.entry_point must be a one-line string describing the real entry point.")
    techs = meta.get("techniques") if isinstance(meta.get("techniques"), list) else []
    # which curated techniques this task applies: the technique scoreboard learns from them (optional field)
    places = meta.get("fix_places") if isinstance(meta.get("fix_places"), list) else []
    # the source files the security fix really needs (stage 4's leave-one-file-out coverage check; optional field)
    trap = meta.get("trap") if isinstance(meta.get("trap"), dict) else {}
    trap_paths = trap.get("paths") if isinstance(trap.get("paths"), list) else []
    contract = trap.get("contract") if isinstance(trap.get("contract"), str) else ""
    unrelated = meta.get("unrelated_files") if isinstance(meta.get("unrelated_files"), list) else []
    sa = meta.get("self_attack") if isinstance(meta.get("self_attack"), dict) else {}
    just = meta.get("test_justifications") if isinstance(meta.get("test_justifications"), dict) else {}
    paths = lambda xs: [str(f).strip().lstrip("./") for f in xs if isinstance(f, str) and f.strip()]
    return {"entry_point": ep.strip(), "techniques": sorted({int(t) for t in techs if str(t).strip().isdigit() and 0 < int(t) < 50}),
            "trap": {"paths": paths(trap_paths)[:10], "contract": " ".join(contract.split())[:400]},
            "fix_places": paths(places)[:40],
            "unrelated_files": paths(unrelated)[:200],
            "self_attack": {"naive_fix": " ".join(str(sa.get("naive_fix") or "").split())[:800],
                            "naive_fix_files": paths(sa.get("naive_fix_files") or [])[:20],
                            "over_broad_fix": " ".join(str(sa.get("over_broad_fix") or "").split())[:600],
                            "why_naive_fails": " ".join(str(sa.get("why_naive_fails") or "").split())[:800]},
            "test_justifications": {str(k): str(v) for k, v in just.items() if isinstance(v, str)}}


SELF_ATTACK_REQUIRED = os.environ.get("GEN_SELF_ATTACK", "1") != "0"


def validate_self_attack(task_meta: dict, patches: dict[str, str]) -> None:
    """Self-break protocol: the design names its own likely repair, keeps a trap place outside it, and the executed check
    patches ARE that repair (shallow) and the over-broad one (removal)."""
    if not SELF_ATTACK_REQUIRED:
        return
    sa = task_meta.get("self_attack") or {}
    naive = set(sa.get("naive_fix_files") or [])
    if len(sa.get("naive_fix") or "") < 20 or not naive or len(sa.get("over_broad_fix") or "") < 10:
        raise GenerationInvalid('metadata.self_attack is required: {"naive_fix", "naive_fix_files", "over_broad_fix", '
                                '"why_naive_fails"} - the repair YOU would make from the report alone (see the '
                                'self-break protocol).')
    trap = task_meta.get("trap", {}).get("paths") or []
    if trap and set(trap) <= naive:
        raise GenerationInvalid(f"every trap path {trap} is inside your own naive_fix_files: the repair you predicted "
                                "already covers the hidden place, so the task is solvable. Move the trap to a place "
                                "the naive fix does not touch (M4/M6/M2/M10/M5), or declare <unsuitable>.")
    shallow = set(parse_changed_files(patches.get("shallow", "")))
    if shallow and not shallow <= naive:
        raise GenerationInvalid(f"the shallow check patch edits {sorted(shallow - naive)}, outside naive_fix_files "
                                f"{sorted(naive)}: the shallow patch must BE your naive fix.")


def _norm_quote(s: str) -> str:
    s = s.lower().translate(str.maketrans({"‘": "'", "’": "'", "“": '"', "”": '"', "—": "-",
                                           "–": "-"}))
    return " ".join(re.sub(r"[*_`#>]", " ", s).split())


def validate_justifications(code: str, md: str, justifs: dict[str, str]) -> None:
    """Fairness, enforced deterministically: every test quotes the instruction sentence that demands what it asserts
    (GitPython/pimcore/stigmem/LibreNMS 2026-10-20: tests demanded behaviour the report never stated)."""
    names = [n.name for n in ast.walk(ast.parse(code)) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
             and n.name.startswith(("test_security_", "test_functional_"))]
    report = _norm_quote(md)
    bad = []
    for n in names:
        q = _norm_quote(justifs.get(n) or "").strip("\"' .")
        if len(q.split()) < 5:
            bad.append(f"{n}: no justification quote (>= 5 words copied from instruction.md)")
        elif q not in report:
            bad.append(f"{n}: quote not found verbatim in instruction.md: {q[:120]!r}")
    if bad:
        raise GenerationInvalid("Every test needs the exact instruction.md sentence that requires its assertion. The "
                                "report is fixed - change the TEST (or drop it) when no sentence justifies it:\n- "
                                + "\n- ".join(bad[:10]))


def validate_design_bound(env_dir: Path, code: str, md: str) -> None:
    """Stage 4's first deterministic check, run at generation time so call 2 cannot ship a suite that only the
    reference design passes."""
    from src.stage4_oracle_validator.oracle_runner import design_bound_names
    names, probes = design_bound_names(env_dir, tests=code, report=md)
    if names or probes:
        raise GenerationInvalid(f"the tests use names that exist only in the reference fix {names[:8]} or probe for "
                                f"members a fix might add {probes[:8]}: any correct repair must pass, so drive behaviour "
                                "only through pre-patch public API and observable results.")


def _ngrams(text: str, n: int = 8) -> set[str]:
    words = re.findall(r"[a-z0-9_]+", text.lower())
    return {" ".join(words[i:i + n]) for i in range(len(words) - n + 1)}


def validate_instruction(md: str, ctx: Context) -> None:
    lowered = md.lower()
    copied = _ngrams(md) & _ngrams(ctx.advisory_text)
    if copied:   # verbatim advisory phrases are the strongest recall cue for a model that has seen the advisory
        raise GenerationInvalid("instruction.md copies the public advisory's wording (e.g. "
                                f"{sorted(copied)[0]!r}). Describe the problem entirely in your own words as a user would.")
    leaked = sorted(t for t in ctx.leak_terms if t in lowered)
    if leaked:
        raise GenerationInvalid(
            f"instruction.md mentions file names/paths from the patch ({', '.join(leaked)}). "
            "Remove every file name and path.")
    named = identifier_leaks(md, ctx.leak_idents)
    if named:
        raise GenerationInvalid(
            f"instruction.md names code the fix changes: {', '.join(named)} (a changed file's base name or a function/"
            "method/class the patch edits). Remove every occurrence of these exact names written as code - in backticks, "
            "as a call like name(...), or as an identifier. Describe the component in plain words by its role instead "
            "(e.g. 'the HTTP response-caching layer' rather than `cache` or cache()); a public option the user sets "
            "may still be described in words.")
    if re.search(r"\bline[s]?\s+\d+\b|\.\w{1,4}:\d+\b|\bL\d{2,}\b", md, re.IGNORECASE):
        raise GenerationInvalid("instruction.md contains line numbers; remove them.")
    if len(md.split()) < 60:
        raise GenerationInvalid("instruction.md is too short to be a realistic report.")
    scope = NEAR_SPEC_SCOPE.search(md)
    if scope:
        raise GenerationInvalid(
            f"instruction.md states how far the bug reaches ({scope.group(0)!r}). That tells the agent to grep for every "
            "sibling, so the hidden place stops being hidden (measured: all 4 evaluated reports with such a phrase were "
            "solved on attempt 1 - fm3f, f3f2, p63j, q2xc). Describe the route(s) the user hit; leave whether others "
            "exist for the agent to find.")


# Scope asserted ABOUT THE BUG ("on every route", "for every operation", "each one we tried", "every command that").
# Calibrated on all 67 reports on disk 2026-10-20: 6 hits, the 4 evaluated ones all solved on attempt 1, 0 hits on either
# accepted task. A broader form ("each backend has its own client") also matched feature descriptions - including vp8m,
# which broke MiMo - and was dropped. Word count, repro headings, code spans and list items were also tried and dropped:
# both accepted tasks have a repro section and ~380 words, and apprise has 12 code spans and 10 list items.
_SCOPE_NOUN = (r"(providers?|endpoints?|routes?|handlers?|nodes?|parsers?|renderers?|backends?|adapters?|plugins?|"
               r"integrations?|connectors?|commands?|loaders?|readers?|writers?|drivers?|operations?|methods?)")
NEAR_SPEC_SCOPE = re.compile(
    r"(?i)\b(each|every)\s+one\s+we\s+tried\b"
    r"|\b(on|in|across|through|of|for|via)\s+(every|each|all(\s+(of\s+)?the)?|all\s+(two|three|four|five|six|seven|eight))"
    r"\s+(\w+\s+)?" + _SCOPE_NOUN + r"\b"
    r"|\bevery\s+(\w+\s+)?" + _SCOPE_NOUN + r"\s+that\b")


def no_silent_skips(code: str) -> str:
    """A skipped test scores as failed and hides an environment gap. Turn guards into hard failures instead, so a missing
    package fails loudly at validation (where it gets fixed): pytest.skip(...) -> pytest.fail(...),
    pytest.importorskip("x") -> importlib.import_module("x"), skip/skipif markers removed. xfail is still rejected."""
    code = re.sub(r"\bpytest\.skip\s*\(", "pytest.fail(", code)
    code = re.sub(r",\s*allow_module_level\s*=\s*True", "", code)
    code = re.sub(r"\bpytest\.importorskip\s*\(\s*(['\"][\w.]+['\"])\s*\)", r"__import__('importlib').import_module(\1)", code)
    code = re.sub(r"(?m)^\s*@pytest\.mark\.skip(if)?\b.*\n", "", code)
    code = re.sub(r"(?m)^\s*pytestmark\s*=\s*pytest\.mark\.skip(if)?\b.*\n", "", code)
    return code


def ensure_pytest_import(code: str) -> str:
    """A missing `import pytest` is a one-line omission, not a design flaw: add it (after a module docstring and
    __future__ imports) instead of rejecting an otherwise valid suite."""
    if re.search(r"(?m)^\s*(import pytest\b|from pytest\b)", code):
        return code
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return code               # validate_tests reports the syntax error
    line = 0
    for node in tree.body:
        is_doc = isinstance(node, ast.Expr) and isinstance(getattr(node, "value", None), ast.Constant) \
            and isinstance(node.value.value, str)
        if is_doc or (isinstance(node, ast.ImportFrom) and node.module == "__future__"):
            line = node.end_lineno
            continue
        break
    lines = code.splitlines(keepends=True)
    return "".join(lines[:line]) + "import pytest\n" + "".join(lines[line:])


def validate_tests(code: str, ctx: Context) -> None:
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        raise GenerationInvalid(f"hidden_tests.py has a syntax error: {e}")
    names = [n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    sec = [n for n in names if n.startswith("test_security_")]
    fun = [n for n in names if n.startswith("test_functional_")]
    if len(sec) < MIN_SECURITY_TESTS:
        raise GenerationInvalid(f"Need >= {MIN_SECURITY_TESTS} test_security_* functions, found {len(sec)}.")
    if len(fun) < MIN_FUNCTIONAL_TESTS:
        raise GenerationInvalid(f"Need >= {MIN_FUNCTIONAL_TESTS} test_functional_* functions, found {len(fun)}.")
    if "import pytest" not in code and "from pytest" not in code:
        raise GenerationInvalid("hidden_tests.py must import pytest.")
    if re.search(r"importorskip|pytest\.skip\s*\(|mark\.skip(if)?\b|pytest\.xfail|mark\.xfail|allow_module_level", code):
        # A skipped test scores as failed: a missing package would look like a model failure. The task image installs
        # the project with all its extras and dev/test groups, so a dependency the tests need is present.
        raise GenerationInvalid("hidden_tests.py must never skip or xfail (no importorskip, pytest.skip, skipif, xfail): "
                                "every test must run. The environment installs the project with all its optional extras "
                                "and dev/test dependencies; import what you need directly.")
    # Tests must not read the answer key.
    if PATCH_NAME in code or "oracle_solution" in code:
        raise GenerationInvalid("hidden_tests.py must not reference the oracle patch.")


# --------------------------------------------------------------------------- #
# Model backends
# --------------------------------------------------------------------------- #
class ApiBackend:
    """Direct Anthropic API (needs ANTHROPIC_API_KEY)."""

    def __init__(self, timeout: float):
        import anthropic
        # The SDK already retries 408/409/429/5xx and connection errors with backoff.
        self.client = anthropic.Anthropic(timeout=timeout, max_retries=5)

    def complete(self, model: str, system: str, messages: list[dict], max_tokens: int) -> tuple[str, dict]:
        # Streaming avoids the SDK's non-streaming guard on long generations.
        with self.client.messages.stream(model=model, max_tokens=max_tokens, system=system, messages=messages) as stream:
            final = stream.get_final_message()
        if final.stop_reason == "refusal":
            raise RuntimeError("model refused the request")
        text = "".join(b.text for b in final.content if getattr(b, "type", "") == "text")
        if final.stop_reason == "max_tokens":
            raise GenerationInvalid("Output was truncated at max_tokens; be more concise.")
        return text, {"input_tokens": final.usage.input_tokens, "output_tokens": final.usage.output_tokens}


def call_model(client, model: str, messages: list[dict], max_tokens: int) -> tuple[str, dict]:
    return client.complete(model, SYSTEM_PROMPT, messages, max_tokens)


SPLIT_DESIGN_SUFFIX = """

# Split generation (this request)
Return ONLY the `<instruction_md>`, `<task_metadata_json>` and `<check_patches_json>` blocks (plus
`<oracle_extension_json>` if your design has a Pattern B route). Do NOT write the
<hidden_tests_py> block; it is requested in a separate step. Keep the check patches minimal (only the edits that
demonstrate shallow / removal / alternative behaviour).
"""

SPLIT_TESTS_SUFFIX = """

# Split generation (this request)
The report, metadata and check patches were approved in the previous step. Return ONLY the `<hidden_tests_py>` block,
following every test constraint above, then a `<test_justifications_json>` block: {"<test name>": "<the exact sentence
copied from instruction.md that requires this test's assertion>"} for EVERY test_security_* and test_functional_*.
The report is fixed: a test no sentence justifies is unfair - change or drop the test. Keep the suite lean: at most 6
`test_security_*` and 6 `test_functional_*` tests, each focused and under 60 lines. The tests must make your own
naive_fix (the shallow check patch) fail at least one test_security_* and your over_broad_fix (the removal check patch)
fail at least one test_functional_*. Do not repeat the instruction, metadata or patches.
"""


def _has_block(text: str) -> bool:
    return any(tag in text[:4000] for tag in ("<instruction_md>", "<hidden_tests_py>", "<task_metadata_json>"))


class CandidateUnsuitable(Exception):
    """The generator declared the candidate unusable (e.g. an incomplete upstream fix, rule 8)."""


def _run_phase(client, ctx: Context, phase: str, prompt: str, model: str, max_tokens: int, max_attempts: int,
               fallback_model: str, accept: Callable[[str], Any]) -> tuple[Any, dict]:
    """One generation phase with retries. `accept` extracts+validates the phase's artifacts or raises GenerationInvalid.
    Splitting the four-artifact response keeps the large test block from sharing the output budget with the rest."""
    messages = [{"role": "user", "content": prompt}]
    last_err = "unknown"
    refused = 0
    total = {"input_tokens": 0, "output_tokens": 0, "attempts": 0, "models": []}
    budget, attempt = max_attempts, 0
    while attempt < budget:
        attempt += 1
        total["attempts"] += 1
        total["models"].append(model)
        text = ""          # never reuse an earlier attempt's output in the feedback below
        try:
            try:
                text, usage = call_model(client, model, messages, max_tokens)
            except OutputLimitExceeded:   # must stay BEFORE the RuntimeError clause: it is a RuntimeError subclass
                if phase == "single":    # generate() splits the request
                    raise
                # a split phase that still overflows is retried with the "be concise" feedback (leantime, cycle 10)
                raise GenerationInvalid("Output exceeded the output-token limit; be more concise (fewer, tighter "
                                        "tests; shorter report; minimal check-patch edits).")
            except RuntimeError as e:
                # A call that outlasted the per-call timeout: the same model would time out again, so switch to the
                # fallback model once (user decision 2026-10-20: Opus 4.8). SafeguardsFlagged is NOT a RuntimeError and is
                # never caught here: a flagged candidate never reaches another Claude model.
                if "timed out" in str(e) and fallback_model and model != fallback_model:
                    log.warning("[%s] %s attempt %d/%d: %s timed out; switching to the fallback model %s",
                                ctx.osv_id, phase, attempt, budget, model, fallback_model)
                    model, budget = fallback_model, budget + 1
                    continue
                raise
            m = re.search(r"<unsuitable>\s*(.*?)\s*</unsuitable>", text or "", re.S)
            if m and "<instruction_md>" not in text and "<hidden_tests_py>" not in text:
                raise CandidateUnsuitable(m.group(1)[:500])
            total["input_tokens"] += usage.get("input_tokens", 0)
            total["output_tokens"] += usage.get("output_tokens", 0)
            if usage.get("output_tokens", 0) >= max_tokens * 0.98:      # cut at the output limit: never use a fragment
                if phase == "single":    # the one-call answer does not fit: split into design + tests calls at once
                    raise OutputLimitExceeded("single-call output truncated at the output-token limit")
                raise GenerationInvalid("Output was truncated at the output-token limit; be more concise.")
            value = accept(text)
            return value, total
        except GenerationInvalid as e:
            last_err = str(e)
            raw = text
            if REFUSAL_RE.search(raw[:600]) and not _has_block(raw):
                # A refusal is not feedback: retry the ORIGINAL request with extra defensive context.
                refused += 1
                if fallback_model and model != fallback_model:
                    log.warning("[%s] %s attempt %d/%d: %s declined (safety filter); switching to the fallback model %s",
                                ctx.osv_id, phase, attempt, budget, model, fallback_model)
                    model, budget = fallback_model, budget + 1
                else:
                    log.warning("[%s] %s attempt %d/%d: %s declined (safety filter); retrying with added context",
                                ctx.osv_id, phase, attempt, budget, model)
                try:
                    # one file per refusal across runs (stage 3 retires a candidate after MAX_REFUSALS in total)
                    (ctx.env_dir / f"generation_refused_{time.strftime('%Y%m%d-%H%M%S')}_{attempt}.txt").write_text(raw)
                except OSError:
                    pass
                messages = [{"role": "user", "content": prompt + REFUSAL_RETRY_NOTE}]
                continue
            log.info("[%s] %s attempt %d/%d rejected: %s", ctx.osv_id, phase, attempt, budget, last_err)
            if raw:
                try:
                    (ctx.env_dir / f"generation_rejected_{time.strftime('%Y%m%d-%H%M%S')}_{attempt}_{phase}.txt").write_text(
                        f"REJECTED ({phase}): {last_err}\n\n{raw}")
                except OSError:
                    pass
                messages = [messages[0],
                            {"role": "assistant", "content": raw},
                            {"role": "user", "content":
                             f"Rejected by the validator: {last_err}\nReturn the corrected full output "
                             "in the same strict format."}]
    if refused == attempt:
        raise GenerationInvalid(f"declined by the safety filter on all {attempt} attempts "
                                f"({', '.join(dict.fromkeys(total['models']))}); no task was produced")
    raise GenerationInvalid(f"no valid {phase} output after {attempt} attempts: {last_err}")


def validate_extension_leaks(md: str, ext: str) -> None:
    """The report must not name a Pattern B route either (its file or the functions the extension edits)."""
    if not ext:
        return
    lowered = md.lower()
    named = [f for f in parse_changed_files(ext) if f.lower() in lowered or (len(Path(f).name) >= 4 and Path(f).name.lower() in lowered)]
    named += identifier_leaks(md, localizing_identifiers(ext))
    if named:
        raise GenerationInvalid(f"instruction.md names a Pattern B route the oracle extension closes: {sorted(set(named))}. "
                                "The report describes only the route the user hit.")


def _accept_design_artifacts(ctx: Context, text: str, md: str, task_meta: dict) -> dict[str, str]:
    """Shared by both generation modes: optional oracle extension (Pattern B), trap and leak checks, check patches."""
    repo = ctx.env_dir / REPO_DIRNAME
    ext = extract_oracle_extension(text, repo, ctx.changed_files)
    # measured: most solved tasks reached every variant through the reported entry point
    validate_trap(md, task_meta, repo,
                  patch_source_files(ctx.changed_files + parse_changed_files(ext), ctx.meta.get("ecosystem", "")))
    validate_instruction(md, ctx)
    validate_extension_leaks(md, ext)
    patches = extract_check_patches(text, repo)
    validate_self_attack(task_meta, patches)
    if ext:
        patches["oracle_extension"] = ext      # merged into oracle_solution.patch by process(), not a check patch
    return patches


def _accept_design(ctx: Context):
    def accept(text: str):
        md = extract_instruction(text)
        task_meta = extract_metadata(text)
        patches = _accept_design_artifacts(ctx, text, md, task_meta)
        return md, task_meta, patches
    return accept


def extract_justifications(text: str) -> dict[str, str]:
    m = re.search(r"<test_justifications_json>\s*(.*?)\s*</test_justifications_json>", text, re.DOTALL)
    if not m:
        return {}
    try:
        got = json.loads(m.group(1))
    except json.JSONDecodeError as e:
        raise GenerationInvalid(f"<test_justifications_json> is not valid JSON: {e}")
    return {str(k): str(v) for k, v in got.items() if isinstance(v, str)} if isinstance(got, dict) else {}


def _accept_tests(ctx: Context, md: str, design_justifs: dict[str, str]):
    def accept(text: str):
        code = extract_tests(text)
        code = no_silent_skips(ensure_pytest_import(code))
        validate_tests(code, ctx)
        justifs = {**design_justifs, **extract_justifications(text)}
        validate_justifications(code, md, justifs)
        validate_design_bound(ctx.env_dir, code, md)
        return code, justifs
    return accept


def _combine_usage(*parts: dict) -> dict:
    out = {"input_tokens": 0, "output_tokens": 0, "attempts": 0, "models": []}
    for p in parts:
        out["input_tokens"] += p.get("input_tokens", 0)
        out["output_tokens"] += p.get("output_tokens", 0)
        out["attempts"] += p.get("attempts", 0)
        out["models"] += p.get("models", [])
    return out


def generate(client, ctx: Context, model: str, max_tokens: int, max_attempts: int,
             fallback_model: str = "", force_split: bool = False) -> tuple[str, str, dict, dict, dict]:
    """Generate in two calls (design+patches, then hidden tests) when the model is reached through an
    Anthropic-compatible third-party API (DeepSeek/MiMo), where the four-block response routinely exceeds the 64k output
    limit. On the Claude subscription the single call is cheaper; override with GEN_SPLIT_ARTIFACTS=1/0.
    A safety refusal switches to `fallback_model` (once, with one extra attempt)."""
    mode = os.environ.get("GEN_SPLIT_ARTIFACTS", "auto").strip().lower()
    external = any(h in (os.environ.get("ANTHROPIC_BASE_URL") or "").lower()
                   for h in ("deepseek.com", "xiaomimimo.com"))
    split = force_split or mode in ("1", "true", "yes", "on") or (mode in ("auto", "") and external)
    if not split:
        try:
            return _generate_single(client, ctx, model, max_tokens, max_attempts, fallback_model)
        except OutputLimitExceeded as e:
            log.info("[%s] single call exceeded the output limit; splitting into design + tests calls: %s",
                     ctx.osv_id, str(e)[:120])

    design_prompt = ctx.prompt + SPLIT_DESIGN_SUFFIX
    (md, task_meta, patches), u1 = _run_phase(
        client, ctx, "design", design_prompt, model, max_tokens, max_attempts, fallback_model, _accept_design(ctx))
    ext = patches.get("oracle_extension", "")
    ext_view = ("\n\n# Oracle extension (Pattern B - part of the reference solution, applied together with the upstream "
                "fix; each route it closes needs its own test_security_* through its own public entry point)\n```diff\n"
                + ext[:20_000] + "\n```") if ext else ""
    tests_prompt = (ctx.prompt + "\n\n# Approved design (previous step)\n<instruction_md>\n" + md
                    + "\n</instruction_md>\n<task_metadata_json>\n"
                    + json.dumps(task_meta, indent=2) + "\n</task_metadata_json>" + ext_view + SPLIT_TESTS_SUFFIX)
    (code, justifs), u2 = _run_phase(
        client, ctx, "tests", tests_prompt, model, max_tokens, max_attempts, fallback_model,
        _accept_tests(ctx, md, task_meta.get("test_justifications") or {}))
    task_meta["test_justifications"] = justifs
    return md, code, _combine_usage(u1, u2), task_meta, patches


def _generate_single(client, ctx: Context, model: str, max_tokens: int, max_attempts: int,
                     fallback_model: str = "") -> tuple[str, str, dict, dict, dict]:
    """Legacy single-call mode (all four blocks in one response)."""
    def accept(text: str):
        md, code = extract_blocks(text)
        code = no_silent_skips(ensure_pytest_import(code))
        task_meta = extract_metadata(text)
        validate_tests(code, ctx)
        patches = _accept_design_artifacts(ctx, text, md, task_meta)
        validate_justifications(code, md, task_meta.get("test_justifications") or {})
        validate_design_bound(ctx.env_dir, code, md)
        return md, code, task_meta, patches

    value, usage = _run_phase(client, ctx, "single", ctx.prompt, model, max_tokens, max_attempts,
                              fallback_model, accept)
    md, code, task_meta, patches = value
    return md, code, usage, task_meta, patches


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def write_atomic(path: Path, content: str) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    os.replace(tmp, path)


def already_done(env_dir: Path) -> bool:
    return all((env_dir / n).is_file() and (env_dir / n).stat().st_size > 0
               for n in (INSTRUCTION_NAME, TESTS_NAME))


ABORT = threading.Event()  # set when the quota is exhausted so remaining folders are not attempted

# User decision (2026-10-20): a candidate Anthropic's safeguards flag - and any candidate of a flagged repo or an
# offensive-security tool repo - is RETIRED and never sent to Claude again. After FLAG_LIMIT flags in one run, the rest of
# the run is DEFERRED (back to pending, no strike) and a cluster warning is logged for the user.
# User decision (2026-10-21): DeepSeek is the PRIMARY generator again (`--backend deepseek`), despite 0 of 15 accepted under
# the old prompt - now behind the pre-build plan gate (plan_gate.py: heuristic, Claude review, self-solve probe), the
# self-break protocol (SELF_BREAK) and the contamination canary. Retired candidates stay retired on every backend.
DEFERRED_MARKER = "generation_deferred.txt"   # skipped this run through no fault of the candidate: no strike
FLAGS_LOCK = threading.Lock()
FLAGS = {"n": 0}
FLAG_LIMIT = int(os.environ.get("GEN_FLAG_LIMIT", "3"))
OFFENSIVE_REPO_RE = re.compile(
    r"github\.com/(projectdiscovery|rapid7|sqlmapproject|zaproxy|bishopfox|bc-security|cobbr|gentilkiwi|fortra|"
    r"lgandx|beefproject|bettercap|epi052|ffuf|owasp-amass)/"
    r"|github\.com/[^/]+/[^/]*(exploit|pentest|red-?team|hacktool|metasploit|nuclei|sqlmap|c2-?framework)", re.I)


def flagged_repos(env_root: Path, candidates: dict) -> set[str]:
    out = set()
    for f in env_root.glob("*/safeguards_flagged.txt"):
        rec = candidates.get(f.parent.name) or {}
        if rec.get("repo_url"):
            out.add(rec["repo_url"].lower().rstrip("/"))
    return out


def deepseek_client(args):
    """Claude Code CLI against DeepSeek's Anthropic-compatible API, for this client only."""
    key = os.environ.get("DEEPSEEK_API_KEY", "").strip()
    if not key:
        return None
    model = os.environ.get("DEEPSEEK_GEN_MODEL", "deepseek-flash[1m]")
    small = model.replace("[1m]", "")
    return CliBackend(args.claude_bin, args.timeout, env_overrides={
        "ANTHROPIC_BASE_URL": "https://api.deepseek.com/anthropic", "ANTHROPIC_AUTH_TOKEN": key,
        "ANTHROPIC_MODEL": model, "ANTHROPIC_DEFAULT_OPUS_MODEL": model, "ANTHROPIC_DEFAULT_SONNET_MODEL": model,
        "ANTHROPIC_DEFAULT_HAIKU_MODEL": small, "CLAUDE_CODE_SUBAGENT_MODEL": small,
        # thinking counts against the 64k output limit. Effort "max" made every call 20+ min (cycle 11: nothing
        # finished inside the 45-min cap), so generation never completes; "high" calls take 3-8 min.
        "CLAUDE_CODE_EFFORT_LEVEL": os.environ.get("DEEPSEEK_GEN_EFFORT", "high"),
        "MAX_THINKING_TOKENS": os.environ.get("DEEPSEEK_GEN_THINKING", "20000")}), model


def process(env_dir: Path, candidates: dict, client, args) -> tuple[str, str, str]:
    osv_id = env_dir.name
    if hasattr(client, "set_label"):       # HandoffBackend: names this candidate's request/response files
        rounds = len(list((env_dir / "attempts").glob("round_*"))) if (env_dir / "attempts").is_dir() else 0
        client.set_label(f"{osv_id}__r{rounds}" if rounds else osv_id)   # a regeneration must not replay old answers
    if ABORT.is_set():
        return osv_id, "failed", "aborted: quota exhausted earlier in this run"
    if already_done(env_dir):
        return osv_id, "skipped", "already generated"
    restore_upstream_patch(env_dir)
    try:
        ctx = build_context(env_dir, candidates)
    except ValueError as e:
        log.warning("[%s] cannot build context: %s", osv_id, e)
        if "too large" in str(e):      # a fixed property of the candidate: retire it, never retry
            (env_dir / UNSUITABLE_MARKER).write_text(str(e) + "\n")
        return osv_id, "failed", str(e)

    if args.dry_run:
        print(f"===== SYSTEM =====\n{SYSTEM_PROMPT}\n\n===== USER ({len(ctx.prompt)} chars) =====\n{ctx.prompt}")
        return osv_id, "skipped", "dry-run"

    repo = (ctx.meta.get("repo_url") or "").lower().rstrip("/")
    if (env_dir / "safeguards_flagged.txt").is_file():
        route = "Anthropic safeguards flagged this candidate earlier"
    elif repo and repo in flagged_repos(env_dir.parent, candidates):
        route = "Anthropic safeguards flagged another candidate of this repository"
    elif OFFENSIVE_REPO_RE.search(ctx.meta.get("repo_url", "") or ""):
        route = "offensive-security tool repository"
    elif FLAGS["n"] >= FLAG_LIMIT:
        route = f"{FLAGS['n']} safeguards flags earlier in this run"
    else:
        route = ""
    if route:
        if "safeguards flags earlier in this run" in route:          # a cluster this run: not the candidate's fault
            (env_dir / DEFERRED_MARKER).write_text(route + "\n")
            log.error("[%s] deferred: %s - safeguards flags are clustering; the user decides how to continue",
                      osv_id, route)
            return osv_id, "failed", f"deferred: {route}"
        (env_dir / UNSUITABLE_MARKER).write_text(f"retired: {route} (flagged candidates are not generated)\n")
        log.warning("[%s] retired without generation: %s", osv_id, route)
        return osv_id, "failed", f"unsuitable: retired: {route}"
    try:
        try:
            md, code, usage, task_meta, patches = generate(client, ctx, args.model, args.max_tokens,
                                                           args.max_attempts, args.fallback_model,
                                                           force_split=args.backend in ("cursor", "handoff", "deepseek")
                                                           and os.environ.get("GEN_SPLIT_ARTIFACTS", "auto").lower() != "0")
        except HandoffPending as e:
            # waiting for a Cursor agent to answer the request: not the candidate's fault, no strike (see _record_failures)
            (env_dir / DEFERRED_MARKER).write_text(f"waiting for handoff response: {e}\n")
            log.info("[%s] handoff request pending: %s", osv_id, e)
            return osv_id, "failed", f"deferred: handoff pending {e}"
        except SafeguardsFlagged as e:
            # never retried on any Claude model (fallback included) and not sent to another engine: retired
            with FLAGS_LOCK:
                FLAGS["n"] += 1
            try:
                (env_dir / "safeguards_flagged.txt").write_text(str(e))
            except OSError:
                pass
            log.error("[%s] Anthropic safeguards flagged the session (AUP, flag %d this run) - never retried on "
                      "Claude; candidate retired: %s", osv_id, FLAGS["n"], str(e)[:200])
            (env_dir / UNSUITABLE_MARKER).write_text("retired: Anthropic safeguards flag\n")
            return osv_id, "failed", "unsuitable: retired: Anthropic safeguards flag"
    except CandidateUnsuitable as e:   # rule 8: retired by stage 3 (generation_unsuitable.txt -> REJECTED)
        log.warning("[%s] generator declared the candidate unsuitable: %s", osv_id, e)
        (env_dir / UNSUITABLE_MARKER).write_text(f"generator: {e}\n")
        return osv_id, "failed", f"unsuitable: {e}"
    except GenerationInvalid as e:
        log.warning("[%s] FAILED validation: %s", osv_id, e)
        return osv_id, "failed", str(e)
    except SafeguardsFlagged as e:   # cannot come from the DeepSeek route; kept so a flag never crashes the run
        log.error("[%s] safeguards flag: %s", osv_id, str(e)[:200])
        return osv_id, "failed", f"safeguards flagged (AUP): {str(e)[:200]}"
    except QuotaExhausted as e:
        ABORT.set()
        log.error("[%s] model quota exhausted - stopping the run: %s", osv_id, e)
        return osv_id, "failed", f"quota exhausted: {e}"
    except Exception as e:  # API errors after SDK retries, auth, refusal, network...
        log.warning("[%s] API FAILURE (%s): %s", osv_id, type(e).__name__, e)
        return osv_id, "failed", f"{type(e).__name__}: {e}"

    ext = patches.pop("oracle_extension", "")
    if ext:
        try:
            merge_oracle_extension(env_dir, ext)
        except GenerationInvalid as e:
            log.warning("[%s] FAILED validation: %s", osv_id, e)
            return osv_id, "failed", str(e)
        task_meta["oracle_extension_files"] = parse_changed_files(ext)
        log.info("[%s] Pattern B: oracle extended beyond the upstream fix  files=%s", osv_id,
                 task_meta["oracle_extension_files"])
    try:
        write_atomic(env_dir / TESTS_NAME, code)
        write_atomic(env_dir / "task_metadata.json", json.dumps(task_meta, indent=2))
        (env_dir / CHECK_DIR).mkdir(exist_ok=True)
        for kind, diff in patches.items():
            write_atomic(env_dir / CHECK_DIR / f"{kind}.patch", diff)
        # handoff: the answer came from whatever model the Cursor operator selected (HANDOFF_MODEL), not args.model -
        # recording args.model would tag Grok-written tasks as Claude and corrupt the generator comparison
        model_used = (os.environ.get("HANDOFF_MODEL", "cursor-handoff (model not recorded)")
                      if args.backend == "handoff" else usage["models"][-1])
        write_atomic(env_dir / META_NAME, json.dumps({**usage, "model": model_used, "backend": args.backend,
                                                      "generator": ("handoff" if args.backend == "handoff"
                                                                    else "cursor" if args.backend == "cursor"
                                                                    else "deepseek" if (args.backend == "deepseek"
                                                                                        or usage.get("generator_route"))
                                                                    else "claude")},
                                                     indent=2))
        write_atomic(env_dir / INSTRUCTION_NAME, md)  # last: its presence marks completion
    except OSError as e:
        return osv_id, "failed", f"write error: {e}"
    log.info("[%s] generated (%d attempt(s), %d out tokens)", osv_id, usage["attempts"], usage["output_tokens"])
    return osv_id, "ok", ""


def load_candidates(path: Optional[Path]) -> dict[str, dict]:
    if not path:
        return {}
    data = json.loads(path.read_text())
    items = data.get("vulnerabilities", []) if isinstance(data, dict) else data
    return {i["osv_id"]: i for i in items if "osv_id" in i}


def load_api_key(env_file: Optional[Path]) -> None:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=env_file, override=False)  # None -> search upward from cwd
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise SystemExit("ANTHROPIC_API_KEY not found in environment or .env file")


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--environments", type=Path, default=Path("environments"))
    p.add_argument("--candidates", type=Path, help="Stage 1 JSON, supplies summary/CVE/CWE")
    p.add_argument("--env-file", type=Path, help=".env path (default: search upward from cwd)")
    p.add_argument("--backend", choices=("cli", "api", "cursor", "handoff", "deepseek"),
                   default=os.environ.get("TASK_GEN_BACKEND", "cli"),
                   help="cli = headless `claude -p` with the logged-in subscription (default); api = ANTHROPIC_API_KEY; "
                        "cursor = headless Cursor Agent CLI (`agent -p`) signed in with the Cursor account "
                        "(model: CURSOR_GEN_MODEL); deepseek = Claude Code CLI against DeepSeek's Anthropic-compatible "
                        "API (DEEPSEEK_API_KEY, model DEEPSEEK_GEN_MODEL), no Claude fallback")
    p.add_argument("--cursor-bin", default=os.environ.get("CURSOR_AGENT_BIN", "agent"))
    p.add_argument("--claude-bin", default=os.environ.get("CLAUDE_BIN", "claude"))
    p.add_argument("--model", default=os.environ.get("ANTHROPIC_MODEL", DEFAULT_MODEL))
    p.add_argument("--fallback-model", default=os.environ.get("GEN_FALLBACK_MODEL", "claude-opus-4-8"),
                   help="model used for a candidate after the primary model's output is stopped by the safety filter "
                        "('' = no fallback)")
    p.add_argument("--max-tokens", type=int, default=64000)
    p.add_argument("--max-attempts", type=int, default=3, help="regeneration attempts when validation rejects output")
    # below the 45-min step cap (was 3600: the cap killed slow calls first, so nothing was logged and they were retired)
    p.add_argument("--timeout", type=float, default=float(os.environ.get("GEN_CALL_TIMEOUT_SEC", "900")),
                   help="per-call timeout seconds; a slow call now fails loudly instead of silently using the window")
    p.add_argument("--workers", type=int, default=2)
    p.add_argument("--only", nargs="+", help="only these OSV IDs")
    p.add_argument("--dry-run", action="store_true", help="print the prompt, make no API call")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    if args.backend == "cursor":
        # Cursor models: their own model id (CURSOR_GEN_MODEL), and a fallback only if it is a Cursor model too
        # (the Claude fallback cannot be reached through this backend).
        args.model = os.environ.get("CURSOR_GEN_MODEL", "grok-4.7-high-fast")
        args.fallback_model = os.environ.get("CURSOR_GEN_FALLBACK_MODEL", "")
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)

    try:
        candidates = load_candidates(args.candidates)
    except (OSError, json.JSONDecodeError) as e:
        log.error("Cannot read candidates file: %s", e)
        return 2
    if not args.environments.is_dir():
        log.error("%s is not a directory", args.environments)
        return 2

    global LESSONS_TEXT
    try:
        from src.common.config import Config
        from src.common.knowledge import lessons_for_prompt
        LESSONS_TEXT = lessons_for_prompt(Config.load())
        if LESSONS_TEXT:
            log.info("Using lessons_learned.md (%d chars) in the generation prompt", len(LESSONS_TEXT))
    except Exception as e:  # lessons are an enhancement, never a blocker
        log.warning("Could not load lessons: %s", e)

    client = None
    if not args.dry_run:
        if args.backend == "cli":
            # Generation-only effort (2026-10-20): .env's CLAUDE_CODE_EFFORT_LEVEL=max made every Claude generation call
            # outlast the 45-min step cap (cycles 13-20: zero Claude-generated tasks finished). The same cause was fixed
            # for DeepSeek earlier ("max: 20+ min per call; high: 3-8 min").
            client = CliBackend(args.claude_bin, args.timeout, effort=os.environ.get("GEN_CLAUDE_EFFORT", "high"))
        elif args.backend == "deepseek":
            # user decision 2026-10-21: DeepSeek is the generator (Grok handoff retired). No Claude fallback, so every
            # task it produces is DeepSeek-authored and the contamination canary (knowledge.generator_canary) stays clean.
            client, args.model = deepseek_client(args) or (None, args.model)
            if client is None:
                log.error("TASK_GEN_BACKEND=deepseek needs DEEPSEEK_API_KEY")
                return 2
            args.fallback_model = ""
        elif args.backend == "handoff":
            client = HandoffBackend()
            args.fallback_model = ""          # a fallback would only queue a second request for the same answer
        elif args.backend == "cursor":
            from src.common.llm import CursorCliBackend
            client = CursorCliBackend(args.cursor_bin, args.timeout)
        else:
            load_api_key(args.env_file)
            client = ApiBackend(args.timeout)

    env_dirs = sorted(d for d in args.environments.iterdir()
                      if d.is_dir() and not d.name.startswith(".") and (d / PATCH_NAME).is_file())
    if args.only:
        env_dirs = [d for d in env_dirs if d.name in set(args.only)]
    log.info("%d environments found; backend=%s model=%s", len(env_dirs), args.backend, args.model)

    counts = {"ok": 0, "skipped": 0, "failed": 0}
    failures = []
    try:
        with ThreadPoolExecutor(max_workers=1 if args.dry_run else args.workers) as pool:
            futs = [pool.submit(process, d, candidates, client, args) for d in env_dirs]
            for fut in as_completed(futs):
                osv_id, status, detail = fut.result()
                counts[status] += 1
                if status == "failed":
                    failures.append((osv_id, detail))
    except KeyboardInterrupt:
        log.error("Interrupted")
        return 130

    log.info("Done: %d generated, %d skipped, %d failed", counts["ok"], counts["skipped"], counts["failed"])
    for osv_id, detail in failures:
        log.info("  failed: %s - %s", osv_id, detail[:200])
    return 0


if __name__ == "__main__":
    sys.exit(main())
