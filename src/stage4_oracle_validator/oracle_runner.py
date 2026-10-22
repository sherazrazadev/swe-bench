"""Stage 4 - Oracle validator.

For every stage-3 task (instruction.md + hidden_tests.py present):

  0. RUBRIC     LLM quality review (rubric_check.py) - cheap, runs before any Docker work.
                Failure => REJECTED_RUBRIC. (--skip-rubric to disable)
  1. BUILD      Harbor task `<env>/harbor_task` (packager).
  2. ORACLE     `harbor run -a oracle -k N`: solve.sh applies the human fix, then tests/test.sh.
                Every trial must score exactly 1.0 (partial scoring: 1.0 means every test passed).
  3. PRE-PATCH  `harbor run -a nop` (vulnerable repo untouched). Reward must be < 1.0 and, from ctrf.json:
                every test_security_* FAILS, every test_functional_* PASSES, both kinds actually ran
                (a collection error must not masquerade as a "fail").
  4. EXISTING   The repo's own tests for the affected code (tests/existing_files.txt) are run in both of the above.
                Those that pass on the oracle in every trial AND on the pre-patch code become the pass->pass set,
                recorded in tests/existing_expected.txt. A final oracle run confirms 1.0 with that set included.
  5. FIX CHECKS The three generated check patches are RUN against the tests (deterministic, no AI judge):
                shallow     (blocks only the reported trigger)  -> >= 1 security test passes AND >= 1 still fails
                removal     (disables / over-restricts feature) -> >= 1 functional or existing test fails
                alternative (correct fix, different design)     -> reward 1.0
                Each outcome also proves the patch really changed the code (it differs from the pre-patch run).
                A wrong outcome sends the task back to stage 3 with the exact failing tests as feedback.
  6. COVERAGE   Leave-one-file-out: the reference fix is run WITHOUT its change to one source file (the largest
                COVERAGE_MAX_FILES files). If every test still passes, an agent that never touches that file solves
                the task (the most common reason solved tasks were too easy) -> sent back with the file names while
                rewrite budget remains; on the last round only a warning.
  Isolation:    static audit of the task dir (only repo/ is copied, single snapshot commit, no fix lines or upstream
                regression tests in the tree or report, offline) + a scan of the BUILT image's whole filesystem for the
                fix's added lines (e.g. an already-fixed copy of the package inside node_modules / site-packages).

Outcomes (StateManager, stage "stage4_oracle_validator")
  DONE             validated; eligible for stage 5
  FAILED_ORACLE    terminal - tests wrong/flaky/unbuildable, or oracle/pre-patch behaviour is not as required
  REJECTED_RUBRIC  terminal - failed the task-quality rubric after --max-regen regeneration rounds
                   (earlier rejections archive the attempt to attempts/round_N and stage 3 regenerates with feedback)
  FAILED           no verdict (infra/harbor/quota trouble); retried, becomes FAILED_ORACLE after MAX_NO_VERDICT tries
"""
from __future__ import annotations

import argparse
import os
import json
import re
import logging
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from src.common.config import Config
from src.common.harbor import HarborUnavailable, Trial, preflight, read_trials, run_harbor
from src.common.llm import CliBackend, QuotaExhausted, SafeguardsFlagged
from src.common.logging_setup import configure_logging
from src.common.state_manager import StateManager, Status
from src.stage4_oracle_validator import plan_probe, recall_probe, rubric_check
from src.common import knowledge
from src.stage6_packager.harbor_packager import (TASK_DIRNAME, VERIFY_BUDGET_SEC, PackagingError, _link_or_copy, audit_task,
                                                 build_task, ensure_egress_image, load_meta,
                                                 ImageScanUnavailable, scan_image_for_fix)
from src.stage3_task_builder.task_generator import CHECK_DIR, CHECK_KINDS

log = logging.getLogger(__name__)

STAGE = "stage4_oracle_validator"
DOCKER_CAPACITY_MARKERS = ("fully subnetted", "Docker compose command failed", "Cannot connect to the Docker daemon",
                           "no space left on device")
MAX_NO_VERDICT = 2
REQUIRED_FILES = ("oracle_solution.patch", "instruction.md", "hidden_tests.py")


def last_part(name: str) -> str:
    return name.split("::")[-1]


@dataclass
class Verdict:
    ok: bool
    detail: str
    terminal: bool = True                 # False => no verdict was reached (retryable)
    status: Optional[Status] = None       # terminal status override (default FAILED_ORACLE)
    data: Optional[dict] = None
    feedback: str = ""                    # real pytest output -> sent back to the generator (test-design defects)


def pytest_feedback(trials: list[Trial], limit: int = 3500) -> str:
    """Condensed real pytest output (summary + distinct error lines) from the first trial that has it."""
    for t in trials:
        p = t.path / "verifier" / "test-stdout.txt"
        if not p.is_file():
            continue
        lines = p.read_text(errors="replace").splitlines()
        errs, seen, last_src = [], set(), ""
        for l in lines:
            if l.startswith(">"):
                last_src = l          # the source line that raised: shows HOW the test called the code
            elif l.startswith("E ") and l not in seen:
                seen.add(l)
                if last_src and last_src not in seen:
                    seen.add(last_src)
                    errs.append(last_src)
                errs.append(l)
        summary = []
        if "short test summary info" in "\n".join(lines):
            idx = max(i for i, l in enumerate(lines) if "short test summary info" in l)
            summary = lines[idx: idx + 30]
        text = "\n".join(summary + ["", "Distinct errors (with the test line that raised each):"] + errs[:40])
        return text[:limit]
    return ""


def check_oracle(trials: list[Trial], expected: int) -> Verdict:
    if len(trials) < expected:
        return Verdict(False, f"oracle run produced {len(trials)}/{expected} trials", terminal=False)
    undecided = [t for t in trials if t.reward is None]
    if undecided:
        return Verdict(False, "oracle run had no verdict: " + "; ".join(t.exception or "no reward file" for t in undecided),
                       terminal=False)
    bad = [t for t in trials if t.reward < 1.0]
    if bad:
        failed = sorted(n for t in bad for n, s in {**(t.ctrf or {}), **(t.ctrf_existing or {})}.items() if s != "passed")
        return Verdict(False, f"oracle does not pass its own tests (reward {[t.reward for t in bad]}, failing: {failed[:10] or 'unknown'})",
                       feedback="With the REFERENCE FIX applied, these hidden tests failed (they must all pass):\n" + pytest_feedback(bad))
    return Verdict(True, "oracle passes all tests")


def check_pre_patch(trials: list[Trial]) -> Verdict:
    if not trials or trials[0].reward is None:
        return Verdict(False, "pre-patch run had no verdict: " + (trials[0].exception or "no reward file" if trials else "no trial"),
                       terminal=False)
    t = trials[0]
    if t.reward >= 1.0:
        return Verdict(False, "tests pass on the vulnerable code - they do not detect the bug")
    if t.ctrf is None:
        log.warning("No ctrf.json on pre-patch run; per-test split not verified", extra={"trial": str(t.path)})
        return Verdict(True, f"pre-patch reward {t.reward} (per-test results unavailable)")
    sec = {n: s for n, s in t.ctrf.items() if last_part(n).startswith("test_security_")}
    fun = {n: s for n, s in t.ctrf.items() if last_part(n).startswith("test_functional_")}
    if not sec or not fun:
        return Verdict(False, f"pre-patch run did not execute both test kinds (security={len(sec)}, functional={len(fun)}) "
                              "- collection/import error?",
                       feedback="On the VULNERABLE code the tests did not run properly (collection/import error?):\n" + pytest_feedback(trials))
    sec_pass = sorted(last_part(n) for n, s in sec.items() if s == "passed")
    fun_bad = sorted(last_part(n) for n, s in fun.items() if s != "passed")
    if sec_pass:
        return Verdict(False, f"security tests that already pass on vulnerable code: {sec_pass}",
                       feedback="These security tests PASS on the vulnerable code, so they do not detect the bug:\n" + pytest_feedback(trials))
    if fun_bad:
        return Verdict(False, f"functional tests failing on vulnerable code (not pass->pass): {fun_bad}",
                       feedback="These functional tests FAIL on the vulnerable code (they must pass before and after the fix):\n" + pytest_feedback(trials))
    return Verdict(True, "pre-patch: security tests fail, functional tests pass")


def _split(t: Trial) -> tuple[dict[str, str], dict[str, str]]:
    sec = {last_part(n): s for n, s in (t.ctrf or {}).items() if last_part(n).startswith("test_security_")}
    fun = {last_part(n): s for n, s in (t.ctrf or {}).items() if last_part(n).startswith("test_functional_")}
    return sec, fun


def check_fix_patches(results: dict[str, list[Trial]], expected_existing: list[str]) -> Verdict:
    """Deterministic test-quality proof from running the three check patches (see module docstring, step 5)."""
    problems: list[str] = []
    for kind in CHECK_KINDS:
        trs = results.get(kind) or []
        if not trs or trs[0].reward is None or trs[0].ctrf is None:
            return Verdict(False, f"check patch {kind!r} produced no per-test verdict: "
                                  f"{(trs[0].exception if trs else 'no trial') or 'no reward/ctrf'}", terminal=False)
    sec_s, fun_s = _split(results["shallow"][0])
    passed = sorted(n for n, s in sec_s.items() if s == "passed")
    open_ = sorted(n for n, s in sec_s.items() if s != "passed")
    if not passed:
        problems.append("SHALLOW fix: no security test passes, so it does not even block the reported trigger. Write a "
                        "shallow fix that blocks exactly the reported case (and nothing more).")
    elif not open_:
        problems.append(f"SHALLOW fix passes EVERY security test ({len(passed)}): a band-aid on the reported trigger "
                        "is not caught. Add security variants that share the root cause but reach it another way "
                        "(sibling entry point, other encoding/normalisation, nested input, other call order) and that "
                        "this shallow fix leaves open - while the reference fix blocks them.")
    t = results["removal"][0]
    sec_r, fun_r = _split(t)
    existing_bad = [n for n in expected_existing if (t.ctrf_existing or {}).get(n) != "passed"]
    if all(s == "passed" for s in fun_r.values()) and not existing_bad:
        problems.append("FEATURE-REMOVAL fix passes every functional test: over-blocking is not caught. Add functional "
                        "tests for legitimate use close to the attack boundary that a disabled or over-restricted "
                        "feature fails.")
    t = results["alternative"][0]
    if t.reward < 1.0:
        failing = sorted(n for n, s in {**(t.ctrf or {}), **(t.ctrf_existing or {})}.items() if s != "passed")
        problems.append(f"ALTERNATIVE correct fix scores {t.reward:.2f}; failing: {[last_part(n) for n in failing][:10]}. "
                        "Either the tests are bound to the reference patch's design (make them check only what a "
                        "caller can observe) or the alternative fix is incomplete (fix it). Real output:\n"
                        + pytest_feedback([t], 1500))
    if problems:
        return Verdict(False, "fix checks: " + " | ".join(p.split(".")[0] for p in problems)[:600],
                       feedback="FIX-CHECK - the pipeline RAN your three check patches against your hidden tests:\n- "
                                + "\n- ".join(problems))
    return Verdict(True, f"fix checks: shallow leaves {len(open_)}/{len(sec_s)} security tests open, removal breaks "
                         f"legitimate use, alternative fix scores 1.0")


def run_fix_checks(env_dir: Path, task: Path, cfg: Config, vdir: Path, stamp: str, timeout: int) -> Verdict:
    """Run each check patch as the 'oracle' of a scratch copy of the task (hardlinked; same Docker build cache)."""
    results: dict[str, list[Trial]] = {}
    for kind in CHECK_KINDS:
        patch = env_dir / CHECK_DIR / f"{kind}.patch"
        if not patch.is_file():
            return Verdict(False, f"missing {CHECK_DIR}/{kind}.patch",
                           feedback="FIX-CHECK - this task has no check patches. Produce the <check_patches_json> block.")
        copy = vdir / "check_tasks" / kind
        shutil.rmtree(copy, ignore_errors=True)
        shutil.copytree(task, copy, symlinks=True, copy_function=_link_or_copy)
        (copy / "solution" / "oracle_solution.patch").unlink()
        shutil.copy2(patch, copy / "solution" / "oracle_solution.patch")
        results[kind] = read_trials(run_harbor(cfg.harbor_bin, copy, "oracle", vdir, f"check-{kind}-{stamp}", attempts=1,
                                               concurrent=1, timeout=timeout, log_path=vdir / f"check-{kind}-{stamp}.log"))
    expected = [l.strip() for l in (task / "tests" / "existing_expected.txt").read_text().splitlines() if l.strip()]
    return check_fix_patches(results, expected)


# 4 left most places of a wide fix unproven (9router: agent changed 1 of 12 fix files and scored 1.0). Each check is one
# oracle run (~2-3 min); 8 keeps a wide task's validation under ~25 min.
COVERAGE_MAX_FILES = int(os.environ.get("COVERAGE_MAX_FILES", "8"))
NON_SOURCE = re.compile(r"(^|/)(tests?|__tests__|spec|fixtures?|docs?|examples?|testdata)/|[._-](test|spec)\.|"
                        r"\.(md|rst|txt|json|ya?ml|toml|lock|snap)$|(^|/)CHANGELOG|\.d\.ts$", re.I)


def split_patch(patch: str) -> list[tuple[str, str, int]]:
    """[(file, chunk, changed lines)] per `diff --git` section."""
    out = []
    for ch in re.split(r"(?m)^(?=diff --git )", patch):
        m = re.match(r"diff --git a/(\S+) b/(\S+)", ch)
        if m:
            out.append((m.group(2), ch, len(re.findall(r"(?m)^[+-](?![+-]{2} )", ch))))
    return out


def run_coverage_checks(env_dir: Path, task: Path, cfg: Config, vdir: Path, stamp: str, timeout: int,
                        can_rewrite: bool = True) -> list[str]:
    """Source files of the reference fix whose change no test needs (fix minus that file still scores 1.0)."""
    chunks = split_patch((env_dir / "oracle_solution.patch").read_text(errors="replace"))
    trap_paths: set = set()
    try:   # only the files the generator declared as part of the security fix (commits bundle unrelated changes)
        tmeta = json.loads((env_dir / "task_metadata.json").read_text())
        places = set(tmeta.get("fix_places") or [])
        trap_paths = set((tmeta.get("trap") or {}).get("paths") or [])
    except (OSError, ValueError):
        places = set()
    if places:
        src = [c for c in chunks if c[0] in places and not NON_SOURCE.search(c[0])]
    elif can_rewrite:
        # tasks generated before fix_places existed: the largest source files (a rewrite then declares fix_places,
        # so a bundled unrelated file costs one rewrite at most). react-router was solved changing 2 of 7.
        src = [c for c in chunks if not NON_SOURCE.search(c[0]) and c[2] >= 6]
    else:
        log.info("Coverage check skipped (no fix_places, no rewrite left)", extra={"osv_id": env_dir.name})
        return []
    if len(src) < 2:
        return []
    uncovered = []
    # declared trap paths first: the trap is only real if the tests provably fail when that file is left unfixed
    for f, _, _ in sorted(src, key=lambda c: (c[0] not in trap_paths, -c[2]))[:COVERAGE_MAX_FILES]:
        name = "lofo-" + re.sub(r"[^a-z0-9]+", "-", Path(f).stem.lower())[:24]
        copy = vdir / "check_tasks" / name
        shutil.rmtree(copy, ignore_errors=True)
        shutil.copytree(task, copy, symlinks=True, copy_function=_link_or_copy)
        (copy / "solution" / "oracle_solution.patch").unlink()
        (copy / "solution" / "oracle_solution.patch").write_text("".join(ch for g, ch, _ in chunks if g != f))
        trs = read_trials(run_harbor(cfg.harbor_bin, copy, "oracle", vdir, f"{name}-{stamp}", attempts=1, concurrent=1,
                                     timeout=timeout, log_path=vdir / f"{name}-{stamp}.log"))
        r = trs[0].reward if trs else None
        log.info("Coverage check", extra={"osv_id": env_dir.name, "left_out": f, "reward": r})
        if r is not None and r >= 1.0:
            uncovered.append(f)
    return uncovered


DESIGN_TOK = re.compile(r"[A-Za-z_][A-Za-z0-9_]{4,}")
# probing for members a fix might add: a literal member name (checked against the vulnerable repo) or a dynamic one
PROBE_LITERAL_RE = re.compile(r"""\b(?:getattr|hasattr)\([^,()]+,\s*['"](\w+)['"]|(?:FieldByName|MethodByName)\(\s*"(\w+)"|"""
                              r"""Reflect\.has\([^,()]+,\s*['"](\w+)['"]""")
PROBE_DYNAMIC_RE = re.compile(r"(?:FieldByName|MethodByName)\(\s*[A-Za-z_]\w*\s*\)")


def design_bound_names(env_dir: Path, tests: Optional[str] = None, report: Optional[str] = None
                       ) -> tuple[list[str], list[str]]:
    """(code-like names the hidden tests use that exist only in the reference fix's added SOURCE code - not in the
    vulnerable repo, not in the report; probing constructs). Either makes a test pass only on the reference design
    (infracost GHSA-6x6c: `TrustedHosts`, `TG_TF_DEFAULT_REGISTRY_HOST`). `tests`/`report` default to the files on disk;
    stage 3 passes its draft to run the same check at generation time."""
    from src.common.classify import is_test_path
    tests = tests if tests is not None else (env_dir / "hidden_tests.py").read_text(errors="replace")
    report = (report if report is not None else (env_dir / "instruction.md").read_text(errors="replace")).lower()
    added = []
    for ch in re.split(r"(?m)^(?=diff --git )", (env_dir / "oracle_solution.patch").read_text(errors="replace")):
        m = re.match(r"diff --git a/\S+ b/(\S+)", ch)
        if m and not is_test_path(m.group(1)):
            added += [l[1:] for l in ch.splitlines() if l.startswith("+") and not l.startswith("+++")]
    defined = {a or b for a, b in re.findall(
        r"(?:def|func|class|const|var|let|function)\s+([A-Za-z_]\w*)|\b([A-Za-z_]\w*)\s*:?=", tests)}
    code_like = lambda n: bool(re.search(r"[a-z][A-Z]|_|^[A-Z][A-Z0-9]+$", n))
    cand = (set(DESIGN_TOK.findall(tests)) & set(DESIGN_TOK.findall("\n".join(added)))) - defined

    def in_repo(name: str) -> bool:
        return subprocess.run(["git", "grep", "-q", "-w", "-F", name, "HEAD"], cwd=env_dir / "repo",
                              capture_output=True).returncode == 0
    names = sorted(n for n in cand if code_like(n) and n.lower() not in report and not in_repo(n))
    # Python-stdlib members the test HARNESS itself touches (subprocess results, paths): not probes for fix-added
    # members, and absent from non-Python repos by nature (false positive: Ghost GHSA-9m84, 2026-10-20).
    harness_attrs = {"returncode", "stdout", "stderr", "args", "pid", "name", "parent", "stem", "suffix"}
    probes = sorted(({"".join(g) for g in PROBE_LITERAL_RE.findall(tests) if not in_repo("".join(g))}
                     | set(PROBE_DYNAMIC_RE.findall(tests))) - harness_attrs)
    return names, probes


def trap_violations(env_dir: Path) -> list[str]:
    """Re-verify the generator's declared trap (task_metadata.json "trap") against the artifacts on disk - stage 3
    already validated it, but a rewrite can drift. Tasks generated before the trap gate have no "trap" field and are
    skipped (backward compatible with cycle <= 11)."""
    try:
        tmeta = json.loads((env_dir / "task_metadata.json").read_text())
    except (OSError, ValueError):
        return []
    trap = tmeta.get("trap") or {}
    paths = trap.get("paths") or []
    if not paths:
        return []
    out = []
    places = set(tmeta.get("fix_places") or [])
    report = (env_dir / "instruction.md").read_text(errors="replace").lower()
    missing = [p for p in paths if not (env_dir / "repo" / p).is_file()]
    if missing:
        out.append(f"trap paths not in the pre-patch repo: {missing}")
    outside = [p for p in paths if p not in places]
    if outside:
        out.append(f"trap paths not in fix_places (coverage check cannot prove them): {outside}")
    named = [p for p in paths
             if re.search(r"(?<![a-z0-9_])" + re.escape(Path(p).stem.lower()) + r"(?![a-z0-9_])", report)]
    if named:
        out.append(f"the report names the trap file(s): {named}")
    return out


def derive_existing_expected(oracle_trials: list[Trial], prepatch: Trial) -> list[str]:
    """Existing tests that pass in EVERY oracle trial and on the pre-patch code (true pass->pass).
    Names that do not survive existing_expected.txt's one-stripped-name-per-line format (a parametrised title ending
    in a space, an embedded newline) are left out: the grader would read them back as a different, missing test."""
    def passed(t: Trial) -> set[str]:
        return {n for n, s in (t.ctrf_existing or {}).items() if s == "passed" and n == n.strip() and "\n" not in n}
    sets = [passed(t) for t in oracle_trials] + [passed(prepatch)]
    return sorted(set.intersection(*sets)) if sets else []


def validate_task(env_dir: Path, cfg: Config, meta: dict, args: argparse.Namespace,
                  backend: Optional[CliBackend]) -> Verdict:
    osv_id = env_dir.name
    names, probes = design_bound_names(env_dir)
    if names or probes:      # deterministic and cheap: before the rubric and any Docker work
        what = (f"names that exist only in the reference fix: {names}" if names else "") + \
               ("; " if names and probes else "") + (f"probing for guessed fields/attributes: {probes}" if probes else "")
        return Verdict(False, f"tests bound to the reference design ({what})"[:600], feedback=(
            f"TEST DESIGN - the hidden tests use {what}. A test may only use interfaces that exist in the vulnerable "
            "code and behaviour the report asks for, so that ANY correct fix passes it (rule 7). Remove these names "
            "and probes; if the behaviour they check matters, state it in the report and observe it through an "
            "existing entry point."))
    trap_bad = trap_violations(env_dir)   # deterministic, trap-gated tasks only (metadata.trap present)
    if trap_bad:
        return Verdict(False, f"trap evidence failed: {'; '.join(trap_bad)}"[:600], feedback=(
            "TRAP EVIDENCE - metadata.trap must name real pre-patch source files, each also in metadata.fix_places, "
            f"and the report must not name them: {'; '.join(trap_bad)}. Fix the metadata or rewrite the report."))
    prior = env_dir / "rubric_check.json"
    task_files = [env_dir / n for n in ("instruction.md", "hidden_tests.py")]
    reuse = (prior.is_file() and json.loads(prior.read_text()).get("passed")
             and all(prior.stat().st_mtime >= f.stat().st_mtime for f in task_files))
    if reuse:
        log.info("Rubric: reusing earlier pass (task files unchanged)", extra={"osv_id": osv_id})
    elif backend is not None:
        rubric = rubric_check.check_task(env_dir, backend, args.model)
        if not rubric.passed:
            return Verdict(False, "rubric: " + "; ".join(rubric.blocking_issues)[:700], status=Status.REJECTED_RUBRIC)

    probe_note = ""
    if not args.skip_probe:
        try:
            pr = recall_probe.probe(env_dir, cfg.eval_endpoints())
            probe_note = f"recall risk {pr['risk']}"
            knowledge.record_outcome(cfg, osv_id, STAGE, "recall_probe", probe_note,
                                     recall_probe={t: bool(v.get("file_hit")) for t, v in pr["models"].items()})
            log.info("Recall probe", extra={"osv_id": osv_id, "risk": pr["risk"]})
            if pr["risk"] == "high" and args.probe_reject:
                return Verdict(False, "recall probe: both models name the fix location from the report alone",
                               status=Status.REJECTED)
        except Exception as e:      # advisory step: never block validation because the probe could not run
            log.warning("Recall probe skipped", extra={"osv_id": osv_id, "error": str(e)[:200]})

    task = env_dir / TASK_DIRNAME
    try:
        net_mode, net_hosts = cfg.agent_network_policy()
        if net_mode == "proxy":
            ensure_egress_image()
        build_task(env_dir, task, meta.get(osv_id, {}), agent_network=net_mode, allowed_hosts=tuple(net_hosts),
                   preinstall_claude_code=cfg.preinstall_claude_code, cpus=cfg.task_cpus, memory_mb=cfg.task_memory_mb,
                   agent_timeout=cfg.agent_timeout_sec)
    except PackagingError as e:
        return Verdict(False, f"packaging: {e}")

    net_mode, net_hosts = cfg.agent_network_policy()
    oracle_patch = (env_dir / "oracle_solution.patch").read_text(errors="replace")
    issues = audit_task(task, oracle_patch, net_mode, tuple(net_hosts))
    scanned = False
    if not issues and not args.skip_image_scan:
        try:
            issues = scan_image_for_fix(task, oracle_patch)
            scanned = True
        except ImageScanUnavailable as e:      # no verdict (retried later): a scan that did not run is not "clean"
            (env_dir / "isolation_audit.json").write_text(json.dumps({"issues": issues, "image_scanned": False,
                                                                      "scan_error": str(e)}, indent=2))
            return Verdict(False, f"image scan could not run: {e}", terminal=False)
    (env_dir / "isolation_audit.json").write_text(json.dumps({"issues": issues, "image_scanned": scanned}, indent=2))
    if issues:
        return Verdict(False, "isolation audit: " + "; ".join(issues)[:600])

    vdir = env_dir / "validation"
    stamp = time.strftime("%Y%m%d-%H%M%S")
    per_run = VERIFY_BUDGET_SEC + 1500          # image build + oracle/nop agent + the full verifier budget
    run = lambda agent, name, k: run_harbor(cfg.harbor_bin, task, agent, vdir, f"{name}-{stamp}", attempts=k,
                                            concurrent=1, timeout=max(args.timeout, k * per_run),
                                            log_path=vdir / f"{name}-{stamp}.log")
    oracle_trials = read_trials(run("oracle", "oracle", args.oracle_repeats))
    v = check_oracle(oracle_trials, args.oracle_repeats)
    if not v.ok:
        return v
    pre_trials = read_trials(run("nop", "prepatch", 1))
    v = check_pre_patch(pre_trials)
    if not v.ok:
        return v

    existing_files = [l for l in (task / "tests" / "existing_files.txt").read_text().splitlines() if l.strip()]
    expected = derive_existing_expected(oracle_trials, pre_trials[0])
    (task / "tests" / "existing_expected.txt").write_text("".join(n + "\n" for n in expected))
    if expected:
        confirm = check_oracle(read_trials(run("oracle", "oracle-final", 1)), 1)
        if not confirm.ok:
            return Verdict(False, "oracle fails once the existing-test set is enforced: " + confirm.detail,
                           terminal=confirm.terminal)
    elif args.require_existing:
        return Verdict(False, f"out of spec: no usable existing tests of the affected code (candidate files: "
                              f"{len(existing_files)}; repos whose test runner we cannot run yet end here too)")
    fix_note = "fix checks skipped"
    if not args.skip_fix_checks:
        fc = run_fix_checks(env_dir, task, cfg, vdir, stamp, max(args.timeout, per_run))
        if not fc.ok:
            return fc
        fix_note = fc.detail
    rounds = len(list((env_dir / "attempts").glob("round_*"))) if (env_dir / "attempts").is_dir() else 0
    uncovered = run_coverage_checks(env_dir, task, cfg, vdir, stamp, max(args.timeout, per_run),
                                    can_rewrite=rounds < args.max_regen)
    if uncovered:
        files = ", ".join(uncovered)
        if rounds < args.max_regen:
            return Verdict(False, f"coverage: reference fix minus {files} still scores 1.0",
                           feedback=(f"COVERAGE - the pipeline ran the reference fix WITHOUT its changes to: {files}. "
                                     "Every hidden test still passed (reward 1.0), so an agent that never touches "
                                     "these files solves the task - the most common reason earlier tasks were "
                                     "solved. For each file: find the attack path that only its change blocks and "
                                     "add a test_security_* reaching it from a real public entry point (and, if that "
                                     "path is legitimate for other inputs, a functional test that keeps it working). "
                                     "Do not test the file directly or by internal names."))
        log.warning("Coverage gap kept (no rewrite budget left)", extra={"osv_id": osv_id, "files": files})
        fix_note += f"; coverage gap: {files}"
    elif not args.skip_fix_checks:
        fix_note += "; every large fix file needed"
    note = f"existing pass->pass tests: {len(expected)} (from {len(existing_files)} candidate files); {fix_note}"
    if not expected:
        log.warning("Task has no existing-test coverage; relies on generated functional tests only", extra={"osv_id": osv_id})
    return Verdict(True, f"oracle 1.0, pre-patch fails as required; {note}", data={"existing_expected": len(expected)})


def process(env_dir: Path, cfg: Config, meta: dict, state: StateManager, args: argparse.Namespace,
            backend: Optional[CliBackend], abort: "list[bool]") -> str:
    osv_id = env_dir.name
    if abort:
        return "failed"
    try:
        v = validate_task(env_dir, cfg, meta, args, backend)
    except QuotaExhausted as e:
        abort.append(True)
        log.error("Claude quota exhausted - stopping stage 4 (resume later): %s", e)
        return "failed"
    except HarborUnavailable as e:
        state.mark(STAGE, osv_id, Status.FAILED, str(e))
        return "failed"
    except SafeguardsFlagged as e:
        # The rubric reviewer (Claude) was safeguards-flagged. Terminal: a FAILED status would retry it next run and send
        # the same flagged material to Claude again. The marker also makes the picker skip this repo's other candidates.
        try:
            (env_dir / "safeguards_flagged.txt").write_text(f"stage 4 rubric: {e}")
        except OSError:
            pass
        log.error("Anthropic safeguards flagged the rubric review - never retried on Claude; task retired",
                  extra={"osv_id": osv_id, "error": str(e)[:200]})
        state.mark(STAGE, osv_id, Status.REJECTED, "safeguards flagged during the rubric review (never retried on Claude)")
        return "failed"
    except Exception as e:
        log.exception("validator crashed", extra={"osv_id": osv_id})
        state.mark(STAGE, osv_id, Status.FAILED, f"unexpected: {e!r}")
        return "failed"

    record = {"osv_id": osv_id, "ok": v.ok, "detail": v.detail, "data": v.data,
              "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    (env_dir / "oracle_validation.json").write_text(json.dumps(record, indent=2))
    knowledge.record_outcome(cfg, osv_id, STAGE, "validated" if v.ok else (v.status.value if v.status else "failed_oracle"),
                             v.detail, existing_expected=(v.data or {}).get("existing_expected"))
    if v.ok:
        # Pre-trial plan probe (2026-10-20): skip tasks the target models already see through (see plan_probe.py)
        if plan_probe.mode() != "off":
            try:
                pp = plan_probe.decide(env_dir, (meta.get(osv_id) or {}).get("ecosystem", ""), cfg.eval_endpoints())
            except Exception as e:      # fail open: the probe must never block a validated task by crashing
                pp = {"verdict": "trial", "why": f"probe crashed: {e!r}"[:200]}
            log.info("Plan probe", extra={"osv_id": osv_id, "verdict": pp["verdict"], "why": pp.get("why", "")})
            if pp["verdict"] == "skip" and plan_probe.mode() == "gate":
                why = f"predicted easy by the plan probe: {pp.get('why', '')}"
                state.mark(STAGE, osv_id, Status.REJECTED, why)
                knowledge.record_outcome(cfg, osv_id, STAGE, "rejected_predicted_easy", why)
                log.warning("Skipped before the trial (predicted easy)", extra={"osv_id": osv_id, "why": why})
                return "rejected"
        state.mark(STAGE, osv_id, Status.DONE, v.detail)
        log.info("Validated", extra={"osv_id": osv_id, "detail": v.detail})
        return "ok"
    if not v.ok and v.terminal and v.feedback and archive_for_regeneration(env_dir, args.max_regen, v.feedback):
        log.warning("Tests failed real execution; archived for regeneration with pytest feedback",
                    extra={"osv_id": osv_id, "reason": v.detail[:300]})
        return "regenerate"
    if v.status is Status.REJECTED_RUBRIC and archive_for_regeneration(env_dir, args.max_regen):
        log.warning("Rubric rejected; archived for regeneration (rerun stage 3 then 4)", extra={"osv_id": osv_id, "reason": v.detail[:300]})
        return "regenerate"
    if v.terminal:
        status = v.status or Status.FAILED_ORACLE
        state.mark(STAGE, osv_id, status, v.detail)
        log.warning(status.value.upper(), extra={"osv_id": osv_id, "reason": v.detail})
        return "rejected" if status is Status.REJECTED_RUBRIC else "failed_oracle"
    if any(m in v.detail for m in DOCKER_CAPACITY_MARKERS):
        # Docker itself ran out of resources (address pools, daemon): not the task's fault, never a strike against it
        state.reset(STAGE, osv_id)
        log.warning("No verdict (Docker capacity) - requeued without a strike", extra={"osv_id": osv_id, "reason": v.detail[:200]})
        return "failed"
    rec = state.get(STAGE, osv_id)
    tries = (rec.attempts if rec else 0) + 1
    status = Status.FAILED_ORACLE if tries >= MAX_NO_VERDICT else Status.FAILED
    state.mark(STAGE, osv_id, status, v.detail)
    log.warning("No verdict", extra={"osv_id": osv_id, "reason": v.detail, "try": tries, "status": status.value})
    return "failed_oracle" if status is Status.FAILED_ORACLE else "failed"


def archive_for_regeneration(env_dir: Path, max_regen: int, execution_feedback: str = "") -> bool:
    """Move a rubric-rejected attempt to attempts/round_N so stage 3 regenerates it with the reviewer's feedback.
    Returns False when the regeneration budget is used up (the rejection then becomes terminal)."""
    attempts = env_dir / "attempts"
    done = len(list(attempts.glob("round_*"))) if attempts.is_dir() else 0
    if done >= max_regen:
        return False
    dest = attempts / f"round_{done + 1}"
    dest.mkdir(parents=True)
    for name in ("instruction.md", "hidden_tests.py", "task_metadata.json", "rubric_check.json", "generation_meta.json"):
        if (env_dir / name).is_file():
            (env_dir / name).replace(dest / name)
    if (env_dir / CHECK_DIR).is_dir():
        (env_dir / CHECK_DIR).replace(dest / CHECK_DIR)
    if execution_feedback:
        (dest / "execution_feedback.txt").write_text(execution_feedback)
    return True


def discover(env_root: Path, only: Optional[list[str]]) -> list[Path]:
    dirs = sorted(d for d in env_root.iterdir()
                  if d.is_dir() and not d.name.startswith(".") and all((d / f).is_file() for f in REQUIRED_FILES))
    return [d for d in dirs if not only or d.name in set(only)]


def parse_args(argv: Optional[list[str]], cfg: Config) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Stage 4: rubric-check and oracle-validate generated tasks")
    p.add_argument("--only", nargs="+")
    p.add_argument("--oracle-repeats", type=int, default=2, help="oracle runs per task; >1 catches flaky tests")
    p.add_argument("--workers", type=int, default=1, help="parallel tasks (Docker builds are heavy)")
    p.add_argument("--timeout", type=int, default=3600, help="seconds per harbor invocation")
    p.add_argument("--skip-rubric", action="store_true", help="skip the LLM quality rubric")
    p.add_argument("--skip-probe", action="store_true", help="skip the text-only recall probe")
    p.add_argument("--probe-reject", action=argparse.BooleanOptionalAction, default=True,
                   help="reject a task when BOTH models name the fix location from the report alone (default on)")
    p.add_argument("--require-existing", action=argparse.BooleanOptionalAction,
                   default=os.environ.get("REQUIRE_EXISTING_TESTS", "1") != "0",
                   help="reject tasks with no usable existing repo tests (task spec: functional tests = existing tests "
                        "of the affected code + legitimate-use cases; default on, --no-require-existing to allow)")
    p.add_argument("--skip-fix-checks", action="store_true",
                   help="do not run the shallow / feature-removal / alternative check patches (not recommended)")
    p.add_argument("--skip-image-scan", action="store_true",
                   help="do not scan the built image for the fix's code (not recommended)")
    p.add_argument("--model", default=cfg.anthropic_model, help="Claude model for the rubric reviewer")
    p.add_argument("--max-regen", type=int, default=2, help="rubric rejections that trigger regeneration with feedback before rejecting for good")
    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None, cfg: Optional[Config] = None) -> int:
    cfg = cfg or Config.load()
    args = parse_args(argv, cfg)
    if not logging.getLogger().handlers:
        configure_logging()

    meta = load_meta(cfg)
    with StateManager(cfg.state_db) as state:
        tasks = [d for d in discover(cfg.stage_dir(3), args.only) if state.should_process(STAGE, d.name, MAX_NO_VERDICT)]
        log.info("Validating", extra={"tasks": len(tasks)})
        if not tasks:
            return 0
        try:
            preflight(cfg.harbor_bin)
        except HarborUnavailable as e:
            log.error("Stage 4 cannot run: %s", e)
            return 1
        # DeepSeek's CoT for a full rubric can exceed 15 min; the output cap is in rubric_check.py.
        # rubric-only effort (2026-10-20): .env's CLAUDE_CODE_EFFORT_LEVEL=max kept two rubric reviews running 30 min
        # (the same failure generation had); the reply is a short JSON verdict
        backend = None
        if not args.skip_rubric:     # REVIEW_BACKEND (default mimo, 2026-10-22): no Claude quota in the pipeline
            from src.common.llm import reviewer_backend
            backend, args.model = reviewer_backend(cfg, float(os.environ.get("RUBRIC_TIMEOUT_SEC", "900")),
                                                   effort=os.environ.get("RUBRIC_CLAUDE_EFFORT", "high"))
        abort: list[bool] = []
        counts = {"ok": 0, "failed_oracle": 0, "rejected": 0, "regenerate": 0, "failed": 0}
        try:
            with ThreadPoolExecutor(max_workers=args.workers) as pool:
                for outcome in pool.map(lambda d: process(d, cfg, meta, state, args, backend, abort), tasks):
                    counts[outcome] += 1
        except KeyboardInterrupt:
            log.error("Interrupted")
            return 130
        log.info("Stage 4 done", extra=counts)
        rows = []
        for d in tasks:
            vf = d / "oracle_validation.json"
            if vf.is_file():
                r = json.loads(vf.read_text())
                rows.append([d.name, "ok" if r["ok"] else "REJECTED", r["detail"]])
        knowledge.append_results(cfg, "Stage 4 - rubric + oracle validation", ["task", "verdict", "detail"], rows,
                                 notes="counts: " + json.dumps(counts))
        return 1 if abort else 0


if __name__ == "__main__":
    sys.exit(main())
