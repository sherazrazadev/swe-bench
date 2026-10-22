"""Pre-build plan gate (stage 3): reject easy or unfair candidates BEFORE the Docker build check and full generation.

Runs after environment_builder (repo checkout + oracle patch, cheap) and before build_check (Docker, up to 30 min) and
task_generator (two long DeepSeek calls). Measured motivation (2026-10-21): 37 of 41 trialled tasks were solved, 10 of 29
stage-3 rejections were Docker builds and 8 were generation timeouts - all spent before anyone asked whether the design
could be hard. Steps, cheapest first; the first rejection ends the gate:

  1. heuristic  (No AI)   fix shape from the oracle patch + weakness class (screener.CWE_CLASS). Rejects only the
                          cwe-bench "control" profile: an easy class (single-sink injection, open redirect, prototype
                          pollution, path traversal) fixed in one compact place, or a fix that only adds new files.
  2. plan draft (DeepSeek) a short JSON design: report sketch, hidden places + mechanism (M4/M6/M2/M10/M5/M11), coupled
                          contract, and a SELF-ATTACK - the repair DeepSeek itself would write from the sketch.
  3. self-solve (DeepSeek + MiMo) the sketch + the repo's source-file LIST (no contents), same probe as stage 4's
                          plan_probe: if EVERY measured target names EVERY hidden place, the trap is visible: too_easy.
  4. review     (Claude)  proceed | too_easy | unfair, on fixed criteria. A non-target model: DeepSeek must not grade
                          its own design. A safeguards flag retires the candidate (standing rule, never retried).

PLAN_GATE=gate (default: rejections are final for stage 3) | advisory (record only) | off. Model errors fail OPEN (the
candidate proceeds, the error is recorded), like plan_probe. Verdicts are cached in <env>/plan_gate.json; an approved
plan is fed to the generator (task_generator.approved_plan_section).
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath
from typing import Any, Optional

from src.common.classify import classify
from src.common.config import Config
from src.common.llm import CliBackend, SafeguardsFlagged, extract_json_object
from src.common.state_manager import StateManager, Status
from src.stage2_screening.screener import PRODUCER_FILE_RE, cwe_class
from src.stage4_oracle_validator import plan_probe

log = logging.getLogger(__name__)

STAGE = "stage3_task_builder"
GATE_FILE = "plan_gate.json"
FINAL = ("proceed", "too_easy", "unfair", "unsuitable")
EASY_CLASSES = {"open_redirect", "prototype_pollution", "injection_single_sink", "path_traversal"}
GENERIC_STEMS = {"index", "init", "__init__", "main", "mod", "utils", "util", "helpers", "types", "config", "constants"}
MAX_PATCH_CHARS = 40_000
MAX_LIST_CHARS = 40_000
# Ranked by misses BY BOTH models (our acceptance needs both): M6 24%, coupled 20%, M4 18%; M2 only 5%, M1 2%
# (colleague's 471 measured traps, skills/task_design_techniques.md). M2/M1 are allowed only next to one of these.
STRONG = {"M4", "M6", "M10", "M5", "M11"}
REDRAFTS = int(os.environ.get("PLAN_GATE_REDRAFTS", "2"))


def mode() -> str:
    return os.environ.get("PLAN_GATE", "gate").strip().lower()


# --------------------------------------------------------------------------- #
# 1. Heuristic (No AI)
# --------------------------------------------------------------------------- #
def fix_shape(patch: str, ecosystem: str) -> dict[str, Any]:
    chunks = re.split(r"(?m)^(?=diff --git )", patch)
    files, new = [], set()
    for ch in chunks:
        m = re.match(r"diff --git a/\S+ b/(\S+)", ch)
        if not m or classify(m.group(1), ecosystem) != "source":
            continue
        files.append(m.group(1))
        if re.search(r"(?m)^new file mode", ch[:400]):
            new.add(m.group(1))
    existing = [f for f in files if f not in new]
    dirs = sorted({str(PurePosixPath(f).parent) for f in existing})
    by_name: dict[str, set] = {}
    for f in existing:
        p = PurePosixPath(f)
        if p.stem.lower() not in GENERIC_STEMS:
            by_name.setdefault(p.name, set()).add(str(p.parent))
    return {"source_files": files, "existing_source_files": existing, "dirs": dirs,
            "parallel_implementation": any(len(d) >= 2 for d in by_name.values()),
            "producer_and_check": any(PRODUCER_FILE_RE.search(PurePosixPath(f).name) for f in existing) and len(dirs) >= 2}


def probe_file_list(files: list[str], shape: dict, cap: int = MAX_LIST_CHARS) -> tuple[list[str], str]:
    """A capped but REPRESENTATIVE source-file list for the plan draft and the self-solve probe.

    Big repos are the good candidates (LibreNMS 5343 files / 270k chars, pimcore 1497 / 77k), but a raw list blows past
    any sane prompt budget. Failing open there made the gate inert exactly where it matters (2026-10-21), so instead the
    list is built priority-first:
      1. every file in a directory the reference fix touches - so each hidden place is certainly in the list, and a probe
         that still cannot name it proves the trap is hidden rather than merely absent from the prompt;
      2. then the remaining source files, nearest directories first, until the cap.
    Returns (files, note). The note goes into plan_gate.json so a truncated probe is never mistaken for a full one."""
    fix_dirs = {str(PurePosixPath(f).parent) for f in shape.get("existing_source_files") or []}
    near = [f for f in files if str(PurePosixPath(f).parent) in fix_dirs]
    rest = sorted((f for f in files if str(PurePosixPath(f).parent) not in fix_dirs),
                  key=lambda f: (len(PurePosixPath(f).parts), f))
    out, used = list(near), len("\n".join(near))
    for f in rest:
        if used + len(f) + 1 > cap:
            break
        out.append(f)
        used += len(f) + 1
    out = sorted(set(out))
    if len(out) == len(files):
        return out, f"all {len(files)} source files"
    return out, (f"{len(out)} of {len(files)} source files ({len(near)} in the fix's {len(fix_dirs)} directory(ies), "
                 f"kept first so every hidden place is listed; the rest truncated at {cap} chars)")


def heuristic(rec: dict, shape: dict) -> tuple[bool, str]:
    existing = shape["existing_source_files"]
    if not existing:
        return False, "the fix only adds new files: no pre-existing place can hide a sibling"
    cls = cwe_class(rec)
    compact = len(shape["dirs"]) <= 1 and len(existing) <= 2
    if (cls in EASY_CLASSES and compact and not shape["parallel_implementation"] and not shape["producer_and_check"]
            and not rec.get("fix_pair")):
        return False, (f"{cls} fixed in one compact place ({len(existing)} file(s), 1 directory): the cwe-bench "
                       "'control' profile (single sink, compact) that the models solve")
    return True, (f"class {cls}; {len(existing)} existing source file(s) in {len(shape['dirs'])} dir(s)"
                  + ("; parallel implementation" if shape["parallel_implementation"] else "")
                  + ("; producer + check" if shape["producer_and_check"] else ""))


# --------------------------------------------------------------------------- #
# 2. Plan draft (DeepSeek)
# --------------------------------------------------------------------------- #
PLAN_PROMPT = """\
You design ONE hard, fair security-repair task from a real, already-fixed vulnerability. Agents (DeepSeek V4.1 Flash and
MiMo-V2.6-Pro - YOU are DeepSeek) will later get ONLY a short user report, the vulnerable repository and 2 hours offline,
and must repair it completely. Today you write only the PLAN (no code, no tests).

What decides difficulty (measured over 41 trialled tasks, 37 solved, and 471 sibling traps in a sister benchmark):
part of the root cause lives in a REAL place the report never leads to, reached by its own public entry point. A task is
accepted only when BOTH models fail, so mechanisms are ranked by how often they beat BOTH models:
M6 producer off the check's path - a schema/serializer/loader/config resolver feeds the check through a path the check
never calls (24% both; e.g. a zod schema strips the issuer on reload); COUPLED value - a legitimate value next to the
bad one that the natural over-broad fix breaks (M11, 20% both; e.g. the visible type-id must still bind); M4
feature-absent - the mechanism never had the protection, so its absence reads as design (18% both; e.g. the any-setter
route has no view code at all); M10 wrong object - the check authorises a neighbouring object or an attacker-chosen
identity field (e.g. parent taken from POST while the check reads GET); M5 merged/defaults route - the restricted value
arrives via defaults, merge, inheritance or stored config (e.g. setOption/merge treat inherited values as set).
WEAK, only next to one of the above: M2 a second implementation (5% both), M1 another handler reaching the same sink
(2% both). TOO EASY, never the difficulty: spelling/case/encoding/input-shape variants, anything one guard closes.
The only task in the sister benchmark that beat BOTH models stacks M4 + M10/M11 + M5 + a coupled value on ONE route.

TWO KINDS OF HIDDEN PLACE (both are real code - nothing is planted):
- Pattern A (in_upstream_fix: true): a file the upstream fix ALSO changed, which the report does not lead to.
- Pattern B (in_upstream_fix: false): a REAL route with the SAME gap that the upstream fix never touched (measured: the
  strongest - 25% missed; the only both-model breaker is pure Pattern B). The task generator will write a small
  "oracle extension" closing it, so the reference solution = upstream fix + extension. Only pick a B route that is
  reachable through a public entry point, has exactly the same missing protection, and that a maintainer would agree
  is part of this vulnerability. Look for it among the repository files below, not in the diff.

SELF-ATTACK: you are also the agent under test. Read only your report sketch and write the repair you would make in
your first 20 minutes (naive_fix) and the sledgehammer you would use when unsure (over_broad_fix). A plan is only good if
a hidden place lies OUTSIDE naive_fix_files and a legitimate feature breaks under over_broad_fix.

If no real hidden place exists (the whole fix is one shared choke point, a dependency bump, config only), answer
{{"verdict": "unsuitable", "unsuitable_reason": "<why>"}}.

Reply with ONLY one JSON object:
{{"verdict": "plan",
 "report_sketch": "<4-7 sentences as the user who hit it: the symptom through ONE route, the impact, the features that
                   must keep working. No file/function/class names, no scope words like 'every'/'all', no fix>",
 "reported_route": "<the public entry point the report shows>",
 "hidden_places": [{{"path": "<repo-relative source file from the list>", "mechanism": "M6|M4|M10|M5|M11|M2|M1",
                     "in_upstream_fix": "<true = Pattern A (the upstream fix changes this file) | false = Pattern B>",
                     "entry_point": "<public way a test reaches it>",
                     "why_missed": "<why an agent fixing the reported route skips it>"}}],
 "coupled_contract": "<the legitimate behaviour an over-broad fix breaks, and the 'must keep working' feature naming it>",
 "naive_fix": "<2-3 sentences>", "naive_fix_files": ["<repo paths>"],
 "over_broad_fix": "<1-2 sentences>",
 "why_naive_fails": "<which hidden place stays open, through which entry point>"}}

# Vulnerability
- ID: {osv_id}   CWE: {cwes}   Ecosystem/package: {ecosystem} / {package}
- Summary: {summary}

# Reference fix (hidden from the agents)
```diff
{patch}
```

# Repository source files ({n} files)
{files}
{feedback}"""

REDRAFT_NOTE = """
# YOUR PREVIOUS PLAN WAS REJECTED - write a NEW plan that fixes every point below
{reasons}
You may keep the vulnerability and pick different hidden places, including a Pattern B route the upstream fix never
touched. Do not just rephrase: change what was wrong. Answer "unsuitable" only if no real hidden place exists at all.
Previous plan:
```json
{plan}
```
"""


def draft_plan(ep, ctx: dict) -> dict[str, Any]:
    reply = extract_json_object(plan_probe.ask(ep, PLAN_PROMPT.format(**ctx)))
    if reply.get("verdict") not in ("plan", "unsuitable"):
        raise ValueError(f"plan draft has no verdict: {str(reply)[:200]}")
    return reply


def product_words(rec: dict) -> set[str]:
    """Words a user report may legitimately contain although a file is named after them: the package and repository
    name parts (a report about Confluence must say "Confluence")."""
    words: set[str] = set()
    for s in (rec.get("package") or "", (rec.get("repo_url") or "").rstrip("/").split("/")[-1],
              (rec.get("repo_url") or "").rstrip("/").split("/")[-2] if (rec.get("repo_url") or "").count("/") >= 4 else ""):
        words.update(w for w in re.split(r"[^a-z0-9]+", s.lower()) if len(w) >= 3)
    return words


def sketch_leaks(sketch: str, paths: list[str], product: set[str]) -> list[str]:
    """Hidden places the report sketch names. Same rule as the generator's identifier_leaks: a code-like stem
    (camelCase, snake_case, digits) leaks as a word; a plain-word stem (`server`, `proxy`, `file`, `http`) only as code -
    in backticks, as a call, or with its extension / directory. 2026-10-21: the old bare-word match rejected 12 plans for
    ordinary words (`server`, `metadata`, `public`, the product name `confluence`)."""
    from src.stage3_task_builder.task_generator import names_hidden_place
    return names_hidden_place(sketch, paths, frozenset(product))


def is_pattern_b(place: dict) -> bool:
    v = place.get("in_upstream_fix")
    return v is False or (isinstance(v, str) and v.strip().lower().startswith("false"))


def plan_problems(plan: dict, files: set[str], upstream: set[str] = frozenset(), product: set[str] = frozenset()) -> list[str]:
    """Deterministic sanity of the draft (no AI): the hidden places must exist and one must escape the naive fix."""
    out = []
    places = [h for h in plan.get("hidden_places") or [] if isinstance(h, dict)]
    paths = [str(h.get("path", "")).strip().lstrip("./") for h in places]
    if not places:
        out.append("no hidden place")
    missing = [p for p in paths if p not in files]
    if missing:
        out.append(f"hidden places not in the repo's source files: {missing[:5]}")
    if upstream:
        wrong_b = [p for p, h in zip(paths, places) if is_pattern_b(h) and p in upstream]
        wrong_a = [p for p, h in zip(paths, places) if not is_pattern_b(h) and p not in upstream]
        if wrong_b:
            out.append(f"in_upstream_fix=false but the upstream fix changes these files: {wrong_b[:5]}")
        if wrong_a:
            out.append(f"in_upstream_fix=true but the upstream fix does not change these files (mark them false - "
                       f"a Pattern B route the generator must fix in an oracle extension): {wrong_a[:5]}")
    naive = {str(f).strip().lstrip("./") for f in plan.get("naive_fix_files") or []}
    if paths and set(paths) <= naive:
        out.append("every hidden place is inside the plan's own naive_fix_files")
    if places and not any(str(h.get("mechanism", "")).upper() in STRONG for h in places):
        out.append("no hidden place uses a top both-model mechanism (M6/M4/M10/M5/M11); M1 parallel entry and M2 "
                   "second implementation are allowed only next to one of them")
    named = sketch_leaks(plan.get("report_sketch") or "", paths, product)
    if named:
        out.append(f"the report sketch names a hidden place: {named}")
    return out


# --------------------------------------------------------------------------- #
# 3. Self-solve probe (target models, file list only)
# --------------------------------------------------------------------------- #
def self_solve(plan: dict, files: list[str], endpoints: list) -> dict[str, Any]:
    hidden = sorted({str(h.get("path", "")).strip().lstrip("./") for h in plan.get("hidden_places") or []
                     if isinstance(h, dict)} & set(files))
    out: dict[str, Any] = {"hidden": hidden, "models": {}}
    prompt = plan_probe.PROMPT.format(report=plan.get("report_sketch") or "", n=len(files), files="\n".join(files))
    for ep in endpoints:
        try:
            cov, hit = plan_probe.coverage(plan_probe.ask(ep, prompt), hidden)
            out["models"][ep.tag] = {"coverage": round(cov, 3), "hit": hit}
        except Exception as e:        # fail open: an unmeasured model never predicts "easy"
            out["models"][ep.tag] = {"error": repr(e)[:200]}
    covs = [m["coverage"] for m in out["models"].values() if "coverage" in m]
    out["visible"] = bool(hidden) and len(covs) == len(endpoints) and len(covs) > 0 and min(covs) >= 1.0
    return out


# --------------------------------------------------------------------------- #
# 4. Review (Claude, non-target)
# --------------------------------------------------------------------------- #
CRITERIA = {
    "real_hidden_place": "every hidden place exists and is genuinely needed to close the vulnerability (changed by the "
                         "upstream fix, or the same unguarded route), and the report sketch does not lead to it",
    "not_one_choke_point": "no single guard in one function closes every hidden place",
    "strong_mechanism": "at least one hidden place hides by M4/M6/M2/M10/M5/M11 - not merely another handler reaching "
                        "the same sink, and not spelling/encoding/input-shape variants",
    "naive_fix_fails": "the predicted naive fix plausibly leaves a hidden place open (an agent would stop after it)",
    "fair": "everything a test would assert follows from the report sketch or a 'must keep working' feature it names; "
            "nothing depends on a design only the reference fix makes or on behaviour the report never states",
    "coupled_contract_fair": "the over-broad fix breaks a legitimate, ordinary feature the report can name",
}
EASY_CRITERIA = ("real_hidden_place", "not_one_choke_point", "strong_mechanism", "naive_fix_fails")

REVIEW_PROMPT = """\
You review a DESIGN PLAN for a security-repair benchmark task before anything is built. The plan was written by one of
the models the task will test, so judge it independently and skeptically. A task is good only if it is HARD (a capable
agent that fixes the reported route stops with part of the vulnerability still open) and FAIR (everything the tests
demand follows from the report).

Answer each criterion pass/fail with a one-sentence reason, then a verdict:
- "proceed" only if every criterion passes;
- "too_easy" if any of real_hidden_place, not_one_choke_point, strong_mechanism, naive_fix_fails fails;
- "unfair" if fair or coupled_contract_fair fails (and the plan is otherwise hard).
List concrete required_changes the generator must make (empty if none).
A hidden place with in_upstream_fix=false is a Pattern B route: a real route the upstream fix never touched. The task
generator will close it with an oracle extension, so it does not appear in the reference fix below. Judge whether that
route really has the same missing protection, is reachable through a public entry point, and belongs to this
vulnerability - not whether the upstream fix changed it.

Criteria:
{criteria}

Reply with ONLY JSON: {{"criteria": {{"<name>": {{"pass": true, "reason": "..."}}}}, "verdict": "...",
"required_changes": ["..."]}}

# Plan
```json
{plan}
```

# Reference fix
```diff
{patch}
```
"""


def review(backend: CliBackend, model: str, plan: dict, patch: str) -> dict[str, Any]:
    prompt = REVIEW_PROMPT.format(criteria="\n".join(f"- {k}: {v}" for k, v in CRITERIA.items()),
                                  plan=json.dumps(plan, indent=2)[:12_000], patch=patch[:MAX_PATCH_CHARS])
    system = "You are a meticulous, skeptical benchmark-design reviewer. Output JSON only."
    max_out = int(os.environ.get("PLAN_GATE_REVIEW_MAX_TOKENS", "32000"))

    def parse(text: str) -> dict:
        reply = extract_json_object(text)
        crit = reply.get("criteria") if isinstance(reply.get("criteria"), dict) else {}
        if not any(isinstance(crit.get(n), dict) and "pass" in crit[n] for n in CRITERIA):
            raise ValueError(f"review answers no criterion: {text[:200]!r}")
        failed = [n for n in CRITERIA if not (isinstance(crit.get(n), dict) and crit[n].get("pass") is True)]
        # the verdict follows from the criteria, never from the reviewer's own label
        verdict = ("proceed" if not failed else "too_easy" if any(n in EASY_CRITERIA for n in failed) else "unfair")
        return {"verdict": verdict, "failed": failed, "criteria": crit,
                "required_changes": [str(x) for x in reply.get("required_changes") or []][:10]}

    text, _ = backend.complete(model, system, [{"role": "user", "content": prompt}], max_out)
    try:
        return parse(text)
    except ValueError:      # malformed (not a flag): the generation fallback model, once - as rubric_check does
        fallback = os.environ.get("GEN_FALLBACK_MODEL", "claude-opus-4-8")
        if not fallback or fallback == model:
            raise
        text, _ = backend.complete(fallback, system, [{"role": "user", "content": prompt}], max_out)
        return parse(text)


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def gate_one(env_dir: Path, rec: dict, cfg: Config, backend: Optional[CliBackend]) -> dict[str, Any]:
    cached = env_dir / GATE_FILE
    if cached.is_file():
        try:
            prev = json.loads(cached.read_text())
            if prev.get("verdict") in FINAL:
                return prev
        except ValueError:
            pass
    eco = rec.get("ecosystem", "")
    patch = (env_dir / "oracle_solution.patch").read_text(errors="replace")
    out: dict[str, Any] = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "mode": mode(), "steps": {}}

    def done(verdict: str, why: str) -> dict:
        out.update(verdict=verdict, why=why)
        cached.write_text(json.dumps(out, indent=2))
        return out

    shape = fix_shape(patch, eco)
    ok, why = heuristic(rec, shape)
    out["steps"]["heuristic"] = {"pass": ok, "why": why, "shape": shape}
    if not ok:
        return done("too_easy", f"heuristic: {why}")

    all_files = plan_probe.source_files(env_dir / "repo", eco)
    files, listing_note = probe_file_list(all_files, shape)
    listing = "\n".join(files)
    out["steps"]["file_list"] = listing_note
    targets = [ep for ep in cfg.eval_endpoints() if ep.check_url]
    drafter = next((ep for ep in targets if ep.tag == "deepseek"), None)
    if drafter is None or not files:
        return done("proceed", "fail open: no DeepSeek endpoint or no source files to probe")

    from src.stage3_task_builder.task_generator import parse_changed_files, prompt_patch_view
    ctx = {"osv_id": env_dir.name, "cwes": ", ".join(rec.get("cwe_ids") or []) or "unknown",
           "ecosystem": eco or "unknown", "package": rec.get("package") or "unknown",
           "summary": rec.get("summary") or "(none - infer from the patch)",
           "patch": prompt_patch_view(patch)[:MAX_PATCH_CHARS], "n": len(files), "files": listing, "feedback": ""}
    upstream, product = set(parse_changed_files(patch)), product_words(rec)
    # One weak draft must not end the candidate (2026-10-21: 39 of ~60 candidates died on a single draft, and the
    # reviewer's required_changes were never read). Each rejection is fed back for up to REDRAFTS new drafts.
    out["rounds"], feedback, last = [], [], ("too_easy", "no plan")
    for rnd in range(REDRAFTS + 1):
        if feedback:
            ctx["feedback"] = REDRAFT_NOTE.format(reasons="\n".join(f"- {r}" for r in feedback)[:4000],
                                                  plan=json.dumps(out.get("plan") or {}, indent=2)[:6000])
        step: dict[str, Any] = {}
        out["rounds"].append(step)
        try:
            plan = draft_plan(drafter, ctx)
        except Exception as e:
            step["draft_error"] = repr(e)[:300]
            if rnd == 0:
                return done("proceed", "fail open: the plan draft failed")
            break
        out["plan"] = plan
        if plan.get("verdict") == "unsuitable":
            return done("unsuitable", f"generator: {plan.get('unsuitable_reason', '')[:300]}")
        problems = plan_problems(plan, set(files), upstream, product)
        step["problems"] = problems
        out["steps"]["draft"] = {"problems": problems, "round": rnd + 1}
        if problems:
            last, feedback = ("too_easy", "plan draft: " + "; ".join(problems)), problems
            continue

        probe = self_solve(plan, files, targets)
        step["self_solve"] = out["steps"]["self_solve"] = probe
        if probe["visible"]:
            last = ("too_easy", f"self-solve: every target named every hidden place {probe['hidden']} from the report "
                                "sketch and the file list alone")
            feedback = [f"Both target models named every hidden place {probe['hidden']} from your report sketch and the "
                        "file list alone, so the sketch leads straight to them. Choose places the sketch does not lead "
                        "to (a producer, a feature that never had the check, a route the upstream fix never touched), "
                        "or describe only the route the user hit."]
            continue

        if backend is None:
            return done("proceed", "no reviewer (rubric backend disabled)")
        try:
            rv = review(backend, cfg.anthropic_model, plan, patch)
        except SafeguardsFlagged as e:
            # standing rule: a flagged candidate is retired, never retried on any Claude model, never worked around
            (env_dir / "safeguards_flagged.txt").write_text(str(e))
            (env_dir / "generation_unsuitable.txt").write_text("retired: Anthropic safeguards flag (plan gate review)\n")
            return done("unsuitable", "retired: Anthropic safeguards flag (plan gate review)")
        except Exception as e:
            step["review_error"] = out["steps"]["review"] = {"error": repr(e)[:300]}
            return done("proceed", "fail open: the review failed")
        out["review"] = step["review"] = rv
        if rv["verdict"] == "proceed":
            return done("proceed", f"heuristic, plan, self-solve probe and review passed (draft {rnd + 1})")
        reasons = [f"{n}: {(rv['criteria'].get(n) or {}).get('reason', '')}"[:300] for n in rv["failed"]]
        last = (rv["verdict"], "review: " + "; ".join(r[:200] for r in reasons))
        feedback = reasons + [f"required change: {c}" for c in rv.get("required_changes") or []]
    return done(last[0], f"{last[1]} (after {len(out['rounds'])} draft(s))")


def run(cfg: Config, src: Path, env_root: Path, only: Optional[list[str]] = None, workers: int = 4) -> dict[str, dict]:
    """Gate every checked-out candidate that has no generated task yet. In gate mode a rejection marks stage 3 REJECTED,
    which build_check and task_generator then skip."""
    from src.common import knowledge
    from src.stage3_task_builder.task_generator import OFFENSIVE_REPO_RE, flagged_repos
    recs = {r["osv_id"]: r for r in json.loads(src.read_text()).get("vulnerabilities", [])}
    # Standing rule: a safeguards-flagged candidate, any candidate of a flagged repo and offensive-security repos are
    # RETIRED and never reach a Claude model - checked here too, because stage 3's repo filter is skipped for --only.
    flagged = flagged_repos(env_root, recs)
    retired = lambda i: ((env_root / i / "safeguards_flagged.txt").is_file()
                         or (env_root / i / "generation_unsuitable.txt").is_file()
                         or (recs[i].get("repo_url") or "").lower().rstrip("/") in flagged
                         or bool(OFFENSIVE_REPO_RE.search(recs[i].get("repo_url") or "")))
    with StateManager(cfg.state_db) as state:
        todo = [i for i in recs if (env_root / i / "oracle_solution.patch").is_file()
                and not (env_root / i / "instruction.md").is_file()
                and not ((r := state.get(STAGE, i)) and r.status is Status.REJECTED)
                and not retired(i)
                and (not only or i in set(only))]
    if not todo:
        return {}
    backend = CliBackend(cfg.claude_bin, float(os.environ.get("PLAN_GATE_TIMEOUT_SEC", "900")),
                         effort=os.environ.get("PLAN_GATE_CLAUDE_EFFORT", "high"))
    log.info("Plan gate", extra={"mode": mode(), "candidates": len(todo)})
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        results = dict(zip(todo, pool.map(lambda i: gate_one(env_root / i, recs[i], cfg, backend), todo)))
    with StateManager(cfg.state_db) as state:
        for i, res in results.items():
            v, why = res.get("verdict"), res.get("why", "")
            if v == "proceed":
                continue
            log.warning("Plan gate rejected" if mode() == "gate" else "Plan gate would reject (advisory)",
                        extra={"osv_id": i, "verdict": v, "why": why[:300]})
            if mode() == "gate":
                state.mark(STAGE, i, Status.REJECTED, f"plan gate: {v}: {why}"[:600])
                knowledge.record_outcome(cfg, i, STAGE, f"rejected_plan_gate_{v}", why)
    counts = {v: sum(1 for r in results.values() if r.get("verdict") == v) for v in FINAL}
    log.info("Plan gate finished", extra=counts)
    return results
