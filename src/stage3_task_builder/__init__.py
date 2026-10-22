"""Stage 3 - Task builder: screened candidates -> data/03_environments/<OSV-ID>/.

  environment_builder.py  repo at pre-patch commit in repo/ + oracle_solution.patch (answer key kept OUTSIDE repo/)
  task_generator.py       Anthropic API -> instruction.md + hidden_tests.py (next to repo/, never inside it)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import logging
from pathlib import Path
from typing import Optional

from src.common.config import Config
from src.common.state_manager import StateManager, Status

STAGE = "stage3_task_builder"
MAX_GEN_FAILURES = 3
MAX_BUILD_NET_ERRORS = 3     # runs whose build hit network/registry errors before a candidate is retired
# GPU / ML-framework dependencies: the image build downloads gigabytes and fails or times out (lmdeploy, flyto-core
# 2026-10-21); the task never reaches validation, so skip it before the 30-minute Docker build.
HEAVY_ML_RE = re.compile(r"(?im)^[\s\"'\-]*(torch|torchvision|tensorflow(?:-gpu)?|jax\[|jaxlib|vllm|triton|deepspeed|"
                         r"flash[-_]attn|xformers|nvidia-[a-z0-9-]+|cupy|onnxruntime-gpu|bitsandbytes)\b")


def heavy_ml_deps(repo: Path) -> list[str]:
    found: list[str] = []
    for name in ("requirements.txt", "requirements-dev.txt", "requirements/base.txt", "pyproject.toml", "setup.py",
                 "setup.cfg", "environment.yml"):
        f = repo / name
        if f.is_file():
            try:
                found += [m.group(1).lower() for m in HEAVY_ML_RE.finditer(f.read_text(errors="replace")[:200_000])]
            except OSError:
                pass
    return sorted(set(found))


MAX_BUILD_TIMEOUTS = 2       # build-check timeouts before a candidate is retired        # generation runs that produced no valid task before a candidate is retired
MAX_REFUSALS = 3            # safety-filter refusals (all runs together) before a candidate is retired

log = logging.getLogger(__name__)


def _revision_pool(cfg: Config, base: Path, only: Optional[list[str]]) -> Path:
    """Revisions (data/02_screened/revisions.json) are repaired re-versions of a task that already ran, e.g.
    PYSEC-2026-3837-v2. They are merged into the candidate pool ONLY when asked for by id, so a fresh cycle never
    re-picks one by score - a cycle must run new candidates (user, 2026-10-21)."""
    revisions = cfg.data_dir / "02_screened" / "revisions.json"
    if not only or not revisions.is_file():
        return base
    try:
        revs = [r for r in json.loads(revisions.read_text()).get("vulnerabilities", []) if r.get("osv_id") in set(only)]
        if not revs:
            return base
        merged = {r["osv_id"]: r for r in json.loads(base.read_text()).get("vulnerabilities", []) + revs}
    except (OSError, json.JSONDecodeError, KeyError) as e:
        log.warning("Could not merge revisions: %s", e)
        return base
    out = cfg.cache_dir / "screened_plus_revisions.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"count": len(merged), "vulnerabilities": list(merged.values())}, indent=2))
    log.info("Revision candidates requested by id", extra={"ids": [r["osv_id"] for r in revs]})
    return out


def _input_file(cfg: Config, allow_unscreened: bool) -> Path:
    screened = cfg.data_dir / "02_screened" / "screened.json"
    injected = cfg.data_dir / "02_screened" / "injected.json"
    if screened.exists():
        # injected candidates are only picked while the injector is enabled (retired 2026-10-20: mined CVEs only)
        if not injected.is_file() or os.environ.get("INJECTOR_ENABLED") != "1":
            return screened
        # Injected "parallel path" candidates (docs/INJECTED_TASKS.md) live in their own registry; merge them for
        # selection without mutating the mined screened.json.
        try:
            base = json.loads(screened.read_text()).get("vulnerabilities", [])
            inj = json.loads(injected.read_text()).get("vulnerabilities", [])
        except (OSError, json.JSONDecodeError) as e:
            log.warning("Could not merge injected candidates: %s", e)
            return screened
        merged = {r["osv_id"]: r for r in base + inj if isinstance(r, dict) and r.get("osv_id")}
        out = cfg.cache_dir / "screened_plus_injected.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps({"count": len(merged), "vulnerabilities": list(merged.values())}, indent=2))
        return out
    mined = cfg.data_dir / "01_mined" / "osv_candidates.json"
    if allow_unscreened and mined.exists():
        log.warning("Using UNSCREENED candidates", extra={"path": str(mined)})
        return mined
    raise FileNotFoundError(
        f"{screened} not found. Run stage 2, or pass --allow-unscreened to build from stage 1 output.")


OFFENSIVE_REPO_RE = re.compile(
    r"github\.com/(projectdiscovery|rapid7|sqlmapproject|zaproxy|bishopfox|bc-security|cobbr|gentilkiwi|fortra|"
    r"lgandx|beefproject|bettercap|epi052|ffuf|owasp-amass)/"
    r"|github\.com/[^/]+/[^/]*(exploit|pentest|red-?team|hacktool|metasploit|nuclei|sqlmap|c2-?framework)", re.I)


def _limit_to_top_n(cfg: Config, src: Path, env_dir: Path, max_tasks: Optional[int], only: Optional[list[str]],
                    exclude: Optional[set] = None) -> Path:
    """Pilot mode: write a subset file with the best-scored candidates that have no finished task yet."""
    if not max_tasks and not only:
        return src
    recs = json.loads(src.read_text()).get("vulnerabilities", [])
    if only:
        recs = [r for r in recs if r["osv_id"] in set(only)]
    else:
        recs = [r for r in recs if not ((env_dir / r["osv_id"] / "instruction.md").is_file()
                                        and (env_dir / r["osv_id"] / "hidden_tests.py").is_file())]
        # never retry candidates the safety filter keeps declining (they burn Opus time and keep failing)
        recs = [r for r in recs if refusals(env_dir / r["osv_id"]) < MAX_REFUSALS]
        recs = [r for r in recs if r["osv_id"] not in (exclude or set())]      # already queued in this cycle
        with StateManager(cfg.state_db) as state:   # nor anything already decided in a later stage
            recs = [r for r in recs if not any(
                (rec := state.get(st, r["osv_id"])) and rec.status.value in ("rejected", "rejected_too_easy", "failed_oracle", "accepted")
                for st in ("stage3_task_builder", "stage4_oracle_validator", "stage5_evaluator"))]
        # learned ranking: what the evaluations so far say about each candidate's family and package/repo
        from src.common import knowledge
        learned = knowledge.learned_ranking(cfg)
        adj = {r["osv_id"]: knowledge.selection_adjustment(learned, r) for r in recs}
        # skip repos that already proved unusable: an image that cannot be built here, or a candidate whose generation
        # session Anthropic safeguards flagged (another advisory of the same repo would likely be flagged too)
        bad_repos: dict[str, str] = {}
        by_id = {r["osv_id"]: r for r in json.loads(src.read_text()).get("vulnerabilities", [])}
        with StateManager(cfg.state_db) as state:
            for k in state.keys(STAGE, Status.REJECTED):
                det = (state.get(STAGE, k).detail or "").lower()
                why = ("unbuildable" if ("docker build" in det or "build timed out" in det or "unbuildable" in det) else "")
                if why and k in by_id:
                    bad_repos[by_id[k]["repo_url"].lower()] = f"{why} ({k})"
        # Flagged candidates are retired (2026-10-20), so a repo with a safeguards-flagged candidate and offensive-security
        # tool repos are not picked at all: picking them only wastes a slot and an env build.
        from src.stage3_task_builder.task_generator import OFFENSIVE_REPO_RE, flagged_repos
        for repo in flagged_repos(env_dir, by_id):
            bad_repos.setdefault(repo, "safeguards-flagged repo")
        for r in recs:
            if OFFENSIVE_REPO_RE.search(r.get("repo_url") or ""):
                bad_repos.setdefault(r["repo_url"].lower(), "offensive-security tool repo")
        skipped = [r["osv_id"] for r in recs if r["repo_url"].lower().rstrip("/") in bad_repos
                   or r["repo_url"].lower() in bad_repos]
        if skipped:
            log.info("Skipping candidates from unusable repos", extra={"n": len(skipped), "ids": skipped[:20]})
        recs = [r for r in recs if r["repo_url"].lower() not in bad_repos
                and r["repo_url"].lower().rstrip("/") not in bad_repos]
        # Injected parallel-path tasks are the measured breaker shape: pilot them ahead of mined candidates.
        recs.sort(key=lambda r: -(current_score(r) + adj[r["osv_id"]][0]
                                  + (1000 if (r.get("source") == "injected" or r.get("injection")) else 0)))
        picked, repos = [], set()
        # diversity: at most one task per repository, and the languages balanced (PICK_ECOSYSTEMS, default all):
        # each ecosystem gets at most ceil(N / #ecosystems) slots; leftover slots go to the next-best candidates.
        allowed = [e.strip() for e in os.environ.get("PICK_ECOSYSTEMS", "").split(",") if e.strip()]
        if allowed:
            recs = [r for r in recs if r.get("ecosystem") in allowed]
        ecos = sorted({r.get("ecosystem") for r in recs})
        cap = -(-max_tasks // max(1, len(ecos)))
        # measured: no fix of <= 5 source files ever broke a model (0/17); >= 6 files broke one in 3/17. So the first
        # passes take only wide fixes; smaller ones only fill slots nothing wider can.
        min_src = int(os.environ.get("MIN_PICK_SOURCE_FILES", "6"))
        width = lambda r: ((r.get("screening") or {}).get("diff") or {}).get("counts", {}).get("source", 0)
        per: dict = {}
        for strict, wide in ((True, True), (False, True), (False, False)):
            for r in recs:
                repo = r["repo_url"].lower()
                inj = r.get("source") == "injected" or r.get("injection")   # built deliberately: width is not its difficulty mechanism
                if repo in repos or (strict and per.get(r.get("ecosystem"), 0) >= cap) or (wide and width(r) < min_src and not inj):
                    continue
                repos.add(repo)
                per[r.get("ecosystem")] = per.get(r.get("ecosystem"), 0) + 1
                picked.append(r)
                if len(picked) >= max_tasks:
                    break
            if len(picked) >= max_tasks:
                break
        recs = picked
    cfg.cache_dir.mkdir(parents=True, exist_ok=True)
    subset = cfg.cache_dir / "stage3_subset.json"
    subset.write_text(json.dumps({"count": len(recs), "vulnerabilities": recs}, indent=2))
    log.info("Pilot subset", extra={"tasks": [r["osv_id"] for r in recs]})
    if not only:
        for r in recs:
            log.info("Pick", extra={"osv_id": r["osv_id"], "package": r.get("package"), "score": current_score(r),
                                     "learned": adj[r["osv_id"]][0], "why": adj[r["osv_id"]][1]})
    return subset


def _buildable_ids(cfg: Config, src: Path, env_dir: Path, args: argparse.Namespace) -> Optional[list[str]]:
    """Docker fail-fast check (skipped, with a warning, when Docker is down). Returns the ids worth generating for."""
    from src.stage3_task_builder import build_check

    wanted = [r["osv_id"] for r in json.loads(src.read_text()).get("vulnerabilities", [])
              if (env_dir / r["osv_id"] / "oracle_solution.patch").is_file()]
    if args.only:
        wanted = [i for i in wanted if i in set(args.only)]
    pending = [i for i in wanted if not ((env_dir / i / "instruction.md").is_file() and (env_dir / i / "hidden_tests.py").is_file())]
    with StateManager(cfg.state_db) as state:   # never generate for a candidate stage 3 already retired
        pending = [i for i in pending if not ((rec := state.get(STAGE, i)) and rec.status is Status.REJECTED)]
    if args.skip_build_check or args.dry_run:
        return pending
    if not build_check.docker_available():
        log.warning("Docker is not running - SKIPPING the fail-fast build check (stage 4 will catch bad builds, "
                    "after Opus time has been spent)")
        return pending
    meta = {r["osv_id"]: r for r in json.loads(src.read_text()).get("vulnerabilities", [])}
    ok_ids = []
    from concurrent.futures import ThreadPoolExecutor
    with StateManager(cfg.state_db) as state:
        todo = []
        for osv_id in pending:
            rec = state.get(STAGE, osv_id)
            if rec and rec.status is Status.REJECTED:
                continue            # failed the build check earlier
            heavy = heavy_ml_deps(env_dir / osv_id / "repo")
            if heavy:
                why = f"heavy ML/GPU dependencies {heavy[:4]}: the image cannot be built within budget"
                state.mark(STAGE, osv_id, Status.REJECTED, why)
                from src.common import knowledge
                knowledge.record_outcome(cfg, osv_id, STAGE, "rejected_unbuildable", why)
                log.warning("Retired before the build: heavy ML dependencies", extra={"osv_id": osv_id, "deps": heavy[:4]})
                continue
            todo.append(osv_id)
        # Docker builds in parallel (3 at a time); results are applied in order afterwards.
        with ThreadPoolExecutor(max_workers=3) as pool:
            results = dict(zip(todo, pool.map(lambda i: build_check.run_checks(env_dir, [i], meta)[i], todo)))
        for osv_id in todo:
            ok, detail = results[osv_id]
            if ok:
                ok_ids.append(osv_id)
            elif detail.startswith(build_check.TRANSIENT) and "timed out" in detail:
                # a build that times out (e.g. compiling torch) will time out again: retire after 2 strikes instead
                # of spending 30 min on it in every batch; network/registry errors stay retryable
                strikes_f = env_dir / osv_id / "build_timeouts.txt"
                strikes = (int(strikes_f.read_text().strip() or 0) if strikes_f.is_file() else 0) + 1
                strikes_f.write_text(str(strikes))
                if strikes >= MAX_BUILD_TIMEOUTS:
                    why = f"image build timed out {strikes} times; retired"
                    state.mark(STAGE, osv_id, Status.REJECTED, why)
                    from src.common import knowledge
                    knowledge.record_outcome(cfg, osv_id, STAGE, "rejected_unbuildable", why)
                    log.warning("Retired: build keeps timing out", extra={"osv_id": osv_id, "strikes": strikes})
                else:
                    log.warning("Build check timed out; one more try next run", extra={"osv_id": osv_id})
            elif detail.startswith(build_check.TRANSIENT):
                # retryable, but not forever: lmdeploy (GHSA-9xq9) held a batch slot in 9 cycles running on 2026-10-21
                strikes_f = env_dir / osv_id / "build_net_errors.txt"
                strikes = (int(strikes_f.read_text().strip() or 0) if strikes_f.is_file() else 0) + 1
                strikes_f.write_text(str(strikes))
                if strikes >= MAX_BUILD_NET_ERRORS:
                    why = f"image build hit network/registry errors in {strikes} runs; retired"
                    state.mark(STAGE, osv_id, Status.REJECTED, why)
                    from src.common import knowledge
                    knowledge.record_outcome(cfg, osv_id, STAGE, "rejected_unbuildable", why)
                    log.warning("Retired: build keeps failing on network/registry errors",
                                extra={"osv_id": osv_id, "strikes": strikes})
                else:
                    log.warning("Build check hit network/registry errors; will retry next run",
                                extra={"osv_id": osv_id, "strikes": strikes})
            else:
                state.mark(STAGE, osv_id, Status.REJECTED, detail)
                from src.common import knowledge
                knowledge.record_outcome(cfg, osv_id, STAGE, "rejected_unbuildable", detail)
    log.info("Build check", extra={"buildable": len(ok_ids), "rejected": len(pending) - len(ok_ids)})
    return ok_ids


def run(cfg: Config, args: argparse.Namespace) -> int:
    from src.stage3_task_builder import environment_builder, task_generator

    try:
        src = _input_file(cfg, args.allow_unscreened)
    except FileNotFoundError as e:
        log.error("%s", e)
        return 2
    env_dir = cfg.stage_dir(3)
    src = _revision_pool(cfg, src, args.only)
    src = _limit_to_top_n(cfg, src, env_dir, args.max_tasks, args.only)

    build_argv = [str(src), "--environments", str(env_dir), "--workers", str(args.workers)]
    rc = environment_builder.main(build_argv)
    if rc != 0:
        return rc

    # Order by cost, cheapest first: the Docker build check spends only local CPU, the plan gate spends model budget
    # (DeepSeek plan + two self-solve probes + a Claude review, ~25 min/candidate) and full generation spends the most.
    # So build first: 10 of 29 stage-3 rejections were build failures (mostly Go and pnpm repos), and paying for a plan
    # review of a repo that cannot build here is pure waste. _buildable_ids marks failures REJECTED, which plan_gate skips.
    only = _buildable_ids(cfg, src, env_dir, args)
    if only is not None and not only:
        log.warning("No buildable environments to generate tasks for")
        return 0

    # Pre-build plan gate (2026-10-21): heuristic, DeepSeek plan draft, self-solve probe, Claude review - before the
    # expensive full generation. Rejections are marked REJECTED here, so generation skips them.
    from src.stage3_task_builder import plan_gate
    if plan_gate.mode() != "off" and not args.dry_run:
        gated = plan_gate.run(cfg, src, env_dir, only, workers=args.workers)
        if plan_gate.mode() == "gate" and gated:
            only = [i for i in only if (gated.get(i) or {}).get("verdict", "proceed") == "proceed"]
            if not only:
                log.warning("Plan gate rejected every candidate in this batch")
                return 0
    gen_argv = (["--only", *only] if only is not None else []) + ["--environments", str(env_dir), "--candidates", str(src), "--workers", str(min(args.workers, 6)),
                "--backend", cfg.task_gen_backend, "--claude-bin", cfg.claude_bin]
    if args.model or cfg.anthropic_model:
        gen_argv += ["--model", args.model or cfg.anthropic_model]
    if args.dry_run:
        gen_argv.append("--dry-run")
    rc = task_generator.main(gen_argv)
    if not args.dry_run:
        _record_state(cfg, env_dir)
        _record_failures(cfg, env_dir, only or [])
    return rc


def refusals(d: Path) -> int:
    return len(list(d.glob("generation_refused_*.txt")))


def current_score(rec: dict) -> int:
    """Rank with the CURRENT screening score function (re-scored from the stored diff facts, so a scoring change
    applies to the whole pool without re-screening) plus the stored learned prior."""
    from src.stage2_screening.screener import score
    scr = rec.get("screening") or {}
    if scr.get("diff") and "source_files" in scr["diff"]:
        return score(scr["diff"], scr.get("repo") or {}, rec) + int(scr.get("prior", 0) or 0)
    return int(scr.get("score", 0) or 0)


def _record_failures(cfg: Config, env_dir: Path, ids: list[str]) -> None:
    """Every candidate that went through generation but has no task is recorded: FAILED (with a counter) so it stops
    taking pilot slots forever, and REJECTED once it was refused MAX_REFUSALS times in total or failed
    MAX_GEN_FAILURES runs - so the lessons/priors also learn which classes the generator cannot produce."""
    from src.common import knowledge
    with StateManager(cfg.state_db) as state:
        for osv_id in ids:
            d = env_dir / osv_id
            if (d / "instruction.md").is_file():
                continue
            # deferred (a safeguards-flag cluster stopped this run): not the candidate's fault, so no strike
            deferred = d / "generation_deferred.txt"
            if deferred.is_file():
                deferred.unlink()
                log.info("Deferred, no strike", extra={"osv_id": osv_id})
                continue
            # a safeguards-flagged candidate is retired (task_generator writes generation_unsuitable.txt), never sent to
            # any Claude model again
            if (d / "generation_unsuitable.txt").is_file():
                why = "unsuitable: " + (d / "generation_unsuitable.txt").read_text().strip()[:200]
                state.mark(STAGE, osv_id, Status.REJECTED, why)
                knowledge.record_outcome(cfg, osv_id, STAGE, "rejected_unsuitable", why)
                log.warning("Retired: unsuitable candidate", extra={"osv_id": osv_id, "why": why})
                continue
            refused = refusals(d)
            rejected = sorted(d.glob("generation_rejected_*.txt"), key=lambda p: p.stat().st_mtime)
            last = rejected[-1].read_text(errors="replace").splitlines()[0][:200] if rejected else "no valid output"
            rec = state.get(STAGE, osv_id)
            runs = (rec.attempts if rec and rec.status is Status.FAILED else 0) + 1
            if refused >= MAX_REFUSALS:
                state.mark(STAGE, osv_id, Status.REJECTED, f"generation declined {refused}x (safety classifier)")
                knowledge.record_outcome(cfg, osv_id, STAGE, "rejected_classifier_blocked",
                                         f"generation declined {refused} times")
                log.warning("Retired: generation blocked by the safety classifier", extra={"osv_id": osv_id})
            elif runs >= MAX_GEN_FAILURES:
                state.mark(STAGE, osv_id, Status.REJECTED, f"no valid task after {runs} generation runs: {last}")
                knowledge.record_outcome(cfg, osv_id, STAGE, "rejected_generation_failed", last)
                log.warning("Retired: generation kept failing", extra={"osv_id": osv_id, "runs": runs})
            else:
                state.mark(STAGE, osv_id, Status.FAILED, f"generation run {runs} produced no valid task: {last}")


def _record_state(cfg: Config, env_dir: Path) -> None:
    """Mark every environment that now has instruction.md + hidden_tests.py as done for stage 3."""
    with StateManager(cfg.state_db) as state:
        for d in sorted(p for p in env_dir.iterdir() if p.is_dir() and not p.name.startswith(".")):
            if (d / "instruction.md").is_file() and (d / "hidden_tests.py").is_file():
                if state.should_process(STAGE, d.name):
                    state.mark(STAGE, d.name, Status.DONE)
