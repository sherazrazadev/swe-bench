#!/usr/bin/env python3
"""Backfill missing CWE labels from the GitHub Advisory Database.

This is CWE-bench: a candidate without a confirmed CWE cannot be classified, scored by weakness class, or reported
against a CWE. OSV's Go (GO-*) and PyPI (PYSEC-*) records almost never carry `database_specific.cwe_ids` - 78% of Go and
57% of PyPI candidates had no CWE on 2026-10-21 - but they DO carry GHSA/CVE aliases, and GHSA's curated records have
the CWEs. npm and Packagist come from GHSA already and are complete.

Resolution order per candidate: GHSA alias -> GET /advisories/{ghsa_id}; else CVE -> GET /advisories?cve_id={cve}.
Results (including "no CWE in GHSA either") are cached in data/.cache/cwe_backfill.json, so re-runs are free.

    .venv/bin/python scripts/backfill_cwe.py --dry-run     # report coverage, write nothing
    .venv/bin/python scripts/backfill_cwe.py               # backfill mined + screened in place

Writes `cwe_ids` and records provenance in `cwe_source` ("osv" | "ghsa:<id>" | "nvd-cve:<id>"). Never overwrites a CWE
the miner already found.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Optional

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from src.common.config import Config  # noqa: E402
from src.common.logging_setup import configure_logging  # noqa: E402
from src.stage1_mining.osv_miner import GITHUB_API, GitHubResolver, RateLimiter, make_session  # noqa: E402

log = logging.getLogger("backfill_cwe")

FILES = ("01_mined/osv_candidates.json", "02_screened/screened.json", "02_screened/revisions.json")


def aliases(rec: dict) -> tuple[Optional[str], Optional[str]]:
    """(ghsa_id, cve_id) reachable from this record."""
    ids = [str(a) for a in (rec.get("aliases") or [])] + [str(rec.get("osv_id") or ""), str(rec.get("cve_id") or "")]
    ghsa = next((i for i in ids if i.upper().startswith("GHSA-")), None)
    cve = next((i for i in ids if i.upper().startswith("CVE-")), None)
    return ghsa, cve


class Backfiller:
    def __init__(self, token: Optional[str], cache_path: Path, rps: float = 3.0):
        self.session = make_session(token)
        self.limiter = RateLimiter(rps)
        self.cache_path = cache_path
        self.cache: dict[str, Any] = {}
        if cache_path.is_file():
            try:
                self.cache = json.loads(cache_path.read_text())
            except json.JSONDecodeError:
                pass

    def save(self) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.cache_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.cache, indent=2))
        tmp.replace(self.cache_path)

    def _get(self, path: str, params: Optional[dict] = None) -> Any:
        for attempt in range(4):
            self.limiter.wait()
            try:
                r = self.session.get(f"{GITHUB_API}{path}", params=params, timeout=45)
            except requests.RequestException as e:
                log.warning("request failed: %s", e)
                time.sleep(2 ** attempt)
                continue
            if r.status_code == 200:
                return r.json()
            if r.status_code in (403, 429) and GitHubResolver._is_rate_limited(r):
                GitHubResolver._sleep_until_reset(r)
                continue
            if r.status_code in (404, 410, 422):
                return None
            time.sleep(2 ** attempt)
        return None

    def lookup(self, ghsa: Optional[str], cve: Optional[str]) -> tuple[list[str], str]:
        """-> (cwe_ids, source). Cached, including empty results."""
        key = ghsa or cve or ""
        if not key:
            return [], ""
        if key in self.cache:
            c = self.cache[key]
            return c.get("cwe_ids") or [], c.get("source") or ""
        cwes: list[str] = []
        source = ""
        if ghsa:
            adv = self._get(f"/advisories/{ghsa}")
            if adv:
                cwes = [c["cwe_id"] for c in adv.get("cwes") or [] if c.get("cwe_id")]
                source = f"ghsa:{ghsa}"
        if not cwes and cve:
            found = self._get("/advisories", {"cve_id": cve, "per_page": 1})
            if isinstance(found, list) and found:
                cwes = [c["cwe_id"] for c in found[0].get("cwes") or [] if c.get("cwe_id")]
                source = f"ghsa-cve:{cve}" if cwes else source
        self.cache[key] = {"cwe_ids": cwes, "source": source}
        return cwes, source


def report(recs: list[dict], label: str) -> Counter:
    from src.stage2_screening.screener import CWE_CLASS, cwe_class
    eco_missing, eco_total, cls = Counter(), Counter(), Counter()
    unmapped = Counter()
    for r in recs:
        e = r.get("ecosystem") or "?"
        eco_total[e] += 1
        cw = [c.upper().removeprefix("CWE-") for c in (r.get("cwe_ids") or [])]
        if not cw:
            eco_missing[e] += 1
        else:
            for c in cw:
                if c not in CWE_CLASS:
                    unmapped[c] += 1
        cls[cwe_class(r)] += 1
    total, miss = sum(eco_total.values()), sum(eco_missing.values())
    log.info("%s: %d candidates, %d without a CWE (%d%%)", label, total, miss, miss * 100 // max(total, 1))
    for e, n in eco_total.most_common():
        log.info("    %-10s %4d total, %4d missing", e, n, eco_missing[e])
    log.info("    weakness classes: %s", dict(cls.most_common()))
    if unmapped:
        log.info("    labelled but unmapped CWEs (fall back to 'other'): %s", dict(unmapped.most_common(10)))
    return eco_missing


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--dry-run", action="store_true", help="report coverage and what would be fetched; write nothing")
    p.add_argument("--rps", type=float, default=3.0)
    args = p.parse_args(argv)
    configure_logging()
    cfg = Config.load()
    if not cfg.github_token:
        log.error("GITHUB_TOKEN is required (60 calls/hour without it)")
        return 2

    bf = Backfiller(cfg.github_token, cfg.cache_dir / "cwe_backfill.json", args.rps)
    filled = Counter()
    try:
        for rel in FILES:
            path = cfg.data_dir / rel
            if not path.is_file():
                continue
            blob = json.loads(path.read_text())
            recs = blob.get("vulnerabilities", [])
            log.info("=== %s", rel)
            report(recs, "before")
            todo = [r for r in recs if not (r.get("cwe_ids") or [])]
            log.info("    %d candidates need a lookup", len(todo))
            if args.dry_run:
                continue
            for i, r in enumerate(todo, 1):
                ghsa, cve = aliases(r)
                cwes, source = bf.lookup(ghsa, cve)
                if cwes:
                    r["cwe_ids"] = cwes
                    r["cwe_source"] = source
                    filled[r.get("ecosystem") or "?"] += 1
                if i % 50 == 0:
                    log.info("    %d/%d looked up (%d filled)", i, len(todo), sum(filled.values()))
                    bf.save()
            for r in recs:                       # provenance for the ones the miner already had
                r.setdefault("cwe_source", "osv" if (r.get("cwe_ids") or []) else "")
            report(recs, "after")
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps({**blob, "vulnerabilities": recs}, indent=2, ensure_ascii=False))
            tmp.replace(path)
            log.info("    wrote %s", path)
    finally:
        bf.save()
    log.info("Backfilled CWEs: %s (total %d)", dict(filled), sum(filled.values()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
