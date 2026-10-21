"""One-off / fallback: infer which curated techniques an already-generated task applies (tasks generated before the
generator recorded `techniques`). Writes task_metadata.json `techniques_inferred`; never touches `techniques`.

    python -m src.common.technique_backfill [osv_id ...]     # default: every evaluated task without a record
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys

from src.common.config import Config
from src.common.llm import CliBackend, SafeguardsFlagged, extract_json_object
from src.common.results_report import technique_names

log = logging.getLogger(__name__)

SYSTEM = ("You classify the design of a benchmark task (a vulnerability report plus hidden tests) against a numbered "
          "list of task-design techniques. Answer only with JSON.")
PROMPT = """Techniques:
{techniques}

Task report given to the agent:
{instruction}

Hidden test names (the agent never saw them):
{tests}

Which techniques does this task clearly apply? Count a technique only if the report and the tests show it (e.g. #4 =
several separate test_security_* variants; #5 = functional tests with legitimate inputs close to the attack).
Reply: {{"techniques": [numbers], "why": "<one short sentence>"}}"""


def infer(cfg: Config, osv_id: str, backend: CliBackend) -> list[int] | None:
    env = cfg.stage_dir(3) / osv_id
    tm = env / "task_metadata.json"
    if not (env / "instruction.md").is_file() or not tm.is_file():
        return None
    names = technique_names(cfg)
    hidden = (env / "hidden_tests.py").read_text(errors="replace") if (env / "hidden_tests.py").is_file() else ""
    prompt = PROMPT.format(techniques="\n".join(f"{n}. {t}" for n, t in sorted(names.items())),
                           instruction=(env / "instruction.md").read_text(errors="replace")[:4000],
                           tests="\n".join(re.findall(r"^def (test_\w+)", hidden, re.M)))
    for model in dict.fromkeys([cfg.anthropic_model, os.environ.get("GEN_FALLBACK_MODEL", "claude-opus-4-8")]):
        try:
            text, _ = backend.complete(model, SYSTEM, [{"role": "user", "content": prompt}], 1000)
            reply = extract_json_object(text)
        except SafeguardsFlagged:
            log.warning("Technique inference skipped: safeguards flagged", extra={"osv_id": osv_id})
            return None
        except Exception as e:
            log.warning("Technique inference failed", extra={"osv_id": osv_id, "model": model, "error": repr(e)[:160]})
            continue
        if isinstance(reply, dict) and isinstance(reply.get("techniques"), list):
            techs = sorted({int(t) for t in reply["techniques"] if str(t).isdigit() and int(t) in names})
            meta = json.loads(tm.read_text())
            meta["techniques_inferred"] = techs
            meta["techniques_inferred_why"] = str(reply.get("why", ""))[:300]
            tm.write_text(json.dumps(meta, indent=2))
            return techs
    return None


def main(argv: list[str]) -> None:
    logging.basicConfig(level=logging.INFO)
    cfg = Config.load(None)
    ids = argv or sorted(d.name for d in cfg.stage_dir(5).glob("GHSA-*") if d.is_dir()) + \
        sorted(d.name for d in cfg.stage_dir(5).glob("PYSEC-*") if d.is_dir())
    backend = CliBackend(cfg.claude_bin, 600.0)
    for osv_id in ids:
        tm = cfg.stage_dir(3) / osv_id / "task_metadata.json"
        meta = json.loads(tm.read_text()) if tm.is_file() else {}
        if meta.get("techniques") or meta.get("techniques_inferred"):
            continue
        print(osv_id, infer(cfg, osv_id, backend), flush=True)


if __name__ == "__main__":
    main(sys.argv[1:])
