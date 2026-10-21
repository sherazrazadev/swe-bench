"""Headless Claude Code client (`claude -p`) shared by task generation, rubric check and trial analysis.

Default: logged-in Anthropic subscription (no API key). Optional: point Claude Code at an Anthropic-compatible
vendor (e.g. DeepSeek) via ANTHROPIC_BASE_URL + ANTHROPIC_AUTH_TOKEN / DEEPSEEK_API_KEY — see DeepSeek's Claude Code
guide. Quota exhaustion raises QuotaExhausted so callers can stop cleanly (pipeline state makes the run resumable).
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from typing import Optional

log = logging.getLogger(__name__)


class QuotaExhausted(Exception):
    """Subscription/API quota is used up; continuing would only burn retries."""


class OutputLimitExceeded(RuntimeError):
    """The reply did not fit the model's output limit (the generator then splits the request)."""


class SafeguardsFlagged(Exception):
    """Anthropic's safeguards flagged the session under the Acceptable Use Policy. This is an account-level enforcement
    signal, not an output filter: never retried and never routed to another model - the candidate is retired and a
    human reviews the account's usage."""


def normalize_model(name: str) -> str:
    """'opus-5.5' -> 'claude-opus-5-5'; full ids and CLI aliases ('opus') pass through."""
    m = re.fullmatch(r"(opus|sonnet|haiku|fable)-(\d+)\.(\d+)", name.strip().lower())
    return f"claude-{m[1]}-{m[2]}-{m[3]}" if m else name


def _external_anthropic_compat() -> bool:
    """True when Claude Code should bill an Anthropic-compatible third-party API (not Claude subscription)."""
    base = (os.environ.get("ANTHROPIC_BASE_URL") or "").strip().lower()
    return any(h in base for h in ("deepseek.com", "xiaomimimo.com"))


class CliBackend:
    """Headless Claude Code (`claude -p`).

    * prompt goes via stdin (no argv length limit); all tools are disabled; cwd is an empty temp dir
      so no project CLAUDE.md / settings leak into the generation
    * Anthropic subscription mode: ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN are removed so the CLI uses login
    * External compat mode (ANTHROPIC_BASE_URL → DeepSeek/MiMo): keep auth token; map DEEPSEEK_API_KEY if needed;
      drop CLAUDE_CODE_OAUTH_TOKEN so the limited Anthropic login is not used
    """
    _QUOTA_MARKERS = ("usage limit", "limit reached", "quota", "credit balance")
    _TRANSIENT_MARKERS = ("overloaded", "rate limit", "529", "503", "timed out", "temporarily", "econnreset")

    def __init__(self, claude_bin: str, timeout: float, retries: int = 3, env_overrides: Optional[dict] = None,
                 effort: Optional[str] = None):
        # effort: CLAUDE_CODE_EFFORT_LEVEL for THIS client's calls only. Task generation passes its own level so the
        # host-wide .env value (which also reaches the Harbor process) is never changed for it.
        self.effort = effort
        if not shutil.which(claude_bin):
            raise SystemExit(f"`{claude_bin}` not found on PATH (is Claude Code installed and logged in?)")
        self.claude_bin, self.timeout, self.retries = claude_bin, timeout, retries
        # e.g. DeepSeek's Anthropic-compatible API for this client only (the process env stays on Claude)
        self.env_overrides = env_overrides or {}

    @staticmethod
    def _flatten(messages: list[dict]) -> str:
        if len(messages) == 1:
            return messages[0]["content"]
        # Retry turn: original request, the previous output, then the validator's complaint.
        return (messages[0]["content"] + "\n\n# Your previous output\n" + messages[1]["content"]
                + "\n\n# Feedback\n" + messages[2]["content"])

    def complete(self, model: str, system: str, messages: list[dict], max_tokens: int) -> tuple[str, dict]:
        if self.env_overrides:
            env = {k: v for k, v in os.environ.items()
                   if k not in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN")}
            env.update(self.env_overrides)
        elif _external_anthropic_compat():
            env = dict(os.environ)
            env.pop("CLAUDE_CODE_OAUTH_TOKEN", None)
            if not (env.get("ANTHROPIC_AUTH_TOKEN") or env.get("ANTHROPIC_API_KEY")):
                if "deepseek.com" in (env.get("ANTHROPIC_BASE_URL") or "").lower() and env.get("DEEPSEEK_API_KEY"):
                    env["ANTHROPIC_AUTH_TOKEN"] = env["DEEPSEEK_API_KEY"]
            log.info("CliBackend using external Anthropic-compat API",
                     extra={"base": (env.get("ANTHROPIC_BASE_URL") or "")[:60], "model": model})
        else:
            env = {k: v for k, v in os.environ.items() if k not in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")}
            # On the host, always use the normal logged-in session; the OAuth token (from `claude setup-token`) is only for
            # containers, which have no access to the Mac keychain. A stale/invalid token must not break host runs.
            if not os.path.exists("/.dockerenv"):
                env.pop("CLAUDE_CODE_OAUTH_TOKEN", None)
        env["CLAUDE_CODE_MAX_OUTPUT_TOKENS"] = str(max_tokens)
        if self.effort:
            env["CLAUDE_CODE_EFFORT_LEVEL"] = self.effort
        cmd = [self.claude_bin, "-p", "--model", normalize_model(model), "--output-format", "json",
               "--tools", "", "--system-prompt", system, "--no-session-persistence"]
        last = "unknown"
        for attempt in range(1, self.retries + 1):
            with tempfile.TemporaryDirectory(prefix="taskgen_") as cwd:
                try:
                    proc = subprocess.run(cmd, input=self._flatten(messages), capture_output=True, text=True,
                                          timeout=self.timeout, cwd=cwd, env=env)
                except subprocess.TimeoutExpired:
                    # never retried: the identical call at the same effort times out again, and 3 tries used to burn
                    # the whole generation window silently (cycles 13-20: no Claude generation finished)
                    log.warning("claude CLI call timed out after %ss (model %s); not retried", self.timeout, model)
                    raise RuntimeError(f"claude CLI timed out after {self.timeout}s")
            if proc is not None:
                text, usage, err = self._parse(proc)
                if not err:
                    return text, usage
                last = err
                low = err.lower()
                if "safeguards flagged" in low or "legal/aup" in low:
                    raise SafeguardsFlagged(err)
                if "output token maximum" in low:       # the same request would overflow again: never retried as-is
                    raise OutputLimitExceeded(err)
                if any(m in low for m in self._QUOTA_MARKERS):
                    raise QuotaExhausted(err)
                if not any(m in low for m in self._TRANSIENT_MARKERS) and proc.returncode == 0:
                    raise RuntimeError(err)  # e.g. refusal / invalid model: retrying will not help
            if attempt < self.retries:
                delay = 5 * 2 ** (attempt - 1)
                log.info("claude CLI call failed (attempt %d/%d), retrying in %ds: %s", attempt, self.retries, delay, last[:200])
                time.sleep(delay)
        raise RuntimeError(f"claude CLI failed after {self.retries} attempts: {last[:300]}")

    @staticmethod
    def _parse(proc: subprocess.CompletedProcess) -> tuple[str, dict, Optional[str]]:
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return "", {}, f"unparseable CLI output (exit {proc.returncode}): {(proc.stderr or proc.stdout)[-300:]}"
        if isinstance(data, list):  # stream-style array: take the final result object
            data = next((d for d in reversed(data) if isinstance(d, dict) and d.get("type") == "result"), {})
        if data.get("is_error") or proc.returncode != 0:
            return "", {}, str(data.get("result") or proc.stderr or "CLI reported an error")[:500]
        u = data.get("usage") or {}
        return data.get("result", ""), {"input_tokens": u.get("input_tokens", 0), "output_tokens": u.get("output_tokens", 0),
                                         "cost_usd": data.get("total_cost_usd")}, None


class CursorCliBackend:
    """Headless Cursor Agent CLI (`agent -p`), signed in with the user's Cursor account (`agent login`; no API key).

    Same `complete()` contract as CliBackend so task generation can swap backends (TASK_GEN_BACKEND=cursor).
    * read-only `--mode ask` in an empty temp workspace: the model only answers, it cannot edit files or run commands
    * the system prompt is prepended to the user prompt (the CLI has no system-prompt flag)
    * max_tokens cannot be set on this CLI; the generator's own truncation checks still apply
    * model is passed as-is, e.g. 'grok-4.7-high-fast' or a bracketed form 'name[effort=high]' (see `agent --list-models`)
    """
    _QUOTA_MARKERS = ("usage limit", "out of usage", "limit reached", "quota", "upgrade your plan", "spend limit")
    _TRANSIENT_MARKERS = ("overloaded", "rate limit", "429", "503", "timed out", "temporarily", "econnreset",
                          "unavailable", "network")

    def __init__(self, agent_bin: str, timeout: float, retries: int = 3):
        resolved = shutil.which(agent_bin) or shutil.which(os.path.expanduser(f"~/.local/bin/{agent_bin}"))
        if not resolved:
            raise SystemExit(f"`{agent_bin}` not found (install: curl https://cursor.com/install -fsS | bash; "
                             "then `agent login`)")
        self.agent_bin, self.timeout, self.retries = resolved, timeout, retries

    def complete(self, model: str, system: str, messages: list[dict], max_tokens: int) -> tuple[str, dict]:
        prompt = f"{system}\n\n---\n\n{CliBackend._flatten(messages)}"
        env = {k: v for k, v in os.environ.items()
               if k not in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL")}
        last = "unknown"
        for attempt in range(1, self.retries + 1):
            with tempfile.TemporaryDirectory(prefix="cursorgen_") as cwd:
                cmd = [self.agent_bin, "-p", "--output-format", "json", "--mode", "ask", "--trust",
                       "--workspace", cwd, "--model", model]
                try:
                    proc = subprocess.run(cmd, input=prompt, capture_output=True, text=True,
                                          timeout=self.timeout, cwd=cwd, env=env)
                except subprocess.TimeoutExpired:
                    log.warning("cursor agent call timed out after %ss (model %s); not retried", self.timeout, model)
                    raise RuntimeError(f"cursor agent timed out after {self.timeout}s")
            text, usage, err = self._parse(proc)
            if not err:
                return text, usage
            last = err
            low = err.lower()
            if "authentication required" in low or "not logged in" in low:
                raise SystemExit("Cursor agent is not logged in: run `agent login` (or set CURSOR_API_KEY)")
            if any(m in low for m in self._QUOTA_MARKERS):
                raise QuotaExhausted(err)
            if not any(m in low for m in self._TRANSIENT_MARKERS):
                raise RuntimeError(err)
            if attempt < self.retries:
                delay = 5 * 2 ** (attempt - 1)
                log.info("cursor agent call failed (attempt %d/%d), retrying in %ds: %s", attempt, self.retries, delay, last[:200])
                time.sleep(delay)
        raise RuntimeError(f"cursor agent failed after {self.retries} attempts: {last[:300]}")

    @staticmethod
    def _parse(proc: subprocess.CompletedProcess) -> tuple[str, dict, Optional[str]]:
        raw = (proc.stdout or "").strip()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return "", {}, f"unparseable agent output (exit {proc.returncode}): {(proc.stderr or raw)[-300:]}"
        if isinstance(data, list):
            data = next((d for d in reversed(data) if isinstance(d, dict) and d.get("type") == "result"), {})
        if data.get("is_error") or proc.returncode != 0:
            return "", {}, str(data.get("result") or proc.stderr or "agent reported an error")[:500]
        u = data.get("usage") or {}
        return data.get("result", ""), {"input_tokens": u.get("inputTokens", u.get("input_tokens", 0)),
                                         "output_tokens": u.get("outputTokens", u.get("output_tokens", 0))}, None


class HandoffPending(Exception):
    """No response file exists yet for this request: it was written to the handoff queue and the candidate is
    deferred (no strike) until a Cursor agent (or a human) answers it and stage 3 is re-run."""


class HandoffBackend:
    """File-drop backend for models we can only reach through the Cursor IDE (no API key, no CLI).

    complete() never calls a model:
      * hash(system + messages) -> <HANDOFF_DIR>/requests/<label>__<hash>.md   (the full prompt)
      * if <HANDOFF_DIR>/responses/<label>__<hash>.md exists -> its text is returned as the model reply, so the
        generator's own extraction, validation and retry logic run on it unchanged
      * otherwise the request is written and HandoffPending is raised (candidate deferred, resumable)
    A validation failure produces a new request (the generator appends the validator's complaint), hence a new hash.
    """
    _tls = threading.local()

    def __init__(self, root: Optional[str] = None):
        from pathlib import Path
        self.root = Path(root or os.environ.get("HANDOFF_DIR") or Path(__file__).resolve().parents[2] / "data" / "handoff")
        (self.root / "requests").mkdir(parents=True, exist_ok=True)
        (self.root / "responses").mkdir(parents=True, exist_ok=True)

    def set_label(self, label: str) -> None:
        self._tls.label = label
        self._tls.n = 0           # call counter for this candidate in this stage-3 run

    def complete(self, model: str, system: str, messages: list[dict], max_tokens: int) -> tuple[str, dict]:
        """Requests are named by candidate + call number (<label>__c<n>.md), not by a hash of the prompt. The generator
        replays the same call sequence on every stage-3 run (the answers are fixed files and the validators are
        deterministic), so call n is the same step each time. A content hash broke whenever stage 5 refreshed the
        knowledge text inside the prompt: every answer in flight was orphaned (2026-10-20). The old hash name is still
        read as a fallback, so answers written under it keep working."""
        import hashlib
        body = CliBackend._flatten(messages)
        digest = hashlib.sha1((system + "\n\x00\n" + body).encode("utf-8")).hexdigest()[:10]
        label = getattr(self._tls, "label", "task")
        self._tls.n = getattr(self._tls, "n", 0) + 1
        name = f"{label}__c{self._tls.n}.md"
        for candidate in (name, f"{label}__{digest}.md"):          # stable name first, then the legacy hash name
            resp = self.root / "responses" / candidate
            if resp.is_file() and resp.stat().st_size > 0:
                return resp.read_text(encoding="utf-8"), {"input_tokens": 0, "output_tokens": 0}
        req = self.root / "requests" / name
        content = f"<!-- label={label} call={self._tls.n} hash={digest} -->\n# SYSTEM\n{system}\n\n# REQUEST\n{body}\n"
        if not req.is_file() or req.read_text(encoding="utf-8") != content:   # always the CURRENT prompt
            req.write_text(content, encoding="utf-8")
            log.info("handoff request written: %s", req.name)
        raise HandoffPending(name)


def extract_json_object(text: str) -> dict:
    """First top-level JSON object in a model reply (tolerates prose and ``` fences around it)."""
    start = text.find("{")
    while start != -1:
        depth = 0
        for i in range(start, len(text)):
            depth += (text[i] == "{") - (text[i] == "}")
            if depth == 0:
                try:
                    obj = json.loads(text[start:i + 1])
                    if isinstance(obj, dict):
                        return obj
                except json.JSONDecodeError:
                    pass
                break
        start = text.find("{", start + 1)
    raise ValueError("no JSON object found in model output")
