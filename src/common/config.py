"""Central configuration: paths and secrets, loaded from the environment / .env."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _default_harbor() -> str:
    """harbor from the interpreter's own venv if present (works without activating it), else PATH."""
    import sys
    local = Path(sys.executable).parent / "harbor"
    return str(local) if local.exists() else "harbor"

# Pipeline station -> data directory that holds its *output*.
STAGE_DATA_DIRS: dict[int, str] = {
    1: "01_mined",
    2: "02_screened",
    3: "03_environments",   # stage 3 builds envs + task files; stage 4 adds oracle_validation.json here
    4: "03_environments",
    5: "04_eval_runs",
    6: "05_accepted_harbor",
}


@dataclass(frozen=True)
class ModelEndpoint:
    """One evaluation target: which Harbor agent runs it, with which model string and credentials."""
    tag: str                       # filesystem-safe label, e.g. "deepseek"
    model: str                     # vendor model id as configured (e.g. in .env)
    agent: str                     # Harbor agent name (terminus-2, mimo, ...)
    harbor_model: str              # value for `harbor run -m` (provider/model)
    api_key: str
    env: dict = field(default_factory=dict)           # passed to the harbor process (keys never go on argv)
    agent_kwargs: dict = field(default_factory=dict)  # --ak key=value
    check_url: Optional[str] = None                   # OpenAI-compatible base for the 1-token ping, if known
    in_container: bool = False                        # agent runs inside the task container (needs network)
    agent_env: dict = field(default_factory=dict)     # non-secret env for the agent process (--ae key=value)
    api_host: Optional[str] = None                    # the ONLY host the container may reach (allowlist)

    def masked(self) -> str:
        return f"{self.tag}: agent={self.agent} model={self.harbor_model} key=…{self.api_key[-4:]}"


class ConfigError(Exception):
    pass


TIMEOUT_POLICIES = ("count", "exclude")


def _timeout_policy(value: Optional[str]) -> str:
    v = (value or "exclude").strip().lower()
    if v not in TIMEOUT_POLICIES:
        raise ConfigError(f"TIMEOUT_POLICY must be one of {TIMEOUT_POLICIES}, got {value!r}")
    return v


@dataclass(frozen=True)
class Config:
    root: Path
    data_dir: Path
    github_token: Optional[str]
    anthropic_api_key: Optional[str]
    anthropic_model: str
    claude_bin: str
    task_gen_backend: str      # "deepseek" (DeepSeek API, default since 2026-10-21) | "cli" | "api" | "cursor" | "handoff"
    harbor_bin: str
    eval_agent: str            # Harbor agent used for target models
    eval_attempts: int
    max_containers: int        # concurrent task containers allowed across stage 5
    published_after: str       # only fixes committed after this date (YYYY-MM-DD); '' = no filter
    task_cpus: int
    task_memory_mb: int
    agent_timeout_sec: int     # per-attempt agent budget written into task.toml
    # ONE timeout rule for every verdict (stage 5, ledger, re-verdicts). A scored run that hit the agent time limit is:
    #   exclude  NOT a model failure (agreed rule, 2026-10-15): a task whose only non-solves are timeouts is rejected
    #   count    a model failure, but only if the run had the full budget (>= full_budget_sec)
    timeout_policy: str = "exclude"
    full_budget_sec: int = 7000

    @classmethod
    def load(cls, data_dir: Optional[Path] = None, env_file: Optional[Path] = None) -> "Config":
        load_dotenv(dotenv_path=env_file or PROJECT_ROOT / ".env", override=False)
        env = os.environ.get
        return cls(
            root=PROJECT_ROOT,
            data_dir=(data_dir or Path(env("CWE_DATA_DIR") or PROJECT_ROOT / "data")).resolve(),
            github_token=env("GITHUB_TOKEN") or None,
            anthropic_api_key=env("ANTHROPIC_API_KEY") or None,
            anthropic_model=env("ANTHROPIC_MODEL", "claude-fable-5-1"),
            claude_bin=env("CLAUDE_BIN", "claude"),
            task_gen_backend=env("TASK_GEN_BACKEND", "cli"),
            harbor_bin=env("HARBOR_BIN") or _default_harbor(),
            eval_agent=env("EVAL_AGENT", "claude-code"),
            eval_attempts=int(env("EVAL_ATTEMPTS", "3")),
            max_containers=int(env("MAX_CONTAINERS", "4")),
            published_after=(env("PUBLISHED_AFTER") or "").strip(),
            task_cpus=int(env("TASK_CPUS", "2")),
            task_memory_mb=int(env("TASK_MEMORY_MB", "3072")),
            agent_timeout_sec=int(env("AGENT_TIMEOUT_SEC", "3600")),
            timeout_policy=_timeout_policy(env("TIMEOUT_POLICY", "exclude")),
            full_budget_sec=int(env("FULL_BUDGET_SEC", "7000")),
        )

    def eval_endpoints(self) -> list[ModelEndpoint]:
        """DeepSeek + MiMo targets from the environment. Raises ConfigError listing what is missing.

        Default harness: Harbor's `claude-code` agent for BOTH models, talking to each vendor's Anthropic-compatible API
        (DeepSeek: https://api.deepseek.com/anthropic, MiMo: https://api.xiaomimimo.com/anthropic). WebSearch/WebFetch are
        disabled and the container may reach only the vendor API host. `<PREFIX>_REASONING_EFFORT` sets Claude Code's
        --effort (DeepSeek default: max, per the "DeepSeek V4.1 Flash (max)" target). Set <PREFIX>_AGENT=terminus-2 to use
        the host-side Terminus-2 agent with the OpenAI-compatible endpoint instead (container fully offline).
        """
        from urllib.parse import urlparse
        e = os.environ.get
        missing: list[str] = []

        def need(name: str) -> str:
            v = (e(name) or "").strip()
            if not v:
                missing.append(name)
            return v

        spec = [  # tag, env prefix, OpenAI-compatible base, Anthropic-compatible base, default effort
            ("deepseek", "DEEPSEEK", "https://api.deepseek.com", "https://api.deepseek.com/anthropic", "max"),
            ("mimo", "MIMO", "https://api.xiaomimimo.com/v1", "https://api.xiaomimimo.com/anthropic", ""),
        ]
        creds = {tag: (need(f"{p}_API_KEY"), need(f"{p}_MODEL")) for tag, p, *_ in spec}
        if missing:
            raise ConfigError("missing environment variables: " + ", ".join(missing))

        out: list[ModelEndpoint] = []
        for tag, prefix, openai_default, anthropic_default, effort_default in spec:
            key, model = creds[tag]
            model_id = model.split("/")[-1]
            openai_base = ((e(f"{prefix}_BASE_URL") or "").strip() or openai_default).rstrip("/")
            agent = (e(f"{prefix}_AGENT") or self.eval_agent).strip()
            if agent == "claude-code":
                anth = ((e(f"{prefix}_ANTHROPIC_BASE_URL") or "").strip() or anthropic_default).rstrip("/")
                effort = (e(f"{prefix}_REASONING_EFFORT") if e(f"{prefix}_REASONING_EFFORT") is not None
                          else effort_default).strip()
                kwargs = {"disable_web_search": "true"}
                if effort:
                    kwargs["reasoning_effort"] = effort
                out.append(ModelEndpoint(
                    tag, model, agent, f"anthropic/{model_id}", key,
                    # secret + endpoint: via the harbor process environment, never argv
                    env={"ANTHROPIC_API_KEY": key, "ANTHROPIC_BASE_URL": anth, "ANTHROPIC_MODEL": model_id,
                         "ANTHROPIC_AUTH_TOKEN": key},   # override host values (e.g. our own Opus settings)
                    agent_kwargs=kwargs,
                    # every Claude Code model slot -> the target model (no silent fallback to another model),
                    # and no telemetry/update traffic (it would be blocked by the allowlist anyway)
                    agent_env={"ANTHROPIC_MODEL": model_id, "ANTHROPIC_SMALL_FAST_MODEL": model_id,
                               "ANTHROPIC_DEFAULT_HAIKU_MODEL": model_id, "ANTHROPIC_DEFAULT_SONNET_MODEL": model_id,
                               "ANTHROPIC_DEFAULT_OPUS_MODEL": model_id, "CLAUDE_CODE_SUBAGENT_MODEL": model_id,
                               "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "DISABLE_AUTOUPDATER": "1"},
                    check_url=openai_base, in_container=True, api_host=urlparse(anth).hostname))
            elif agent == "terminus-2":
                # Host-side agent: LLM calls + keys stay on the host; the task container has NO network at all.
                prov = "deepseek" if tag == "deepseek" else "openai"
                env_ = ({"DEEPSEEK_API_KEY": key, "DEEPSEEK_BASE_URL": openai_base} if tag == "deepseek" else
                        {"OPENAI_API_KEY": key, "OPENAI_API_BASE": openai_base, "OPENAI_BASE_URL": openai_base})
                effort = (e(f"{prefix}_REASONING_EFFORT") if e(f"{prefix}_REASONING_EFFORT") is not None
                          else effort_default).strip()
                kwargs = {} if tag == "deepseek" else {"api_base": openai_base}
                if effort:
                    kwargs["reasoning_effort"] = effort
                # Harbor assumes a 1M-token context for models LiteLLM does not know, so it would never summarise before
                # the real window is full. With the real size set, it summarises in time instead of failing mid-run;
                # time (AGENT_TIMEOUT_SEC) stays the only limit on a run. There is no turn cap (max_turns unset).
                ctx = (e(f"{prefix}_CONTEXT_TOKENS") or "").strip()
                if ctx:
                    info = {"max_input_tokens": int(ctx), "input_cost_per_token": 0, "output_cost_per_token": 0}
                    if (e(f"{prefix}_MAX_OUTPUT_TOKENS") or "").strip():
                        info["max_output_tokens"] = int(e(f"{prefix}_MAX_OUTPUT_TOKENS"))
                    kwargs["model_info"] = json.dumps(info)
                out.append(ModelEndpoint(tag, model, agent, f"{prov}/{model_id}", key, env=env_,
                                         agent_kwargs=kwargs, check_url=openai_base))
            else:   # e.g. Harbor's own `mimo` CLI agent - runs in the container, endpoint built in
                out.append(ModelEndpoint(tag, model, agent, model if "/" in model else f"{tag}/{model}", key,
                                         env={f"{prefix}_API_KEY": key}, check_url=openai_base, in_container=True))
        return out

    def agent_network_policy(self) -> tuple[str, list[str]]:
        """(network_mode, allowed_hosts) for the agent phase in task.toml.
        In-container agents (claude-code) get an allowlist with ONLY the vendor API hosts; host-side agents get no network."""
        forced = (os.environ.get("AGENT_NETWORK") or "").strip()
        try:
            eps = self.eval_endpoints()
        except ConfigError:
            eps = []
        hosts = sorted({ep.api_host for ep in eps if ep.in_container and ep.api_host})
        if forced:
            return forced, (hosts if forced == "allowlist" else [])
        if any(ep.in_container for ep in eps):
            # Internal Docker network + egress proxy allowing only these hosts (works on Docker Desktop for Mac,
            # unlike Harbor's nftables-based allowlist). AGENT_NETWORK=allowlist selects Harbor's own mode on Linux.
            return ("proxy", hosts) if hosts else ("public", [])
        return "no-network", []

    @property
    def agent_network(self) -> str:
        return self.agent_network_policy()[0]

    @property
    def preinstall_claude_code(self) -> bool:
        try:
            return any(ep.agent == "claude-code" for ep in self.eval_endpoints())
        except ConfigError:
            return False

    def stage_dir(self, stage: int) -> Path:
        path = self.data_dir / STAGE_DATA_DIRS[stage]
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def state_db(self) -> Path:
        return self.data_dir / "pipeline_state.sqlite3"

    @property
    def cache_dir(self) -> Path:
        return self.data_dir / ".cache"
