"""Fail-fast buildability check, run BEFORE the (expensive) Opus generation.

Builds the pre-patch repo in Docker with a STRICT install (the real task image tolerates install failures; this one does
not). Repos that cannot be installed are rejected here, so no Opus quota is spent writing tasks that stage 4 would only
discard. A `Dockerfile.override` in the environment folder is honoured (and tested) as-is.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import time
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from src.stage6_packager.harbor_packager import (DOCKERFILE_OVERRIDE, NODE_BASE, PY_BASE, UV_WORKSPACE_INSTALL, _link_or_copy,
                                                 node_base_image, python_base_image)

log = logging.getLogger(__name__)

PY_STRICT = f"""\
FROM {PY_BASE}
RUN apt-get update && apt-get install -y --no-install-recommends git build-essential curl && rm -rf /var/lib/apt/lists/*
ENV SETUPTOOLS_SCM_PRETEND_VERSION=999.0.0 PBR_VERSION=999.0.0
WORKDIR /app
COPY repo/ /app/
RUN ({UV_WORKSPACE_INSTALL}) || pip install --no-cache-dir -e . || (test -f requirements.txt && pip install --no-cache-dir -r requirements.txt)
"""
from src.stage6_packager.harbor_packager import NODE_INSTALL  # same package-manager logic as the task image

GO_STRICT = """\
FROM golang:1.24-bookworm
ENV GOTOOLCHAIN=auto
WORKDIR /app
COPY repo/ /app/
RUN go mod download && go build ./...
"""

from src.stage6_packager.harbor_packager import PHP_DOCKERFILE, php_base_image, PHP_BASE  # noqa: E402

# strict: the composer install must succeed (the task image tolerates a failure; the build check does not)
PHP_STRICT = PHP_DOCKERFILE.rstrip("\n").removesuffix(" || true") + "\n"

NODE_STRICT = f"""\
FROM node:22-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends git build-essential && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY repo/ /app/
{NODE_INSTALL}
"""


def docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        subprocess.run(["docker", "info"], check=True, capture_output=True, timeout=30)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


def dockerfile_for(env_dir: Path, ecosystem: str) -> str:
    """The exact Dockerfile the build check uses for this environment."""
    repo = env_dir / "repo"
    override = env_dir / DOCKERFILE_OVERRIDE
    dockerfile = override.read_text() if override.is_file() else {"PyPI": PY_STRICT, "Go": GO_STRICT, "Packagist": PHP_STRICT}.get(ecosystem, NODE_STRICT)
    if ecosystem == "PyPI" and not override.is_file():
        dockerfile = dockerfile.replace(f"FROM {PY_BASE}\n", f"FROM {python_base_image(repo)}\n", 1)
    if ecosystem == "npm" and not override.is_file():
        dockerfile = dockerfile.replace(f"FROM {NODE_BASE}\n", f"FROM {node_base_image(repo)}\n", 1)
    if ecosystem == "Packagist" and not override.is_file():
        dockerfile = dockerfile.replace(f"FROM {PHP_BASE}\n", f"FROM {php_base_image(repo)}\n", 1)
    return dockerfile


def dockerfile_fingerprint(env_dir: Path, ecosystem: str) -> str:
    import hashlib
    return hashlib.sha1(dockerfile_for(env_dir, ecosystem).encode()).hexdigest()[:12]


def check_buildable(env_dir: Path, ecosystem: str, timeout: int = 1800) -> tuple[bool, str]:
    osv_id = env_dir.name
    repo = env_dir / "repo"
    if not repo.is_dir():
        return False, "repo/ missing"
    dockerfile = dockerfile_for(env_dir, ecosystem)
    tag = f"cwe-buildcheck-{osv_id.lower()}"
    for attempt in range(3):          # registry/network hiccups are retried, never turned into a rejection
        with tempfile.TemporaryDirectory(prefix="buildcheck_") as ctx_s:
            ctx = Path(ctx_s)
            try:
                shutil.copytree(repo, ctx / "repo", symlinks=True, copy_function=_link_or_copy)
            except (shutil.Error, OSError) as e:   # e.g. a file vanished mid-copy: retry, never crash the stage
                if attempt == 2:
                    return False, TRANSIENT + f"could not copy the repo for the build check: {str(e)[:200]}"
                continue
            (ctx / "Dockerfile").write_text(dockerfile)
            try:
                proc = subprocess.run(["docker", "build", "--progress=plain", "-t", tag, str(ctx)], capture_output=True,
                                      text=True, timeout=timeout)
            except subprocess.TimeoutExpired:
                return False, f"{TRANSIENT}docker build timed out after {timeout}s"
            finally:
                subprocess.run(["docker", "image", "rm", "-f", tag], capture_output=True)
        if proc.returncode == 0:
            return True, "docker build ok"
        full = (proc.stderr or "") + (proc.stdout or "")
        tail = full.strip().splitlines()[-6:]
        if not TRANSIENT_RE.search(full):
            return False, "docker build failed: " + " | ".join(tail)[:500]
        time.sleep(30 * (attempt + 1))
    return False, f"{TRANSIENT}docker build failed with network/registry errors 3 times: " + " | ".join(tail)[:400]


TRANSIENT = "TRANSIENT: "      # not cached and not a rejection: the next stage-3 run tries again
TRANSIENT_RE = re.compile(r"trouble with your network|malformed response from registry|registry may be down|ECONNRESET|"
                          r"ETIMEDOUT|EAI_AGAIN|ENOTFOUND|socket hang up|Temporary failure in name resolution|"
                          r"Read timed out|Connection (reset|refused|timed out)|TLS handshake timeout|"
                          r"failed to (fetch|resolve|do request)|i/o timeout|503 Service|502 Bad Gateway|429 Too Many|"
                          r"context canceled|Canceled: context|Cannot connect to the Docker daemon|EOF while|"
                          r"input/output error|no space left on device|error committing|metadata.*\.db",
                          re.IGNORECASE)


def run_checks(env_dir_root: Path, ids: list[str], meta: dict[str, dict]) -> dict[str, tuple[bool, str]]:
    """Check each environment once; results cached in <env>/build_check.json."""
    out: dict[str, tuple[bool, str]] = {}
    for osv_id in ids:
        env = env_dir_root / osv_id
        cache = env / "build_check.json"
        eco = meta.get(osv_id, {}).get("ecosystem", "PyPI")
        fp = dockerfile_fingerprint(env, eco) if (env / "repo").is_dir() else ""
        if cache.is_file():
            c = json.loads(cache.read_text())
            # a result is only reused for the Dockerfile it was built with: after a template fix (PHP, 2026-10-20)
            # a cached failure would otherwise reject the candidate forever. Old entries without a fingerprint are
            # trusted when they passed and re-checked when they failed.
            if c.get("dockerfile") == fp or (c["ok"] and "dockerfile" not in c):
                out[osv_id] = (c["ok"], c["detail"])
                continue
            log.info("Build check re-run: the Dockerfile changed since the cached result", extra={"osv_id": osv_id})
        ok, detail = check_buildable(env, eco)
        if not detail.startswith(TRANSIENT):
            cache.write_text(json.dumps({"ok": ok, "detail": detail, "dockerfile": fp}))
        log.info("Build check", extra={"osv_id": osv_id, "ok": ok, "detail": detail[:200]})
        out[osv_id] = (ok, detail)
    return out
