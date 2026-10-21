FROM python:3.11-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends git build-essential curl tmux asciinema \
    && rm -rf /var/lib/apt/lists/*
# The repo's git history is a single snapshot commit (answer-key hygiene), so version-from-git-tags tooling
# (setuptools_scm, hatch-vcs, pbr) would report 0.1.dev1 and break dependency resolution. Pin a high version.
ENV SETUPTOOLS_SCM_PRETEND_VERSION=999.0.0 PBR_VERSION=999.0.0
RUN pip install --no-cache-dir pytest==8.4.1 pytest-json-ctrf==0.3.5
# Agent harness baked into the image (same native installer Harbor uses on Debian; needs no Node.js, so the project's own
# Node version is untouched). Nothing is downloaded during the allowlisted agent phase.
RUN curl -fsSL https://downloads.claude.ai/claude-code-releases/bootstrap.sh | bash -s -- 2.1.292 \
    && ln -sf "$HOME/.local/bin/claude" /usr/local/bin/claude && claude --version
WORKDIR /app
COPY repo/ /app/
RUN (pip install --no-cache-dir -e ".[test,tests,testing,dev]" || pip install --no-cache-dir -e . || true) \
    && for f in requirements.txt requirements-dev.txt requirements_dev.txt requirements-test.txt \
                requirements_test.txt requirements/test.txt requirements/dev.txt dev-requirements.txt \
                test-requirements.txt; do \
         if [ -f "$f" ]; then pip install --no-cache-dir -r "$f" || true; fi; \
       done
RUN cd /app && git -c safe.directory=/app -c user.name=image -c user.email=image@localhost add -A -- . ':!node_modules' ':!**/node_modules' >/dev/null 2>&1; git -c safe.directory=/app -c user.name=image -c user.email=image@localhost commit -q --allow-empty -m 'image build state' >/dev/null 2>&1; git -c safe.directory=/app -c user.name=image -c user.email=image@localhost rev-parse HEAD > /etc/.cwe_image_commit 2>/dev/null; touch /etc/.cwe_image_built
