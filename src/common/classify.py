"""Path classification shared by screening (what did the fix touch?) and packaging (strip tests from the oracle)."""
from __future__ import annotations

import re
from pathlib import PurePosixPath

TEST_PATH_RE = re.compile(
    r"(^|/)(tests?|__tests__|spec|specs|testing|testdata)(/|$)"
    r"|(^|/)(test_[^/]+|[^/]+_test\.\w+|[^/]+\.(test|spec)\.\w+|conftest\.py|[^/]+Tests?\.php)$",
    re.IGNORECASE)
GENERATED_RE = re.compile(
    r"(^|/)(node_modules|vendor|_vendor|third_party|dist|build|\.min)(/|$)|\.min\.(js|css)$|\.map$|\.snap$"
    r"|\.pb(\.gw)?\.go$|(^|/)zz_generated[^/]*\.go$|_gen(erated)?\.go$",
    re.IGNORECASE)
DOC_RE = re.compile(
    r"\.(md|markdown|rst|txt|adoc)$|(^|/)(docs?|documentation|examples?)(/|$)|(^|/)(CHANGELOG|CHANGES|HISTORY|LICENSE|NOTICE|AUTHORS|README)[^/]*$",
    re.IGNORECASE)
MANIFEST_NAMES = {
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "pipfile", "pipfile.lock", "poetry.lock", "pdm.lock", "uv.lock", "pyproject.toml", "setup.cfg",
    "constraints.txt", "tox.ini", "bower.json", "renovate.json", "go.mod", "go.sum", "go.work", "go.work.sum",
    "composer.json", "composer.lock",
}
MANIFEST_RE = re.compile(r"(^|/)(requirements[^/]*\.(txt|in)|constraints[^/]*\.txt)$", re.IGNORECASE)
CONFIG_RE = re.compile(
    r"\.(ya?ml|toml|ini|cfg|conf|json|lock|env|properties)$|(^|/)\.[^/]+$|(^|/)(Dockerfile[^/]*|Makefile|MANIFEST\.in|\.github/.*)$",
    re.IGNORECASE)

PY_EXT = {".py"}
JS_EXT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
GO_EXT = {".go"}
PHP_EXT = {".php"}
SUPPORTED_EXT = {"PyPI": PY_EXT, "npm": JS_EXT, "Go": GO_EXT, "Packagist": PHP_EXT}


def classify(path: str, ecosystem: str) -> str:
    """One of: generated, test, docs, manifest, config, source, other_code."""
    name = PurePosixPath(path).name.lower()
    ext = PurePosixPath(path).suffix.lower()
    if GENERATED_RE.search(path):
        return "generated"
    if TEST_PATH_RE.search(path):
        return "test"
    if name in MANIFEST_NAMES or MANIFEST_RE.search(path):
        return "manifest"
    if DOC_RE.search(path):
        return "docs"
    if ext in SUPPORTED_EXT.get(ecosystem, set()):
        return "source"
    if CONFIG_RE.search(path):
        return "config"
    return "other_code"


def is_test_path(path: str) -> bool:
    return bool(TEST_PATH_RE.search(path))
