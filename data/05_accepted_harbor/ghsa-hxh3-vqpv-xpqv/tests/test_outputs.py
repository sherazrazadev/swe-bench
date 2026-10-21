import os
import subprocess
import uuid

import pytest

REPO_ROOT = os.environ.get("REPO_ROOT", os.getcwd())
VITEST_BIN = os.path.join(REPO_ROOT, "node_modules", ".bin", "vitest")

# The temp test lives inside src/jsx so the project's own vitest config, JSX
# tooling and relative imports resolve exactly as they do for the repo's tests.
TEMPLATE = r"""
import { test } from 'vitest'
import * as fs from 'node:fs'
import { jsx, Suspense, ErrorBoundary, createContext } from './index'
import { raw } from '../helper/html'
import { renderToString, renderToReadableStream } from './dom/server'
import { HtmlEscapedCallbackPhase, resolveCallback } from '../utils/html'

const unsafe = '<img src=x onerror=alert(1)>'
const escaped = '&lt;img src=x onerror=alert(1)&gt;'

async function stringify(node) {
  return String(
    await resolveCallback(await node.toString(), HtmlEscapedCallbackPhase.Stringify, false, {})
  )
}

async function drain(stream) {
  const reader = stream.getReader()
  const dec = new TextDecoder()
  let out = ''
  for (;;) {
    const r = await reader.read()
    if (r.done) break
    out += dec.decode(r.value)
  }
  return out
}

function ok(cond, msg) {
  if (!cond) throw new Error(msg || 'assertion failed')
}

test('sectest', async () => {
__BODY__
  fs.writeFileSync(process.env.SECTEST_MARKER, 'OK')
})
"""


def _run_vitest(body, marker_path):
    """Run `body` as a single vitest case against src/; returns (marker_written, output)."""
    assert os.path.exists(VITEST_BIN), (
        "vitest binary not found at %s; run `npm install`/`bun install` first" % VITEST_BIN
    )
    name = "__sectest_%s.test.ts" % uuid.uuid4().hex
    rel = os.path.join("src", "jsx", name)
    abspath = os.path.join(REPO_ROOT, rel)
    with open(abspath, "w") as f:
        f.write(TEMPLATE.replace("__BODY__", body))
    env = dict(os.environ)
    env["SECTEST_MARKER"] = str(marker_path)
    try:
        proc = subprocess.run(
            [VITEST_BIN, "run", rel, "--no-color"],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=240,
        )
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    finally:
        try:
            os.remove(abspath)
        except OSError:
            pass
    return os.path.exists(str(marker_path)), output


def assert_safe(body, marker_path):
    """Hostile input must be handled safely (escaped); marker only written if JS asserts pass."""
    written, output = _run_vitest(body, marker_path)
    assert written, "expected hostile input to be neutralised (escaped), but it was not:\n" + output


def assert_works(body, marker_path):
    """Legitimate usage must keep working; marker only written if JS asserts pass."""
    written, output = _run_vitest(body, marker_path)
    assert written, "expected legitimate rendering to work, but it did not:\n" + output


# --------------------------------------------------------------------------
# Security tests: must FAIL on vulnerable code, PASS after a correct fix.
# Each is a distinct entry point / variant that shares the same root cause,
# so a fix that only patches the single reported path still fails here.
# --------------------------------------------------------------------------

def test_security_deferred_placeholder_boundary_escapes_string_child(tmp_path):
    """Untrusted text beside an async child in a deferred/placeholder boundary must be escaped."""
    marker = tmp_path / "m"
    body = """
  const Async = async () => jsx('span', null, 'done')
  const node = jsx(Suspense, { fallback: 'loading' }, unsafe, jsx(Async, null))
  const out = await drain(await renderToReadableStream(node))
  ok(!out.includes(unsafe), 'raw markup present in output')
  ok(out.includes(escaped), 'escaped form missing from output')
"""
    assert_safe(body, marker)


def test_security_error_fallback_boundary_escapes_string_child(tmp_path):
    """Untrusted text in an error-fallback boundary with an async sibling must be escaped."""
    marker = tmp_path / "m"
    body = """
  const Async = async () => jsx('span', null, 'done')
  const node = jsx(ErrorBoundary, { fallback: 'error' }, unsafe, jsx(Async, null))
  const out = await stringify(node)
  ok(!out.includes(unsafe), 'raw markup present in output')
  ok(out.includes(escaped), 'escaped form missing from output')
"""
    assert_safe(body, marker)


def test_security_value_provider_escapes_single_string_child(tmp_path):
    """A lone untrusted string child of the shared-value provider must be escaped."""
    marker = tmp_path / "m"
    body = """
  const C = createContext('d')
  const node = jsx(C.Provider, { value: 'd' }, unsafe)
  const out = await stringify(node)
  ok(!out.includes(unsafe), 'raw markup present in output')
  ok(out.includes(escaped), 'escaped form missing from output')
"""
    assert_safe(body, marker)


def test_security_render_to_string_escapes_string_root(tmp_path):
    """A bare untrusted string given to the sync server renderer must be escaped."""
    marker = tmp_path / "m"
    body = """
  const out = renderToString(unsafe)
  ok(!out.includes(unsafe), 'raw markup present in output')
  ok(out.includes(escaped), 'escaped form missing from output')
"""
    assert_safe(body, marker)


def test_security_render_to_string_escapes_array_root(tmp_path):
    """An array of untrusted strings given to the sync server renderer must be escaped."""
    marker = tmp_path / "m"
    body = """
  const out = renderToString([unsafe, [unsafe]])
  ok(!out.includes(unsafe), 'raw markup present in output')
  ok(out.includes(escaped), 'escaped form missing from output')
"""
    assert_safe(body, marker)


def test_security_render_to_stream_escapes_string_root(tmp_path):
    """A bare untrusted string given to the streaming server renderer must be escaped."""
    marker = tmp_path / "m"
    body = """
  const out = await drain(await renderToReadableStream(unsafe))
  ok(!out.includes(unsafe), 'raw markup present in output')
  ok(out.includes(escaped), 'escaped form missing from output')
"""
    assert_safe(body, marker)


# --------------------------------------------------------------------------
# Functional tests: must PASS on both vulnerable and fixed code.
# A fix that disables the feature or over-escapes everything breaks these.
# --------------------------------------------------------------------------

def test_functional_plain_string_root_still_renders(tmp_path):
    """A harmless plain string must still render as its own visible text at the root."""
    marker = tmp_path / "m"
    body = """
  const out = renderToString('Hono')
  ok(out === 'Hono', 'plain string root not rendered verbatim: ' + out)
"""
    assert_works(body, marker)


def test_functional_trusted_raw_root_preserved(tmp_path):
    """Explicitly trusted raw HTML at the root must still be emitted as real markup."""
    marker = tmp_path / "m"
    body = """
  const out = renderToString(raw('<strong>trusted</strong>'))
  ok(out === '<strong>trusted</strong>', 'trusted raw markup was altered: ' + out)
"""
    assert_works(body, marker)


def test_functional_normal_element_tree_renders(tmp_path):
    """A normal element tree must still render to the expected HTML."""
    marker = tmp_path / "m"
    body = """
  const out = renderToString(jsx('h1', null, 'Hello'))
  ok(out === '<h1>Hello</h1>', 'element tree not rendered correctly: ' + out)
"""
    assert_works(body, marker)


def test_functional_value_provider_renders_text_child(tmp_path):
    """The shared-value provider must still render an ordinary string child as visible text."""
    marker = tmp_path / "m"
    body = """
  const C = createContext('d')
  const node = jsx(C.Provider, { value: 'd' }, 'hello world')
  const out = await stringify(node)
  ok(out === 'hello world', 'provider dropped/garbled its text child: ' + out)
"""
    assert_works(body, marker)


def test_functional_deferred_boundary_renders_text_and_async(tmp_path):
    """A deferred boundary must still show its ordinary text child and the resolved async child."""
    marker = tmp_path / "m"
    body = """
  const Async = async () => jsx('span', null, 'done')
  const node = jsx(Suspense, { fallback: 'wait' }, 'hello', jsx(Async, null))
  const out = await drain(await renderToReadableStream(node))
  ok(out.includes('hello'), 'ordinary text child missing: ' + out)
  ok(out.includes('<span>done</span>'), 'resolved async child missing: ' + out)
"""
    assert_works(body, marker)


def test_functional_error_boundary_renders_children_without_error(tmp_path):
    """An error-fallback boundary must still render its children normally when nothing throws."""
    marker = tmp_path / "m"
    body = """
  const node = jsx(ErrorBoundary, { fallback: 'error' }, jsx('div', null, 'content'))
  const out = await stringify(node)
  ok(out.includes('<div>content</div>'), 'children not rendered on the happy path: ' + out)
"""
    assert_works(body, marker)
