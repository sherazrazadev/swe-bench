import json
import os
import subprocess

import pytest

REPO = os.environ.get("REPO_ROOT") or os.getcwd()

DEEP = "100000"

PRELUDE = r"""
'use strict'
const msgpack = require(process.env.REPO_ROOT)
const util = require('util')
function nest (unitBytes, n, tailBytes) {
  const unit = Buffer.from(unitBytes)
  const body = n > 0 ? Buffer.alloc(unit.length * n, unit) : Buffer.alloc(0)
  return Buffer.concat([body, Buffer.from(tailBytes || [])])
}
function describeError (e) {
  const message = String(e && e.message)
  return {
    threw: true,
    name: String(e && e.name),
    stackOverflow: (e instanceof RangeError) && /call stack/i.test(message)
  }
}
function attempt (fn) {
  try { fn(); return { threw: false } } catch (e) { return describeError(e) }
}
function emit (obj) { process.stdout.write('\n@@RESULT@@' + JSON.stringify(obj) + '\n') }
"""


def run_node(body, timeout=180):
    env = dict(os.environ)
    env["REPO_ROOT"] = REPO
    try:
        proc = subprocess.run(
            ["node", "-e", PRELUDE + body],
            cwd=REPO,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        pytest.fail("node script timed out after %ss" % timeout)
    result = None
    for line in proc.stdout.splitlines():
        if line.startswith("@@RESULT@@"):
            result = json.loads(line[len("@@RESULT@@"):])
    if result is None:
        pytest.fail(
            "node script produced no result (rc=%s)\nstdout:\n%s\nstderr:\n%s"
            % (proc.returncode, proc.stdout[-2000:], proc.stderr[-4000:])
        )
    return result


def assert_blocked(outcome, what):
    assert outcome["threw"], "%s: hostile deeply nested input was accepted" % what
    assert not outcome["stackOverflow"], (
        "%s: input was only stopped by exhausting the engine call stack" % what
    )


# ---------------------------------------------------------------- security


def test_security_deep_fixarray_nesting_rejected():
    """Reported trigger: 100k nested one-element arrays must be refused without stack exhaustion."""
    res = run_node(
        "emit(attempt(() => msgpack().decode(nest([0x91], " + DEEP + ", [0xc0]))))"
    )
    assert_blocked(res, "nested fixarrays")


def test_security_deep_map_nesting_rejected():
    """Same flaw through nested single-entry maps (objects) instead of arrays."""
    res = run_node(
        "emit(attempt(() => msgpack().decode(nest([0x81, 0xa1, 0x78], " + DEEP + ", [0xc0]))))"
    )
    assert_blocked(res, "nested fixmaps")


def test_security_deep_wide_header_arrays_rejected():
    """Same flaw through arrays encoded with 16-bit and 32-bit length headers."""
    res = run_node(
        "emit({"
        " a16: attempt(() => msgpack().decode(nest([0xdc, 0x00, 0x01], " + DEEP + ", [0xc0]))),"
        " a32: attempt(() => msgpack().decode(nest([0xdd, 0x00, 0x00, 0x00, 0x01], " + DEEP + ", [0xc0])))"
        "})"
    )
    assert_blocked(res["a16"], "array16 nesting")
    assert_blocked(res["a32"], "array32 nesting")


def test_security_deep_wide_header_maps_rejected():
    """Same flaw through maps encoded with 16-bit and 32-bit length headers."""
    res = run_node(
        "emit({"
        " m16: attempt(() => msgpack().decode(nest([0xde, 0x00, 0x01, 0xa1, 0x78], " + DEEP + ", [0xc0]))),"
        " m32: attempt(() => msgpack().decode(nest([0xdf, 0x00, 0x00, 0x00, 0x01, 0xa1, 0x78], " + DEEP + ", [0xc0])))"
        "})"
    )
    assert_blocked(res["m16"], "map16 nesting")
    assert_blocked(res["m32"], "map32 nesting")


def test_security_deep_nesting_through_map_keys_rejected():
    """Nesting carried through map keys (not values) must be refused too."""
    res = run_node(
        "const n = " + DEEP + "\n"
        "const buf = nest([0x81], n, new Array(n + 1).fill(0xc0))\n"
        "emit(attempt(() => msgpack().decode(buf)))"
    )
    assert_blocked(res, "nesting via map keys")


def test_security_deep_mixed_nesting_inside_legit_wrapper_rejected():
    """Alternating array/map nesting embedded inside an ordinary envelope must be refused."""
    res = run_node(
        "const prefix = Buffer.from([0x93, 0x01, 0xa2, 0x6f, 0x6b, 0x81, 0xa4, 0x64, 0x61, 0x74, 0x61])\n"
        "const deep = nest([0x91, 0x81, 0xa1, 0x78], 50000, [0xc0])\n"
        "emit(attempt(() => msgpack().decode(Buffer.concat([prefix, deep]))))"
    )
    assert_blocked(res, "mixed nesting inside envelope")


def test_security_stream_interface_rejects_deep_nesting():
    """The streaming interface must report a controlled error, not engine stack exhaustion."""
    res = run_node(
        r"""
const pack = msgpack()
const d = pack.decoder()
const state = { errors: [] }
d.on('data', () => {})
d.on('error', (e) => { state.errors.push(describeError(e)) })
process.on('exit', () => emit(state))
const payload = Buffer.concat([
  Buffer.from([0x92, 0x01]),
  nest([0x81, 0xa1, 0x78, 0x91], 50000, [0xc0]),
  Buffer.from([0x02])
])
const all = Buffer.concat([pack.encode({ hello: 'world' }), payload])
const a = Math.floor(all.length / 3)
const b = Math.floor(2 * all.length / 3)
try {
  d.write(all.slice(0, a))
  d.write(all.slice(a, b))
  d.end(all.slice(b))
} catch (e) {
  state.errors.push(describeError(e))
}
"""
    )
    assert res["errors"], "stream accepted hostile deeply nested input without error"
    for err in res["errors"]:
        assert not err["stackOverflow"], "stream input was only stopped by engine stack exhaustion"


# ---------------------------------------------------------------- functional


def test_functional_hundred_level_arrays_unpack():
    """Arrays nested 100 levels deep (raw bytes and encoder output) must still round-trip."""
    res = run_node(
        r"""
const pack = msgpack()
let v = pack.decode(nest([0x91], 100, [0xc0]))
let rawOk = true
for (let i = 0; i < 100; i++) {
  if (!Array.isArray(v) || v.length !== 1) { rawOk = false; break }
  v = v[0]
}
rawOk = rawOk && v === null
let src = 'sentinel-7f3a'
for (let i = 0; i < 100; i++) src = [src]
const back = pack.decode(pack.encode(src))
emit({ rawOk, roundTrip: util.isDeepStrictEqual(back, src) })
"""
    )
    assert res["rawOk"], "100-level nested arrays no longer unpack correctly"
    assert res["roundTrip"], "100-level nested arrays no longer round-trip"


def test_functional_hundred_level_objects_unpack():
    """Objects/maps nested 100 levels deep must still round-trip."""
    res = run_node(
        r"""
const pack = msgpack()
let v = pack.decode(nest([0x81, 0xa1, 0x78], 100, [0xc0]))
let rawOk = true
for (let i = 0; i < 100; i++) {
  if (!v || typeof v !== 'object' || !('x' in v)) { rawOk = false; break }
  v = v.x
}
rawOk = rawOk && v === null
let src = 'sentinel-leaf'
for (let i = 0; i < 100; i++) src = { level: i, child: src }
const back = pack.decode(pack.encode(src))
emit({ rawOk, roundTrip: util.isDeepStrictEqual(back, src) })
"""
    )
    assert res["rawOk"], "100-level nested maps no longer unpack correctly"
    assert res["roundTrip"], "100-level nested objects no longer round-trip"


def test_functional_large_shallow_documents_unpack():
    """Many sibling containers (large but shallow) must not be mistaken for deep nesting."""
    res = run_node(
        r"""
const pack = msgpack()
const doc = { items: [] }
for (let i = 0; i < 3000; i++) {
  doc.items.push({ id: i, tags: ['a', 'b'], meta: { ok: true, n: [i, [i]] } })
}
let deep = 'bottom'
for (let i = 0; i < 90; i++) deep = (i % 2) ? { k: deep } : [deep]
doc.deep = deep
const siblings = []
for (let i = 0; i < 70000; i++) siblings.push([])
const r1 = util.isDeepStrictEqual(pack.decode(pack.encode(doc)), doc)
const r2 = util.isDeepStrictEqual(pack.decode(pack.encode(siblings)), siblings)
emit({ r1, r2 })
"""
    )
    assert res["r1"], "wide document with many nested siblings failed to round-trip"
    assert res["r2"], "array with 70000 sibling arrays failed to round-trip"


def test_functional_instance_reusable_after_rejection():
    """An instance that rejected hostile payloads must keep unpacking legitimate nested data."""
    res = run_node(
        r"""
const pack = msgpack()
for (let round = 0; round < 3; round++) {
  try { pack.decode(nest([0x91], 100000, [0xc0])) } catch (e) {}
  try { pack.decode(nest([0x81, 0xa1, 0x78], 100000, [0xc0])) } catch (e) {}
}
const checks = []
for (let round = 0; round < 3; round++) {
  let arr = null
  for (let i = 0; i < 100; i++) arr = [arr]
  let obj = 'leaf'
  for (let i = 0; i < 100; i++) obj = { x: obj }
  checks.push(util.isDeepStrictEqual(pack.decode(nest([0x91], 100, [0xc0])), arr))
  checks.push(util.isDeepStrictEqual(pack.decode(pack.encode(obj)), obj))
}
emit({ checks })
"""
    )
    assert all(res["checks"]), "legitimate nested data fails after a hostile payload was rejected"


def test_functional_stream_delivers_nested_messages():
    """The streaming interface must deliver legitimate 100-level messages even when fed byte by byte."""
    res = run_node(
        r"""
const pack = msgpack()
const d = pack.decoder()
const got = []
const errors = []
d.on('data', (v) => got.push(v))
d.on('error', (e) => errors.push(String(e && e.message)))
let deepObj = 'sentinel-leaf'
for (let i = 0; i < 100; i++) deepObj = { level: i, child: deepObj }
let deepArr = null
for (let i = 0; i < 100; i++) deepArr = [deepArr]
const msgs = [{ hello: 'world' }, deepObj, [1, [2, [3]]]]
const expected = msgs.concat([deepArr])
const bytes = Buffer.concat(msgs.map((m) => pack.encode(m)).concat([nest([0x91], 100, [0xc0])]))
process.on('exit', () => emit({ ok: util.isDeepStrictEqual(got, expected), count: got.length, errors }))
for (let i = 0; i < bytes.length; i++) d.write(Buffer.from([bytes[i]]))
d.end()
"""
    )
    assert not res["errors"], "stream raised errors on legitimate data: %r" % res["errors"]
    assert res["ok"], "stream did not deliver all legitimate nested messages (got %s)" % res["count"]


def test_functional_prefer_map_nested_maps_unpack():
    """Nested Maps with non-string keys (preferMap option) must still round-trip."""
    res = run_node(
        r"""
const pack = msgpack({ preferMap: true, maxArrayLength: 1000, maxMapLength: 1000 })
let m = 'leaf'
for (let i = 0; i < 60; i++) {
  const mm = new Map()
  mm.set(i, m)
  mm.set('arr', [i, [i]])
  m = mm
}
const back = pack.decode(pack.encode(m))
emit({ ok: back instanceof Map && util.isDeepStrictEqual(back, m) })
"""
    )
    assert res["ok"], "nested Maps no longer round-trip with preferMap"
