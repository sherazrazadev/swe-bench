# Small, deeply nested MessagePack payload makes unpacking blow the JavaScript call stack

## Summary

Our service uses this MessagePack library to unpack messages from clients we do not trust. A client can send a payload of about 100 KB that contains nothing but nested containers. Unpacking it does not fail with a normal parse error. It runs until the JavaScript engine runs out of call stack and then throws the engine's own `RangeError: Maximum call stack size exceeded`.

## Reproduction

1. Create a default instance of the library.
2. Build a buffer of 100,000 copies of byte `0x91` (a one-element array), followed by one `0xc0` (nil).
3. Pass the buffer to the instance's one-shot unpacking function.

**Observed:** the call goes one level deeper for every nested array, never stops, and fails only when the engine's stack is exhausted.

**Expected:** the input is refused with an ordinary error from the library.

## Impact

- **Cheap to send.** Each nesting level costs the attacker about one byte, so a small request reaches any depth.
- **Length limits don't help.** `maxArrayLength` and `maxMapLength` are no defence, because every container in the payload holds a single element.
- **Wrong kind of error.** Stack exhaustion is an engine fault, not a format error. Our error handling treats it as an internal crash and recycles the worker. A stream of such messages keeps knocking workers over.
- **Unreliable failure point.** Code that runs close to the stack limit may fail somewhere unrelated instead of in a controlled way.

## Expected behaviour

- **Security property:** with default options and no extra configuration, input whose arrays and maps nest far beyond what real data needs must be rejected with a regular, catchable library error. The library must not rely on the engine's stack running out. This applies to any nesting of arrays and maps the format allows.
- **Must keep working:**
  - Legitimate documents unpack exactly as before. Some of our real payloads nest arrays and maps (or a mix of both) up to **100 levels deep**, and those must still round-trip.
  - Large but shallow documents must keep working. For example, tens of thousands of sibling arrays or objects.
  - An instance that has just rejected a hostile payload must continue to unpack later legitimate payloads normally.
