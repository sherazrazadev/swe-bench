# Streaming a gzip-labelled HTTP body expands the whole payload in memory at once

**Severity:** High. A remote server can exhaust the process's memory (denial of service).

## Background

We run a link-preview worker built on httpx2. It fetches untrusted URLs in streaming mode and stops iterating once it has seen enough bytes. We stream so that a hostile server cannot make the worker buffer an arbitrarily large body.

## What happens

A server can mark a very small body as compressed and send bytes that expand roughly 1000×. By default the library offers `gzip`, `deflate`, `br` and `zstd` in its `Accept-Encoding` header. When one network read passes such a blob to the library, the library expands the entire payload in memory before our loop gets its first byte. Our per-iteration size cap never gets a chance to run. Streaming gives no protection here.

## Reproduction

1. Build a gzip body that encodes 64 MiB of zero bytes. It is about 64 KiB on the wire.
2. Serve it labelled as gzip and deliver it in a single read. A mock transport whose body iterator yields the whole blob as one piece is enough.
3. Open the URL in streaming mode with `tracemalloc` enabled. Iterate over the body's bytes and throw each piece away.

**Observed:** the first piece the loop receives is the full 64 MiB, and peak traced memory goes above 64 MiB. Peak memory grows linearly with the payload, so a few hundred KiB of input can get the worker OOM-killed.

## Expected

- **Bounded memory.** Iterating a streamed body should need only a small working set, a few MiB at most, no matter how large the body becomes once expanded. This should hold:
  - for every compression format the library negotiates by default;
  - for bodies with several stacked codings;
  - for every way the library offers to iterate a streamed body: bytes or text, blocking or asyncio.
- **No lost functionality.** Legitimate use must keep working as it does today:
  - The complete body must still arrive byte-for-byte, even when it is large and extremely compressible. We regularly download compressed exports of several MiB that are mostly repeated bytes.
  - A chunk size requested by the caller must still be honoured.
  - Non-streaming requests must still return the full body.
  - Corrupt compressed data must still raise the library's existing decoding error.
