"""Hidden regression suite: streamed compressed HTTP bodies must expand with bounded memory."""

from __future__ import annotations

import asyncio
import functools
import gc
import sys
import tracemalloc
import typing
import zlib

import pytest

import httpx2

MiB = 1024 * 1024
BOMB_SIZE = 64 * MiB
# The report promises "a few MiB at most"; the attack body is 64 MiB once expanded.
PEAK_LIMIT = BOMB_SIZE // 8
URL = "https://example.org/export"
_ZERO_BLOCK = bytes(MiB)

SAMPLE = b"".join(b"record %08d: the quick brown fox jumps\n" % i for i in range(100_000))


# ---------------------------------------------------------------------------
# compression helpers (test-side only)
# ---------------------------------------------------------------------------


def _zstd_module() -> typing.Any:
    if sys.version_info >= (3, 14):
        from compression import zstd
    else:
        from backports import zstd
    return zstd


def _zlib_compress(data: bytes, wbits: int) -> bytes:
    compressor = zlib.compressobj(9, zlib.DEFLATED, wbits)
    return compressor.compress(data) + compressor.flush()


def gzip_c(data: bytes) -> bytes:
    return _zlib_compress(data, zlib.MAX_WBITS | 16)


def zlib_c(data: bytes) -> bytes:
    return _zlib_compress(data, zlib.MAX_WBITS)


def raw_deflate_c(data: bytes) -> bytes:
    return _zlib_compress(data, -zlib.MAX_WBITS)


def brotli_c(data: bytes) -> bytes:
    import brotli

    return brotli.compress(data, quality=5)


def zstd_c(data: bytes) -> bytes:
    return _zstd_module().compress(data)


_WBITS = {
    "gzip": zlib.MAX_WBITS | 16,
    "deflate": zlib.MAX_WBITS,
    "raw-deflate": -zlib.MAX_WBITS,
}


@functools.lru_cache(maxsize=None)
def _bomb(kind: str) -> bytes:
    """A small compressed payload that expands to BOMB_SIZE zero bytes (built without a 64 MiB buffer)."""
    blocks = BOMB_SIZE // MiB
    if kind in _WBITS:
        compressor = zlib.compressobj(9, zlib.DEFLATED, _WBITS[kind])
        parts = [compressor.compress(_ZERO_BLOCK) for _ in range(blocks)]
        parts.append(compressor.flush())
    elif kind == "br":
        import brotli

        compressor = brotli.Compressor(quality=5)
        step = compressor.process if hasattr(compressor, "process") else compressor.compress
        parts = [step(_ZERO_BLOCK) for _ in range(blocks)]
        parts.append(compressor.finish())
    elif kind == "zstd":
        compressor = _zstd_module().ZstdCompressor()
        parts = [compressor.compress(_ZERO_BLOCK) for _ in range(blocks)]
        parts.append(compressor.flush())
    elif kind == "gzip-gzip":
        return gzip_c(_bomb("gzip"))
    else:  # pragma: no cover
        raise AssertionError(kind)
    return b"".join(parts)


def _pieces(data: bytes, size: int) -> list[bytes]:
    return [data[i : i + size] for i in range(0, len(data), size)]


# ---------------------------------------------------------------------------
# harness helpers
# ---------------------------------------------------------------------------


def _sync_client(payload_pieces: list[bytes], coding: str | None) -> httpx2.Client:
    def handler(request: httpx2.Request) -> httpx2.Response:
        headers = [("Content-Encoding", coding)] if coding else []
        return httpx2.Response(200, headers=headers, content=iter(list(payload_pieces)))

    return httpx2.Client(transport=httpx2.MockTransport(handler))


def _trace_begin() -> tuple[int, bool]:
    gc.collect()
    was_tracing = tracemalloc.is_tracing()
    if not was_tracing:
        tracemalloc.start()
    tracemalloc.reset_peak()
    baseline = tracemalloc.get_traced_memory()[0]
    return baseline, was_tracing


def _trace_end(was_tracing: bool) -> None:
    if not was_tracing:
        tracemalloc.stop()


def _traced_total(make_iter: typing.Callable[[], typing.Iterable[typing.Sized]]) -> tuple[int, int]:
    baseline, was_tracing = _trace_begin()
    try:
        total = 0
        for piece in make_iter():
            total += len(piece)
        peak = tracemalloc.get_traced_memory()[1] - baseline
    finally:
        _trace_end(was_tracing)
    return total, peak


def _sync_bomb_run(
    payload: bytes,
    coding: str,
    consume: typing.Callable[[httpx2.Response], typing.Iterable[typing.Sized]],
) -> tuple[int, int]:
    with _sync_client([payload], coding) as client:
        with client.stream("GET", URL) as response:
            return _traced_total(lambda: consume(response))


def _assert_bounded(total: int, peak: int) -> None:
    assert total == BOMB_SIZE, "the complete expanded body must still be delivered"
    assert peak < PEAK_LIMIT, f"peak traced memory while streaming was {peak} bytes"


# ---------------------------------------------------------------------------
# security tests
# ---------------------------------------------------------------------------


def test_security_gzip_stream_bytes_bounded_memory() -> None:
    """Streaming a gzip bomb delivered in one read must not expand it all at once (reported case)."""
    total, peak = _sync_bomb_run(_bomb("gzip"), "gzip", lambda r: r.iter_bytes())
    _assert_bounded(total, peak)


def test_security_gzip_stream_text_bounded_memory() -> None:
    """Iterating a streamed gzip bomb as text must also keep memory bounded."""
    total, peak = _sync_bomb_run(_bomb("gzip"), "gzip", lambda r: r.iter_text())
    _assert_bounded(total, peak)


def test_security_zlib_deflate_stream_bounded_memory() -> None:
    """A zlib-wrapped deflate bomb must be expanded with bounded memory while streaming."""
    total, peak = _sync_bomb_run(_bomb("deflate"), "deflate", lambda r: r.iter_bytes())
    _assert_bounded(total, peak)


def test_security_raw_deflate_stream_bounded_memory() -> None:
    """A raw (headerless) deflate bomb must be expanded with bounded memory while streaming."""
    total, peak = _sync_bomb_run(_bomb("raw-deflate"), "deflate", lambda r: r.iter_bytes())
    _assert_bounded(total, peak)


def test_security_brotli_stream_bounded_memory() -> None:
    """A brotli bomb must be expanded with bounded memory while streaming."""
    total, peak = _sync_bomb_run(_bomb("br"), "br", lambda r: r.iter_bytes())
    _assert_bounded(total, peak)


def test_security_zstd_stream_bounded_memory() -> None:
    """A zstd bomb must be expanded with bounded memory while streaming."""
    total, peak = _sync_bomb_run(_bomb("zstd"), "zstd", lambda r: r.iter_bytes())
    _assert_bounded(total, peak)


def test_security_stacked_codings_stream_bounded_memory() -> None:
    """A bomb wrapped in two stacked gzip codings must be expanded with bounded memory."""
    total, peak = _sync_bomb_run(_bomb("gzip-gzip"), "gzip, gzip", lambda r: r.iter_bytes())
    _assert_bounded(total, peak)


def test_security_async_gzip_stream_bounded_memory() -> None:
    """The asyncio streaming interface must also expand a gzip bomb with bounded memory."""
    payload = _bomb("gzip")

    async def handler(request: httpx2.Request) -> httpx2.Response:
        async def body() -> typing.AsyncIterator[bytes]:
            yield payload

        return httpx2.Response(200, headers=[("Content-Encoding", "gzip")], content=body())

    async def main() -> tuple[int, int]:
        async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
            async with client.stream("GET", URL) as response:
                baseline, was_tracing = _trace_begin()
                try:
                    total = 0
                    async for piece in response.aiter_bytes():
                        total += len(piece)
                    peak = tracemalloc.get_traced_memory()[1] - baseline
                finally:
                    _trace_end(was_tracing)
                return total, peak

    total, peak = asyncio.run(main())
    _assert_bounded(total, peak)


# ---------------------------------------------------------------------------
# functional tests
# ---------------------------------------------------------------------------

CODINGS = [
    ("gzip", gzip_c),
    ("deflate", zlib_c),
    ("deflate", raw_deflate_c),
    ("br", brotli_c),
    ("zstd", zstd_c),
    ("gzip, gzip", lambda d: gzip_c(gzip_c(d))),
    ("br, gzip", lambda d: gzip_c(brotli_c(d))),
    ("zstd, gzip", lambda d: gzip_c(zstd_c(d))),
]
CODING_IDS = ["gzip", "deflate-zlib", "deflate-raw", "br", "zstd", "gzip-gzip", "br-gzip", "zstd-gzip"]


@pytest.mark.parametrize(("coding", "encode"), CODINGS, ids=CODING_IDS)
def test_functional_streamed_codings_round_trip(coding: str, encode: typing.Callable[[bytes], bytes]) -> None:
    """Every supported coding (and stacked codings) still streams the exact original body."""
    encoded = encode(SAMPLE)
    with _sync_client(_pieces(encoded, 4096), coding) as client:
        with client.stream("GET", URL) as response:
            assert b"".join(response.iter_bytes()) == SAMPLE


@pytest.mark.parametrize(("coding", "encode"), [("gzip", gzip_c), ("zstd", zstd_c)], ids=["gzip", "zstd"])
def test_functional_large_highly_compressible_body_complete(
    coding: str, encode: typing.Callable[[bytes], bytes]
) -> None:
    """A legitimate multi-MiB, extremely compressible body arriving in one read is still returned in full."""
    original = bytes(8 * MiB)
    encoded = encode(original)
    with _sync_client([encoded], coding) as client:
        response = client.get(URL)
    assert response.status_code == 200
    assert len(response.content) == len(original)
    assert response.content == original


def test_functional_chunk_size_is_honoured() -> None:
    """A caller-requested chunk size is still respected for compressed bodies."""
    encoded = gzip_c(SAMPLE)
    with _sync_client(_pieces(encoded, 4096), "gzip") as client:
        with client.stream("GET", URL) as response:
            chunks = list(response.iter_bytes(chunk_size=10_000))
    assert b"".join(chunks) == SAMPLE
    assert all(len(chunk) == 10_000 for chunk in chunks[:-1])
    assert 0 < len(chunks[-1]) <= 10_000


def test_functional_line_iteration_over_compressed_stream() -> None:
    """Line iteration over a compressed streamed body yields every line intact."""
    encoded = gzip_c(SAMPLE)
    with _sync_client(_pieces(encoded, 4096), "gzip") as client:
        with client.stream("GET", URL) as response:
            lines = list(response.iter_lines())
    assert lines == SAMPLE.decode("ascii").splitlines()


def test_functional_async_get_and_stream_round_trip() -> None:
    """The asyncio API still returns full bodies for non-streaming and streaming requests."""
    gz = gzip_c(SAMPLE)
    br = brotli_c(SAMPLE)

    async def handler(request: httpx2.Request) -> httpx2.Response:
        payload, coding = (br, "br") if request.url.path.endswith("/br") else (gz, "gzip")

        async def body() -> typing.AsyncIterator[bytes]:
            for piece in _pieces(payload, 4096):
                yield piece

        return httpx2.Response(200, headers=[("Content-Encoding", coding)], content=body())

    async def main() -> tuple[bytes, bytes]:
        async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
            full = (await client.get("https://example.org/gz")).content
            async with client.stream("GET", "https://example.org/br") as response:
                streamed = b"".join([piece async for piece in response.aiter_bytes()])
        return full, streamed

    full, streamed = asyncio.run(main())
    assert full == SAMPLE
    assert streamed == SAMPLE


def test_functional_corrupt_gzip_still_raises_decoding_error() -> None:
    """Corrupt compressed data is still reported through the library's decoding error."""
    with _sync_client([b"this is definitely not gzip data"], "gzip") as client:
        with pytest.raises(httpx2.DecodingError):
            client.get(URL)


def test_functional_uncompressed_stream_passthrough() -> None:
    """Bodies without any coding still stream through unchanged, including large pieces."""
    pieces = [b"alpha-", b"", b"beta" * 500_000, b"-omega"]
    with _sync_client(pieces, None) as client:
        with client.stream("GET", URL) as response:
            assert b"".join(response.iter_bytes()) == b"".join(pieces)
        assert client.get(URL).content == b"".join(pieces)
