"""Egress proxy for in-container agents: the task container has no route out (Docker internal network); this proxy is
its only way out and forwards HTTPS (CONNECT) to the model-API hosts in $ALLOWED_HOSTS only. Everything else: 403.
Every decision is printed (docker logs) so a run can be audited."""
import asyncio
import os
import socket
import time

ALLOWED = {h.strip().lower() for h in os.environ.get("ALLOWED_HOSTS", "").split(",") if h.strip()}


def keepalive(writer):
    """Long silent turns (a model thinking for minutes) must not look idle to NAT on the way: probe every 20 s."""
    sock = writer.get_extra_info("socket")
    if sock is None:
        return
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    for opt, val in (("TCP_KEEPIDLE", 20), ("TCP_KEEPINTVL", 10), ("TCP_KEEPCNT", 9)):
        if hasattr(socket, opt):
            sock.setsockopt(socket.IPPROTO_TCP, getattr(socket, opt), val)


async def pipe(reader, writer, stats, side):
    try:
        while data := await reader.read(65536):
            stats[side] += len(data)
            writer.write(data)
            await writer.drain()
        stats.setdefault("closed_first", side + " sent EOF")
    except Exception as e:
        stats.setdefault("closed_first", f"{side} error {type(e).__name__}: {e}")
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def handle(cr, cw):
    try:
        line = await asyncio.wait_for(cr.readline(), 30)
        parts = line.decode("latin-1").split()
        while (await cr.readline()) not in (b"\r\n", b"\n", b""):
            pass
        if len(parts) < 2 or parts[0].upper() != "CONNECT":
            print(f"DENY non-CONNECT {line[:80]!r}", flush=True)
            cw.write(b"HTTP/1.1 405 Only HTTPS CONNECT is allowed\r\n\r\n")
            await cw.drain()
            return cw.close()
        host, _, port = parts[1].rpartition(":")
        if host.lower() not in ALLOWED or port != "443":
            print(f"DENY {parts[1]}", flush=True)
            cw.write(b"HTTP/1.1 403 Forbidden by egress allowlist\r\n\r\n")
            await cw.drain()
            return cw.close()
        ur, uw = await asyncio.wait_for(asyncio.open_connection(host, 443), 30)
        keepalive(cw)
        keepalive(uw)
        print(f"ALLOW {parts[1]}", flush=True)
        cw.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await cw.drain()
        stats, t0 = {"client->api": 0, "api->client": 0}, time.monotonic()
        await asyncio.gather(pipe(cr, uw, stats, "client->api"), pipe(ur, cw, stats, "api->client"))
        print(f"CLOSE {parts[1]} after {time.monotonic() - t0:.0f}s up={stats['client->api']}B "
              f"down={stats['api->client']}B first: {stats.get('closed_first')}", flush=True)
    except Exception:
        try:
            cw.close()
        except Exception:
            pass


async def main():
    print(f"egress allowlist: {sorted(ALLOWED)}", flush=True)
    server = await asyncio.start_server(handle, "0.0.0.0", 3128)
    async with server:
        await server.serve_forever()


asyncio.run(main())
