#!/usr/bin/env python3
"""
PGPChat Relay Server

Zero-knowledge relay: authenticates clients via RSA challenge-response, then
routes encrypted messages between them. The server never sees plaintext.

Usage:
    python server.py [--host 0.0.0.0] [--port 7890] [--max-queue 100]

Protocol (newline-delimited JSON):
    Client → Server:  HELLO, CHALLENGE_RESPONSE, RELAY, WHO, PING, BYE
    Server → Client:  CHALLENGE, SERVER_READY, RELAYED, DELIVERED, QUEUED,
                      WHO_RESP, KICKED, PONG, ERROR
"""

import asyncio
import base64
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

import crypto

LOG_FILE = Path("server.log")
logging.basicConfig(
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ],
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
_log = logging.getLogger("pgpchat.server")

VERSION        = "1.0"
DEFAULT_PORT   = 7890
HANDSHAKE_TO   = 30.0   # seconds to complete auth
READ_TIMEOUT   = 1.0    # short poll so keepalive fires
KEEPALIVE_INT  = 45     # seconds idle before server pings client
MAX_QUEUE      = 100    # queued frames per offline fingerprint
MAX_LINE_BYTES = 128 * 1024


# ── I/O helpers ────────────────────────────────────────────────────────────────

async def _send(writer: asyncio.StreamWriter, obj: dict) -> None:
    writer.write(json.dumps(obj, separators=(",", ":")).encode() + b"\n")
    await writer.drain()


async def _read(reader: asyncio.StreamReader, timeout: float = HANDSHAKE_TO) -> Optional[dict]:
    try:
        raw = await asyncio.wait_for(reader.readuntil(b"\n"), timeout=timeout)
    except asyncio.TimeoutError:
        raise
    except (asyncio.IncompleteReadError, ConnectionResetError):
        return None
    if len(raw) > MAX_LINE_BYTES:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


# ── Client state ───────────────────────────────────────────────────────────────

class Client:
    __slots__ = ("reader", "writer", "fingerprint", "nickname", "pubkey", "addr", "connected_at")

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader       = reader
        self.writer       = writer
        self.fingerprint: str  = ""
        self.nickname:    str  = "unknown"
        self.pubkey            = None
        self.addr              = writer.get_extra_info("peername")
        self.connected_at: float = time.time()

    async def send(self, obj: dict) -> None:
        await _send(self.writer, obj)

    async def read(self, timeout: float = HANDSHAKE_TO) -> Optional[dict]:
        return await _read(self.reader, timeout)

    def close(self) -> None:
        try:
            self.writer.close()
        except Exception:
            pass


# ── Relay server ───────────────────────────────────────────────────────────────

class RelayServer:
    def __init__(self, max_queue: int = MAX_QUEUE):
        self._clients:   Dict[str, Client] = {}
        self._queue:     Dict[str, List]   = {}
        self._max_queue: int               = max_queue

    # ── connection handler ──────────────────────────────────────────────────

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        client = Client(reader, writer)
        _log.info("connection from %s", client.addr)
        try:
            await self._authenticate(client)
        except Exception as exc:
            _log.warning("auth failed from %s: %s", client.addr, exc)
            client.close()
            return

        fp = client.fingerprint
        _log.info("authenticated: %s (%s…) from %s", client.nickname, fp[:16], client.addr)

        # Kick any stale session for this fingerprint
        old = self._clients.get(fp)
        if old:
            try:
                await old.send({"type": "KICKED", "reason": "new_login"})
            except Exception:
                pass
            old.close()

        self._clients[fp] = client

        # Flush queued messages accumulated while client was offline
        pending = self._queue.pop(fp, [])
        for frame in pending:
            try:
                await client.send(frame)
            except Exception:
                break
        if pending:
            _log.info("flushed %d queued messages to %s…", len(pending), fp[:16])

        await client.send({
            "type":    "SERVER_READY",
            "version": VERSION,
            "online":  len(self._clients),
        })

        try:
            await self._message_loop(client)
        except Exception as exc:
            _log.debug("message loop error for %s…: %s", fp[:16], exc)
        finally:
            if self._clients.get(fp) is client:
                del self._clients[fp]
            _log.info("disconnected: %s (%s…)", client.nickname, fp[:16])
            client.close()

    # ── authentication ──────────────────────────────────────────────────────

    async def _authenticate(self, client: Client) -> None:
        hello = await client.read(HANDSHAKE_TO)
        if not hello or hello.get("type") != "HELLO":
            raise ValueError("expected HELLO")

        fp   = hello.get("fingerprint", "")
        pem  = hello.get("pubkey_pem",  "")
        nick = hello.get("nickname",    "unknown")

        if not fp or not pem:
            raise ValueError("missing fingerprint or pubkey_pem")

        try:
            pubkey = crypto.load_public_key(pem)
        except Exception:
            raise ValueError("invalid public key PEM")

        if crypto.fingerprint(pubkey) != fp:
            raise ValueError("fingerprint does not match public key")

        client.fingerprint = fp
        client.nickname    = nick
        client.pubkey      = pubkey

        nonce = os.urandom(32)
        await client.send({"type": "CHALLENGE", "nonce_b64": base64.b64encode(nonce).decode()})

        resp = await client.read(HANDSHAKE_TO)
        if not resp or resp.get("type") != "CHALLENGE_RESPONSE":
            raise ValueError("expected CHALLENGE_RESPONSE")

        if not crypto.verify(nonce, resp.get("sig_b64", ""), pubkey):
            raise ValueError("challenge-response signature invalid")

    # ── message loop ───────────────────────────────────────────────────────

    async def _message_loop(self, client: Client) -> None:
        last_recv = time.time()
        while True:
            try:
                msg = await client.read(timeout=READ_TIMEOUT)
            except asyncio.TimeoutError:
                if time.time() - last_recv >= KEEPALIVE_INT:
                    try:
                        await client.send({"type": "PING"})
                        last_recv = time.time()
                    except Exception:
                        return
                continue

            if msg is None:
                return

            last_recv = time.time()
            mtype = msg.get("type")

            if mtype == "RELAY":
                await self._handle_relay(client, msg)
            elif mtype == "WHO":
                await self._handle_who(client, msg)
            elif mtype == "PING":
                await client.send({"type": "PONG"})
            elif mtype == "BYE":
                return
            # unknown types are silently ignored

    # ── RELAY ───────────────────────────────────────────────────────────────

    async def _handle_relay(self, sender: Client, msg: dict) -> None:
        to = msg.get("to", "")
        if not to:
            await sender.send({"type": "ERROR", "reason": "missing_to"})
            return

        frame = {
            "type":      "RELAYED",
            "from":      sender.fingerprint,
            "from_nick": sender.nickname,
            "payload":   msg.get("payload"),
            "sig_b64":   msg.get("sig_b64"),
            "ts":        msg.get("ts", time.time()),
        }

        target = self._clients.get(to)
        if target:
            try:
                await target.send(frame)
                await sender.send({"type": "DELIVERED", "to": to})
                _log.debug("relay %s… → %s…", sender.fingerprint[:8], to[:8])
            except Exception:
                await sender.send({"type": "ERROR", "reason": "delivery_failed"})
        else:
            q = self._queue.setdefault(to, [])
            if len(q) < self._max_queue:
                q.append(frame)
                await sender.send({"type": "QUEUED", "to": to, "queue_depth": len(q)})
                _log.debug("queued for offline %s… (depth=%d)", to[:8], len(q))
            else:
                await sender.send({"type": "ERROR", "reason": "queue_full"})

    # ── WHO ─────────────────────────────────────────────────────────────────

    async def _handle_who(self, client: Client, msg: dict) -> None:
        fp = msg.get("fingerprint")
        if fp:
            target = self._clients.get(fp)
            await client.send({
                "type":        "WHO_RESP",
                "fingerprint": fp,
                "online":      target is not None,
                "nickname":    target.nickname if target else None,
            })
        else:
            # Return list of online fingerprints (excluding caller)
            online = [f for f in self._clients if f != client.fingerprint]
            await client.send({
                "type":   "WHO_RESP",
                "online": online,
                "count":  len(online),
            })


# ── Entry point ────────────────────────────────────────────────────────────────

async def _run(host: str, port: int, max_queue: int) -> None:
    relay  = RelayServer(max_queue=max_queue)
    server = await asyncio.start_server(relay.handle, host, port)
    addrs  = ", ".join(str(s.getsockname()) for s in server.sockets)
    _log.info("relay server listening on %s  (max_queue=%d)", addrs, max_queue)
    print(f"\nPGPChat Relay Server")
    print(f"  Listening : {addrs}")
    print(f"  Log file  : {LOG_FILE.resolve()}")
    print(f"  Max queue : {max_queue} messages per offline user")
    print("\nPress Ctrl-C to stop.\n")
    async with server:
        await server.serve_forever()


def main() -> None:
    import argparse
    p = argparse.ArgumentParser(
        description="PGPChat zero-knowledge relay server",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--host",      default="0.0.0.0",   help="bind address")
    p.add_argument("--port",      type=int, default=DEFAULT_PORT, help="TCP port")
    p.add_argument("--max-queue", type=int, default=MAX_QUEUE,
                   help="max queued messages per offline fingerprint")
    args = p.parse_args()
    try:
        asyncio.run(_run(args.host, args.port, args.max_queue))
    except KeyboardInterrupt:
        print("\nServer stopped.")


if __name__ == "__main__":
    main()
