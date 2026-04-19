"""
TCP transport with mutual authentication.

Handshake (newline-delimited JSON):
  1. HELLO       {type, fingerprint, pubkey_pem, nickname, version}
  2. CHALLENGE   {type, nonce_b64}          — 32 random bytes
  3. CHALLENGE_RESPONSE {type, sig_b64}     — sign the nonce you received
  4. READY       {type}

Chat messages:
  MSG  {type, payload, sig_b64, ts}   — hybrid-encrypted + signed
  BYE  {type}                         — clean disconnect

Both sides must have each other imported as a contact. The challenge/response
proves key possession so a leaked fingerprint can't be used to impersonate.
"""

import asyncio
import base64
import json
import logging
import os
import pathlib
import queue
import time
from typing import Dict, Optional, Tuple

import crypto

_log = logging.getLogger("pgpchat.network")
logging.basicConfig(
    filename=str(pathlib.Path.home() / ".pgpchat" / "debug.log"),
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(message)s",
)

VERSION           = "1.0"
DEFAULT_PORT      = 7890
HANDSHAKE_TO      = 30   # seconds to complete the full handshake
READ_TIMEOUT      = 1.0  # seconds for chat-loop reads (allows stop-event polling)
MAX_LINE_BYTES    = 128 * 1024  # 128 KB hard limit per framed message
KEEPALIVE_INTERVAL = 30  # send PING if idle this many seconds (beats NAT timeouts)


async def _read(reader: asyncio.StreamReader, timeout: float = HANDSHAKE_TO) -> Optional[Dict]:
    try:
        raw = await asyncio.wait_for(
            reader.readuntil(b"\n"),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        raise
    except (asyncio.IncompleteReadError, ConnectionResetError) as exc:
        _log.debug("_read: connection closed (%s: %s)", type(exc).__name__, exc)
        return None
    if len(raw) > MAX_LINE_BYTES:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


async def _send(writer: asyncio.StreamWriter, obj: Dict) -> None:
    writer.write(json.dumps(obj, separators=(",", ":")).encode("utf-8") + b"\n")
    await writer.drain()


class AuthError(Exception): pass
class PeerNotKnownError(Exception): pass


async def _handshake(
    reader,
    writer,
    my_private_key,
    my_public_key,
    my_fingerprint: str,
    my_nickname: str,
    contacts: Dict,
) -> Tuple[str, str, object]:
    """Returns (peer_nick, peer_fp, peer_pubkey) or raises AuthError/PeerNotKnownError."""

    # step 1: exchange HELLO
    await _send(writer, {
        "type":        "HELLO",
        "fingerprint": my_fingerprint,
        "pubkey_pem":  crypto.serialize_public_key(my_public_key),
        "nickname":    my_nickname,
        "version":     VERSION,
    })

    hello = await _read(reader)
    if not hello or hello.get("type") != "HELLO":
        raise AuthError("Expected HELLO from peer")

    peer_fp   = hello.get("fingerprint", "")
    peer_nick = hello.get("nickname", "unknown")
    peer_pem  = hello.get("pubkey_pem", "")

    if peer_fp not in contacts:
        await _send(writer, {"type": "ERROR", "message": "Unknown peer — not in contact list"})
        raise PeerNotKnownError(f"Peer fingerprint not in contacts: {peer_fp[:20]}…")

    try:
        advertised_key = crypto.load_public_key(peer_pem)
        advertised_fp  = crypto.fingerprint(advertised_key)
    except Exception:
        raise AuthError("Peer sent an invalid public key")

    if advertised_fp != peer_fp:
        raise AuthError("Peer's advertised fingerprint does not match their key")

    # trust anchor: the key we imported, not what the peer just sent
    stored_pubkey = contacts[peer_fp]["pubkey"]

    # step 2: exchange CHALLENGE
    my_nonce = os.urandom(32)
    await _send(writer, {
        "type":      "CHALLENGE",
        "nonce_b64": base64.b64encode(my_nonce).decode(),
    })

    challenge = await _read(reader)
    if not challenge or challenge.get("type") != "CHALLENGE":
        raise AuthError("Expected CHALLENGE from peer")

    try:
        peer_nonce = base64.b64decode(challenge["nonce_b64"])
    except Exception:
        raise AuthError("Malformed nonce in CHALLENGE")

    # step 3: sign the nonce WE received (proves we hold our private key)
    await _send(writer, {
        "type":    "CHALLENGE_RESPONSE",
        "sig_b64": crypto.sign(peer_nonce, my_private_key),
    })

    response = await _read(reader)
    if not response or response.get("type") != "CHALLENGE_RESPONSE":
        raise AuthError("Expected CHALLENGE_RESPONSE from peer")

    peer_sig = response.get("sig_b64", "")
    if not crypto.verify(my_nonce, peer_sig, stored_pubkey):
        await _send(writer, {"type": "ERROR", "message": "Authentication failed"})
        raise AuthError("Peer failed the authentication challenge")

    # step 4: both sides send READY
    await _send(writer, {"type": "READY"})

    ready = await _read(reader)
    if not ready or ready.get("type") != "READY":
        raise AuthError("Expected READY from peer")

    return peer_nick, peer_fp, stored_pubkey


async def _chat_loop(
    reader,
    writer,
    peer_nick: str,
    peer_fp: str,
    peer_pubkey,
    my_private_key,
    incoming_q: queue.Queue,
    outgoing_q: queue.Queue,
    stop_event: asyncio.Event,
) -> None:
    loop = asyncio.get_running_loop()

    async def recv_task():
        while not stop_event.is_set():
            try:
                msg = await _read(reader, timeout=READ_TIMEOUT)
            except asyncio.TimeoutError:
                continue
            if msg is None:
                _log.debug("recv_task: msg=None → DISCONNECT (%s)", peer_nick)
                incoming_q.put(("DISCONNECT", peer_nick, None))
                stop_event.set()
                return
            mtype = msg.get("type")
            if mtype == "PING":
                continue  # keepalive — no action needed
            if mtype == "BYE":
                _log.debug("recv_task: BYE received → DISCONNECT (%s)", peer_nick)
                incoming_q.put(("DISCONNECT", peer_nick, None))
                stop_event.set()
                return
            if mtype == "MSG":
                payload = msg.get("payload", {})
                sig     = msg.get("sig_b64", "")
                ts      = msg.get("ts", time.time())
                payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
                if not crypto.verify(payload_bytes, sig, peer_pubkey):
                    incoming_q.put(("WARNING", peer_nick, "⚠  Message signature invalid — discarded"))
                    continue
                try:
                    plaintext = crypto.decrypt_message(payload, my_private_key)
                    incoming_q.put(("MSG", peer_nick, plaintext, ts))
                except Exception as exc:
                    incoming_q.put(("WARNING", peer_nick, f"⚠  Decryption error: {exc}"))

    async def send_task():
        last_send = time.time()
        while not stop_event.is_set():
            # Poll outgoing queue without blocking the event loop
            try:
                text = await loop.run_in_executor(None, lambda: outgoing_q.get(timeout=0.4))
            except Exception:
                # Nothing to send — fire keepalive if idle too long
                if time.time() - last_send >= KEEPALIVE_INTERVAL:
                    try:
                        await _send(writer, {"type": "PING"})
                        last_send = time.time()
                    except Exception as exc:
                        _log.debug("send_task: keepalive failed (%s: %s)", type(exc).__name__, exc)
                        stop_event.set()
                        return
                continue
            try:
                if text is None:  # /quit sentinel
                    await _send(writer, {"type": "BYE"})
                    stop_event.set()
                    return
                payload       = crypto.encrypt_message(text, peer_pubkey)
                payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
                sig           = crypto.sign(payload_bytes, my_private_key)
                await _send(writer, {
                    "type":    "MSG",
                    "payload": payload,
                    "sig_b64": sig,
                    "ts":      time.time(),
                })
                last_send = time.time()
            except Exception as exc:
                _log.debug("send_task: exception → stopping (%s: %s)", type(exc).__name__, exc)
                stop_event.set()
                return

    await asyncio.gather(recv_task(), send_task())


async def listen_for_one(
    port: int,
    my_private_key,
    my_public_key,
    my_nickname: str,
    contacts: Dict,
    incoming_q: queue.Queue,
    outgoing_q: queue.Queue,
) -> None:
    my_fp = crypto.fingerprint(my_public_key)
    connected = asyncio.Event()
    done     = asyncio.Event()

    async def handle(reader, writer):
        if connected.is_set():
            try:
                await _send(writer, {"type": "ERROR", "message": "Busy"})
            except Exception:
                pass
            writer.close()
            return

        connected.set()
        addr = writer.get_extra_info("peername")
        try:
            peer_nick, peer_fp, peer_pubkey = await _handshake(
                reader, writer,
                my_private_key, my_public_key,
                my_fp, my_nickname, contacts,
            )
            _log.debug("listen handle: handshake OK with %s (%s)", peer_nick, peer_fp[:20])
            incoming_q.put(("CONNECTED", peer_nick, addr))
            stop_event = asyncio.Event()
            _log.debug("listen handle: entering _chat_loop")
            await _chat_loop(
                reader, writer,
                peer_nick, peer_fp, peer_pubkey,
                my_private_key,
                incoming_q, outgoing_q, stop_event,
            )
            _log.debug("listen handle: _chat_loop returned normally")
        except PeerNotKnownError as exc:
            _log.debug("listen handle: PeerNotKnownError: %s", exc)
            incoming_q.put(("ERROR", None, str(exc)))
        except AuthError as exc:
            _log.debug("listen handle: AuthError: %s", exc)
            incoming_q.put(("ERROR", None, f"Handshake failed: {exc}"))
        except Exception as exc:
            _log.debug("listen handle: unexpected exception: %s: %s", type(exc).__name__, exc)
            incoming_q.put(("ERROR", None, f"Unexpected error: {exc}"))
        finally:
            _log.debug("listen handle: finally — closing writer")
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            done.set()

    async def _watch_quit() -> None:
        """Release the server if /quit is issued while still in standby."""
        loop = asyncio.get_running_loop()
        while not done.is_set() and not connected.is_set():
            try:
                item = await loop.run_in_executor(
                    None, lambda: outgoing_q.get(timeout=0.4)
                )
                if item is None:
                    done.set()
                    return
                outgoing_q.put(item)   # put back anything that isn't a quit
            except Exception:
                continue

    server = await asyncio.start_server(handle, "0.0.0.0", port)
    incoming_q.put(("LISTENING", None, port))
    async with server:
        watcher = asyncio.ensure_future(_watch_quit())
        await done.wait()
        watcher.cancel()


# ── Relay-server client functions ─────────────────────────────────────────────

async def _server_auth(
    reader,
    writer,
    my_private_key,
    my_public_key,
    my_fingerprint: str,
    my_nickname: str,
) -> None:
    """Authenticate with the relay server (one-way challenge from server)."""
    await _send(writer, {
        "type":       "HELLO",
        "fingerprint": my_fingerprint,
        "pubkey_pem":  crypto.serialize_public_key(my_public_key),
        "nickname":    my_nickname,
        "version":     VERSION,
    })

    challenge = await _read(reader)
    if not challenge or challenge.get("type") != "CHALLENGE":
        raise AuthError(f"Expected CHALLENGE from relay server, got: {challenge}")

    try:
        nonce = base64.b64decode(challenge["nonce_b64"])
    except Exception:
        raise AuthError("Malformed nonce from relay server")

    await _send(writer, {
        "type":    "CHALLENGE_RESPONSE",
        "sig_b64": crypto.sign(nonce, my_private_key),
    })

    ready = await _read(reader)
    if not ready or ready.get("type") != "SERVER_READY":
        raise AuthError(f"Expected SERVER_READY from relay server, got: {ready}")


async def _relay_chat_loop(
    reader,
    writer,
    peer_nick: str,
    peer_fp: str,
    peer_pubkey,
    my_private_key,
    incoming_q: queue.Queue,
    outgoing_q: queue.Queue,
    stop_event: asyncio.Event,
) -> None:
    """Like _chat_loop but over a relay connection (RELAY/RELAYED frames)."""
    loop = asyncio.get_running_loop()

    async def recv_task():
        while not stop_event.is_set():
            try:
                msg = await _read(reader, timeout=READ_TIMEOUT)
            except asyncio.TimeoutError:
                continue
            if msg is None:
                _log.debug("relay recv_task: connection closed (%s)", peer_nick)
                incoming_q.put(("DISCONNECT", peer_nick, None))
                stop_event.set()
                return
            mtype = msg.get("type")
            if mtype in ("PING", "PONG", "DELIVERED", "QUEUED"):
                continue
            if mtype == "KICKED":
                incoming_q.put(("ERROR", None, f"Relay server kicked us: {msg.get('reason')}"))
                stop_event.set()
                return
            if mtype == "BYE":
                incoming_q.put(("DISCONNECT", peer_nick, None))
                stop_event.set()
                return
            if mtype == "RELAYED":
                if msg.get("from") != peer_fp:
                    continue  # message from a different contact — ignore in this session
                payload = msg.get("payload", {})
                sig     = msg.get("sig_b64", "")
                ts      = msg.get("ts", time.time())
                payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
                if not crypto.verify(payload_bytes, sig, peer_pubkey):
                    incoming_q.put(("WARNING", peer_nick, "⚠  Message signature invalid — discarded"))
                    continue
                try:
                    plaintext = crypto.decrypt_message(payload, my_private_key)
                    incoming_q.put(("MSG", peer_nick, plaintext, ts))
                except Exception as exc:
                    incoming_q.put(("WARNING", peer_nick, f"⚠  Decryption error: {exc}"))
            elif mtype == "ERROR":
                incoming_q.put(("WARNING", None, f"Relay error: {msg.get('reason')}"))

    async def send_task():
        last_send = time.time()
        while not stop_event.is_set():
            try:
                text = await loop.run_in_executor(None, lambda: outgoing_q.get(timeout=0.4))
            except Exception:
                if time.time() - last_send >= KEEPALIVE_INTERVAL:
                    try:
                        await _send(writer, {"type": "PING"})
                        last_send = time.time()
                    except Exception as exc:
                        _log.debug("relay send_task: keepalive failed (%s)", exc)
                        stop_event.set()
                        return
                continue
            try:
                if text is None:  # /quit sentinel
                    await _send(writer, {"type": "BYE"})
                    stop_event.set()
                    return
                payload       = crypto.encrypt_message(text, peer_pubkey)
                payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
                sig           = crypto.sign(payload_bytes, my_private_key)
                await _send(writer, {
                    "type":    "RELAY",
                    "to":      peer_fp,
                    "payload": payload,
                    "sig_b64": sig,
                    "ts":      time.time(),
                })
                last_send = time.time()
            except Exception as exc:
                _log.debug("relay send_task: exception → stopping (%s)", exc)
                stop_event.set()
                return

    await asyncio.gather(recv_task(), send_task())


async def connect_via_relay(
    server_host: str,
    server_port: int,
    target_fp: str,
    my_private_key,
    my_public_key,
    my_nickname: str,
    contacts: Dict,
    incoming_q: queue.Queue,
    outgoing_q: queue.Queue,
) -> None:
    """Connect to a contact through a relay server."""
    my_fp = crypto.fingerprint(my_public_key)
    try:
        reader, writer = await asyncio.open_connection(server_host, server_port)
    except Exception as exc:
        incoming_q.put(("ERROR", None, f"Cannot reach relay {server_host}:{server_port} — {exc}"))
        return

    try:
        await _server_auth(reader, writer, my_private_key, my_public_key, my_fp, my_nickname)
    except AuthError as exc:
        incoming_q.put(("ERROR", None, f"Relay auth failed: {exc}"))
        writer.close()
        return

    if target_fp not in contacts:
        incoming_q.put(("ERROR", None, f"Target fingerprint not in contacts: {target_fp[:20]}…"))
        writer.close()
        return

    # Check if target is connected to relay
    await _send(writer, {"type": "WHO", "fingerprint": target_fp})
    who = await _read(reader)
    if not who or who.get("type") != "WHO_RESP":
        incoming_q.put(("ERROR", None, "Relay did not respond to WHO query"))
        writer.close()
        return
    if not who.get("online"):
        incoming_q.put(("ERROR", None, "Contact is not connected to the relay server"))
        writer.close()
        return

    peer_nick   = contacts[target_fp]["name"]
    peer_pubkey = contacts[target_fp]["pubkey"]

    _log.debug("connect_via_relay: target %s (%s) is online", peer_nick, target_fp[:20])
    incoming_q.put(("CONNECTED", peer_nick, (server_host, server_port)))

    try:
        stop_event = asyncio.Event()
        await _relay_chat_loop(
            reader, writer,
            peer_nick, target_fp, peer_pubkey,
            my_private_key,
            incoming_q, outgoing_q, stop_event,
        )
    except Exception as exc:
        _log.debug("connect_via_relay: unexpected exception: %s", exc)
        incoming_q.put(("ERROR", None, f"Relay session error: {exc}"))
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def listen_via_relay(
    server_host: str,
    server_port: int,
    my_private_key,
    my_public_key,
    my_nickname: str,
    contacts: Dict,
    incoming_q: queue.Queue,
    outgoing_q: queue.Queue,
) -> None:
    """Connect to relay and wait for an incoming message from any known contact."""
    my_fp = crypto.fingerprint(my_public_key)
    try:
        reader, writer = await asyncio.open_connection(server_host, server_port)
    except Exception as exc:
        incoming_q.put(("ERROR", None, f"Cannot reach relay {server_host}:{server_port} — {exc}"))
        return

    try:
        await _server_auth(reader, writer, my_private_key, my_public_key, my_fp, my_nickname)
    except AuthError as exc:
        incoming_q.put(("ERROR", None, f"Relay auth failed: {exc}"))
        writer.close()
        return

    incoming_q.put(("LISTENING", None, f"relay://{server_host}:{server_port}"))
    _log.debug("listen_via_relay: registered, waiting for caller")

    loop = asyncio.get_running_loop()
    peer_nick = peer_fp = peer_pubkey = first_msg = None

    # Standby: wait for the first RELAYED message from a known contact
    while True:
        # Non-blocking check for /quit
        try:
            item = outgoing_q.get_nowait()
            if item is None:
                await _send(writer, {"type": "BYE"})
                writer.close()
                return
            outgoing_q.put(item)
        except queue.Empty:
            pass

        try:
            msg = await _read(reader, timeout=READ_TIMEOUT)
        except asyncio.TimeoutError:
            continue

        if msg is None:
            incoming_q.put(("DISCONNECT", None, None))
            writer.close()
            return

        mtype = msg.get("type")
        if mtype == "KICKED":
            incoming_q.put(("ERROR", None, f"Relay kicked us: {msg.get('reason')}"))
            writer.close()
            return
        if mtype == "PING":
            await _send(writer, {"type": "PONG"})
            continue
        if mtype == "RELAYED":
            from_fp = msg.get("from", "")
            if from_fp in contacts:
                peer_fp     = from_fp
                peer_nick   = contacts[from_fp]["name"]
                peer_pubkey = contacts[from_fp]["pubkey"]
                first_msg   = msg
                break
            _log.debug("listen_via_relay: RELAYED from unknown fingerprint %s…, ignored", from_fp[:16])

    # Process the first message that "rang" us
    incoming_q.put(("CONNECTED", peer_nick, (server_host, server_port)))
    payload       = first_msg.get("payload", {})
    sig           = first_msg.get("sig_b64", "")
    ts            = first_msg.get("ts", time.time())
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    if crypto.verify(payload_bytes, sig, peer_pubkey):
        try:
            plaintext = crypto.decrypt_message(payload, my_private_key)
            incoming_q.put(("MSG", peer_nick, plaintext, ts))
        except Exception as exc:
            incoming_q.put(("WARNING", peer_nick, f"⚠  First message decryption failed: {exc}"))
    else:
        incoming_q.put(("WARNING", peer_nick, "⚠  First message signature invalid — discarded"))

    try:
        stop_event = asyncio.Event()
        await _relay_chat_loop(
            reader, writer,
            peer_nick, peer_fp, peer_pubkey,
            my_private_key,
            incoming_q, outgoing_q, stop_event,
        )
    except Exception as exc:
        _log.debug("listen_via_relay: unexpected exception: %s", exc)
        incoming_q.put(("ERROR", None, f"Relay session error: {exc}"))
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def connect_to_peer(
    host: str,
    port: int,
    my_private_key,
    my_public_key,
    my_nickname: str,
    contacts: Dict,
    incoming_q: queue.Queue,
    outgoing_q: queue.Queue,
) -> None:
    my_fp = crypto.fingerprint(my_public_key)
    try:
        reader, writer = await asyncio.open_connection(host, port)
    except Exception as exc:
        incoming_q.put(("ERROR", None, f"Cannot connect to {host}:{port} — {exc}"))
        return

    try:
        peer_nick, peer_fp, peer_pubkey = await _handshake(
            reader, writer,
            my_private_key, my_public_key,
            my_fp, my_nickname, contacts,
        )
        _log.debug("connect_to_peer: handshake OK with %s (%s)", peer_nick, peer_fp[:20])
        incoming_q.put(("CONNECTED", peer_nick, (host, port)))
        stop_event = asyncio.Event()
        _log.debug("connect_to_peer: entering _chat_loop")
        await _chat_loop(
            reader, writer,
            peer_nick, peer_fp, peer_pubkey,
            my_private_key,
            incoming_q, outgoing_q, stop_event,
        )
    except PeerNotKnownError as exc:
        _log.debug("connect_to_peer: PeerNotKnownError: %s", exc)
        incoming_q.put(("ERROR", None, str(exc)))
    except AuthError as exc:
        _log.debug("connect_to_peer: AuthError: %s", exc)
        incoming_q.put(("ERROR", None, f"Handshake failed: {exc}"))
    except Exception as exc:
        _log.debug("connect_to_peer: unexpected exception: %s: %s", type(exc).__name__, exc)
        incoming_q.put(("ERROR", None, f"Unexpected error: {exc}"))
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
