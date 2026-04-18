#!/usr/bin/env python3
"""
pgpchat — PGP-style encrypted P2P terminal communicator
========================================================

Commands
--------
  keygen                          Generate your RSA-4096 key pair
  whoami                          Show your public key & fingerprint

  import  <name> [keyfile]        Import a contact's public key
  contacts                        List all contacts (with stored addresses)
  remove  <name>                  Remove a contact
  set-address <name> <host> [port]  Store/update a contact's IP address

  daemon  [port]                  Persistent listener — loops after each session
  call    <name> [host] [port]    Connect to a contact (uses stored address)
  listen  [port]                  One-shot listen (then exit)
  connect <name> <host> [port]    One-shot connect  (then exit)

  history <name>                  View encrypted chat history

Typical workflow
----------------
  # One-time setup (both sides):
  pgpchat keygen
  pgpchat whoami           # copy public key, send to peer
  pgpchat import alice     # paste peer's key

  # Store peer address so you don't type it every time:
  pgpchat set-address alice 10.0.0.5

  # Leave daemon running all day (tmux / screen recommended):
  pgpchat daemon

  # Call your buddy from any terminal:
  pgpchat call alice

Data directory:  ~/.pgpchat/
"""

import asyncio
import json
import queue
import sys
import threading
import time
from datetime import datetime
from getpass import getpass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

import crypto
import storage
from network import DEFAULT_PORT, connect_to_peer, listen_for_one
from ui import RetroUI


# paths

HOME_DIR     = Path.home() / ".pgpchat"
KEYS_DIR     = HOME_DIR / "keys"
CONTACTS_DIR = HOME_DIR / "contacts"
LOGS_DIR     = HOME_DIR / "logs"
CONFIG_FILE  = HOME_DIR / "config.json"
PRIV_FILE    = KEYS_DIR / "private.pem"
PUB_FILE     = KEYS_DIR / "public.pem"


def _ensure_dirs() -> None:
    for d in [HOME_DIR, KEYS_DIR, CONTACTS_DIR, LOGS_DIR]:
        d.mkdir(mode=0o700, parents=True, exist_ok=True)


# config

def _load_config() -> Dict:
    if CONFIG_FILE.exists():
        return json.loads(CONFIG_FILE.read_text())
    return {}


def _save_config(cfg: Dict) -> None:
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
    CONFIG_FILE.chmod(0o600)


# keys

def _prompt_passphrase(confirm: bool = False) -> str:
    pw = getpass("Private key passphrase: ")
    if confirm:
        pw2 = getpass("Confirm passphrase:     ")
        if pw != pw2:
            _die("Passphrases do not match.")
    return pw


def _load_my_keys():
    if not PRIV_FILE.exists():
        _die("No key pair found.  Run:  pgpchat keygen")
    pw = _prompt_passphrase()
    try:
        priv = crypto.load_private_key(PRIV_FILE, pw)
    except Exception:
        _die("Wrong passphrase or corrupted key file.")
    return priv, priv.public_key()


# contacts

def _load_contacts() -> Dict:
    """
    Returns {fingerprint: {name, fingerprint, pubkey, pubkey_pem, host?, port?}}.
    """
    contacts: Dict = {}
    for f in CONTACTS_DIR.glob("*.json"):
        try:
            meta   = json.loads(f.read_text())
            pubkey = crypto.load_public_key(meta["pubkey_pem"])
            entry  = {
                "name":        meta["name"],
                "fingerprint": meta["fingerprint"],
                "pubkey":      pubkey,
                "pubkey_pem":  meta["pubkey_pem"],
                "host":        meta.get("host"),
                "port":        meta.get("port", DEFAULT_PORT),
                "_file":       f,
            }
            contacts[meta["fingerprint"]] = entry
        except Exception:
            pass
    return contacts


def _contact_by_name(name: str, contacts: Dict) -> Optional[Dict]:
    for c in contacts.values():
        if c["name"].lower() == name.lower():
            return c
    return None


def _save_contact(meta: Dict) -> None:
    """Write (or overwrite) a contact JSON file."""
    name = meta["name"]
    safe = "".join(ch for ch in name if ch.isalnum() or ch in "-_.")[:64] or "contact"
    path = CONTACTS_DIR / f"{safe}.json"
    # Persist only serialisable fields
    out  = {k: v for k, v in meta.items() if k not in ("pubkey", "_file")}
    path.write_text(json.dumps(out, indent=2))
    path.chmod(0o600)


# utils

def _die(msg: str, code: int = 1) -> None:
    print(f"Error: {msg}", file=sys.stderr)
    sys.exit(code)


def _hr(char: str = "─", width: int = 60) -> None:
    print(char * width)


def _now() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _banner(title: str) -> None:
    print()
    _hr("═")
    print(f"  {title}")
    _hr("═")
    print()


def _run_one_session(
    net_coro_factory: Callable[[queue.Queue, queue.Queue], object],
    priv,
    my_nick:       str,
    contacts:      Dict,
    port:          int            = DEFAULT_PORT,
    known_peer_fp: Optional[str] = None,
    standby_msg:   str            = "",
) -> None:
    net_q:  queue.Queue = queue.Queue()   # raw network → relay thread
    out_q:  queue.Queue = queue.Queue()   # UI → network
    ui_q:   queue.Queue = queue.Queue()   # relay → UI

    loop = asyncio.new_event_loop()
    threading.Thread(
        target=lambda: loop.run_until_complete(net_coro_factory(net_q, out_q)),
        daemon=True,
    ).start()

    log_box: List = [None]   # set on CONNECTED once peer fp is known

    def relay() -> None:
        while True:
            try:
                ev = net_q.get(timeout=0.2)
            except queue.Empty:
                continue

            if ev[0] == "CONNECTED":
                peer_nick = ev[1]
                fp = known_peer_fp or ""
                if not fp:
                    for c in contacts.values():
                        if c["name"] == peer_nick:
                            fp = c["fingerprint"]
                            break
                if fp:
                    log_box[0] = storage.ChatLog(LOGS_DIR, fp, priv)

            if ev[0] == "MSG" and log_box[0]:
                log_box[0].append("recv", ev[1], ev[2])

            ui_q.put(ev)

            if ev[0] in ("DISCONNECT", "ERROR"):
                break

    threading.Thread(target=relay, daemon=True).start()

    def on_message(text: str) -> None:
        out_q.put(text)
        if log_box[0]:
            log_box[0].append("sent", my_nick, text)

    def on_quit() -> None:
        out_q.put(None)

    contacts_list = list(contacts.values())
    ui = RetroUI(
        my_nick=my_nick,
        contacts=contacts_list,
        port=port,
        incoming_q=ui_q,
        outgoing_q=out_q,
        on_message=on_message,
        on_quit=on_quit,
        active_fp=known_peer_fp,
        standby_msg=standby_msg,
    )
    ui.run()


# commands

def cmd_keygen(args):
    _ensure_dirs()
    if PRIV_FILE.exists():
        yn = input("Key pair already exists.  Overwrite? [y/N] ").strip().lower()
        if yn != "y":
            print("Aborted.")
            return

    cfg      = _load_config()
    nickname = input("Your nickname: ").strip()
    if not nickname:
        _die("Nickname cannot be empty.")

    print("Generating RSA-4096 key pair … (this takes a few seconds)")
    priv, pub = crypto.generate_keypair()
    pw        = _prompt_passphrase(confirm=True)

    crypto.save_private_key(priv, PRIV_FILE, pw)
    PUB_FILE.write_text(crypto.serialize_public_key(pub))
    PUB_FILE.chmod(0o644)

    cfg["nickname"] = nickname
    _save_config(cfg)

    fp = crypto.fingerprint(pub)
    print(f"\n✓ Key pair generated.")
    print(f"  Nickname    : {nickname}")
    print(f"  Fingerprint : {fp}")
    print(f"\nRun  pgpchat whoami  to get your public key to share.")


def cmd_whoami(args):
    if not PUB_FILE.exists():
        _die("No key pair found.  Run:  pgpchat keygen")
    pem = PUB_FILE.read_text()
    pub = crypto.load_public_key(pem)
    fp  = crypto.fingerprint(pub)
    cfg = _load_config()
    print(f"Nickname    : {cfg.get('nickname', '(not set)')}")
    print(f"Fingerprint : {fp}")
    print()
    print("Public key — paste this to your contacts:")
    _hr()
    print(pem)


def cmd_import(args):
    """Import a contact's public key.  Optionally record their address too."""
    if not args:
        _die("Usage:  pgpchat import <name> [keyfile]")
    _ensure_dirs()
    name = args[0]

    # Read PEM
    if len(args) >= 2:
        kf = Path(args[1])
        if not kf.exists():
            _die(f"File not found: {kf}")
        pem = kf.read_text()
    else:
        print(f"Paste {name}'s public key below (blank line to finish):")
        lines = []
        while True:
            line = input()
            if not line:
                break
            lines.append(line)
        pem = "\n".join(lines)

    try:
        pubkey = crypto.load_public_key(pem)
    except Exception:
        _die("Invalid public key — check the PEM data.")

    fp       = crypto.fingerprint(pubkey)
    contacts = _load_contacts()
    for existing_fp, c in contacts.items():
        if existing_fp == fp:
            _die(f"Key already exists as contact '{c['name']}' ({fp})")

    # Optionally store their address right away
    host: Optional[str] = None
    port: int           = DEFAULT_PORT
    addr_in = input(f"Store {name}'s address? (leave blank to skip)  host[:port]: ").strip()
    if addr_in:
        if ":" in addr_in:
            h, p   = addr_in.rsplit(":", 1)
            host   = h.strip()
            port   = int(p.strip())
        else:
            host = addr_in

    meta = {
        "name":        name,
        "fingerprint": fp,
        "pubkey_pem":  crypto.serialize_public_key(pubkey),
        "added_at":    time.time(),
    }
    if host:
        meta["host"] = host
        meta["port"] = port

    _save_contact(meta)

    print(f"\n✓ Contact '{name}' imported.")
    print(f"  Fingerprint : {fp}")
    if host:
        print(f"  Address     : {host}:{port}")
    print(f"\nVerify this fingerprint with {name} out-of-band before trusting.")


def cmd_contacts(args):
    contacts = _load_contacts()
    if not contacts:
        print("No contacts yet.  Import one:  pgpchat import <name> [keyfile]")
        return
    print(f"{'NAME':<18} {'ADDRESS':<22} FINGERPRINT")
    _hr(width=75)
    for c in sorted(contacts.values(), key=lambda x: x["name"].lower()):
        addr = f"{c['host']}:{c['port']}" if c.get("host") else "—"
        print(f"{c['name']:<18} {addr:<22} {c['fingerprint']}")


def cmd_remove(args):
    if not args:
        _die("Usage:  pgpchat remove <name>")
    name     = args[0]
    contacts = _load_contacts()
    contact  = _contact_by_name(name, contacts)
    if not contact:
        _die(f"Contact not found: {name}")
    f = contact.get("_file")
    if f and Path(f).exists():
        Path(f).unlink()
    print(f"✓ Removed contact: {name}")


def cmd_set_address(args):
    """Store or update the IP address for an existing contact."""
    if len(args) < 2:
        _die("Usage:  pgpchat set-address <name> <host> [port]")
    name     = args[0]
    host     = args[1]
    port     = int(args[2]) if len(args) >= 3 else DEFAULT_PORT
    contacts = _load_contacts()
    contact  = _contact_by_name(name, contacts)
    if not contact:
        _die(f"Contact not found: {name}")

    # Read existing file, update, re-save
    existing = json.loads(Path(contact["_file"]).read_text())
    existing["host"] = host
    existing["port"] = port
    _save_contact(existing)
    print(f"✓ Address updated: {name} → {host}:{port}")


def cmd_daemon(args):
    port      = int(args[0]) if args else DEFAULT_PORT
    priv, pub = _load_my_keys()
    cfg       = _load_config()
    my_nick   = cfg.get("nickname", "me")

    session_count = 0
    while True:
        try:
            contacts = _load_contacts()
            if not contacts:
                print("No contacts yet — import someone first:  pgpchat import <name>")
                print("Retrying in 10 s …")
                time.sleep(10)
                continue

            _run_one_session(
                net_coro_factory=lambda iq, oq: listen_for_one(
                    port, priv, pub, my_nick, contacts, iq, oq
                ),
                priv=priv,
                my_nick=my_nick,
                contacts=contacts,
                port=port,
                standby_msg=f"LISTENING ON PORT {port}",
            )
            session_count += 1

        except KeyboardInterrupt:
            print("\n\nDaemon stopped.")
            break


def cmd_call(args):
    if not args:
        _die("Usage:  pgpchat call <name> [host] [port]")

    name      = args[0]
    priv, pub = _load_my_keys()
    cfg       = _load_config()
    my_nick   = cfg.get("nickname", "me")
    contacts  = _load_contacts()
    contact   = _contact_by_name(name, contacts)

    if not contact:
        _die(f"Contact not found: {name}")

    host = args[1] if len(args) >= 2 else contact.get("host")
    port = int(args[2]) if len(args) >= 3 else contact.get("port") or DEFAULT_PORT

    if not host:
        host = input(f"No address stored for {name}.  Enter host: ").strip()
        if not host:
            _die("Host required.")
        # Offer to save it
        save_yn = input(f"Save {host}:{port} for future calls? [Y/n] ").strip().lower()
        if save_yn != "n":
            existing = json.loads(Path(contact["_file"]).read_text())
            existing["host"] = host
            existing["port"] = port
            _save_contact(existing)
            print(f"✓ Address saved.")
    elif len(args) >= 2:
        existing = json.loads(Path(contact["_file"]).read_text())
        if existing.get("host") != host or existing.get("port") != port:
            existing["host"] = host
            existing["port"] = port
            _save_contact(existing)

    print(f"[{_now()}]  Calling {name} at {host}:{port} …")

    peer_fp = contact["fingerprint"]

    _run_one_session(
        net_coro_factory=lambda iq, oq: connect_to_peer(
            host, port, priv, pub, my_nick, contacts, iq, oq
        ),
        priv=priv,
        my_nick=my_nick,
        contacts=contacts,
        port=port,
        known_peer_fp=peer_fp,
        standby_msg=f"CONNECTING TO {name.upper()} @ {host}:{port}",
    )


def cmd_listen(args):
    port      = int(args[0]) if args else DEFAULT_PORT
    priv, pub = _load_my_keys()
    cfg       = _load_config()
    my_nick   = cfg.get("nickname", "me")
    contacts  = _load_contacts()
    if not contacts:
        _die("No contacts yet.  Import one first:  pgpchat import <name>")

    _run_one_session(
        net_coro_factory=lambda iq, oq: listen_for_one(
            port, priv, pub, my_nick, contacts, iq, oq
        ),
        priv=priv,
        my_nick=my_nick,
        contacts=contacts,
        port=port,
        standby_msg=f"LISTENING ON PORT {port}",
    )


def cmd_connect(args):
    if len(args) < 2:
        _die("Usage:  pgpchat connect <name> <host> [port]")
    name      = args[0]
    host      = args[1]
    port      = int(args[2]) if len(args) >= 3 else DEFAULT_PORT
    priv, pub = _load_my_keys()
    cfg       = _load_config()
    my_nick   = cfg.get("nickname", "me")
    contacts  = _load_contacts()
    contact   = _contact_by_name(name, contacts)
    if not contact:
        _die(f"Contact not found: {name}")

    _run_one_session(
        net_coro_factory=lambda iq, oq: connect_to_peer(
            host, port, priv, pub, my_nick, contacts, iq, oq
        ),
        priv=priv,
        my_nick=my_nick,
        contacts=contacts,
        port=port,
        known_peer_fp=contact["fingerprint"],
        standby_msg=f"CONNECTING TO {name.upper()} @ {host}:{port}",
    )


def cmd_history(args):
    if not args:
        _die("Usage:  pgpchat history <name>")
    name     = args[0]
    contacts = _load_contacts()
    contact  = _contact_by_name(name, contacts)
    if not contact:
        _die(f"Contact not found: {name}")

    priv, _ = _load_my_keys()
    log     = storage.ChatLog(LOGS_DIR, contact["fingerprint"], priv)
    entries = log.read_all()

    if not entries:
        print(f"No history with {name}.")
        return

    print(f"Chat history with {contact['name']}:")
    _hr()
    for entry in entries:
        ts    = datetime.fromtimestamp(entry["ts"]).strftime("%Y-%m-%d %H:%M:%S")
        arrow = "→" if entry["dir"] == "sent" else "←"
        print(f"[{ts}] {arrow} {entry['nick']}: {entry['msg']}")


# dispatch

COMMANDS = {
    "keygen":       cmd_keygen,
    "whoami":       cmd_whoami,
    "import":       cmd_import,
    "contacts":     cmd_contacts,
    "remove":       cmd_remove,
    "set-address":  cmd_set_address,
    "daemon":       cmd_daemon,
    "call":         cmd_call,
    "listen":       cmd_listen,
    "connect":      cmd_connect,
    "history":      cmd_history,
}

HELP = """\
pgpchat — PGP-style encrypted P2P terminal communicator

Setup (one-time, both sides):
  keygen                          Generate your RSA-4096 key pair
  whoami                          Print your public key to share with contacts
  import  <name> [keyfile]        Import a contact's public key (+ optional address)
  set-address <name> <host> [p]   Store/update a contact's IP address

Contacts:
  contacts                        List contacts with stored addresses
  remove  <name>                  Remove a contact

Chat:
  daemon  [port]                  Persistent listener — stays alive, loops after each call
  call    <name> [host] [port]    Call a contact (uses stored address if host omitted)
  listen  [port]                  One-shot listen, then exit  (default port: 7890)
  connect <name> <host> [port]    One-shot connect, then exit

History:
  history <name>                  View encrypted local chat log

Quickstart:
  # Machine A                       # Machine B
  pgpchat keygen                    pgpchat keygen
  pgpchat whoami | mail B           pgpchat whoami | mail A
  pgpchat import bob bob.pub        pgpchat import alice alice.pub
  pgpchat set-address bob 10.0.0.2  pgpchat daemon
  pgpchat daemon
                                     # From a second terminal on B:
  pgpchat call bob                   pgpchat call alice 10.0.0.1

In-chat commands:  /help  /fp  /clear  /quit
"""


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print(HELP)
        return
    cmd  = sys.argv[1]
    args = sys.argv[2:]
    if cmd not in COMMANDS:
        print(f"Unknown command: {cmd!r}\nRun 'pgpchat help' for usage.", file=sys.stderr)
        sys.exit(1)
    COMMANDS[cmd](args)


if __name__ == "__main__":
    main()
