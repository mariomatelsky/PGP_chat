# pgpchat

Terminal chat with end-to-end encryption. Two people, direct TCP connection, no server in the middle.

Uses RSA-4096 key pairs for identity and authentication, AES-256-GCM for message encryption. Chat history is saved locally and encrypted with a key derived from your private key.

```
░▒▓█ PGPCHAT █▓▒░  ·  RSA-4096 // AES-256-GCM  ·  alice  ·  14:32:01
╔══════════════════════╦═══════════════════════════════════════════════╗
║  C O N T A C T S    ║  CHANNEL : BOB                 [ ENCRYPTED ] ║
╠══════════════════════╬═══════════════════════════════════════════════╣
║ ► BOB           ●   ║  14:30    BOB ▌ yo                            ║
║   CHARLIE       ○   ║  14:31  ALICE ▌ hey                           ║
╠══════════════════════╬═══════════════════════════════════════════════╣
║  ● 1 / 2  ONLINE    ║  ALICE►  _                                    ║
╚══════════════════════╩═══════════════════════════════════════════════╝
```

## Requirements

- Python 3.9+
- `cryptography` library

## Install

```bash
bash install.sh
```

This installs the `cryptography` package and drops a `pgpchat` wrapper in `~/bin/` (or `/usr/local/bin/` if you have access).

If `~/bin` isn't on your PATH yet, add this to `~/.zshrc` or `~/.bashrc`:

```bash
export PATH="$HOME/bin:$PATH"
```

## Setup

Both sides do this once:

```bash
pgpchat keygen          # generates RSA-4096 key pair, asks for passphrase
pgpchat whoami          # prints your public key to share
pgpchat import bob      # paste bob's public key (or: pgpchat import bob bob.pub)
pgpchat set-address bob 10.0.0.5   # optional, saves the address so you don't type it each time
```

## Usage

**Leave a listener running (recommended):**
```bash
pgpchat daemon          # loops after each session, ctrl-c to stop
```

**Call someone:**
```bash
pgpchat call bob        # uses stored address
pgpchat call bob 10.0.0.5   # or specify host directly
```

**One-shot variants:**
```bash
pgpchat listen          # wait for one connection then exit
pgpchat connect bob 10.0.0.5
```

**View history:**
```bash
pgpchat history bob
```

## In-chat commands

```
/help   show commands
/fp     show peer fingerprint
/clear  clear the screen (log stays on disk)
/quit   disconnect
```

Scroll with arrow keys or Page Up/Down.

## Data

Everything lives in `~/.pgpchat/`:
- `keys/` — your RSA key pair
- `contacts/` — imported public keys + addresses
- `logs/` — encrypted chat history (one file per contact)

## Notes

- Both sides need to have each other imported as a contact before a connection will succeed.
- Verify fingerprints out-of-band (`pgpchat whoami` / `pgpchat contacts`) before trusting a contact.
- Default port is 7890. Override with `pgpchat daemon 8000`, etc.
- Works over LAN or any direct IP connection. No relay, no accounts.
