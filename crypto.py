"""Crypto layer: RSA-4096 keys, hybrid AES-256-GCM encryption, PSS signing, HKDF log keys."""

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Tuple, Dict

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def generate_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    return private_key, private_key.public_key()


def serialize_public_key(public_key) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def load_public_key(pem: str):
    return serialization.load_pem_public_key(pem.encode())


def save_private_key(private_key, path: Path, passphrase: str):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode()),
    )
    path.write_bytes(pem)
    path.chmod(0o600)


def load_private_key(path: Path, passphrase: str):
    return serialization.load_pem_private_key(path.read_bytes(), password=passphrase.encode())


def fingerprint(public_key) -> str:
    # SHA-256 of DER SubjectPublicKeyInfo → 8 groups of 4 hex chars
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i:i+4] for i in range(0, 32, 4))


def encrypt_message(plaintext: str, recipient_pub) -> Dict[str, str]:
    # returns {enc_key, nonce, ciphertext} — all base64
    aes_key = os.urandom(32)
    nonce   = os.urandom(12)

    aesgcm     = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

    enc_key = recipient_pub.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return {
        "enc_key":    base64.b64encode(enc_key).decode(),
        "nonce":      base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }


def decrypt_message(payload: Dict[str, str], private_key) -> str:
    enc_key    = base64.b64decode(payload["enc_key"])
    nonce      = base64.b64decode(payload["nonce"])
    ciphertext = base64.b64decode(payload["ciphertext"])

    aes_key = private_key.decrypt(
        enc_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")


def sign(data: bytes, private_key) -> str:
    sig = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(sig).decode()


def verify(data: bytes, signature_b64: str, public_key) -> bool:
    try:
        sig = base64.b64decode(signature_b64)
        public_key.verify(
            sig,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def derive_log_key(private_key, contact_fingerprint: str) -> bytes:
    # HKDF over raw private key DER — reproducible from same key+contact pair
    raw = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=f"pgpchat-log:{contact_fingerprint}".encode(),
    )
    return hkdf.derive(raw)


def encrypt_log_entry(plaintext: str, key: bytes) -> str:
    nonce = os.urandom(12)
    ct    = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ct).decode()


def decrypt_log_entry(blob_b64: str, key: bytes) -> str:
    blob  = base64.b64decode(blob_b64)
    nonce = blob[:12]
    ct    = blob[12:]
    return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")
