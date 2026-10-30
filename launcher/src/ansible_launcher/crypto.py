"""Versioned authenticated hybrid encryption: RSA-OAEP/SHA-256 + AES-256-GCM.

Wire format (binary):
    MAGIC (22 bytes) | kind (1 byte) | wrapped-key length (2 bytes BE)
    | nonce (12 bytes) | RSA-wrapped 32-byte AES key | AES-GCM ciphertext + tag
Everything before ciphertext is authenticated as AES-GCM associated data.
"""

from __future__ import annotations

import os
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import DecryptionError, LauncherError

MAGIC = b"ANSIBLE-LAUNCHER-ENC\x00\x01"
PURPOSE = {"inventory": 1, "vault-password": 2}
NONCE_BYTES = 12
AES_KEY_BYTES = 32
MAX_FILE_BYTES = 64 * 1024 * 1024


def _oaep() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def encrypt_bytes(plaintext: bytes, public_key: rsa.RSAPublicKey, purpose: str) -> bytes:
    if purpose not in PURPOSE:
        raise LauncherError("Unbekannter Dateityp für die Verschlüsselung.")
    if len(plaintext) > MAX_FILE_BYTES:
        raise LauncherError("Datei zu groß (maximal 64 MiB).")
    aes_key = os.urandom(AES_KEY_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    wrapped_key = public_key.encrypt(aes_key, _oaep())
    header = MAGIC + struct.pack(">BH", PURPOSE[purpose], len(wrapped_key)) + nonce + wrapped_key
    return header + AESGCM(aes_key).encrypt(nonce, plaintext, header)


def decrypt_bytes(blob: bytes, private_key: rsa.RSAPrivateKey, purpose: str) -> bytes:
    if purpose not in PURPOSE:
        raise LauncherError("Unbekannter Dateityp für die Entschlüsselung.")
    minimum = len(MAGIC) + 3 + NONCE_BYTES + 16
    if len(blob) < minimum or not blob.startswith(MAGIC):
        raise DecryptionError("Verschlüsselte Datei hat ein ungültiges Format.")
    offset = len(MAGIC)
    kind, wrapped_len = struct.unpack_from(">BH", blob, offset)
    offset += 3
    if kind != PURPOSE[purpose]:
        raise DecryptionError("Dateityp stimmt nicht überein (Inventory/Vault-Passwort).")
    if wrapped_len < 256 or wrapped_len > 1024:
        raise DecryptionError("Ungültige RSA-Schlüssellänge in der Datei.")
    if len(blob) < offset + NONCE_BYTES + wrapped_len + 16:
        raise DecryptionError("Verschlüsselte Datei ist unvollständig.")
    nonce = blob[offset : offset + NONCE_BYTES]
    offset += NONCE_BYTES
    wrapped = blob[offset : offset + wrapped_len]
    offset += wrapped_len
    try:
        aes_key = private_key.decrypt(wrapped, _oaep())
        if len(aes_key) != AES_KEY_BYTES:
            raise DecryptionError("Entschlüsselter AES-Schlüssel hat ungültige Länge.")
        plaintext = AESGCM(aes_key).decrypt(nonce, blob[offset:], blob[:offset])
        if len(plaintext) > MAX_FILE_BYTES:
            raise DecryptionError("Entschlüsselte Datei überschreitet das Größenlimit.")
        return plaintext
    except (ValueError, InvalidTag) as exc:
        raise DecryptionError("Entschlüsselung fehlgeschlagen: falscher RSA-Key oder beschädigte Datei.") from exc
