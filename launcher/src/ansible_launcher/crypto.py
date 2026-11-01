"""Versioned authenticated hybrid encryption: RSA-OAEP/SHA-256 + AES-256-GCM.

Wire format (binary):
    MAGIC (22 bytes) | kind (1 byte) | wrapped-key length (2 bytes BE)
    | nonce (12 bytes) | RSA-wrapped 32-byte AES key | AES-GCM ciphertext + tag
Everything before ciphertext is authenticated as AES-GCM associated data.
"""

from __future__ import annotations

import os
import struct
import hashlib

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import DecryptionError, LauncherError

MAGIC = b"ANSIBLE-LAUNCHER-ENC\x00\x01"
PURPOSE = {"inventory": 1, "vault-password": 2, "file": 3, "keyring": 4}
MAGIC_V2 = b"ANSIBLE-LAUNCHER-ENC\x00\x02"
ENCRYPTED_PREFIX = b"ANSIBLE-LAUNCHER-ENC\x00"
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


def _fingerprint(public_key: rsa.RSAPublicKey) -> bytes:
    data = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(data).digest()


def encrypt_bytes_v2(plaintext: bytes, public_key: rsa.RSAPublicKey, purpose: str) -> bytes:
    """Encrypt once with AES; wrap the AES key for the first RSA recipient.

    V2 format:
      MAGIC_V2 | purpose (1) | nonce (12) | recipient count (2) |
      (fingerprint (32) | wrapped size (2) | RSA-OAEP wrapped AES key) |
      AES-GCM ciphertext and tag

    AES-GCM AAD is only MAGIC_V2 + purpose + nonce, so future recipients
    can be added without changing the ciphertext or authentication tag.
    """
    if purpose not in PURPOSE:
        raise LauncherError("Unbekannter Dateityp fuer die Verschluesselung.")
    if len(plaintext) > MAX_FILE_BYTES:
        raise LauncherError("Datei zu gross (maximal 64 MiB).")
    aes_key = os.urandom(AES_KEY_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    aad = MAGIC_V2 + bytes((PURPOSE[purpose],)) + nonce
    wrapped = public_key.encrypt(aes_key, _oaep())
    recipients = (
        struct.pack(">H", 1) + _fingerprint(public_key) +
        struct.pack(">H", len(wrapped)) + wrapped
    )
    return aad + recipients + AESGCM(aes_key).encrypt(nonce, plaintext, aad)


def _decrypt_v2(blob: bytes, private_key: rsa.RSAPrivateKey, purpose: str) -> bytes:
    if len(blob) < len(MAGIC_V2) + 1 + NONCE_BYTES + 2 + 16:
        raise DecryptionError("Verschluesselte Datei ist unvollstaendig.")
    offset = len(MAGIC_V2)
    kind = blob[offset]
    offset += 1
    if kind != PURPOSE[purpose]:
        raise DecryptionError("Dateityp stimmt nicht ueberein.")
    nonce = blob[offset:offset + NONCE_BYTES]
    offset += NONCE_BYTES
    aad = blob[:offset]
    count, = struct.unpack_from(">H", blob, offset)
    offset += 2
    if not 1 <= count <= 128:
        raise DecryptionError("Ungueltige Empfaengeranzahl.")
    expected_fingerprint = _fingerprint(private_key.public_key())
    wrapped_key = None
    seen = set()
    for _ in range(count):
        if len(blob) - offset < 34 + 16:
            raise DecryptionError("Ungueltiger RSA-Empfaenger-Header.")
        fingerprint = blob[offset:offset + 32]
        offset += 32
        wrapped_length, = struct.unpack_from(">H", blob, offset)
        offset += 2
        if fingerprint in seen or not 256 <= wrapped_length <= 1024:
            raise DecryptionError("Ungueltiger RSA-Empfaenger-Header.")
        seen.add(fingerprint)
        if len(blob) - offset < wrapped_length + 16:
            raise DecryptionError("Unvollstaendiger RSA-Empfaenger-Header.")
        if fingerprint == expected_fingerprint:
            wrapped_key = blob[offset:offset + wrapped_length]
        offset += wrapped_length
    if wrapped_key is None:
        raise DecryptionError("Dieser RSA-Key ist kein Empfaenger dieser Datei.")
    try:
        aes_key = private_key.decrypt(wrapped_key, _oaep())
        if len(aes_key) != AES_KEY_BYTES:
            raise DecryptionError("Entschluesselter AES-Key hat ungueltige Laenge.")
        plaintext = AESGCM(aes_key).decrypt(nonce, blob[offset:], aad)
    except (ValueError, InvalidTag) as exc:
        raise DecryptionError("Entschluesselung fehlgeschlagen.") from exc
    if len(plaintext) > MAX_FILE_BYTES:
        raise DecryptionError("Entschluesselte Datei ist zu gross.")
    return plaintext


def decrypt_bytes(blob: bytes, private_key: rsa.RSAPrivateKey, purpose: str) -> bytes:
    if purpose not in PURPOSE:
        raise LauncherError("Unbekannter Dateityp für die Entschlüsselung.")
    if blob.startswith(MAGIC_V2):
        return _decrypt_v2(blob, private_key, purpose)
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


def _v2_sections(blob: bytes, purpose: str) -> tuple[bytes, bytes, bytes, dict[bytes, bytes]]:
    """Parse a V2 envelope; return (AAD, nonce, ciphertext, wrapped keys)."""
    if purpose not in PURPOSE or not blob.startswith(MAGIC_V2):
        raise DecryptionError("Ungueltiges V2-Dateiformat.")
    offset = len(MAGIC_V2)
    if len(blob) < offset + 1 + NONCE_BYTES + 2 + 16:
        raise DecryptionError("V2-Datei ist unvollstaendig.")
    kind = blob[offset]
    if kind != PURPOSE[purpose]:
        raise DecryptionError("Dateityp stimmt nicht ueberein.")
    offset += 1
    nonce = blob[offset:offset + NONCE_BYTES]
    offset += NONCE_BYTES
    aad = blob[:offset]
    count, = struct.unpack_from(">H", blob, offset)
    offset += 2
    if not 1 <= count <= 128:
        raise DecryptionError("Ungueltige Empfaengeranzahl.")
    recipients = {}
    for _ in range(count):
        if len(blob) - offset < 34 + 16:
            raise DecryptionError("Unvollstaendiger Empfaengerheader.")
        fp = blob[offset:offset + 32]
        offset += 32
        size, = struct.unpack_from(">H", blob, offset)
        offset += 2
        if fp in recipients or not 256 <= size <= 1024 or len(blob) - offset < size + 16:
            raise DecryptionError("Ungueltiger Empfaengerheader.")
        recipients[fp] = blob[offset:offset + size]
        offset += size
    return aad, nonce, blob[offset:], recipients


def recipient_fingerprints(blob: bytes, purpose: str) -> set[str] | None:
    """For V2 return recipient fingerprints; V1 cannot identify its recipient."""
    if blob.startswith(MAGIC_V2):
        return {item.hex() for item in _v2_sections(blob, purpose)[3]}
    if blob.startswith(MAGIC):
        return None
    raise DecryptionError("Nicht unterstuetztes verschluesseltes Dateiformat.")


def _wrap_for_keys(aes_key: bytes, keys: list[rsa.RSAPublicKey]) -> bytes:
    if not 1 <= len(keys) <= 128:
        raise LauncherError("Es muessen 1 bis 128 autorisierte RSA-Empfaenger vorliegen.")
    recipients = []
    seen = set()
    for key in sorted(keys, key=_fingerprint):
        fp = _fingerprint(key)
        if fp in seen:
            raise LauncherError("RSA-Empfaenger doppelt vorhanden.")
        seen.add(fp)
        wrapped = key.encrypt(aes_key, _oaep())
        recipients.append(fp + struct.pack(">H", len(wrapped)) + wrapped)
    return struct.pack(">H", len(recipients)) + b"".join(recipients)


def encrypt_bytes_v2_many(plaintext: bytes, keys: list[rsa.RSAPublicKey], purpose: str) -> bytes:
    """Encrypt once for every public key from the verified key registry."""
    if purpose not in PURPOSE or len(plaintext) > MAX_FILE_BYTES:
        raise LauncherError("Ungueltiger Dateityp oder Datei zu gross.")
    aes_key, nonce = os.urandom(AES_KEY_BYTES), os.urandom(NONCE_BYTES)
    aad = MAGIC_V2 + bytes((PURPOSE[purpose],)) + nonce
    return aad + _wrap_for_keys(aes_key, keys) + AESGCM(aes_key).encrypt(nonce, plaintext, aad)


def rewrap_v2_recipients(
    blob: bytes, private_key: rsa.RSAPrivateKey,
    keys: list[rsa.RSAPublicKey], purpose: str,
) -> bytes:
    """Replace wrapped AES keys without re-encrypting V2 AES ciphertext.

    V1 is converted by decrypting and encrypting once, because V1 uses a
    different authenticated envelope that cannot be rewrapped directly.
    """
    if blob.startswith(MAGIC) and not blob.startswith(MAGIC_V2):
        plaintext = decrypt_bytes(blob, private_key, purpose)
        return encrypt_bytes_v2_many(plaintext, keys, purpose)
    aad, nonce, ciphertext, recipients = _v2_sections(blob, purpose)
    fp = _fingerprint(private_key.public_key())
    wrapped = recipients.get(fp)
    if wrapped is None:
        raise DecryptionError("Dieser RSA-Key ist kein Empfaenger dieser Datei.")
    try:
        aes_key = private_key.decrypt(wrapped, _oaep())
        if len(aes_key) != AES_KEY_BYTES:
            raise DecryptionError("Ungueltiger AES-Dateischluessel.")
        AESGCM(aes_key).decrypt(nonce, ciphertext, aad)
    except (ValueError, InvalidTag) as exc:
        raise DecryptionError("Datei ist beschaedigt oder falscher RSA-Key.") from exc
    return aad + _wrap_for_keys(aes_key, keys) + ciphertext
