"""RSA keys in OpenSSH or PEM format; SSH agents are not decryptors."""

from __future__ import annotations

import getpass
import os
from pathlib import Path
import stat

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.exceptions import UnsupportedAlgorithm

from .errors import LauncherError

MIN_RSA_BITS = 3072  # RSA-4096 is recommended.


def _check_private_file(path: Path) -> bytes:
    try:
        st = path.stat()
        if not stat.S_ISREG(st.st_mode):
            raise LauncherError(f"Der RSA-Key ist keine reguläre Datei: {path}")
        if os.name == "posix" and (stat.S_IMODE(st.st_mode) & 0o077):
            raise LauncherError(
                f"Unsichere Dateirechte für {path}. Erwartet wird z. B. chmod 600."
            )
        return path.read_bytes()
    except OSError as exc:
        raise LauncherError(f"RSA-Key kann nicht gelesen werden: {path}: {exc.strerror}") from exc


def load_rsa_private_key(path: Path, *, prompt: bool = True) -> rsa.RSAPrivateKey:
    """Load an RSA private key. Prompt for passphrase only if needed."""
    data = _check_private_file(path)
    is_openssh = data.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----")
    loader = serialization.load_ssh_private_key if is_openssh else serialization.load_pem_private_key

    def deserialize(password: bytes | None):
        return loader(data, password=password)

    try:
        try:
            key = deserialize(None)
        except TypeError as exc:
            # Encrypted OpenSSH/PEM keys require a passphrase. Do not echo it.
            if not prompt:
                raise LauncherError("RSA-Key ist passwortgeschützt; interaktive Abfrage deaktiviert.") from exc
            try:
                password = getpass.getpass(f"RSA-Key-Passphrase ({path.name}): ").encode("utf-8")
            except (EOFError, KeyboardInterrupt) as err:
                raise LauncherError("RSA-Key-Passphrase wurde nicht eingegeben.") from err
            if not password:
                raise LauncherError("Leere RSA-Key-Passphrase wurde nicht akzeptiert.")
            key = deserialize(password)
    except UnsupportedAlgorithm as exc:
        if "bcrypt" in str(exc).lower():
            raise LauncherError("Für verschlüsselte OpenSSH-Keys wird das Python-Paket bcrypt benötigt.") from exc
        raise LauncherError("RSA-Key verwendet ein nicht unterstütztes Format oder einen Algorithmus.") from exc
    except (ValueError, TypeError) as exc:
        raise LauncherError("RSA-Key konnte nicht geladen werden (Format oder Passphrase ungültig).") from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise LauncherError("Es werden ausschließlich RSA-Private-Keys unterstützt (kein Ed25519/ECDSA).")
    if key.key_size < MIN_RSA_BITS:
        raise LauncherError(f"RSA-Key zu kurz: {key.key_size} Bit. Mindestens {MIN_RSA_BITS} Bit erforderlich.")
    return key
