"""Safe file handling for encrypted artifacts (not temporary cleartext)."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import tempfile

from .crypto import MAX_FILE_BYTES, decrypt_bytes, encrypt_bytes
from .errors import DecryptionError, LauncherError


def read_regular(path: Path, *, max_bytes: int = MAX_FILE_BYTES + 8192) -> bytes:
    try:
        if not stat.S_ISREG(path.stat().st_mode):
            raise LauncherError(f"Keine reguläre Datei: {path}")
        with path.open("rb") as stream:
            data = stream.read(max_bytes + 1)
    except OSError as exc:
        raise LauncherError(f"Datei kann nicht gelesen werden: {path}: {exc.strerror}") from exc
    if len(data) > max_bytes:
        raise LauncherError(f"Datei überschreitet die zulässige Größe: {path}")
    return data


def atomic_write(path: Path, content: bytes, *, overwrite: bool = False) -> None:
    """Write file with mode 0600, avoid creating partial destination files."""
    path = path.expanduser().absolute()
    if path.exists() and not overwrite:
        raise LauncherError(f"Zieldatei existiert bereits: {path} (verwende --force).")
    if not path.parent.is_dir():
        raise LauncherError(f"Zielverzeichnis existiert nicht: {path.parent}")
    fd: int | None = None
    temporary: str | None = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=".ansible-launcher-", suffix=".tmp", dir=path.parent)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            fd = None
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if overwrite:
            os.replace(temporary, path)
        else:
            # link() without following the destination provides atomic no-overwrite.
            try:
                os.link(temporary, path)
            except FileExistsError as exc:
                raise LauncherError(f"Zieldatei existiert bereits: {path}") from exc
            os.unlink(temporary)
        temporary = None
    except OSError as exc:
        raise LauncherError(f"Datei kann nicht sicher geschrieben werden: {path}: {exc.strerror}") from exc
    finally:
        if fd is not None:
            os.close(fd)
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def encrypt_file(source: Path, target: Path, public_key, purpose: str, *, force: bool = False, delete_source: bool = False, verify_private_key=None) -> None:
    source = source.expanduser().resolve()
    target = target.expanduser().absolute()
    if source == target:
        raise LauncherError("Quell- und Zieldatei dürfen nicht identisch sein.")
    plaintext = read_regular(source, max_bytes=MAX_FILE_BYTES)
    if purpose == "vault-password" and not plaintext.strip():
        raise LauncherError("Master-Vault-Passwortdatei ist leer.")
    ciphertext = encrypt_bytes(plaintext, public_key, purpose)
    atomic_write(target, ciphertext, overwrite=force)
    # Round-trip verification is mandatory before unlinking the plaintext source.
    if delete_source:
        if verify_private_key is None:
            raise LauncherError("--delete-source erfordert einen RSA-Private-Key zur Integritätsprüfung.")
        if decrypt_file(target, verify_private_key, purpose) != plaintext:
            raise LauncherError("Integritätsprüfung fehlgeschlagen; Klartextquelle bleibt erhalten.")
        try:
            source.unlink()
        except OSError as exc:
            raise LauncherError(f"Verschlüsselung erfolgreich, Quelldatei konnte nicht entfernt werden: {source}") from exc


def decrypt_file(source: Path, private_key, purpose: str) -> bytes:
    source = source.expanduser().resolve()
    ciphertext = read_regular(source)
    return decrypt_bytes(ciphertext, private_key, purpose)
