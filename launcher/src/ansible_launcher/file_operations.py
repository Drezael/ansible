"""Explicit encrypt/decrypt/synchronize commands for the launcher file list.

Only keys from the encrypted, signed key registry can be used. Adding a key
never edits a ciphertext: synchronization is a separate explicit command.
"""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import stat
import tempfile

from .config import LauncherConfig, resolve_project_relative
from .crypto import (
    ENCRYPTED_PREFIX, MAX_FILE_BYTES, decrypt_bytes, encrypt_bytes_v2_many,
    recipient_fingerprints, rewrap_v2_recipients,
)
from .errors import LauncherError
from .files import read_regular
from .keyring import authorized_private_key


def _check_relative_path(raw: str) -> PurePosixPath:
    if (
        not isinstance(raw, str) or not raw or raw.startswith("/")
        or "\\" in raw or "\x00" in raw
        or any(part in ("", ".", "..") for part in raw.split("/"))
        or raw.endswith(".enc")
    ):
        raise LauncherError(f"Ungueltiger Dateipfad in der Liste: {raw!r}.")
    return PurePosixPath(raw)


def _check_no_symlinks(path: Path, root: Path) -> None:
    if not path.is_relative_to(root):
        raise LauncherError(f"Datei liegt ausserhalb des Projekts: {path}")
    current = path
    while current != root:
        if current.is_symlink():
            raise LauncherError(f"Symbolische Links sind nicht erlaubt: {current}")
        current = current.parent



def _entries(
    root: Path, cfg: LauncherConfig, names: list[str], selected: str | None,
) -> list[tuple[Path, Path, str, str]]:
    if not isinstance(names, list) or not names:
        raise LauncherError("Die Verschluesselungsliste ist leer.")
    if selected is not None and selected not in names:
        raise LauncherError(f"Datei steht nicht in encryption-files.txt: {selected}")
    selected_names = [selected] if selected else names
    root = root.resolve()
    inventory_dir = resolve_project_relative(root, cfg.inventory_dir)
    master_target = cfg.master_path(root)
    entries = []
    seen = set()
    for name in selected_names:
        rel = _check_relative_path(name)
        source = root.joinpath(*rel.parts)
        target = source.with_name(source.name + ".enc")
        # The user-controlled file list must never replace the trust database.
        protected = {
            root / "launcher" / "authorized-keys.enc",
            root / "launcher" / "authorized-keys.sig",
            root / "launcher" / "encryption-files.txt",
        }
        if source in protected or target in protected:
            raise LauncherError(f"Geschuetzte Launcher-Datei in der Verschluesselungsliste: {name}")
        if source in seen or target in seen:
            raise LauncherError("Doppelter Dateipfad in der Verschluesselungsliste.")
        seen.add(source)
        for path in (source, target):
            _check_no_symlinks(path, root)
        if not source.parent.is_dir() or not target.parent.is_dir():
            raise LauncherError(f"Verzeichnis fuer Datei fehlt: {name}")
        purpose = (
            "vault-password" if target == master_target else
            "inventory" if source.parent == inventory_dir and source.suffix in (".yml", ".yaml") else
            "file"
        )
        entries.append((source, target, purpose, name))
    return entries


def _regular_existing(path: Path) -> None:
    try:
        if not stat.S_ISREG(path.stat().st_mode):
            raise LauncherError(f"Keine regulaere Datei: {path}")
    except OSError as exc:
        raise LauncherError(f"Datei fehlt oder ist nicht lesbar: {path}: {exc}") from exc


def _write_batch(contents: list[tuple[Path, bytes]], *, overwrite: bool = False) -> None:
    """Stage everything first; replace atomically and roll back on errors."""
    if not contents:
        return
    for target, _ in contents:
        if target.is_symlink():
            raise LauncherError(f"Symlinks sind nicht erlaubt: {target}")
        if not target.parent.is_dir():
            raise LauncherError(f"Zielverzeichnis fehlt: {target.parent}")
        if os.path.lexists(target) and not overwrite:
            raise LauncherError(f"Zieldatei existiert bereits (verwende --force): {target}")
        if os.path.lexists(target):
            _regular_existing(target)

    staged: list[tuple[Path, Path]] = []
    previous: dict[Path, Path] = {}
    written: list[Path] = []
    try:
        for target, data in contents:
            fd, temp_name = tempfile.mkstemp(prefix=".ansible-seal-", dir=target.parent)
            temp = Path(temp_name)
            staged.append((temp, target))
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())

        for temp, target in staged:
            if os.path.lexists(target):
                fd, name = tempfile.mkstemp(prefix=".ansible-backup-", dir=target.parent)
                os.close(fd)
                backup = Path(name)
                backup.unlink()
                os.link(target, backup)
                previous[target] = backup
                os.replace(temp, target)
            else:
                os.link(temp, target, follow_symlinks=False)
            written.append(target)
    except Exception as exc:
        for target in reversed(written):
            backup = previous.get(target)
            if backup is not None and backup.exists():
                os.replace(backup, target)
            else:
                target.unlink(missing_ok=True)
        if isinstance(exc, OSError):
            raise LauncherError(f"Dateien konnten nicht geschrieben werden: {exc}") from exc
        raise
    finally:
        for temp, _ in staged:
            temp.unlink(missing_ok=True)
        for backup in previous.values():
            backup.unlink(missing_ok=True)


def _validate_recipients(blob: bytes, purpose: str, allowed: set[str]) -> None:
    existing = recipient_fingerprints(blob, purpose)
    if existing is not None and not existing.issubset(allowed):
        raise LauncherError(
            "Verschluesselte Datei enthaelt RSA-Empfaenger, die nicht in der "
            "signierten Schluesselregistrierung autorisiert sind. Abbruch."
        )


def encrypt_list(
    *, project_root: Path, cfg: LauncherConfig, file_list: list[str],
    private_key_path: Path, selected: str | None = None,
    force: bool = False, delete_source: bool = False,
) -> list[Path]:
    """Explicitly encrypt plaintext using ALL signed authorized public keys."""
    private, keys = authorized_private_key(project_root, private_key_path)
    entries = _entries(project_root, cfg, file_list, selected)
    payloads: list[tuple[Path, bytes]] = []
    originals: list[tuple[Path, bytes, Path, str]] = []
    for source, target, purpose, _ in entries:
        _regular_existing(source)
        if os.path.lexists(target):
            if not force:
                raise LauncherError(f"Bereits verschluesselt: {target} (erneut mit --force verschluesseln).")
            _regular_existing(target)
            old = read_regular(target)
            _validate_recipients(old, purpose, set(keys))
            # Do not replace an encrypted file that this caller cannot decrypt.
            decrypt_bytes(old, private, purpose)
        plaintext = read_regular(source, max_bytes=MAX_FILE_BYTES)
        if plaintext.startswith(ENCRYPTED_PREFIX):
            raise LauncherError(f"Quelldatei ist bereits verschluesselt: {source}")
        if purpose == "vault-password" and not plaintext.strip():
            raise LauncherError(f"Leere Vault-Passwortdatei: {source}")
        payloads.append((target, encrypt_bytes_v2_many(plaintext, list(keys.values()), purpose)))
        originals.append((source, plaintext, target, purpose))
    _write_batch(payloads, overwrite=force)
    if delete_source:
        for source, original, target, purpose in originals:
            if decrypt_bytes(read_regular(target), private, purpose) != original:
                raise LauncherError(f"Verifikation fehlgeschlagen; Klartext bleibt erhalten: {source}")
        for source, _, _, _ in originals:
            source.unlink()
    return [target for target, _ in payloads]


def decrypt_list(
    *, project_root: Path, cfg: LauncherConfig, file_list: list[str],
    private_key_path: Path, selected: str | None = None, force: bool = False,
) -> list[Path]:
    """Export plaintext for editing; no implicit overwrites."""
    private, keys = authorized_private_key(project_root, private_key_path)
    entries = _entries(project_root, cfg, file_list, selected)
    payloads = []
    for source, target, purpose, _ in entries:
        _regular_existing(target)
        if os.path.lexists(source) and not force:
            raise LauncherError(f"Klartextdatei existiert bereits (verwende --force): {source}")
        blob = read_regular(target)
        _validate_recipients(blob, purpose, set(keys))
        payloads.append((source, decrypt_bytes(blob, private, purpose)))
    _write_batch(payloads, overwrite=force)
    return [source for source, _ in payloads]


def sync_recipients(
    *, project_root: Path, cfg: LauncherConfig, file_list: list[str],
    private_key_path: Path, selected: str | None = None,
) -> list[Path]:
    """Update recipient slots only, preserving AES content for V2 files."""
    private, keys = authorized_private_key(project_root, private_key_path)
    entries = _entries(project_root, cfg, file_list, selected)
    payloads = []
    for _, target, purpose, _ in entries:
        _regular_existing(target)
        blob = read_regular(target)
        _validate_recipients(blob, purpose, set(keys))
        payloads.append((target, rewrap_v2_recipients(blob, private, list(keys.values()), purpose)))
    _write_batch(payloads, overwrite=True)
    return [path for path, _ in payloads]
