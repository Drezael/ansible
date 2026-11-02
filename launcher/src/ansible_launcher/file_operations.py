"""Configuration-driven encrypted file operations with signed authorized keys."""
from __future__ import annotations
import os
from pathlib import Path
import stat
import tempfile
from .config import LauncherConfig, resolve_project_relative
from .crypto import (ENCRYPTED_PREFIX, MAX_FILE_BYTES, decrypt_bytes,
                     encrypt_bytes_v2_many, recipient_fingerprints, rewrap_v2_recipients)
from .errors import LauncherError
from .files import read_regular
from .keyring import authorized_private_key


def _check_no_symlinks(path: Path, root: Path) -> None:
    if not path.is_relative_to(root):
        raise LauncherError(f'Datei liegt ausserhalb des Projekts: {path}')
    current = path
    while current != root:
        if current.is_symlink():
            raise LauncherError(f'Symbolische Links sind nicht erlaubt: {current}')
        current = current.parent


def _entries(root: Path, cfg: LauncherConfig, names: list[str], selected: str | None):
    """Use only validated source/target mappings from the home configuration."""
    if not cfg.files:
        raise LauncherError('Keine files-Eintraege in der Home-Konfiguration vorhanden.')
    sources = [entry.source for entry in cfg.files]
    if selected is not None and selected not in sources:
        raise LauncherError(f'Datei steht nicht unter files in der Home-Konfiguration: {selected}')
    root = root.resolve()
    protected = {resolve_project_relative(root, cfg.keyring_file),
                 resolve_project_relative(root, cfg.keyring_signature_file)}
    entries = []
    inventory_dir = resolve_project_relative(root, cfg.inventory_dir)
    master_target = cfg.master_path(root)
    for entry in cfg.files:
        if selected is not None and entry.source != selected:
            continue
        source = resolve_project_relative(root, entry.source)
        target = resolve_project_relative(root, entry.target)
        if source == target or source in protected or target in protected:
            raise LauncherError(f'Ungueltiger oder geschuetzter Pfad: {entry.source} -> {entry.target}')
        for path in (source, target):
            _check_no_symlinks(path, root)
            if not path.parent.is_dir():
                raise LauncherError(f'Verzeichnis fuer Datei fehlt: {path.parent}')
        if entry.purpose == 'vault-password' and target != master_target:
            raise LauncherError('Vault-Passwort-Ziel stimmt nicht mit master_password_file ueberein.')
        if entry.purpose == 'inventory' and (target.parent != inventory_dir or not target.name.endswith('.yml.enc')):
            raise LauncherError('Inventory-Ziel muss in inventory_dir liegen und auf .yml.enc enden.')
        entries.append((source, target, entry.purpose, entry.source))
    return entries


def _regular_existing(path: Path) -> None:
    try:
        if not stat.S_ISREG(path.stat().st_mode):
            raise LauncherError(f'Keine regulaere Datei: {path}')
    except OSError as exc:
        raise LauncherError(f'Datei fehlt oder ist nicht lesbar: {path}: {exc}') from exc


def _write_batch(contents: list[tuple[Path, bytes]], *, overwrite: bool = False) -> None:
    """Stage all outputs and roll back changed paths on failure."""
    if not contents:
        return
    for target, _ in contents:
        if target.is_symlink():
            raise LauncherError(f'Symlinks sind nicht erlaubt: {target}')
        if not target.parent.is_dir():
            raise LauncherError(f'Zielverzeichnis fehlt: {target.parent}')
        if os.path.lexists(target) and not overwrite:
            raise LauncherError(f'Zieldatei existiert bereits (verwende --force): {target}')
        if os.path.lexists(target):
            _regular_existing(target)
    staged: list[tuple[Path, Path]] = []
    previous: dict[Path, Path] = {}
    written: list[Path] = []
    try:
        for target, data in contents:
            fd, temp_name = tempfile.mkstemp(prefix='.ansible-seal-', dir=target.parent)
            temp = Path(temp_name)
            staged.append((temp, target))
            with os.fdopen(fd, 'wb') as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        for temp, target in staged:
            if os.path.lexists(target):
                fd, name = tempfile.mkstemp(prefix='.ansible-backup-', dir=target.parent)
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
            raise LauncherError(f'Dateien konnten nicht geschrieben werden: {exc}') from exc
        raise
    finally:
        for temp, _ in staged:
            temp.unlink(missing_ok=True)
        for backup in previous.values():
            backup.unlink(missing_ok=True)


def _validate_recipients(blob: bytes, purpose: str, allowed: set[str]) -> None:
    existing = recipient_fingerprints(blob, purpose)
    if existing is not None and not existing.issubset(allowed):
        raise LauncherError('Verschluesselte Datei enthaelt nicht autorisierte RSA-Empfaenger.')


def encrypt_list(*, project_root: Path, cfg: LauncherConfig, file_list: list[str],
                 private_key_path: Path, selected: str | None = None,
                 force: bool = False, delete_source: bool = False) -> list[Path]:
    private, keys = authorized_private_key(project_root, private_key_path)
    entries = _entries(project_root, cfg, file_list, selected)
    payloads = []
    originals = []
    for source, target, purpose, _ in entries:
        _regular_existing(source)
        if os.path.lexists(target):
            if not force:
                raise LauncherError(f'Bereits verschluesselt: {target} (erneut mit --force verschluesseln).')
            _regular_existing(target)
            old = read_regular(target)
            _validate_recipients(old, purpose, set(keys))
            decrypt_bytes(old, private, purpose)
        plaintext = read_regular(source, max_bytes=MAX_FILE_BYTES)
        if plaintext.startswith(ENCRYPTED_PREFIX):
            raise LauncherError(f'Quelldatei ist bereits verschluesselt: {source}')
        if purpose == 'vault-password' and not plaintext.strip():
            raise LauncherError(f'Leere Vault-Passwortdatei: {source}')
        payloads.append((target, encrypt_bytes_v2_many(plaintext, list(keys.values()), purpose)))
        originals.append((source, plaintext, target, purpose))
    _write_batch(payloads, overwrite=force)
    if delete_source:
        for source, original, target, purpose in originals:
            if decrypt_bytes(read_regular(target), private, purpose) != original:
                raise LauncherError(f'Verifikation fehlgeschlagen; Klartext bleibt erhalten: {source}')
        for source, _, _, _ in originals:
            source.unlink()
    return [target for target, _ in payloads]


def decrypt_list(*, project_root: Path, cfg: LauncherConfig, file_list: list[str],
                 private_key_path: Path, selected: str | None = None,
                 force: bool = False) -> list[Path]:
    private, keys = authorized_private_key(project_root, private_key_path)
    entries = _entries(project_root, cfg, file_list, selected)
    payloads = []
    for source, target, purpose, _ in entries:
        _regular_existing(target)
        if os.path.lexists(source) and not force:
            raise LauncherError(f'Klartextdatei existiert bereits (verwende --force): {source}')
        blob = read_regular(target)
        _validate_recipients(blob, purpose, set(keys))
        payloads.append((source, decrypt_bytes(blob, private, purpose)))
    _write_batch(payloads, overwrite=force)
    return [source for source, _ in payloads]


def sync_recipients(*, project_root: Path, cfg: LauncherConfig, file_list: list[str],
                    private_key_path: Path, selected: str | None = None) -> list[Path]:
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
