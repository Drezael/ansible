"""Signed-key file operations from a repository-owned file list.

No file mappings are stored in the personal YAML. A line is either a source
path (default target: source + '.enc') or 'source -> target'. The latter is
necessary for a custom master-password target such as vault-master.pass.
"""
from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import stat
import tempfile

from .config import LauncherConfig, resolve_project_relative
from .crypto import (ENCRYPTED_PREFIX, MAX_FILE_BYTES, decrypt_bytes,
                     encrypt_bytes_v2_many, recipient_fingerprints, rewrap_v2_recipients)
from .errors import LauncherError
from .files import read_regular
from .keyring import authorized_private_key


PROTECTED_PATHS = (
    'launcher/authorized-keys.enc',
    'launcher/authorized-keys.sig',
    'launcher/encryption-files.txt',
)


def _check_relative_path(raw: str) -> PurePosixPath:
    if (not isinstance(raw, str) or not raw or raw.startswith('/')
            or '\\' in raw or '\x00' in raw or raw.endswith('.enc')
            or any(part in ('', '.', '..') for part in raw.split('/'))):
        raise LauncherError(f'Ungueltiger Quelldateipfad: {raw!r}.')
    return PurePosixPath(raw)


def _check_target(raw: str) -> PurePosixPath:
    if (not isinstance(raw, str) or not raw or raw.startswith('/')
            or '\\' in raw or '\x00' in raw
            or any(part in ('', '.', '..') for part in raw.split('/'))):
        raise LauncherError(f'Ungueltiger Zieldateipfad: {raw!r}.')
    return PurePosixPath(raw)


def load_file_list(root: Path) -> list[str]:
    """Read repository-owned mappings without touching any source plaintext."""
    path = root / 'launcher/encryption-files.txt'
    try:
        if path.stat().st_size > 1024 * 1024:
            raise LauncherError('Die Verschluesselungsliste ist groesser als 1 MiB.')
        lines = path.read_text(encoding='utf-8').splitlines()
    except (OSError, UnicodeError) as exc:
        raise LauncherError(f'Dateiliste konnte nicht gelesen werden: {path}: {exc}') from exc
    result: list[str] = []
    sources: set[str] = set()
    for lineno, line in enumerate(lines, 1):
        value = line.strip()
        if not value or value.startswith('#'):
            continue
        parts = value.split('->')
        if len(parts) not in (1, 2):
            raise LauncherError(f'Ungueltige Dateizuordnung in Zeile {lineno}.')
        source = parts[0].strip()
        _check_relative_path(source)
        if len(parts) == 2:
            _check_target(parts[1].strip())
        if source in sources:
            raise LauncherError(f'Doppelte Quelle in Zeile {lineno}: {source}')
        sources.add(source)
        result.append(value)
    return result


def _check_no_symlinks(path: Path, root: Path) -> None:
    if not path.is_relative_to(root):
        raise LauncherError(f'Datei liegt ausserhalb des Projekts: {path}')
    current = path
    while current != root:
        if current.is_symlink():
            raise LauncherError(f'Symbolische Links sind nicht erlaubt: {current}')
        current = current.parent


def _entries(root: Path, cfg: LauncherConfig, names: list[str], selected: str | None):
    """Resolve list entries against repo root, with explicit master target."""
    if not names:
        raise LauncherError('Die Verschluesselungsliste ist leer.')
    root = root.resolve()
    inventory_dir = resolve_project_relative(root, cfg.inventory_dir)
    master_target = cfg.master_path(root)
    protected = {root / name for name in PROTECTED_PATHS}
    mappings = []
    all_sources: set[str] = set()
    used_paths: set[Path] = set()
    vault_targets = 0
    for line in names:
        pieces = line.split('->')
        if len(pieces) not in (1, 2):
            raise LauncherError(f'Ungueltige Dateizuordnung: {line!r}')
        raw_source = pieces[0].strip()
        rel = _check_relative_path(raw_source)
        raw_target = pieces[1].strip() if len(pieces) == 2 else raw_source + '.enc'
        target_rel = _check_target(raw_target)
        source = root.joinpath(*rel.parts)
        target = root.joinpath(*target_rel.parts)
        if source == target or source in used_paths or target in used_paths:
            raise LauncherError('Doppelter Quell-/Zielpfad oder Quelle gleich Ziel in der Dateiliste.')
        used_paths.update((source, target))
        all_sources.add(raw_source)
        if source in protected or target in protected:
            raise LauncherError(f'Geschuetzte Launcher-Datei in Dateiliste: {line}')
        for path in (source, target):
            _check_no_symlinks(path, root)
            if not path.parent.is_dir():
                raise LauncherError(f'Verzeichnis fuer Datei fehlt: {path.parent}')
        if target == master_target:
            purpose = 'vault-password'
            vault_targets += 1
        elif source.parent == inventory_dir and source.suffix in ('.yml', '.yaml'):
            purpose = 'inventory'
            expected = cfg.inventory_path(source.stem, root)
            if target != expected:
                raise LauncherError(f'Inventory-Ziel muss {expected} sein.')
        else:
            purpose = 'file'
        mappings.append((source, target, purpose, raw_source))
    if vault_targets > 1:
        raise LauncherError('Master-Passwort-Ziel mehrfach in Dateiliste.')
    if selected is not None and selected not in all_sources:
        raise LauncherError(f'Datei steht nicht in encryption-files.txt: {selected}')
    return [item for item in mappings if selected is None or item[3] == selected]


def _regular_existing(path: Path) -> None:
    try:
        if not stat.S_ISREG(path.stat().st_mode):
            raise LauncherError(f'Keine regulaere Datei: {path}')
    except OSError as exc:
        raise LauncherError(f'Datei fehlt oder ist nicht lesbar: {path}: {exc}') from exc


def _write_batch(contents: list[tuple[Path, bytes]], *, overwrite: bool = False) -> None:
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
