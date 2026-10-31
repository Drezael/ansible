"""Initial encryption of every file from the launcher text list.

Preflight all entries before writing anything. No overwrites and no automatic
removal of plaintext sources. This step deliberately does NOT add other keys.
"""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import stat
import tempfile

from .config import LauncherConfig, resolve_project_relative
from .crypto import ENCRYPTED_PREFIX, MAX_FILE_BYTES, encrypt_bytes_v2
from .errors import LauncherError
from .files import read_regular
from .keys import load_rsa_public_key


def _check_relative_path(raw: str) -> PurePosixPath:
    if (
        not isinstance(raw, str) or not raw or raw.startswith("/")
        or "\\" in raw or "\x00" in raw
        or any(part in ("", ".", "..") for part in raw.split("/"))
        or raw.endswith(".enc")
    ):
        raise LauncherError(f"Ungueltiger Quelldateipfad in der Liste: {raw!r}.")
    return PurePosixPath(raw)


def _check_no_symlinks(path: Path, root: Path) -> None:
    """Do not follow links inside the repo when encrypting secret files."""
    if not path.is_relative_to(root):
        raise LauncherError(f"Datei liegt ausserhalb des Projekts: {path}")
    current = path
    while current != root:
        if current.is_symlink():
            raise LauncherError(f"Symbolische Links sind nicht erlaubt: {current}")
        current = current.parent


def _preflight(
    project_root: Path,
    config: LauncherConfig,
    file_list: list[str],
) -> list[tuple[Path, Path, str]]:
    """Check ALL encrypted destinations before any source is encrypted."""
    if not isinstance(file_list, list) or not file_list:
        raise LauncherError("Die Verschluesselungsliste ist leer.")

    root = project_root.resolve()
    inventory_dir = resolve_project_relative(root, config.inventory_dir)
    vault_password = config.master_path(root)
    entries: list[tuple[Path, Path, str]] = []
    seen: set[Path] = set()
    existing: list[Path] = []

    # Phase 1: only check whether an encrypted result already exists.
    for raw in file_list:
        relative = _check_relative_path(raw)
        source = root.joinpath(*relative.parts)
        target = source.with_name(source.name + ".enc")
        if source in seen or target in seen:
            raise LauncherError(f"Mehrdeutiger Dateieintrag: {raw}")
        seen.add(source)
        if os.path.lexists(target):
            existing.append(target.relative_to(root))
        purpose = (
            "vault-password" if target == vault_password else
            "inventory" if source.parent == inventory_dir and source.suffix in (".yml", ".yaml") else
            "file"
        )
        entries.append((source, target, purpose))

    if existing:
        names = ", ".join(str(path) for path in existing)
        raise LauncherError(
            "Init abgebrochen: Bereits verschluesselte Zieldatei(en) vorhanden: " + names
        )

    # Phase 2: validate ALL plaintext inputs, without writing files.
    for source, target, purpose in entries:
        _check_no_symlinks(source, root)
        _check_no_symlinks(target, root)
        try:
            info = source.stat()
            if not stat.S_ISREG(info.st_mode):
                raise LauncherError(f"Quelldatei ist keine regulaere Datei: {source}")
            if info.st_size > MAX_FILE_BYTES:
                raise LauncherError(f"Quelldatei zu gross (64 MiB): {source}")
            with source.open("rb") as stream:
                prefix = stream.read(len(ENCRYPTED_PREFIX))
                if prefix == ENCRYPTED_PREFIX:
                    raise LauncherError(f"Quelldatei ist bereits verschluesselt: {source}")
                if purpose == "vault-password" and info.st_size == 0:
                    raise LauncherError(f"Master-Vault-Passwortdatei ist leer: {source}")
        except OSError as exc:
            raise LauncherError(f"Quelldatei kann nicht gelesen werden: {source}: {exc}") from exc
        if not target.parent.is_dir():
            raise LauncherError(f"Zielverzeichnis fehlt: {target.parent}")

    return entries


def initialize_encryption(
    *,
    project_root: Path,
    config: LauncherConfig,
    file_list: list[str],
    public_key_path: Path,
) -> list[Path]:
    """Encrypt all list entries using one RSA public key; never overwrite.

    Stage every result in its destination directory, then publish via hard
    links with no-overwrite semantics. On error, discard temporary results and
    remove the results created by THIS invocation, leaving sources untouched.
    """
    entries = _preflight(project_root, config, file_list)
    public_key = load_rsa_public_key(public_key_path.expanduser().resolve())

    staged: list[tuple[Path, Path]] = []
    published: list[Path] = []
    try:
        for source, target, purpose in entries:
            plaintext = read_regular(source, max_bytes=MAX_FILE_BYTES)
            if plaintext.startswith(ENCRYPTED_PREFIX):
                raise LauncherError(f"Quelldatei ist bereits verschluesselt: {source}")
            if purpose == "vault-password" and not plaintext.strip():
                raise LauncherError(f"Master-Vault-Passwortdatei ist leer: {source}")
            ciphertext = encrypt_bytes_v2(plaintext, public_key, purpose)
            fd, name = tempfile.mkstemp(
                prefix=".ansible-init-", suffix=".tmp", dir=target.parent
            )
            temporary = Path(name)
            staged.append((temporary, target))
            with os.fdopen(fd, "wb") as stream:
                stream.write(ciphertext)
                stream.flush()
                os.fsync(stream.fileno())

        # Phase 3: every file is staged. Publish only if none now exists.
        for temporary, target in staged:
            os.link(temporary, target, follow_symlinks=False)
            published.append(target)
        return published
    except OSError as exc:
        raise LauncherError(f"Initiale Verschluesselung fehlgeschlagen: {exc}") from exc
    finally:
        # Roll back only when not every result was published successfully.
        if len(published) != len(entries):
            for target in published:
                target.unlink(missing_ok=True)
        for temporary, _ in staged:
            temporary.unlink(missing_ok=True)
