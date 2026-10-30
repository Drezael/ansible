"""Restrictive per-run ephemeral cleartext workspace, defaulting to tmpfs."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import tempfile

from .errors import LauncherError


def _unescape_mount(value: str) -> str:
    # Linux /proc/self/mountinfo octal escaping for spaces and special chars.
    for sequence, character in (("\\040", " "), ("\\011", "\t"), ("\\012", "\n"), ("\\134", "\\")):
        value = value.replace(sequence, character)
    return value


def filesystem_type(path: Path) -> str | None:
    """Read actual Linux mount type of a path; account for nested mountpoints."""
    candidate = path.resolve()
    matched_length = -1
    matched_fs = None
    try:
        with open("/proc/self/mountinfo", encoding="utf-8") as stream:
            for line in stream:
                left, sep, right = line.rstrip("\n").partition(" - ")
                if not sep:
                    continue
                left_fields = left.split()
                right_fields = right.split()
                if len(left_fields) < 5 or not right_fields:
                    continue
                mount_point = Path(_unescape_mount(left_fields[4]))
                if candidate == mount_point or mount_point in candidate.parents:
                    if len(str(mount_point)) > matched_length:
                        matched_length = len(str(mount_point))
                        matched_fs = right_fields[0]
    except OSError:
        return None
    return matched_fs


def select_temp_base(*, specified: str | None, allow_disk: bool) -> Path:
    candidates = [Path(specified).expanduser()] if specified else [Path("/dev/shm"), Path(os.environ.get("XDG_RUNTIME_DIR", "/nonexistent"))]
    for path in candidates:
        if not path.is_dir() or not os.access(path, os.W_OK | os.X_OK):
            continue
        if filesystem_type(path) == "tmpfs" or allow_disk:
            return path.resolve()
    if allow_disk and not specified:
        return Path(tempfile.gettempdir()).resolve()
    raise LauncherError(
        "Kein beschreibbares tmpfs für Klartextdateien gefunden. "
        "Gib --temp-dir mit tmpfs-Pfad an; unsicherer Datenträger-Fallback nur "
        "mit --allow-disk-temp."
    )


class SecretWorkspace:
    """Context-managed directory with 0700 and secret files with 0600."""

    def __init__(self, *, base_dir: Path):
        self.base_dir = base_dir
        self._directory: tempfile.TemporaryDirectory[str] | None = None
        self.path: Path | None = None

    def __enter__(self) -> "SecretWorkspace":
        self._directory = tempfile.TemporaryDirectory(prefix="ansible-launcher-", dir=self.base_dir)
        self.path = Path(self._directory.name)
        os.chmod(self.path, 0o700)
        return self

    def write_secret(self, filename: str, content: bytes) -> Path:
        if self.path is None:
            raise LauncherError("Temporärer Speicher wurde nicht geöffnet.")
        if not filename or filename != Path(filename).name or filename in (".", ".."):
            raise LauncherError("Ungültiger temporärer Dateiname.")
        path = self.path / filename
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as stream:
                fd = -1
                stream.write(content)
                stream.flush()
        finally:
            if fd != -1:
                os.close(fd)
        return path

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._directory:
            self._directory.cleanup()
        self._directory = None
        self.path = None
