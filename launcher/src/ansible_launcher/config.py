"""Home-level TOML configuration; secrets must never be stored here."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import stat
import tomllib

from .errors import LauncherError

DEFAULT_CONFIG = Path("~/.config/ansible-launcher/config.toml")


@dataclass(frozen=True)
class LauncherConfig:
    project_root: Path | None = None
    key_file: Path | None = None
    inventory_dir: str = "inventory"
    master_password_file: str = "vaults/master-password.enc"

    def inventory_path(self, name: str, project_root: Path) -> Path:
        return resolve_project_relative(project_root, self.inventory_dir) / f"{name}.yml.enc"

    def master_path(self, project_root: Path) -> Path:
        return resolve_project_relative(project_root, self.master_password_file)


def resolve_project_relative(root: Path, configured: str) -> Path:
    path = Path(configured).expanduser()
    return (path if path.is_absolute() else root / path).resolve()


def resolve_config_path(raw: str | None) -> Path:
    return Path(raw).expanduser().resolve() if raw else DEFAULT_CONFIG.expanduser().resolve()


def _parse_string(tbl: dict, field: str, default: str | None = None) -> str | None:
    value = tbl.get(field, default)
    if value is not None and (not isinstance(value, str) or not value.strip()):
        raise LauncherError(f"Ungültiger Konfigurationswert: launcher.{field}")
    return value


def load_config(path: Path) -> LauncherConfig:
    if not path.exists():
        return LauncherConfig()
    try:
        with path.open("rb") as handle:
            cfg = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise LauncherError(f"Konfigurationsdatei kann nicht gelesen werden: {path}") from exc
    tbl = cfg.get("launcher", {})
    if not isinstance(tbl, dict):
        raise LauncherError("Konfiguration muss eine TOML-Tabelle [launcher] enthalten.")
    project = _parse_string(tbl, "project_root")
    key = _parse_string(tbl, "key_file")
    return LauncherConfig(
        project_root=Path(project).expanduser().resolve() if project else None,
        key_file=Path(key).expanduser().resolve() if key else None,
        inventory_dir=_parse_string(tbl, "inventory_dir", "inventory") or "inventory",
        master_password_file=_parse_string(tbl, "master_password_file", "vaults/master-password.enc") or "vaults/master-password.enc",
    )


def find_project_root(start: Path) -> Path:
    for folder in [start.resolve(), *start.resolve().parents]:
        if (folder / "ansible.cfg").is_file() and (folder / "playbooks").is_dir():
            return folder
    raise LauncherError("Ansible-Projekt nicht gefunden. --project-root oder config.toml angeben.")


def get_project_root(argument: str | None, cfg: LauncherConfig) -> Path:
    root = (
        Path(argument).expanduser().resolve() if argument else
        cfg.project_root if cfg.project_root else
        find_project_root(Path.cwd())
    )
    if not (root / "ansible.cfg").is_file() or not (root / "playbooks").is_dir():
        raise LauncherError(f"Kein gültiges Ansible-Projektverzeichnis: {root}")
    return root


def get_private_key_path(argument: str | None, cfg: LauncherConfig) -> Path:
    path = Path(argument).expanduser().resolve() if argument else cfg.key_file
    if path is None:
        raise LauncherError("RSA-Private-Key fehlt: --key PATH oder launcher.key_file in config.toml.")
    return path


def write_config(path: Path, *, project_root: Path, key_file: Path, overwrite: bool = False) -> None:
    if path.exists() and not overwrite:
        raise LauncherError(f"Konfiguration existiert bereits: {path} (verwende --force).")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    content = (
        "# Ansible Launcher; no passwords or private keys are stored here.\n"
        "[launcher]\n"
        f"project_root = {json.dumps(str(project_root))}\n"
        f"key_file = {json.dumps(str(key_file))}\n"
        'inventory_dir = "inventory"\n'
        'master_password_file = "vaults/master-password.enc"\n'
    ).encode("utf-8")
    # Use atomic replacement with an exclusive temporary file, mode 0600.
    from .files import atomic_write
    atomic_write(path, content, overwrite=overwrite)
    if os.name == "posix":
        os.chmod(path.parent, stat.S_IRWXU)
