"""User configuration for the Ansible launcher.

Relative inventory and master-password paths are ALWAYS relative to the
repository root, independent of the shell working directory and config path.
Only file paths belong in the config; never store private keys or passwords.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import stat
import tomllib

from .errors import LauncherError

HOME_YAML = Path("~/.ansible-launcher.yml")
HOME_YAML_ALT = Path("~/.ansible-launcher.yaml")
LEGACY_TOML = Path("~/.config/ansible-launcher/config.toml")
# Keep the old symbol for existing imports.
DEFAULT_CONFIG = HOME_YAML
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


@dataclass(frozen=True)
class LauncherConfig:
    project_root: Path | None = None
    key_file: Path | None = None
    inventory_dir: str = "inventory"
    master_password_file: str = "vault-master.pass"

    def inventory_path(self, name: str, project_root: Path) -> Path:
        return resolve_project_relative(project_root, self.inventory_dir) / f"{name}.yml.enc"

    def master_path(self, project_root: Path) -> Path:
        return resolve_project_relative(project_root, self.master_password_file)


def resolve_project_relative(root: Path, configured: str) -> Path:
    """Resolve relative paths against root, never cwd or the YAML directory."""
    path = Path(configured).expanduser()
    return (path if path.is_absolute() else root.resolve() / path).resolve()


def resolve_config_path(raw: str | None) -> Path:
    if raw:
        return Path(raw).expanduser().resolve()
    for candidate in (HOME_YAML, HOME_YAML_ALT, LEGACY_TOML):
        path = candidate.expanduser().resolve()
        if path.is_file():
            return path
    return HOME_YAML.expanduser().resolve()


def _parse_string(tbl: dict, field: str, default: str | None = None) -> str | None:
    value = tbl.get(field, default)
    if value is not None and (not isinstance(value, str) or not value.strip()):
        raise LauncherError(f"Ungueltiger Konfigurationswert: {field}")
    return value


def _read_yaml(path: Path) -> dict:
    try:
        import yaml
    except ImportError as exc:
        raise LauncherError("PyYAML fehlt im Launcher-Environment.") from exc
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise LauncherError(f"YAML-Konfiguration konnte nicht gelesen werden: {path}: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise LauncherError("YAML-Konfiguration muss ein Mapping enthalten.")
    if "launcher" in data:
        raise LauncherError("Die YAML-Konfiguration darf keine uebergeordnete launcher-Ebene enthalten.")
    return data


def load_config(path: Path) -> LauncherConfig:
    if not path.exists():
        return LauncherConfig()
    if path.suffix.lower() in (".yml", ".yaml"):
        tbl = _read_yaml(path)
    elif path.suffix.lower() == ".toml":
        try:
            with path.open("rb") as handle:
                data = tomllib.load(handle)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise LauncherError(f"TOML-Konfiguration konnte nicht gelesen werden: {path}") from exc
        tbl = data.get("launcher", {})
        if not isinstance(tbl, dict):
            raise LauncherError("TOML-Konfiguration benoetigt [launcher].")
    else:
        raise LauncherError("Konfiguration muss .yml, .yaml oder .toml sein.")
    key = _parse_string(tbl, "key_file")
    return LauncherConfig(
        key_file=Path(key).expanduser().resolve() if key else None,
        inventory_dir=_parse_string(tbl, "inventory_dir", "inventory") or "inventory",
        master_password_file=_parse_string(tbl, "master_password_file", "vault-master.pass") or "vault-master.pass",
    )


def find_project_root(start: Path) -> Path:
    """The checked-out repository, not the invocation directory, is authoritative."""
    root = REPOSITORY_ROOT
    if (root / "ansible.cfg").is_file() and (root / "playbooks").is_dir():
        return root
    raise LauncherError(f"Ansible-Projekt nicht gefunden: {root}")


def get_project_root(argument: str | None, cfg: LauncherConfig) -> Path:
    root = Path(argument).expanduser().resolve() if argument else find_project_root(Path.cwd())
    if not (root / "ansible.cfg").is_file() or not (root / "playbooks").is_dir():
        raise LauncherError(f"Kein gueltiges Ansible-Projektverzeichnis: {root}")
    return root


def get_private_key_path(argument: str | None, cfg: LauncherConfig) -> Path:
    path = Path(argument).expanduser().resolve() if argument else cfg.key_file
    if path is None:
        raise LauncherError("RSA-Private-Key fehlt: --key PATH oder key_file in ~/.ansible-launcher.yml.")
    return path


def write_config(path: Path, *, project_root: Path, key_file: Path, overwrite: bool = False) -> None:
    if path.exists() and not overwrite:
        raise LauncherError(f"Konfiguration existiert bereits: {path} (verwende --force).")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.suffix.lower() == ".toml":
        # Legacy explicitly requested TOML files remain writable.
        content = (
            "# Ansible Launcher (no secrets)\n[launcher]\n"
            f"key_file = {json.dumps(str(key_file))}\n"
            'inventory_dir = "inventory"\n'
            'master_password_file = "vault-master.pass"\n'
        ).encode("utf-8")
    elif path.suffix.lower() in (".yml", ".yaml"):
        # json.dumps produces valid quoted YAML scalars without relying on a dumper.
        content = (
            "# Ansible Launcher: relative paths are relative to the repository root.\n"
            f"key_file: {json.dumps(str(key_file))}\n"
            "inventory_dir: inventory\n"
            "master_password_file: vault-master.pass\n"
        ).encode("utf-8")
    else:
        raise LauncherError("Konfiguration muss .yml, .yaml oder .toml sein.")
    from .files import atomic_write
    atomic_write(path, content, overwrite=overwrite)
    if os.name == "posix":
        os.chmod(path.parent, stat.S_IRWXU)
