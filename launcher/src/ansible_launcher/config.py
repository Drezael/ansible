"""Personal launcher configuration: only key and inventory/master paths.

Project internals, signed key registry and file selection are not user settings.
Project-relative paths are resolved from the checked-out repository root.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import stat
import tomllib

from .errors import LauncherError

HOME_YAML = Path('~/.ansible-launcher.yml')
HOME_YAML_ALT = Path('~/.ansible-launcher.yaml')
LEGACY_TOML = Path('~/.config/ansible-launcher/config.toml')
DEFAULT_CONFIG = HOME_YAML
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
ALLOWED_FIELDS = frozenset({'key_file', 'inventory_dir', 'master_password_file'})


@dataclass(frozen=True)
class LauncherConfig:
    key_file: Path | None = None
    inventory_dir: str = 'inventory'
    master_password_file: str = 'vault-master.pass'

    def inventory_path(self, name: str, project_root: Path) -> Path:
        return resolve_project_relative(project_root, self.inventory_dir) / f'{name}.yml.enc'

    def master_path(self, project_root: Path) -> Path:
        """Return the encrypted master-password file, relative to the repo root.

        The user setting names the master-password file (plaintext base name).
        File operations append '.enc' to the source by default. Reuse that
        convention here so encrypt, decrypt, status and playbook execution
        resolve exactly the same ciphertext. Do not append twice when the user
        explicitly configures a name already ending in '.enc'.
        """
        configured = self.master_password_file
        encrypted = configured if configured.endswith('.enc') else configured + '.enc'
        return resolve_project_relative(project_root, encrypted)


def resolve_project_relative(root: Path, configured: str) -> Path:
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


def _string(tbl: dict, key: str, default: str | None = None) -> str | None:
    value = tbl.get(key, default)
    if value is not None and (not isinstance(value, str) or not value.strip()):
        raise LauncherError(f'Ungueltiger Konfigurationswert: {key}')
    return value


def _relative(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or value.startswith('/') or '\\' in value or '\x00' in value:
        raise LauncherError(f'{field} muss ein relativer Pfad zum Repository-Root sein.')
    if any(part in ('', '.', '..') for part in value.split('/')):
        raise LauncherError(f'Ungueltiger Projektpfad: {field}: {value!r}')
    return value


def load_config(path: Path) -> LauncherConfig:
    if not path.exists():
        return LauncherConfig()
    if path.suffix.lower() in ('.yml', '.yaml'):
        try:
            import yaml
        except ImportError as exc:
            raise LauncherError('PyYAML fehlt im Launcher-Environment.') from exc
        try:
            with path.open('r', encoding='utf-8') as handle:
                tbl = yaml.safe_load(handle)
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            raise LauncherError(f'YAML-Konfiguration konnte nicht gelesen werden: {path}: {exc}') from exc
        if tbl is None:
            tbl = {}
        if not isinstance(tbl, dict) or 'launcher' in tbl:
            raise LauncherError('YAML-Konfiguration muss ein Mapping ohne launcher-Ebene sein.')
    elif path.suffix.lower() == '.toml':
        try:
            with path.open('rb') as handle:
                data = tomllib.load(handle)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise LauncherError(f'TOML-Konfiguration nicht lesbar: {path}') from exc
        tbl = data.get('launcher', {})
        if not isinstance(tbl, dict):
            raise LauncherError('TOML-Konfiguration benoetigt [launcher].')
    else:
        raise LauncherError('Konfiguration muss .yml, .yaml oder .toml sein.')
    unknown = set(tbl) - ALLOWED_FIELDS
    if unknown:
        raise LauncherError(f'Nicht unterstuetzte Benutzerkonfiguration: {", ".join(sorted(map(str, unknown)))}')
    key = _string(tbl, 'key_file')
    inventory = _string(tbl, 'inventory_dir', 'inventory') or 'inventory'
    master = _string(tbl, 'master_password_file', 'vault-master.pass') or 'vault-master.pass'
    _relative(inventory, 'inventory_dir')
    _relative(master, 'master_password_file')
    return LauncherConfig(
        key_file=Path(key).expanduser().resolve() if key else None,
        inventory_dir=inventory,
        master_password_file=master,
    )


def find_project_root(start: Path) -> Path:
    root = REPOSITORY_ROOT
    if (root / 'ansible.cfg').is_file() and (root / 'playbooks').is_dir():
        return root
    raise LauncherError(f'Ansible-Projekt nicht gefunden: {root}')


def get_project_root(argument: str | None, cfg: LauncherConfig) -> Path:
    root = Path(argument).expanduser().resolve() if argument else find_project_root(Path.cwd())
    if not (root / 'ansible.cfg').is_file() or not (root / 'playbooks').is_dir():
        raise LauncherError(f'Kein gueltiges Ansible-Projektverzeichnis: {root}')
    return root


def get_private_key_path(argument: str | None, cfg: LauncherConfig) -> Path:
    path = Path(argument).expanduser().resolve() if argument else cfg.key_file
    if path is None:
        raise LauncherError('RSA-Private-Key fehlt: --key PATH oder key_file in ~/.ansible-launcher.yml.')
    return path


def write_config(path: Path, *, project_root: Path, key_file: Path, overwrite: bool = False) -> None:
    if path.exists() and not overwrite:
        raise LauncherError(f'Konfiguration existiert bereits: {path} (verwende --force).')
    if path.suffix.lower() not in ('.yaml', '.yml'):
        raise LauncherError('Neue Konfigurationen werden ausschliesslich als YAML erstellt.')
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    content = (
        f'key_file: {json.dumps(str(key_file))}\n'
        'inventory_dir: inventory\n'
        'master_password_file: vault-master.pass\n'
    ).encode('utf-8')
    from .files import atomic_write
    atomic_write(path, content, overwrite=overwrite)
    if os.name == 'posix':
        os.chmod(path.parent, stat.S_IRWXU)
