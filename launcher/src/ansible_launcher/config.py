"""YAML configuration for Ansible launcher; all relative paths use repository root."""
from __future__ import annotations
from dataclasses import dataclass
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tomllib
from .errors import LauncherError

HOME_YAML = Path('~/.ansible-launcher.yml')
HOME_YAML_ALT = Path('~/.ansible-launcher.yaml')
LEGACY_TOML = Path('~/.config/ansible-launcher/config.toml')
DEFAULT_CONFIG = HOME_YAML
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]

@dataclass(frozen=True)
class FileSpec:
    source: str
    target: str
    purpose: str

@dataclass(frozen=True)
class LauncherConfig:
    project_root: Path | None = None
    key_file: Path | None = None
    inventory_dir: str = 'inventory'
    master_password_file: str = 'vault-master.pass'
    files: tuple[FileSpec, ...] = ()
    keyring_file: str = 'launcher/authorized-keys.enc'
    keyring_signature_file: str = 'launcher/authorized-keys.sig'
    playbooks_dir: str = 'playbooks'
    ansible_config_file: str = 'ansible.cfg'
    encryption_files_list: str | None = None

    def inventory_path(self, name: str, project_root: Path) -> Path:
        return resolve_project_relative(project_root, self.inventory_dir) / f'{name}.yml.enc'

    def master_path(self, project_root: Path) -> Path:
        return resolve_project_relative(project_root, self.master_password_file)


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


def _parse_files(tbl: dict, inventory_dir: str, master: str) -> tuple[FileSpec, ...]:
    raw = tbl.get('files', [])
    if not isinstance(raw, list):
        raise LauncherError('files muss eine YAML-Liste sein.')
    parsed = []
    sources, targets = set(), set()
    master_targets = 0
    for i, item in enumerate(raw, 1):
        if not isinstance(item, dict) or set(item) != {'source', 'target', 'purpose'}:
            raise LauncherError(f'files[{i}] benoetigt source, target und purpose.')
        source = _relative(item['source'], f'files[{i}].source')
        target = _relative(item['target'], f'files[{i}].target')
        purpose = item['purpose']
        if not isinstance(purpose, str) or purpose not in ('inventory', 'vault-password', 'file'):
            raise LauncherError(f'files[{i}].purpose muss inventory, vault-password oder file sein.')
        if source == target or source in sources or target in targets:
            raise LauncherError('Doppelte Quelldatei/Zieldatei oder Quelle gleich Ziel in files.')
        sources.add(source)
        targets.add(target)
        if purpose == 'vault-password':
            master_targets += 1
            if resolve_project_relative(REPOSITORY_ROOT, target) != resolve_project_relative(REPOSITORY_ROOT, master):
                raise LauncherError('Das Ziel mit purpose vault-password muss master_password_file entsprechen.')
        if purpose == 'inventory' and not target.endswith('.yml.enc'):
            raise LauncherError('Inventory-Ziele muessen auf .yml.enc enden.')
        parsed.append(FileSpec(source, target, purpose))
    if master_targets > 1:
        raise LauncherError('Nur eine vault-password-Datei ist erlaubt.')
    if sources & targets:
        raise LauncherError('Ein Dateipfad darf nicht zugleich Quelle und Ziel sein.')
    return tuple(parsed)


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
    key = _string(tbl, 'key_file')
    inventory = _string(tbl, 'inventory_dir', 'inventory') or 'inventory'
    master = _string(tbl, 'master_password_file', 'vault-master.pass') or 'vault-master.pass'
    _relative(inventory, 'inventory_dir')
    _relative(master, 'master_password_file')
    for field in ('keyring_file', 'keyring_signature_file', 'playbooks_dir', 'ansible_config_file'):
        _relative(_string(tbl, field, getattr(LauncherConfig(), field)), field)
    return LauncherConfig(
        keyring_file=_string(tbl, 'keyring_file', 'launcher/authorized-keys.enc'),
        keyring_signature_file=_string(tbl, 'keyring_signature_file', 'launcher/authorized-keys.sig'),
        playbooks_dir=_string(tbl, 'playbooks_dir', 'playbooks'),
        ansible_config_file=_string(tbl, 'ansible_config_file', 'ansible.cfg'),
        key_file=Path(key).expanduser().resolve() if key else None,
        inventory_dir=inventory, master_password_file=master,
        files=_parse_files(tbl, inventory, master),
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
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.suffix.lower() not in ('.yaml', '.yml'):
        raise LauncherError('Neue Konfigurationen werden ausschliesslich als YAML erstellt.')
    content = ('# Relative Pfade beziehen sich auf das Repository-Root.\n'
               f'key_file: {json.dumps(str(key_file))}\n'
               'inventory_dir: inventory\n'
               'master_password_file: vault-master.pass\n'
               'keyring_file: launcher/authorized-keys.enc\n'
               'keyring_signature_file: launcher/authorized-keys.sig\n'
               'playbooks_dir: playbooks\n'
               'ansible_config_file: ansible.cfg\n'
               'files: []\n').encode('utf-8')
    from .files import atomic_write
    atomic_write(path, content, overwrite=overwrite)
    if os.name == 'posix':
        os.chmod(path.parent, stat.S_IRWXU)
