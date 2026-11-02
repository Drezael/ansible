"""Execute a command parsed by the repository-root launch.py.

The worker receives arguments through an inherited anonymous pipe, not argv/env.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
from pathlib import Path
import subprocess
import sys

from .cli import execute
from .errors import LauncherError

MAX_ARGUMENT_BYTES = 16 * 1024 * 1024
SUPPORTED_COMMANDS = {
    'run', 'init-config', 'encrypt-inventory', 'encrypt-master',
    'decrypt-inventory', 'menu', 'status', 'keys-init', 'keys-add',
    'keys-list', 'encrypt-files', 'decrypt-files', 'sync-recipients',
}


def _load_args() -> argparse.Namespace:
    if len(sys.argv) != 2 or not sys.argv[1].isdigit():
        raise LauncherError('Ungueltiger interner Worker-Aufruf.')
    fd = int(sys.argv[1])
    with os.fdopen(fd, 'rb') as stream:
        raw = stream.read(MAX_ARGUMENT_BYTES + 1)
    if len(raw) > MAX_ARGUMENT_BYTES:
        raise LauncherError('Interne Argumentdaten sind zu gross.')
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise LauncherError('Interne Argumentdaten sind ungueltig.') from exc
    if not isinstance(data, dict) or data.get('command') not in SUPPORTED_COMMANDS:
        raise LauncherError('Ungueltiger interner Launcher-Befehl.')
    return argparse.Namespace(**data)


def _interactive(args: argparse.Namespace) -> int:
    from .menu import InteractiveMenu
    from .file_operations import load_file_list

    project_root = Path(args.project_root).expanduser().resolve()
    entry_point = Path(__file__).resolve().parents[3] / 'launch.py'
    if not entry_point.is_file():
        raise LauncherError(f'Zentraler Einstiegspunkt nicht gefunden: {entry_point}')

    def dispatch(parameters: list[str]) -> int:
        cmd = [sys.executable, str(entry_point), *parameters]
        cmd.extend(['--project-root', str(project_root)])
        if args.config:
            cmd.extend(['--config', args.config])
        if args.key and not any(p == '--key' or p.startswith('--key=') for p in parameters):
            cmd.extend(['--key', args.key])
        return subprocess.run(cmd, check=False).returncode

    instance = InteractiveMenu(project_root, dispatch, config_path=args.config)
    instance._listed_files = lambda: [item.split('->', 1)[0].strip() for item in load_file_list(project_root)]
    return instance.run()


class _Termination(Exception):
    """SIGTERM caught outside the Ansible executor's own signal handler."""


def _report_configuration(args: argparse.Namespace) -> None:
    from .config import load_config, resolve_config_path
    selected = resolve_config_path(args.config)
    if not selected.is_file():
        if args.config:
            raise LauncherError(f'Explizite Konfigurationsdatei nicht gefunden: {selected}')
        print('Launcher-Konfiguration: Keine Home-Konfigurationsdatei gefunden (Standardwerte).', flush=True)
        return
    load_config(selected)
    location = 'Home-Konfiguration' if selected.is_relative_to(Path.home().resolve()) else 'Konfiguration'
    print(f'Launcher-Konfiguration: {location} geladen: {selected}', flush=True)


def _validate_existing_files_before_keys_init(args: argparse.Namespace) -> None:
    """Verify existing ciphertext recipients against first authorized RSA key."""
    from .config import load_config, resolve_config_path
    from .file_operations import _entries
    from .files import read_regular
    from .crypto import recipient_fingerprints, decrypt_bytes
    from .keys import load_rsa_private_key, load_rsa_public_key
    from .keyring import fingerprint
    cfg = load_config(resolve_config_path(args.config))
    root = Path(args.project_root).resolve()
    private_path = Path(args.key).expanduser().resolve() if args.key else cfg.key_file
    if private_path is None:
        raise LauncherError('RSA-Private-Key fehlt.')
    private = load_rsa_private_key(private_path)
    public = load_rsa_public_key(Path(args.public_key).expanduser().resolve())
    if fingerprint(private.public_key()) != fingerprint(public):
        raise LauncherError('Erster Public Key passt nicht zum Private Key.')
    for _, target, purpose, _ in _entries(root, cfg, args.encryption_files, None):
        if target.is_file():
            blob = read_regular(target)
            if recipient_fingerprints(blob, purpose) not in (None, {fingerprint(public)}):
                raise LauncherError(f'Bestehende Datei enthaelt fremde RSA-Empfaenger: {target}')
            decrypt_bytes(blob, private, purpose)


def main() -> int:
    previous_term = signal.getsignal(signal.SIGTERM)

    def terminate(_signum: int, _frame: object) -> None:
        raise _Termination()

    signal.signal(signal.SIGTERM, terminate)
    try:
        args = _load_args()
        _report_configuration(args)
        from .file_operations import load_file_list
        root = Path(args.project_root).expanduser().resolve()
        if args.command in ('keys-init', 'encrypt-files', 'decrypt-files', 'sync-recipients'):
            args.encryption_files = load_file_list(root)
        if args.command == 'status':
            from .menu import show_status
            return show_status(root, config_path=args.config)
        if args.command == 'menu':
            return _interactive(args)
        if args.command == 'keys-init':
            if args.encryption_files:
                _validate_existing_files_before_keys_init(args)
            # The original keyring initializer assumes source+'.enc'. Verification
            # above uses the explicit repo mapping, so do not repeat the old check.
            args.encryption_files = []
        return execute(args)
    except LauncherError as exc:
        print(f'Fehler: {exc}', file=sys.stderr)
        return 2
    except _Termination:
        return 143
    except KeyboardInterrupt:
        print('Abbruch durch Benutzer.', file=sys.stderr)
        return 130
    finally:
        signal.signal(signal.SIGTERM, previous_term)


if __name__ == '__main__':
    raise SystemExit(main())
