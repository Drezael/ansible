"""Execute a command parsed by the repository-root launch.py.

The worker runs only under launcher/.venv/bin/python. It receives an already
parsed argument dictionary via an inherited anonymous pipe (not argv/env).
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
    "run", "init-config", "encrypt-inventory", "encrypt-master",
    "decrypt-inventory", "menu", "status",
    "keys-init", "keys-add", "keys-list",
    "encrypt-files", "decrypt-files", "sync-recipients",
}


def _load_args() -> argparse.Namespace:
    if len(sys.argv) != 2 or not sys.argv[1].isdigit():
        raise LauncherError("Ungueltiger interner Worker-Aufruf.")
    fd = int(sys.argv[1])
    with os.fdopen(fd, "rb") as stream:
        raw = stream.read(MAX_ARGUMENT_BYTES + 1)
    if len(raw) > MAX_ARGUMENT_BYTES:
        raise LauncherError("Interne Argumentdaten sind zu gross.")
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise LauncherError("Interne Argumentdaten sind ungueltig.") from exc
    if not isinstance(data, dict) or data.get("command") not in SUPPORTED_COMMANDS:
        raise LauncherError("Ungueltiger interner Launcher-Befehl.")
    return argparse.Namespace(**data)


def _interactive(args: argparse.Namespace) -> int:
    from .menu import InteractiveMenu

    project_root = Path(args.project_root).expanduser().resolve()
    entry_point = Path(__file__).resolve().parents[3] / "launch.py"
    if not entry_point.is_file():
        raise LauncherError(f"Zentraler Einstiegspunkt nicht gefunden: {entry_point}")

    def dispatch(parameters: list[str]) -> int:
        cmd = [sys.executable, str(entry_point), *parameters]
        cmd.extend(["--project-root", str(project_root)])
        if args.config:
            cmd.extend(["--config", args.config])
        if args.key and not any(p == "--key" or p.startswith("--key=") for p in parameters):
            cmd.extend(["--key", args.key])
        return subprocess.run(cmd, check=False).returncode

    from .config import load_config, resolve_config_path
    instance = InteractiveMenu(project_root, dispatch, config_path=args.config)
    # The interactive file selector must use precisely the same YAML mappings.
    instance._listed_files = lambda: [item.source for item in load_config(resolve_config_path(args.config)).files]
    instance._playbook_names = lambda: sorted(p.stem for p in (project_root / load_config(resolve_config_path(args.config)).playbooks_dir).glob("*.yml") if p.is_file())
    return instance.run()


class _Termination(Exception):
    """SIGTERM caught outside the Ansible executor's own signal handler."""


def _apply_project_configuration(args: argparse.Namespace) -> None:
    """Apply YAML path configuration to modules that consume project files."""
    from .config import load_config, resolve_config_path
    from . import keyring
    from pathlib import Path
    cfg = load_config(resolve_config_path(args.config))
    keyring.REGISTRY_FILE = Path(cfg.keyring_file)
    keyring.SIGNATURE_FILE = Path(cfg.keyring_signature_file)


def _report_configuration(args: argparse.Namespace) -> None:
    """Report the configuration actually parsed; never print secret values."""
    from .config import load_config, resolve_config_path

    selected = resolve_config_path(args.config)
    if not selected.is_file():
        if args.config:
            raise LauncherError(f"Explizite Konfigurationsdatei nicht gefunden: {selected}")
        print("Launcher-Konfiguration: Keine Home-Konfigurationsdatei gefunden (Standardwerte).", flush=True)
        return

    # Validate before claiming that the file was loaded successfully.
    load_config(selected)
    location = "Home-Konfiguration" if selected.is_relative_to(Path.home().resolve()) else "Konfiguration"
    print(f"Launcher-Konfiguration: {location} geladen: {selected}", flush=True)


def _validate_existing_files_before_keys_init(args: argparse.Namespace) -> None:
    """Preserve the old keys-init verification for explicitly configured target paths."""
    from .config import load_config, resolve_config_path, resolve_project_relative
    from .file_operations import _check_no_symlinks
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
    public = load_rsa_public_key(Path(args.public_key))
    if fingerprint(private.public_key()) != fingerprint(public):
        raise LauncherError('Erster Public Key passt nicht zum Private Key.')
    protected = {root / cfg.keyring_file, root / cfg.keyring_signature_file}
    for item in cfg.files:
        source = resolve_project_relative(root, item.source)
        target = resolve_project_relative(root, item.target)
        if source in protected or target in protected:
            raise LauncherError(f'Geschuetzte Datei in der Konfiguration: {item.source}')
        _check_no_symlinks(source, root)
        _check_no_symlinks(target, root)
        if target.is_file():
            blob = read_regular(target)
            if recipient_fingerprints(blob, item.purpose) not in (None, {fingerprint(public)}):
                raise LauncherError(f'Bestehende Datei enthaelt fremde RSA-Empfaenger: {target}')
            decrypt_bytes(blob, private, item.purpose)


def main() -> int:
    previous_term = signal.getsignal(signal.SIGTERM)

    def terminate(_signum: int, _frame: object) -> None:
        raise _Termination()

    signal.signal(signal.SIGTERM, terminate)
    try:
        args = _load_args()
        _report_configuration(args)
        _apply_project_configuration(args)
        if args.command == "status":
            from .menu import show_status
            return show_status(Path(args.project_root).expanduser().resolve(), config_path=args.config)
        if args.command == "menu":
            return _interactive(args)
        if args.command == 'keys-init':
            _validate_existing_files_before_keys_init(args)
        return execute(args)
    except LauncherError as exc:
        print(f"Fehler: {exc}", file=sys.stderr)
        return 2
    except _Termination:
        return 143
    except KeyboardInterrupt:
        print("Abbruch durch Benutzer.", file=sys.stderr)
        return 130
    finally:
        signal.signal(signal.SIGTERM, previous_term)


if __name__ == "__main__":
    raise SystemExit(main())
