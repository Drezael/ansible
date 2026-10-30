#!/usr/bin/env python3
"""Central Ansible launcher: parse arguments with the standard library.

The launcher itself does not import third-party packages. All work executes
with launcher/.venv/bin/python, without activating the virtual environment.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parent
LAUNCHER_DIRECTORY = REPOSITORY_ROOT / "launcher"
VENV_PYTHON = LAUNCHER_DIRECTORY / ".venv" / "bin" / "python"
PACKAGE_DIRECTORY = LAUNCHER_DIRECTORY / "src" / "ansible_launcher"
MAX_ARGUMENT_BYTES = 16 * 1024 * 1024


class _Termination(Exception):
    """Local shutdown requested by SIGTERM."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="launch.py",
        description=(
            "Ansible-Playbooks und verschluesselte Inventories mit dem "
            "virtuellen Python-Environment unter launcher/.venv verwalten."
        ),
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", help="Alternative TOML-Konfiguration im Home-Verzeichnis")
    common.add_argument("--project-root", help="Ansible-Projektverzeichnis (Standard: Verzeichnis von launch.py)")
    common.add_argument("--key", help="RSA-Private-Key (ueberschreibt die Home-Konfiguration)")

    parser.epilog = "Beispiel: python3 launch.py run prepare_server --inventory dev --hostname test-host"
    commands = parser.add_subparsers(dest="command")

    commands.add_parser("menu", parents=[common], help="Interaktive Verwaltung starten")
    commands.add_parser("status", parents=[common], help="Konfiguration und Dateien pruefen")

    config = commands.add_parser("init-config", parents=[common], help="Home-Konfiguration erstellen")
    config.add_argument("--force", action="store_true", help="Vorhandene Konfiguration ersetzen")

    inventory = commands.add_parser("encrypt-inventory", parents=[common], help="Inventory verschluesseln")
    inventory.add_argument("--source", required=True, help="Quelldatei")
    inventory.add_argument("--output", help="Zieldatei (Standard: Quelle + .enc)")
    inventory.add_argument("--force", action="store_true")
    inventory.add_argument("--delete-source", action="store_true")

    master = commands.add_parser("encrypt-master", parents=[common], help="Master-Vault-Passwort verschluesseln")
    master.add_argument("--source", required=True, help="Quelldatei des Master-Passworts")
    master.add_argument("--output", help="Zieldatei (Standard: vaults/master-password.enc)")
    master.add_argument("--force", action="store_true")
    master.add_argument("--delete-source", action="store_true")

    decrypt = commands.add_parser("decrypt-inventory", parents=[common], help="Inventory als Klartext exportieren")
    decrypt.add_argument("--source", required=True, help="Verschluesselte Quelldatei")
    decrypt.add_argument("--output", required=True, help="Klartext-Zieldatei")
    decrypt.add_argument("--force", action="store_true")

    run = commands.add_parser("run", parents=[common], help="Playbook ausfuehren")
    run.add_argument("playbook", help="Playbookname ohne .yml, z. B. prepare_server")
    run.add_argument("--inventory", required=True, help="Verschluesseltes Inventory, z. B. dev")
    run.add_argument("--hostname", help="Zielhost fuer -e hostname=...")
    run.add_argument("-e", "--extra-var", action="append", default=[], help="Weitere Ansible-Variable (mehrfach moeglich)")
    run.add_argument("--limit", help="Ansible --limit")
    run.add_argument("--tags", help="Ansible --tags")
    run.add_argument("--skip-tags", help="Ansible --skip-tags")
    run.add_argument("--forks", type=int, help="Ansible --forks")
    run.add_argument("--check", action="store_true", help="Check-Modus")
    run.add_argument("--diff", action="store_true", help="Unterschiede anzeigen")
    run.add_argument("-v", "--verbose", action="count", default=0, help="Ausfuehrlichere Ansible-Ausgabe")
    run.add_argument("--temp-dir", help="Temporäres Verzeichnis (Standard: tmpfs)")
    run.add_argument("--allow-disk-temp", action="store_true", help="Unsicheren Datentraeger als Zwischenspeicher zulassen")
    return parser


def _venv_ready() -> bool:
    if not VENV_PYTHON.is_file() or not os.access(VENV_PYTHON, os.X_OK):
        print(
            f"Fehler: Python-venv nicht gefunden: {VENV_PYTHON}\n"
            "Bitte zuerst das Setup-Skript im Repository-Root ausfuehren, "
            "um launcher/.venv anzulegen.",
            file=sys.stderr,
        )
        return False
    if not (PACKAGE_DIRECTORY / "worker.py").is_file():
        print(
            f"Fehler: Launcher-Modul fehlt: {PACKAGE_DIRECTORY / 'worker.py'}",
            file=sys.stderr,
        )
        return False
    return True


def _finish_child(process: subprocess.Popen[bytes], sig: int, exit_code: int) -> int:
    """Give the child time to remove its decrypted temporary files."""
    if process.poll() is not None:
        return exit_code
    try:
        process.send_signal(sig)
    except ProcessLookupError:
        return exit_code
    try:
        process.wait(timeout=25)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    return exit_code


def _run_in_venv(arguments: argparse.Namespace) -> int:
    if not _venv_ready():
        return 2
    if arguments.command == "run":
        ansible_playbook = VENV_PYTHON.parent / "ansible-playbook"
        if not ansible_playbook.is_file() or not os.access(ansible_playbook, os.X_OK):
            print(
                f"Fehler: ansible-playbook fehlt im virtuellen Environment: {ansible_playbook}\n"
                "Bitte das Setup-Skript erneut ausfuehren, um die Pakete aus "
                "launcher/requirements.txt zu installieren.",
                file=sys.stderr,
            )
            return 2

    values = vars(arguments).copy()
    values["project_root"] = str(
        Path(values["project_root"]).expanduser().resolve()
        if values.get("project_root") else REPOSITORY_ROOT
    )
    for option in ("key", "config", "temp_dir"):
        if values.get(option):
            values[option] = str(Path(values[option]).expanduser().resolve())

    # The extra-vars may contain secrets. Do not add them to the worker argv,
    # an environment variable or a plaintext file. Pass them through an FD.
    payload = json.dumps(values, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_ARGUMENT_BYTES:
        print("Fehler: Zu viele beziehungsweise zu grosse Argumente.", file=sys.stderr)
        return 2

    env = os.environ.copy()
    env["PATH"] = str(VENV_PYTHON.parent) + os.pathsep + env.get("PATH", "")
    env["VIRTUAL_ENV"] = str(VENV_PYTHON.parent.parent)
    env.pop("PYTHONHOME", None)
    source_path = str(LAUNCHER_DIRECTORY / "src")
    env["PYTHONPATH"] = source_path + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    env["PYTHONUNBUFFERED"] = "1"

    read_fd, write_fd = os.pipe()
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            [str(VENV_PYTHON), "-m", "ansible_launcher.worker", str(read_fd)],
            cwd=REPOSITORY_ROOT,
            env=env,
            pass_fds=(read_fd,),
        )
        os.close(read_fd)
        read_fd = -1
        with os.fdopen(write_fd, "wb") as stream:
            write_fd = -1
            stream.write(payload)
        previous_term = signal.getsignal(signal.SIGTERM)

        def terminate_child(signum: int, _frame: object) -> None:
            raise _Termination()

        signal.signal(signal.SIGTERM, terminate_child)
        try:
            return process.wait()
        except KeyboardInterrupt:
            # For an interactive Ctrl+C, the child has also received SIGINT.
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                return _finish_child(process, signal.SIGINT, 130)
            return 130
        except _Termination:
            return _finish_child(process, signal.SIGTERM, 143)
        finally:
            signal.signal(signal.SIGTERM, previous_term)
    except (OSError, BrokenPipeError) as exc:
        print(f"Fehler beim Starten des Launcher-Prozesses: {exc}", file=sys.stderr)
        if process is not None:
            return _finish_child(process, signal.SIGTERM, 2)
        return 2
    finally:
        if read_fd != -1:
            os.close(read_fd)
        if write_fd != -1:
            os.close(write_fd)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        if not sys.stdin.isatty():
            parser.print_help()
            return 0
        args = parser.parse_args(["menu"])
    if args.command == "menu" and not sys.stdin.isatty():
        parser.error("Das interaktive Menue benoetigt ein Terminal.")
    return _run_in_venv(args)


if __name__ == "__main__":
    raise SystemExit(main())
