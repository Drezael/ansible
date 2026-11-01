
#!/usr/bin/env python3
"""Central Ansible launcher: parse arguments with the standard library.

The launcher itself does not import third-party packages. All work executes
with launcher/.venv/bin/python, without activating the virtual environment.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import textwrap
from pathlib import Path
import signal
import subprocess
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parent
LAUNCHER_DIRECTORY = REPOSITORY_ROOT / "launcher"
VENV_PYTHON = LAUNCHER_DIRECTORY / ".venv" / "bin" / "python"
PACKAGE_DIRECTORY = LAUNCHER_DIRECTORY / "src" / "ansible_launcher"
ENCRYPTION_FILES_PATH = LAUNCHER_DIRECTORY / "encryption-files.txt"
MAX_ARGUMENT_BYTES = 16 * 1024 * 1024
PLAYBOOK_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]+)*$")
METADATA_BEGIN = "# ANSIBLE_LAUNCHER_METADATA_BEGIN"
METADATA_END = "# ANSIBLE_LAUNCHER_METADATA_END"


class _Termination(Exception):
    """Local shutdown requested by SIGTERM."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="launch.py",
        allow_abbrev=False,
        description=(
            "Ansible-Playbooks und verschluesselte Inventories mit dem "
            "virtuellen Python-Environment unter launcher/.venv verwalten."
        ),
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", help="Alternative TOML-Konfiguration im Home-Verzeichnis")
    common.add_argument("--project-root", help="Ansible-Projektverzeichnis (Standard: Verzeichnis von launch.py)")
    common.add_argument("--key", help="RSA-Private-Key (ueberschreibt die Home-Konfiguration)")

    metadata_actions = parser.add_mutually_exclusive_group()
    metadata_actions.add_argument(
        "--playbooks-list",
        action="store_true",
        help="Alle verfuegbaren YAML-Playbooks unter playbooks/ anzeigen (ohne venv)",
    )
    metadata_actions.add_argument(
        "--playbook-details",
        metavar="NAME",
        help="Metadaten eines Playbooks anzeigen, z. B. server.bootstrap (ohne venv)",
    )
    parser.epilog = (
        "Beispiel: python3 launch.py run server.prepare "
        "--inventory dev --hostname test-host"
    )
    commands = parser.add_subparsers(dest="command")

    commands.add_parser("menu", parents=[common], help="Interaktive Verwaltung starten")
    commands.add_parser("status", parents=[common], help="Konfiguration und Dateien pruefen")

    keys_init = commands.add_parser("keys-init", parents=[common], help="Ersten RSA-Key registrieren (keine Verschluesselung)")
    keys_init.add_argument("--public-key", required=True, help="Public Key des ersten Benutzers")

    keys_add = commands.add_parser("keys-add", parents=[common], help="RSA-Public-Key mit einem autorisierten Private Key freigeben")
    keys_add.add_argument("--public-key", required=True, help="Neu zu autorisierender Public Key")

    commands.add_parser("keys-list", parents=[common], help="Signierte RSA-Schluesselliste pruefen und anzeigen")

    for name, label in (
        ("encrypt-files", "Aufgelistete Klartextdateien fuer alle registrierten RSA-Keys verschluesseln"),
        ("decrypt-files", "Aufgelistete Dateien mit autorisiertem RSA-Key entschluesseln"),
        ("sync-recipients", "Empfaenger bereits verschluesselter Dateien aktualisieren"),
    ):
        command = commands.add_parser(name, parents=[common], help=label)
        command.add_argument("--file", help="Optional nur einen Dateipfad aus encryption-files.txt bearbeiten")
        if name != "sync-recipients":
            command.add_argument("--force", action="store_true", help="Vorhandenes Ziel explizit ersetzen")
        if name == "encrypt-files":
            command.add_argument("--delete-source", action="store_true", help="Klartextdateien erst nach Entschluesselungspruefung entfernen")

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
    run.add_argument("playbook", help="Playbookname ohne Dateiendung, z. B. server.prepare")
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


def _load_encryption_file_list() -> list[str]:
    """Load repo-relative file paths, one per line, without touching those files."""
    try:
        if ENCRYPTION_FILES_PATH.stat().st_size > 1024 * 1024:
            raise ValueError("Dateiliste ist groesser als 1 MiB.")
        lines = ENCRYPTION_FILES_PATH.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"Dateiliste konnte nicht geladen werden: {exc}") from exc

    files: list[str] = []
    seen: set[str] = set()
    for line_number, line in enumerate(lines, start=1):
        path = line.strip()
        if not path or path.startswith("#"):
            continue
        if (
            path.startswith("/") or "\\" in path or "\x00" in path
            or any(part in ("", ".", "..") for part in path.split("/"))
        ):
            raise ValueError(f"Zeile {line_number}: Ungueltiger relativer Pfad: {path!r}.")
        if path in seen:
            raise ValueError(f"Zeile {line_number}: Pfad mehrfach vorhanden: {path}.")
        seen.add(path)
        files.append(path)
    return files


def _list_playbooks() -> int:
    """List YAML playbooks without loading secrets, venv or Ansible modules."""
    playbook_dir = REPOSITORY_ROOT / "playbooks"
    if not playbook_dir.is_dir():
        print(f"Fehler: Playbook-Verzeichnis fehlt: {playbook_dir}", file=sys.stderr)
        return 2
    try:
        files = sorted(
            (
                path for path in playbook_dir.iterdir()
                if path.is_file() and path.suffix in (".yml", ".yaml")
            ),
            key=lambda path: (path.name.casefold(), path.name),
        )
    except OSError as exc:
        print(f"Fehler beim Lesen von {playbook_dir}: {exc}", file=sys.stderr)
        return 2
    if not files:
        print("Keine Playbooks im Verzeichnis playbooks/ gefunden.")
        return 0
    print("Verfuegbare Playbooks (playbooks/):")
    for path in files:
        print(f"  {path.stem}")
    return 0


def _playbook_path(name: str) -> Path | None:
    """Resolve an extensionless playbook name without allowing path traversal."""
    if not PLAYBOOK_NAME_RE.fullmatch(name) or name.endswith((".yml", ".yaml")):
        print(
            "Fehler: Ungueltiger Playbookname. Bitte den Namen ohne "
            "Dateiendung und ohne Verzeichnispfad angeben.",
            file=sys.stderr,
        )
        return None

    directory = REPOSITORY_ROOT / "playbooks"
    if not directory.is_dir():
        print(f"Fehler: Playbook-Verzeichnis fehlt: {directory}", file=sys.stderr)
        return None

    matches = [
        path for suffix in (".yml", ".yaml")
        if (path := directory / f"{name}{suffix}").is_file()
        and not path.is_symlink()
    ]
    if not matches:
        print(f"Fehler: Playbook nicht gefunden: {name}", file=sys.stderr)
        return None
    if len(matches) > 1:
        print(
            f"Fehler: Mehrdeutiger Playbookname '{name}': "
            "sowohl .yml als auch .yaml vorhanden.",
            file=sys.stderr,
        )
        return None
    return matches[0]


def _read_playbook_metadata(playbook: Path) -> dict:
    """Read the JSON comment header without parsing or executing Ansible YAML."""
    metadata_lines: list[str] = []
    reading = False
    try:
        with playbook.open("r", encoding="utf-8") as stream:
            for line in stream:
                stripped = line.strip()
                if not reading:
                    if stripped == METADATA_BEGIN:
                        reading = True
                    elif stripped and not stripped.startswith("#"):
                        break  # Metadata must be in the leading comment header.
                    continue

                if stripped == METADATA_END:
                    try:
                        result = json.loads("\n".join(metadata_lines))
                    except json.JSONDecodeError as exc:
                        raise ValueError(f"Ungueltiges JSON in den Metadaten: {exc}") from exc
                    if not isinstance(result, dict):
                        raise ValueError("Die Metadaten muessen ein JSON-Objekt sein.")
                    return result

                if not stripped.startswith("#"):
                    raise ValueError("Metadaten-Header enthaelt eine Zeile ohne Kommentarzeichen (#).")
                metadata_lines.append(stripped[1:].lstrip())
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"Playbook konnte nicht gelesen werden: {exc}") from exc

    if reading:
        raise ValueError(f"Metadaten-Header unvollstaendig: {METADATA_END} fehlt.")
    raise ValueError("Kein Metadaten-Header im Playbook gefunden.")


def _human_value(value: object) -> str:
    """Format optional metadata values for terminal display."""
    if value is True:
        return "Ja"
    if value is False:
        return "Nein"
    if value is None:
        return "Nicht angegeben"
    if isinstance(value, list):
        return ", ".join(_human_value(item) for item in value)
    if isinstance(value, dict):
        return ", ".join(f"{key}: {_human_value(item)}" for key, item in value.items())
    return str(value)


def _print_wrapped(value: object, *, indent: str = "  ") -> None:
    """Wrap descriptions to the available terminal width."""
    width = max(40, min(shutil.get_terminal_size(fallback=(96, 24)).columns, 100))
    content = str(value).strip()
    if not content:
        content = "Keine Beschreibung vorhanden."
    print(textwrap.fill(
        content,
        width=width,
        initial_indent=indent,
        subsequent_indent=indent,
    ))


def _show_playbook_detail(name: str) -> int:
    """Show a readable German description of the playbook metadata."""
    playbook = _playbook_path(name)
    if playbook is None:
        return 2
    try:
        metadata = _read_playbook_metadata(playbook)
    except ValueError as exc:
        print(f"Fehler in playbooks/{playbook.name}: {exc}", file=sys.stderr)
        return 2

    parameters = metadata.get("parameters", [])
    if not isinstance(parameters, list) or any(not isinstance(p, dict) for p in parameters):
        print(
            f"Fehler in playbooks/{playbook.name}: "
            "'parameters' muss eine Liste von JSON-Objekten sein.",
            file=sys.stderr,
        )
        return 2

    title = metadata.get("title") or name
    width = max(40, min(shutil.get_terminal_size(fallback=(96, 24)).columns, 100))
    print()
    print("=" * width)
    _print_wrapped(title, indent="")
    print("=" * width)
    print(f"  Playbook:        {name}")
    print(f"  Datei:           playbooks/{playbook.name}")
    print(f"  Kategorie:       {_human_value(metadata.get('category'))}")
    print(f"  Schema-Version:  {_human_value(metadata.get('schema_version'))}")

    print("\nBeschreibung")
    print("------------")
    _print_wrapped(metadata.get("description") or "Keine Beschreibung vorhanden.")

    print("\nVoraussetzungen")
    print("---------------")
    for label, field in (
        ("Inventory", "inventory_required"),
        ("Master-Vault", "vault_required"),
    ):
        requirement = metadata.get(field)
        if requirement is True:
            value = "Erforderlich"
        elif requirement is False:
            value = "Nicht erforderlich"
        else:
            value = "Nicht angegeben"
        print(f"  {label:<13}: {value}")

    print("\nParameter")
    print("---------")
    if not parameters:
        print("  Keine Parameter definiert.")
    else:
        types = {
            "string": "Text",
            "integer": "Ganzzahl",
            "number": "Zahl",
            "float": "Dezimalzahl",
            "boolean": "Ja/Nein",
            "array": "Liste",
            "object": "Objekt",
        }
        for index, parameter in enumerate(parameters, start=1):
            param_name = _human_value(parameter.get("name"))
            type_name = str(parameter.get("type") or "Nicht angegeben")
            type_label = types.get(type_name.lower(), type_name)
            if parameter.get("required") is True:
                requirement = "Pflicht"
            elif parameter.get("required") is False:
                requirement = "Optional"
            else:
                requirement = "Nicht angegeben"
            print(f"  {index}. {param_name} ({type_label}, {requirement})")
            if parameter.get("description"):
                _print_wrapped(parameter["description"], indent="     ")
            if "default" in parameter:
                print(f"     Standardwert: {_human_value(parameter['default'])}")
            if "choices" in parameter:
                print(f"     Erlaubte Werte: {_human_value(parameter['choices'])}")
            if index < len(parameters):
                print()

    known_fields = {
        "schema_version", "title", "description", "category",
        "inventory_required", "vault_required", "parameters",
    }
    extras = {key: value for key, value in metadata.items() if key not in known_fields}
    if extras:
        print("\nWeitere Metadaten")
        print("-----------------")
        for key, value in extras.items():
            print(f"  {key}: {_human_value(value)}")

    print()
    return 0


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
    try:
        encryption_files = _load_encryption_file_list()
    except ValueError as exc:
        print(f"Fehler in {ENCRYPTION_FILES_PATH}: {exc}", file=sys.stderr)
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
    values["encryption_files"] = encryption_files
    values["project_root"] = str(
        Path(values["project_root"]).expanduser().resolve()
        if values.get("project_root") else REPOSITORY_ROOT
    )
    for option in ("key", "config", "temp_dir", "public_key"):
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
    if args.playbooks_list or args.playbook_details is not None:
        if args.command is not None:
            parser.error("--playbooks-list und --playbook-details sind nicht mit Unterbefehlen kombinierbar.")
        if args.playbooks_list:
            return _list_playbooks()
        return _show_playbook_detail(args.playbook_details)
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
