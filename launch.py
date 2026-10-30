#!/usr/bin/env python3
"""Central entry point for the Ansible project.

Run from any directory:
    python3 /path/to/ansible/launch.py
    python3 /path/to/ansible/launch.py run prepare_server --inventory dev --hostname test-host

The implementation remains in launcher/src/ansible_launcher. The repository
root is inferred from this file, not the current working directory.
"""

from __future__ import annotations

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent
PACKAGE_SOURCE = PROJECT_ROOT / "launcher" / "src"
COMMANDS = frozenset({
    "init-config", "encrypt-inventory", "encrypt-master",
    "decrypt-inventory", "run",
})


def _ensure_package_path() -> bool:
    if not (PACKAGE_SOURCE / "ansible_launcher" / "cli.py").is_file():
        print(
            f"Fehler: Python-Launcher fehlt unter {PACKAGE_SOURCE}. "
            "Pruefe die Repository-Struktur.",
            file=sys.stderr,
        )
        return False
    if str(PACKAGE_SOURCE) not in sys.path:
        sys.path.insert(0, str(PACKAGE_SOURCE))
    return True


def _with_project_root(arguments: list[str]) -> list[str]:
    """Use the repository containing launch.py unless explicitly overridden."""
    if any(
        arg == "--project-root" or arg.startswith("--project-root=")
        for arg in arguments
    ):
        return list(arguments)
    return [arguments[0], "--project-root", str(PROJECT_ROOT), *arguments[1:]]


def run_command(arguments: list[str]) -> int:
    """Forward a CLI action without duplicating any crypto or Ansible logic."""
    if not arguments or arguments[0] not in COMMANDS:
        print("Fehler: Unbekannter Launcher-Befehl.", file=sys.stderr)
        return 2
    if not _ensure_package_path():
        return 2
    try:
        from ansible_launcher.cli import main as cli_main
    except ModuleNotFoundError as exc:
        print(
            f"Fehlende Python-Abhaengigkeit: {exc.name}. "
            "Installiere sie im Projekt mit "
            "python3 -m pip install -e './launcher'.",
            file=sys.stderr,
        )
        return 2
    return cli_main(_with_project_root(arguments))


def _print_help() -> None:
    print(
        "Ansible Launcher - zentraler Einstiegspunkt\n\n"
        "Verwendung:\n"
        "  python3 launch.py                    Interaktives Menue (Terminal)\n"
        "  python3 launch.py menu               Interaktives Menue starten\n"
        "  python3 launch.py status             Konfiguration und Dateien pruefen\n"
        "  python3 launch.py <befehl> [optionen]\n\n"
        "Befehle:\n"
        "  init-config, encrypt-inventory, encrypt-master,\n"
        "  decrypt-inventory, run\n\n"
        "Beispiele:\n"
        "  python3 launch.py run prepare_server --inventory dev --hostname test-host\n"
        "  python3 launch.py encrypt-inventory --source inventory/dev.yml\n"
        "  python3 launch.py encrypt-master --source ~/vault.pass\n"
        "  python3 launch.py run --help\n\n"
        "Die Projektwurzel wird aus dem Speicherort von launch.py ermittelt.\n"
        "--project-root kann diesen Standard ueberschreiben."
    )


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args in (["--help"], ["-h"]):
        _print_help()
        return 0
    if not _ensure_package_path():
        return 2

    if not args and not sys.stdin.isatty():
        _print_help()
        return 0

    if not args or args in (["menu"], ["--menu"]):
        if not sys.stdin.isatty():
            print("Fehler: Das Menue benoetigt ein interaktives Terminal.", file=sys.stderr)
            return 2
        from ansible_launcher.menu import InteractiveMenu
        return InteractiveMenu(PROJECT_ROOT, run_command).run()

    if args == ["status"]:
        from ansible_launcher.menu import show_status
        return show_status(PROJECT_ROOT)

    if args[0] in COMMANDS:
        return run_command(args)

    _print_help()
    print(f"\nFehler: Unbekannter Befehl: {args[0]}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
