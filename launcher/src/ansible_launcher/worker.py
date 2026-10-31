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
    "decrypt-inventory", "menu", "status", "init-encryption",
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

    return InteractiveMenu(
        project_root,
        dispatch,
        config_path=args.config,
    ).run()


class _Termination(Exception):
    """SIGTERM caught outside the Ansible executor's own signal handler."""


def main() -> int:
    previous_term = signal.getsignal(signal.SIGTERM)

    def terminate(_signum: int, _frame: object) -> None:
        raise _Termination()

    signal.signal(signal.SIGTERM, terminate)
    try:
        args = _load_args()
        if args.command == "status":
            from .menu import show_status
            return show_status(Path(args.project_root).expanduser().resolve(), config_path=args.config)
        if args.command == "menu":
            return _interactive(args)
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
