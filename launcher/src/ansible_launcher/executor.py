
"""Ansible execution with temporary plaintext files and propagated env for nested plays."""

from __future__ import annotations

import os
from pathlib import Path
import re
import signal
import subprocess
import threading

from .config import LauncherConfig
from .errors import LauncherError
from .files import decrypt_file
from .temporary import SecretWorkspace, select_temp_base

NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]*$")
PLAYBOOK_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]+)*$")


class _SignalStop(Exception):
    def __init__(self, signum: int):
        self.signum = signum


def _end_child(process: subprocess.Popen, initial_signal: int) -> None:
    """Stop the process group (including nested ansible-playbook processes)."""
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, initial_signal)
        else:
            process.send_signal(initial_signal)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=8)
        return
    except subprocess.TimeoutExpired:
        pass
    if process.poll() is None:
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGTERM)
            else:
                process.terminate()
        except ProcessLookupError:
            return
    try:
        process.wait(timeout=4)
    except subprocess.TimeoutExpired:
        if process.poll() is None:
            try:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except ProcessLookupError:
                pass
            process.wait()


def _execute(argv: list[str], root: Path, env: dict[str, str]) -> int:
    try:
        process = subprocess.Popen(argv, cwd=root, env=env, start_new_session=(os.name == "posix"))
    except FileNotFoundError as exc:
        raise LauncherError("ansible-playbook nicht gefunden. Ansible muss im PATH verfügbar sein.") from exc
    previous_term = None
    handler_active = threading.current_thread() is threading.main_thread()

    def on_terminate(signum, frame):
        raise _SignalStop(signum)

    try:
        if handler_active:
            previous_term = signal.signal(signal.SIGTERM, on_terminate)
        try:
            return process.wait()
        except KeyboardInterrupt:
            _end_child(process, signal.SIGINT)
            return 130
        except _SignalStop as exc:
            _end_child(process, exc.signum)
            return 128 + exc.signum
    finally:
        if process.poll() is None:
            _end_child(process, signal.SIGTERM)
        if handler_active and previous_term is not None:
            signal.signal(signal.SIGTERM, previous_term)


def run_playbook(
    *, project_root: Path, cfg: LauncherConfig, private_key,
    playbook_name: str, inventory_name: str, hostname: str | None,
    extra_vars: list[str], check: bool, diff: bool,
    limit: str | None, tags: str | None, skip_tags: str | None,
    forks: int | None, verbose: int,
    temp_dir: str | None, allow_disk_temp: bool,
) -> int:
    if not PLAYBOOK_NAME_RE.fullmatch(playbook_name):
        raise LauncherError("Playbookname ungültig (nur Dateiname ohne .yml).")
    if not NAME_RE.fullmatch(inventory_name):
        raise LauncherError("Inventoryname ungültig (z. B. dev).")
    playbooks_dir = project_root / "playbooks"
    candidates = [playbooks_dir / f"{playbook_name}{suffix}" for suffix in (".yml", ".yaml")]
    matches = [candidate for candidate in candidates if candidate.is_file()]
    if not matches:
        raise LauncherError(f"Playbook nicht gefunden: {playbook_name} (.yml/.yaml)")
    if len(matches) > 1:
        raise LauncherError(f"Mehrdeutiger Playbookname: {playbook_name} (.yml und .yaml vorhanden)")
    playbook = matches[0]
    inventory_encrypted = cfg.inventory_path(inventory_name, project_root)
    if not inventory_encrypted.is_file():
        raise LauncherError(f"Verschlüsseltes Inventory nicht gefunden: {inventory_encrypted}")
    master_encrypted = cfg.master_path(project_root)
    if not master_encrypted.is_file():
        raise LauncherError(f"Verschlüsseltes Master-Passwort nicht gefunden: {master_encrypted}")
    if hostname is not None and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", hostname):
        raise LauncherError("Hostname ist ungültig.")
    if hostname is not None and any(re.match(r"^hostname\s*=", value) for value in extra_vars):
        raise LauncherError("Hostname nicht zugleich mit --hostname und --extra-var hostname=... setzen.")
    if forks is not None and forks <= 0:
        raise LauncherError("--forks muss größer als null sein.")

    inventory = decrypt_file(inventory_encrypted, private_key, "inventory")
    master_password = decrypt_file(master_encrypted, private_key, "vault-password")
    if not inventory.strip():
        raise LauncherError("Entschlüsseltes Inventory ist leer.")
    if not master_password.strip():
        raise LauncherError("Entschlüsseltes Master-Vault-Passwort ist leer.")

    temp_base = select_temp_base(specified=temp_dir, allow_disk=allow_disk_temp)
    with SecretWorkspace(base_dir=temp_base) as workspace:
        inventory_file = workspace.write_secret(f"{inventory_name}.yml", inventory)
        password_file = workspace.write_secret("master.pass", master_password)
        env = os.environ.copy()
        env.pop("ANSIBLE_VAULT_PASSWORD_FILE", None)
        env["ANSIBLE_CONFIG"] = str((project_root / "ansible.cfg").resolve())
        env["ANSIBLE_INVENTORY"] = str(inventory_file)
        env["ANSIBLE_VAULT_IDENTITY_LIST"] = f"master@{password_file}"
        env["ANSIBLE_VAULT_ID_MATCH"] = "True"

        # -i is explicit for the main process; inherited ANSIBLE_INVENTORY and
        # ANSIBLE_VAULT_IDENTITY_LIST support nested ansible-playbook calls.
        argv = ["ansible-playbook", "-i", str(inventory_file), str(playbook)]
        if hostname is not None:
            argv.extend(["--extra-vars", f"hostname={hostname}"])
        for extra in extra_vars:
            if not extra:
                raise LauncherError("Leerer Wert für --extra-var ist nicht erlaubt.")
            argv.extend(["--extra-vars", extra])
        if check:
            argv.append("--check")
        if diff:
            argv.append("--diff")
        if limit:
            argv.extend(["--limit", limit])
        if tags:
            argv.extend(["--tags", tags])
        if skip_tags:
            argv.extend(["--skip-tags", skip_tags])
        if forks is not None:
            argv.extend(["--forks", str(forks)])
        if verbose:
            argv.append("-" + "v" * verbose)
        print(f"Starte {playbook.name} mit Inventory {inventory_name} ...", flush=True)
        return _execute(argv, project_root, env)
