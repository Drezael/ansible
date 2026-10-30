"""Entry point: encrypt inventories/master password and launch Ansible."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .config import (
    get_private_key_path, get_project_root, load_config,
    resolve_config_path, write_config,
)
from .errors import LauncherError
from .executor import run_playbook
from .files import decrypt_file, encrypt_file
from .keys import load_rsa_private_key


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ansible-launcher",
        description="RSA-geschützter Ansible-Launcher mit temporären Inventories und Vault-Passwörtern.",
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", help="Pfad zur TOML-Konfiguration (Standard: ~/.config/ansible-launcher/config.toml)")
    common.add_argument("--project-root", help="Ansible-Projektverzeichnis (überschreibt config.toml)")
    common.add_argument("--key", help="RSA-Private-Key-Datei (überschreibt config.toml)")
    subs = parser.add_subparsers(dest="command", required=True)

    init = subs.add_parser("init-config", parents=[common], help="Home-Konfiguration schreiben")
    init.add_argument("--force", action="store_true", help="Vorhandene Konfiguration überschreiben")

    enc_inv = subs.add_parser("encrypt-inventory", parents=[common], help="Inventory mit RSA/AES verschlüsseln")
    enc_inv.add_argument("--source", required=True, help="Unverschlüsselte YAML-Inventory-Datei")
    enc_inv.add_argument("--output", help="Zieldatei (Standard: Quelle + .enc)")
    enc_inv.add_argument("--force", action="store_true")
    enc_inv.add_argument("--delete-source", action="store_true", help="Klartextquelle nach überprüfter Verschlüsselung entfernen")

    enc_master = subs.add_parser("encrypt-master", parents=[common], help="Master-Vault-Passwortdatei verschlüsseln")
    enc_master.add_argument("--source", required=True, help="Vorhandene Datei mit dem Master-Vault-Passwort")
    enc_master.add_argument("--output", help="Zieldatei (Standard: vaults/master-password.enc)")
    enc_master.add_argument("--force", action="store_true")
    enc_master.add_argument("--delete-source", action="store_true", help="Klartextquelle nach überprüfter Verschlüsselung entfernen")

    dec_inv = subs.add_parser("decrypt-inventory", parents=[common], help="Inventory als Klartextdatei exportieren (Vorsicht)")
    dec_inv.add_argument("--source", required=True, help="Verschlüsseltes Inventory")
    dec_inv.add_argument("--output", required=True, help="Unverschlüsselter Ausgabe-Pfad")
    dec_inv.add_argument("--force", action="store_true")

    run = subs.add_parser("run", parents=[common], help="Playbook mit entschlüsseltem Inventory und Master-Passwort starten")
    run.add_argument("playbook", help="Playbookname ohne Endung, z. B. prepare_server")
    run.add_argument("--inventory", required=True, help="Inventoryname, z. B. dev")
    run.add_argument("--hostname", help="Zielhost für -e hostname=...")
    run.add_argument("--extra-var", "-e", action="append", default=[], help="Weiteres Ansible --extra-vars Argument (wiederholbar)")
    run.add_argument("--limit", help="Ansible --limit")
    run.add_argument("--tags", help="Ansible --tags")
    run.add_argument("--skip-tags", help="Ansible --skip-tags")
    run.add_argument("--forks", type=int, help="Ansible --forks")
    run.add_argument("--check", action="store_true", help="Ansible --check")
    run.add_argument("--diff", action="store_true", help="Ansible --diff")
    run.add_argument("-v", "--verbose", action="count", default=0, help="Ansible Verbosity (wiederholbar)")
    run.add_argument("--temp-dir", help="Temporärer Speicherort (standardmäßig /dev/shm)")
    run.add_argument("--allow-disk-temp", action="store_true", help="UNSICHER: Klartext temporär auf einem Datenträger zulassen")
    return parser


def _path(raw: str, project_root: Path) -> Path:
    p = Path(raw).expanduser()
    return (p if p.is_absolute() else project_root / p).resolve()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config_file = resolve_config_path(args.config)
        cfg = load_config(config_file)
        project_root = get_project_root(args.project_root, cfg)
        key_path = get_private_key_path(args.key, cfg)
        if args.command == "init-config":
            # Check the path now; an encrypted key will prompt for passphrase.
            load_rsa_private_key(key_path)
            write_config(config_file, project_root=project_root, key_file=key_path, overwrite=args.force)
            print(f"Konfiguration geschrieben: {config_file}")
            return 0

        key = load_rsa_private_key(key_path)
        if args.command == "encrypt-inventory":
            source = _path(args.source, project_root)
            output = _path(args.output, project_root) if args.output else Path(str(source) + ".enc")
            encrypt_file(source, output, key.public_key(), "inventory", force=args.force,
                         delete_source=args.delete_source, verify_private_key=key)
            print(f"Inventory verschlüsselt: {output}")
            return 0
        if args.command == "encrypt-master":
            source = _path(args.source, project_root)
            output = _path(args.output, project_root) if args.output else cfg.master_path(project_root)
            encrypt_file(source, output, key.public_key(), "vault-password", force=args.force,
                         delete_source=args.delete_source, verify_private_key=key)
            print(f"Master-Passwort verschlüsselt: {output}")
            return 0
        if args.command == "decrypt-inventory":
            from .files import atomic_write
            source = _path(args.source, project_root)
            output = _path(args.output, project_root)
            if source == output:
                raise LauncherError("Quell- und Zieldatei dürfen nicht identisch sein.")
            plaintext = decrypt_file(source, key, "inventory")
            atomic_write(output, plaintext, overwrite=args.force)
            print(f"Klartext-Inventory exportiert (bitte anschließend sicher entfernen): {output}")
            return 0
        if args.command == "run":
            return run_playbook(
                project_root=project_root, cfg=cfg, private_key=key,
                playbook_name=args.playbook, inventory_name=args.inventory,
                hostname=args.hostname, extra_vars=args.extra_var,
                check=args.check, diff=args.diff, limit=args.limit,
                tags=args.tags, skip_tags=args.skip_tags, forks=args.forks,
                verbose=args.verbose, temp_dir=args.temp_dir,
                allow_disk_temp=args.allow_disk_temp,
            )
        raise LauncherError("Unbekannter Befehl.")
    except LauncherError as exc:
        print(f"Fehler: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Abbruch durch Benutzer.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
