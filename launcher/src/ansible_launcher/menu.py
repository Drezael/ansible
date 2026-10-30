"""Interactive management UI for the repository-root launch.py command.

The menu only builds CLI arguments. Encryption, decryption and subprocess
management stay in cli.py/executor.py and are never reimplemented here.
"""

from __future__ import annotations

from pathlib import Path
import re
from typing import Callable

from .config import LauncherConfig, load_config, resolve_config_path, resolve_project_relative
from .errors import LauncherError

NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")


def show_status(
    root: Path, *, config_path: str | None = None, output: Callable[[str], None] = print
) -> int:
    """Show nonsecret readiness information; never read key or vault contents."""
    config_file = resolve_config_path(config_path)
    try:
        cfg = load_config(config_file)
    except LauncherError as exc:
        output(f"Konfiguration fehlerhaft: {exc}")
        return 2

    inventory_dir = resolve_project_relative(root, cfg.inventory_dir)
    inventories = sorted(
        p.name.removesuffix(".yml.enc")
        for p in inventory_dir.glob("*.yml.enc")
        if NAME_RE.fullmatch(p.name.removesuffix(".yml.enc"))
    )
    plaintext = sorted(p.name for p in inventory_dir.glob("*.yml"))
    master_file = cfg.master_path(root)
    key_file = cfg.key_file
    output("\nAnsible Launcher - Status")
    output(f"Projekt:               {root}")
    output(f"Konfiguration:          {config_file} ({'vorhanden' if config_file.is_file() else 'fehlt'})")
    output(f"RSA-Schluessel:        {key_file or 'nicht konfiguriert'}")
    output(f"RSA-Schluesseldatei:   {'vorhanden' if key_file and key_file.is_file() else 'fehlt'}")
    output(f"Inventory-Verzeichnis: {inventory_dir}")
    output(f"Verschluesselt:        {', '.join(inventories) or 'keine Inventories'}")
    output(f"Klartext-Inventories:  {', '.join(plaintext) or 'keine'}")
    output(f"Master-Passwort:       {master_file} ({'verschluesselt vorhanden' if master_file.is_file() else 'fehlt'})")
    if plaintext:
        output("ACHTUNG: Klartext-Inventories sollten nach der Migration nicht in Git liegen.")
    return 0


class InteractiveMenu:
    """Small terminal controller; all operations delegate to the existing CLI."""

    def __init__(
        self,
        root: Path,
        dispatch: Callable[[list[str]], int],
        *,
        input_fn: Callable[[str], str] = input,
        output: Callable[[str], None] = print,
        config_path: str | None = None,
    ) -> None:
        self.root = root
        self.dispatch = dispatch
        self.input = input_fn
        self.output = output
        self.session_key: str | None = None
        self.config_path = config_path

    def _ask(self, label: str, *, default: str = "") -> str:
        hint = f" [{default}]" if default else ""
        text = self.input(f"{label}{hint}: ").strip()
        return text if text else default

    def _yes(self, message: str) -> bool:
        return self._ask(f"{message} [j/N]").casefold() in ("j", "ja", "y", "yes")

    def _config(self) -> LauncherConfig:
        return load_config(resolve_config_path(self.config_path))

    def _inventory_dir(self) -> Path:
        return resolve_project_relative(self.root, self._config().inventory_dir)

    def _key_arguments(self) -> list[str]:
        return ["--key", self.session_key] if self.session_key else []

    def _call(self, argv: list[str]) -> int:
        args = [argv[0], *self._key_arguments(), *argv[1:]]
        result = self.dispatch(args)
        self.output(f"Rueckgabecode: {result}")
        return result

    def _choose(self, label: str, options: list[str]) -> str | None:
        if not options:
            self.output(f"Keine Eintraege vorhanden: {label}")
            return None
        self.output(f"\n{label}:")
        for index, option in enumerate(options, start=1):
            self.output(f"  {index}. {option}")
        value = self._ask("Nummer (leer = Abbruch)")
        if not value:
            return None
        if not value.isdecimal() or not (1 <= int(value) <= len(options)):
            self.output("Ungueltige Auswahl.")
            return None
        return options[int(value) - 1]

    def _playbook(self) -> None:
        names = sorted(
            p.stem for p in (self.root / "playbooks").glob("*.yml")
            if NAME_RE.fullmatch(p.stem)
        )
        playbook = self._choose("Playbooks", names)
        if playbook is None:
            return
        inventories = sorted(
            p.name.removesuffix(".yml.enc")
            for p in self._inventory_dir().glob("*.yml.enc")
            if NAME_RE.fullmatch(p.name.removesuffix(".yml.enc"))
        )
        inventory = self._choose("Verschluesselte Inventories", inventories)
        if inventory is None:
            return

        hostname = self._ask("Hostname (leer = kein hostname-Parameter)")
        args = ["run", playbook, "--inventory", inventory]
        if hostname:
            args.extend(["--hostname", hostname])
        self.output("Zusatzvariablen niemals fuer Klartext-Passwoerter verwenden.")
        while True:
            variable = self._ask("Extra-Variable KEY=VALUE (leer = fertig)")
            if not variable:
                break
            if "=" not in variable or variable.startswith("="):
                self.output("Erwartet wird KEY=VALUE.")
                continue
            args.extend(["--extra-var", variable])

        if self._yes("Check-Modus (keine Aenderungen)"):
            args.append("--check")
        if self._yes("Diff anzeigen"):
            args.append("--diff")
        if self._yes("Erweiterte Optionen setzen"):
            for prompt, flag in (
                ("Limit (leer = kein Limit)", "--limit"),
                ("Tags (leer = alle)", "--tags"),
                ("Tags auslassen (leer = keine)", "--skip-tags"),
                ("Forks (leer = Ansible-Standard)", "--forks"),
            ):
                value = self._ask(prompt)
                if value:
                    args.extend([flag, value])
            verbosity = self._ask("Verbosity 0-4", default="0")
            if verbosity.isdecimal() and 0 <= int(verbosity) <= 4:
                args.extend(["-v"] * int(verbosity))
            else:
                self.output("Ungueltige Verbosity; Standard wird verwendet.")

        self.output(f"\nPlaybook: {playbook}, Inventory: {inventory}, Hostname: {hostname or '-'}")
        if not self._yes("Playbook jetzt starten"):
            self.output("Start abgebrochen.")
            return
        self._call(args)

    def _encrypt_inventory(self) -> None:
        directory = self._inventory_dir()
        sources = sorted(p.name for p in directory.glob("*.yml"))
        chosen = self._choose("Klartext-Inventories", sources)
        if chosen is None:
            return
        source = directory / chosen
        target = Path(str(source) + ".enc")
        args = ["encrypt-inventory", "--source", str(source), "--output", str(target)]
        if target.exists():
            if not self._yes("Verschluesselte Zieldatei existiert. Ueberschreiben"):
                return
            args.append("--force")
        if self._yes("Klartextquelle NACH erfolgreicher Verifikation entfernen"):
            args.append("--delete-source")
        self._call(args)

    def _encrypt_master(self) -> None:
        source = self._ask("Master-Passwort-Quelldatei", default="~/vault.pass")
        target = self._config().master_path(self.root)
        args = ["encrypt-master", "--source", source]
        if target.exists():
            if not self._yes("Verschluesseltes Master-Passwort existiert. Ueberschreiben"):
                return
            args.append("--force")
        if self._yes("Klartextquelle NACH erfolgreicher Verifikation entfernen"):
            args.append("--delete-source")
        self._call(args)

    def _decrypt_inventory(self) -> None:
        directory = self._inventory_dir()
        names = sorted(
            p.name.removesuffix(".yml.enc")
            for p in directory.glob("*.yml.enc")
            if NAME_RE.fullmatch(p.name.removesuffix(".yml.enc"))
        )
        chosen = self._choose("Verschluesselte Inventories", names)
        if chosen is None:
            return
        source = directory / f"{chosen}.yml.enc"
        output_file = directory / f"{chosen}.yml"
        self.output("ACHTUNG: Der Export erzeugt eine dauerhafte Klartextdatei.")
        if self._ask("Zum Fortfahren EXPORT eingeben") != "EXPORT":
            self.output("Export abgebrochen.")
            return
        args = ["decrypt-inventory", "--source", str(source), "--output", str(output_file)]
        if output_file.exists():
            if not self._yes("Bestehende Klartextdatei ueberschreiben"):
                return
            args.append("--force")
        self._call(args)

    def _init_config(self) -> None:
        path = resolve_config_path(self.config_path)
        current_key = self.session_key
        if current_key is None:
            try:
                current_key = str(self._config().key_file or "")
            except LauncherError:
                pass
        key = self._ask("Pfad zum RSA-Private-Key", default=current_key or "")
        if not key:
            self.output("Ein RSA-Private-Key ist erforderlich.")
            return
        args = ["init-config", "--key", key]
        if path.exists():
            if not self._yes("Bestehende Home-Konfiguration ueberschreiben"):
                return
            args.append("--force")
        self._call(args)

    def _session_key(self) -> None:
        key = self._ask("RSA-Private-Key fuer diese Sitzung (leer = Konfiguration verwenden)")
        if not key:
            self.session_key = None
            self.output("Sitzungsschluessel zurueckgesetzt.")
            return
        path = Path(key).expanduser().resolve()
        if not path.is_file():
            self.output("Datei nicht gefunden. Schluessel wurde nicht geaendert.")
            return
        self.session_key = str(path)
        self.output(f"Sitzungsschluessel gesetzt: {path}")

    def run(self) -> int:
        self.output(f"Ansible Launcher | Projekt {self.root}")
        commands = {
            "1": self._playbook,
            "2": self._encrypt_inventory,
            "3": self._encrypt_master,
            "4": self._decrypt_inventory,
            "5": self._init_config,
            "6": lambda: show_status(self.root, config_path=self.config_path, output=self.output),
            "7": self._session_key,
        }
        try:
            while True:
                self.output(
                    "\n1 Playbook starten\n"
                    "2 Inventory verschluesseln\n"
                    "3 Master-Vault-Passwort verschluesseln\n"
                    "4 Inventory als Klartext exportieren\n"
                    "5 Home-Konfiguration einrichten\n"
                    "6 Status anzeigen\n"
                    "7 RSA-Key fuer diese Sitzung waehlen\n"
                    "0 Beenden"
                )
                choice = self._ask("Auswahl")
                if choice == "0":
                    return 0
                command = commands.get(choice)
                if command is None:
                    self.output("Ungueltige Auswahl.")
                    continue
                try:
                    command()
                except LauncherError as exc:
                    self.output(f"Fehler: {exc}")
        except (EOFError, KeyboardInterrupt):
            self.output("\nMenue beendet.")
            return 130
