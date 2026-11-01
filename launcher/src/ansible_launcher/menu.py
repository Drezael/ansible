"""Central interactive controller for the Ansible launcher.

All security-sensitive operations delegate to the established CLI.  The menu
never implements cryptography or invokes Ansible directly.
"""
from __future__ import annotations

from pathlib import Path
import re
import subprocess
import sys
from typing import Callable

from .config import LauncherConfig, load_config, resolve_config_path, resolve_project_relative
from .errors import LauncherError

NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")
PLAYBOOK_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]+)*$")


def show_status(root: Path, *, config_path: str | None = None,
                output: Callable[[str], None] = print) -> int:
    """Report readiness without exposing any secrets."""
    config_file = resolve_config_path(config_path)
    try:
        cfg = load_config(config_file)
        from .keyring import registry_exists
        registry = registry_exists(root)
    except LauncherError as exc:
        output(f"Konfiguration fehlerhaft: {exc}")
        return 2
    inventory_dir = resolve_project_relative(root, cfg.inventory_dir)
    inventories = sorted(p.name.removesuffix(".yml.enc") for p in inventory_dir.glob("*.yml.enc")
                         if NAME_RE.fullmatch(p.name.removesuffix(".yml.enc")))
    plaintext = sorted(p.name for p in inventory_dir.glob("*.yml"))
    master_file = cfg.master_path(root)
    key_file = cfg.key_file
    output("\nAnsible Launcher - Status")
    output(f"Projekt:               {root}")
    output(f"Konfiguration:          {config_file} ({'vorhanden' if config_file.is_file() else 'fehlt'})")
    output(f"RSA-Schluessel:        {key_file or 'nicht konfiguriert'}")
    output(f"RSA-Schluesseldatei:   {'vorhanden' if key_file and key_file.is_file() else 'fehlt'}")
    output(f"RSA-Key-Registrierung: {'aktiv' if registry else 'nicht initialisiert'}")
    output(f"Inventory-Verzeichnis: {inventory_dir}")
    output(f"Verschluesselt:        {', '.join(inventories) or 'keine Inventories'}")
    output(f"Klartext-Inventories:  {', '.join(plaintext) or 'keine'}")
    output(f"Master-Passwort:       {master_file} ({'verschluesselt vorhanden' if master_file.is_file() else 'fehlt'})")
    if plaintext:
        output("ACHTUNG: Klartext-Inventories sollten nach der Migration nicht in Git liegen.")
    return 0


class InteractiveMenu:
    """Interactive CLI menu; dispatch all actions through launch.py."""

    def __init__(self, root: Path, dispatch: Callable[[list[str]], int], *,
                 input_fn: Callable[[str], str] = input,
                 output: Callable[[str], None] = print,
                 config_path: str | None = None) -> None:
        self.root = root
        self.dispatch = dispatch
        self.input = input_fn
        self.output = output
        self.session_key: str | None = None
        self.config_path = config_path

    def _ask(self, label: str, *, default: str = "") -> str:
        hint = f" [{default}]" if default else ""
        value = self.input(f"{label}{hint}: ").strip()
        return value if value else default

    def _yes(self, prompt: str) -> bool:
        return self._ask(f"{prompt} [j/N]").casefold() in ("j", "ja", "y", "yes")

    def _config(self) -> LauncherConfig:
        return load_config(resolve_config_path(self.config_path))

    def _inventory_dir(self) -> Path:
        return resolve_project_relative(self.root, self._config().inventory_dir)

    def _call(self, argv: list[str]) -> int:
        args = [argv[0], *(["--key", self.session_key] if self.session_key else []), *argv[1:]]
        result = self.dispatch(args)
        self.output(f"Rueckgabecode: {result}")
        return result

    def _choose(self, title: str, options: list[str]) -> str | None:
        if not options:
            self.output(f"Keine Eintraege vorhanden: {title}")
            return None
        self.output(f"\n{title}:")
        for index, entry in enumerate(options, 1):
            self.output(f"  {index}. {entry}")
        answer = self._ask("Nummer (leer = Abbruch)")
        if not answer:
            return None
        if not answer.isdecimal() or not 1 <= int(answer) <= len(options):
            self.output("Ungueltige Auswahl.")
            return None
        return options[int(answer) - 1]

    def _playbook_names(self) -> list[str]:
        directory = self.root / "playbooks"
        return sorted({p.stem for p in directory.glob("*") if p.is_file()
                       and p.suffix in (".yml", ".yaml")
                       and PLAYBOOK_NAME_RE.fullmatch(p.stem)})

    def _playbook(self) -> None:
        playbook = self._choose("Playbooks", self._playbook_names())
        if playbook is None:
            return
        inventories = sorted(p.name.removesuffix(".yml.enc")
                             for p in self._inventory_dir().glob("*.yml.enc")
                             if NAME_RE.fullmatch(p.name.removesuffix(".yml.enc")))
        inventory = self._choose("Verschluesselte Inventories", inventories)
        if inventory is None:
            return
        hostname = self._ask("Hostname (leer = kein hostname-Parameter)")
        args = ["run", playbook, "--inventory", inventory]
        if hostname:
            args += ["--hostname", hostname]
        self.output("Keine Klartext-Passwoerter als Extra-Variablen eingeben.")
        while True:
            variable = self._ask("Extra-Variable KEY=VALUE (leer = fertig)")
            if not variable:
                break
            if "=" not in variable or variable.startswith("="):
                self.output("Erwartet wird KEY=VALUE.")
                continue
            args += ["--extra-var", variable]
        if self._yes("Check-Modus (keine Aenderungen)"):
            args.append("--check")
        if self._yes("Diff anzeigen"):
            args.append("--diff")
        if self._yes("Erweiterte Ansible-Optionen setzen"):
            for prompt, flag in (("Limit", "--limit"), ("Tags", "--tags"),
                                 ("Tags auslassen", "--skip-tags"),
                                 ("Forks", "--forks")):
                value = self._ask(f"{prompt} (leer = Standard)")
                if value:
                    if flag == "--forks" and (not value.isdecimal() or int(value) < 1):
                        self.output("Forks muss eine positive Ganzzahl sein.")
                        return
                    args += [flag, value]
            verbosity = self._ask("Verbosity 0-4", default="0")
            if not verbosity.isdecimal() or int(verbosity) > 4:
                self.output("Ungueltige Verbosity.")
                return
            args += ["-v"] * int(verbosity)
        if self._yes("Temp-Optionen konfigurieren"):
            temp_dir = self._ask("Temp-Verzeichnis (leer = RAM-Standard)")
            if temp_dir:
                args += ["--temp-dir", temp_dir]
            if self._yes("UNSICHER: Klartext temporaer auf Datentraeger erlauben"):
                args.append("--allow-disk-temp")
        self.output(f"\nPlaybook: {playbook}, Inventory: {inventory}, Hostname: {hostname or '-'}")
        if self._yes("Playbook jetzt starten"):
            self._call(args)

    def _registry_enabled(self) -> bool:
        from .keyring import registry_exists
        return registry_exists(self.root)

    def _key_admin(self) -> None:
        while True:
            self.output("\nRSA-Schluesselverwaltung\n1 Ersten RSA-Key registrieren\n2 Weiteren RSA-Key autorisieren\n3 Autorisierte Keys anzeigen\n0 Zurueck")
            choice = self._ask("Auswahl")
            if choice == "0":
                return
            if choice == "3":
                self._call(["keys-list"])
            elif choice in ("1", "2"):
                if choice == "1" and self._registry_enabled():
                    self.output("Schluesselregistrierung bereits vorhanden.")
                    continue
                if choice == "2" and not self._registry_enabled():
                    self.output("Zuerst den ersten Key mit keys-init registrieren.")
                    continue
                raw = self._ask("Public-Key-Datei (z.B. public_keys/user.pub)")
                if not raw:
                    continue
                key = Path(raw).expanduser()
                if not key.is_absolute():
                    key = self.root / key
                if not key.is_file():
                    self.output("Public-Key-Datei fehlt.")
                    continue
                self.output("Fingerprint vor Freigabe ueber vertrauenswuerdigen Kanal vergleichen.")
                if self._yes("Schluessel verbindlich registrieren"):
                    self._call(["keys-init" if choice == "1" else "keys-add", "--public-key", str(key)])
            else:
                self.output("Ungueltige Auswahl.")

    def _listed_files(self) -> list[str]:
        path = self.root / "launcher/encryption-files.txt"
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as exc:
            raise LauncherError(f"Verschluesselungsliste nicht lesbar: {exc}") from exc
        return [s for line in lines if (s := line.strip()) and not s.startswith("#")]

    def _file_admin(self) -> None:
        while True:
            self.output("\nDateiverschluesselung\n1 Dateien verschluesseln\n2 Dateien entschluesseln\n3 Empfaenger synchronisieren\n4 Legacy: Inventory verschluesseln\n5 Legacy: Master-Passwort verschluesseln\n6 Legacy: Inventory exportieren\n0 Zurueck")
            choice = self._ask("Auswahl")
            if choice == "0":
                return
            if choice in ("4", "5", "6"):
                if self._registry_enabled():
                    self.output("Legacy-Operationen sind bei aktiver Key-Registrierung gesperrt.")
                    continue
                {"4": self._encrypt_inventory, "5": self._encrypt_master,
                 "6": self._decrypt_inventory}[choice]()
                continue
            action = {"1": "encrypt-files", "2": "decrypt-files",
                      "3": "sync-recipients"}.get(choice)
            if not action:
                self.output("Ungueltige Auswahl.")
                continue
            names = self._listed_files()
            if not names:
                self.output("Verschluesselungsliste ist leer.")
                continue
            selected = "" if self._yes("Alle Dateien bearbeiten") else self._choose("Datei", names)
            if selected is None:
                continue
            args = [action]
            if selected:
                args += ["--file", selected]
            if action != "sync-recipients":
                if self._yes("Existierende Zieldateien mit --force ersetzen"):
                    args.append("--force")
                if action == "encrypt-files" and self._yes("Klartextquellen nach Verifikation entfernen"):
                    args.append("--delete-source")
            if action == "decrypt-files":
                self.output("WARNUNG: Dies erzeugt dauerhafte Klartextdateien.")
                if self._ask("Zur Bestaetigung EXPORT eingeben") != "EXPORT":
                    continue
            if self._yes("Operation ausfuehren"):
                self._call(args)

    def _encrypt_inventory(self) -> None:
        directory = self._inventory_dir()
        chosen = self._choose("Klartext-Inventories", sorted(p.name for p in directory.glob("*.yml")))
        if chosen is None:
            return
        source = directory / chosen
        target = Path(str(source) + ".enc")
        args = ["encrypt-inventory", "--source", str(source), "--output", str(target)]
        if target.exists():
            if not self._yes("Zieldatei ueberschreiben"):
                return
            args.append("--force")
        if self._yes("Klartext nach erfolgreicher Verifikation entfernen"):
            args.append("--delete-source")
        self._call(args)

    def _encrypt_master(self) -> None:
        source = self._ask("Master-Passwort-Quelldatei", default="~/vault.pass")
        args = ["encrypt-master", "--source", source]
        if self._config().master_path(self.root).exists():
            if not self._yes("Verschluesseltes Master-Passwort ueberschreiben"):
                return
            args.append("--force")
        if self._yes("Klartext nach Verifikation entfernen"):
            args.append("--delete-source")
        self._call(args)

    def _decrypt_inventory(self) -> None:
        directory = self._inventory_dir()
        names = sorted(p.name.removesuffix(".yml.enc") for p in directory.glob("*.yml.enc")
                       if NAME_RE.fullmatch(p.name.removesuffix(".yml.enc")))
        chosen = self._choose("Verschluesselte Inventories", names)
        if chosen is None:
            return
        self.output("WARNUNG: Dies erzeugt eine Klartextdatei.")
        if self._ask("Zum Fortfahren EXPORT eingeben") != "EXPORT":
            return
        target = directory / f"{chosen}.yml"
        args = ["decrypt-inventory", "--source", str(directory / f"{chosen}.yml.enc"),
                "--output", str(target)]
        if target.exists():
            if not self._yes("Existierende Klartextdatei ueberschreiben"):
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
        key = self._ask("RSA-Private-Key", default=current_key or "")
        if not key:
            self.output("RSA-Key ist erforderlich.")
            return
        args = ["init-config", "--key", key]
        if path.exists():
            if not self._yes("Home-Konfiguration ueberschreiben"):
                return
            args.append("--force")
        self._call(args)

    def _session_key(self) -> None:
        key = self._ask("RSA-Private-Key fuer Sitzung (leer = Konfiguration)")
        if not key:
            self.session_key = None
            self.output("Sitzungsschluessel zurueckgesetzt.")
            return
        path = Path(key).expanduser().resolve()
        if not path.is_file():
            self.output("Schluesseldatei nicht gefunden.")
            return
        self.session_key = str(path)
        self.output(f"Sitzungsschluessel gesetzt: {path}")

    def _playbook_information(self) -> None:
        name = self._choose("Playbook-Details", self._playbook_names())
        if name:
            process = subprocess.run([sys.executable, str(self.root / "launch.py"),
                                      "--playbook-details", name], check=False)
            self.output(f"Rueckgabecode: {process.returncode}")

    def run(self) -> int:
        self.output(f"Ansible Launcher | Projekt {self.root}")
        actions = {
            "1": self._playbook, "2": self._key_admin, "3": self._file_admin,
            "4": self._init_config,
            "5": lambda: show_status(self.root, config_path=self.config_path, output=self.output),
            "6": self._session_key, "7": self._playbook_information,
        }
        try:
            while True:
                self.output("\n1 Playbook starten\n2 RSA-Schluesselverwaltung\n3 Dateiverschluesselung\n4 Home-Konfiguration einrichten\n5 Status anzeigen\n6 RSA-Key fuer Sitzung waehlen\n7 Playbook-Details anzeigen\n0 Beenden")
                choice = self._ask("Auswahl")
                if choice == "0":
                    return 0
                action = actions.get(choice)
                if action is None:
                    self.output("Ungueltige Auswahl.")
                    continue
                try:
                    action()
                except LauncherError as exc:
                    self.output(f"Fehler: {exc}")
        except (EOFError, KeyboardInterrupt):
            self.output("\nMenue beendet.")
            return 130
