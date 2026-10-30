# Ansible Launcher (Version 0.1.0)

Python-CLI zum Starten von `ansible-playbook` mit RSA/AES-verschlüsselten
Inventories und einem RSA/AES-verschlüsselten Master-Vault-Passwort.
Die vorhandenen Ansible-Vault-Dateien (`vaults/master.vault` usw.) und die
Playbooks bleiben unverändert.

## Voraussetzungen

- Linux mit Python 3.12+ und `ansible-playbook` im `PATH`
- Python-Pakete `cryptography` und `bcrypt` (über `pip install -e .`)
- Privater RSA-Schlüssel im OpenSSH- oder PEM-Format, **mindestens 3072 Bit**,
  empfohlen 4096 Bit; Dateirechte `0600`/`0400`.
- Für die standardmäßig verpflichtende RAM-Zwischenablage ein beschreibbares
  tmpfs (üblicherweise `/dev/shm`).

**Wichtig:** Ed25519/ECDSA-Schlüssel können nicht als RSA-Entschlüsselungsschlüssel
verwendet werden. Ein SSH-Agent stellt die benötigte RSA-OAEP-Entschlüsselung
normalerweise nicht bereit. Das Tool lädt den privaten RSA-Schlüssel aus der Datei.

## Installation

Archiv entpacken, im entpackten Projekt:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
ansible-launcher --help
```

Ohne Installation (mit installierter Dependency und `PYTHONPATH=src`):

```bash
PYTHONPATH=src python -m ansible_launcher --help
```

## Einrichten

Der vorhandene SSH-RSA-Private-Key kann verwendet werden, wenn er den
Voraussetzungen entspricht. Bei einem passphrasegeschützten Key wird die
Passphrase interaktiv (ohne Echo) abgefragt.

Beispiel-Konfiguration erstellen:

```bash
ansible-launcher init-config \
  --project-root /home/USER/ansible \
  --key /home/USER/.ssh/id_rsa
```

Dies erzeugt `~/.config/ansible-launcher/config.toml` (0600) mit folgenden Feldern:

```toml
[launcher]
project_root = "/home/USER/ansible"
key_file = "/home/USER/.ssh/id_rsa"
inventory_dir = "inventory"
master_password_file = "vaults/master-password.enc"
```

**Niemals Passwörter oder private Schlüssel in die TOML-Konfiguration schreiben.**
Alle Befehle akzeptieren außerdem `--key PFAD`, `--project-root PFAD` und
`--config PFAD`; CLI-Angaben überschreiben die Konfiguration.

## Bestehende Inventories verschlüsseln

Beispiel (aus beliebigem Arbeitsverzeichnis, wenn config.toml existiert):

```bash
ansible-launcher encrypt-inventory --source inventory/dev.yml
```

Erzeugt `inventory/dev.yml.enc`. Die Quelldatei bleibt zunächst unverändert.
Nach einer erfolgreichen Prüfung kann man die Klartextquelle beim erneuten
Verschlüsseln explizit entfernen:

```bash
ansible-launcher encrypt-inventory --source inventory/dev.yml --force --delete-source
```

`--delete-source` prüft das gespeicherte Chiffrat durch vollständige
Entschlüsselung, bevor die Quelle entfernt wird. **Löschen ist keine sichere
Datenträgerbereinigung.** Zuvor veröffentlichte Git-Commits bleiben erhalten.
Keinesfalls die unverschlüsselte Datei weiter in Git versionieren.

## Master-Vault-Passwort verschlüsseln

Die bestehende Master-Vault-Passwortdatei bleibt zunächst Quelle für die Migration.
Sie wird **nicht** in ein Ansible-Vault-Format umgewandelt, sondern unter RSA/AES
als `vaults/master-password.enc` gespeichert:

```bash
ansible-launcher encrypt-master --source ~/vault.pass
```

Passe den Quellpfad an die bisher verwendete Datei an. Die vorhandene
`vaults/master.vault` wird nicht verändert. Bei bereits vorhandenem Chiffrat:
`--force`. Nur nach Überprüfung: optional `--delete-source`.

Hinweis: In der vorhandenen `ansible.cfg` zeigt `vault_identity_list`
auf `~/vault.pass`. Bei Launcher-Ausführung wird diese Einstellung über
`ANSIBLE_VAULT_IDENTITY_LIST` mit dem temporären Dateipfad überschrieben.
Außerhalb des Launchers benötigen bisherige manuelle Ansible-Aufrufe weiterhin
eine geeignete Vault-Identität.

## Playbook ausführen

```bash
ansible-launcher run prepare_server --inventory dev --hostname test-host
ansible-launcher run bootstrap_server --inventory dev --hostname test-host
ansible-launcher run prepare_server --inventory dev --hostname test-host --check --diff
ansible-launcher run prepare_server --inventory dev --hostname test-host -vv --tags install
ansible-launcher run prepare_server --inventory dev --hostname test-host -e debug=true --limit test-host
```

Mit anderem RSA-Key:

```bash
ansible-launcher run prepare_server --inventory dev --hostname test-host \
  --key ~/.ssh/id_rsa
```

Für beliebige Playbooks werden zusätzliche Variablen via `-e`/`--extra-var`
weitergegeben; `--hostname` erzeugt `-e hostname=...`. Die CLI unterstützt
`--limit`, `--tags`, `--skip-tags`, `--forks`, `--check`, `--diff`, `-v` bis `-vvvv`.
Playbooks werden ausschließlich aus `playbooks/<name>.yml` geladen.

### Ablauf

1. RSA-Private-Key öffnen (ggf. Passphrase abfragen)
2. `inventory/dev.yml.enc` und `vaults/master-password.enc` entschlüsseln
3. Beide Dateien mit `0600` in einem `0700`-Verzeichnis auf einem tmpfs schreiben
4. `ansible-playbook -i <temporäres Inventory> ...` ohne `shell=True` starten
5. `ANSIBLE_INVENTORY`, `ANSIBLE_VAULT_IDENTITY_LIST`, `ANSIBLE_CONFIG` und
   `ANSIBLE_VAULT_ID_MATCH` an den Prozess vererben, auch für untergeordnete
   `ansible-playbook`-Aufrufe aus `bootstrap_server.yml`
6. Live-Ausgabe und den Exit-Code des Playbooks übernehmen
7. Prozessgruppe vollständig beenden und temporäre Dateien entfernen

Die Klartextdateien werden standardmäßig **nicht** auf einem regulären
Datenträger angelegt. Nur in ausdrücklich akzeptierten Ausnahmefällen kann
`--allow-disk-temp` zusammen mit `--temp-dir PFAD` verwendet werden.

## Ver- und Entschlüsselung

- Daten: AES-256-GCM mit frischem 32-Byte-Schlüssel und 96-Bit-Nonce pro Datei
- AES-Schlüssel: RSA-OAEP mit SHA-256 und MGF1-SHA-256
- Dateiformat: `ANSIBLE-LAUNCHER-ENC`, Version 1, Zweckkennung (Inventory/Vault),
  RSA-Schlüssellänge, Nonce, verschlüsselter AES-Schlüssel, Chiffrat und GCM-Tag
- Der Datei-Header ist als GCM-AAD gegen Manipulation geschützt.
- Integrität wird beim Entschlüsseln geprüft; falsche Keys und veränderte
  Chiffrate werden abgewiesen.
- Maximum der Klartextdateigröße: 64 MiB.

Das Format ist eigens für dieses Tool definiert und nicht mit Ansible Vault,
OpenSSL `enc` oder anderen Dateiformaten kompatibel. Die unveränderten
`*.vault`-Dateien entschlüsselt weiterhin Ansible mit dem temporären Master-
Vault-Passwort.

## Inventories bearbeiten

Ein Inventory lässt sich explizit entschlüsseln:

```bash
ansible-launcher decrypt-inventory \
  --source inventory/dev.yml.enc \
  --output inventory/dev.yml
```

**Achtung:** Das schreibt absichtlich einen persistenten Klartext. Bearbeiten,
`encrypt-inventory --force` aufrufen und das Klartextoriginal entfernen.
Eine verschlüsselte In-place-Editierfunktion ohne persistente Klartextdatei
ist für eine spätere Version vorgesehen. Editor-Swapfiles und temporäre
Backups können Klartext auf reguläre Datenträger schreiben.

## Sicherheit und Einschränkungen

- RAM-Zwischenspeicher und Dateirechte reduzieren das Risiko, garantieren aber
  keine vollständige Vertraulichkeit gegen Root, Speicherabbilder, Swap oder
  kompromittierte Prozesse.
- Bei regulärem Ende, Fehler, `Ctrl+C` und `SIGTERM` wird bereinigt.
  Nach `SIGKILL`, Absturz oder Stromausfall ist Cleanup nicht garantiert,
  wobei tmpfs beim Neustart geleert wird.
- Zusätzliche `-e`-Variablen werden als normale Prozessargumente übertragen.
  **Keine geheimen Passwörter als Klartext in `-e` verwenden** (Prozessliste/Logs).
- Die externe Ansible-Ausführung benötigt ihr installiertes `ansible-core`,
  eine funktionierende SSH-Verbindung und die bekannten Vault-Geheimnisse.
- Die bestehenden Playbooks behalten ihre Funktion; der Launcher ersetzt
  **nicht** die Ansible-Vault-Encryption deiner weiteren Secret-Dateien.
- Vor Umstellung aller Aufrufe sicherstellen, dass auch eigenständige Aufrufe
  der Playbooks (außerhalb des Launchers) berücksichtigt sind.

## Tests

```bash
python -m pip install -e '.[test]'
pytest -q
```

Die Tests prüfen Kryptografie, Dateiformat, RSA-Passphrase und Dateirechte,
Konfiguration, Dateischutz, Runner-Parameter, Prozessumgebung, Exit-Codes
und Cleanup mit einem lokalen Ansible-Test-Dummy. Auf realen Ansible-Zielhosts
wird nichts geändert.

## Übernahme in das bestehende GitHub-Repository

Der ZIP-Ordner `ansible_launcher_v1` kann als Unterverzeichnis des bestehenden
Repositories `ansible/` abgelegt werden. Dann einmalig installieren:

```bash
cd /pfad/zu/ansible/ansible_launcher_v1
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

`project_root` in der Home-Konfiguration zeigt weiterhin auf das **äußere**
Ansible-Repository, nicht auf `ansible_launcher_v1`.

Die `.gitignore` im Launcher-Unterordner schützt nur diesen Unterordner.
Zusätzlich im `.gitignore` des **äußeren** Ansible-Repositories die untenstehenden
Zeilen ergänzen, sobald die Inventories migriert werden:

```gitignore
/inventory/*.yml
/inventory/*.yaml
/vault.pass
```

Das Entfernen bereits versionierter Dateien aus der Git-Historie muss gesondert
geplant werden; `.gitignore` allein löscht keine bisherigen Git-Commits.
