# Ansible Launcher: verschluesselte und signierte RSA-Schluesselregistrierung

Diese Version baut auf dem GitHub-Stand vom 31.10.2026 auf. Die bisherige
`init-encryption`-Funktion wird durch eine getrennte Schluesselregistrierung und
explizite Dateioperationen ersetzt. Die Playbooks werden weiterhin lokal mit
Ansible ausgefuehrt; es gibt keine Playbook-/Host-ACL und keinen Master-Key.

## Dateien im Repository

```text
public_keys/
  user1.pub                       # Eingabe fuer keys-init
  user2.pub                       # Eingabe fuer keys-add
launcher/
  encryption-files.txt            # Ein Quellpfad je Zeile
  authorized-keys.enc             # Bei keys-init erzeugt, AES-256-GCM/RSA-OAEP
  authorized-keys.sig             # Bei keys-init erzeugt, RSA-PSS-Signatur
```

Der gesamte RSA-Public-Key (kanonisch als DER/Base64) wird **innerhalb**
von `authorized-keys.enc` gespeichert. Der SHA-256-Fingerprint wird daraus
abgeleitet. Nach der Registrierung werden die `.pub`-Dateien in `public_keys/`
**nicht mehr** zum Verschluesseln verwendet. Ein spaeterer Austausch einer
solchen Datei aendert weder Berechtigungen noch Empfaenger.

Die verschluesselte Schluesselliste enthaelt eine Kette signierter
Registrierungen. Jeder neue Public Key muss von einem bereits autorisierten
Private Key signiert sein. Zusaetzlich signiert der Autorisierende **die exakten
verschluesselten Bytes** der aktuellen Liste in `authorized-keys.sig`.
Ein ungueltiger Hash, eine manipulierte Signatur, fehlende Datei oder ein
nicht autorisierter Empfaenger fuehrt zum Abbruch.

Jeder autorisierte Key ist gleichberechtigt. Beim Erst-Init signiert der erste
Key seine eigene Registrierung. Es wird keine neue Admin-Rolle erstellt.

## Einrichtung

Voraussetzungen: Python 3.12+, das bisherige `launcher/.venv`, `cryptography`,
RSA-Private-Keys mit mindestens 3072 Bit und Dateirechten 0600.
Private Keys gehoeren **niemals** ins Repository.

**1. Ersten Public Key aufnehmen** (noch keine Nutzdateien verschluesseln):

```bash
python3 launch.py keys-init \
  --key ~/.ssh/user1 \
  --public-key public_keys/user1.pub
```

Die Dateien `launcher/authorized-keys.enc` und
`launcher/authorized-keys.sig` werden neu erstellt. Bestehende verschluesselte
Dateien aus dem frueheren `init-encryption`-Ablauf werden vorab auf
Entschluesselbarkeit mit Key 1 geprueft, aber nicht veraendert.

**2. Weitere Public Keys aufnehmen** (keine Nutzdateien veraendern):

```bash
python3 launch.py keys-add \
  --key ~/.ssh/user1 \
  --public-key public_keys/user2.pub
```

Vor `keys-add` den Fingerprint der neuen `.pub`-Datei ueber eine
vertrauenswuerdige Quelle vergleichen: Wird die `.pub`-Datei **vor der
Aufnahme** ausgetauscht, wuerde der bisher autorisierte Benutzer sonst den
falschen Key unterschreiben. **Nach** der Aufnahme ist die externe `.pub`-Datei
nicht mehr massgeblich.

Nach der Aufnahme kann auch Key 2 die Schluesselliste entschluesseln und
weitere Schluessel autorisieren. Zum Pruefen:

```bash
python3 launch.py keys-list --key ~/.ssh/user2
```

`keys-list` benoetigt einen autorisierten Private Key, weil die Liste
verschluesselt ist.

**3. Aufgelistete Nutzdateien fuer ALLE autorisierten Keys verschluesseln:**

```bash
python3 launch.py encrypt-files --key ~/.ssh/user1
```

Nur die Dateien aus `launcher/encryption-files.txt` werden verarbeitet.
Die Quellen bleiben standardmaessig erhalten. Sie koennen nach erfolgreicher
Entschluesselungspruefung entfernt werden:

```bash
python3 launch.py encrypt-files --key ~/.ssh/user1 --force --delete-source
```

`--force` erlaubt das absichtliche Ersetzen bereits vorhandener `.enc`-Dateien.
Ohne `--force` wird bei vorhandenen Zieldateien vor der Verarbeitung abgebrochen.

**4. Dateien zur Bearbeitung explizit entschluesseln:**

```bash
python3 launch.py decrypt-files --key ~/.ssh/user2
```

Optional ist eine einzelne Datei mit `--file inventory/dev.yml` waehlbar.
Bereits vorhandene Klartextdateien werden ohne `--force` niemals ersetzt.
Bearbeitete Dateien wieder fuer alle autorisierten Keys verschluesseln:

```bash
python3 launch.py encrypt-files --key ~/.ssh/user2 --force --delete-source
```

**5. Nach Aufnahme weiterer Keys bereits verschluesselte Daten aktualisieren:**

```bash
python3 launch.py sync-recipients --key ~/.ssh/user1
```

Bei V2-Dateien bleibt das AES-Chiffrat unveraendert; nur die RSA-verpackten
AES-Dateischluessel werden fuer alle aktuell autorisierten Public Keys
neu erstellt. Alte V1-Dateien werden dabei einmalig zu V2 migriert.

**6. Playbooks wie zuvor starten:**

```bash
python3 launch.py run server.prepare --inventory dev \
  --hostname test-host --key ~/.ssh/user2
```

Bei vorhandener Registrierung muss der Private Key die signierte Schluesselliste
oeffnen koennen und darin autorisiert sein. Unautorisierte RSA-Empfaenger in
den verschluesselten Inventory-/Vault-Passwortdateien werden abgewiesen.
Die bisherigen Einzeldateibefehle `encrypt-inventory`, `encrypt-master` und
`decrypt-inventory` sind dann gesperrt, da sie nicht alle Empfaenger verarbeiten.

## Dateiliste

`launcher/encryption-files.txt` enthaelt jeweils **einen repo-relativen
Quellpfad pro Zeile**, ohne `.enc`. Beispiel:

```text
inventory/dev.yml
vaults/master-password
```

Die Zieldatei ist jeweils der Quellpfad mit `.enc` am Ende. Leere Zeilen und
Kommentarzeilen (`#`) werden ignoriert. Aufgelistete geschuetzte
Registrierungsdateien oder symbolische Links sind nicht erlaubt.

## Kryptografie und Vertrauensmodell

- AES-256-GCM verschluesselt jede Nutzdatei genau einmal.
- RSA-OAEP/SHA-256 verpackt den AES-Dateischluessel fuer jeden autorisierten
  Public Key der geprueften Schluesselliste.
- RSA-PSS/SHA-256 signiert die Erstregistrierung, jede weitere Key-Aufnahme
  und den exakten verschluesselten aktuellen Registrierungsstand.
- Signierte Autorisierungen verweisen auf den vorherigen signierten Eintrag.
- Der SHA-256-Fingerprint basiert auf dem DER-kodierten RSA-Public-Key.
- Vollstaendige Public Keys werden aus der verifizierten, **verschluesselten**
  Liste geladen, nicht aus beliebigen `.pub`-Dateien.

**Vertrauensgrenze:** Der erste Key signiert sich selbst. Seine Erstregistrierung
ist nur so vertrauenswuerdig wie der urspruenglich kontrollierte Git-Stand.
Wer das gesamte Repository einschliesslich der Anfangshistorie austauschen
kann, kann auch eine neue selbstsignierte Kette herstellen. Ein solcher
kompletter Austausch oder ein Rollback zu einer aelteren gueltig signierten
Version ist **ohne unabhaengigen Vertrauensanker nicht kryptografisch
nachweisbar**. Der Repository-Zugriff und die Git-Historie muessen deshalb
geschuetzt werden. Fuer die beschriebenen Ablaufe ist kein lokaler Trust-Pin
und keine weitere Datei ausserhalb des Repositories erforderlich.

Auch kann ein bereits autorisierter Benutzer die von ihm entschluesselten
Geheimnisse weitergeben. Eine lokale Python-Anwendung ist keine gegen
berechtigte lokale Benutzer unueberwindbare Zugriffssperre.

## Migration und Sicherheitshinweise

- `init-encryption` und das alte Modul `initial_encryption.py` werden entfernt.
  Ein erster Key wird nun mit `keys-init` registriert, ohne Nutzdaten zu
  verschluesseln. Erst danach `encrypt-files` oder `sync-recipients` ausfuehren.
- `authorized-keys.enc` und `.sig` muessen **zusammen** versioniert und
  unveraendert gehalten werden. Bei fehlender oder ungueltiger Signatur
  bricht der Launcher ab.
- Klartextdateien und Private Keys nicht nach Git committen. Der lokale
  Loeschvorgang entfernt keine Daten aus bereits veroeffentlichten Git-Commits.
- `decrypt-files` schreibt bewusste Klartextdateien auf den Datentraeger.
  Bei Dateiausgabe erfolgt eine Vorpruefung und bestmoeglicher Rollback;
  ein Stromausfall waehrend mehrerer Dateiersetzungen ist keine transaktionale
  Operation.
- Entfernen eines registrierten Schluessels und sicherer Widerruf sind in
  dieser Version **noch nicht** implementiert.

## Tests

```bash
PYTHONPATH=launcher/src python3 -m pytest -q launcher/tests
```

Alle Integrationstests verwenden lokale Beispieldateien und simulieren
Ansible-Aufrufe. Es werden keine Zielserver veraendert.
