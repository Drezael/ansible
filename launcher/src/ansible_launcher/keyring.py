"""Encrypted RSA key registration with signed, append-only authorization chain.

The complete RSA public keys are embedded in the AES-GCM-encrypted registry.
Every addition is signed by a key authorized in the preceding chain state.
The current encrypted registry is separately signed by the authorized issuer.

The initial root key is self-signed (trust on first use). Without a trusted
Git history or an external fingerprint, replacing the *entire* initial history
or rolling back to an old signed revision is not detectable cryptographically.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .crypto import decrypt_bytes, encrypt_bytes_v2_many, recipient_fingerprints
from .errors import LauncherError
from .files import read_regular
from .keys import MIN_RSA_BITS, load_rsa_private_key, load_rsa_public_key

REGISTRY_FILE = Path("launcher/authorized-keys.enc")
SIGNATURE_FILE = Path("launcher/authorized-keys.sig")
ROOT_DOMAIN = b"ansible-launcher/keyring/root/v1\x00"
ADD_DOMAIN = b"ansible-launcher/keyring/add/v1\x00"
REGISTRY_DOMAIN = b"ansible-launcher/keyring/encrypted/v1\x00"
MAX_KEYS = 128
MAX_REGISTRY_BYTES = 256 * 1024
MAX_SIGNATURE_BYTES = 16 * 1024


def _canonical(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value: str) -> bytes:
    if not isinstance(value, str) or len(value) > 16384:
        raise LauncherError("Ungueltige Base64-Daten in der Schluesselregistrierung.")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise LauncherError("Ungueltige Base64-Daten in der Schluesselregistrierung.") from exc


def _parse_json(data: bytes, *, description: str) -> dict[str, Any]:
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Doppelter JSON-Schluessel")
            result[key] = value
        return result

    try:
        parsed = json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeError, ValueError) as exc:
        raise LauncherError(f"{description} ist kein gueltiges JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise LauncherError(f"{description} muss ein JSON-Objekt sein.")
    return parsed


def public_der(key: rsa.RSAPublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def fingerprint(key: rsa.RSAPublicKey) -> str:
    return hashlib.sha256(public_der(key)).hexdigest()


def _from_der(encoded: str) -> rsa.RSAPublicKey:
    try:
        key = serialization.load_der_public_key(_unb64(encoded))
    except (ValueError, TypeError) as exc:
        raise LauncherError("Public Key in der verschluesselten Liste ist ungueltig.") from exc
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < MIN_RSA_BITS:
        raise LauncherError("Schluesselliste enthaelt keinen RSA-Key mit mindestens 3072 Bit.")
    if public_der(key) != _unb64(encoded):
        raise LauncherError("Nicht-kanonischer Public Key in der Schluesselliste.")
    return key


def _sign(private: rsa.RSAPrivateKey, content: bytes) -> str:
    return _b64(private.sign(
        content, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256()
    ))


def _verify(public: rsa.RSAPublicKey, content: bytes, signature: str) -> None:
    try:
        public.verify(
            _unb64(signature), content,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256(),
        )
    except (InvalidSignature, ValueError) as exc:
        raise LauncherError("Schluesselregistrierung: RSA-Signatur ungueltig.") from exc


def _root_digest(root: rsa.RSAPublicKey) -> str:
    return hashlib.sha256(ROOT_DOMAIN + public_der(root)).hexdigest()


def _entry_digest(entry: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(entry)).hexdigest()


def _verify_history(registry: dict[str, Any]) -> tuple[dict[str, rsa.RSAPublicKey], str]:
    if (
        set(registry) != {"schema_version", "root_public_key", "root_signature", "additions"}
        or type(registry.get("schema_version")) is not int
        or registry["schema_version"] != 1
    ):
        raise LauncherError("Ungueltige Struktur der Schluesselregistrierung.")
    root = _from_der(registry["root_public_key"])
    _verify(root, ROOT_DOMAIN + public_der(root), registry["root_signature"])
    root_fp = fingerprint(root)
    keys: dict[str, rsa.RSAPublicKey] = {root_fp: root}
    last_issuer = root_fp
    previous = _root_digest(root)
    additions = registry["additions"]
    if not isinstance(additions, list) or len(additions) >= MAX_KEYS:
        raise LauncherError("Ungueltige Anzahl von Schluesselautorisierungen.")
    for sequence, entry in enumerate(additions, start=2):
        if not isinstance(entry, dict) or set(entry) != {
            "sequence", "public_key", "authorized_by", "previous_hash", "signature"
        }:
            raise LauncherError("Ungueltiger Schluesselautorisierungseintrag.")
        if type(entry["sequence"]) is not int or entry["sequence"] != sequence:
            raise LauncherError("Schluesselautorisierungs-Reihenfolge ungueltig.")
        issuer = entry["authorized_by"]
        if not isinstance(issuer, str) or issuer not in keys:
            raise LauncherError("Schluessel wurde nicht von einem bereits autorisierten Key freigegeben.")
        public = _from_der(entry["public_key"])
        fp = fingerprint(public)
        if fp in keys or entry["previous_hash"] != previous:
            raise LauncherError("Schluesselautorisierung enthaelt Duplikate oder eine unterbrochene Kette.")
        body = {item: entry[item] for item in ("sequence", "public_key", "authorized_by", "previous_hash")}
        _verify(keys[issuer], ADD_DOMAIN + _canonical(body), entry["signature"])
        keys[fp] = public
        previous = _entry_digest(entry)
        last_issuer = issuer
    return keys, last_issuer


def _registry_paths(project_root: Path) -> tuple[Path, Path]:
    return project_root / REGISTRY_FILE, project_root / SIGNATURE_FILE


def registry_exists(project_root: Path) -> bool:
    encrypted, signature = _registry_paths(project_root)
    if encrypted.is_symlink() or signature.is_symlink():
        raise LauncherError("Schluesselregistrierungsdateien duerfen keine Symlinks sein.")
    exists_enc, exists_sig = encrypted.exists(), signature.exists()
    if exists_enc != exists_sig:
        raise LauncherError("Unvollstaendige Schluesselregistrierung: .enc und .sig werden gemeinsam benoetigt.")
    return exists_enc


def _envelope(private: rsa.RSAPrivateKey, ciphertext: bytes, signer_fp: str, revision: int) -> bytes:
    unsigned = {
        "schema_version": 1,
        "signer": signer_fp,
        "revision": revision,
        "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
    }
    signed = {**unsigned, "signature": _sign(private, REGISTRY_DOMAIN + _canonical(unsigned))}
    return json.dumps(signed, indent=2, sort_keys=True).encode("utf-8") + b"\n"


def _verified_registry(
    project_root: Path, private: rsa.RSAPrivateKey
) -> tuple[dict[str, Any], dict[str, rsa.RSAPublicKey]]:
    if not registry_exists(project_root):
        raise LauncherError("Keine Schluesselregistrierung vorhanden. Zuerst keys-init verwenden.")
    encrypted_path, signature_path = _registry_paths(project_root)
    ciphertext = read_regular(encrypted_path, max_bytes=MAX_REGISTRY_BYTES)
    signature = _parse_json(read_regular(signature_path, max_bytes=MAX_SIGNATURE_BYTES), description="Signaturdatei")
    try:
        plaintext = decrypt_bytes(ciphertext, private, "keyring")
    except LauncherError as exc:
        raise LauncherError("Schluesselregistrierung konnte mit diesem RSA-Private-Key nicht entschluesselt werden.") from exc
    if len(plaintext) > MAX_REGISTRY_BYTES:
        raise LauncherError("Schluesselregistrierung ist zu gross.")
    registry = _parse_json(plaintext, description="Entschluesselte Schluesselliste")
    keys, last_issuer = _verify_history(registry)
    if fingerprint(private.public_key()) not in keys:
        raise LauncherError("Dieser Private Key ist in der Registrierung nicht autorisiert.")
    recipients = recipient_fingerprints(ciphertext, "keyring")
    if recipients != set(keys):
        raise LauncherError("Schluesselregistrierung enthaelt unautorisierte oder fehlende RSA-Empfaenger.")
    if set(signature) != {"schema_version", "signer", "revision", "ciphertext_sha256", "signature"}:
        raise LauncherError("Ungueltige Struktur der Signaturdatei.")
    unsigned = {key: signature[key] for key in ("schema_version", "signer", "revision", "ciphertext_sha256")}
    if (
        type(signature["schema_version"]) is not int or signature["schema_version"] != 1
        or type(signature["revision"]) is not int
        or signature["revision"] != 1 + len(registry["additions"])
        or signature["signer"] != last_issuer
        or signature["ciphertext_sha256"] != hashlib.sha256(ciphertext).hexdigest()
    ):
        raise LauncherError("Signaturdatei stimmt nicht mit dem autorisierten Registrierungsstand ueberein.")
    _verify(keys[last_issuer], REGISTRY_DOMAIN + _canonical(unsigned), signature["signature"])
    return registry, keys


def _write_registry(project_root: Path, registry: dict[str, Any], private: rsa.RSAPrivateKey,
                    keys: dict[str, rsa.RSAPublicKey], *, overwrite: bool) -> None:
    from .file_operations import _write_batch
    plaintext = _canonical(registry)
    if len(plaintext) > MAX_REGISTRY_BYTES:
        raise LauncherError("Schluesselregistrierung ueberschreitet 256 KiB.")
    ciphertext = encrypt_bytes_v2_many(plaintext, list(keys.values()), "keyring")
    last_issuer = _verify_history(registry)[1]
    if fingerprint(private.public_key()) != last_issuer:
        raise LauncherError("Signierender Private Key ist nicht der autorisierende Schluessel.")
    detached = _envelope(private, ciphertext, last_issuer, 1 + len(registry["additions"]))
    encrypted_path, signature_path = _registry_paths(project_root)
    # Validate the complete new document while still in memory.
    if decrypt_bytes(ciphertext, private, "keyring") != plaintext:
        raise LauncherError("Schluesselregistrierungs-Entschluesselung fehlgeschlagen.")
    if recipient_fingerprints(ciphertext, "keyring") != set(keys):
        raise LauncherError("Schluesselregistrierungs-Empfaenger stimmen nicht ueberein.")
    signature_doc = _parse_json(detached, description="Neue Signaturdatei")
    unsigned = {key: signature_doc[key] for key in ("schema_version", "signer", "revision", "ciphertext_sha256")}
    _verify(keys[last_issuer], REGISTRY_DOMAIN + _canonical(unsigned), signature_doc["signature"])
    _write_batch([(encrypted_path, ciphertext), (signature_path, detached)], overwrite=overwrite)


def init_keys(
    project_root: Path, public_path: Path, private_path: Path,
    *, file_list: list[str] | None = None, cfg=None,
) -> str:
    """Self-sign first key, store encrypted registry, do not encrypt data files."""
    if registry_exists(project_root):
        raise LauncherError("Schluesselregistrierung existiert bereits; keys-init wird abgebrochen.")
    private = load_rsa_private_key(private_path)
    public = load_rsa_public_key(public_path)
    if fingerprint(private.public_key()) != fingerprint(public):
        raise LauncherError("Erster Public Key passt nicht zum uebergebenen Private Key.")
    if file_list:
        # Existing V1/V2 files may exist after the previous init-encryption workflow.
        from .config import LauncherConfig, resolve_project_relative
        configuration = cfg or LauncherConfig()
        root = project_root.resolve()
        inventory_dir = resolve_project_relative(root, configuration.inventory_dir)
        vault_target = configuration.master_path(root)
        from .file_operations import _check_relative_path, _check_no_symlinks
        for name in file_list:
            rel = _check_relative_path(name)
            source = root.joinpath(*rel.parts)
            target = Path(str(source) + ".enc")
            protected = {
                root / "launcher" / "authorized-keys.enc",
                root / "launcher" / "authorized-keys.sig",
                root / "launcher" / "encryption-files.txt",
            }
            if source in protected or target in protected:
                raise LauncherError(f"Geschuetzte Launcher-Datei in encryption-files.txt: {name}")
            _check_no_symlinks(source, root)
            _check_no_symlinks(target, root)
            if target.exists():
                purpose = (
                    "vault-password" if target == vault_target else
                    "inventory" if source.parent == inventory_dir and source.suffix in (".yml", ".yaml") else
                    "file"
                )
                blob = read_regular(target)
                if recipient_fingerprints(blob, purpose) not in (None, {fingerprint(public)}):
                    raise LauncherError(f"Bestehende Datei hat fremde RSA-Empfaenger: {target}")
                try:
                    decrypt_bytes(blob, private, purpose)
                except LauncherError as exc:
                    raise LauncherError(f"Erster Key kann bestehende Datei nicht oeffnen: {target}") from exc
    (project_root / "launcher").mkdir(parents=True, exist_ok=True)
    registry = {
        "schema_version": 1,
        "root_public_key": _b64(public_der(public)),
        "root_signature": _sign(private, ROOT_DOMAIN + public_der(public)),
        "additions": [],
    }
    keys = {fingerprint(public): public}
    _write_registry(project_root, registry, private, keys, overwrite=False)
    return fingerprint(public)


def authorize_key(project_root: Path, public_path: Path, signer_path: Path) -> str:
    """Sign an addition using a previously authorized RSA private key."""
    private = load_rsa_private_key(signer_path)
    registry, keys = _verified_registry(project_root, private)
    issuer = fingerprint(private.public_key())
    new_public = load_rsa_public_key(public_path)
    new_fp = fingerprint(new_public)
    if new_fp in keys:
        raise LauncherError("Dieser RSA-Key ist bereits registriert.")
    if len(keys) >= MAX_KEYS:
        raise LauncherError("Maximale Anzahl autorisierter RSA-Keys erreicht.")
    root = _from_der(registry["root_public_key"])
    history = registry["additions"]
    previous = _entry_digest(history[-1]) if history else _root_digest(root)
    entry = {
        "sequence": len(history) + 2,
        "public_key": _b64(public_der(new_public)),
        "authorized_by": issuer,
        "previous_hash": previous,
    }
    registry["additions"].append({**entry, "signature": _sign(private, ADD_DOMAIN + _canonical(entry))})
    updated = {**keys, new_fp: new_public}
    _write_registry(project_root, registry, private, updated, overwrite=True)
    return new_fp


def load_authorized_keys(project_root: Path, private: rsa.RSAPrivateKey) -> dict[str, rsa.RSAPublicKey]:
    return _verified_registry(project_root, private)[1]


def authorized_private_key(
    project_root: Path, private_path: Path
) -> tuple[rsa.RSAPrivateKey, dict[str, rsa.RSAPublicKey]]:
    private = load_rsa_private_key(private_path)
    keys = load_authorized_keys(project_root, private)
    return private, keys
