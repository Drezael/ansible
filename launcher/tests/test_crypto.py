from pathlib import Path
import os

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.primitives import serialization

from ansible_launcher.crypto import MAGIC, decrypt_bytes, encrypt_bytes
from ansible_launcher.errors import DecryptionError, LauncherError
from ansible_launcher.files import decrypt_file, encrypt_file
from ansible_launcher.keys import load_rsa_private_key


def test_roundtrip_inventory_and_password(rsa_key):
    for purpose, plaintext in (("inventory", b"all:\n  hosts:\n    test-host:\n"),
                               ("vault-password", b"a strong vault passphrase\n")):
        sealed = encrypt_bytes(plaintext, rsa_key.public_key(), purpose)
        assert sealed.startswith(MAGIC)
        assert plaintext not in sealed
        assert decrypt_bytes(sealed, rsa_key, purpose) == plaintext
        assert encrypt_bytes(plaintext, rsa_key.public_key(), purpose) != sealed


def test_wrong_key_and_corrupted_ciphertext(rsa_key):
    sealed = encrypt_bytes(b"secret", rsa_key.public_key(), "inventory")
    wrong = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    with pytest.raises(DecryptionError):
        decrypt_bytes(sealed, wrong, "inventory")
    corrupt = bytearray(sealed)
    corrupt[-1] ^= 0x01
    with pytest.raises(DecryptionError):
        decrypt_bytes(bytes(corrupt), rsa_key, "inventory")
    with pytest.raises(DecryptionError):
        decrypt_bytes(sealed, rsa_key, "vault-password")


def test_short_or_invalid_blob(rsa_key):
    for blob in (b"invalid", MAGIC, MAGIC + b"\x01\x00\x00"):
        with pytest.raises(DecryptionError):
            decrypt_bytes(blob, rsa_key, "inventory")


def test_openssh_rsa_private_with_passphrase(tmp_path, rsa_key, monkeypatch):
    pytest.importorskip("bcrypt", reason="Optional native bcrypt library unavailable in test container")
    secret = tmp_path / "id_rsa"
    secret.write_bytes(rsa_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.BestAvailableEncryption(b"testing-passphrase"),
    ))
    secret.chmod(0o600)
    monkeypatch.setattr("ansible_launcher.keys.getpass.getpass", lambda _: "testing-passphrase")
    assert load_rsa_private_key(secret).private_numbers() == rsa_key.private_numbers()


def test_only_rsa_allowed(tmp_path):
    key = ed25519.Ed25519PrivateKey.generate()
    p = tmp_path / "ed25519"
    p.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    p.chmod(0o600)
    with pytest.raises(LauncherError, match="RSA"):
        load_rsa_private_key(p)


def test_bad_private_key_permissions(rsa_file):
    rsa_file.chmod(0o644)
    with pytest.raises(LauncherError, match="Dateirechte"):
        load_rsa_private_key(rsa_file)


def test_encrypt_file_safe_and_delete_source(tmp_path, rsa_key):
    source = tmp_path / "dev.yml"
    dest = tmp_path / "dev.yml.enc"
    source.write_text("all:\n  hosts: {}\n")
    encrypt_file(source, dest, rsa_key.public_key(), "inventory")
    assert source.exists()
    assert dest.stat().st_mode & 0o777 == 0o600
    assert decrypt_file(dest, rsa_key, "inventory") == source.read_bytes()
    with pytest.raises(LauncherError, match="existiert"):
        encrypt_file(source, dest, rsa_key.public_key(), "inventory")
    encrypt_file(source, dest, rsa_key.public_key(), "inventory", force=True,
                 delete_source=True, verify_private_key=rsa_key)
    assert not source.exists()
    assert decrypt_file(dest, rsa_key, "inventory") == b"all:\n  hosts: {}\n"


def test_private_key_loading_plain(rsa_file, rsa_key):
    assert load_rsa_private_key(rsa_file).private_numbers() == rsa_key.private_numbers()
