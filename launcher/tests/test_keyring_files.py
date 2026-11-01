"""Encrypted and signed RSA key registry, explicit file operations, no targets."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ansible_launcher.config import LauncherConfig
from ansible_launcher.crypto import (
    MAGIC_V2, decrypt_bytes, encrypt_bytes, recipient_fingerprints, _v2_sections,
)
from ansible_launcher.errors import DecryptionError, LauncherError
from ansible_launcher.file_operations import decrypt_list, encrypt_list, sync_recipients
from ansible_launcher.keyring import (
    authorize_key, authorized_private_key, fingerprint, init_keys,
    load_authorized_keys, registry_exists,
)

ROOT = Path(__file__).resolve().parents[2]
FILES = ["inventory/dev.yml", "vaults/master-password"]


@pytest.fixture
def keys(project, tmp_path, rsa_key):
    second = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    third = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    fourth = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    (project / "public_keys").mkdir()
    result = []
    for i, key in enumerate((rsa_key, second, third, fourth)):
        private_path = tmp_path / f"user{i}"
        private_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        private_path.chmod(0o600)
        public_path = project / "public_keys" / f"user{i}.pub"
        public_path.write_bytes(key.public_key().public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH,
        ))
        result.append((key, private_path, public_path))
    return result


@pytest.fixture
def setup(project, keys):
    (project / "inventory" / "dev.yml").write_text("all:\n  hosts: {}\n")
    (project / "vaults" / "master-password").write_text("vaultpw\n")
    return project, keys


def common(project, key_path):
    return dict(project_root=project, cfg=LauncherConfig(), file_list=FILES,
                private_key_path=key_path)


def register_first(project, keys):
    return init_keys(project, keys[0][2], keys[0][1], file_list=FILES, cfg=LauncherConfig())


def test_first_registration_is_encrypted_signed_but_does_not_encrypt_data(setup):
    project, keys = setup
    fp = register_first(project, keys)
    encrypted = project / "launcher" / "authorized-keys.enc"
    signature = project / "launcher" / "authorized-keys.sig"
    assert registry_exists(project)
    assert encrypted.read_bytes().startswith(MAGIC_V2)
    assert fp.encode() not in encrypted.read_bytes()
    assert json.loads(signature.read_text())["signer"] == fp
    assert not (project / "inventory" / "dev.yml.enc").exists()
    assert not (project / "vaults" / "master-password.enc").exists()
    assert set(load_authorized_keys(project, keys[0][0])) == {fp}


def test_new_key_without_existing_signer_rejected(setup):
    project, keys = setup
    register_first(project, keys)
    before = (project / "launcher" / "authorized-keys.enc").read_bytes()
    with pytest.raises(LauncherError, match="nicht entschluesselt"):
        authorize_key(project, keys[2][2], keys[1][1])
    assert (project / "launcher" / "authorized-keys.enc").read_bytes() == before


def test_second_key_can_authorize_third_without_first(setup):
    project, keys = setup
    register_first(project, keys)
    authorize_key(project, keys[1][2], keys[0][1])
    authorize_key(project, keys[2][2], keys[1][1])
    fingerprints = {fingerprint(item[0].public_key()) for item in keys[:3]}
    for item in keys[:3]:
        assert set(load_authorized_keys(project, item[0])) == fingerprints
    assert not (project / "inventory" / "dev.yml.enc").exists()


def test_tampered_public_key_file_does_not_change_encryption_recipients(setup):
    project, keys = setup
    register_first(project, keys)
    authorize_key(project, keys[1][2], keys[0][1])
    keys[1][2].write_bytes(keys[3][2].read_bytes())
    encrypt_list(**common(project, keys[0][1]))
    blob = (project / "inventory" / "dev.yml.enc").read_bytes()
    assert recipient_fingerprints(blob, "inventory") == {
        fingerprint(keys[0][0].public_key()), fingerprint(keys[1][0].public_key())
    }
    assert decrypt_bytes(blob, keys[1][0], "inventory") == (project / "inventory" / "dev.yml").read_bytes()
    with pytest.raises(DecryptionError):
        decrypt_bytes(blob, keys[3][0], "inventory")


def test_modified_encrypted_registry_is_rejected(setup):
    project, keys = setup
    register_first(project, keys)
    path = project / "launcher" / "authorized-keys.enc"
    blob = bytearray(path.read_bytes())
    blob[-1] ^= 1
    path.write_bytes(blob)
    with pytest.raises(LauncherError):
        load_authorized_keys(project, keys[0][0])


def test_modified_detached_signature_is_rejected(setup):
    project, keys = setup
    register_first(project, keys)
    path = project / "launcher" / "authorized-keys.sig"
    data = json.loads(path.read_text())
    data["signature"] = "AA=="
    path.write_text(json.dumps(data))
    with pytest.raises(LauncherError, match="RSA-Signatur"):
        load_authorized_keys(project, keys[0][0])


def test_changed_signer_and_fingerprint_rejected(setup):
    project, keys = setup
    register_first(project, keys)
    authorize_key(project, keys[1][2], keys[0][1])
    path = project / "launcher" / "authorized-keys.sig"
    signed = json.loads(path.read_text())
    signed["signer"] = fingerprint(keys[1][0].public_key())
    path.write_text(json.dumps(signed))
    with pytest.raises(LauncherError):
        load_authorized_keys(project, keys[0][0])


def test_deleted_signature_file_causes_hard_failure(setup):
    project, keys = setup
    register_first(project, keys)
    (project / "launcher" / "authorized-keys.sig").unlink()
    with pytest.raises(LauncherError, match="Unvollstaendige"):
        registry_exists(project)
    with pytest.raises(LauncherError, match="Unvollstaendige"):
        encrypt_list(**common(project, keys[0][1]))


def test_cannot_initialize_again_or_with_wrong_public_key(setup):
    project, keys = setup
    with pytest.raises(LauncherError, match="passt nicht"):
        init_keys(project, keys[1][2], keys[0][1])
    register_first(project, keys)
    with pytest.raises(LauncherError, match="bereits"):
        register_first(project, keys)


def test_encrypt_and_decrypt_all_with_second_key(setup):
    project, keys = setup
    register_first(project, keys)
    authorize_key(project, keys[1][2], keys[0][1])
    encrypt_list(**common(project, keys[0][1]), delete_source=True)
    assert not (project / "inventory" / "dev.yml").exists()
    decrypt_list(**common(project, keys[1][1]))
    (project / "inventory" / "dev.yml").write_text("new content\n")
    encrypt_list(**common(project, keys[1][1]), force=True, delete_source=True)
    blob = (project / "inventory" / "dev.yml.enc").read_bytes()
    for key, _, _ in keys[:2]:
        assert decrypt_bytes(blob, key, "inventory") == b"new content\n"


def test_new_key_requires_explicit_sync_for_existing_data(setup):
    project, keys = setup
    register_first(project, keys)
    encrypt_list(**common(project, keys[0][1]))
    old = (project / "inventory" / "dev.yml.enc").read_bytes()
    old_aes_ciphertext = _v2_sections(old, "inventory")[2]
    authorize_key(project, keys[1][2], keys[0][1])
    assert (project / "inventory" / "dev.yml.enc").read_bytes() == old
    with pytest.raises(DecryptionError):
        decrypt_bytes(old, keys[1][0], "inventory")
    sync_recipients(**common(project, keys[0][1]))
    new = (project / "inventory" / "dev.yml.enc").read_bytes()
    assert _v2_sections(new, "inventory")[2] == old_aes_ciphertext
    assert decrypt_bytes(new, keys[1][0], "inventory") == (project / "inventory" / "dev.yml").read_bytes()


def test_encrypt_refuses_existing_ciphertext_without_force(setup):
    project, keys = setup
    register_first(project, keys)
    encrypt_list(**common(project, keys[0][1]))
    blob = (project / "inventory" / "dev.yml.enc").read_bytes()
    with pytest.raises(LauncherError, match="Bereits verschluesselt"):
        encrypt_list(**common(project, keys[0][1]))
    assert (project / "inventory" / "dev.yml.enc").read_bytes() == blob


def test_encrypt_preflight_missing_source_does_not_write_partial_data(setup):
    project, keys = setup
    register_first(project, keys)
    (project / "vaults" / "master-password").unlink()
    with pytest.raises(LauncherError):
        encrypt_list(**common(project, keys[0][1]))
    assert not (project / "inventory" / "dev.yml.enc").exists()


def test_rogue_recipient_header_is_rejected_before_decryption(setup):
    project, keys = setup
    register_first(project, keys)
    encrypt_list(**common(project, keys[0][1]))
    path = project / "inventory" / "dev.yml.enc"
    blob = bytearray(path.read_bytes())
    count_pos = len(MAGIC_V2) + 1 + 12
    blob[count_pos:count_pos + 2] = (2).to_bytes(2, "big")
    offset = count_pos + 2 + 32 + 2 + 384
    blob[offset:offset] = b"\0" * 32 + (384).to_bytes(2, "big") + b"\0" * 384
    path.write_bytes(blob)
    with pytest.raises(LauncherError, match="nicht in der"):
        decrypt_list(**common(project, keys[0][1]), force=True)


def test_existing_v1_files_can_be_migrated_on_explicit_sync(setup):
    project, keys = setup
    for source, purpose in zip(FILES, ("inventory", "vault-password")):
        plaintext = (project / source).read_bytes()
        (project / (source + ".enc")).write_bytes(encrypt_bytes(plaintext, keys[0][0].public_key(), purpose))
    register_first(project, keys)
    authorize_key(project, keys[1][2], keys[0][1])
    sync_recipients(**common(project, keys[0][1]))
    for source, purpose in zip(FILES, ("inventory", "vault-password")):
        blob = (project / (source + ".enc")).read_bytes()
        assert blob.startswith(MAGIC_V2)
        assert decrypt_bytes(blob, keys[1][0], purpose) == (project / source).read_bytes()


def test_initialization_does_not_accept_wrong_existing_file_key(setup):
    project, keys = setup
    path = project / "inventory" / "dev.yml.enc"
    path.write_bytes(encrypt_bytes(b"old data", keys[1][0].public_key(), "inventory"))
    with pytest.raises(LauncherError, match="Erster Key"):
        register_first(project, keys)
    assert not (project / "launcher" / "authorized-keys.enc").exists()


def test_cli_roundtrip_via_real_launch_py(setup, tmp_path):
    project, keys = setup
    repo = tmp_path / "repo"
    repo.mkdir()
    shutil.copyfile(ROOT / "launch.py", repo / "launch.py")
    shutil.copytree(ROOT / "launcher" / "src" / "ansible_launcher", repo / "launcher" / "src" / "ansible_launcher")
    (repo / "launcher" / "encryption-files.txt").write_text("\n".join(FILES) + "\n")
    (repo / "launcher" / ".venv" / "bin").mkdir(parents=True)
    (repo / "launcher" / ".venv" / "bin" / "python").symlink_to(sys.executable)
    (repo / "public_keys").mkdir()
    for _, _, public_path in keys:
        shutil.copyfile(public_path, repo / "public_keys" / public_path.name)
    (repo / "playbooks").mkdir()
    (repo / "inventory").mkdir()
    (repo / "vaults").mkdir()
    (repo / "ansible.cfg").write_text("[defaults]\n")
    (repo / "inventory" / "dev.yml").write_text("all: {}\n")
    (repo / "vaults" / "master-password").write_text("vault pw\n")
    def run(*parts):
        args = [sys.executable, str(repo / "launch.py"), *map(str, parts), "--project-root", str(repo)]
        result = subprocess.run(args, cwd=tmp_path, capture_output=True, text=True)
        assert result.returncode == 0, (args, result.stdout, result.stderr)
        return result.stdout
    assert "Keine Nutzdateien" in run("keys-init", "--public-key", repo / "public_keys" / "user0.pub", "--key", keys[0][1])
    assert not (repo / "inventory" / "dev.yml.enc").exists()
    run("keys-add", "--public-key", repo / "public_keys" / "user1.pub", "--key", keys[0][1])
    assert "2" in run("keys-list", "--key", keys[1][1])
    run("encrypt-files", "--key", keys[0][1], "--delete-source")
    run("decrypt-files", "--key", keys[1][1])
    assert (repo / "inventory" / "dev.yml").read_text() == "all: {}\n"


def test_signed_registry_files_readable_only_by_registered_private_keys(setup):
    project, keys = setup
    register_first(project, keys)
    authorize_key(project, keys[1][2], keys[0][1])
    for key, _, _ in keys[:2]:
        assert len(load_authorized_keys(project, key)) == 2
    with pytest.raises(LauncherError):
        load_authorized_keys(project, keys[3][0])


def test_manifest_cannot_overwrite_key_registration(setup):
    project, keys = setup
    register_first(project, keys)
    for protected in ("launcher/authorized-keys", "launcher/authorized-keys.sig", "launcher/encryption-files.txt"):
        with pytest.raises(LauncherError, match="Geschuetzte"):
            encrypt_list(project_root=project, cfg=LauncherConfig(),
                         file_list=[protected], private_key_path=keys[0][1])


def test_registered_public_keys_remain_valid_if_source_files_removed(setup):
    project, keys = setup
    register_first(project, keys)
    authorize_key(project, keys[1][2], keys[0][1])
    for _, _, public_path in keys[:2]:
        public_path.unlink()
    encrypt_list(**common(project, keys[1][1]))
    encrypted = (project / "inventory" / "dev.yml.enc").read_bytes()
    assert decrypt_bytes(encrypted, keys[0][0], "inventory") == b"all:\n  hosts: {}\n"
    assert decrypt_bytes(encrypted, keys[1][0], "inventory") == b"all:\n  hosts: {}\n"


def test_run_command_accepts_authorized_key_and_rejects_unregistered_key(setup, tmp_path, monkeypatch):
    from ansible_launcher import cli
    project, keys = setup
    register_first(project, keys)
    encrypt_list(**common(project, keys[0][1]))
    observed = []
    monkeypatch.setattr(cli, "run_playbook", lambda **kwargs: observed.append(kwargs) or 42)
    def call(key_path):
        argv = cli.build_parser().parse_args([
            "run", "prepare_server", "--inventory", "dev", "--key", str(key_path),
            "--project-root", str(project), "--config", str(tmp_path / "none.toml"),
        ])
        return cli.execute(argv)
    assert call(keys[0][1]) == 42
    assert len(observed) == 1
    assert call(keys[2][1]) == 2
    assert len(observed) == 1


def test_legacy_single_recipient_commands_disabled_when_registry_exists(setup, tmp_path):
    from ansible_launcher import cli
    project, keys = setup
    register_first(project, keys)
    argv = cli.build_parser().parse_args([
        "encrypt-inventory", "--source", "inventory/dev.yml",
        "--key", str(keys[0][1]), "--project-root", str(project),
        "--config", str(tmp_path / "none.toml"),
    ])
    assert cli.execute(argv) == 2
    assert not (project / "inventory" / "dev.yml.enc").exists()


def test_playbook_start_refuses_extra_recipient_header(setup, tmp_path, monkeypatch):
    from ansible_launcher import cli
    project, keys = setup
    register_first(project, keys)
    encrypt_list(**common(project, keys[0][1]))
    path = project / "inventory" / "dev.yml.enc"
    blob = bytearray(path.read_bytes())
    count_pos = len(MAGIC_V2) + 1 + 12
    blob[count_pos:count_pos + 2] = (2).to_bytes(2, "big")
    insert_pos = count_pos + 2 + 32 + 2 + 384
    blob[insert_pos:insert_pos] = b"\0" * 32 + (384).to_bytes(2, "big") + b"\0" * 384
    path.write_bytes(blob)
    monkeypatch.setattr(cli, "run_playbook", lambda **kwargs: pytest.fail("Ansible must not start"))
    argv = cli.build_parser().parse_args([
        "run", "prepare_server", "--inventory", "dev", "--key", str(keys[0][1]),
        "--project-root", str(project), "--config", str(tmp_path / "none.toml"),
    ])
    assert cli.execute(argv) == 2


def test_duplicate_key_addition_keeps_registry_unchanged(setup):
    project, keys = setup
    register_first(project, keys)
    authorize_key(project, keys[1][2], keys[0][1])
    old_ciphertext = (project / "launcher" / "authorized-keys.enc").read_bytes()
    old_signature = (project / "launcher" / "authorized-keys.sig").read_bytes()
    with pytest.raises(LauncherError, match="bereits registriert"):
        authorize_key(project, keys[1][2], keys[0][1])
    assert (project / "launcher" / "authorized-keys.enc").read_bytes() == old_ciphertext
    assert (project / "launcher" / "authorized-keys.sig").read_bytes() == old_signature
