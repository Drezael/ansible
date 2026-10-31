"""Initial encryption using a public key; no real Ansible or servers involved."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ansible_launcher import initial_encryption as initial
from ansible_launcher.config import LauncherConfig
from ansible_launcher.crypto import MAGIC, MAGIC_V2, decrypt_bytes, encrypt_bytes
from ansible_launcher.errors import DecryptionError, LauncherError
from ansible_launcher.keys import load_rsa_public_key

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def public_key_path(tmp_path, rsa_key):
    path = tmp_path / "first.pub"
    path.write_bytes(rsa_key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    ) + b" initial-user@example\n")
    return path


@pytest.fixture
def listed_project(project):
    inventory = project / "inventory" / "dev.yml"
    master = project / "vaults" / "master-password"
    inventory.write_bytes(b"all:\n  hosts: {}\n")
    master.write_bytes(b"test-vault-password\n")
    paths = ["inventory/dev.yml", "vaults/master-password"]
    return project, paths


def _encrypt(root, paths, pub):
    return initial.initialize_encryption(
        project_root=root, config=LauncherConfig(),
        file_list=paths, public_key_path=pub,
    )


def test_initial_encryption_roundtrip_and_source_retention(listed_project, public_key_path, rsa_key):
    root, paths = listed_project
    outputs = _encrypt(root, paths, public_key_path)
    assert [str(p.relative_to(root)) for p in outputs] == [f"{p}.enc" for p in paths]
    for item, purpose in zip(paths, ("inventory", "vault-password")):
        original = (root / item).read_bytes()
        sealed = (root / (item + ".enc")).read_bytes()
        assert sealed.startswith(MAGIC_V2)
        assert original not in sealed
        assert decrypt_bytes(sealed, rsa_key, purpose) == original
        assert (root / item).is_file()
        assert (root / (item + ".enc")).stat().st_mode & 0o777 == 0o600


def test_preflight_aborts_if_any_output_exists(listed_project, public_key_path):
    root, paths = listed_project
    blocked = root / "vaults" / "master-password.enc"
    blocked.write_bytes(b"already encrypted")
    with pytest.raises(LauncherError, match="Bereits verschluesselte Zieldatei"):
        _encrypt(root, paths, public_key_path)
    assert blocked.read_bytes() == b"already encrypted"
    assert not (root / "inventory" / "dev.yml.enc").exists()


def test_preflight_aborts_on_dangling_symlink_destination(listed_project, public_key_path):
    root, paths = listed_project
    (root / "vaults" / "master-password.enc").symlink_to(root / "does-not-exist")
    with pytest.raises(LauncherError, match="Bereits verschluesselte Zieldatei"):
        _encrypt(root, paths, public_key_path)
    assert not (root / "inventory" / "dev.yml.enc").exists()


def test_preflight_aborts_if_source_is_already_encrypted(listed_project, public_key_path, rsa_key):
    root, paths = listed_project
    source = root / "vaults" / "master-password"
    source.write_bytes(encrypt_bytes(b"test", rsa_key.public_key(), "vault-password"))
    with pytest.raises(LauncherError, match="bereits verschluesselt"):
        _encrypt(root, paths, public_key_path)
    assert not list(root.rglob("*.enc"))


def test_preflight_aborts_if_source_missing(listed_project, public_key_path):
    root, paths = listed_project
    (root / "vaults" / "master-password").unlink()
    with pytest.raises(LauncherError, match="Quelldatei kann nicht gelesen"):
        _encrypt(root, paths, public_key_path)
    assert not list(root.rglob("*.enc"))


def test_bad_public_key_aborts_without_outputs(listed_project, tmp_path):
    root, paths = listed_project
    path = tmp_path / "bad.pub"
    path.write_text("not a key")
    with pytest.raises(LauncherError, match="Public-Key"):
        _encrypt(root, paths, path)
    assert not list(root.rglob("*.enc"))


def test_rejects_symlink_source(listed_project, public_key_path, tmp_path):
    root, paths = listed_project
    file = root / "vaults" / "master-password"
    file.unlink()
    file.symlink_to(tmp_path / "outside")
    with pytest.raises(LauncherError, match="Symbolische Links"):
        _encrypt(root, paths, public_key_path)
    assert not list(root.rglob("*.enc"))


def test_encryption_failure_before_publish_leaves_no_outputs(listed_project, public_key_path, monkeypatch):
    root, paths = listed_project
    real = initial.encrypt_bytes_v2
    state = {"count": 0}

    def fail_second(plaintext, public_key, purpose):
        state["count"] += 1
        if state["count"] == 2:
            raise LauncherError("simulated crypto failure")
        return real(plaintext, public_key, purpose)

    monkeypatch.setattr(initial, "encrypt_bytes_v2", fail_second)
    with pytest.raises(LauncherError, match="simulated crypto failure"):
        _encrypt(root, paths, public_key_path)
    assert not list(root.rglob("*.enc"))
    assert not list(root.rglob(".ansible-init-*.tmp"))


def test_publish_failure_rolls_back_previous_output(listed_project, public_key_path, monkeypatch):
    root, paths = listed_project
    original_link = initial.os.link
    state = {"count": 0}

    def fail_second_link(src, dst, *args, **kwargs):
        state["count"] += 1
        if state["count"] == 2:
            raise FileExistsError("simulated concurrent creation")
        return original_link(src, dst, *args, **kwargs)

    monkeypatch.setattr(initial.os, "link", fail_second_link)
    with pytest.raises(LauncherError, match="Initiale Verschluesselung fehlgeschlagen"):
        _encrypt(root, paths, public_key_path)
    assert not list(root.rglob("*.enc"))
    assert not list(root.rglob(".ansible-init-*.tmp"))


def test_pem_public_key(tmp_path, rsa_key):
    pem = tmp_path / "public.pem"
    pem.write_bytes(rsa_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    assert load_rsa_public_key(pem).public_numbers() == rsa_key.public_key().public_numbers()


def test_v2_wrong_key_wrong_purpose_tampering(listed_project, public_key_path, rsa_key):
    root, paths = listed_project
    _encrypt(root, paths, public_key_path)
    ciphertext = (root / "inventory" / "dev.yml.enc").read_bytes()
    wrong = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    with pytest.raises(DecryptionError):
        decrypt_bytes(ciphertext, wrong, "inventory")
    with pytest.raises(DecryptionError):
        decrypt_bytes(ciphertext, rsa_key, "vault-password")
    tampered = bytearray(ciphertext)
    tampered[-1] ^= 1
    with pytest.raises(DecryptionError):
        decrypt_bytes(bytes(tampered), rsa_key, "inventory")
    # Old V1 format still decrypts.
    legacy = encrypt_bytes(b"legacy", rsa_key.public_key(), "inventory")
    assert legacy.startswith(MAGIC)
    assert decrypt_bytes(legacy, rsa_key, "inventory") == b"legacy"


def test_additional_file_category(listed_project, public_key_path, rsa_key):
    root, paths = listed_project
    (root / "vars").mkdir()
    (root / "vars" / "sample.txt").write_bytes(b"additional")
    _encrypt(root, paths + ["vars/sample.txt"], public_key_path)
    assert decrypt_bytes((root / "vars" / "sample.txt.enc").read_bytes(), rsa_key, "file") == b"additional"


def test_reject_empty_list(listed_project, public_key_path):
    root, _ = listed_project
    with pytest.raises(LauncherError, match="Liste ist leer|liste ist leer"):
        _encrypt(root, [], public_key_path)


def test_full_launch_cli(tmp_path, rsa_key, public_key_path):
    isolated = tmp_path / "repo"
    (isolated / "launcher" / "src").mkdir(parents=True)
    (isolated / "launcher" / ".venv" / "bin").mkdir(parents=True)
    (isolated / "launcher" / ".venv" / "bin" / "python").symlink_to(sys.executable)
    shutil.copyfile(ROOT / "launch.py", isolated / "launch.py")
    shutil.copytree(ROOT / "launcher" / "src" / "ansible_launcher", isolated / "launcher" / "src" / "ansible_launcher")
    (isolated / "launcher" / "encryption-files.txt").write_text(
        "# test\ninventory/dev.yml\nvaults/master-password\n"
    )
    (isolated / "playbooks").mkdir()
    (isolated / "inventory").mkdir()
    (isolated / "vaults").mkdir()
    (isolated / "ansible.cfg").write_text("[defaults]\n")
    (isolated / "inventory" / "dev.yml").write_text("all:\n  hosts: {}\n")
    (isolated / "vaults" / "master-password").write_text("vaultpw\n")
    command = [
        sys.executable, str(isolated / "launch.py"), "init-encryption",
        "--public-key", str(public_key_path),
    ]
    first = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True)
    assert first.returncode == 0, first.stderr
    encrypted = (isolated / "inventory" / "dev.yml.enc")
    before = encrypted.read_bytes()
    assert decrypt_bytes(before, rsa_key, "inventory") == b"all:\n  hosts: {}\n"
    second = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True)
    assert second.returncode == 2
    assert "Init abgebrochen" in second.stderr
    assert encrypted.read_bytes() == before


def test_v2_files_work_with_existing_ansible_executor(
    listed_project, public_key_path, rsa_key, tmp_path, monkeypatch
):
    from ansible_launcher.executor import run_playbook
    root, paths = listed_project
    _encrypt(root, paths, public_key_path)
    observed = {}

    def simulate_ansible(argv, cwd, env):
        observed["inventory"] = Path(env["ANSIBLE_INVENTORY"]).read_bytes()
        observed["vault"] = Path(env["ANSIBLE_VAULT_IDENTITY_LIST"].split("@", 1)[1]).read_bytes()
        return 0

    monkeypatch.setattr("ansible_launcher.executor._execute", simulate_ansible)
    result = run_playbook(
        project_root=root, cfg=LauncherConfig(), private_key=rsa_key,
        playbook_name="prepare_server", inventory_name="dev", hostname="test-host",
        extra_vars=[], check=False, diff=False, limit=None,
        tags=None, skip_tags=None, forks=None, verbose=0,
        temp_dir=str(tmp_path), allow_disk_temp=True,
    )
    assert result == 0
    assert observed["inventory"] == b"all:\n  hosts: {}\n"
    assert observed["vault"] == b"test-vault-password\n"
