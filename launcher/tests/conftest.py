from pathlib import Path
import pytest

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


@pytest.fixture(scope="session")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


@pytest.fixture
def rsa_file(tmp_path: Path, rsa_key):
    p = tmp_path / "id_rsa"
    p.write_bytes(rsa_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    p.chmod(0o600)
    return p


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "ansible"
    (root / "playbooks").mkdir(parents=True)
    (root / "inventory").mkdir()
    (root / "vaults").mkdir()
    (root / "playbooks" / "prepare_server.yml").write_text("---\n- hosts: all\n  tasks: []\n")
    (root / "ansible.cfg").write_text("[defaults]\nvault_identity_list = master@~/vault.pass\n")
    return root
