"""Regression tests for previously encrypted master passwords labeled 'file'."""
from pathlib import Path

import pytest

from ansible_launcher import file_operations as operations
from ansible_launcher.config import LauncherConfig
from ansible_launcher.crypto import MAGIC_V2, PURPOSE
from ansible_launcher.errors import LauncherError


def _ciphertext(purpose: str) -> bytes:
    return MAGIC_V2 + bytes([PURPOSE[purpose]]) + b'example-header'


def test_only_master_accepts_legacy_file_label():
    old = _ciphertext('file')
    assert operations._stored_purpose(old, 'vault-password') == 'file'
    assert operations._stored_purpose(old, 'inventory') == 'inventory'
    assert operations._stored_purpose(old, 'file') == 'file'
    assert operations._stored_purpose(_ciphertext('vault-password'), 'vault-password') == 'vault-password'


def _fixture(tmp_path: Path, monkeypatch, *, source_exists: bool):
    (tmp_path / 'inventory').mkdir()
    (tmp_path / 'launcher').mkdir()
    source = tmp_path / 'vault-master.pass'
    target = tmp_path / 'vault-master.pass.enc'
    if source_exists:
        source.write_bytes(b'current master password')
    target.write_bytes(_ciphertext('file'))
    monkeypatch.setattr(operations, 'authorized_private_key', lambda *_: ('private', {'fingerprint': 'public'}))
    validated = []
    monkeypatch.setattr(operations, '_validate_recipients', lambda blob, purpose, keys: validated.append(purpose))
    decrypted = []

    def decrypt(blob, private, purpose):
        decrypted.append(purpose)
        if purpose != 'file':
            raise AssertionError(f'Legacy file read with incorrect purpose: {purpose}')
        return b'old master password'

    monkeypatch.setattr(operations, 'decrypt_bytes', decrypt)
    written = []
    monkeypatch.setattr(operations, '_write_batch', lambda contents, **kw: written.extend(contents))
    return source, target, validated, decrypted, written


def test_force_reencrypt_master_verifies_legacy_before_writing(tmp_path, monkeypatch):
    source, target, validated, decrypted, written = _fixture(tmp_path, monkeypatch, source_exists=True)
    generated = []

    def encrypt(data, keys, purpose):
        generated.append(purpose)
        return b'correctly-labeled-new-ciphertext'

    monkeypatch.setattr(operations, 'encrypt_bytes_v2_many', encrypt)
    results = operations.encrypt_list(project_root=tmp_path, cfg=LauncherConfig(),
        file_list=['vault-master.pass'], private_key_path=Path('/unused'), force=True)
    assert results == [target]
    assert validated == ['file']
    assert decrypted == ['file']
    assert generated == ['vault-password']
    assert written == [(target, b'correctly-labeled-new-ciphertext')]
    assert source.read_bytes() == b'current master password'


def test_legacy_master_can_be_exported(tmp_path, monkeypatch):
    source, target, validated, decrypted, written = _fixture(tmp_path, monkeypatch, source_exists=False)
    results = operations.decrypt_list(project_root=tmp_path, cfg=LauncherConfig(),
        file_list=['vault-master.pass'], private_key_path=Path('/unused'))
    assert results == [source]
    assert validated == ['file']
    assert decrypted == ['file']
    assert written == [(source, b'old master password')]


def test_sync_requires_conversion_of_legacy_master(tmp_path, monkeypatch):
    _fixture(tmp_path, monkeypatch, source_exists=False)
    with pytest.raises(LauncherError, match='Veralteter Dateityp'):
        operations.sync_recipients(project_root=tmp_path, cfg=LauncherConfig(),
            file_list=['vault-master.pass'], private_key_path=Path('/unused'))
