"""Regression tests for the master-password path used by encryption and Ansible."""

from pathlib import Path

import pytest

from ansible_launcher.config import LauncherConfig, load_config
from ansible_launcher.errors import LauncherError


def test_master_password_basename_uses_encrypted_file(tmp_path: Path) -> None:
    cfg = LauncherConfig(master_password_file='vault-master.pass')
    assert cfg.master_path(tmp_path) == tmp_path / 'vault-master.pass.enc'


def test_master_password_explicit_enc_suffix_is_not_duplicated(tmp_path: Path) -> None:
    cfg = LauncherConfig(master_password_file='vault-master.pass.enc')
    assert cfg.master_path(tmp_path) == tmp_path / 'vault-master.pass.enc'


def test_master_password_nested_path_is_repo_relative(tmp_path: Path) -> None:
    cfg = LauncherConfig(master_password_file='vaults/master-password')
    assert cfg.master_path(tmp_path) == tmp_path / 'vaults/master-password.enc'


def test_three_field_yaml_is_unchanged_and_resolves_ciphertext(tmp_path: Path) -> None:
    path = tmp_path / 'home.yml'
    original = (
        'key_file: ~/.ssh/id_rsa\n'
        'inventory_dir: inventory\n'
        'master_password_file: vault-master.pass\n'
    )
    path.write_text(original, encoding='utf-8')

    config = load_config(path)

    assert config.master_password_file == 'vault-master.pass'
    assert config.master_path(tmp_path) == tmp_path / 'vault-master.pass.enc'
    assert config.inventory_path('dev', tmp_path) == tmp_path / 'inventory/dev.yml.enc'
    assert path.read_text(encoding='utf-8') == original


def test_home_yaml_rejects_extra_fields(tmp_path: Path) -> None:
    path = tmp_path / 'home.yml'
    path.write_text('master_password_file: vault-master.pass\nfiles: []\n', encoding='utf-8')
    with pytest.raises(LauncherError, match='Nicht unterstuetzte Benutzerkonfiguration'):
        load_config(path)
