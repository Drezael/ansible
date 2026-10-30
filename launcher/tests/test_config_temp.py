from pathlib import Path
import stat

import pytest

from ansible_launcher.config import load_config, write_config, LauncherConfig
from ansible_launcher.errors import LauncherError
from ansible_launcher.temporary import SecretWorkspace, filesystem_type, select_temp_base


def test_home_config(tmp_path, project, rsa_file):
    config_path = tmp_path / "configdir" / "config.toml"
    write_config(config_path, project_root=project, key_file=rsa_file)
    assert stat.S_IMODE(config_path.stat().st_mode) == 0o600
    assert load_config(config_path).project_root == project
    assert load_config(config_path).key_file == rsa_file
    with pytest.raises(LauncherError, match="bereits"):
        write_config(config_path, project_root=project, key_file=rsa_file)


def test_tmp_files_permissions_and_cleanup(tmp_path):
    with SecretWorkspace(base_dir=tmp_path) as ws:
        directory = ws.path
        secret = ws.write_secret("master.pass", b"hello")
        assert secret.read_bytes() == b"hello"
        assert stat.S_IMODE(secret.stat().st_mode) == 0o600
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
        with pytest.raises(FileExistsError):
            ws.write_secret("master.pass", b"other")
        with pytest.raises(LauncherError):
            ws.write_secret("../escape", b"no")
    assert not directory.exists()


def test_disk_tmp_denied_without_opt_in(tmp_path):
    if filesystem_type(tmp_path) != "tmpfs":
        with pytest.raises(LauncherError, match="tmpfs"):
            select_temp_base(specified=str(tmp_path), allow_disk=False)
    assert select_temp_base(specified=str(tmp_path), allow_disk=True) == tmp_path.resolve()
