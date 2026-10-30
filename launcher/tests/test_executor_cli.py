import json
import os
from pathlib import Path
import stat
import textwrap

import pytest

from ansible_launcher.cli import main
from ansible_launcher.config import LauncherConfig
from ansible_launcher.crypto import encrypt_bytes
from ansible_launcher.errors import LauncherError
from ansible_launcher.executor import run_playbook


def setup_encrypted_project(project, rsa_key):
    inventory = b"all:\n  hosts:\n    test-host:\n      ansible_host: 127.0.0.1\n"
    master = b"test-master-vault-password\n"
    (project / "inventory" / "dev.yml.enc").write_bytes(
        encrypt_bytes(inventory, rsa_key.public_key(), "inventory")
    )
    (project / "vaults" / "master-password.enc").write_bytes(
        encrypt_bytes(master, rsa_key.public_key(), "vault-password")
    )
    return inventory, master


def test_run_live_env_and_cleanup(project, rsa_file, rsa_key, tmp_path, monkeypatch):
    inventory, password = setup_encrypted_project(project, rsa_key)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    exe = bin_dir / "ansible-playbook"
    exe.write_text(textwrap.dedent('''\
        #!/usr/bin/env python3
        import json, os, pathlib, sys
        password_path = os.environ['ANSIBLE_VAULT_IDENTITY_LIST'].removeprefix('master@')
        inventory_path = os.environ['ANSIBLE_INVENTORY']
        d = {
          'argv':sys.argv[1:],
          'pwd':str(pathlib.Path.cwd()),
          'config':os.environ['ANSIBLE_CONFIG'],
          'inventory':pathlib.Path(inventory_path).read_text(),
          'password':pathlib.Path(password_path).read_text(),
          'inventory_path':inventory_path,
          'password_path':password_path,
          'perm_inventory':oct(pathlib.Path(inventory_path).stat().st_mode & 0o777),
          'perm_password':oct(pathlib.Path(password_path).stat().st_mode & 0o777),
          'temp_dir':str(pathlib.Path(inventory_path).parent),
        }
        pathlib.Path(os.environ['TEST_CAPTURE']).write_text(json.dumps(d))
        sys.exit(int(os.environ.get('TEST_EXIT_CODE','0')))
    '''))
    exe.chmod(0o755)
    capture = tmp_path / "capture.json"
    monkeypatch.setenv("TEST_CAPTURE", str(capture))
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("TEST_EXIT_CODE", "42")
    config_path = tmp_path / "launch.toml"
    rc = main([
        "run", "prepare_server", "--inventory", "dev",
        "--hostname", "test-host", "--extra-var", "testmode=1",
        "--check", "--diff", "--limit", "test-host",
        "--tags", "install", "--skip-tags", "skipme",
        "--forks", "2", "-v",
        "--project-root", str(project), "--key", str(rsa_file),
        "--config", str(config_path),
        "--temp-dir", str(tmp_path), "--allow-disk-temp",
    ])
    assert rc == 42
    data = json.loads(capture.read_text())
    assert data["pwd"] == str(project)
    assert data["config"] == str(project / "ansible.cfg")
    assert data["inventory"].encode() == inventory
    assert data["password"].encode() == password
    assert data["perm_inventory"] == "0o600"
    assert data["perm_password"] == "0o600"
    assert "--check" in data["argv"]
    assert "--diff" in data["argv"]
    assert "hostname=test-host" in data["argv"]
    assert "testmode=1" in data["argv"]
    assert not Path(data["inventory_path"]).exists()
    assert not Path(data["password_path"]).exists()
    assert not Path(data["temp_dir"]).exists()


def test_no_run_on_wrong_key(project, rsa_key, tmp_path):
    setup_encrypted_project(project, rsa_key)
    other_key = __import__('cryptography.hazmat.primitives.asymmetric.rsa', fromlist=['rsa']).generate_private_key(
        public_exponent=65537, key_size=3072
    )
    with pytest.raises(LauncherError):
        # Run cannot start because the key cannot decrypt the encrypted inventory.
        run_playbook(
            project_root=project, cfg=LauncherConfig(), private_key=other_key,
            playbook_name="prepare_server", inventory_name="dev", hostname="test-host",
            extra_vars=[], check=False, diff=False, limit=None,
            tags=None, skip_tags=None, forks=None, verbose=0,
            temp_dir=str(tmp_path), allow_disk_temp=True,
        )


def test_run_rejects_conflicting_hostname(project, rsa_key, tmp_path):
    setup_encrypted_project(project, rsa_key)
    with pytest.raises(LauncherError, match="Hostname"):
        run_playbook(
            project_root=project, cfg=LauncherConfig(), private_key=rsa_key,
            playbook_name="prepare_server", inventory_name="dev", hostname="test-host",
            extra_vars=["hostname=other"], check=False, diff=False, limit=None,
            tags=None, skip_tags=None, forks=None, verbose=0,
            temp_dir=str(tmp_path), allow_disk_temp=True,
        )


def test_encrypt_master_and_inventory_cli(project, rsa_file, tmp_path, rsa_key):
    inventory_src = project / "inventory" / "dev.yml"
    inventory_src.write_text("all:\n  hosts: {}\n")
    password_src = tmp_path / "vault.pass"
    password_src.write_text("my vault secret\n")
    common = ["--project-root", str(project), "--key", str(rsa_file),
              "--config", str(tmp_path / "config.toml")]
    assert main(["encrypt-inventory", "--source", "inventory/dev.yml", *common]) == 0
    assert main(["encrypt-master", "--source", str(password_src), *common]) == 0
    assert (project / "inventory" / "dev.yml.enc").exists()
    assert (project / "vaults" / "master-password.enc").exists()
    assert password_src.exists()
    assert inventory_src.exists()
    assert main(["decrypt-inventory", "--source", "inventory/dev.yml.enc",
                 "--output", "inventory/temporary.yml", *common]) == 0
    assert (project / "inventory" / "temporary.yml").read_bytes() == inventory_src.read_bytes()


def test_sigterm_terminates_child_and_cleans_temp(project, rsa_file, rsa_key, tmp_path):
    """SIGTERM of the launcher must not leave cleartext files behind."""
    import signal
    import subprocess
    import sys
    import time

    setup_encrypted_project(project, rsa_key)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    marker = tmp_path / "started.json"
    child = bindir / "ansible-playbook"
    child.write_text(textwrap.dedent('''\
        #!/usr/bin/env python3
        import json,os,pathlib,time
        marker = pathlib.Path(os.environ['TEST_CAPTURE'])
        marker.write_text(json.dumps({
            'inventory_path':os.environ['ANSIBLE_INVENTORY'],
            'password_path':os.environ['ANSIBLE_VAULT_IDENTITY_LIST'].split('@', 1)[1],
        }))
        while True:
            time.sleep(0.1)
    '''))
    child.chmod(0o755)
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
    env["TEST_CAPTURE"] = str(marker)
    cmd = [sys.executable, "-m", "ansible_launcher", "run", "prepare_server",
           "--project-root", str(project), "--key", str(rsa_file),
           "--inventory", "dev", "--temp-dir", str(tmp_path), "--allow-disk-temp"]
    p = subprocess.Popen(cmd, cwd=project, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        for _ in range(80):
            if marker.exists():
                break
            if p.poll() is not None:
                raise AssertionError(f"Launcher exited early: {p.communicate()[1]}")
            time.sleep(0.05)
        assert marker.exists(), "The fake Ansible command did not start."
        paths = json.loads(marker.read_text())
        assert Path(paths["password_path"]).is_file()
        p.send_signal(signal.SIGTERM)
        assert p.wait(timeout=12) == 143
        assert not Path(paths["inventory_path"]).exists()
        assert not Path(paths["password_path"]).exists()
        assert not Path(paths["inventory_path"]).parent.exists()
    finally:
        if p.poll() is None:
            p.kill()
            p.wait()
