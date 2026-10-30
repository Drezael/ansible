"""Integration tests for root launch.py and its venv worker (no real host access)."""

import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import textwrap
import time

from ansible_launcher.crypto import encrypt_bytes


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "launch.py"
VENV_BIN = ROOT / "launcher" / ".venv" / "bin"


def _venv(monkeypatch):
    VENV_BIN.mkdir(parents=True, exist_ok=True)
    interpreter = VENV_BIN / "python"
    if interpreter.exists() or interpreter.is_symlink():
        interpreter.unlink()
    interpreter.symlink_to(sys.executable)
    return interpreter


def _run(*args, env=None):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *map(str, args)],
        cwd="/tmp",
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=40,
    )


def test_parser_help_works_without_venv(tmp_path):
    copied = tmp_path / "launch.py"
    shutil.copyfile(SCRIPT, copied)
    result = subprocess.run([sys.executable, str(copied), "--help"], capture_output=True, text=True)
    assert result.returncode == 0
    assert "run" in result.stdout
    result = subprocess.run([sys.executable, str(copied), "run", "prepare_server"], capture_output=True, text=True)
    assert result.returncode == 2
    assert "--inventory" in result.stderr


def test_venv_absent_has_actionable_error(tmp_path):
    root = tmp_path / "isolated"
    root.mkdir()
    shutil.copyfile(SCRIPT, root / "launch.py")
    result = subprocess.run([sys.executable, str(root / "launch.py"), "status"], capture_output=True, text=True)
    assert result.returncode == 2
    assert "launcher/.venv" in result.stderr


def test_status_is_executed_by_venv(tmp_path, monkeypatch):
    _venv(monkeypatch)
    result = _run("status", "--project-root", tmp_path, "--config", tmp_path / "no-config.toml")
    assert result.returncode == 0, result.stderr
    assert "Ansible Launcher - Status" in result.stdout
    assert str(tmp_path) in result.stdout


def test_encrypt_inventory_uses_parsed_args_and_venv(project, rsa_file, rsa_key, tmp_path, monkeypatch):
    _venv(monkeypatch)
    source = project / "inventory" / "dev.yml"
    source.write_text("all:\n  hosts: {}\n")
    result = _run(
        "encrypt-inventory", "--source", "inventory/dev.yml",
        "--project-root", project, "--key", rsa_file,
        "--config", tmp_path / "does-not-exist.toml",
    )
    assert result.returncode == 0, result.stderr
    assert (project / "inventory" / "dev.yml.enc").is_file()
    assert source.exists()


def test_run_with_encrypted_files(project, rsa_file, rsa_key, tmp_path, monkeypatch):
    _venv(monkeypatch)
    inventory = b"all:\n  hosts:\n    test-host:\n      ansible_host: 127.0.0.1\n"
    password = b"test-vault-password\n"
    (project / "inventory" / "dev.yml.enc").write_bytes(
        encrypt_bytes(inventory, rsa_key.public_key(), "inventory"))
    (project / "vaults" / "master-password.enc").write_bytes(
        encrypt_bytes(password, rsa_key.public_key(), "vault-password"))

    fake_bin = VENV_BIN
    fake = fake_bin / "ansible-playbook"
    fake.write_text(textwrap.dedent('''\
        #!/usr/bin/env python3
        import json, os, pathlib, sys
        inv = pathlib.Path(os.environ['ANSIBLE_INVENTORY'])
        vault = pathlib.Path(os.environ['ANSIBLE_VAULT_IDENTITY_LIST'].split('@', 1)[1])
        pathlib.Path(os.environ['CAPTURE_FILE']).write_text(json.dumps({
            'argv': sys.argv[1:],
            'executable': sys.executable,
            'inventory': inv.read_text(),
            'password': vault.read_text(),
            'path': str(inv),
            'vault_path': str(vault),
            'cwd': str(pathlib.Path.cwd()),
        }))
        sys.exit(17)
    '''))
    fake.chmod(0o755)
    capture = tmp_path / "captured.json"
    env = os.environ.copy()
    env["CAPTURE_FILE"] = str(capture)
    result = _run(
        "run", "prepare_server", "--inventory", "dev", "--hostname", "test-host",
        "-e", "value=some text", "--check", "-vv",
        "--project-root", project, "--key", rsa_file,
        "--temp-dir", tmp_path, "--allow-disk-temp",
        env=env,
    )
    assert result.returncode == 17, (result.stdout, result.stderr)
    data = json.loads(capture.read_text())
    assert data["inventory"] == inventory.decode()
    assert data["password"] == password.decode()
    assert data["cwd"] == str(project)
    assert "--check" in data["argv"]
    assert "-vv" in data["argv"]
    assert "hostname=test-host" in data["argv"]
    assert "value=some text" in data["argv"]
    assert not Path(data["path"]).exists()
    assert not Path(data["vault_path"]).exists()


def test_root_sigterm_propagates_and_cleans_files(project, rsa_file, rsa_key, tmp_path, monkeypatch):
    _venv(monkeypatch)
    (project / "inventory" / "dev.yml.enc").write_bytes(
        encrypt_bytes(b"all:\n  hosts: {}\n", rsa_key.public_key(), "inventory"))
    (project / "vaults" / "master-password.enc").write_bytes(
        encrypt_bytes(b"vaultpw\n", rsa_key.public_key(), "vault-password"))
    fake_bin = VENV_BIN
    fake = fake_bin / "ansible-playbook"
    fake.write_text(textwrap.dedent('''\
        #!/usr/bin/env python3
        import json, os, pathlib, time
        pathlib.Path(os.environ['CAPTURE_FILE']).write_text(json.dumps({
            'inventory': os.environ['ANSIBLE_INVENTORY'],
            'password': os.environ['ANSIBLE_VAULT_IDENTITY_LIST'].split('@', 1)[1],
        }))
        while True: time.sleep(0.1)
    '''))
    fake.chmod(0o755)
    marker = tmp_path / "marker.json"
    env = os.environ.copy()
    env["CAPTURE_FILE"] = str(marker)
    process = subprocess.Popen([
        sys.executable, str(SCRIPT), "run", "prepare_server", "--inventory", "dev",
        "--key", str(rsa_file), "--project-root", str(project),
        "--temp-dir", str(tmp_path), "--allow-disk-temp",
    ], env=env, cwd="/tmp", stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        for _ in range(100):
            if marker.is_file():
                break
            if process.poll() is not None:
                raise AssertionError(process.communicate()[1].decode())
            time.sleep(.05)
        assert marker.exists()
        paths = json.loads(marker.read_text())
        assert Path(paths["password"]).exists()
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=20) == 143
        assert not Path(paths["inventory"]).exists()
        assert not Path(paths["password"]).exists()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def test_run_rejects_venv_without_ansible_binary(tmp_path, monkeypatch):
    _venv(monkeypatch)
    ansible_binary = VENV_BIN / "ansible-playbook"
    if ansible_binary.exists():
        ansible_binary.unlink()
    result = _run("run", "prepare_server", "--inventory", "dev")
    assert result.returncode == 2
    assert "ansible-playbook fehlt im virtuellen Environment" in result.stderr
