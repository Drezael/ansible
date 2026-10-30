"""Root launcher lists renamed playbooks without requiring the virtual environment."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from ansible_launcher.executor import PLAYBOOK_NAME_RE
from ansible_launcher.menu import InteractiveMenu

ROOT = Path(__file__).resolve().parents[2]
ENTRY = ROOT / "launch.py"
CURRENT_NAMES = [
    "server.bootstrap.yml",
    "server.prepare.yml",
    "server.secrets.generate.yml",
    "server.secrets.rotate.yml",
]


def test_list_without_venv_from_another_directory(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "playbooks").mkdir()
    (root / "launch.py").write_bytes(ENTRY.read_bytes())
    for name in reversed(CURRENT_NAMES):
        (root / "playbooks" / name).write_text("---\n- hosts: all\n  tasks: []\n")
    (root / "playbooks" / "not-a-playbook.txt").write_text("ignore")
    (root / "playbooks" / "directory.yaml").mkdir()
    run = subprocess.run(
        [sys.executable, str(root / "launch.py"), "--playbooks_list"],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert run.returncode == 0, run.stderr
    assert run.stdout.splitlines()[1:] == [f"  {name}" for name in CURRENT_NAMES]
    assert "not-a-playbook" not in run.stdout
    assert "directory.yaml" not in run.stdout
    assert not (root / "launcher").exists()


def test_list_empty_and_missing_directory(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "launch.py").write_bytes(ENTRY.read_bytes())
    missing = subprocess.run([sys.executable, str(root / "launch.py"), "--playbooks_list"], capture_output=True, text=True)
    assert missing.returncode == 2
    assert "Playbook-Verzeichnis fehlt" in missing.stderr
    (root / "playbooks").mkdir()
    empty = subprocess.run([sys.executable, str(root / "launch.py"), "--playbooks_list"], capture_output=True, text=True)
    assert empty.returncode == 0
    assert "Keine Playbooks" in empty.stdout


def test_parser_avoids_conflicting_subcommands():
    run = subprocess.run([sys.executable, str(ENTRY), "--playbooks_list", "status"], capture_output=True, text=True)
    assert run.returncode == 2
    assert "nicht mit einem Unterbefehl" in run.stderr


def test_dotted_playbooks_are_valid():
    assert PLAYBOOK_NAME_RE.fullmatch("server.prepare")
    assert PLAYBOOK_NAME_RE.fullmatch("server.secrets.rotate")
    assert not PLAYBOOK_NAME_RE.fullmatch("../server.prepare")
    assert not PLAYBOOK_NAME_RE.fullmatch("bad..name")


def test_interactive_menu_lists_dotted_playbook_names(project, tmp_path, monkeypatch):
    for f in (project / "playbooks").glob("*.yml"):
        f.unlink()
    (project / "playbooks" / "server.prepare.yml").write_text("---\n- hosts: all\n  tasks: []\n")
    (project / "inventory" / "dev.yml.enc").write_bytes(b"dummy")
    monkeypatch.setenv("HOME", str(tmp_path))
    inputs = iter(["1", "1", "1", "", "", "n", "n", "n", "j", "0"])
    calls: list[list[str]] = []
    menu = InteractiveMenu(
        project, lambda args: calls.append(args) or 0,
        input_fn=lambda _prompt: next(inputs), output=lambda _msg: None,
    )
    assert menu.run() == 0
    assert calls and calls[0][:4] == ["run", "server.prepare", "--inventory", "dev"]


def test_dotted_name_runs_with_encrypted_inventory(project, rsa_key, tmp_path, monkeypatch):
    from ansible_launcher.config import LauncherConfig
    from ansible_launcher.crypto import encrypt_bytes
    from ansible_launcher.executor import run_playbook
    (project / "playbooks" / "server.prepare.yml").write_text("---\n- hosts: all\n  tasks: []\n")
    (project / "inventory" / "dev.yml.enc").write_bytes(
        encrypt_bytes(b"all:\n  hosts: {}\n", rsa_key.public_key(), "inventory")
    )
    (project / "vaults" / "master-password.enc").write_bytes(
        encrypt_bytes(b"test-password\n", rsa_key.public_key(), "vault-password")
    )
    captured: dict = {}

    def dummy_execute(argv, root, env):
        captured["argv"] = argv
        captured["root"] = root
        return 0

    monkeypatch.setattr("ansible_launcher.executor._execute", dummy_execute)
    result = run_playbook(
        project_root=project, cfg=LauncherConfig(), private_key=rsa_key,
        playbook_name="server.prepare", inventory_name="dev", hostname="test-host",
        extra_vars=[], check=False, diff=False, limit=None, tags=None,
        skip_tags=None, forks=None, verbose=0,
        temp_dir=str(tmp_path), allow_disk_temp=True,
    )
    assert result == 0
    assert str(project / "playbooks" / "server.prepare.yml") in captured["argv"]
