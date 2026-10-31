"""Only loading simple text paths is tested, no file encryption occurs."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "launch.py"
SAMPLE_FILES = ["inventory/dev.yml", "vaults/master-password"]


def load_launcher():
    spec = importlib.util.spec_from_file_location("standalone_ansible_launcher", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_loads_plain_lines_without_accessing_sources(tmp_path, monkeypatch):
    launcher = load_launcher()
    file_list = tmp_path / "encryption-files.txt"
    file_list.write_text(
        "# Verschluesselungsliste\n\n"
        "inventory/dev.yml\n"
        "vaults/master-password\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(launcher, "ENCRYPTION_FILES_PATH", file_list)
    assert launcher._load_encryption_file_list() == SAMPLE_FILES
    assert list(tmp_path.iterdir()) == [file_list]


def test_empty_list_is_allowed(tmp_path, monkeypatch):
    launcher = load_launcher()
    file_list = tmp_path / "encryption-files.txt"
    file_list.write_text("# Noch keine Dateien\n\n", encoding="utf-8")
    monkeypatch.setattr(launcher, "ENCRYPTION_FILES_PATH", file_list)
    assert launcher._load_encryption_file_list() == []


@pytest.mark.parametrize(
    "content, error",
    [
        ("../secret\n", "Ungueltiger relativer Pfad"),
        ("/etc/passwd\n", "Ungueltiger relativer Pfad"),
        ("inventory//dev.yml\n", "Ungueltiger relativer Pfad"),
        ("inventory/./dev.yml\n", "Ungueltiger relativer Pfad"),
        ("inventory\\dev.yml\n", "Ungueltiger relativer Pfad"),
        ("inventory/dev.yml\ninventory/dev.yml\n", "mehrfach vorhanden"),
    ],
)
def test_rejects_invalid_paths(tmp_path, monkeypatch, content, error):
    launcher = load_launcher()
    file_list = tmp_path / "encryption-files.txt"
    file_list.write_text(content, encoding="utf-8")
    monkeypatch.setattr(launcher, "ENCRYPTION_FILES_PATH", file_list)
    with pytest.raises(ValueError, match=error):
        launcher._load_encryption_file_list()


def test_missing_file_list(tmp_path, monkeypatch):
    launcher = load_launcher()
    monkeypatch.setattr(launcher, "ENCRYPTION_FILES_PATH", tmp_path / "missing.txt")
    with pytest.raises(ValueError, match="konnte nicht geladen werden"):
        launcher._load_encryption_file_list()


def test_launcher_forwards_file_list_without_encrypting(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    shutil.copyfile(SCRIPT, repo / "launch.py")
    launcher_dir = repo / "launcher"
    launcher_dir.mkdir()
    (launcher_dir / "encryption-files.txt").write_text(
        "\n".join(SAMPLE_FILES) + "\n", encoding="utf-8"
    )
    venv_bin = launcher_dir / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    (venv_bin / "python").symlink_to(sys.executable)
    package = launcher_dir / "src" / "ansible_launcher"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (package / "worker.py").write_text(
        "import json, os, sys\n"
        "with os.fdopen(int(sys.argv[1]), 'rb') as stream:\n"
        "    command = json.load(stream)\n"
        "print(json.dumps(command['encryption_files']))\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [sys.executable, str(repo / "launch.py"), "status"],
        capture_output=True, text=True, cwd=tmp_path,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == SAMPLE_FILES
    assert list(repo.rglob("*.enc")) == []


def test_launcher_rejects_invalid_list_before_worker(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    shutil.copyfile(SCRIPT, repo / "launch.py")
    launcher_dir = repo / "launcher"
    launcher_dir.mkdir()
    (launcher_dir / "encryption-files.txt").write_text("../secret\n", encoding="utf-8")
    venv_bin = launcher_dir / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    (venv_bin / "python").symlink_to(sys.executable)
    package = launcher_dir / "src" / "ansible_launcher"
    package.mkdir(parents=True)
    (package / "worker.py").write_text("raise RuntimeError('should not run')\n")
    result = subprocess.run(
        [sys.executable, str(repo / "launch.py"), "status"],
        capture_output=True, text=True, cwd=tmp_path,
    )
    assert result.returncode == 2
    assert "Ungueltiger relativer Pfad" in result.stderr
    assert "should not run" not in result.stderr
