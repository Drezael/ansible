#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
LAUNCHER_DIR="${ROOT_DIR}/launcher"
VENV_DIR="${LAUNCHER_DIR}/.venv"
REQUIREMENTS_FILE="${LAUNCHER_DIR}/requirements.txt"

if [[ ! -f "${REQUIREMENTS_FILE}" ]]; then
    printf 'Fehler: requirements.txt nicht gefunden: %s\n' "${REQUIREMENTS_FILE}" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    printf 'Fehler: python3 ist nicht installiert.\n' >&2
    exit 1
fi

if [[ -e "${VENV_DIR}" || -L "${VENV_DIR}" ]]; then
    rm -rf -- "${VENV_DIR}"
fi

python3 -m venv "${VENV_DIR}"

"${VENV_DIR}/bin/python" -m pip install --upgrade pip
"${VENV_DIR}/bin/python" -m pip install -r "${REQUIREMENTS_FILE}"