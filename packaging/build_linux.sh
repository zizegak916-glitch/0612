#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"
python3 -m pip install --upgrade pyinstaller keyring
pyinstaller --clean --paths src --onefile --name ipbatch-cli scripts/ip_inspector.py
pyinstaller --clean --paths src --onefile --windowed --name IPBatchInspector apps/desktop/launcher.py
echo "Built dist/ipbatch-cli and dist/IPBatchInspector"
