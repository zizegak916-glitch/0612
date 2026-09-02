$ErrorActionPreference = "Stop"
$ProjectDirectory = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $ProjectDirectory
py -3 -m pip install --upgrade pyinstaller keyring
py -3 -m PyInstaller --clean --paths src --onefile --name ipbatch-cli scripts/ip_inspector.py
py -3 -m PyInstaller --clean --paths src --onefile --windowed --name IPBatchInspector apps/desktop/launcher.py
Write-Host "Built dist/ipbatch-cli.exe and dist/IPBatchInspector.exe"
