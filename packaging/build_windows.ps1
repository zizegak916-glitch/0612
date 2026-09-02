$ErrorActionPreference = "Stop"
$ProjectDirectory = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $ProjectDirectory
py -3 -m pip install --upgrade pyinstaller keyring
pyinstaller --clean --paths src --onefile --name ipbatch-cli scripts/ip_inspector.py
pyinstaller --clean --paths src --onefile --windowed --name IPBatchInspector apps/desktop/launcher.py
Write-Host "Built dist/ipbatch-cli.exe and dist/IPBatchInspector.exe"
