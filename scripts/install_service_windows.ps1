$ErrorActionPreference = "Stop"
$ProjectDirectory = Resolve-Path (Join-Path $PSScriptRoot "..")
$ConfigDirectory = Join-Path $env:APPDATA "ipbatch-inspector"
$StateDirectory = Join-Path $env:LOCALAPPDATA "ipbatch-inspector\monitor-results"
$ConfigPath = Join-Path $ConfigDirectory "monitor.json"

py -3 -m pip install --user "$ProjectDirectory[secure-store]"
New-Item -ItemType Directory -Force $ConfigDirectory, $StateDirectory | Out-Null
if (-not (Test-Path $ConfigPath)) {
    $Config = Get-Content (Join-Path $ProjectDirectory "monitor.example.json") -Raw | ConvertFrom-Json
    $Config.output_directory = $StateDirectory
    $Config | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 $ConfigPath
}
$Python = (Get-Command py).Source
$Arguments = "-3 -m ipbatch_inspector monitor --config `"$ConfigPath`""
$Action = New-ScheduledTaskAction -Execute $Python -Argument $Arguments -WorkingDirectory $ProjectDirectory
$Trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$Principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName "IPBatchInspector Monitor" -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force | Out-Null
Start-ScheduledTask -TaskName "IPBatchInspector Monitor"
Write-Host "Installed current-user background task. Config: $ConfigPath"
