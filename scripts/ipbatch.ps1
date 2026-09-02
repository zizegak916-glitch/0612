$ErrorActionPreference = "Stop"
$ScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$EntryPoint = Join-Path $ScriptDirectory "ip_inspector.py"

if (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 $EntryPoint @args
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    & python $EntryPoint @args
} else {
    throw "Python 3.10 or newer is required."
}
exit $LASTEXITCODE
