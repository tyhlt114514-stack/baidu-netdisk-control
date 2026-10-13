param(
    [ValidateSet('pcs','openapi')][string]$Backend,
    [string]$ClientId,
    [string]$AppName,
    [switch]$Login,
    [ValidateSet('cookie','bduss','qr')][string]$LoginMethod = 'cookie',
    [switch]$LoginGui,
    [switch]$InstallMcp
)
$ErrorActionPreference = 'Stop'
$netdiskIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($env:USERNAME -and ($netdiskIdentity.Name.Split('\')[-1] -ne $env:USERNAME)) {
    throw 'Run setup from the signed-in Windows user, not an agent sandbox account.'
}
$netdiskRoot = $PSScriptRoot
$netdiskRuntime = Join-Path $netdiskRoot 'runtime.json'
if (Test-Path -LiteralPath $netdiskRuntime) {
    $netdiskPython = (Get-Content -Raw -Encoding UTF8 -LiteralPath $netdiskRuntime | ConvertFrom-Json).python
} else {
    $netdiskPython = (Get-Command python -ErrorAction Stop).Source
}
& $netdiskPython -c 'import mcp.server.fastmcp' 2>$null
if ($LASTEXITCODE -ne 0) {
    & $netdiskPython -m venv (Join-Path $netdiskRoot '.venv')
    if ($LASTEXITCODE -ne 0) { throw 'Could not create Python environment.' }
    $netdiskPython = Join-Path $netdiskRoot '.venv\Scripts\python.exe'
    & $netdiskPython -m pip install -r (Join-Path $netdiskRoot 'requirements.txt')
    if ($LASTEXITCODE -ne 0) { throw 'Could not install MCP runtime.' }
}
$netdiskConfigureArgs = @((Join-Path $netdiskRoot 'tools\configure.py'))
if ($Backend) { $netdiskConfigureArgs += @('--backend', $Backend) }
if ($ClientId) { $netdiskConfigureArgs += @('--client-id', $ClientId) }
if ($AppName) { $netdiskConfigureArgs += @('--app-name', $AppName) }
& $netdiskPython @netdiskConfigureArgs
if ($LASTEXITCODE -ne 0) { throw 'Could not write plugin configuration.' }
$netdiskConfig = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $netdiskRoot 'config.json') | ConvertFrom-Json
$netdiskPrivate = [IO.Path]::GetFullPath($netdiskConfig.state_dir)
New-Item -ItemType Directory -Force -Path $netdiskPrivate | Out-Null
# BaiduPCS-Go stores session cookies in its config; restrict the directory to this Windows user.
$netdiskSid = $netdiskIdentity.User.Value
& icacls.exe $netdiskPrivate '/inheritance:r' '/grant:r' ('*' + $netdiskSid + ':(OI)(CI)F') | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict private directory permissions.' }
if ($netdiskConfig.backend -eq 'pcs' -and -not (Test-Path -LiteralPath $netdiskConfig.pcs_executable)) {
    & $netdiskPython (Join-Path $netdiskRoot 'tools\bootstrap.py')
    if ($LASTEXITCODE -ne 0) { throw 'Could not install the verified BaiduPCS-Go release.' }
}
if ($Login) {
    $netdiskLoginArgs = @((Join-Path $netdiskRoot 'cli.py'), 'login', '--method', $LoginMethod)
    if ($LoginGui) { $netdiskLoginArgs += '--gui' }
    & $netdiskPython @netdiskLoginArgs
    if ($LASTEXITCODE -ne 0) {
        $netdiskLoginExit = $LASTEXITCODE
        Write-Host 'Login did not complete. See the safe error details above or run cli.py login-status.'
        exit $netdiskLoginExit
    }
}
if ($InstallMcp) { & (Join-Path $netdiskRoot 'install.ps1') }
& $netdiskPython (Join-Path $netdiskRoot 'cli.py') status
