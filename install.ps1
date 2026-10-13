param([ValidateSet('plugin','mcp')][string]$Mode = 'plugin')
$ErrorActionPreference = 'Stop'
$netdiskRoot = $PSScriptRoot
$netdiskPython = (Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $netdiskRoot 'runtime.json') | ConvertFrom-Json).python
if ($Mode -eq 'plugin') {
    & codex plugin marketplace add $netdiskRoot --json
    if ($LASTEXITCODE -ne 0) { throw 'Could not register the local plugin marketplace.' }
    & codex plugin add 'baidu-netdisk-control@baidu-netdisk-local' --json
    if ($LASTEXITCODE -ne 0) { throw 'Could not install the plugin.' }
} else {
    & codex mcp add baidu-netdisk -- $netdiskPython '-X' 'utf8' (Join-Path $netdiskRoot 'server.py') --config (Join-Path $netdiskRoot 'config.json')
    if ($LASTEXITCODE -ne 0) { throw 'Could not register the MCP server.' }
}
Write-Host 'Installed. Reload Codex or open a new chat to discover the tools.'
