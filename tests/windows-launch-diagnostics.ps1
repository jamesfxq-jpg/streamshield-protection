#requires -Version 7.0
# Diagnostics only. Never turns a failed installer smoke test into a pass.
$ErrorActionPreference = 'Stop'
$work = Get-ChildItem $env:RUNNER_TEMP -Directory -Filter 'streamshield-smoke-*' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $work) { throw 'No disposable smoke-test workspace exists.' }
$profile = Join-Path $work.FullName 'profile'
$root = Join-Path $profile 'AppData/Local/StreamShield Protection'
$node = Join-Path $root 'runtime/node.exe'
$app = Join-Path $root 'app'
foreach ($log in Get-ChildItem $work.FullName -File -Filter '*.log') {
    Write-Host "--- $($log.Name) ---"
    Get-Content $log.FullName -Tail 45 | Write-Host
}
Write-Host ('Installed executable exists: ' + (Test-Path $node))
Write-Host ('Installed server exists: ' + (Test-Path (Join-Path $app 'dist/src/server.js')))
if (-not (Test-Path $node)) { throw 'Runtime was not installed.' }
$env:LOCALAPPDATA = Join-Path $profile 'AppData/Local'
$env:USERPROFILE = $profile
$env:DATA_DIR = Join-Path $app 'data'
$env:PUBLIC_BASE_URL = 'http://localhost:8787'
$env:PORT = '8787'
$env:STREAMSHIELD_REMOTE_BACKEND_URL = 'http://127.0.0.1:9'
$env:STREAMSHIELD_PUBLIC_OAUTH = '0'
$env:KICK_CLIENT_ID = ''
$env:KICK_CLIENT_SECRET = ''
$env:KICK_WEBHOOK_PUBLIC_URL = ''
$env:NODE_OPTIONS = '--require="' + (Join-Path $work.FullName 'no-network.cjs') + '"'
& $node --version
$stdout = Join-Path $work.FullName 'direct-start.stdout.log'
$stderr = Join-Path $work.FullName 'direct-start.stderr.log'
$process = $null
try {
    $process = Start-Process -FilePath $node -ArgumentList 'dist/src/server.js' -WorkingDirectory $app -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
    [void]$process.Handle
    Start-Sleep -Seconds 3
    $process.Refresh()
    Write-Host ('Direct startup exited: ' + $process.HasExited)
    if ($process.HasExited) { Write-Host ('Direct startup exit code: ' + $process.ExitCode) }
    foreach ($url in @('http://127.0.0.1:8787/health','http://localhost:8787/health')) {
        try { Write-Host ($url + ' -> ' + (Invoke-WebRequest $url -TimeoutSec 3).StatusCode) }
        catch { Write-Host ($url + ' -> ' + $_.Exception.Message) }
    }
} finally {
    if ($process -and -not $process.HasExited) { $process.Kill($true) }
    foreach ($path in @($stdout,$stderr)) {
        Write-Host "--- $([IO.Path]::GetFileName($path)) ---"
        if (Test-Path $path) { Get-Content $path -Tail 60 | Write-Host }
    }
}
