#requires -Version 7.0
<#
Exercise the unchanged, published Windows ZIP in a disposable profile.
No KICK login, viewer verification, or live moderation is performed.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'This smoke test requires Windows.' }

function Assert-Check([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
    Write-Host "PASS: $Message"
}

$repoRoot = Split-Path $PSScriptRoot -Parent
$manifest = Get-Content (Join-Path $repoRoot 'release.json') -Raw | ConvertFrom-Json
$uri = [uri]$manifest.download_url
Assert-Check ($uri.Scheme -eq 'https' -and $uri.Host -eq 'streamshield-protection-public.vercel.app' -and $uri.IsDefaultPort -and -not $uri.UserInfo -and -not $uri.Query -and -not $uri.Fragment) 'Release URL is on the exact allowed HTTPS host.'
Assert-Check ($manifest.sha256 -match '^[a-f0-9]{64}$') 'Manifest contains a SHA-256 digest.'
Assert-Check ($manifest.size_bytes -gt 0 -and $manifest.size_bytes -lt 50000000) 'Release size is within the smoke-test limit.'

$tempBase = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
$work = Join-Path $tempBase ('streamshield-smoke-' + [guid]::NewGuid().ToString('N'))
$profile = Join-Path $work 'profile'
$localAppData = Join-Path $profile 'AppData/Local'
$installRoot = Join-Path $localAppData 'StreamShield Protection'
$runtime = Join-Path $installRoot 'runtime/node.exe'
$extractRoot = Join-Path $work 'published'
$healthUrl = 'http://localhost:8787/health'
$overrideNames = @('LOCALAPPDATA','USERPROFILE','TEMP','TMP','DATA_DIR','PORT','PUBLIC_BASE_URL','STREAMSHIELD_REMOTE_BACKEND_URL','STREAMSHIELD_PUBLIC_OAUTH','KICK_CLIENT_ID','KICK_CLIENT_SECRET','KICK_WEBHOOK_PUBLIC_URL','NODE_OPTIONS')
$savedEnv = @{}
foreach ($name in $overrideNames) { $savedEnv[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
$success = $false

function Stop-TestServer {
    # Never kill other node.exe instances or use the user's own stop/uninstall tools.
    $ours = @(Get-CimInstance Win32_Process -Filter "Name='node.exe'" | Where-Object { $_.ExecutablePath -and $_.ExecutablePath -ieq $runtime })
    foreach ($item in $ours) { Stop-Process -Id $item.ProcessId -Force -ErrorAction SilentlyContinue }
    if ($ours.Count) { Start-Sleep -Seconds 1 }
}

function Invoke-PublishedInstaller([string]$Label) {
    $stdout = Join-Path $work "$Label.stdout.log"
    $stderr = Join-Path $work "$Label.stderr.log"
    $installer = Join-Path $extractRoot 'Install StreamShield.cmd'
    $arguments = '/d /s /c ""' + $installer + '" < NUL"'
    $process = Start-Process -FilePath $env:ComSpec -ArgumentList $arguments -WorkingDirectory $extractRoot -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
    [void]$process.Handle
    if (-not $process.WaitForExit(180000)) {
        $process.Kill($true)
        throw "$Label installer exceeded three minutes."
    }
    if ($process.ExitCode -ne 0) {
        Get-Content $stdout, $stderr -ErrorAction SilentlyContinue | Write-Host
        throw "$Label installer returned exit code $($process.ExitCode)."
    }
    $health = $null
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        try { $health = Invoke-RestMethod $healthUrl -TimeoutSec 2; break }
        catch { Start-Sleep -Milliseconds 500 }
    }
    Assert-Check ($null -ne $health -and $health.ok -eq $true) "${Label}: installed application starts and reports health."
    Assert-Check ($health.sessions -eq 0 -and $health.publicOauthBroker -eq $false -and $health.remoteBackendConfigured -eq $false -and $health.kickConfigured -eq $false) "${Label}: no account is connected and KICK/cloud access is disabled."
    Assert-Check ($health.encryptedStateAtRest -eq $true) "${Label}: encrypted-state support is enabled."
    $page = Invoke-WebRequest 'http://localhost:8787/' -TimeoutSec 5
    Assert-Check ($page.StatusCode -eq 200 -and $page.Headers.'Content-Type' -like '*text/html*' -and $page.Content -match 'StreamShield') "${Label}: application serves the HTML landing page."
    $guard = Invoke-WebRequest 'http://localhost:8787/api/network-history' -SkipHttpErrorCheck -TimeoutSec 5
    Assert-Check ($guard.StatusCode -eq 401) "${Label}: private network history rejects unauthenticated access."
}

try {
    New-Item -ItemType Directory -Force -Path $work, $localAppData, (Join-Path $profile 'Desktop'), (Join-Path $work 'temp') | Out-Null
    $listener = @(Get-NetTCPConnection -LocalPort 8787 -State Listen -ErrorAction SilentlyContinue)
    Assert-Check ($listener.Count -eq 0) 'Port 8787 is unused before installation.'
    $zipPath = Join-Path $work 'release.zip'
    Invoke-WebRequest -Uri $uri -OutFile $zipPath -MaximumRedirection 0 -TimeoutSec 90
    Assert-Check ((Get-Item $zipPath).Length -eq $manifest.size_bytes) 'Downloaded ZIP length matches the committed manifest.'
    Assert-Check ((Get-FileHash $zipPath -Algorithm SHA256).Hash.ToLowerInvariant() -eq $manifest.sha256) 'Downloaded ZIP SHA-256 matches the committed manifest.'
    $archive = [IO.Compression.ZipFile]::OpenRead($zipPath)
    try {
        $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $total = 0L
        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName.Replace('\','/')
            if ($name.StartsWith('/') -or $name.Contains(':') -or @($name.Split('/') | Where-Object { $_ -eq '..' }).Count -gt 0 -or -not $names.Add($name)) { throw 'Unsafe or duplicate ZIP entry.' }
            $total += $entry.Length
            if ($total -gt 100000000) { throw 'ZIP exceeds expanded-size limit.' }
        }
    } finally { $archive.Dispose() }
    Expand-Archive -LiteralPath $zipPath -DestinationPath $extractRoot
    $package = Get-Content (Join-Path $extractRoot 'app/package.json') -Raw | ConvertFrom-Json
    Assert-Check ($package.version -eq $manifest.version) 'Packaged application version matches the release.'

    $env:LOCALAPPDATA = $localAppData
    $env:USERPROFILE = $profile
    $env:TEMP = Join-Path $work 'temp'
    $env:TMP = $env:TEMP
    $env:DATA_DIR = Join-Path $installRoot 'app/data'
    $env:PORT = '8787'
    $env:PUBLIC_BASE_URL = 'http://localhost:8787'
    # A non-HTTPS loopback URL disables the remote backend before any session exists.
    $env:STREAMSHIELD_REMOTE_BACKEND_URL = 'http://127.0.0.1:9'
    $env:STREAMSHIELD_PUBLIC_OAUTH = '0'
    $env:KICK_CLIENT_ID = ''
    $env:KICK_CLIENT_SECRET = ''
    $env:KICK_WEBHOOK_PUBLIC_URL = ''
    # Defense in depth: reject all app fetches, without changing distributed files.
    $guardPath = Join-Path $work 'no-network.cjs'
    Set-Content $guardPath 'globalThis.fetch = async () => { throw new Error("Windows smoke test: app network access is disabled"); };' -Encoding utf8
    $env:NODE_OPTIONS = '--require="' + $guardPath + '"'

    Invoke-PublishedInstaller 'Fresh installation'
    Assert-Check (Test-Path $runtime) 'Installer supplies its own Node.js runtime.'
    $installedVersion = (& $runtime --version).Trim()
    $installerText = Get-Content (Join-Path $extractRoot 'Install StreamShield.cmd') -Raw
    $versionMatch = [regex]::Match($installerText, 'set "NODEVER=([0-9.]+)"')
    Assert-Check ($versionMatch.Success -and $installedVersion -eq ('v' + $versionMatch.Groups[1].Value)) 'Installed Node.js version matches the installer pin.'
    foreach ($name in @('StreamShield Protection.cmd','Uninstall StreamShield.cmd')) {
        Assert-Check (Test-Path (Join-Path $profile "Desktop/$name")) "Desktop launcher was created: $name"
    }
    foreach ($name in @('OBS_SETUP.txt','StreamShield_Full_Overlay.png','StreamShield_Horizontal_Overlay.png','StreamShield_Shield_Badge.png','StreamShield_Brand_Kit_Preview.png')) {
        $source = Join-Path $extractRoot "Streamer Branding/$name"
        $target = Join-Path $installRoot "Streamer Branding/$name"
        Assert-Check ((Test-Path $target) -and (Get-FileHash $source).Hash -eq (Get-FileHash $target).Hash) "OBS branding copied intact: $name"
    }
    Stop-TestServer
    $marker = Join-Path $env:DATA_DIR 'smoke-preservation.txt'
    $markerValue = [guid]::NewGuid().ToString('N')
    Set-Content $marker $markerValue -NoNewline
    Invoke-PublishedInstaller 'Reinstallation'
    Assert-Check ((Get-Content $marker -Raw) -eq $markerValue) 'Reinstallation preserves existing application data.'
    $success = $true
    Write-Host "PASS: published $($manifest.version) installer and reinstallation smoke test on Windows."
} finally {
    Stop-TestServer
    foreach ($name in $overrideNames) { [Environment]::SetEnvironmentVariable($name, $savedEnv[$name], 'Process') }
    $result = if ($success) { 'PASS' } else { 'FAIL' }
    $summary = "## Windows published-release smoke test: $result`n`nVersion: $($manifest.version)`n`nThe test uses a disposable profile and the unchanged, checksum-verified published ZIP. No KICK account, viewer OAuth, or live moderation is tested. Reinstallation only checks synthetic local-data preservation; it does not establish real-account migration correctness.`n"
    if ($env:GITHUB_STEP_SUMMARY) { Add-Content $env:GITHUB_STEP_SUMMARY $summary }
    Write-Host "Smoke-test workspace: $work"
}
