[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Archive,
    [Parameter(Mandatory = $true)]
    [string]$ChecksumFile,
    [Parameter(Mandatory = $true)]
    [string]$WorkDirectory,
    [Parameter(Mandatory = $true)]
    [string]$Repository
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$archivePath = (Resolve-Path -LiteralPath $Archive).Path
$checksumPath = (Resolve-Path -LiteralPath $ChecksumFile).Path
$repositoryPath = (Resolve-Path -LiteralPath $Repository).Path
$expectedHash = (Get-Content -LiteralPath $checksumPath -Raw).Trim().ToLowerInvariant()
if ($expectedHash -notmatch "^[0-9a-f]{64}$") {
    throw "Needle archive checksum file is malformed"
}
$actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualHash -ne $expectedHash) {
    throw "Needle archive checksum mismatch: expected $expectedHash, got $actualHash"
}

$work = [System.IO.Path]::GetFullPath($WorkDirectory)
if (Test-Path -LiteralPath $work) {
    if ((Get-ChildItem -LiteralPath $work -Force | Measure-Object).Count -ne 0) {
        throw "Needle package verification directory must be empty: $work"
    }
} else {
    [System.IO.Directory]::CreateDirectory($work) | Out-Null
}

$extracted = Join-Path $work "extracted"
$installed = Join-Path $work "installed"
$preservedInstalled = Join-Path $work "preserved-installed"
$data = Join-Path $work "data"
Expand-Archive -LiteralPath $archivePath -DestinationPath $extracted

$requiredArchiveFiles = @(
    "needle.exe",
    "install.ps1",
    "uninstall.ps1",
    "LICENSE.md",
    "README.md"
)
foreach ($relativePath in $requiredArchiveFiles) {
    $path = Join-Path $extracted $relativePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Needle archive is incomplete: missing $relativePath"
    }
}
if (Test-Path -LiteralPath (Join-Path $extracted "runtime")) {
    throw "Needle archive must not contain a bundled host runtime"
}

$packagedNeedle = Join-Path $extracted "needle.exe"
& $packagedNeedle --version | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Packaged Needle executable failed its version probe"
}

$legacyRuntime = Join-Path $installed "runtime"
$legacyRuntimeFiles = @(
    "bin\codex.exe",
    "bin\codex-code-mode-host.exe",
    "codex-path\rg.exe",
    "codex-resources\codex-command-runner.exe",
    "codex-resources\codex-windows-sandbox-setup.exe",
    "codex-package.json"
)
foreach ($relativePath in $legacyRuntimeFiles) {
    $path = Join-Path $legacyRuntime $relativePath
    [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($path)) | Out-Null
    Set-Content -LiteralPath $path -Value "legacy Needle runtime fixture"
}
$preservedInstallFile = Join-Path $installed "preserve.txt"
Set-Content -LiteralPath $preservedInstallFile -Value "unmanaged installation content"

& (Join-Path $extracted "install.ps1") -InstallDirectory $installed -SkipPathUpdate
$installedNeedle = Join-Path $installed "needle.exe"
$installedUninstaller = Join-Path $installed "uninstall.ps1"
foreach ($path in @($installedNeedle, $installedUninstaller)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Needle isolated installation is incomplete: missing $path"
    }
}
if (Test-Path -LiteralPath (Join-Path $installed "runtime")) {
    throw "Needle installer must remove the complete legacy managed runtime"
}
if (-not (Test-Path -LiteralPath $preservedInstallFile -PathType Leaf)) {
    throw "Needle installer removed unrelated installation content"
}

& $installedNeedle uninstall --help | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Installed Needle executable failed its uninstall help probe"
}
& $installedUninstaller `
    -ParentProcessId $PID `
    -InstallDirectory $installed `
    -Executable $installedNeedle `
    -ValidateOnly
if ($LASTEXITCODE -ne 0) {
    throw "Installed Needle uninstaller failed validation"
}

$stdout = Join-Path $work "serve.stdout"
$stderr = Join-Path $work "serve.stderr"
$arguments = @(
    "serve",
    "--data-dir", ('"{0}"' -f $data),
    "--repository", ('"{0}"' -f $repositoryPath)
)
$server = Start-Process `
    -FilePath $installedNeedle `
    -ArgumentList $arguments `
    -RedirectStandardOutput $stdout `
    -RedirectStandardError $stderr `
    -WindowStyle Hidden `
    -PassThru
try {
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    $launchUrl = $null
    while ([DateTime]::UtcNow -lt $deadline) {
        if (Test-Path -LiteralPath $stdout) {
            $launchUrl = Get-Content -LiteralPath $stdout | ForEach-Object {
                if ($_ -match "^Needle control plane: (http://.+)$") { $Matches[1] }
            } | Select-Object -First 1
        }
        if ($launchUrl) {
            break
        }
        if ($server.HasExited) {
            $serverError = if (Test-Path -LiteralPath $stderr) {
                Get-Content -LiteralPath $stderr -Raw
            } else {
                ""
            }
            throw "Installed Needle server exited before startup: $serverError"
        }
        Start-Sleep -Milliseconds 100
    }
    if (-not $launchUrl) {
        throw "Installed Needle server did not report a launch URL"
    }
    $response = Invoke-WebRequest -Uri $launchUrl -UseBasicParsing
    if ($response.StatusCode -ne 200 -or
        $response.Content -notmatch '<div id="root"></div>' -or
        $response.Content -match '__NEEDLE_CSRF__') {
        throw "Installed Needle executable did not serve its embedded web control plane"
    }
} finally {
    if (-not $server.HasExited) {
        Stop-Process -Id $server.Id -Force
        $server.WaitForExit()
    }
}

if ((Test-Path -LiteralPath $stderr) -and
    -not [string]::IsNullOrWhiteSpace((Get-Content -LiteralPath $stderr -Raw))) {
    throw "Installed Needle server wrote unexpected diagnostics: $(Get-Content -LiteralPath $stderr -Raw)"
}

& $installedUninstaller `
    -ParentProcessId ([int]::MaxValue) `
    -InstallDirectory $installed `
    -Executable $installedNeedle
foreach ($path in @($installedNeedle, $installedUninstaller)) {
    if (Test-Path -LiteralPath $path) {
        throw "Needle uninstaller did not remove managed file: $path"
    }
}
if (-not (Test-Path -LiteralPath $preservedInstallFile -PathType Leaf)) {
    throw "Needle uninstaller removed unrelated installation content"
}

$preservedRuntime = Join-Path $preservedInstalled "runtime"
$preservedRuntimeMarker = Join-Path $preservedRuntime "user-host.txt"
[System.IO.Directory]::CreateDirectory($preservedRuntime) | Out-Null
Set-Content -LiteralPath $preservedRuntimeMarker -Value "unmanaged user host fixture"
& (Join-Path $extracted "install.ps1") `
    -InstallDirectory $preservedInstalled `
    -SkipPathUpdate
$preservedNeedle = Join-Path $preservedInstalled "needle.exe"
$preservedUninstaller = Join-Path $preservedInstalled "uninstall.ps1"
if (-not (Test-Path -LiteralPath $preservedRuntimeMarker -PathType Leaf)) {
    throw "Needle installer removed an unmanaged host runtime"
}
& $preservedUninstaller `
    -ParentProcessId ([int]::MaxValue) `
    -InstallDirectory $preservedInstalled `
    -Executable $preservedNeedle
foreach ($path in @($preservedNeedle, $preservedUninstaller)) {
    if (Test-Path -LiteralPath $path) {
        throw "Needle uninstaller did not remove managed file: $path"
    }
}
if (-not (Test-Path -LiteralPath $preservedRuntimeMarker -PathType Leaf)) {
    throw "Needle uninstaller removed an unmanaged host runtime"
}

Write-Host "Needle Windows package verification passed."
