[CmdletBinding()]
param(
    [string]$SourceBinary = (Join-Path $PSScriptRoot "needle.exe"),
    [string]$SourceUninstaller = (Join-Path $PSScriptRoot "uninstall.ps1"),
    [string]$InstallDirectory = (Join-Path $env:LOCALAPPDATA "Programs\Needle"),
    [switch]$SkipPathUpdate
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not (Test-Path -LiteralPath $SourceBinary -PathType Leaf)) {
    throw "Needle binary was not found at $SourceBinary"
}
if (-not (Test-Path -LiteralPath $SourceUninstaller -PathType Leaf)) {
    throw "Needle's managed uninstaller was not found at $SourceUninstaller"
}

$source = (Resolve-Path -LiteralPath $SourceBinary).Path
$uninstallerSource = (Resolve-Path -LiteralPath $SourceUninstaller).Path
[System.IO.Directory]::CreateDirectory($InstallDirectory) | Out-Null
$separators = [char[]]@(
    [System.IO.Path]::DirectorySeparatorChar,
    [System.IO.Path]::AltDirectorySeparatorChar
)
$install = [System.IO.Path]::GetFullPath($InstallDirectory).TrimEnd($separators)
$legacyRuntime = Join-Path $install "runtime"
if (Test-Path -LiteralPath $legacyRuntime -PathType Container) {
    $legacyRuntime = [System.IO.Path]::GetFullPath($legacyRuntime).TrimEnd($separators)
    $comparer = [System.StringComparer]::OrdinalIgnoreCase
    if (-not $comparer.Equals([System.IO.Path]::GetDirectoryName($legacyRuntime), $install) -or
        -not $comparer.Equals([System.IO.Path]::GetFileName($legacyRuntime), "runtime")) {
        throw "Legacy Needle runtime is outside the installation directory"
    }
    $requiredLegacyRuntimeFiles = @(
        "bin\codex.exe",
        "bin\codex-code-mode-host.exe",
        "codex-path\rg.exe",
        "codex-resources\codex-command-runner.exe",
        "codex-resources\codex-windows-sandbox-setup.exe",
        "codex-package.json"
    )
    $legacyRuntimeItem = Get-Item -LiteralPath $legacyRuntime -Force
    $legacyRuntimeIsManaged = -not [bool](
        $legacyRuntimeItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint
    )
    foreach ($relativePath in $requiredLegacyRuntimeFiles) {
        if (-not (Test-Path -LiteralPath (Join-Path $legacyRuntime $relativePath) -PathType Leaf)) {
            $legacyRuntimeIsManaged = $false
            break
        }
    }
    if ($legacyRuntimeIsManaged) {
        Remove-Item -LiteralPath $legacyRuntime -Recurse -Force
    }
}
$destination = Join-Path $InstallDirectory "needle.exe"
if (-not [System.StringComparer]::OrdinalIgnoreCase.Equals($source, $destination)) {
    Copy-Item -LiteralPath $source -Destination $destination -Force
}

$uninstallerDestination = Join-Path $InstallDirectory "uninstall.ps1"
if (-not [System.StringComparer]::OrdinalIgnoreCase.Equals(
    $uninstallerSource,
    $uninstallerDestination
)) {
    Copy-Item -LiteralPath $uninstallerSource -Destination $uninstallerDestination -Force
}

if (-not $SkipPathUpdate) {
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $entries = @($userPath -split ";" | Where-Object { $_ })
    $normalizedInstallDirectory = $InstallDirectory.TrimEnd([System.IO.Path]::DirectorySeparatorChar)
    if (-not ($entries | Where-Object {
        [System.StringComparer]::OrdinalIgnoreCase.Equals(
            $_.TrimEnd([System.IO.Path]::DirectorySeparatorChar),
            $normalizedInstallDirectory
        )
    })) {
        $updatedPath = (@($entries) + $InstallDirectory) -join ";"
        [Environment]::SetEnvironmentVariable("Path", $updatedPath, "User")
    }
}

Write-Host "Needle installed at $destination"
Write-Host "Open a new terminal in a Git repository, then run:"
Write-Host "  needle enable"
