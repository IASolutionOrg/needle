[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [int]$ParentProcessId,
    [Parameter(Mandatory = $true)]
    [string]$InstallDirectory,
    [Parameter(Mandatory = $true)]
    [string]$Executable,
    [string]$LegacyRuntimeDirectory,
    [switch]$ValidateOnly
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$separators = [char[]]@(
    [System.IO.Path]::DirectorySeparatorChar,
    [System.IO.Path]::AltDirectorySeparatorChar
)
$install = [System.IO.Path]::GetFullPath($InstallDirectory).TrimEnd($separators)
$executablePath = [System.IO.Path]::GetFullPath($Executable)
$scriptPath = [System.IO.Path]::GetFullPath($PSCommandPath)

$comparer = [System.StringComparer]::OrdinalIgnoreCase
if (-not $comparer.Equals([System.IO.Path]::GetDirectoryName($executablePath), $install)) {
    throw "Needle executable is outside the managed installation directory"
}
if (-not $comparer.Equals([System.IO.Path]::GetFileName($executablePath), "needle.exe")) {
    throw "Needle executable has an unexpected file name"
}
if (-not $comparer.Equals([System.IO.Path]::GetDirectoryName($scriptPath), $install)) {
    throw "Needle uninstaller is outside the managed installation directory"
}

$legacyRuntimePath = $null
if ($LegacyRuntimeDirectory) {
    $legacyRuntimePath = [System.IO.Path]::GetFullPath($LegacyRuntimeDirectory).TrimEnd($separators)
    if (-not $comparer.Equals([System.IO.Path]::GetDirectoryName($legacyRuntimePath), $install) -or
        -not $comparer.Equals([System.IO.Path]::GetFileName($legacyRuntimePath), "runtime")) {
        throw "Legacy Needle runtime is outside the managed installation directory"
    }
    $legacyRuntimeItem = Get-Item -LiteralPath $legacyRuntimePath -Force
    if ($legacyRuntimeItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw "Legacy Needle runtime must not be a reparse point"
    }
    foreach ($relativePath in @(
        "bin\codex.exe",
        "bin\codex-code-mode-host.exe",
        "codex-path\rg.exe",
        "codex-resources\codex-command-runner.exe",
        "codex-resources\codex-windows-sandbox-setup.exe",
        "codex-package.json"
    )) {
        $path = Join-Path $legacyRuntimePath $relativePath
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Legacy Needle runtime is incomplete: missing $path"
        }
    }
}
if (-not (Test-Path -LiteralPath $executablePath -PathType Leaf)) {
    throw "Needle managed installation is incomplete: missing $executablePath"
}

if ($ValidateOnly) {
    exit 0
}

Wait-Process -Id $ParentProcessId -ErrorAction SilentlyContinue

Remove-Item -LiteralPath $executablePath -Force
if ($legacyRuntimePath) {
    Remove-Item -LiteralPath $legacyRuntimePath -Recurse -Force
}
Remove-Item -LiteralPath $scriptPath -Force

if ((Get-ChildItem -LiteralPath $install -Force | Measure-Object).Count -eq 0) {
    Remove-Item -LiteralPath $install -Force
}
