# install.ps1 — Mekong Tunnel CLI installer for Windows
# Usage: irm https://mekongtunnel.dev/install.ps1 | iex
# Or:   .\install.ps1 [-Version v1.4.9] [-InstallDir "$env:LOCALAPPDATA\Programs\mekong"]
#
# Installs to %LOCALAPPDATA%\Programs\mekong\mekong.exe (no admin required)
# and adds it to your User PATH — works with VS Code, npm, and pip SDKs.
#
# NOTE: If SmartScreen blocks the script, run:
#   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
# Then re-run the installer.

param(
    [string]$Version = "",
    [string]$InstallDir = ""
)

$ErrorActionPreference = "Stop"

# ── Colors / helpers ──────────────────────────────────────────────────────────
function Write-Info  { param($Msg) Write-Host "  -> $Msg" -ForegroundColor Cyan }
function Write-Ok    { param($Msg) Write-Host "  v  $Msg" -ForegroundColor Green }
function Write-Warn  { param($Msg) Write-Host "  !  $Msg" -ForegroundColor Yellow }
function Write-Err   { param($Msg) Write-Host "  x  $Msg" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "  Mekong Tunnel - CLI Installer" -ForegroundColor White
Write-Host ""

# ── Detect architecture ───────────────────────────────────────────────────────
$Arch = (Get-WmiObject Win32_Processor).AddressWidth
$CpuArch = (Get-WmiObject Win32_Processor).Caption

if ($env:PROCESSOR_ARCHITEW6432 -eq "ARM64" -or $env:PROCESSOR_ARCHITECTURE -eq "ARM64" -or $CpuArch -match "ARM") {
    $BinaryName = "mekong-windows-arm64.exe"
    $PlatformLabel = "Windows/arm64"
} else {
    $BinaryName = "mekong-windows-amd64.exe"
    $PlatformLabel = "Windows/amd64"
}

Write-Info "Platform: $PlatformLabel"

# ── Resolve version ───────────────────────────────────────────────────────────
$Repo = "MuyleangIng/MekongTunnel"

if (-not $Version) {
    Write-Info "Fetching latest version from GitHub..."
    try {
        $Release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -UseBasicParsing
        $Version = $Release.tag_name
    } catch {
        Write-Err "Could not determine latest version. Specify -Version v1.4.9"
    }
}

Write-Ok "Version: $Version"

# ── Resolve install dir ───────────────────────────────────────────────────────
if (-not $InstallDir) {
    # %LOCALAPPDATA%\Programs\mekong — standard user-space install, no admin needed.
    # VS Code, npm mekong-cli, and pip mekong-tunnel all search this path.
    $InstallDir = Join-Path $env:LOCALAPPDATA "Programs\mekong"
}

if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
}

$DestPath = Join-Path $InstallDir "mekong.exe"
$DownloadUrl = "https://github.com/$Repo/releases/download/$Version/$BinaryName"

Write-Info "Installing to: $DestPath"

# ── Download ──────────────────────────────────────────────────────────────────
$TempFile = Join-Path $env:TEMP "mekong-installer.exe"

Write-Info "Downloading $BinaryName..."
try {
    # Use TLS 1.2+
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempFile -UseBasicParsing
    $ProgressPreference = 'Continue'
} catch {
    Write-Err "Download failed: $_. Check your internet connection or try a different version."
}

# ── Verify file size ──────────────────────────────────────────────────────────
$FileSize = (Get-Item $TempFile).Length
if ($FileSize -lt 1MB) {
    Remove-Item $TempFile -Force -ErrorAction SilentlyContinue
    Write-Err "Downloaded file is too small ($FileSize bytes). The URL may be wrong."
}

# ── Remove SmartScreen / Zone.Identifier (mark-of-the-web) ───────────────────
# This is the safe, built-in PowerShell way to unblock a downloaded file.
Write-Info "Removing Windows SmartScreen block (Unblock-File)..."
Unblock-File -Path $TempFile

# ── Install ───────────────────────────────────────────────────────────────────
Copy-Item -Path $TempFile -Destination $DestPath -Force
Remove-Item $TempFile -Force -ErrorAction SilentlyContinue
Write-Ok "Binary installed"

# ── Add to user PATH ──────────────────────────────────────────────────────────
$CurrentPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($CurrentPath -notlike "*$InstallDir*") {
    Write-Info "Adding $InstallDir to your PATH..."
    $NewPath = "$CurrentPath;$InstallDir"
    [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
    # Also update current session
    $env:Path = "$env:Path;$InstallDir"
    Write-Ok "PATH updated (takes effect in new terminals)"
} else {
    Write-Ok "Already in PATH"
}

# ── Verify ────────────────────────────────────────────────────────────────────
try {
    $Out = & $DestPath version 2>&1
    Write-Ok "mekong installed successfully! ($Out)"
} catch {
    Write-Warn "Installed but could not verify — try: mekong version"
}

# ── Windows Defender note ─────────────────────────────────────────────────────
Write-Host ""
Write-Warn "Windows Defender tip:"
Write-Warn "  If Windows shows 'Windows protected your PC', click 'More info' then 'Run anyway'."
Write-Warn "  The binary is open-source: https://github.com/$Repo"
Write-Host ""

# ── Done ─────────────────────────────────────────────────────────────────────
Write-Host "  Ready! Open a new terminal and run:" -ForegroundColor White
Write-Host ""
Write-Host "  mekong login" -ForegroundColor Cyan -NoNewline
Write-Host "       -- sign in for a reserved subdomain"
Write-Host "  mekong 3000" -ForegroundColor Cyan -NoNewline
Write-Host "        -- expose localhost:3000"
Write-Host "  mekong test" -ForegroundColor Cyan -NoNewline
Write-Host "        -- verify your setup"
Write-Host ""
