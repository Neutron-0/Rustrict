<#
.SYNOPSIS
    Rustrict Windows Installation Script (PowerShell)
.DESCRIPTION
    Installs the Rustrict executable and kernel packet diversion drivers (WinDivert)
    from GitHub Releases or a local archive.
    Supports unauthenticated public downloads as well as authenticated private forks.
.PARAMETER Version
    The version tag to install (e.g. '2.0.0' or 'v2.0.0'). Defaults to 2.0.0.
.PARAMETER InstallDir
    Target directory for the rustrict executable and drivers. Defaults to %LOCALAPPDATA%\Programs\rustrict\bin.
.PARAMETER LocalArchive
    Path to a local zip archive to install instead of downloading from GitHub.
.PARAMETER SkipChecksum
    Explicit switch to bypass SHA-256 verification when using a local archive without a checksum file.
.PARAMETER Token
    Optional GitHub token (GH_TOKEN or GITHUB_TOKEN) for authenticated API access or private forks.
.PARAMETER AddToPath
    Whether to add InstallDir to the User PATH if not already present. Defaults to $true.
#>

[CmdletBinding()]
param(
    [string]$Version = "2.0.0",
    [string]$InstallDir = "$env:LOCALAPPDATA\Programs\rustrict\bin",
    [string]$LocalArchive = "",
    [switch]$SkipChecksum = $false,
    [string]$Token = "",
    [switch]$NoPath = $false
)

$ErrorActionPreference = "Stop"

function Get-ArchiveSha256([string]$FilePath) {
    if (Get-Command Get-FileHash -ErrorAction SilentlyContinue) {
        return (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.ToLower()
    }
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $fileStream = [System.IO.File]::OpenRead($FilePath)
    try {
        $hashBytes = $sha256.ComputeHash($fileStream)
        return ([System.BitConverter]::ToString($hashBytes) -replace '-').ToLower()
    } finally {
        $fileStream.Dispose()
        $sha256.Dispose()
    }
}

function Download-FileRobust([string]$Url, [string]$OutPath, [hashtable]$Headers) {
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curl) {
        $headerArgs = @()
        if ($Headers) {
            foreach ($k in $Headers.Keys) {
                $headerArgs += "-H"
                $headerArgs += "$k`: $($Headers[$k])"
            }
        }
        & curl.exe -fSL --retry 2 --connect-timeout 30 -o $OutPath @headerArgs $Url 2>$null
        if ($LASTEXITCODE -eq 0 -and (Test-Path $OutPath) -and (Get-Item $OutPath).Length -gt 0) {
            return
        }
    }

    $prevProgress = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
        Invoke-WebRequest -Uri $Url -OutFile $OutPath -Headers $Headers -UseBasicParsing -TimeoutSec 180
    } finally {
        $ProgressPreference = $prevProgress
    }
}

$Repo = "Neutron-0/Rustrict"
$CleanVersion = $Version.TrimStart('v')
$Target = "x86_64-pc-windows-msvc"
$ArchiveName = "rustrict-v$CleanVersion-$Target.zip"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Rustrict Windows Installer" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Target Architecture: $Target"
Write-Host "Target Version:      v$CleanVersion"
Write-Host "Installation Path:   $InstallDir\rustrict.exe"

$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("rustrict-install-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

try {
    $zipPath = ""
    $expectedHash = ""

    if ($LocalArchive) {
        if (-not (Test-Path $LocalArchive)) {
            throw "Error: Local archive not found at '$LocalArchive'."
        }
        $zipPath = [System.IO.Path]::GetFullPath($LocalArchive)
        Write-Host "Using local archive: $zipPath"

        # Check for local checksum file
        $archiveDir = [System.IO.Path]::GetDirectoryName($zipPath)
        $sidecarSha = "$zipPath.sha256"
        $dirSums = [System.IO.Path]::Combine($archiveDir, "SHA256SUMS.txt")

        if (Test-Path $sidecarSha) {
            $expectedHash = (Get-Content $sidecarSha -Raw).Trim()
        } elseif (Test-Path $dirSums) {
            $sumsLines = Get-Content $dirSums
            $line = $sumsLines | Where-Object { $_ -match [regex]::Escape((Split-Path $zipPath -Leaf)) } | Select-Object -First 1
            if ($line) {
                $expectedHash = ($line.Trim() -split "\s+")[0].Trim()
            }
        }

        if ($expectedHash) {
            Write-Host "Found local checksum manifest. Verifying SHA-256 integrity..."
            $actualHash = Get-ArchiveSha256 -FilePath $zipPath
            $cleanExpected = ($expectedHash -split "\s+")[0].ToLower().Trim()
            if ($cleanExpected -ne $actualHash) {
                throw "Error: SHA-256 verification failed for $zipPath! Expected: $cleanExpected, Actual: $actualHash. Archive is corrupt."
            }
            Write-Host "Checksum verified: $actualHash" -ForegroundColor Green
        } elseif (-not $SkipChecksum) {
            Write-Host "Warning: No checksum file found for local archive. Use -SkipChecksum to bypass verification." -ForegroundColor Yellow
        }
    } else {
        # Remote download from GitHub Releases
        $zipPath = Join-Path $TempDir $ArchiveName
        $sumsPath = Join-Path $TempDir "SHA256SUMS.txt"

        $baseUrl = "https://github.com/$Repo/releases/download/v$CleanVersion"
        $archiveUrl = "$baseUrl/$ArchiveName"
        $sumsUrl = "$baseUrl/SHA256SUMS.txt"

        $webHeaders = @{ "User-Agent" = "Rustrict-Installer" }
        $ghToken = if ($Token) { $Token } elseif ($env:GH_TOKEN) { $env:GH_TOKEN } elseif ($env:GITHUB_TOKEN) { $env:GITHUB_TOKEN } else { "" }
        if ($ghToken) {
            $webHeaders["Authorization"] = "Bearer $ghToken"
        }

        Write-Host "Downloading $ArchiveName..."
        try {
            Download-FileRobust -Url $archiveUrl -OutPath $zipPath -Headers $webHeaders
        } catch {
            throw "Error: Failed to download release archive from '$archiveUrl'. Verify that release v$CleanVersion exists at https://github.com/$Repo/releases. Detail: $_"
        }

        Write-Host "Downloading checksum manifest (SHA256SUMS.txt)..."
        try {
            Download-FileRobust -Url $sumsUrl -OutPath $sumsPath -Headers $webHeaders
        } catch {
            throw "Error: Failed to download SHA256SUMS.txt from '$sumsUrl'. Cannot verify archive integrity. Aborting installation."
        }

        if (-not (Test-Path $sumsPath) -or (Get-Item $sumsPath).Length -eq 0) {
            throw "Error: Checksum manifest 'SHA256SUMS.txt' is missing or empty. Cannot verify archive integrity."
        }

        $sumsLines = Get-Content $sumsPath
        $matchingLine = $sumsLines | Where-Object { $_ -match [regex]::Escape($ArchiveName) } | Select-Object -First 1
        if (-not $matchingLine) {
            throw "Error: Archive entry for '$ArchiveName' was not found in 'SHA256SUMS.txt'."
        }

        $expectedHash = ($matchingLine.Trim() -split "\s+")[0].ToLower().Trim()
        Write-Host "Verifying SHA-256 archive checksum..."
        $actualHash = Get-ArchiveSha256 -FilePath $zipPath
        if ($expectedHash -ne $actualHash) {
            throw "Error: SHA-256 verification failed for $ArchiveName! Expected: $expectedHash, Actual: $actualHash. The downloaded archive may be corrupted or tampered with."
        }
        Write-Host "Checksum verified successfully: $actualHash" -ForegroundColor Green
    }

    # Extract archive
    $extractStaging = Join-Path $TempDir "extracted"
    Expand-Archive -Path $zipPath -DestinationPath $extractStaging -Force

    $stagedBin = Join-Path $extractStaging "rustrict.exe"
    if (-not (Test-Path $stagedBin)) {
        throw "Error: Extracted archive does not contain 'rustrict.exe'."
    }

    # Verify extracted binary runs correctly prior to installation
    Write-Host "Verifying extracted binary..."
    & $stagedBin nic list | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Error: Extracted binary failed pre-installation verification."
    }

    # Prepare installation directory
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    # Copy binary and runtime dependencies (WinDivert driver files)
    $filesToInstall = @("rustrict.exe", "WinDivert.dll", "WinDivert64.sys", "LICENSE")
    foreach ($file in $filesToInstall) {
        $sourceFile = Join-Path $extractStaging $file
        if (Test-Path $sourceFile) {
            $destFile = Join-Path $InstallDir $file
            $tempTarget = Join-Path $InstallDir ("$file.tmp." + [System.Guid]::NewGuid().ToString("N"))
            Copy-Item -Path $sourceFile -Destination $tempTarget -Force
            Move-Item -Path $tempTarget -Destination $destFile -Force
        }
    }

    Write-Host "Successfully installed Rustrict to $InstallDir\rustrict.exe" -ForegroundColor Green

    # Manage PATH
    $currentPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
    if ($null -eq $currentPath) { $currentPath = "" }
    if ($currentPath -notlike "*$InstallDir*") {
        if (-not $NoPath) {
            Write-Host "Adding $InstallDir to User PATH..."
            $newPath = if ($currentPath) { "$currentPath;$InstallDir" } else { $InstallDir }
            [System.Environment]::SetEnvironmentVariable("Path", $newPath, "User")
            $env:Path = "$env:Path;$InstallDir"
            Write-Host "Added to User PATH. Restart open terminal sessions for changes to take effect everywhere." -ForegroundColor Cyan
        } else {
            Write-Host "Notice: $InstallDir is not in PATH. Run with full path or add to PATH manually." -ForegroundColor Yellow
        }
    }

    Write-Host "Installed version verification:"
    & "$InstallDir\rustrict.exe" nic list | Out-Null
    Write-Host "[OK] Rustrict installation complete and verified." -ForegroundColor Green
    Write-Host "Run 'rustrict --help' or 'rustrict --router-lab' to get started." -ForegroundColor Green
} finally {
    if (Test-Path $TempDir) {
        Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
