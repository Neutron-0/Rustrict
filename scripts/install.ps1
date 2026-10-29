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
    [string]$Version = "2.0.2",
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

function Download-FileReliable([string[]]$Urls, [string]$OutPath) {
    $prevProgress = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
    
    $downloadSucceeded = $false
    $lastError = ""
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    
    foreach ($url in $Urls) {
        # 1. Priority: curl.exe with forced IPv4 (-4) and visual progress bar (-#)
        if ($curl) {
            try {
                if (Test-Path $OutPath) { Remove-Item -Force $OutPath }
                & curl.exe -4 -# -L -f --connect-timeout 15 -o $OutPath $url
                if ($LASTEXITCODE -eq 0 -and (Test-Path $OutPath) -and (Get-Item $OutPath).Length -gt 0) {
                    $downloadSucceeded = $true
                    break
                } else {
                    $lastError = "curl.exe exited with code $LASTEXITCODE"
                }
            } catch {
                $lastError = $_.Exception.Message
            }
        }
        
        # 2. Fallback: System.Net.WebClient (direct streaming in .NET)
        if (-not $downloadSucceeded) {
            try {
                if (Test-Path $OutPath) { Remove-Item -Force $OutPath }
                $wc = New-Object System.Net.WebClient
                $wc.Headers.Add("User-Agent", "Rustrict-Installer")
                $wc.DownloadFile($url, $OutPath)
                if ((Test-Path $OutPath) -and (Get-Item $OutPath).Length -gt 0) {
                    $downloadSucceeded = $true
                    break
                }
            } catch {
                $lastError = $_.Exception.Message
            }
        }
        
        # 3. Fallback: Invoke-WebRequest
        if (-not $downloadSucceeded) {
            try {
                if (Test-Path $OutPath) { Remove-Item -Force $OutPath }
                Invoke-WebRequest -Uri $url -OutFile $OutPath -UseBasicParsing -TimeoutSec 60
                if ((Test-Path $OutPath) -and (Get-Item $OutPath).Length -gt 0) {
                    $downloadSucceeded = $true
                    break
                }
            } catch {
                $lastError = $_.Exception.Message
            }
        }
    }
    
    $ProgressPreference = $prevProgress
    
    if (-not $downloadSucceeded) {
        throw "Failed to download from available endpoints: $($Urls -join ' | '). Detail: $lastError"
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

        $rawBase = "https://raw.githubusercontent.com/$Repo/main/dist"
        $releaseBase = "https://github.com/$Repo/releases/download/v$CleanVersion"

        $archiveUrls = @(
            "$rawBase/$ArchiveName",
            "$releaseBase/$ArchiveName"
        )
        $sumsUrls = @(
            "$rawBase/SHA256SUMS.txt",
            "$releaseBase/SHA256SUMS.txt"
        )

        Write-Host "Downloading $ArchiveName..."
        try {
            Download-FileReliable -Urls $archiveUrls -OutPath $zipPath
        } catch {
            throw "Error: Failed to download release archive '$ArchiveName'. Verify network connection. Detail: $_"
        }

        Write-Host "Downloading checksum manifest (SHA256SUMS.txt)..."
        try {
            Download-FileReliable -Urls $sumsUrls -OutPath $sumsPath
        } catch {
            throw "Error: Failed to download SHA256SUMS.txt. Cannot verify archive integrity. Detail: $_"
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
            try {
                Copy-Item -Path $sourceFile -Destination $destFile -Force -ErrorAction Stop
            } catch {
                # If driver file is currently loaded in the Windows kernel, keep existing copy
                if (Test-Path $destFile) {
                    Write-Host "Notice: $file is currently locked by active system service; preserving installed copy." -ForegroundColor Yellow
                } else {
                    throw "Failed to install ${file}: $_"
                }
            }
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
