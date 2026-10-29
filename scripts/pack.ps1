# Packs release artifacts into standard zip and computes SHA256SUMS.txt
param(
    [string]$OutputDir = "target\packages"
)

$ErrorActionPreference = "Stop"

$Target = "x86_64-pc-windows-msvc"
$ArchiveName = "rustrict-$Target.zip"

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$stageDir = Join-Path $OutputDir "stage"
if (Test-Path $stageDir) {
    Remove-Item -Path $stageDir -Recurse -Force
}
New-Item -ItemType Directory -Path $stageDir -Force | Out-Null

$releaseDir = "target\release"
$files = @(
    "rustrict.exe",
    "WinDivert.dll",
    "WinDivert64.sys"
)

foreach ($f in $files) {
    $src = Join-Path $releaseDir $f
    if (-not (Test-Path $src)) {
        throw "Missing required release binary: $src. Run 'cargo build --release' first."
    }
    Copy-Item $src $stageDir\
}

Copy-Item "LICENSE" $stageDir\
Copy-Item "README.md" $stageDir\

$zipPath = Join-Path $OutputDir $ArchiveName
if (Test-Path $zipPath) {
    Remove-Item $zipPath -Force
}

Write-Host "Compressing $ArchiveName..." -ForegroundColor Cyan
Compress-Archive -Path "$stageDir\*" -DestinationPath $zipPath -Force

$hash = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToLower()
$sumsPath = Join-Path $OutputDir "SHA256SUMS.txt"
Set-Content -Path $sumsPath -Value "$hash  $ArchiveName"

Remove-Item -Path $stageDir -Recurse -Force

Write-Host "Archive created: $zipPath" -ForegroundColor Green
Write-Host "Checksum file:   $sumsPath" -ForegroundColor Green
Write-Host "SHA256:          $hash" -ForegroundColor Yellow
