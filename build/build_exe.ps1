param(
    [switch]$OneFile
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $RepoRoot

Write-Host "Building UGAV executable from $RepoRoot ..."
if ($OneFile) {
    python -m PyInstaller --noconfirm --clean --onefile --windowed --noupx --name UGAV `
        --paths "$RepoRoot" `
        --add-data "$RepoRoot\ugav\db\schema.sql;ugav/db" `
        --add-data "$RepoRoot\ugav\gui\static;ugav/gui/static" `
        --add-data "$RepoRoot\rules;rules" `
        --collect-all webview `
        --collect-all pythonnet `
        --collect-all clr_loader `
        --hidden-import uvicorn.loops.auto `
        --hidden-import uvicorn.protocols.http.auto `
        --hidden-import uvicorn.lifespan.on `
        --hidden-import lxml.etree `
        --hidden-import lxml._elementpath `
        --hidden-import PIL.DdsImagePlugin `
        --hidden-import PIL.TgaImagePlugin `
        "$RepoRoot\ugav\app.py"
    Write-Host "Build completed: $RepoRoot\dist\UGAV.exe"
} else {
    $StagingDist = Join-Path $RepoRoot "dist\_build_stage"
    $FinalDist = Join-Path $RepoRoot "dist\UGAV_Latest"
    if (Test-Path $StagingDist) {
        Remove-Item -Path $StagingDist -Recurse -Force
    }
    python -m PyInstaller --noconfirm --clean --distpath "$StagingDist" "$RepoRoot\build\ugav.spec"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    if (-not (Test-Path $FinalDist)) {
        New-Item -ItemType Directory -Path $FinalDist -Force | Out-Null
    }
    $BuiltDir = Join-Path $StagingDist "UGAV"
    Copy-Item -Path (Join-Path $BuiltDir "UGAV.exe") -Destination (Join-Path $FinalDist "UGAV.exe") -Force
    Copy-Item -Path (Join-Path $BuiltDir "ugav-cli.exe") -Destination (Join-Path $FinalDist "ugav-cli.exe") -Force
    $FinalInternal = Join-Path $FinalDist "_internal"
    if (Test-Path $FinalInternal) {
        Remove-Item -Path $FinalInternal -Recurse -Force
    }
    Move-Item -Path (Join-Path $BuiltDir "_internal") -Destination $FinalInternal
    Remove-Item -Path $StagingDist -Recurse -Force
    Write-Host "Build completed: $FinalDist\UGAV.exe"
}
