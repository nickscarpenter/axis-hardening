# Build the two offline deliverables on an internet-connected Windows build machine:
#   dist\axharden-win64\       PyInstaller one-folder build (no Python needed on the target)
#   dist\axharden-src\         source folder + wheels\ for:  pip install --no-index --find-links wheels -r requirements.lock
#   dist\sbom.cdx.json         CycloneDX SBOM of the runtime dependencies
# Usage:  powershell -ExecutionPolicy Bypass -File build_offline.ps1 [-Python path\to\python.exe]
param([string]$Python = "python")
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$dist = Join-Path $PSScriptRoot "dist"
if (Test-Path $dist) { Remove-Item -Recurse -Force $dist }
New-Item -ItemType Directory -Force $dist | Out-Null

Write-Host "== build venv"
& $Python -m venv .build-venv
$py = Join-Path $PSScriptRoot ".build-venv\Scripts\python.exe"
& $py -m pip install -q --upgrade pip
& $py -m pip install -q --require-hashes -r requirements.lock
& $py -m pip install -q --no-deps -e .
& $py -m pip install -q pyinstaller cyclonedx-bom

Write-Host "== source folder + wheels"
$src = Join-Path $dist "axharden-src"
New-Item -ItemType Directory -Force $src | Out-Null
& $py -m pip download -q --require-hashes -r requirements.lock -d (Join-Path $src "wheels")
foreach ($item in "src","catalog","templates","docs","README.md","SECURITY.md","requirements.lock","requirements.in","pyproject.toml","axharden-cli.cmd","axharden-gui.cmd","axharden-cli.sh","axharden-gui.sh") {
    if (Test-Path $item) { Copy-Item -Recurse $item $src }
}

Write-Host "== PyInstaller one-folder build (GUI + CLI)"
& $py -m PyInstaller --noconfirm --clean --distpath (Join-Path $dist "pyi") --workpath build\pyi packaging\axharden.spec
# build\pyi holds half-built exes that fail with "Failed to load Python DLL" if run; remove it.
Remove-Item -Recurse -Force build\pyi
$win = Join-Path $dist "axharden-win64"
Move-Item (Join-Path $dist "pyi\axharden") $win
Remove-Item -Recurse -Force (Join-Path $dist "pyi")
foreach ($item in "templates","docs","README.md","SECURITY.md") {
    if (Test-Path $item) { Copy-Item -Recurse $item $win }
}

Write-Host "== SBOM"
& $py -m cyclonedx_py requirements requirements.lock --output-format JSON -o (Join-Path $dist "sbom.cdx.json")

Write-Host "== smoke test"
& (Join-Path $win "axharden-cli.exe") --version
Write-Host "Done: $dist"
