#!/usr/bin/env sh
# Build offline deliverables on an internet-connected Linux build machine:
#   dist/axharden-linux/   PyInstaller one-folder build
#   dist/axharden-src/     source folder + wheels/ (Linux wheels) for offline pip install
#   dist/sbom.cdx.json     CycloneDX SBOM
# Usage: ./build_offline.sh [python3.12]
set -eu
PY="${1:-python3}"
cd "$(dirname "$0")"
rm -rf dist && mkdir -p dist

"$PY" -m venv .build-venv
BP=.build-venv/bin/python
$BP -m pip install -q --upgrade pip
$BP -m pip install -q --require-hashes -r requirements.lock
$BP -m pip install -q --no-deps -e .
$BP -m pip install -q pyinstaller cyclonedx-bom

mkdir -p dist/axharden-src
$BP -m pip download -q --require-hashes -r requirements.lock -d dist/axharden-src/wheels
for item in src catalog templates docs README.md SECURITY.md requirements.lock requirements.in pyproject.toml axharden.cmd axharden.sh; do
  [ -e "$item" ] && cp -r "$item" dist/axharden-src/
done

$BP -m PyInstaller --noconfirm --clean --onedir --name axharden \
  --distpath dist/pyi --workpath build/pyi --specpath build \
  --add-data "$(pwd)/catalog:catalog" --paths src packaging/axharden_entry.py
mv dist/pyi/axharden dist/axharden-linux && rm -rf dist/pyi
for item in templates docs README.md SECURITY.md; do
  [ -e "$item" ] && cp -r "$item" dist/axharden-linux/
done

$BP -m cyclonedx_py requirements requirements.lock --output-format JSON -o dist/sbom.cdx.json
dist/axharden-linux/axharden --version
echo "Done: dist/"
