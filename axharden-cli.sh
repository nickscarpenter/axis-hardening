#!/usr/bin/env sh
# Run axharden from the source folder. First time only (offline):
#   python3 -m venv .venv && .venv/bin/python -m pip install --no-index --find-links wheels -r requirements.lock
HERE="$(cd "$(dirname "$0")" && pwd)"
export PYTHONPATH="$HERE/src"
if [ -x "$HERE/.venv/bin/python" ]; then exec "$HERE/.venv/bin/python" -m axharden "$@"; fi
exec python3 -m axharden "$@"
