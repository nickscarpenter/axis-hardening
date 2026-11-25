#!/usr/bin/env sh
# Open the axharden GUI from the source folder (Linux).
exec "$(cd "$(dirname "$0")" && pwd)/axharden-cli.sh" gui "$@"
