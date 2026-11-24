"""PyInstaller entry point for the windowed GUI executable."""
import sys

from axharden.gui.app import run_gui

if __name__ == "__main__":
    sys.exit(run_gui())
