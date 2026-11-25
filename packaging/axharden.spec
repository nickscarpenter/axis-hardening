# PyInstaller spec: one folder containing two programs sharing the same libraries.
#   "AXIS Hardening Check GUI.exe"  windowed GUI (what most people double-click)
#   axharden-cli.exe            console CLI
# Build: pyinstaller --noconfirm --clean --distpath dist/pyi --workpath build/pyi packaging/axharden.spec
import os

root = os.path.abspath(os.path.join(SPECPATH, ".."))
src = os.path.join(root, "src")
datas = [(os.path.join(root, "catalog"), "catalog")]
excludes = ["PIL", "numpy", "matplotlib", "pytest", "responses"]

cli_a = Analysis([os.path.join(root, "packaging", "axharden_entry.py")], pathex=[src], datas=datas,
                 hiddenimports=["axharden.gui.app"], excludes=excludes)
gui_a = Analysis([os.path.join(root, "packaging", "axharden_gui_entry.py")], pathex=[src], datas=datas,
                 excludes=excludes)

cli_pyz = PYZ(cli_a.pure)
gui_pyz = PYZ(gui_a.pure)

cli_exe = EXE(cli_pyz, cli_a.scripts, [], exclude_binaries=True, name="axharden-cli", console=True)
gui_exe = EXE(gui_pyz, gui_a.scripts, [], exclude_binaries=True, name="AXIS Hardening Check GUI", console=False)

coll = COLLECT(cli_exe, cli_a.binaries, cli_a.datas,
               gui_exe, gui_a.binaries, gui_a.datas,
               name="axharden")
