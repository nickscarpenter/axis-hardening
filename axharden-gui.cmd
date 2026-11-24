@echo off
rem Open the GUI from the source folder (no console window). First time only (offline):
rem   python -m venv .venv
rem   .venv\Scripts\python -m pip install --no-index --find-links wheels -r requirements.lock
setlocal
set "HERE=%~dp0"
set "PYTHONPATH=%HERE%src"
if exist "%HERE%.venv\Scripts\pythonw.exe" (
  start "" "%HERE%.venv\Scripts\pythonw.exe" -m axharden gui
) else (
  start "" pythonw -m axharden gui
)
