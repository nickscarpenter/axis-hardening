@echo off
rem Run axharden from the source folder. First time only (offline):
rem   python -m venv .venv
rem   .venv\Scripts\python -m pip install --no-index --find-links wheels -r requirements.lock
setlocal
set "HERE=%~dp0"
set "PYTHONPATH=%HERE%src"
if exist "%HERE%.venv\Scripts\python.exe" (
  "%HERE%.venv\Scripts\python.exe" -m axharden %*
) else (
  python -m axharden %*
)
