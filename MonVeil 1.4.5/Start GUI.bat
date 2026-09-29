@echo off
setlocal
cd /d "%~dp0"
python -m moonveil.gui
if errorlevel 1 pause
