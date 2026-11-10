@echo off
python "%~dp0sanitize_ui.py"
if errorlevel 1 pause
