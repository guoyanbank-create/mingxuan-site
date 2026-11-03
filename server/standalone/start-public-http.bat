@echo off
setlocal DisableDelayedExpansion
cd /d "%~dp0"
if errorlevel 1 goto path_error
set "PYTHON_CMD="
py -3 "%~dp0launch_public_http.py" --check-runtime >nul 2>&1
if not errorlevel 1 goto use_py
python "%~dp0launch_public_http.py" --check-runtime >nul 2>&1
if not errorlevel 1 goto use_python
echo [ERROR] Python 3.8+ with required modules was not found.
py -3 "%~dp0launch_public_http.py" --check-runtime
python "%~dp0launch_public_http.py" --check-runtime
set "RUN_EXIT=1"
goto done
:use_py
set "PYTHON_CMD=py -3"
goto ready
:use_python
set "PYTHON_CMD=python"
:ready
%PYTHON_CMD% "%~dp0launch_public_http.py"
set "RUN_EXIT=%ERRORLEVEL%"
goto done
:path_error
echo [ERROR] Cannot open the launcher directory.
set "RUN_EXIT=1"
:done
echo.
echo Press any key to close this window.
pause >nul
exit /b %RUN_EXIT%
