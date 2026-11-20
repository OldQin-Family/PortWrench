@echo off
rem Port Console launcher. Uses %~dp0 so it works from any directory.
rem Python opens the browser itself; this bat does NOT open a second one.
cd /d "%~dp0"
where py >nul 2>nul
if not errorlevel 1 (
    py -3 "port_console.py"
) else (
    where python >nul 2>nul
    if not errorlevel 1 (
        python "port_console.py"
    ) else (
        echo [port-console] Python not found. Install Python 3.10+ and ensure 'py -3' or 'python' is on PATH.
        pause
        exit /b 1
    )
)
:after
if not %errorlevel%==0 (
    echo.
    echo [port-console] Exited with error code %errorlevel%. See messages above.
    pause
)
exit /b 0
