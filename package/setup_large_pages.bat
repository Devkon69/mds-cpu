@echo off
rem Gives your Windows user the "Lock pages in memory" right, so the scratchpads can use
rem large pages (Midstate Walk 5-15% faster). Run once; it asks for administrator rights.
cd /d "%~dp0"
net session >nul 2>&1
if errorlevel 1 (
    echo Asking for administrator rights...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
mds-cpu.exe --setup-large-pages
echo.
echo Now sign out of Windows and back in (or reboot), then start the miner:
echo it prints "scratchpads in large pages on all threads".
pause
