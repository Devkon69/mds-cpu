@echo off
rem start_mds_cpu.bat - mines Midstate (MDS) with the CPU on LuckyPool (Midstate Walk).
rem Put your reusable MSS address here (midstate wallet generate-mss) and a worker name.
set USER=YOUR_MSS_ADDRESS
set RIG=cpu
rem Pool password: x if not needed
set PASS=x
set POOL=stratum+ssl://eu.lproute.com:8960
rem Extra options, e.g. the line printed by tune.bat (--threads N --walk-k K --walk-engine E)
set EXTRA=

cd /d "%~dp0"
if "%USER%"=="YOUR_MSS_ADDRESS" (
    echo Edit start_mds_cpu.bat and put your MSS address in USER.
    pause
    exit /b 2
)
:loop
mds-cpu.exe --pool %POOL% --user %USER%.%RIG% --pass "%PASS%" --log mds-cpu.log %EXTRA%
echo.
echo mds-cpu stopped (code %errorlevel%): restarting in 10 s, Ctrl-C to quit.
timeout /t 10 >nul
goto loop
