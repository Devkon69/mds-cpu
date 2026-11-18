@echo off
rem tries 1-6 walks per thread with all threads and with one thread per core (8 s each)
cd /d "%~dp0"
mds-cpu.exe --tune 8
pause
