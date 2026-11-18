@echo off
rem stops every running mds-cpu (also one left without a window)
taskkill /F /IM mds-cpu.exe
pause
