@echo off
setlocal
set "DIR=%~dp0"
set "PYTHONPATH=%DIR%src;%PYTHONPATH%"
where python >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    python -m noxpwn %*
) else (
    py -3 -m noxpwn %*
)
endlocal