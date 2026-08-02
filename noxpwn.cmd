@echo off
setlocal
set "DIR=%~dp0"
set "PYTHONPATH=%DIR%src;%PYTHONPATH%"
python -m noxpwn %*
endlocal