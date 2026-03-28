@echo off
setlocal

set "NPCAP_DIR=C:\Windows\System32\Npcap"
if not exist "%NPCAP_DIR%\wpcap_arm64.dll" set "NPCAP_DIR=C:\Program Files\Npcap"

if exist "%NPCAP_DIR%\wpcap_arm64.dll" (
    set "PATH=%NPCAP_DIR%;%PATH%"
)

set "CMD=%~1"
shift

set "ARGS="
:collect_args
if "%~1"=="" goto run
set "ARGS=%ARGS% %1"
shift
goto collect_args

:run
call "%CMD%" %ARGS%
set "EXIT_CODE=%ERRORLEVEL%"
exit /b %EXIT_CODE%
