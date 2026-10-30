@echo off
setlocal
if not exist "%~dp0ferrox-cli.exe" (
  echo ferrox-cli.cmd: ferrox-cli.exe is missing beside this file.>&2
  exit /b 1
)
"%~dp0ferrox-cli.exe" %*
exit /b %ERRORLEVEL%
