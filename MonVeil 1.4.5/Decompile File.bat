@echo off
setlocal
cd /d "%~dp0"
set "SOURCE=%~1"
if not defined SOURCE set /p "SOURCE=Path to the MoonVeil-obfuscated Lua file: "
if not defined SOURCE exit /b 1
call :decompile "%SOURCE%"
set "RESULT=%ERRORLEVEL%"
pause
exit /b %RESULT%

:decompile
if not exist "%~1" (
  echo Input file does not exist: "%~1"
  exit /b 2
)
set "OUTPUT=%~dpn1.deobfuscated.luau"
set "ARTIFACTS=%~dpn1.moonveil"
python -m moonveil decompile "%~f1" -o "%OUTPUT%" --artifacts "%ARTIFACTS%"
if errorlevel 1 exit /b %ERRORLEVEL%
echo.
echo Recovered: "%OUTPUT%"
echo Artifacts: "%ARTIFACTS%"
exit /b 0
