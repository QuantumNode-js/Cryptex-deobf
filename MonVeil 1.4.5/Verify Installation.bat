@echo off
setlocal
cd /d "%~dp0"
python -B -m unittest discover -s tests -v
set "RESULT=%ERRORLEVEL%"
echo.
if "%RESULT%"=="0" echo Installation verified successfully.
if not "%RESULT%"=="0" echo Verification failed.
pause
exit /b %RESULT%
