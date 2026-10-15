@echo off
setlocal
call "%~dp0NDFinanceBackend\start-nd-finance.bat"
exit /b %errorlevel%
