chcp 65001 >nul
@echo off
title Антират - Удаление dcrat

echo [1/2] Удаляю папку browserwebsessionRuntime...
rd /s /q "C:\browserwebsessionRuntime" 2>nul
if exist "C:\browserwebsessionRuntime" (
    echo НЕ УДАЛЕНО! Папка не найдена или защищена.
) else (
    echo ГОТОВО!
)

echo.
echo [2/2] Удаляю DCRatBuild.exe (Temp и рабочий стол) у всех пользователей...
for /f "tokens=*" %%a in ('dir /b /ad "C:\Users" 2^>nul') do (
    if /i not "%%a"=="Public" if /i not "%%a"=="Default" if /i not "%%a"=="Default User" if /i not "%%a"=="All Users" if /i not "%%a"=="WDAGUtilityAccount" (
        call :clean "C:\Users\%%a"
    )
)
echo ГОТОВО!
pause
exit /b 0

:clean
del /f /q "%~1\AppData\Local\Temp\DCRatBuild.exe" 2>nul
if exist "%~1\AppData\Local\Temp\DCRatBuild.exe" echo НЕ УДАЛЕНО (занят?): %~1\AppData\Local\Temp\DCRatBuild.exe
del /f /q "%~1\Desktop\DCRatBuild.exe" 2>nul
if exist "%~1\Desktop\DCRatBuild.exe" echo НЕ УДАЛЕНО (занят?): %~1\Desktop\DCRatBuild.exe
goto :eof
