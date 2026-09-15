chcp 65001 >nul
@echo off
title Антират - Удаление sheetrat

echo [1/1] Удаляю папку Sub из INetCookies у всех пользователей...
set "found="
for /f "tokens=*" %%a in ('dir /b /ad "C:\Users" 2^>nul') do (
    if /i not "%%a"=="Public" if /i not "%%a"=="Default" if /i not "%%a"=="Default User" if /i not "%%a"=="All Users" if /i not "%%a"=="WDAGUtilityAccount" (
        if exist "C:\Users\%%a\AppData\Local\Microsoft\Windows\INetCookies\Sub" (
            set "found=1"
            call :clean "C:\Users\%%a"
        )
    )
)
if not defined found echo Папка Sub не найдена ни у одного пользователя.
pause
exit /b 0

:clean
echo Профиль: %~1
rd /s /q "%~1\AppData\Local\Microsoft\Windows\INetCookies\Sub" 2>nul
if exist "%~1\AppData\Local\Microsoft\Windows\INetCookies\Sub" (
    echo НЕ УДАЛЕНО! Папка защищена: %~1\AppData\Local\Microsoft\Windows\INetCookies\Sub
) else (
    echo ГОТОВО! Папка удалена.
)
goto :eof
