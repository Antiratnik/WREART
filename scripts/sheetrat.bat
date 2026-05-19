chcp 65001 >nul
@echo off
title Антират - Удаление sheetrat

set "username="
for /f "tokens=*" %%a in ('dir /b /ad "C:\Users" 2^>nul') do (
    if /i not "%%a"=="Public" if /i not "%%a"=="Default" if /i not "%%a"=="All Users" (
        set "username=%%a"
        goto :found
    )
)
:found
if "%username%"=="" (
    echo НЕ УДАЛОСЬ ОПРЕДЕЛИТЬ ИМЯ ПОЛЬЗОВАТЕЛЯ!
    pause
    exit /b
)

echo [1/1] Удаляю папку Sub из INetCookies...
rd /s /q "C:\Users\%username%\AppData\Local\Microsoft\Windows\INetCookies\Sub" 2>nul
if exist "C:\Users\%username%\AppData\Local\Microsoft\Windows\INetCookies\Sub" (
    echo НЕ УДАЛЕНО! Папка не найдена или защищена.
    echo Проверьте путь: C:\Users\%username%\AppData\Local\Microsoft\Windows\INetCookies\Sub
) else (
    echo ГОТОВО! Папка удалена.
)
pause