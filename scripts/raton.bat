chcp 65001 >nul
@echo off
title Антират - Удаление raton

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

echo [1/1] Удаляю папку PlatformRuntime...
rd /s /q "C:\Users\%username%\AppData\Roaming\PlatformRuntime" 2>nul
if exist "C:\Users\%username%\AppData\Roaming\PlatformRuntime" (
    echo НЕ УДАЛЕНО! Папка не найдена или защищена.
    echo Проверьте путь: C:\Users\%username%\AppData\Roaming\PlatformRuntime
) else (
    echo ГОТОВО! Папка удалена.
)
pause