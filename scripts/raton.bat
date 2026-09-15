chcp 65001 >nul
@echo off
title Антират - Удаление raton

echo [1/1] Удаляю папку PlatformRuntime у всех пользователей...
set "found="
for /f "tokens=*" %%a in ('dir /b /ad "C:\Users" 2^>nul') do (
    if /i not "%%a"=="Public" if /i not "%%a"=="Default" if /i not "%%a"=="Default User" if /i not "%%a"=="All Users" if /i not "%%a"=="WDAGUtilityAccount" (
        if exist "C:\Users\%%a\AppData\Roaming\PlatformRuntime" (
            set "found=1"
            call :clean "C:\Users\%%a"
        )
    )
)
if not defined found echo Папка PlatformRuntime не найдена ни у одного пользователя.
pause
exit /b 0

:clean
echo Профиль: %~1
rd /s /q "%~1\AppData\Roaming\PlatformRuntime" 2>nul
if exist "%~1\AppData\Roaming\PlatformRuntime" (
    echo НЕ УДАЛЕНО! Папка защищена: %~1\AppData\Roaming\PlatformRuntime
) else (
    echo ГОТОВО! Папка удалена.
)
goto :eof
