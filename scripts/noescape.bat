chcp 65001 >nul
@echo off
title Антират - Удаление NoEscape

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

echo [1/1] Удаляю NoEscape.exe...
del /f /q "C:\Users\%username%\AppData\Roaming\NoEscape.exe" 2>nul
if exist "C:\Users\%username%\AppData\Roaming\NoEscape.exe" (
    echo НЕ УДАЛЕНО! Файл не найден или защищен.
    echo Проверьте путь: C:\Users\%username%\AppData\Roaming\NoEscape.exe
) else (
    echo ГОТОВО! Файл удален.
)
pause