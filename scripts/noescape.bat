chcp 65001 >nul
@echo off
title Антират - Удаление NoEscape

echo [1/1] Удаляю NoEscape.exe у всех пользователей...
set "found="
for /f "tokens=*" %%a in ('dir /b /ad "C:\Users" 2^>nul') do (
    if /i not "%%a"=="Public" if /i not "%%a"=="Default" if /i not "%%a"=="Default User" if /i not "%%a"=="All Users" if /i not "%%a"=="WDAGUtilityAccount" (
        if exist "C:\Users\%%a\AppData\Roaming\NoEscape.exe" (
            set "found=1"
            call :clean "C:\Users\%%a"
        )
    )
)
if not defined found echo Файл NoEscape.exe не найден ни у одного пользователя.
pause
exit /b 0

:clean
echo Профиль: %~1
del /f /q "%~1\AppData\Roaming\NoEscape.exe" 2>nul
if exist "%~1\AppData\Roaming\NoEscape.exe" (
    echo НЕ УДАЛЕНО! Файл занят или защищен: %~1\AppData\Roaming\NoEscape.exe
) else (
    echo ГОТОВО! Файл удален.
)
goto :eof
