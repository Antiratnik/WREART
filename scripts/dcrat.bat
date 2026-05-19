chcp 65001 >nul
@echo off
title Антират - Удаление dcrat

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

echo [1/3] Удаляю папку browserwebsessionRuntime...
rd /s /q "C:\browserwebsessionRuntime" 2>nul
if exist "C:\browserwebsessionRuntime" (
    echo НЕ УДАЛЕНО! Папка не найдена или защищена.
) else (
    echo ГОТОВО!
)

echo.
echo [2/3] Удаляю DCRatBuild.exe из Temp...
del /f /q "C:\Users\%username%\AppData\Local\Temp\DCRatBuild.exe" 2>nul
if exist "C:\Users\%username%\AppData\Local\Temp\DCRatBuild.exe" (
    echo НЕ УДАЛЕНО! Файл не найден или защищен.
) else (
    echo ГОТОВО!
)

echo.
echo [3/3] Удаляю DCRatBuild.exe с рабочего стола...
del /f /q "C:\Users\%username%\Desktop\DCRatBuild.exe" 2>nul
if exist "C:\Users\%username%\Desktop\DCRatBuild.exe" (
    echo НЕ УДАЛЕНО! Файл не найден или защищен.
) else (
    echo ГОТОВО!
)
pause