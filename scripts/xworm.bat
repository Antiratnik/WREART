chcp 65001 >nul
@echo off
title Антират - Удаление xworm

set "username="
for /f "tokens=*" %%a in ('dir /b /ad "C:\Users" 2^>nul') do (
    if /i not "%%a"=="Public" (
        if /i not "%%a"=="Default" (
            if /i not "%%a"=="All Users" (
                set "username=%%a"
                goto :found
            )
        )
    )
)
:found
if "%username%"=="" (
    echo НЕ УДАЛОСЬ ОПРЕДЕЛИТЬ ИМЯ ПОЛЬЗОВАТЕЛЯ!
    echo Проверьте папку C:\Users вручную и замените ИМЯ_ПОЛЬЗОВАТЕЛЯ в путях.
    pause
    exit /b
)
echo Определен пользователь: %username%

echo [1/2] Удаляю маскирующийся svchost.exe...
del /f /q "C:\Users\%username%\AppData\Roaming\svchost.exe" 2>nul
if exist "C:\Users\%username%\AppData\Roaming\svchost.exe" (
    echo НЕ УДАЛЕНО! Файл не найден или защищен.
    echo Проверьте путь: C:\Users\%username%\AppData\Roaming\svchost.exe
) else (
    echo ГОТОВО! Файл удален.
)

echo.
echo [2/2] Переименовываю .exe в .bin на рабочем столе...
set "desktop=C:\Users\%username%\Desktop"
if exist "%desktop%" (
    cd /d "%desktop%" 2>nul
    for %%f in (*.exe) do (
        echo %%~nf | findstr /i /v "WREART" >nul
        if not errorlevel 1 (
            ren "%%f" "%%~nf.bin" 2>nul
            echo Переименован: %%f -> %%~nf.bin
        )
    )
    echo ГОТОВО!
) else (
    echo РАБОЧИЙ СТОЛ НЕ НАЙДЕН: %desktop%
    echo Переименуйте .exe в .bin вручную
)

echo.
echo После лечения вы можете вернуть .bin обратно в .exe вручную.
pause