chcp 65001 >nul
@echo off
title Антират - Удаление xworm

echo [1/2] Удаляю маскирующийся svchost.exe из AppData у всех пользователей...
for /f "tokens=*" %%a in ('dir /b /ad "C:\Users" 2^>nul') do (
    if /i not "%%a"=="Public" if /i not "%%a"=="Default" if /i not "%%a"=="Default User" if /i not "%%a"=="All Users" if /i not "%%a"=="WDAGUtilityAccount" (
        del /f /q "C:\Users\%%a\AppData\Roaming\svchost.exe" 2>nul
        if exist "C:\Users\%%a\AppData\Roaming\svchost.exe" (
            echo НЕ УДАЛЕНО (занят?): C:\Users\%%a\AppData\Roaming\svchost.exe
        )
    )
)
echo ГОТОВО!

echo.
echo [2/2] Переименовываю .exe в .bin на рабочем столе у всех пользователей...
for /f "tokens=*" %%a in ('dir /b /ad "C:\Users" 2^>nul') do (
    if /i not "%%a"=="Public" if /i not "%%a"=="Default" if /i not "%%a"=="Default User" if /i not "%%a"=="All Users" if /i not "%%a"=="WDAGUtilityAccount" (
        if exist "C:\Users\%%a\Desktop" call :renamedesktop "C:\Users\%%a\Desktop"
    )
)
echo ГОТОВО!

echo.
echo После лечения вы можете вернуть .bin обратно в .exe вручную.
pause
exit /b 0

:renamedesktop
echo Рабочий стол: %~1
pushd "%~1"
for %%f in (*.exe) do (
    echo %%~nf | findstr /i /v "WREART" >nul
    if not errorlevel 1 (
        ren "%%f" "%%~nf.bin" 2>nul
        echo Переименован: %%f -^> %%~nf.bin
    )
)
popd
goto :eof
