chcp 65001 >nul
@echo off
setlocal enabledelayedexpansion
title Антират - Удаление WebRAT

set "RUNKEYS=HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
set "WLKEY=HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
set "NAMES=explorer svchost smss csrss services lsass taskhostw taskhost audiodg wininit spoolsv dwm"

echo [1/4] Завершаю вредоносные процессы...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$n=@('explorer','svchost','smss','csrss','services','lsass','taskhostw','taskhost','audiodg','wininit','spoolsv','dwm'); Get-Process -ErrorAction SilentlyContinue | Where-Object { $n -contains $_.ProcessName -and $_.Path -and -not $_.Path.StartsWith(($env:WINDIR + '\'),[System.StringComparison]::OrdinalIgnoreCase) } | ForEach-Object { Write-Host ('Завершаю: ' + $_.ProcessName + '.exe -> ' + $_.Path); Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }"
echo ГОТОВО!

echo.
echo [2/4] Очищаю автозагрузку и удаляю тело вируса...
for %%N in (%NAMES%) do (
    for %%K in (%RUNKEYS%) do (
        for /f "tokens=1,2*" %%A in ('reg query "%%K" /v "%%N" 2^>nul ^| findstr /i /c:"REG_"') do (
            if /i "%%A"=="%%N" (
                set "VPATH=%%C"
                echo НАЙДЕНА запись автозагрузки [%%K]: %%N
                echo Путь: !VPATH!
                reg delete "%%K" /v "%%N" /f >nul 2>&1
                call :killfile "!VPATH!"
            )
        )
    )
)
echo ГОТОВО!

echo.
echo [3/4] Очищаю планировщик задач...
for %%N in (%NAMES%) do (
    schtasks /query /tn "%%N" >nul 2>&1
    if not errorlevel 1 (
        echo НАЙДЕНА задача планировщика: %%N
        schtasks /delete /tn "%%N" /f >nul 2>&1
    )
)
echo ГОТОВО!

echo.
echo [4/4] Проверяю параметр Shell в Winlogon...
for /f "tokens=1,2*" %%A in ('reg query "%WLKEY%" /v Shell 2^>nul ^| findstr /i /c:"REG_"') do (
    set "SHELLVAL=%%C"
    echo НАЙДЕН параметр Shell: !SHELLVAL!
    for %%S in ("!SHELLVAL:,=" "!") do call :cleanshell "%%~S"
    reg delete "%WLKEY%" /v Shell /f >nul 2>&1
)
echo ГОТОВО!

echo.
echo Лечение завершено. Рекомендуется перезагрузить компьютер.
pause
exit /b 0

:cleanshell
set "E=%~1"
for /f "tokens=* delims= " %%E in ("%E%") do set "E=%%E"
if not defined E goto :eof
if /i "%E%"=="explorer.exe" goto :eof
if /i "%E%"=="explorer" goto :eof
call :killfile "%E%"
goto :eof

:killfile
set "F=%~1"
call set "F=%F%"
if not defined F goto :eof
if exist "%F%" (
    del /f /q "%F%" >nul 2>&1
    if exist "%F%" (
        echo НЕ УДАЛЕНО! Файл занят или защищен: %F%
    ) else (
        echo ГОТОВО! Тело вируса удалено: %F%
    )
) else (
    echo Файл не найден: %F%
)
goto :eof
