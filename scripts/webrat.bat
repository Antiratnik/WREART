chcp 65001
@echo off
title Антират - Удаление винлокера / WebRAT
echo [1/2] Очищаю автозагрузку...
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /va /f 2>nul
echo ГОТОВО! Все записи из Run удалены.

echo.
echo [2/2] Проверяю параметр Shell в Winlogon...
reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell >nul 2>nul
if %errorlevel% equ 0 (
    echo НАЙДЕН параметр Shell.
    echo.
    echo ВАЖНО: Запомните или запишите значение параметра Shell — это файл вируса.
    echo Затем удалите сам параметр Shell вручную:
    echo 1. Нажмите Win+R, введите regedit
    echo 2. Перейдите по пути: HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
    echo 3. Удалите параметр Shell (правой кнопкой -> Удалить)
    echo 4. Удалите сам файл, путь к которому вы записали
    echo.
    echo После перезагрузки вирус НЕ запустится.
) else (
    echo Параметр Shell НЕ НАЙДЕН. Хорошо.
)
pause