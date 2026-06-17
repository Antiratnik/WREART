chcp 65001 >nul
@echo off
title Антират - Удаление 000.exe
echo [1/1] Удаляю rniw.exe из автозагрузки...
del /f /q "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\rniw.exe" 2>nul
if exist "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\rniw.exe" (
    echo НЕ УДАЛЕНО! Файл не найден или защищен.
    echo Проверьте путь вручную: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\rniw.exe
) else (
    echo ГОТОВО! Файл удален.
)
pause