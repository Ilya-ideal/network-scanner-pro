@echo off
chcp 65001
title Network Scanner Pro
echo ========================================
echo    Запуск Network Scanner
echo ========================================
echo.

REM Проверка виртуального окружения
if not exist "venv\Scripts\activate.bat" (
    echo ❌ Виртуальное окружение не найдено!
    echo Запустите install.bat для установки
    pause
    exit /b 1
)

REM Активация виртуального окружения
call venv\Scripts\activate.bat

REM Проверка Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python не найден!
    pause
    exit /b 1
)

REM Проверка Nmap
nmap --version >nul 2>&1
if errorlevel 1 (
    echo ⚠  Nmap не найден!
    echo Для полного сканирования установите Nmap
    echo и добавьте в PATH
    timeout /t 3 >nul
)

REM Проверка порта
for /f "tokens=1-5" %%a in ('netstat -ano ^| findstr :8000') do (
    if not "%%e"=="" (
        echo ❌ Порт 8000 уже используется!
        echo Закройте другие приложения или измените порт в config.json
        pause
        exit /b 1
    )
)

REM Запуск сканера
echo 🚀 Запуск Network Scanner...
echo.
echo 📍 Откройте в браузере: http://10.0.9.172:8000
echo 📍 Или на этом компьютере: http://localhost:8000
echo.
echo ⚠  Не закрывайте это окно!
echo.
python network_scanner.py

REM Если скрипт завершился
echo.
echo Программа завершена.
pause