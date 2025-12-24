@echo off
chcp 65001
echo ========================================
echo    Установка Network Scanner
echo ========================================
echo.

REM Проверка Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python не установлен!
    echo Установите Python с https://python.org
    pause
    exit /b 1
)

REM Проверка Nmap
nmap --version >nul 2>&1
if errorlevel 1 (
    echo ⚠  Nmap не найден в PATH!
    echo Установите Nmap с https://nmap.org
    echo И добавьте в системный PATH
    pause
)

REM Создание виртуального окружения
echo 🔧 Создание виртуального окружения...
python -m venv venv

REM Активация и установка зависимостей
echo 📦 Установка зависимостей Python...
call venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt

echo.
echo ✅ Установка завершена!
echo.
echo Запустите start.bat для запуска сканера
pause