@echo off
chcp 65001
title Network Scanner Pro - Мастер установки
echo ========================================
echo    Network Scanner Pro для Windows
echo ========================================
echo.
echo 1. Проверка системы
echo 2. Установка зависимостей
echo 3. Запуск сканера
echo.
echo ========================================

:menu
echo.
echo Выберите действие:
echo   1. Полная установка и запуск
echo   2. Только запуск
echo   3. Выход
echo.

set /p choice="Введите номер: "

if "%choice%"=="1" goto full_install
if "%choice%"=="2" goto run_only
if "%choice%"=="3" goto exit
goto menu

:full_install
echo.
echo 🛠  Начинаю полную установку...
call install.bat
if errorlevel 1 (
    echo ❌ Установка не удалась!
    pause
    goto menu
)
goto run_scanner

:run_only
echo.
echo ⚡ Пропускаю установку, запускаю сканер...
goto run_scanner

:run_scanner
echo.
echo 🚀 Запуск Network Scanner...
start.bat
goto exit

:exit
echo.
echo До свидания!
timeout /t 2 >nul
exit