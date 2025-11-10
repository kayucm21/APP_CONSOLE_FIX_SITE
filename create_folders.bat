@echo off
chcp 866 >nul
echo.
echo =========================================================
echo   Создание структуры папок для компиляции
echo =========================================================
echo.

echo Создание папок...
echo.

REM Основная папка x64
if not exist "x64" (
    mkdir "x64"
    echo [+] Создана: x64
) else (
    echo [OK] Существует: x64
)

REM Папка Release
if not exist "x64\Release" (
    mkdir "x64\Release"
    echo [+] Создана: x64\Release
) else (
    echo [OK] Существует: x64\Release
)

REM Папка Debug
if not exist "x64\Debug" (
    mkdir "x64\Debug"
    echo [+] Создана: x64\Debug
) else (
    echo [OK] Существует: x64\Debug
)

REM Папка для логов компиляции
if not exist "x64\Release\goodboyDPI.tlog" (
    mkdir "x64\Release\goodboyDPI.tlog"
    echo [+] Создана: x64\Release\goodboyDPI.tlog
) else (
    echo [OK] Существует: x64\Release\goodboyDPI.tlog
)

echo.
echo =========================================================
echo   Структура папок создана!
echo =========================================================
echo.

echo Проверка структуры:
echo.
tree /F /A x64 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo x64\
    echo +-- Release\
    echo +-- Debug\
)

echo.
echo =========================================================
echo   Готово! Теперь можно компилировать проект.
echo =========================================================
echo.

pause



