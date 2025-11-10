@echo off
chcp 866 >nul
echo.
echo =========================================================
echo   Отображение скрытых файлов и папок
echo =========================================================
echo.

echo Снятие атрибутов "скрытый" и "системный" с папки x64...
echo.

REM Снимаем атрибуты с папки x64 и всех её подпапок
if exist "x64" (
    attrib -h -s "x64" /s /d
    echo [OK] Атрибуты сняты с папки x64
) else (
    echo [!] Папка x64 не найдена
)

echo.
echo Снятие атрибутов с папки Release...
if exist "x64\Release" (
    attrib -h -s "x64\Release" /s /d
    echo [OK] Атрибуты сняты с папки x64\Release
)

echo.
echo Снятие атрибутов с FIX_RUNET.exe...
if exist "x64\Release\FIX_RUNET.exe" (
    attrib -h -s "x64\Release\FIX_RUNET.exe"
    echo [OK] Атрибуты сняты с FIX_RUNET.exe
    echo.
    echo Информация о файле:
    dir "x64\Release\FIX_RUNET.exe"
) else (
    echo [!] Файл FIX_RUNET.exe не найден
)

echo.
echo =========================================================
echo   Готово! Файлы теперь видимы.
echo =========================================================
echo.

echo Содержимое папки x64\Release:
dir /a "x64\Release"

echo.
pause



