@echo off
chcp 866 >nul
cls
echo.
echo =========================================================
echo          MASTER BUILD SCRIPT - ZAPRET
echo =========================================================
echo.
echo Этот скрипт выполнит ВСЕ шаги автоматически:
echo 1. Создание папок
echo 2. Завершение старого процесса
echo 3. Очистку проекта
echo 4. Компиляцию
echo.
echo =========================================================
echo.
pause

REM =====================================================
REM ШАГ 1: СОЗДАНИЕ ПАПОК
REM =====================================================
echo.
echo [ШАГ 1/4] Создание структуры папок...
echo =========================================================
echo.

if not exist "x64" mkdir "x64"
if not exist "x64\Release" mkdir "x64\Release"
if not exist "x64\Debug" mkdir "x64\Debug"
if not exist "x64\Release\goodboyDPI.tlog" mkdir "x64\Release\goodboyDPI.tlog"

echo [OK] Папки созданы:
echo     - x64
echo     - x64\Release
echo     - x64\Debug
echo.

REM =====================================================
REM ШАГ 2: ЗАВЕРШЕНИЕ СТАРОГО ПРОЦЕССА
REM =====================================================
echo [ШАГ 2/4] Завершение старого процесса FIX_RUNET.exe...
echo =========================================================
echo.

tasklist /FI "IMAGENAME eq FIX_RUNET.exe" 2>NUL | find /I /N "FIX_RUNET.exe">NUL
if "%ERRORLEVEL%"=="0" (
    echo [!] Найден запущенный процесс
    taskkill /F /IM FIX_RUNET.exe >nul 2>&1
    timeout /t 1 /nobreak >nul
    echo [OK] Процесс завершен
) else (
    echo [OK] Процесс не запущен
)
echo.

REM Удаление старого файла
if exist "x64\Release\FIX_RUNET.exe" (
    del /F /Q "x64\Release\FIX_RUNET.exe" >nul 2>&1
    echo [OK] Старый EXE удален
)
echo.

REM =====================================================
REM ШАГ 3: ПОИСК MSBUILD
REM =====================================================
echo [ШАГ 3/4] Поиск MSBuild...
echo =========================================================
echo.

set MSBUILD_PATH=

if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe" set MSBUILD_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" set MSBUILD_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\MSBuild\Current\Bin\MSBuild.exe" set MSBUILD_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\MSBuild\Current\Bin\MSBuild.exe
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe" set MSBUILD_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe
if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe" set MSBUILD_PATH=C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" set MSBUILD_PATH=C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe

if "%MSBUILD_PATH%"=="" (
    echo [X] MSBuild не найден!
    echo.
    echo Установите Visual Studio:
    echo https://visualstudio.microsoft.com/downloads/
    echo.
    pause
    exit /b 1
)

echo [OK] MSBuild найден
echo     %MSBUILD_PATH%
echo.

REM =====================================================
REM ШАГ 4: КОМПИЛЯЦИЯ
REM =====================================================
echo [ШАГ 4/4] Компиляция проекта...
echo =========================================================
echo.

"%MSBUILD_PATH%" goodboyDPI.sln ^
  /p:Configuration=Release ^
  /p:Platform=x64 ^
  /p:OutDir=x64\Release\ ^
  /p:IntDir=x64\Release\ ^
  /p:TargetName=FIX_RUNET ^
  /verbosity:minimal ^
  /nologo

echo.
echo =========================================================

if %ERRORLEVEL% EQU 0 (
    if exist "x64\Release\FIX_RUNET.exe" (
        REM Снимаем атрибуты "скрытый" с папок компиляции
        attrib -h -s "x64" >nul 2>&1
        attrib -h -s "x64\Release" >nul 2>&1
        attrib -h -s "x64\Release\FIX_RUNET.exe" >nul 2>&1
        
        echo.
        echo ╔═════════════════════════════════════════════════════════╗
        echo ║                                                         ║
        echo ║              КОМПИЛЯЦИЯ УСПЕШНА!                        ║
        echo ║                                                         ║
        echo ╚═════════════════════════════════════════════════════════╝
        echo.
        echo Готовый файл: x64\Release\FIX_RUNET.exe
        for %%A in ("x64\Release\FIX_RUNET.exe") do (
            set /a SIZE_KB=%%~zA/1024
            echo Размер: %%~zA байт (SIZE_KB KB^)
        )
        echo.
        echo Все функции включены:
        echo  [+] Автозапуск после перезагрузки
        echo  [+] Проверка прав администратора
        echo  [+] Защита от антивируса
        echo  [+] Правильная кодировка (CP866)
        echo  [+] Защита от повторного запуска
        echo.
    ) else (
        echo.
        echo [X] ОШИБКА: Файл не создан!
        echo.
        echo Проверьте ошибки компиляции выше.
        echo.
    )
) else (
    echo.
    echo [X] ОШИБКА КОМПИЛЯЦИИ!
    echo     Код ошибки: %ERRORLEVEL%
    echo.
    echo Смотрите ошибки выше.
    echo.
)

echo =========================================================
echo.
pause

