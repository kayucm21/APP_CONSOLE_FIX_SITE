@echo off
chcp 866 >nul
echo.
echo =========================================================
echo   Подготовка к компиляции ZAPRET
echo =========================================================
echo.

REM Завершаем процесс FIX_RUNET.exe если он запущен
echo Поиск запущенных процессов FIX_RUNET.exe...
tasklist /FI "IMAGENAME eq FIX_RUNET.exe" 2>NUL | find /I /N "FIX_RUNET.exe">NUL
if "%ERRORLEVEL%"=="0" (
    echo Найден запущенный процесс FIX_RUNET.exe
    echo Завершение процесса...
    taskkill /F /IM FIX_RUNET.exe >nul 2>&1
    timeout /t 1 /nobreak >nul
    echo Процесс завершен!
) else (
    echo Процесс FIX_RUNET.exe не запущен
)

echo.
echo Создание папок для компиляции...
if not exist "x64" mkdir "x64"
if not exist "x64\Release" mkdir "x64\Release"
echo Папки созданы!

echo.
echo Удаление старого EXE файла...
if exist "x64\Release\FIX_RUNET.exe" (
    del /F /Q "x64\Release\FIX_RUNET.exe" >nul 2>&1
    if exist "x64\Release\FIX_RUNET.exe" (
        echo ВНИМАНИЕ: Не удалось удалить файл!
        echo Возможно файл используется другим процессом.
        echo.
        pause
        exit /b 1
    ) else (
        echo Файл удален успешно!
    )
) else (
    echo Файл не существует, пропускаем
)

echo.
echo Очистка промежуточных файлов...
if exist "x64\Release\*.obj" del /F /Q "x64\Release\*.obj" >nul 2>&1
if exist "x64\Release\*.pdb" del /F /Q "x64\Release\*.pdb" >nul 2>&1
if exist "x64\Release\*.log" del /F /Q "x64\Release\*.log" >nul 2>&1
echo Очистка завершена!

echo.
echo =========================================================
echo   Компиляция проекта
echo =========================================================
echo.

REM Поиск MSBuild
set MSBUILD_PATH=

if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe" (
    set MSBUILD_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe
)
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" (
    set MSBUILD_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe
)
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\MSBuild\Current\Bin\MSBuild.exe" (
    set MSBUILD_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\MSBuild\Current\Bin\MSBuild.exe
)
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe" (
    set MSBUILD_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe
)
if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe" (
    set MSBUILD_PATH=C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe
)
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" (
    set MSBUILD_PATH=C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe
)

if "%MSBUILD_PATH%"=="" (
    echo ОШИБКА: MSBuild не найден!
    echo Установите Visual Studio Build Tools или Visual Studio.
    echo.
    pause
    exit /b 1
)

echo Найден MSBuild: %MSBUILD_PATH%
echo.

REM Принудительное создание выходных папок
echo Создание выходных папок...
if not exist "x64" mkdir "x64" 2>nul
if not exist "x64\Release" mkdir "x64\Release" 2>nul

REM Также создаем папку для промежуточных файлов
if not exist "x64\Release\goodboyDPI.tlog" mkdir "x64\Release\goodboyDPI.tlog" 2>nul

echo Папки созданы: x64\Release
echo.

echo Запуск компиляции...
echo.

REM Компилируем с явным указанием выходной папки
"%MSBUILD_PATH%" goodboyDPI.sln ^
  /p:Configuration=Release ^
  /p:Platform=x64 ^
  /p:OutDir=x64\Release\ ^
  /p:IntDir=x64\Release\ ^
  /p:TargetName=FIX_RUNET ^
  /verbosity:detailed ^
  /nologo

echo.
echo =========================================================

if %ERRORLEVEL% EQU 0 (
    echo   Компиляция завершена!
    echo =========================================================
    echo.
    
    REM Снимаем атрибуты "скрытый" чтобы файлы были видны
    attrib -h -s "x64" >nul 2>&1
    attrib -h -s "x64\Release" >nul 2>&1
    attrib -h -s "x64\Release\FIX_RUNET.exe" >nul 2>&1
    
    REM Проверяем что файл действительно создан
    if exist "x64\Release\FIX_RUNET.exe" (
        echo Готовый файл: x64\Release\FIX_RUNET.exe
        for %%A in ("x64\Release\FIX_RUNET.exe") do (
            echo Размер: %%~zA байт
            set /a SIZE_KB=%%~zA/1024
        )
        echo.
        echo УСПЕХ! Файл создан успешно!
    ) else (
        echo ВНИМАНИЕ: Компиляция завершилась, но файл не найден!
        echo.
        echo Проверьте:
        echo 1. Нет ли ошибок компиляции выше
        echo 2. Правильно ли настроен проект
        echo 3. Есть ли все необходимые файлы
        echo.
        echo Содержимое папки x64\Release:
        dir /b "x64\Release"
    )
) else (
    echo   ОШИБКА КОМПИЛЯЦИИ!
    echo =========================================================
    echo.
    echo Код ошибки: %ERRORLEVEL%
    echo.
    echo Возможные причины:
    echo 1. Синтаксические ошибки в коде
    echo 2. Отсутствуют необходимые библиотеки
    echo 3. Неправильные настройки проекта
    echo.
    pause
    exit /b 1
)
echo =========================================================

pause

