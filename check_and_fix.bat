@echo off
chcp 866 >nul
echo.
echo =========================================================
echo   Проверка и исправление структуры проекта
echo =========================================================
echo.

REM Проверяем наличие файлов проекта
if not exist "goodboyDPI.sln" (
    echo ОШИБКА: Файл goodboyDPI.sln не найден!
    echo Убедитесь что вы запускаете скрипт из папки проекта.
    pause
    exit /b 1
)

if not exist "goodboyDPI.vcxproj" (
    echo ОШИБКА: Файл goodboyDPI.vcxproj не найден!
    pause
    exit /b 1
)

if not exist "goodboyDPI.cpp" (
    echo ОШИБКА: Файл goodboyDPI.cpp не найден!
    pause
    exit /b 1
)

echo Файлы проекта найдены!
echo.

REM Создаем необходимые папки
echo Создание структуры папок...
if not exist "x64" (
    mkdir "x64"
    echo Создана папка: x64
)
if not exist "x64\Release" (
    mkdir "x64\Release"
    echo Создана папка: x64\Release
)
if not exist "x64\Debug" (
    mkdir "x64\Debug"
    echo Создана папка: x64\Debug
)
if not exist "bin" (
    echo.
    echo ВНИМАНИЕ: Папка bin не найдена!
    echo Убедитесь что все файлы программы находятся в папке bin
    echo.
)

echo.
echo Структура папок готова!
echo.

REM Проверяем наличие MSBuild
echo Поиск MSBuild...
set MSBUILD_PATH=

if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe" (
    set MSBUILD_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe
    goto :msbuild_found
)
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" (
    set MSBUILD_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe
    goto :msbuild_found
)
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\MSBuild\Current\Bin\MSBuild.exe" (
    set MSBUILD_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\MSBuild\Current\Bin\MSBuild.exe
    goto :msbuild_found
)
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe" (
    set MSBUILD_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe
    goto :msbuild_found
)
if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe" (
    set MSBUILD_PATH=C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe
    goto :msbuild_found
)
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" (
    set MSBUILD_PATH=C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe
    goto :msbuild_found
)

echo ОШИБКА: MSBuild не найден!
echo.
echo Установите Visual Studio Build Tools:
echo https://visualstudio.microsoft.com/downloads/
echo.
pause
exit /b 1

:msbuild_found
echo MSBuild найден: %MSBUILD_PATH%
echo.

REM Принудительное создание всех необходимых папок
echo Создание всех необходимых папок...
if not exist "x64" mkdir "x64"
if not exist "x64\Release" mkdir "x64\Release"
if not exist "x64\Debug" mkdir "x64\Debug"
if not exist "x64\Release\goodboyDPI.tlog" mkdir "x64\Release\goodboyDPI.tlog"
echo Все папки созданы!
echo.

REM Очистка проекта
echo =========================================================
echo   Очистка проекта
echo =========================================================
echo.
"%MSBUILD_PATH%" goodboyDPI.sln /t:Clean /p:Configuration=Release /p:Platform=x64 /verbosity:minimal /nologo
echo Очистка завершена!
echo.

REM Пересоздаем папки после очистки
echo Пересоздание выходных папок...
if not exist "x64" mkdir "x64"
if not exist "x64\Release" mkdir "x64\Release"
echo Готово!
echo.

echo =========================================================
echo   Проверка завершена успешно!
echo =========================================================
echo.
echo Теперь можно запустить kill_and_build.bat для компиляции
echo.
pause

