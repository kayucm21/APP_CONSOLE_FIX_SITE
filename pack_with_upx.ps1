# Скрипт для упаковки EXE с помощью UPX
# Автоматически скачивает UPX если его нет

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "      Упаковка EXE с помощью UPX       " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Пути
$exePath = ".\x64\Release\FIX_RUNET.exe"
$upxDir = ".\upx"
$upxExe = "$upxDir\upx.exe"
$upxUrl = "https://github.com/upx/upx/releases/download/v4.2.1/upx-4.2.1-win64.zip"
$upxZip = "$upxDir\upx.zip"

# Проверяем наличие EXE
if (-Not (Test-Path $exePath)) {
    Write-Host "❌ Ошибка: файл $exePath не найден!" -ForegroundColor Red
    Write-Host "Сначала скомпилируйте проект." -ForegroundColor Yellow
    pause
    exit 1
}

Write-Host "✅ Файл найден: $exePath" -ForegroundColor Green
$originalSize = (Get-Item $exePath).Length / 1KB
Write-Host "   Исходный размер: $([math]::Round($originalSize, 2)) KB" -ForegroundColor Cyan
Write-Host ""

# Создаем резервную копию
Write-Host "💾 Создание резервной копии..." -ForegroundColor Yellow
Copy-Item $exePath "$exePath.backup" -Force
Write-Host "✅ Резервная копия создана: $exePath.backup" -ForegroundColor Green
Write-Host ""

# Проверяем наличие UPX
if (-Not (Test-Path $upxExe)) {
    Write-Host "⬇️  UPX не найден. Скачивание..." -ForegroundColor Yellow
    
    # Создаем директорию
    New-Item -ItemType Directory -Force -Path $upxDir | Out-Null
    
    try {
        # Скачиваем UPX
        Write-Host "   Загрузка с GitHub..." -ForegroundColor Gray
        Invoke-WebRequest -Uri $upxUrl -OutFile $upxZip -UseBasicParsing
        
        # Распаковываем
        Write-Host "   Распаковка..." -ForegroundColor Gray
        Expand-Archive -Path $upxZip -DestinationPath $upxDir -Force
        
        # Перемещаем файлы из подпапки
        $upxSubDir = Get-ChildItem -Path $upxDir -Directory | Select-Object -First 1
        if ($upxSubDir) {
            Get-ChildItem -Path $upxSubDir.FullName -File | Move-Item -Destination $upxDir -Force
            Remove-Item $upxSubDir.FullName -Recurse -Force
        }
        
        # Удаляем архив
        Remove-Item $upxZip -Force
        
        Write-Host "✅ UPX успешно скачан!" -ForegroundColor Green
    } catch {
        Write-Host "❌ Ошибка скачивания UPX: $_" -ForegroundColor Red
        Write-Host "Скачайте UPX вручную с https://upx.github.io/" -ForegroundColor Yellow
        pause
        exit 1
    }
    Write-Host ""
}

# Упаковываем EXE
Write-Host "📦 Упаковка EXE с максимальным сжатием..." -ForegroundColor Yellow
Write-Host "   (Это может занять некоторое время)" -ForegroundColor Gray
Write-Host ""

try {
    # Используем максимальное сжатие и дополнительные опции
    & $upxExe --best --ultra-brute --lzma $exePath
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "✅ Упаковка завершена успешно!" -ForegroundColor Green
        
        $packedSize = (Get-Item $exePath).Length / 1KB
        $compression = [math]::Round(($originalSize - $packedSize) / $originalSize * 100, 2)
        
        Write-Host "   Новый размер: $([math]::Round($packedSize, 2)) KB" -ForegroundColor Cyan
        Write-Host "   Сжатие: $compression%" -ForegroundColor Green
    } else {
        Write-Host "❌ Ошибка упаковки!" -ForegroundColor Red
        Write-Host "   Восстановление из резервной копии..." -ForegroundColor Yellow
        Copy-Item "$exePath.backup" $exePath -Force
        pause
        exit 1
    }
} catch {
    Write-Host "❌ Ошибка: $_" -ForegroundColor Red
    Write-Host "   Восстановление из резервной копии..." -ForegroundColor Yellow
    Copy-Item "$exePath.backup" $exePath -Force
    pause
    exit 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Готово! EXE файл упакован.           " -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Резервная копия сохранена в: $exePath.backup" -ForegroundColor Yellow
Write-Host ""

pause



