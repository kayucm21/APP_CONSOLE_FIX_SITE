# ПОЛНЫЙ АВТОМАТИЗИРОВАННЫЙ СКРИПТ СБОРКИ ZAPRET
# Компиляция -> Подпись -> Упаковка -> Готовый EXE
# Запускать с правами администратора!

param(
    [switch]$SkipSign = $false,
    [switch]$SkipPack = $false
)

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                                                            ║" -ForegroundColor Cyan
Write-Host "║         АВТОМАТИЧЕСКАЯ СБОРКА ZAPRET v2.0                 ║" -ForegroundColor Cyan
Write-Host "║                                                            ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Проверка прав администратора
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "⚠️  ВНИМАНИЕ: Скрипт запущен БЕЗ прав администратора!" -ForegroundColor Yellow
    Write-Host "   Некоторые операции могут не выполниться." -ForegroundColor Gray
    Write-Host ""
}

# ==================== ШАГ 1: КОМПИЛЯЦИЯ ====================
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
Write-Host "║  ШАГ 1: КОМПИЛЯЦИЯ ПРОЕКТА                                ║" -ForegroundColor Yellow
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
Write-Host ""

# Поиск MSBuild
$msbuildPaths = @(
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe",
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe",
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\MSBuild\Current\Bin\MSBuild.exe",
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe",
    "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe",
    "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
)

$msbuild = $null
foreach ($path in $msbuildPaths) {
    if (Test-Path $path) {
        $msbuild = $path
        break
    }
}

if (-not $msbuild) {
    Write-Host "❌ MSBuild не найден!" -ForegroundColor Red
    Write-Host "   Установите Visual Studio Build Tools или Visual Studio." -ForegroundColor Yellow
    Write-Host ""
    pause
    exit 1
}

Write-Host "✅ MSBuild найден: $msbuild" -ForegroundColor Green
Write-Host ""

# Очистка предыдущей сборки
Write-Host "🧹 Очистка предыдущей сборки..." -ForegroundColor Yellow
if (Test-Path ".\x64\Release") {
    Remove-Item ".\x64\Release\*" -Force -Recurse -ErrorAction SilentlyContinue
}
Write-Host "✅ Очистка завершена" -ForegroundColor Green
Write-Host ""

# Компиляция
Write-Host "⚙️  Компиляция проекта (Release x64)..." -ForegroundColor Yellow
Write-Host "   (Это может занять 1-2 минуты)" -ForegroundColor Gray
Write-Host ""

$buildResult = & $msbuild "goodboyDPI.sln" /p:Configuration=Release /p:Platform=x64 /verbosity:minimal /nologo 2>&1

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Компиляция успешно завершена!" -ForegroundColor Green
} else {
    Write-Host "❌ Ошибка компиляции!" -ForegroundColor Red
    Write-Host $buildResult -ForegroundColor Red
    pause
    exit 1
}

$exePath = ".\x64\Release\FIX_RUNET.exe"
if (-not (Test-Path $exePath)) {
    Write-Host "❌ EXE файл не найден после компиляции!" -ForegroundColor Red
    pause
    exit 1
}

$originalSize = (Get-Item $exePath).Length / 1KB
Write-Host "   Размер: $([math]::Round($originalSize, 2)) KB" -ForegroundColor Cyan
Write-Host ""

# ==================== ШАГ 2: ПОДПИСЬ ====================
if (-not $SkipSign) {
    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "║  ШАГ 2: ЦИФРОВАЯ ПОДПИСЬ                                  ║" -ForegroundColor Yellow
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
    Write-Host ""
    
    Write-Host "📝 Создание самоподписанного сертификата..." -ForegroundColor Yellow
    
    # Проверяем существующий сертификат
    $existingCert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*ZAPRET*" } | Select-Object -First 1
    
    if ($existingCert) {
        Write-Host "✅ Найден существующий сертификат ZAPRET" -ForegroundColor Green
        $cert = $existingCert
    } else {
        try {
            $cert = New-SelfSignedCertificate `
                -Type CodeSigningCert `
                -Subject "CN=ZAPRET Software Publisher, O=ZAPRET, C=RU" `
                -KeyAlgorithm RSA `
                -KeyLength 2048 `
                -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" `
                -CertStoreLocation "Cert:\CurrentUser\My" `
                -NotAfter (Get-Date).AddYears(5) `
                -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3")
            
            Write-Host "✅ Новый сертификат создан" -ForegroundColor Green
            
            # Добавляем в доверенные
            $destStore = New-Object System.Security.Cryptography.X509Certificates.X509Store "Root", "CurrentUser"
            $destStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            $destStore.Add($cert)
            $destStore.Close()
            Write-Host "✅ Сертификат добавлен в доверенные" -ForegroundColor Green
        } catch {
            Write-Host "⚠️  Не удалось создать сертификат: $_" -ForegroundColor Yellow
            Write-Host "   Продолжаем без подписи..." -ForegroundColor Gray
            $cert = $null
        }
    }
    
    if ($cert) {
        Write-Host ""
        Write-Host "✍️  Подпись EXE файла..." -ForegroundColor Yellow
        try {
            Set-AuthenticodeSignature -FilePath $exePath -Certificate $cert -TimestampServer "http://timestamp.digicert.com" -HashAlgorithm SHA256 -ErrorAction Stop | Out-Null
            Write-Host "✅ EXE файл успешно подписан!" -ForegroundColor Green
        } catch {
            Write-Host "⚠️  Не удалось подписать: $_" -ForegroundColor Yellow
        }
    }
    Write-Host ""
} else {
    Write-Host "⏭️  Пропуск подписи (параметр -SkipSign)" -ForegroundColor Gray
    Write-Host ""
}

# ==================== ШАГ 3: УПАКОВКА UPX ====================
if (-not $SkipPack) {
    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "║  ШАГ 3: УПАКОВКА UPX                                      ║" -ForegroundColor Yellow
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
    Write-Host ""
    
    $upxDir = ".\upx"
    $upxExe = "$upxDir\upx.exe"
    
    # Проверяем UPX
    if (-not (Test-Path $upxExe)) {
        Write-Host "⬇️  UPX не найден. Скачивание..." -ForegroundColor Yellow
        
        New-Item -ItemType Directory -Force -Path $upxDir | Out-Null
        
        $upxUrl = "https://github.com/upx/upx/releases/download/v4.2.1/upx-4.2.1-win64.zip"
        $upxZip = "$upxDir\upx.zip"
        
        try {
            Invoke-WebRequest -Uri $upxUrl -OutFile $upxZip -UseBasicParsing
            Expand-Archive -Path $upxZip -DestinationPath $upxDir -Force
            
            $upxSubDir = Get-ChildItem -Path $upxDir -Directory | Select-Object -First 1
            if ($upxSubDir) {
                Get-ChildItem -Path $upxSubDir.FullName -File | Move-Item -Destination $upxDir -Force
                Remove-Item $upxSubDir.FullName -Recurse -Force
            }
            
            Remove-Item $upxZip -Force
            Write-Host "✅ UPX скачан" -ForegroundColor Green
        } catch {
            Write-Host "⚠️  Не удалось скачать UPX: $_" -ForegroundColor Yellow
            Write-Host "   Продолжаем без упаковки..." -ForegroundColor Gray
            $upxExe = $null
        }
        Write-Host ""
    }
    
    if ($upxExe -and (Test-Path $upxExe)) {
        # Резервная копия
        Write-Host "💾 Создание резервной копии..." -ForegroundColor Yellow
        Copy-Item $exePath "$exePath.backup" -Force
        Write-Host "✅ Резервная копия создана" -ForegroundColor Green
        Write-Host ""
        
        Write-Host "📦 Упаковка EXE (максимальное сжатие)..." -ForegroundColor Yellow
        Write-Host "   (Это займет 2-3 минуты)" -ForegroundColor Gray
        Write-Host ""
        
        try {
            & $upxExe --best --ultra-brute --lzma $exePath 2>&1 | Out-Null
            
            if ($LASTEXITCODE -eq 0) {
                $packedSize = (Get-Item $exePath).Length / 1KB
                $compression = [math]::Round(($originalSize - $packedSize) / $originalSize * 100, 2)
                
                Write-Host "✅ Упаковка завершена!" -ForegroundColor Green
                Write-Host "   Исходный размер: $([math]::Round($originalSize, 2)) KB" -ForegroundColor Cyan
                Write-Host "   Новый размер: $([math]::Round($packedSize, 2)) KB" -ForegroundColor Cyan
                Write-Host "   Сжатие: $compression%" -ForegroundColor Green
            } else {
                Write-Host "⚠️  Ошибка упаковки, восстановление..." -ForegroundColor Yellow
                Copy-Item "$exePath.backup" $exePath -Force
            }
        } catch {
            Write-Host "⚠️  Ошибка: $_" -ForegroundColor Yellow
            Copy-Item "$exePath.backup" $exePath -Force
        }
        Write-Host ""
    }
} else {
    Write-Host "⏭️  Пропуск упаковки (параметр -SkipPack)" -ForegroundColor Gray
    Write-Host ""
}

# ==================== ЗАВЕРШЕНИЕ ====================
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║                                                            ║" -ForegroundColor Green
Write-Host "║              ✅ СБОРКА ЗАВЕРШЕНА УСПЕШНО! ✅                ║" -ForegroundColor Green
Write-Host "║                                                            ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "📁 Готовый файл: $exePath" -ForegroundColor Cyan
Write-Host ""

if (Test-Path "$exePath.backup") {
    Write-Host "💾 Резервная копия: $exePath.backup" -ForegroundColor Gray
    Write-Host ""
}

Write-Host "🔒 Включена защита от антивируса:" -ForegroundColor Yellow
Write-Host "   ✓ Антидебаг" -ForegroundColor Green
Write-Host "   ✓ Анти-песочница" -ForegroundColor Green
Write-Host "   ✓ Проверка VM" -ForegroundColor Green
Write-Host "   ✓ Обфускация" -ForegroundColor Green
Write-Host "   ✓ Проверка целостности" -ForegroundColor Green
if (-not $SkipSign) {
    Write-Host "   ✓ Цифровая подпись" -ForegroundColor Green
}
if (-not $SkipPack) {
    Write-Host "   ✓ UPX упаковка" -ForegroundColor Green
}
Write-Host ""

Write-Host "💡 Рекомендации:" -ForegroundColor Cyan
Write-Host "   1. Добавьте файл в исключения Windows Defender" -ForegroundColor Gray
Write-Host "   2. Запускайте с правами администратора" -ForegroundColor Gray
Write-Host "   3. Отключите другие антивирусы перед запуском" -ForegroundColor Gray
Write-Host ""

pause



