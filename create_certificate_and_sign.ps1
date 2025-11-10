# Скрипт для создания самоподписанного сертификата и подписи EXE
# Запускать с правами администратора

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Создание сертификата и подпись EXE  " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Путь к EXE файлу
$exePath = ".\x64\Release\FIX_RUNET.exe"

# Проверяем наличие файла
if (-Not (Test-Path $exePath)) {
    Write-Host "❌ Ошибка: файл $exePath не найден!" -ForegroundColor Red
    Write-Host "Сначала скомпилируйте проект." -ForegroundColor Yellow
    pause
    exit 1
}

Write-Host "✅ Файл найден: $exePath" -ForegroundColor Green
Write-Host ""

# Создаем самоподписанный сертификат
Write-Host "📝 Создание самоподписанного сертификата..." -ForegroundColor Yellow

$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject "CN=ZAPRET Software Publisher, O=ZAPRET, C=RU" `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -NotAfter (Get-Date).AddYears(5) `
    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3")

if ($cert) {
    Write-Host "✅ Сертификат создан успешно!" -ForegroundColor Green
    Write-Host "   Отпечаток: $($cert.Thumbprint)" -ForegroundColor Cyan
} else {
    Write-Host "❌ Ошибка создания сертификата!" -ForegroundColor Red
    pause
    exit 1
}

Write-Host ""

# Экспортируем сертификат в доверенные корневые
Write-Host "🔐 Добавление сертификата в доверенные..." -ForegroundColor Yellow

$certPath = "Cert:\CurrentUser\My\$($cert.Thumbprint)"
$destStore = New-Object System.Security.Cryptography.X509Certificates.X509Store "Root", "CurrentUser"
$destStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$destStore.Add($cert)
$destStore.Close()

Write-Host "✅ Сертификат добавлен в доверенные!" -ForegroundColor Green
Write-Host ""

# Подписываем EXE файл
Write-Host "✍️  Подпись EXE файла..." -ForegroundColor Yellow

try {
    Set-AuthenticodeSignature -FilePath $exePath -Certificate $cert -TimestampServer "http://timestamp.digicert.com" -HashAlgorithm SHA256
    Write-Host "✅ EXE файл успешно подписан!" -ForegroundColor Green
} catch {
    Write-Host "❌ Ошибка подписи: $_" -ForegroundColor Red
    pause
    exit 1
}

Write-Host ""

# Проверяем подпись
Write-Host "🔍 Проверка подписи..." -ForegroundColor Yellow
$signature = Get-AuthenticodeSignature -FilePath $exePath

if ($signature.Status -eq "Valid") {
    Write-Host "✅ Подпись действительна!" -ForegroundColor Green
    Write-Host "   Издатель: $($signature.SignerCertificate.Subject)" -ForegroundColor Cyan
} else {
    Write-Host "⚠️  Статус подписи: $($signature.Status)" -ForegroundColor Yellow
    Write-Host "   (Это нормально для самоподписанного сертификата)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Готово! EXE файл подписан.           " -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

pause



