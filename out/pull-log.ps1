# SPDX-License-Identifier: GPL-2.0-only
# Снять лог с флешки и сохранить его в out\usb-log.txt
#
# Обёртка над read-log.ps1: читает сырые секторы с флешки, печатает лог и
# СРАЗУ сохраняет копию в out\usb-log-<метка>.txt (предыдущий прогон
# автоматически остаётся на месте — так логи разных заходов не
# перетирают друг друга).
#
# ВАЖНО: запускать ПОСЛЕ загрузки с флешки. Скрипт не создаёт лог,
#        а читает уже записанный.
#
# Запуск:
#     powershell -ExecutionPolicy Bypass -File out\pull-log.ps1
#     powershell -ExecutionPolicy Bypass -File out\pull-log.ps1 -Tag after-fbp

[CmdletBinding()]
param(
    # Метка для имени файла. По умолчанию — метка времени.
    [string]$Tag = '',
    # Не сохранять копию, только напечатать.
    [switch]$NoSave
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$outDir = Join-Path $root 'out'

if (-not $Tag) { $Tag = (Get-Date -Format 'MMdd-HHmmss') }
$dest = Join-Path $outDir "usb-log-$Tag.txt"

# Консоль Windows по умолчанию OEM-кодовая, а скрипт печатает по-русски.
# Форсируем UTF-8, иначе вывод приходит кракозябрами (и в консоль, и в
# перенаправление).
try {
    [Console]::OutputEncoding = [Text.Encoding]::UTF8
    $OutputEncoding           = [Text.Encoding]::UTF8
} catch { }

Write-Host ("Снимаю лог с флешки (метка '{0}')..." -f $Tag) -ForegroundColor Cyan
Write-Host ""

$text = & powershell -ExecutionPolicy Bypass `
                      -File (Join-Path $PSScriptRoot 'read-log.ps1') 2>&1 | Out-String

if ($LASTEXITCODE -eq 2) {
    Write-Host "Лога на флешке нет (или он не с того загрузчика)." -ForegroundColor Red
    Write-Host "См. подсказки выше от read-log.ps1."
    exit 2
}

Write-Host $text

if (-not $NoSave) {
    # Пишем в UTF-8 С BOM, чтобы файл нормально открывался в блокноте и
    # чтобы при следующем прогоне не потерять кириллицу.
    $enc = New-Object Text.UTF8Encoding $true
    [IO.File]::WriteAllText($dest, $text, $enc)
    Write-Host ("Сохранено: {0} ({1:N0} байт)" -f $dest, (Get-Item $dest).Length) `
               -ForegroundColor Green
}
