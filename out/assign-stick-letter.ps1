# SPDX-License-Identifier: GPL-2.0-only
<#
    assign-stick-letter.ps1 — назначить букву тому флешки с образом.

    ЗАЧЕМ. Образ записан на флешку, но в Проводнике её не видно: буквы нет.
    Это НЕ поломка. Причина — тип раздела в MBR, который образ обязан иметь:

        раздел типа 0xEF = EFI System Partition

    Windows такие тома не монтирует автоматически: Get-Partition показывает
    Type = 'Unknown', Get-Volume — том без DriveLetter. Тип 0xEF обязателен
    для ЗАГРУЗКИ — часть AMI-прошивок не показывает removable-USB как
    UEFI-загрузочную опцию без него (docs/GOTCHAS.md, замер 2026-08-25), и
    отказ от него уберёт разблокировку графики. Поэтому буквы просто не
    будет, и это нужно пережить, а не лечить.

    Что при этом НЕ нужно: буква не требуется ни для загрузки, ни для снятия
    лога. out\read-log.ps1 ищет флешку по геометрии (out\find-stick.ps1) и
    читает \\.\PhysicalDriveN напрямую. Этот скрипт — только для удобства
    Проводника.

    Usage (PowerShell as Administrator):
        powershell -ExecutionPolicy Bypass -File out\assign-stick-letter.ps1
        powershell -ExecutionPolicy Bypass -File out\assign-stick-letter.ps1 -DriveLetter E
        powershell -ExecutionPolicy Bypass -File out\assign-stick-letter.ps1 -Scan

    -DriveLetter  буква, которую назначить (по умолчанию — первая свободная
                  от R вниз; X:, C:, D:… не трогаем)
    -Scan         только показать, что найдено, ничего не назначать

    Код возврата: 0 назначено (или -Scan), 1 не найдено.
#>
[CmdletBinding()]
param(
    [string]$DriveLetter = '',
    [switch]$Scan,
    # Включить поиск на системных дисках. Нужно только если образ почему-то
    # оказался на внутреннем носителе — тогда последствия на вашей совести.
    [switch]$IncludeSystemDisks
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }

. (Join-Path $PSScriptRoot 'find-stick.ps1')

Write-Host '=== CMP unlock: назначение буквы флешке ===' -ForegroundColor Cyan
Write-Host ''

$hit = Find-StickDisk -IncludeSystemDisks:$IncludeSystemDisks
if (-not $hit) {
    Show-StickScan -IncludeSystemDisks:$IncludeSystemDisks
    Write-Host ''
    Write-Host 'Флешка с нашей разметкой не найдена.' -ForegroundColor Red
    Write-Host 'Проверьте: образ записан целиком (Rufus в режиме DD), а не только' -ForegroundColor Red
    Write-Host 'его начало, и флешка видна в «Диспетчере дисков».' -ForegroundColor Red
    exit 1
}

$sizeGB = ($hit.TotalSectors * 512) / 1GB
Write-Host ("  найдено: PhysicalDrive{0}  {1}  {2:N2} ГБ  ESP {3} секторов с LBA 2048" -f `
            $hit.DiskNumber, $hit.Label, $sizeGB, $hit.EspSectors) -ForegroundColor Green
if (-not $hit.LogFits) {
    Write-Warning ("Флешка меньше 4 002 048 секторов ({0}) — лог прогона на неё не пишется." -f $hit.TotalSectors)
}

if ($Scan) { exit 0 }

# Том по номеру диска и номеру раздела. Буквы у тома нет, поэтому ищем по
# геометрии раздела: ESP у нас всегда partition 1 с LBA 2048.
$part = @(Get-Partition -DiskNumber $hit.DiskNumber | Sort-Object PartitionNumber)[0]
$vol  = Get-Volume -Partition $part -ErrorAction SilentlyContinue
if (-not $vol) { Write-Host 'Том не найден на разделе — возможно, файловая система не читается.' -ForegroundColor Red; exit 1 }

if ($vol.FileSystem -ne 'FAT32') {
    Write-Warning ("Файловая система тома: '{0}', ожидалась FAT32. Всё равно назначу букву." -f $vol.FileSystem)
}

if (-not $DriveLetter) {
    $used = @((Get-Volume | Where-Object { $_.DriveLetter }).DriveLetter)
    foreach ($c in [char[]]@('R','Q','P','O','N','M','L','K','J','I','H','E','F','G')) {
        if ($used -notcontains $c) { $DriveLetter = [string]$c; break }
    }
    if (-not $DriveLetter) { Write-Host 'Свободных букв не осталось.' -ForegroundColor Red; exit 1 }
}
$DriveLetter = $DriveLetter.TrimEnd(':').ToUpper()
if ($DriveLetter.Length -ne 1) { Write-Host "Буква '$DriveLetter' недопустима." -ForegroundColor Red; exit 1 }

if ((Get-Volume -DriveLetter $DriveLetter -ErrorAction SilentlyContinue)) {
    Write-Host "Буква $DriveLetter` уже занята. Возьмите другую: -DriveLetter E" -ForegroundColor Red
    exit 1
}

# Add-PartitionAccessPath, а не New-Item на разделе: буква должна пережить
# переподключение флешки, а монтирование тома по пути — нет.
Add-PartitionAccessPath -DiskNumber $hit.DiskNumber -PartitionNumber $part.PartitionNumber -AccessPath "$DriveLetter`:" | Out-Null
Start-Sleep -Seconds 2

$check = Get-Volume -DriveLetter $DriveLetter -ErrorAction SilentlyContinue
Write-Host ''
if ($check) {
    Write-Host ("  {0}:  {1}  '{2}'  {3:N0} байт" -f `
                $DriveLetter, $check.FileSystem, $check.FileSystemLabel, $check.Size) -ForegroundColor Green
    Write-Host ''
    Write-Host "Буква назначена. Загрузка от этого не зависела — теперь флешка видна и в Проводнике." -ForegroundColor Green
    exit 0
}
Write-Host "Не удалось назначить $DriveLetter`." -ForegroundColor Red
exit 1