<#
    reset-stick-log.ps1 — стереть СТАРЫЙ лог прогона с флешки.

    ЗАЧЕМ. Образ 256 МиБ покрывает только начало носителя. Область лога лежит
    на LBA 4 000 000 (~1,9 ГиБ) и В ОБРАЗ НЕ ПОПАДАЕТ — а `log_clear_area()`
    затирает её только когда приложение реально стартовало. Значит после записи
    образа на флешке там остаётся лог ПРЕДЫДУЩЕЙ загрузки.

    Это ловушка приёмки, а не мелочь. Сценарий: записали образ, загрузились,
    приложение не стартовало (прошивка не показала флешку), затем запустили
    `pull-log.ps1` — он спокойно прочитал СТАРЫЙ лог, с маркером `END` и
    «GFX_SPEED_SELECT=0x4 SET», и приёмка объявила успех. Именно этот класс
    ошибок («лог врёт») в проекте уже случался неоднократно, поэтому здесь
    он закрыт явным шагом.

    Что делает: затирает 1 МиБ по LBA 4000000..4002047 нулями. Загрузчику это
    не мешает — перед первой записью он всё равно чистит область сам.

    Usage (PowerShell as Administrator):
        powershell -ExecutionPolicy Bypass -File out\reset-stick-log.ps1
        powershell -ExecutionPolicy Bypass -File out\reset-stick-log.ps1 -WhatIfCheck

    -WhatIfCheck   ничего не писать: только сообщить, есть ли на флешке лог.

    Код возврата: 0 стёрто (или проверено), 1 флешка не найдена, 2 лога не было.
#>
[CmdletBinding()]
param(
    [switch]$WhatIfCheck
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }

. (Join-Path $PSScriptRoot 'find-stick.ps1')

$LOG_LBA  = 4000000
$LOG_SEC  = 2048
$SECTOR   = 512
$MAGIC    = 'CMPUNLOG'
$OFFSET   = [int64]$LOG_LBA * $SECTOR
$LEN      = [int64]$LOG_SEC * $SECTOR

Write-Host '=== CMP unlock: сброс старого лога на флешке ===' -ForegroundColor Cyan
Write-Host ''

$hit = Find-StickDisk
if (-not $hit) {
    Show-StickScan
    Write-Host ''
    Write-Host 'Флешка с нашей разметкой не найдена.' -ForegroundColor Red
    exit 1
}
Write-Host ("  флешка: PhysicalDrive{0}  {1}  {2:N2} ГБ" -f `
            $hit.DiskNumber, $hit.Label, ($hit.TotalSectors * 512 / 1GB)) -ForegroundColor Green

if (-not $hit.LogFits) {
    Write-Host ''
    Write-Host ("Носитель меньше {0} секторов — область лога за пределами флешки," -f ($LOG_LBA + $LOG_SEC))
    Write-Host 'лог на нём записаться не мог. Сбрасывать нечего.' -ForegroundColor Yellow
    exit 2
}

# читаем область, чтобы понять, есть ли там лог
$fs = [IO.File]::Open($hit.DevicePath, 'Open', 'Read', 'ReadWrite')
$hasLog = $false
try {
    $fs.Seek($OFFSET, 'Begin') | Out-Null
    $head = New-Object byte[] 512
    $null = $fs.Read($head, 0, 512)
    # сектор 0 области = "CMPN" + указатель, лог начинается со сектора 1
    $fs.Seek($OFFSET + $SECTOR, 'Begin') | Out-Null
    $first = New-Object byte[] 512
    $null = $fs.Read($first, 0, 512)
    $hasLog = ([Text.Encoding]::ASCII.GetString($first, 0, 8)).StartsWith($MAGIC)
} finally { $fs.Dispose() }

if (-not $hasLog) {
    Write-Host ''
    Write-Host "Лога на флешке нет — сбрасывать нечего." -ForegroundColor Green
    Write-Host 'Хорошо: после загрузки с флешки read-log.ps1 найдёт именно СВОЙ лог.' -ForegroundColor DarkGray
    exit 0
}

Write-Host ("  найден СТАРЫЙ лог на LBA {0}." -f $LOG_LBA) -ForegroundColor Yellow
if ($WhatIfCheck) {
    Write-Host '  -WhatIfCheck: ничего не записано.' -ForegroundColor Yellow
    exit 0
}

$zero = New-Object byte[] (1MB)
$fs = [IO.File]::Open($hit.DevicePath, 'Open', 'ReadWrite', 'ReadWrite')
try {
    $fs.Seek($OFFSET, 'Begin') | Out-Null
    $left = $LEN
    while ($left -gt 0) {
        $want = [int][Math]::Min([int64]$zero.Length, $left)
        $fs.Write($zero, 0, $want)
        $left -= $want
    }
    $fs.Flush($true)
} finally { $fs.Dispose() }

Write-Host ''
Write-Host ("  Затёрто {0:N0} байт (LBA {1}..{2})." -f $LEN, $LOG_LBA, ($LOG_LBA + $LOG_SEC - 1)) -ForegroundColor Green
Write-Host '  Теперь read-log.ps1 честно скажет «ЛОГА НЕТ», пока вы не загрузитесь с флешки.' -ForegroundColor Green
exit 0