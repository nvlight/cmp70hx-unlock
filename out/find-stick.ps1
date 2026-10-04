<#
    find-stick.ps1 — найти флешку ПО ГЕОМЕТРИИ, а не по букве тома.

    Общий модуль для out\read-log.ps1 и out\assign-stick-letter.ps1.
    Подключается точечно: . "$PSScriptRoot\find-stick.ps1"

    ПОЧЕМУ НЕ ПО БУКВЕ. После записи релизного образа Windows НЕ назначает
    том букву: тип раздела в MBR = 0xEF (ESP), а Windows такие тома не
    монтирует автоматически — Get-Partition показывает Type = 'Unknown'.
    Тип 0xEF обязателен для загрузки (прошивка не показывает флешку как
    UEFI-загрузочную без него, docs/GOTCHAS.md, замер 2026-08-25), поэтому
    отказ от него — не вариант, а отсутствие буквы приходится просто
    переживать. Старый поиск по DriveLetter в read-log.ps1 в этом сценарии
    возвращал «флешка не найдена» при совершенно рабочей разблокировке.

    Критерии скопированы из log_stick_ok() (src/unlock_v2.c:9731-9811) —
    это буквально те же проверки, которые делает само EFI-приложение, чтобы
    выбрать «свою» флешку. Пока флешка им не удовлетворяет, лог на неё и не
    пишется, поэтому искать её по геометрии бессмысленно — нет лога.

        1. Media->BlockSize == 512            (проверяем размер чтения)
        2. читается LBA 0
        3. mbr[510..511] == 55 AA             (MBR, а не GPT)
        4. ровно ОДИН раздел типа 0xEF
        5. этот раздел начинается с LBA 2048   (именно этот разрез отличает
                                                 нашу флешку от второго USB)
        6. по LBA 2048 читается загрузочный сектор: 55 AA и FilSysType по
           смещению 0x52 == "FAT32   "  (по 0x54 читается хвост поля —
           "T32   3?" — и настоящая флешка молча отбраковывается)

    Требование Media->LastBlock >= LOG_LBA + LOG_SECTORS (4 002 048 секторов,
    ~1,9 ГиБ) проверяется отдельно и как ФАКТ логирования, а не как признак
    нашей флешки: на носителе меньше анлок работает, лог просто не пишется.

    Требует прав администратора: чтение \\.\PhysicalDriveN.
#>

$script:STICK_ESP_TYPE = 0xEF
$script:STICK_ESP_LBA  = 2048
$script:STICK_LOG_LBA  = 4000000
$script:STICK_LOG_SEC  = 2048

# Подробный разбор одного диска. Возвращает PSCustomObject или $null,
# а в $why — причину отказа (её же показываем пользователю: на экране EFI
# она печатается построчно, docs/LOGGING.md §7).
function Test-StickGeometry {
    param([int]$DiskNo, [string]$Label = '', [uint64]$TotalSectors = 0)

    # Размер берём из Get-Disk, а НЕ из FileStream.Length: на сыром
    # \\.\PhysicalDriveN .NET возвращает 0, и «флешка меньше 4 ГиБ» получалось
    # ложно даже для 15 ГБ Kingston.
    # Ровно ДВА обратных слеша: так канонический путь к физическому диску
    # (\\.\PhysicalDriveN). "\" в PowerShell НЕ является эскейпом, поэтому
    # строка пишется именно с двумя. Со ОДНИМ слешем путь не открывается
    # вовсе — это проверялось, скан молча перестаёт видеть флешку.
    $raw = "\\.\PhysicalDrive$DiskNo"
    try { $fs = [IO.File]::Open($raw, 'Open', 'Read', 'ReadWrite') }
    catch { return $null }

    try {
        $mbr = New-Object byte[] 512
        $fs.Seek(0, 'Begin') | Out-Null
        if ($fs.Read($mbr, 0, 512) -ne 512) { return $null }

        if ($mbr[510] -ne 0x55 -or $mbr[511] -ne 0xAA) { return $null }

        $esp = @()
        for ($i = 0; $i -lt 4; $i++) {
            $o = 446 + 16 * $i
            if ($mbr[$o + 4] -eq $script:STICK_ESP_TYPE) {
                $esp += [pscustomobject]@{
                    Index   = $i
                    Start   = [BitConverter]::ToUInt32($mbr, $o + 8)
                    Sectors = [BitConverter]::ToUInt32($mbr, $o + 12)
                }
            }
        }
        if ($esp.Count -ne 1) { return $null }
        if ($esp[0].Start -ne $script:STICK_ESP_LBA) { return $null }

        $bs = New-Object byte[] 512
        $fs.Seek([int64]$script:STICK_ESP_LBA * 512, 'Begin') | Out-Null
        if ($fs.Read($bs, 0, 512) -ne 512) { return $null }
        if ($bs[510] -ne 0x55 -or $bs[511] -ne 0xAA) { return $null }
        if ([Text.Encoding]::ASCII.GetString($bs, 0x52, 8) -ne 'FAT32   ') { return $null }

        $sectors = $TotalSectors
        if ($sectors -eq 0) {
            try { $sectors = [uint64]((Get-Disk -Number $DiskNo).Size / 512) } catch { $sectors = 0 }
        }
        return [pscustomobject]@{
            DiskNumber    = $DiskNo
            DevicePath    = $raw
            Label         = $Label
            EspSectors    = $esp[0].Sectors
            TotalSectors  = $sectors
            # Лог пишется, только если носитель дотягивает до области лога.
            LogFits       = ($sectors -ge ($script:STICK_LOG_LBA + $script:STICK_LOG_SEC))
        }
    } catch {
        return $null
    } finally { $fs.Dispose() }
}

# Перебор дисков. Системный/загрузочный пропускаем: читать с них 512 байт
# незачем, а лишний raw-доступ к системному диску — плохая практика.
function Find-StickDisk {
    param([switch]$IncludeSystemDisks)

    $disks = @(Get-Disk | Sort-Object Number)
    foreach ($d in $disks) {
        if (-not $IncludeSystemDisks -and ($d.IsBoot -or $d.IsSystem)) { continue }
        $hit = Test-StickGeometry -DiskNo $d.Number -Label $d.FriendlyName -TotalSectors ([uint64]($d.Size / 512))
        if ($hit) { return $hit }
    }
    return $null
}

# Диагностика для пользователя: что нашлось на каждом диске и почему нет.
function Show-StickScan {
    param([switch]$IncludeSystemDisks)

    Write-Host 'Поиск флешки по геометрии (критерии log_stick_ok):' -ForegroundColor Cyan
    foreach ($d in @(Get-Disk | Sort-Object Number)) {
        $skip = (-not $IncludeSystemDisks -and ($d.IsBoot -or $d.IsSystem))
        $hit  = Test-StickGeometry -DiskNo $d.Number -Label $d.FriendlyName -TotalSectors ([uint64]($d.Size / 512))
        if ($hit) {
            $logNote = if ($hit.LogFits) { 'лог поместится' } else { 'лог НЕ поместится (< 4 002 048 секторов)' }
            Write-Host ("  disk {0} {1}: НАША ФЛЕШКА, ESP {2} секторов с LBA {3}, {4}" -f `
                        $d.Number, $d.FriendlyName, $hit.EspSectors, $script:STICK_ESP_LBA, $logNote) -ForegroundColor Green
        } elseif ($skip) {
            Write-Host ("  disk {0} {1}: системный, пропущен" -f $d.Number, $d.FriendlyName) -ForegroundColor DarkGray
        } else {
            Write-Host ("  disk {0} {1}: не наша разметка (нет MBR 55AA / раздела 0xEF с LBA 2048 / FAT32)" -f `
                        $d.Number, $d.FriendlyName) -ForegroundColor DarkGray
        }
    }
}