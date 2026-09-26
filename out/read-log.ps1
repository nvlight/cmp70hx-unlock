# Прочитать лог, который unlock_v2 пишет на флешку сырыми секторами.
# Логика записи: LBA 4000000, ASCII-текст, каждый сектор 512 байт,
# хвост сектора добит нулями. Сектор 0 — заголовок с профилем.
#
# Сектор 4000000 — это ~2 ГБ от начала флешки; занято под файлы ~85 МБ,
# так что область лога FAT32 не использует и ничего не портит.
#
# ВАЖНО 1: лог появляется ТОЛЬКО после загрузки с флешки. Скрипт не
#           создаёт лог, а читает уже записанный. Если вы запустили его
#           до перезагрузки — лога там не будет.
# ВАЖНО 2: этот файл сохранён в UTF-8 С BOM. Windows PowerShell 5.1
#           читает .ps1 без BOM как ANSI, и русские строки превращаются в
#           мусор — скрипт падает на синтаксисе. Не пересохраняйте без BOM.
#
# Запуск:
#     powershell -ExecutionPolicy Bypass -File out\read-log.ps1

$ErrorActionPreference = 'Stop'
$LBA    = 4000000
$SECTOR = 512
$MAXSEC = 2048
$MAGIC  = 'CMPUNLOG'
# Маркер конца лога. Держим в СИНХРОНЕ с unlock_v2.c (ulogf "END   ----
# end of log ----"). Обе стороны обязаны быть ASCII: лог декодируется
# через [Text.Encoding]::ASCII, который заменяет не-ASCII на '?'.
$MARKER_END = 'END   ---- end of log ----'

function Get-StickDisk {
    $vol = Get-Volume | Where-Object { $_.FileSystem -eq 'FAT32' -and
                                       $_.DriveLetter -and
                                       $_.DriveType -eq 'Removable' }
    if (-not $vol) {
        $vol = Get-Volume | Where-Object { $_.FileSystem -eq 'FAT32' -and
                                           $_.DriveLetter -and
                                           $_.SizeRemaining -gt 0 }
    }
    if (-not $vol) { throw "Флешка не найдена — вставьте её и повторите." }
    $letter = $vol[0].DriveLetter
    $part   = Get-Partition -DriveLetter $letter
    $disk   = Get-Disk -Number $part.DiskNumber
    Write-Host ("Флешка: {0}:  метка '{1}'  {2}  {3:N2} ГБ  {4} секторов" -f `
                $letter, $vol[0].FileSystemLabel, "PhysicalDrive$($disk.Number)",
                ($disk.Size/1GB), ($disk.Size/512))
    return $disk
}

function Read-Raw {
    # ОДИН Read может вернуть меньше, чем просили, — читаем циклом.
    param([int]$DiskNo, [long]$Offset, [int]$Len)
    $fs = [IO.File]::Open("\\.\PhysicalDrive$DiskNo", 'Open', 'Read', 'ReadWrite')
    try {
        $null = $fs.Seek($Offset, 'Begin')
        $b = New-Object byte[] $Len
        $n = 0
        while ($n -lt $Len) {
            $k = $fs.Read($b, $n, $Len - $n)
            if ($k -le 0) { break }
            $n += $k
        }
        return $b
    } finally { $fs.Dispose() }
}

$disk = Get-StickDisk
if ($disk.Size -lt ($LBA + $MAXSEC) * $SECTOR) {
    throw "Флешка меньше, чем область лога."
}
Write-Host ""

$raw = Read-Raw -DiskNo $disk.Number -Offset ($LBA * $SECTOR) -Len ($MAXSEC * $SECTOR)
$all = [Text.Encoding]::ASCII.GetString($raw)

# --- главная проверка: без магии читать нечего ---
$magicAt = $all.IndexOf($MAGIC)
if ($magicAt -lt 0) {
    $nz = 0
    foreach ($x in $raw) { if ($x -ne 0) { $nz++ } }
    Write-Host "ЛОГА НЕТ — по адресу LBA $LBA записаны чужие данные." -ForegroundColor Red
    Write-Host ""
    Write-Host ("  ненулевых байт: {0:N0} из {1:N0}" -f $nz, $raw.Length)
    Write-Host "  это старое содержимое флешки, а не лог."
    Write-Host ""
    Write-Host "ЧТО ДЕЛАТЬ:" -ForegroundColor Yellow
    Write-Host "  1. Убедитесь, что на флешке свежий загрузчик:"
    Write-Host "     X:\EFI\BOOT\BOOTX64.EFI  (ожидается 577024 байта)"
    Write-Host "  2. ПЕРЕЗАГРУЗИТЕСЬ и загрузитесь с этой флешки."
    Write-Host "  3. Убедитесь на экране загрузки, что есть строка"
    Write-Host "     '[log] флешка = ...' и НЕТ строки 'только на экран'."
    Write-Host "  4. Только потом запускайте этот скрипт."
    exit 2
}

$firstSector = [int]($magicAt / $SECTOR)
Write-Host ("Магия найдена: сектор {0}, LBA {1}." -f $firstSector, ($LBA + $firstSector)) -ForegroundColor DarkGreen
Write-Host ""

# --- склеиваем секторы НАЧИНАЯ С ТОГО, где магия ---
# Три ловушки, каждая стоила абракадабры:
#  1) сектор 0 не пишется никогда — там старое содержимое флешки, поэтому
#     начинаем с сектора, где найдена магия, а не с нуля;
#  2) не записанный хвост области может начинаться с ненулевого байта
#     (остатки ЛОГОГО ЖЕ лога от прошлой загрузки), поэтому признак
#     «это лог» — перевод строки в начале сектора, а не только первый байт;
#  3) каждый сектор режем по первому нулю.
$sb = New-Object Text.StringBuilder
$stopped = ''
for ($i = $firstSector; $i -lt $MAXSEC; $i++) {
    $off = $i * $SECTOR
    if ($raw[$off] -eq 0) { $stopped = "сектор $i не записан"; break }
    $chunk = $raw[$off .. ($off + $SECTOR - 1)]
    $head  = [Math]::Min(300, $SECTOR)
    $nl = $chunk[0..($head-1)].IndexOf(10)
    if ($nl -lt 0) { $stopped = "сектор $i не похож на лог (нет перевода строки)"; break }
    $end = $chunk.IndexOf(0)
    if ($end -ge 0) { $chunk = $chunk[0..($end-1)] }
    if ($chunk.Length) { $null = $sb.Append([Text.Encoding]::ASCII.GetString($chunk)) }
    if ($sb.ToString().Contains($MARKER_END)) { $stopped = 'маркер конца'; break }
}
if ($stopped) { Write-Host ("Останов на: {0}" -f $stopped) -ForegroundColor DarkGray }
$text = $sb.ToString()
# Отрезаем всё после маркера конца (ASCII — см. $MARKER_END вверху)
$stop = $text.IndexOf($MARKER_END)
if ($stop -ge 0) {
    $nl = $text.IndexOf("`n", $stop)
    $text = if ($nl -ge 0) { $text.Substring(0, $nl + 1) }
            else          { $text.Substring(0, $stop + $MARKER_END.Length) + "`n" }
}
$text = $text.TrimEnd("`r", "`n") + "`n"

Write-Host ("================ ЛОГ С ФЛЕШКИ ({0} байт) ================" -f $text.Length) -ForegroundColor Cyan
Write-Host $text
Write-Host "=================== КОНЕЦ ЛОГА ===================" -ForegroundColor Cyan

Write-Host ""
Write-Host "--- ключевые строки ---" -ForegroundColor Yellow
$text -split "`n" | Where-Object { $_ -match '^(PRE|FWSEC|FIND|PICK|FBIOS|META|END)\b' } |
    ForEach-Object { "  " + $_.TrimEnd() }

Write-Host ""
Write-Host "--- что делать дальше ---" -ForegroundColor Yellow
if ($text -match 'PRE   OK' -or $text -match 'PRE   CHANGED') {
    Write-Host "  ШТАТНЫЙ FWSEC ПОДНЯЛ WPR2 — дальше смотрите блок FWSEC/END."
} elseif ($text -match 'PRE   imem_card=(\w+).*match=0') {
    Write-Host ("  В IMEM лежит ЧУЖОЙ код (0x{0}) — наш образ не загружен." -f $Matches[1])
} elseif ($text -match 'dbg=0x00780009') {
    Write-Host "  dbg=0x780009 — ядро стартует и гибнет на проверке подписи/окружения."
} elseif ($text -match 'PRE   FAIL') {
    Write-Host "  Штатный FWSEC не поднял WPR2. Смотрите PRE imem_card — загружен ли он вообще."
} elseif ($text -match 'флешка не найдена|лог не пишем') {
    Write-Host "  Приложение не нашло флешку — см. строку [log] на экране загрузки."
}
