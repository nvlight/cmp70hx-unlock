# Прочитать лог, который unlock_v2 пишет на флешку сырыми секторами.
# Логика записи: LBA 4000000, ASCII-текст, каждый сектор 512 байт,
# хвост сектора добит нулями. Сектор 0 — заголовок с профилем.
#
# Сектор 4000000 — это ~2 ГБ от начала флешки; занято под файлы ~85 МБ,
# так что область лога FAT32 не использует и ничего не портит.
#
# Механика формата на диске и всего пути записи в unlock_v2.c описана в
# docs/LOGGING.md. Здесь — только ридер: как добраться до флешки, как
# декодировать и где остановиться. Значения $LBA/$MAXSEC/$MAGIC/$MARKER_END
# обязаны совпадать с LOG_LBA/LOG_SECTORS/LOG_HDR и маркером в unlock_v2.c.
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
    Write-Host "     X:\EFI\BOOT\BOOTX64.EFI"
    Write-Host "     md5 должен совпадать с out\unlock_v3r_CMP70HX.efi"
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
#
# ЛОВУШКА (исправлено 2026-09-28). Срез байтового массива в PowerShell —
# это object[], а не byte[]. У object[] метод IndexOf сравнивает ЗНАЧЕНИЕ
# БЕЗ ПРИВЕДЕНИЯ ТИПА, поэтому IndexOf(10) ищет Int32(10) и никогда не
# находит byte(10):
#     $raw[0..511][0..299].IndexOf(10)        -> -1   (всегда!)
#     $raw[0..511][0..299].IndexOf([byte]10)  ->  9   (правильно)
# Симптом был тихий и коварный: ридер всегда останавливался на первом
# секторе с сообщением «нет перевода строки» и печатал лог в 1 байт,
# хотя лог на флешке был полный. Именно из-за этого две строки ниже
# используют [Array]::IndexOf с ЯВНЫМ приведением к [byte].
$sb = New-Object Text.StringBuilder
$stopped = ''
$sawMarker = $false
# v3.48: СТОП НА МАРКЕРЕ КОНЦА УБРАН (здесь был `break`).
#
# Маркер 'END   ---- end of log ----' печатается ДО выгрузки кольца консоли
# (вызов fx_pr_dump в unlock_v2.c идёт после него), то есть за ним лежит
# законная часть лога - сам дамп. Останавливаясь на маркере, ридер выбрасывал
# ровно то, что все предыдущие сессии искали:
#   - заголовок 'PRN   ==== console ring:' - его нет в логе НИ В ОДНОМ прогоне
#     начиная с v3.17, и v3.19 записал это как дефект прошивки;
#   - метку фазы 'console ring dump to log' - её не могло быть в принципе,
#     потому что fx_mk_report() печатает сводку ДО выгрузки, заведомо раньше.
#     Отсутствие этой метки выглядело как вторая, независимая улика.
#
# Оба «неуказания» годами указывали на читалку, а не на прошивку: шесть дней
# искали баг там, где его не было, потому что улика была неотличима от
# симптома. Воспроизведено на прогоне 1004-161157.
#
# Останов по незанятому сектору ($raw[$off] -eq 0) остаётся и работает: область
# лога чистится на каждом прогоне, поэтому за хвостом текущего прогона идёт
# незанятый сектор.
#
# Чтобы это не повторили: МАРКЕР КОНЦА ОЗНАЧАЕТ «конец обычного текста»,
# а НЕ «конец лога».
for ($i = $firstSector; $i -lt $MAXSEC; $i++) {
    $off = $i * $SECTOR
    if ($raw[$off] -eq 0) { $stopped = "сектор $i не записан"; break }
    $chunk = $raw[$off .. ($off + $SECTOR - 1)]
    $head  = [Math]::Min(300, $SECTOR)
    $nl = [Array]::IndexOf([object[]]$chunk[0..($head-1)], [byte]10)
    if ($nl -lt 0) { $stopped = "сектор $i не похож на лог (нет перевода строки)"; break }
    $end = [Array]::IndexOf([object[]]$chunk, [byte]0)
    if ($end -ge 1) { $chunk = $chunk[0..($end-1)] }
    if ($chunk.Length) { $null = $sb.Append([Text.Encoding]::ASCII.GetString($chunk)) }
    if ($sb.ToString().Contains($MARKER_END)) { $sawMarker = $true }
}
if ($stopped) { Write-Host ("Останов на: {0}" -f $stopped) -ForegroundColor DarkGray }
$text = $sb.ToString()
# Отрезаем всё после ПОСЛЕДНЕГО маркера конца (ASCII — см. $MARKER_END вверху).
#
# v3.48: IndexOf -> LastIndexOf. IndexOf резал по ПЕРВОМУ маркеру и выбрасывал
# дамп кольца вместе с метками PRND. LastIndexOf режет по последнему: дамп
# текущего прогона, записанный после его маркера, сохраняется, а хвост
# ПРЕЖНЕГО прогона (он остаётся, если прежний был длиннее) отбрасывается.
$stop = $text.LastIndexOf($MARKER_END)
if ($stop -ge 0) {
    $nl = $text.IndexOf("`n", $stop)
    $text = if ($nl -ge 0) { $text.Substring(0, $nl + 1) }
            else          { $text.Substring(0, $stop + $MARKER_END.Length) + "`n" }
}

# --- ЛОВУШКА (2026-09-28): лог НЕ затирался между прогонами -----------
# Раньше unlock_v2.c писал «прогон продолжает с сектора N (логи не
# затираются)», и на флешке лежала конкатенация всех прошлых прогонов.
# Новый перезаписывал начало, а хвост старого выживал, если новый был
# короче. Симптом: в логе были строки «DMA   imem_sec_bit=0», которых в
# записанном EFI нет вообще (проверено поиском по бинарю), и метки
# времени шли назад (t=33368 -> t=29756). Из-за этого вывод «после правки
# три ретрая пошли по старому коду» был ложным.
#
# Теперь область очищается на каждом прогоне (g_logClear = TRUE в
# unlock_v2.c), так что смешивания быть не должно. Проверка ниже остаётся
# как СТРАХОВКА: если заголовков оказалось больше одного — значит очистка
# не сработала и выводы могут быть недостоверны.
$hdr = 'CMPUNLOG v1 '
$runs = ([regex]::Matches($text, [regex]::Escape($hdr))).Count
if ($runs -gt 1) {
    $lastHdr = $text.LastIndexOf($hdr)
    Write-Host ("ВНИМАНИЕ: в области {0} прогонов, показан только последний." -f $runs) -ForegroundColor Red
    Write-Host "Очистка области лога не сработала — выводы о правках ненадёжны." -ForegroundColor Red
    if ($lastHdr -gt 0) { $text = $text.Substring($lastHdr) }
    Write-Host ""
} else {
    Write-Host "Прогонов в области лога: 1 (чисто)." -ForegroundColor DarkGreen
    Write-Host ""
}
# v3.48: ЭТИ ДВА БАННЕРА - ГРАНИЦЫ ТЕЛА ЛОГА, И ОНИ НЕ КОСМЕТИКА.
#
# pull-log.ps1 сохраняет не $text, а ВЕСЬ stdout этого скрипта. А stdout
# содержит и подсказки Write-Host, и сводку '--- ключевые строки ---', которая
# ПЕРЕПЕЧАТЫВАЕТ каждую строку по списку префиксов (TIME и END в него входят).
#
# Из-за этого сохранённый usb-log-*.txt содержит лог ДВАЖДЫ. На этом уже была
# построена неверная выводка: два 'TIME I/O' и две пары 'END' в файле
# читаются как «два прогона в области лога», а на деле второй экземпляр пришёл
# из сводки. Проверка verify-log.ps1 теперь режет файл по этим баннерам и
# работает только с телом.
$text = $text.TrimEnd("`r", "`n") + "`n"

Write-Host ("================ ЛОГ С ФЛЕШКИ ({0} байт) ================" -f $text.Length) -ForegroundColor Cyan
Write-Host $text
Write-Host "=================== КОНЕЦ ЛОГА ===================" -ForegroundColor Cyan

Write-Host ""
Write-Host "--- ключевые строки ---" -ForegroundColor Yellow
# Список префиксов. Раньше здесь стояло
#   PRE|FWSEC|FIND|PICK|FBIOS|META|END|FBP|TIME|BOOTER|GEN2
# и в сводку НЕ попадал весь фазовый блок: STG (анлок), FUSE (до/после
# селекторов), OKCHK (проверки драйвера), IVER/DMA/BROM (загрузка образа),
# PREFLR/FLRX (сброс). То есть ровно то, ради чего лог и снимается, в
# сводке отсутствовало (заметил 2026-09-29 по логу от 0929-023826).
# Порядок ниже — это порядок стадий прогона, а не алфавит.
$keyPrefixes = 'FIND|PICK|BARSCN|VROM|PROBE|MC|TIME|MEM|BUF|META|GEOM|FBIOS|' +
               'G2NVR|PRE|FBP|FWSEC|DMA2|IVER|DMA|BROM|WAIT|OKCHK|BOOTER|GEN2|' +
               'STG|FUSE|PROBE|PREFLR|FLRX|END'
$text -split "`n" | Where-Object { $_ -match "^($keyPrefixes)\b" } |
    ForEach-Object { "  " + $_.TrimEnd() }

Write-Host ""
Write-Host "--- что делать дальше ---" -ForegroundColor Yellow

# v3n: адрес FRTS берём ИЗ САМОГО ЛОГА, а не из константы в скрипте.
# Раньше здесь стоял литерал 0x1FFE00000 — это адрес СТАРОЙ формулы
# (docs/70HX-PORT-STATUS.md §frtsOffset), и подсказка печатала неверное
# число: прогон от 2026-09-29 отработал с frts=0x1F7E00000, а скрипт
# писал «FB по 0x1FFE00000 недоступен». Литерал разъехался с профилем,
# и это молчалo вводило в заблуждение. Теперь единственный источник
# правды — заголовок прогона:
#     CMPUNLOG v1 profile=... frts=0x<addr> wpr2=0x..\/0x..
$frtsAddr = '?'
if ($text -match 'frts=0x([0-9a-fA-F]+)') { $frtsAddr = '0x' + $Matches[1] }

# ШАГ 1: вердикт пробы доступа к кадровому буферу — самое важное.
if ($text -match 'FBP\s+VERDICT (.+)') {
    Write-Host "  ШАГ 1 (проба FB): $($Matches[1])" -ForegroundColor Magenta
    $v = $Matches[1]
    if ($v -match 'ctrlA=FAIL') {
        Write-Host "    -> положительный контроль не прошёл: чинить окно DMEM/DMA, C-G не читать."
    } elseif ($v -match 'roundTrip=PASS') {
        Write-Host "    -> FB ДОСТУПЕН ДЛЯ ЗАПИСИ через GSP-DMA."
        Write-Host "       FRTS-регион можно заполнять напрямую (след. шаг)."
    } elseif ($v -match 'frtsRead=nonzero') {
        Write-Host "    -> FB читается, но не пишется: смотреть FBP-F / FBP-G в логе."
    } else {
        Write-Host ("    -> FB по {0} недоступен: работать с командой маппера" -f $frtsAddr)
        Write-Host "       (gfwImageSize в readVbiosDesc) — см. docs/70HX-NEXT-STEPS.md §4a."
    }
}

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
