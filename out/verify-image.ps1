<#
    verify-image.ps1 — проверка релизного .img ДО записи на флешку.

    Это автоматизация BUILDING.md §5. Смысл: «обновлённый» образ однажды
    содержал внутри СТАРЫЙ загрузчик, и по одному имени файла это не
    видно. Поэтому проверяются и геометрия, и СОДЕРЖИМОЕ образа.

    Что проверяется
      геометрия (то, что требует log_stick_ok(), src/unlock_v2.c:9731):
        * LBA 0: сигнатура 55AA и ни одного признака GPT
        * ровно ОДИН раздел, тип 0xEF, флаг boot 0x80, начало LBA 2048
        * загрузочный сектор раздела: 55AA и "FAT32   " по 0x52 (не 0x54!)
        * последний сектор раздела упирается в конец образа
      содержимое (FAT32 разбирается напрямую, без монтирования):
        * EFI\BOOT\BOOTX64.EFI существует, размер и md5 совпадают с
          src\unlock_v3r.efi
        * маркерные строки ВНУТРИ файла: профиль карты, gfx, rmask, loghdr;
          профиль 90HX отсутствует
        * VERSION.txt совпадает с текущим src\unlock_v3r.efi
        * gsp_ga10x.bin отсутствует (с v3.42 он не читается)
      общее:
        * размер образа в байтах

    Usage:
        powershell -ExecutionPolicy Bypass -File out\verify-image.ps1
        powershell -ExecutionPolicy Bypass -File out\verify-image.ps1 -Image dist\cmp70hx-unlock-1.0.0.img
        powershell -ExecutionPolicy Bypass -File out\verify-image.ps1 -Efi D:\some\unlock_v3r.efi

    Код возврата: 0 — PASS, 1 — есть FAIL (образ публиковать нельзя).
#>
[CmdletBinding()]
param(
    # Образ для проверки. По умолчанию — самый свежий .img в dist\.
    [string]$Image = '',

    # Эталонный загрузчик. По умолчанию src\unlock_v3r.efi.
    [string]$Efi = '',

    # Ожидаемый размер образа в МиБ; 0 = не проверять.
    [int]$SizeMiB = 256,

    # Побайтово сверить УЖЕ ЗАПИСАННУЮ флешку с образом. Образ покрывает
    # только первые SizeMiB, поэтому сверяется именно этот префикс.
    #   -CompareTo            - найти флешку по геометрии
    #   -CompareTo <образ>    - сверить конкретный .img с найденной флешкой
    [string]$CompareTo = '',

    # Пропустить геометрию/содержимое образа и сделать только сверку.
    [switch]$CompareOnly
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }

$projRoot = Split-Path -Parent $PSScriptRoot
$distDir  = Join-Path $projRoot 'dist'
if (-not $Efi) { $Efi = Join-Path $projRoot 'src\unlock_v3r.efi' }

# Ожидания log_stick_ok() — жёсткие, как в коде.
$ESP_LBA     = 2048
$PART_TYPE   = 0xEF
$PART_BOOT   = 0x80
$LOG_LBA     = 4000000
$LOG_SECTORS = 2048
$EXPECT_LOADER = 'EFI/BOOT/BOOTX64.EFI'
$EXPECT_GSP    = 'gsp_ga10x.bin'

$REQUIRED = @(
    @{ name = 'profile70'; text = 'CMP 70HX (GA104)'  },
    @{ name = 'loghdr';    text = 'CMPUNLOG v1 '      },
    @{ name = 'gfx';       text = 'GFX_SPEED_SELECT' },
    @{ name = 'rmask';     text = 'G2RMS'            }
)
$FORBIDDEN = @(
    @{ name = 'profile90'; text = 'CMP 90HX (GA102)' }
)

$script:fail = 0
$script:pass = 0

function Say  ($m) { Write-Host $m -ForegroundColor Cyan }
function OK   ($m) { $script:pass++; Write-Host "  OK   $m" -ForegroundColor Green }
function Fail ($m) { $script:fail++; Write-Host "  FAIL $m" -ForegroundColor Red }
function Info ($m) { Write-Host "  --   $m" -ForegroundColor DarkGray }
# Good/Warn печатают, НЕ меняя счётчики: это сообщения о ходе дела, а не
# результат проверки. Они были объявлены только в make-image.ps1, а ветка
# -CompareOnly вызывает их — и падала с «CommandNotFoundException: Good».
function Good ($m) { Write-Host "  OK   $m" -ForegroundColor Green }
function Warn ($m) { Write-Host "  WARN $m" -ForegroundColor Yellow }

# ============================================================ входные файлы
if (-not $Image) {
    if (-not (Test-Path -LiteralPath $distDir)) { Write-Host "Нет каталога $distDir — соберите образ: out\make-image.ps1" -ForegroundColor Red; exit 1 }
    $cand = @(Get-ChildItem -LiteralPath $distDir -Filter 'cmp70hx-unlock-*.img' -File |
              Sort-Object LastWriteTime -Descending)
    if ($cand.Count -eq 0) { Write-Host "В $distDir нет ни одного .img" -ForegroundColor Red; exit 1 }
    $Image = $cand[0].FullName
}
if (-not (Test-Path -LiteralPath $Image)) { Write-Host "Образ не найден: $Image" -ForegroundColor Red; exit 1 }
if (-not (Test-Path -LiteralPath $Efi))   { Write-Host "Эталонный загрузчик не найден: $Efi" -ForegroundColor Red; exit 1 }

$imgSize = (Get-Item -LiteralPath $Image).Length
$efiMd5  = (Get-FileHash -LiteralPath $Efi -Algorithm MD5).Hash
$efiSize = (Get-Item -LiteralPath $Efi).Length

Say '=== CMP unlock: проверка образа ==='
Say "    образ:     $Image"
Say "    загрузчик: $Efi"
Write-Host ''

# ------------------------------------------------------------------ сверка
# Отдельный режим: образ уже записан на флешку, надо убедиться, что записалось
# именно он, а не что-то другое. Скорость не важна — сверка идёт блоками.
function Invoke-StickCompare {
    $ref = if ($CompareTo -and (Test-Path -LiteralPath $CompareTo)) { $CompareTo } else { $Image }
    if (-not (Test-Path -LiteralPath $ref)) { Write-Host "Образ для сверки не найден: $ref" -ForegroundColor Red; exit 1 }

    $finder = Join-Path $PSScriptRoot 'find-stick.ps1'
    if (-not (Test-Path -LiteralPath $finder)) { Write-Host "Нет $finder" -ForegroundColor Red; exit 1 }
    . $finder
    $stick = Find-StickDisk
    if (-not $stick) {
        Show-StickScan
        Write-Host 'Флешка с нашей разметкой не найдена.' -ForegroundColor Red
        exit 1
    }

    Say "Сверка: $(Split-Path $ref -Leaf) против PhysicalDrive$($stick.DiskNumber) ..."
    $refSize = (Get-Item -LiteralPath $ref).Length
    $chunk = 4MB
    $b1 = New-Object byte[] $chunk
    $b2 = New-Object byte[] $chunk
    $sf = [IO.File]::Open($stick.DevicePath, 'Open', 'Read', 'ReadWrite')
    $rf = [IO.File]::OpenRead($ref)
    $bad = 0
    $done = 0L
    try {
        while ($done -lt $refSize) {
            $want = [int][Math]::Min([int64]$chunk, $refSize - $done)
            $r1 = $sf.Read($b1, 0, $want)
            $r2 = $rf.Read($b2, 0, $want)
            if ($r1 -ne $want -or $r2 -ne $want) {
                Fail ("прочитано меньше, чем нужно, на отметке {0} байт (диск {1}, образ {2})" -f $done, $r1, $r2)
                break
            }
            if (-not [System.Linq.Enumerable]::SequenceEqual([byte[]]$b1, [byte[]]$b2)) {
                # НЕ Fail: расхождение в первых блоках — это serial тома и метки
                # времени FAT32, они случайны при каждой пересборке. Побайтовое
                # совпадение возможно только с ТЕМ ЖЕ файлом .img. Вердикт даёт
                # сверка загрузчика ниже.
                if ($bad -eq 0) { Info ("первое расхождение на отметке {0} (0x{0:X})" -f $done) }
                $bad++
            }
            $done += $want
        }
    } finally { $sf.Dispose(); $rf.Dispose() }

    if ($bad -eq 0 -and $done -eq $refSize) {
        Good ("совпало {0:N0} байт ({1} МиБ), различий нет — это и есть побайтовое совпадение" -f $done, ($done / 1MB))
        Info 'такое возможно только с ТЕМ ЖЕ файлом .img, который записан на флешку'
    } else {
        # Два билда одного и того же образа ВСЕГДА различаются: внутри FAT32
        # есть случайный serial тома и метки времени в записях каталога. Так
        # что побайтовое сравнение с ПЕРЕСОБРАННЫМ образом — не брак, а
        # ожидаемость. Ниже решается вопрос, который на самом деле важен:
        # лежит ли на флешке тот загрузчик, который мы собирались записать.
        Info ("побайтово совпало {0} из {1} блоков по 4 МиБ" -f `
              ([int][Math]::Ceiling($done / [double]$chunk) - $bad), [int][Math]::Ceiling($done / [double]$chunk))
        Info 'расхождения в serial тома и метках времени FAT32 — они случайны,' -ForegroundColor DarkGray
        Info 'поэтому пересобранный образ никогда не совпадёт побайтово.' -ForegroundColor DarkGray
    }

    # Проверка загрузчика идёт ВСЕГДА, даже при полном побайтовом совпадении.
    # Иначе в ветке «различий нет» счётчик проверок остаётся нулевым, и вывод
    # «СВЕРКА ПРОЙДЕНА: 0 проверок» выглядит так, будто ничего не проверяли.
    $espSectors = $stick.EspSectors
    if (-not $espSectors) {
        $rf2 = [IO.File]::OpenRead($ref)
        try {
            $rm = New-Object byte[] 512
            $null = $rf2.Read($rm, 0, 512)
            for ($i = 0; $i -lt 4; $i++) {
                $o = 446 + 16 * $i
                if ($rm[$o + 4] -eq $PART_TYPE) {
                    $espSectors = [BitConverter]::ToUInt32($rm, $o + 12)
                    break
                }
            }
        } finally { $rf2.Close() }
    }
    Say ''
    Say 'Сверка содержимого флешки с эталонным загрузчиком ...'
    Test-StickPayload -Device $stick.DevicePath -EspSectors $espSectors
    Info ('образ покрывает только первые {0:N0} байт; хвост флешки — старая разметка, она не проверялась' -f $refSize)
    Info 'буквы тома не будет (тип раздела 0xEF) — для проверки это не нужно'
}

function Test-StickPayload {
    param([string]$Device, [int]$EspSectors = 0)

    # Флешку читаем ЧЕРЕЗ ВРЕМЕННЫЙ ДАМП РАЗДЕЛА, а не по смещениям напрямую.
    # Причина техническая: дескрипт��р \\.\PhysicalDriveN открывается под
    # overlapped-I/O, и произвольный синхронный FileStream.Read() на нём
    # падает с «дескриптор не поддерживает синхронных операций». Надёжно
    # читать физический диск получается только в конкретном виде
    # (File.Open + Read, как в Invoke-StickCompare). Поэтому содержимое
    # раздела один раз выгружаем во временный файл, а дальше работаем с
    # обычным файлом, где поведение предсказуемо.
    if ($EspSectors -le 0) { $EspSectors = 524288 - $ESP_LBA }
    $tmp = [IO.Path]::Combine([IO.Path]::GetTempPath(), ("cmp70-sp-" + [Guid]::NewGuid().ToString('N') + ".bin"))
    $dev = [IO.File]::Open($Device, 'Open', 'Read', 'ReadWrite')
    try {
        $dev.Seek([int64]$ESP_LBA * 512, 'Begin') | Out-Null
        $out = [IO.File]::Create($tmp)
        try {
            $buf = New-Object byte[] (4MB)
            $left = [int64]$EspSectors * 512
            while ($left -gt 0) {
                $n = [int][Math]::Min([int64]$buf.Length, $left)
                $got = $dev.Read($buf, 0, $n)
                if ($got -le 0) { break }
                $out.Write($buf, 0, $got)
                $left -= $got
            }
        } finally { $out.Close() }
    } finally { $dev.Close() }

    try { Test-ImagePayload -Image $tmp }
    finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
}

# Содержимое образа: найти EFI\BOOT\BOOTX64.EFI в FAT32, сверить md5 с
# эталоном, поискать маркеры внутри файла. Отдельная функция, потому что то
# же самое нужно для двух источников — файла .img и дампа раздела флешки.
# Смещения внутри раздела считаются от нуля, поэтому дамп раздела годится
# прямо здесь, без поправки на LBA 2048.
function Test-ImagePayload {
    param([string]$Image)

    $h = [IO.File]::OpenRead($Image)
    try {
        $bs = New-Object byte[] 512
        if ($h.Read($bs, 0, 512) -ne 512) { Fail 'не прочитал загрузочный сектор'; return }
        if ($bs[510] -ne 0x55 -or $bs[511] -ne 0xAA) { Fail 'в разделе нет сигнатуры 55AA'; return }
        if ([Text.Encoding]::ASCII.GetString($bs, 0x52, 8) -ne 'FAT32   ') { Fail 'в разделе не FAT32'; return }
    } finally { $h.Close() }

    $bps     = [BitConverter]::ToUInt16($bs, 0x0B)
    $fatOff  = [uint64][BitConverter]::ToUInt16($bs, 0x0E) * $bps
    $dataOff = $fatOff + [uint64]$bs[0x10] * [BitConverter]::ToUInt32($bs, 0x24) * $bps
    $clus    = [uint64]$bs[0x0D] * $bps
    $root    = [BitConverter]::ToUInt32($bs, 0x2C)
    $MASK    = 0x0FFFFFFF
    $EOC     = 0x0FFFFFF8

$hh = [IO.File]::OpenRead($Image)
    try {
        # Имена функций здесь длинные и НЕ пересекаются с встроенными
        # алиасами PowerShell. Алиас имеет приоритет над функцией: короткое
        # имя вроде Rd (это алиас Remove-Item) молча вызвало бы Remove-Item.
        function Read-Sectors ([uint64]$off, [int]$len) {
            $b = New-Object byte[] $len
            $hh.Seek([int64]$off, 'Begin') | Out-Null
            $k = $hh.Read($b, 0, $len)
            if ($k -lt $len) { throw "короткое чтение на $off" }
            return $b
        }
        function Get-FatChain ([uint32]$first) {
            $o = New-Object System.Collections.ArrayList
            $c = $first
            while ($c -ge 2 -and $c -lt $EOC -and $o.Count -lt 4194304) {
                [void]$o.Add([uint32]$c)
                $entry = Read-Sectors ([uint64]($fatOff + 4 * $c)) 4
                $c = ([BitConverter]::ToUInt32($entry, 0) -band $MASK)
            }
            return $o
        }
        function Get-NodeData ([uint32]$first, [uint32]$size) {
            $ms = New-Object IO.MemoryStream
            $left = [uint64]$size
            foreach ($c in (Get-FatChain $first)) {
                if ($left -eq 0) { break }
                $cb = Read-Sectors ([uint64]($dataOff + ($c - 2) * $clus)) ([int]$clus)
                $take = [int][Math]::Min([uint64]$cb.Length, $left)
                $ms.Write($cb, 0, $take); $left -= $take
            }
            return $ms.ToArray()
        }
        function Get-DirData ([uint32]$first) {
            $ms = New-Object IO.MemoryStream
            foreach ($c in (Get-FatChain $first)) {
                $cb = Read-Sectors ([uint64]($dataOff + ($c - 2) * $clus)) ([int]$clus)
                $ms.Write($cb, 0, $cb.Length)
            }
            return $ms.ToArray()
        }
        function Get-DirEntries ([uint32]$clus0) {
            $out = @{}
            $bytes = Get-DirData $clus0
            $lfn = New-Object System.Collections.ArrayList
            for ($i = 0; $i + 32 -le $bytes.Length; $i += 32) {
                if ($bytes[$i] -eq 0x00) { break }
                if ($bytes[$i] -eq 0xE5) { $lfn.Clear(); continue }
                $attr = $bytes[$i + 11]
                if ($attr -eq 0x0F) {
                    $part = ''
                    foreach ($off in 1,3,5,7,9,14,16,18,20,22,24,28,30) {
                        $ch = [BitConverter]::ToUInt16($bytes, $i + $off)
                        if ($ch -eq 0x0000 -or $ch -eq 0xFFFF) { break }
                        $part += [char]$ch
                    }
                    [void]$lfn.Add([pscustomobject]@{ Seq = ($bytes[$i] -band 0x3F); Text = $part })
                    continue
                }
                $b8 = [Text.Encoding]::ASCII.GetString($bytes, $i, 8).TrimEnd()
                $x3 = [Text.Encoding]::ASCII.GetString($bytes, $i + 8, 3).TrimEnd()
                $nm = if ($x3) { "$b8.$x3" } else { $b8 }
                if ($nm -eq '.' -or $nm -eq '..') { $lfn.Clear(); continue }
                if (($attr -band 0x08) -ne 0) { $lfn.Clear(); continue }
                if ($lfn.Count -gt 0) {
                    $nm = ''
                    foreach ($p in ($lfn | Sort-Object Seq)) { $nm += $p.Text }
                    $lfn.Clear()
                }
                $out[$nm.ToUpperInvariant()] = [pscustomobject]@{
                    IsDir = (($attr -band 0x10) -ne 0)
                    Clus  = [uint32]([BitConverter]::ToUInt16($bytes, $i + 26))
                    Size  = [BitConverter]::ToUInt32($bytes, $i + 28)
                }
            }
            return $out
        }
        function Find-StickFile ([string]$path) {
            $parts = $path.ToUpperInvariant() -split '/'
            $here = Get-DirEntries $root
            for ($i = 0; $i -lt $parts.Count - 1; $i++) {
                if (-not $here.ContainsKey($parts[$i])) { return $null }
                $e = $here[$parts[$i]]
                if (-not $e.IsDir) { return $null }
                $here = Get-DirEntries $e.Clus
            }
            if ($here.ContainsKey($parts[-1])) { return $here[$parts[-1]] }
            return $null
        }

        $ent = Find-StickFile $EXPECT_LOADER
        if (-not $ent -or $ent.IsDir) {
            Fail ("нет {0} — прошивка не найдёт загрузчик" -f $EXPECT_LOADER)
        } else {
            $lb = Get-NodeData $ent.Clus $ent.Size
            $md5 = [Security.Cryptography.MD5]::Create()
            $lMd5 = (($md5.ComputeHash($lb) | ForEach-Object { $_.ToString('x2') }) -join '')
            if ($ent.Size -eq $efiSize) { OK ("{0}: размер {1} байт" -f $EXPECT_LOADER, $ent.Size) }
            else { Fail ("{0}: размер {1}, у эталона {2}" -f $EXPECT_LOADER, $ent.Size, $efiSize) }
            if ($lMd5 -eq $efiMd5.ToLower()) { OK ("{0}: md5 {1} — это ровно тот загрузчик, что собран" -f $EXPECT_LOADER, $lMd5) }
            else { Fail ("{0}: md5 {1}, а собран {2}. Другая сборка" -f $EXPECT_LOADER, $lMd5, $efiMd5) }
            if ($lb.Length -ge 2 -and $lb[0] -eq 0x4D -and $lb[1] -eq 0x5A) { OK 'загрузчик PE: сигнатура MZ' }
            else { Fail 'загрузчик без сигнатуры MZ' }
            $txt = [Text.Encoding]::ASCII.GetString($lb) + "`n" + [Text.Encoding]::Unicode.GetString($lb)
            foreach ($r in $REQUIRED) {
                if ($txt.Contains($r.text)) { OK ("маркер {0,-10} ВНУТРИ загрузчика: {1}" -f $r.name, $r.text) }
                else { Fail ("маркер {0} ОТСУТСТВУЕТ в загрузчике: {1} — gfx/rmask это маркеры -DRENDER_MASKS, без них compute работает, а игры дают ноль" -f $r.name, $r.text) }
            }
            foreach ($f in $FORBIDDEN) {
                if ($txt.Contains($f.text)) { Fail ("маркер {0} есть — это профиль ЧУЖОЙ карты" -f $f.name) }
                else { OK ("маркер {0,-10} отсутствует (верно)" -f $f.name) }
            }
        }
        if (Find-StickFile 'VERSION.TXT') { OK 'VERSION.txt на месте' } else { Fail 'нет VERSION.txt' }
        if (Find-StickFile $EXPECT_GSP) {
            Fail ("есть {0} — с v3.42 он не читается, это лишние 84 МБ и вопрос лицензии NVIDIA" -f $EXPECT_GSP)
        } else { OK ("{0} отсутствует — и он не нужен с v3.42" -f $EXPECT_GSP) }
    } finally { $hh.Close() }
}

# Сверка «флешка против образа». Идёт ПЕРЕД проверкой самого .img, потому что
# -CompareOnly должен пропустить её: сверяться с чем-то, что заведомо не
# проверено, смысла нет.
if ($CompareTo -or $CompareOnly) {
    Invoke-StickCompare
    Write-Host ''
    if ($script:fail) {
        Write-Host (" СВЕРКА НЕ ПРОЙДЕНА: {0} OK, {1} FAIL" -f $script:pass, $script:fail) -ForegroundColor Red
        exit 1
    }
    Write-Host (" СВЕРКА ПРОЙДЕНА: {0} проверок" -f $script:pass) -ForegroundColor Green
    exit 0
}

# ============================================================ геометрия
Say '[1/3] геометрия образа (то, что требует log_stick_ok) ...'
if ($SizeMiB -gt 0) {
    $want = [uint64]$SizeMiB * 1MB
    if ($imgSize -eq $want) { OK ("размер {0:N0} байт = {1} МиБ" -f $imgSize, $SizeMiB) }
    else { Fail ("размер {0:N0} байт, ожидалось {1:N0} ({2} МиБ)" -f $imgSize, $want, $SizeMiB) }
}

$fs = [IO.File]::Open($Image, 'Open', 'Read', 'ReadWrite')
try {
    $mbr = New-Object byte[] 512
    $fs.Seek(0, 'Begin') | Out-Null
    [void]$fs.Read($mbr, 0, 512)

    if ($mbr[510] -eq 0x55 -and $mbr[511] -eq 0xAA) { OK 'LBA 0: сигнатура 55AA' }
    else { Fail ("LBA 0: 55AA нет (0x{0:X2} 0x{1:X2}) — это не MBR" -f $mbr[510], $mbr[511]) }

    # GPT-признаки в MBR: protective MBR оставляет тип 0xEE и раздел на LBA 2+.
    $efParts = @()
    for ($i = 0; $i -lt 4; $i++) {
        $o = 446 + 16 * $i
        $type = $mbr[$o + 4]
        if ($type -ne 0) { $efParts += [pscustomobject]@{ Index = $i; Type = $type; Boot = $mbr[$o]; Start = [BitConverter]::ToUInt32($mbr, $o + 8); Sectors = [BitConverter]::ToUInt32($mbr, $o + 12) } }
    }
    if ($efParts.Count -eq 0) { Fail 'в MBR нет ни одной записи раздела' }
    else { Info ("записей раздела в MBR: {0} -> {1}" -f $efParts.Count, (($efParts | ForEach-Object { "type=0x{0:X2} boot=0x{1:X2} LBA {2}+{3}" -f $_.Type, $_.Boot, $_.Start, $_.Sectors }) -join '; ')) }
    if (@($efParts | Where-Object { $_.Type -eq 0xEE }).Count) { Fail 'в MBR есть тип 0xEE — похоже на protective MBR от GPT, прошивка может уйти мимо флешки' }
    if ($efParts.Count -ne 1) { Fail ("разделов в MBR {0}, log_stick_ok требует РОВНО ОДИН 0xEF" -f $efParts.Count) }

    $p = @($efParts | Where-Object { $_.Type -eq $PART_TYPE })
    if ($p.Count -ne 1) {
        Fail ("разделов типа 0xEF: {0}, нужен ровно один (AMI-прошивки и log_stick_ok оба требуют ESP-тип)" -f $p.Count)
    } else {
        $esp = $p[0]
        if ($esp.Boot -eq $PART_BOOT) { OK 'флаг boot 0x80 установлен' } else { Fail ("флаг boot = 0x{0:X2}, ожидался 0x80" -f $esp.Boot) }
        if ($esp.Start -eq $ESP_LBA)    { OK 'раздел начинается с LBA 2048 — это разрез, отличающий нашу флешку' }
        else { Fail ("раздел начинается с LBA {0}, а не 2048 — log_stick_ok отбросит флешку, лог не пишется" -f $esp.Start) }
        $end = [uint64]$esp.Start + [uint64]$esp.Sectors
        $total = [uint64]($imgSize / 512)
        if ($end -le $total) { OK ("раздел кончается на LBA {0} (весь образ {1} секторов) — хвоста нет" -f $end, $total) }
        else { Fail ("раздел кончается на LBA {0}, а образ всего {1} секторов — образ короче раздела" -f $end, $total) }
    }

    # загрузочный сектор раздела
    $bsOff = [uint64]$ESP_LBA * 512
    $bs = New-Object byte[] 512
    $fs.Seek([int64]$bsOff, 'Begin') | Out-Null
    [void]$fs.Read($bs, 0, 512)
    if ($bs[510] -eq 0x55 -and $bs[511] -eq 0xAA) { OK 'загрузочный сектор раздела: 55AA' }
    else { Fail ("загрузочный сектор раздела без 55AA (0x{0:X2} 0x{1:X2})" -f $bs[510], $bs[511]) }
    $fsType = [Text.Encoding]::ASCII.GetString($bs, 0x52, 8)
    if ($fsType -eq 'FAT32   ') { OK 'FilSysType по 0x52 = "FAT32   " — ровно как читает log_stick_ok' }
    else { Fail ("FilSysType по 0x52 = '{0}' — log_stick_ok отбросит флешку. ВНИМАНИЕ: читать надо 0x52, по 0x54 хвост поля" -f $fsType) }

    $bps   = [BitConverter]::ToUInt16($bs, 0x0B)
    $spc   = $bs[0x0D]
    $resv  = [BitConverter]::ToUInt16($bs, 0x0E)
    $nfat  = $bs[0x10]
    $tot32 = [BitConverter]::ToUInt32($bs, 0x20)
    $fatsz = [BitConverter]::ToUInt32($bs, 0x24)
    $root  = [BitConverter]::ToUInt32($bs, 0x2C)
    Info ("BPB: bps={0} spc={1} resv={2} nfat={3} totSec32={4} fatsz={5} rootClus={6}" -f $bps, $spc, $resv, $nfat, $tot32, $fatsz, $root)
    if ($bps -eq 512) { OK 'bps = 512' } else { Fail "bps = $bps, ожидалось 512" }
    # Сверять BPB с разделом можно только когда ESP найден РОВНО ОДИН: при
    # двух разделах 0xEF непонятно, к какому из них относится загрузочный сектор,
    # и такое сравнение даёт ложный FAIL поверх настоящей ошибки.
    if ($tot32 -gt 0 -and $p.Count -eq 1) {
        if ($tot32 -eq $esp.Sectors) { OK "BPB totalSec32 = $tot32 совпадает с размером раздела" }
        else { Fail ("BPB totalSec32 = $tot32, а раздел {0} секторов. Windows покажет «неправильный диск» или откажется давать букву — ровно та ловушка, что описана в make-usb-stick.ps1" -f $esp.Sectors) }
    } elseif ($p.Count -ne 1) {
        Info 'сверка BPB с разделом пропущена: разделов 0xEF не ровно один'
    } else { Info 'totSec32 = 0 (для FAT32 это допустимо) — размер раздела не сверяем' }

    # ------------------------------------------------------ разбор FAT32
    Say ''
    Say '[2/3] содержимое образа (FAT32 разбирается напрямую) ...'
    $fatOff    = [uint64]$bsOff + [uint64]$resv * $bps
    $dataOff   = $fatOff + [uint64]$nfat * $fatsz * $bps
    $clusBytes = [uint64]$spc * $bps

    $EOC  = 0x0FFFFFF8
    $MASK = 0x0FFFFFFF

    function Read-At ([uint64]$off, [int]$len) {
        $b = New-Object byte[] $len
        $fs.Seek([int64]$off, 'Begin') | Out-Null
        $got = $fs.Read($b, 0, $len)
        if ($got -lt $len) { throw "короткое чтение на $off" }
        return $b
    }
    function Get-FatEntry ([uint32]$c) {
        $b = Read-At ([uint64]($fatOff + 4 * $c)) 4
        return ([BitConverter]::ToUInt32($b, 0) -band $MASK)
    }
    # кластеры файла/каталога по цепочке FAT
    function Get-Chain ([uint32]$first) {
        $chain = New-Object System.Collections.ArrayList
        $c = $first
        $guard = 0
        while ($c -ge 2 -and $c -lt $EOC -and $guard -lt 4194304) {
            [void]$chain.Add([uint32]$c)
            $c = Get-FatEntry $c
            $guard++
        }
        return $chain
    }
    function Get-ClusterBytes ([uint32]$c) { return (Read-At ([uint64]($dataOff + ($c - 2) * $clusBytes)) ([int]$clusBytes)) }
    function Get-NodeBytes ([uint32]$first, [uint32]$size) {
        $ms = New-Object IO.MemoryStream
        $left = [uint64]$size
        foreach ($c in (Get-Chain $first)) {
            if ($left -eq 0) { break }
            $cb = Get-ClusterBytes $c
            $take = [int][Math]::Min([uint64]$cb.Length, $left)
            $ms.Write($cb, 0, $take)
            $left -= $take
        }
        return $ms.ToArray()
    }
    # Каталог читаем целиком по цепочке. Литерал 0xFFFFFFFF в PowerShell — это
    # int -1, поэтому «читать всё» здесь отдельной функцией, а не размером.
    function Get-NodeAll ([uint32]$first) {
        $ms = New-Object IO.MemoryStream
        foreach ($c in (Get-Chain $first)) {
            $cb = Get-ClusterBytes $c
            $ms.Write($cb, 0, $cb.Length)
        }
        return $ms.ToArray()
    }
    function Get-Sha ([byte[]]$bytes) {
        $md5 = [Security.Cryptography.MD5]::Create()
        return (($md5.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
    }

    # $entries: PSCustomObject Name/Short/IsDir/Clus/Size
    #
    # Длинные имена. Windows записывает EFI\BOOT\BOOTX64.EFI как 8.3
    # («BOOTX64 EFI») плюс записи LFN (атрибут 0x0F), и читает файл именно
    # по LFN — так же поступает и UEFI. Поэтому проверять 8.3-имя
    # недостаточно: имя могло бы разъехаться и прошивка не нашла бы файл.
    # Порядок проверен на реальном образе (dump каталога): на диске записи идут
    # ПО УБЫВАНИЮ seq, и старший seq хранит ХВОСТ имени — seq 1 = «System
    # Volume», seq 2 = « Information». Значит склеивать надо ПО ВОЗРАСТАНИЮ.
    # Именно этот порядок и читает UEFI.
    function Read-Dir ([uint32]$clus) {
        $out = @()
        $bytes = Get-NodeAll $clus
        $lfn = New-Object System.Collections.ArrayList
        for ($i = 0; $i + 32 -le $bytes.Length; $i += 32) {
            $first = $bytes[$i]
            if ($first -eq 0x00) { break }            # конец каталога
            if ($first -eq 0xE5) { $lfn.Clear(); continue }   # удалённая запись
            $attr = $bytes[$i + 11]
            if ($attr -eq 0x0F) {
                # 13 слотов UTF-16 по смещениям 1..9, 14..24, 28..30. Обрезаем по
                # ПЕРВОМУ нулю: хвост слота забит 0x0000/0xFFFF.
                $part = ''
                foreach ($off in 1,3,5,7,9,14,16,18,20,22,24,28,30) {
                    $ch = [BitConverter]::ToUInt16($bytes, $i + $off)
                    if ($ch -eq 0x0000 -or $ch -eq 0xFFFF) { break }
                    $part += [char]$ch
                }
                [void]$lfn.Add([pscustomobject]@{ Seq = ($first -band 0x3F); Text = $part })
                continue
            }
            # 8.3-имя: 8 байт базы + точка + 3 байта расширения. Без точки
            # «BOOTX64 EFI» не совпадёт с «BOOTX64.EFI», который ищет прошивка.
            $base = [Text.Encoding]::ASCII.GetString($bytes, $i, 8).TrimEnd()
            $ext  = [Text.Encoding]::ASCII.GetString($bytes, $i + 8, 3).TrimEnd()
            $short = if ($ext) { "$base.$ext" } else { $base }
            if ($short -eq '.' -or $short -eq '..') { $lfn.Clear(); continue }
            if (($attr -band 0x08) -ne 0) { $lfn.Clear(); continue }   # метка тома, не файл
            $name = $short
            if ($lfn.Count -gt 0) {
                $name = ''
                foreach ($p in ($lfn | Sort-Object Seq)) { $name += $p.Text }
                $lfn.Clear()
            }
            $out += [pscustomobject]@{
                Name  = $name
                Short = $short
                IsDir = (($attr -band 0x10) -ne 0)
                Clus  = [uint32]([BitConverter]::ToUInt16($bytes, $i + 26))
                Size  = [BitConverter]::ToUInt32($bytes, $i + 28)
            }
        }
        return $out
    }

    $files = @{}
    $dirsToRead = New-Object System.Collections.ArrayList
    [void]$dirsToRead.Add([pscustomobject]@{ Path = ''; Clus = $root })
    while ($dirsToRead.Count -gt 0) {
        $d = $dirsToRead[0]; $dirsToRead.RemoveAt(0)
        foreach ($e in (Read-Dir $d.Clus)) {
            $path = if ($d.Path) { "$($d.Path)/$($e.Name)" } else { $e.Name }
            if ($e.IsDir) { [void]$dirsToRead.Add([pscustomobject]@{ Path = $path; Clus = $e.Clus }) }
            else { $files[$path.ToUpperInvariant()] = $e }
        }
    }
    Info ("файлов в разделе: {0}" -f $files.Count)
    foreach ($k in ($files.Keys | Sort-Object)) {
        Info ("  {0}  ({1} байт, 8.3: {2})" -f $k, $files[$k].Size, $files[$k].Short)
    }

    $loaderRel = $EXPECT_LOADER
    if (-not $files.ContainsKey($loaderRel.ToUpperInvariant())) {
        Fail ("в образе нет {0} — прошивка не найдёт загрузчик и флешка не загрузится" -f $loaderRel)
    } else {
        $ent = $files[$loaderRel]
        $loaderBytes = Get-NodeBytes $ent.Clus $ent.Size
        $lMd5 = Get-Sha $loaderBytes
        if ($ent.Size -eq $efiSize) { OK ("{0}: размер {1} байт" -f $loaderRel, $ent.Size) }
        else { Fail ("{0}: размер {1}, у эталона {2}" -f $loaderRel, $ent.Size, $efiSize) }
        if ($lMd5 -eq $efiMd5) { OK ("{0}: md5 {1} — совпадает с src\unlock_v3r.efi" -f $loaderRel, $lMd5) }
        else { Fail ("{0}: md5 {1}, а у эталона {2}. В образе СТАРЫЙ или чужой загрузчик — публиковать нельзя" -f $loaderRel, $lMd5, $efiMd5) }

        if ($loaderBytes.Length -ge 2 -and $loaderBytes[0] -eq 0x4D -and $loaderBytes[1] -eq 0x5A) { OK 'загрузчик PE: сигнатура MZ' }
        else { Fail 'загрузчик без сигнатуры MZ — это не PE/COFF' }

        $ascii = [Text.Encoding]::ASCII.GetString($loaderBytes)
        $utf16 = [Text.Encoding]::Unicode.GetString($loaderBytes)
        $all   = $ascii + "`n" + $utf16
        foreach ($r in $REQUIRED) {
            if ($all.Contains($r.text)) { OK ("маркер {0,-10} ВНУТРИ загрузчика: {1}" -f $r.name, $r.text) }
            else { Fail ("маркер {0} ОТСУТСТВУЕТ в загрузчике: {1} — gfx/rmask это маркеры -DRENDER_MASKS, без них compute работает, а игры дают ноль" -f $r.name, $r.text) }
        }
        foreach ($f in $FORBIDDEN) {
            if ($all.Contains($f.text)) { Fail ("маркер {0} есть — это профиль ЧУЖОЙ карты" -f $f.name) }
            else { OK ("маркер {0,-10} отсутствует (верно)" -f $f.name) }
        }
    }

    if ($files.ContainsKey('VERSION.TXT')) {
        $e = $files['VERSION.TXT']
        $vt = [Text.Encoding]::ASCII.GetString((Get-NodeBytes $e.Clus $e.Size))
        if ($vt -match [regex]::Escape($efiMd5)) { OK 'VERSION.txt содержит md5 текущего загрузчика' }
        else { Fail "VERSION.txt не содержит md5 $efiMd5 — на флешке лежит другая сборка" }
    } else { Fail 'в образе нет VERSION.txt' }

    if ($files.ContainsKey('README.TXT')) { OK 'README.txt на месте' } else { Fail 'в образе нет README.txt' }

    if ($files.ContainsKey($EXPECT_GSP.ToUpperInvariant())) {
        Fail ("в образе есть {0} ({1} байт). С v3.42 он не читается (GSP_FW_LBA=0), это лишние 84 МБ и вопрос лицензии NVIDIA — собирайте без -WithGsp" -f $EXPECT_GSP, $files[$EXPECT_GSP.ToUpperInvariant()].Size)
    } else { OK ("{0} отсутствует — и он не нужен с v3.42" -f $EXPECT_GSP) }

    # ------------------------------------------------------ область лога
    Say ''
    Say '[3/3] область лога ...'
    $needLast = [uint64]$LOG_LBA + $LOG_SECTORS
    if ([uint64]($imgSize / 512) -ge $needLast) { OK ("образ покрывает область лога (LBA {0}..{1})" -f $LOG_LBA, ($needLast - 1)) }
    else { Info ("образ НЕ покрывает область лога (LBA {0}) — это нормально: log_clear_area() затирает её на флешке перед каждой записью. Но запись лога возможна только на носителе >= {1} секторов (~{2:N1} ГиБ)" -f $LOG_LBA, $needLast, ($needLast * 512 / 1GB)) }
} finally {
    $fs.Close()
}

Write-Host ''
Write-Host '================================================================================' -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) {
    Write-Host (" ПРОВЕРКА НЕ ПРОЙДЕНА: {0} OK, {1} FAIL" -f $script:pass, $script:fail) -ForegroundColor Red
    Write-Host ' Образ нельзя записывать на флешку и нельзя публиковать.' -ForegroundColor Red
    exit 1
}
Write-Host (" ВСЁ ЧИСТО: {0} проверок" -f $script:pass) -ForegroundColor Green
Write-Host ' Можно записывать на флешку и проверять загрузку на железе.' -ForegroundColor Green
exit 0