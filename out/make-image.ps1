# SPDX-License-Identifier: GPL-2.0-only
<#
    make-image.ps1 — собирает релизный .img для загрузки с флешки.

    Образ: classic MBR + одна primary FAT32 (тип 0xEF), полезная нагрузка
    EFI\BOOT\BOOTX64.EFI. Схема не выбрана нами — её требует код: отбор
    «своей» флешки в log_stick_ok() (src/unlock_v2.c:9731) принимает только
    MBR (не GPT), ровно один раздел типа 0xEF, начинающийся с LBA 2048, и
    "FAT32   " по смещению 0x52 в его загрузочном секторе. Подробности —
    docs/LOGGING.md §3.1, грабли — docs/GOTCHAS.md («Загрузка/образы»).

    Usage (PowerShell as Administrator):
        powershell -ExecutionPolicy Bypass -File out\make-image.ps1
        powershell -ExecutionPolicy Bypass -File out\make-image.ps1 -Version 1.0.1
        powershell -ExecutionPolicy Bypass -File out\make-image.ps1 -SizeMiB 64   # быстрый смоук
        powershell -ExecutionPolicy Bypass -File out\make-image.ps1 -WithGsp

    Как собрано и почему именно так:
      * VHDX фиксированного размера + Initialize-Disk/Format-Volume.
        Рукописный BPB однажды уже не распознавался (make-usb-stick.ps1,
        шапка) — поэтому файловую систему создаёт Windows, а не мы.
      * сырые байты читаются с \\.\PhysicalDriveN ПОСЛЕ размонтирования
        тома и повторного подключения VHDX только на чтение. Пока том
        смонтирован, Windows буферизует запись, и raw-чтение видит мусор —
        ровно та ловушка, что описана в docs/GOTCHAS.md.
      * гейты: маркеры внутри бинаря проверяются ДО сборки, содержимое
        готового образа — ПОСЛЕ, отдельным скриптом out\verify-image.ps1.

    НЕ делает: ничего разрушающего на реальных носителях. VHDX создаётся в
    каталоге образа и удаляется в конце. Запись образа на флешку — это шаг
    человека (BUILDING.md §6.3).

    Exit codes: 0 ok, 1 refused до записи образа, 2 образ записан, но
    проверка после неё не прошла (считать образ непригодным).
#>
[CmdletBinding()]
param(
    # Релиз-версия. Идёт в имя файла, VERSION.txt и отчёт — в бинарник она
    # НЕ вшивается: номера версии в баннере нет намеренно (docs/GOTCHAS.md:
    # отличать сборки по маркерам, а не по номеру), а любая правка исходников
    # двигает md5 и требует нового прогона на железе.
    [string]$Version = '1.0.0',

    # Размер образа в МиБ. 256 МиБ достаточно: полезная нагрузка — один
    # загрузчик (~681 КБ), gsp_ga10x.bin с v3.42 не читается вовсе.
    # Меньше 64 — FAT32 не создастся.
    [int]$SizeMiB = 256,

    # Куда класть .img/.gz/SHA256SUMS. По умолчанию <корень>\dist.
    [string]$OutDir = '',

    # Положить gsp_ga10x.bin (84 МБ). НЕ НУЖЕН: с v3.42 чтение GSP с
    # флешки отключено (GSP_FW_LBA=0), в логе `FWRD READ SKIPPED`.
    # Оставлено для экспериментов с прошивкой.
    [switch]$WithGsp,

    # Не жать .img в .gz.
    [switch]$NoGzip
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }

$projRoot = Split-Path -Parent $PSScriptRoot
$srcEfi   = Join-Path $projRoot 'src\unlock_v3r.efi'
$gspRef   = Join-Path $PSScriptRoot 'gsp_ga10x.bin'
if (-not $OutDir) { $OutDir = Join-Path $projRoot 'dist' }

# --- геометрия, которую требует log_stick_ok() ---------------------------------
$ESP_LBA   = 2048      # src/unlock_v2.c, пункт 6: «ровно один 0xEF с LBA 2048»
$PART_TYPE = 0xEF      # пункт 5; Windows пишет 0x0C — меняем байт @450
$PART_BOOT = 0x80      # байт @446, флаг active

# --- маркеры, которые обязаны выжить в бинарь ---------------------------------
# gfx/rmask — маркеры графики: сборка без -DRENDER_MASKS загружается и
# анлочит compute, выглядит здоровой, а игры дают ноль (flash-build.ps1).
$REQUIRED = @(
    @{ name = 'profile70'; text = 'CMP 70HX (GA104)'  },
    @{ name = 'loghdr';    text = 'CMPUNLOG v1 '      },
    @{ name = 'gfx';       text = 'GFX_SPEED_SELECT' },
    @{ name = 'rmask';     text = 'G2RMS'            }
)
$FORBIDDEN = @(
    @{ name = 'profile90'; text = 'CMP 90HX (GA102)' }
)

$script:img = ''

function Say  ($m) { Write-Host $m -ForegroundColor Cyan }
function Good ($m) { Write-Host "  OK   $m" -ForegroundColor Green }
function Warn ($m) { Write-Host "  WARN $m" -ForegroundColor Yellow }
function Die  ($m, $code = 1) {
    Write-Host ''
    Write-Host "FAIL: $m" -ForegroundColor Red
    if ($script:img -and (Test-Path -LiteralPath $script:img)) {
        Write-Host "      Образ записан, но НЕПРОВЕРЕН: $script:img" -ForegroundColor Red
        Write-Host '      Удалите его и не публикуйте.' -ForegroundColor Red
        exit 2
    }
    Write-Host '      Образ не записан.' -ForegroundColor DarkGray
    exit $code
}
function MD5 ($p) { (Get-FileHash -LiteralPath $p -Algorithm MD5).Hash }

# Работа с томом по пути \\?\Volume{...}\. Провайдер PowerShell такие пути не
# понимает: New-Item, Copy-Item, Get-Item и Get-FileHash на них падают,
# поэтому всё здесь — через System.IO. Заодно Flush($true) на каждом файле:
# том потом отсоединяется, и лишняя запись в кэш нам не нужна.
function MD5Of ([string]$path) {
    $fs = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
    try {
        $h = [Security.Cryptography.MD5]::Create()
        return (($h.ComputeHash($fs) | ForEach-Object { $_.ToString('x2') }) -join '').ToUpper()
    } finally { $fs.Dispose() }
}
# Создать каталог, если его нет. Отдельная функция из-за одной грабли: для
# файла в КОРНЕ тома GetDirectoryName возвращает путь \\?\Volume{...} без
# завершающего слеша; Directory.Exists() на такой форме возвращает False, а
# CreateDirectory() падает с «filename, directory name, or volume label syntax
# is incorrect». Такой каталог по определению существует — его пропускаем.
function Ensure-Dir ([string]$dir) {
    if (-not $dir) { return }
    if ([IO.Directory]::Exists($dir)) { return }
    if ($dir -like '\\?\Volume{*}' -and -not $dir.EndsWith('\')) { return }
    [IO.Directory]::CreateDirectory($dir) | Out-Null
}
function Copy-ToStick ([string]$src, [string]$dst) {
    Ensure-Dir ([IO.Path]::GetDirectoryName($dst))
    [IO.File]::Copy($src, $dst, $true)
    $fs = [IO.File]::Open($dst, 'Open', 'ReadWrite', 'ReadWrite')
    try { $fs.Flush($true) } finally { $fs.Dispose() }
    return $true
}
function Write-StickText ([string]$path, [string]$text) {
    Ensure-Dir ([IO.Path]::GetDirectoryName($path))
    $bytes = [Text.Encoding]::ASCII.GetBytes(($text -replace "`r?`n", "`r`n"))
    $fs = [IO.File]::Open($path, 'Create', 'Write', 'ReadWrite')
    try { $fs.Write($bytes, 0, $bytes.Length); $fs.Flush($true) } finally { $fs.Dispose() }
    return $bytes.Length
}

# Строки лога — широкие (UTF-16LE), поэтому ASCII-скан рапортует «чисто» на
# заведомо хорошем бинаре. Читаем оба представления (flash-build.ps1).
function Get-BlobText ($path) {
    $b = [IO.File]::ReadAllBytes($path)
    if ($b.Length -lt 2 -or $b[0] -ne 0x4D -or $b[1] -ne 0x5A) { return $null }
    return ([Text.Encoding]::ASCII.GetString($b)) + "`n" + ([Text.Encoding]::Unicode.GetString($b))
}

# Номер диска смонтированного VHDX. Ни Get-Disk -ImagePath, ни Get-Disk -Path
# на Windows 10 IoT LTSC не работают, зато у Get-DiskImage есть DevicePath =
# \\.\PhysicalDriveN, из которого номер вынимается напрямую.
function Get-DiskNumberFromDevice ([string]$dev) {
    if ($dev -and $dev -match 'PhysicalDrive(\d+)') { return [int]$Matches[1] }
    return $null
}
function Get-MountedDiskNumber ($vhdx) {
    for ($i = 0; $i -lt 30; $i++) {
        $di = Get-DiskImage -ImagePath $vhdx -ErrorAction SilentlyContinue
        if ($di -and $di.Attached -and $di.DevicePath) {
            $n = Get-DiskNumberFromDevice $di.DevicePath
            if ($null -ne $n) { return $n }
        }
        Start-Sleep -Milliseconds 500
    }
    return $null
}

# Отсоединить VHDX, предварительно сбросив том. Dismount-Volume на этой
# Windows нет, поэтому если образ не отсоединяется «просто так», том
# размонтируется через fsutil. Возвращает $false, если не отсоединился.
function Detach-Vhd ($path) {
    $di = Get-DiskImage -ImagePath $path -ErrorAction SilentlyContinue
    if (-not $di -or -not $di.Attached) { return $true }
    try {
        Dismount-DiskImage -ImagePath $path -ErrorAction Stop
        return $true
    } catch {
        $n = Get-DiskNumberFromDevice $di.DevicePath
        if ($null -ne $n) {
            foreach ($p in @(Get-Partition -DiskNumber $n -ErrorAction SilentlyContinue)) {
                $v = $null
                try { $v = Get-Volume -Partition $p -ErrorAction Stop } catch { }
                if ($v -and $v.DriveLetter) {
                    Say "    том $($v.DriveLetter): занят — размонтирую через fsutil"
                    & fsutil volume dismount "$($v.DriveLetter):" /f | Out-Null
                }
            }
        }
        Start-Sleep -Seconds 2
        try { Dismount-DiskImage -ImagePath $path -ErrorAction Stop; return $true } catch { return $false }
    }
}

# =============================================================================
Say '=== CMP unlock: сборка релизного образа ==='
Say "    версия: $Version    размер: $SizeMiB МиБ"
Say "    вывод:  $OutDir"
Write-Host ''

# --------------------------------------------------------------- 1. исходники
Say '[1/7] загрузчик и его маркеры ...'
if (-not (Test-Path -LiteralPath $srcEfi)) {
    Die "нет $srcEfi`n      Соберите: cd src && BLOBS=`$PWD/blobs bash build.sh  (WSL)"
}
$blobText = Get-BlobText $srcEfi
if (-not $blobText) { Die "$srcEfi не PE-образ (нет сигнатуры MZ)" }
$efiMd5  = MD5 $srcEfi
$efiSize = (Get-Item -LiteralPath $srcEfi).Length
$bad = @()
foreach ($r in $REQUIRED) {
    if ($blobText.Contains($r.text)) { Good ("маркер {0,-10} PRESENT  ({1})" -f $r.name, $r.text) }
    else { $bad += "маркер $($r.name) MISSING ($($r.text))" }
}
foreach ($f in $FORBIDDEN) {
    if ($blobText.Contains($f.text)) { $bad += "маркер $($f.name) PRESENT — это профиль ЧУЖОЙ карты" }
    else { Good ("маркер {0,-10} MISSING (верно)" -f $f.name) }
}
if ($bad.Count) { Die ("бинарь не проходит проверку:`n    " + ($bad -join "`n    ")) }
Good "src\unlock_v3r.efi = $efiMd5 ($efiSize байт)"

$commit = 'nogit'
try { $c = & git -C $projRoot rev-parse --short HEAD 2>$null; if ($c) { $commit = $c } } catch { }
$built = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')

$gspMd5 = $null
$gspLine = 'not required since v3.42 (GSP_FW_LBA=0, never read from the stick)'
if ($WithGsp) {
    if (-not (Test-Path -LiteralPath $gspRef)) { Die "-WithGsp, но нет $gspRef" }
    $gspMd5  = MD5 $gspRef
    $gspLine = "included, md5 $gspMd5 (still not required since v3.42)"
    Good "gsp_ga10x.bin = $gspMd5 (кладём по -WithGsp)"
} else {
    Say '    gsp_ga10x.bin не кладём: с v3.42 он не читается (GSP_FW_LBA=0)'
}

# ------------------------------------------------------------- 2. рабочий VHDX
if ($SizeMiB -lt 64) { Die "SizeMiB $SizeMiB слишком мало, FAT32 не создастся (нужно >= 64)" }
$imgBytes = [uint64]$SizeMiB * 1MB
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$vhdx = Join-Path $OutDir 'build.vhdx'
$img  = Join-Path $OutDir ("cmp70hx-unlock-{0}.img" -f $Version)
$script:img = $img

Say '[2/7] VHDX фиксированного размера и его монтирование ...'
# Остаток прошлого прогона: прерванный скрипт оставляет VHDX подключённым, а
# подключённый файл удалить нельзя. Снимаем и убираем, иначе повторный запуск
# падает на Remove-Item.
if (Test-Path -LiteralPath $vhdx) {
    Say '    найден остаток прошлого прогона — снимаю и удаляю'
    if (-not (Detach-Vhd $vhdx)) { Die "не удалось отсоединить $vhdx — закройте всё, что его держит" }
    Remove-Item -LiteralPath $vhdx -Force
}
New-VHD -Path $vhdx -SizeBytes $imgBytes -Fixed | Out-Null
Good ("vhdx {0:N0} байт" -f $imgBytes)
Mount-DiskImage -ImagePath $vhdx | Out-Null

$dn = Get-MountedDiskNumber $vhdx
if ($null -eq $dn) { Die 'VHDX смонтирован, но номер диска не определяется' }
$disk = Get-Disk -Number $dn
Good "диск $dn ($($disk.BusType), $([math]::Round($disk.Size/1MB)) МиБ)"

# ------------------------------------------- 3. разметка и формат (создаёт Windows)
Say '[3/7] MBR + primary FAT32 со смещением 1 МиБ ...'
Initialize-Disk -Number $dn -PartitionStyle MBR -Confirm:$false | Out-Null
$part = New-Partition -DiskNumber $dn -Offset 1MB -UseMaximumSize

# При смещении 0 загрузочный сектор FAT перезаписал бы MBR, и прошивка молча
# ушла бы мимо флешки — тот самый «FAT16, no drive letter» mess.
if ($part.Offset -ne (1MB)) {
    Die ("раздел начинается с {0}, а не с 1048576 (LBA 2048)" -f $part.Offset)
}
$parts = @(Get-Partition -DiskNumber $dn)
if ($parts.Count -ne 1) { Die ("на диске $dn разделов $($parts.Count), нужен ровно один") }
Good ("раздел: offset={0} (LBA {1}), size={2}" -f $part.Offset, ($part.Offset / 512), $part.Size)

$part | Format-Volume -FileSystem FAT32 -NewFileSystemLabel 'CMP70UNLOCK' -Force -Confirm:$false | Out-Null
Start-Sleep -Seconds 2

# Букву тома мы НЕ назначаем. Буква — это запись в системной таблице
# монтирований хоста, а здесь нужен одноразовый VHDX: создавать ради него
# букву незачем, и она потом остаётся жить в mountvol. Работаем через путь
# тома \\?\Volume{...}\ — он есть всегда, с буквой или без неё.
$vol = $null
for ($i = 0; $i -lt 20; $i++) {
    $vol = Get-Partition -DiskNumber $dn -PartitionNumber $part.PartitionNumber |
           Get-Volume -ErrorAction SilentlyContinue
    if ($vol -and $vol.FileSystem) { break }
    Start-Sleep -Milliseconds 500
}
if (-not $vol -or -not $vol.FileSystem) { Die 'Format-Volume отработал, но том так и не появился' }
if ($vol.FileSystem -ne 'FAT32') { Die "формат дал $($vol.FileSystem), а не FAT32" }
$vroot = $vol.UniqueId.TrimEnd('\')
if (-not $vroot) { Die 'у тома нет пути вида \\?\Volume{...}' }
Good "том $($vol.FileSystem) '$($vol.FileSystemLabel)', путь $vroot (без буквы — намеренно)"
# MbrType читаем ПОСЛЕ формата: до него раздел 0x06, после — 0x0C, который
# шаг 5 и превращает в 0xEF.
$mbrType = [int](Get-Partition -DiskNumber $dn).MbrType
Good ("MBR-тип раздела после формата: 0x{0:X2} (будет заменён на 0x{1:X2})" -f $mbrType, $PART_TYPE)

# --------------------------------------------------------- 4. полезная нагрузка
Say '[4/7] полезная нагрузка ...'
Copy-ToStick $srcEfi "$vroot\EFI\BOOT\BOOTX64.EFI" | Out-Null

# Что лежит на флешке, должно быть опознаваемо без компа, с другого ноутбука.
$versionTxt = @"
CMP 70HX Unlock $Version
release=$Version
commit=$commit
built=$built
loader=EFI/BOOT/BOOTX64.EFI
loader_md5=$efiMd5
loader_size=$efiSize
gsp_ga10x.bin=$gspLine
log_area=lba 4000000..4002047 (1 MiB, outside this image; cleared at every run)
secure_boot=must be OFF
boot=select this stick in the UEFI boot menu; no reboot, Windows chainloads itself
"@
Write-StickText "$vroot\VERSION.txt" $versionTxt | Out-Null

$readmeTxt = @"
CMP 70HX Unlock $Version
=========================

This stick unlocks an NVIDIA CMP 70HX (GA104) before Windows boots.
Nothing to edit and no reboot: pick this USB in the UEFI boot menu
(F12 / F8 / Del) and let it chain-load Windows by itself.

Requirements
  * NVIDIA CMP 70HX (PCI ID 10de:248a), UEFI board with a boot menu
  * Secure Boot DISABLED - this loader is unsigned
  * Windows on a GPT disk with an EFI System Partition
  * This stick is complete; nothing else has to be copied onto it

Windows may not show this stick in Explorer
  The partition type in the MBR is 0xEF (EFI System). That type is REQUIRED
  here - firmware that does not see an ESP will not offer the stick as a
  UEFI boot option - but Windows does not mount 0xEF volumes automatically,
  so there may be no drive letter. This is not damage, and booting does not
  need a letter. To see the files, assign one by hand in Disk Management, or
  use the helper from the project: out\assign-stick-letter.ps1

Repeat runs
  The unlock is volatile: a full reboot (POST) resets the GPU. Just boot
  from this stick again whenever you need the card unlocked.

Notes
  * Graphics needs the patched NVIDIA driver:
    github.com/dartraiden/NVIDIA-patcher
  * The on-stick run log lives outside the filesystem (LBA 4000000..4002047)
    and is only recorded on a medium of at least 4002048 sectors (~4 GB).
    On a smaller stick the unlock still works, the log just stays on screen.
"@
Write-StickText "$vroot\README.txt" $readmeTxt | Out-Null

if ($WithGsp) { Copy-ToStick $gspRef "$vroot\gsp_ga10x.bin" | Out-Null }

# md5 файлов на СМОНТИРОВАННОМ томе: том авторитетен, .img вычитывается
# из этого же виртуального диска. Это ловит ту самую историю «обновлённый
# образ, а внутри СТАРЫЙ загрузчик» (BUILDING.md §5).
$onVol = MD5Of "$vroot\EFI\BOOT\BOOTX64.EFI"
if ($onVol -ne $efiMd5) { Die "md5 на томе $onVol != исходник $efiMd5" }
Good "BOOTX64.EFI на томе = $onVol"
foreach ($f in @('VERSION.txt', 'README.txt')) {
    Good ("{0} ({1} байт)" -f $f, ([IO.FileInfo]::new("$vroot\$f")).Length)
}

# ---------------------------------------------------------------- 5. патч MBR
Say '[5/7] тип раздела 0xEF + флаг boot в MBR ...'
# Windows пишет 0x0C. Часть AMI-прошивок не показывает removable-USB как
# UEFI-опцию без ESP-типа (docs/GOTCHAS.md: замена одного байта @450
# вернула загрузку на реальной машине).
$fs = [IO.File]::Open("\\.\PhysicalDrive$dn", 'Open', 'ReadWrite', 'ReadWrite')
try {
    $mbr = New-Object byte[] 512
    $fs.Seek(0, 'Begin') | Out-Null
    if ($fs.Read($mbr, 0, 512) -ne 512) { Die 'не прочитал LBA 0' }
    if ($mbr[510] -ne 0x55 -or $mbr[511] -ne 0xAA) { Die 'LBA 0 без сигнатуры 55AA — это не MBR' }
    if ($mbr[450] -eq $PART_TYPE) { Warn 'байт @450 уже был 0xEF — патч ничего не изменил' }
    $mbr[446] = $PART_BOOT
    $mbr[450] = $PART_TYPE
    $fs.Seek(0, 'Begin') | Out-Null
    $fs.Write($mbr, 0, 512)
    $fs.Flush($true)
} finally { $fs.Close() }
Good 'MBR: @446=0x80 @450=0xEF, 55AA на месте'

# ------------------------------------------- 6. размонтировать и вычитать сырое
Say '[6/7] отсоединение VHDX, затем вычитка сырых байт в .img ...'
# Пока том смонтирован, записи лежат в кэше Windows, и raw-чтение видит
# предыдущее содержимое. Порядок: файлы уже сброшены на диск по одному
# (Flush($true) в шаге 4), теперь отсоединяем VHDX — detach сбрасывает и
# метаданные тома — и подсоединяем обратно ТОЛЬКО НА ЧТЕНИЕ.
# Flush-Volume и fsutil volume dismount здесь неприменимы: оба требуют букву,
# а мы её намеренно не создавали.
if (-not (Detach-Vhd $vhdx)) { Die 'VHDX не отсоединяется — том держит какой-то процесс' }
Start-Sleep -Seconds 2
Mount-DiskImage -ImagePath $vhdx -Access ReadOnly | Out-Null
$rdn = Get-MountedDiskNumber $vhdx
if ($null -eq $rdn) { Die 'повторное монтирование VHDX не дало диска' }
Good "повторно подключено только на чтение: диск $rdn"

$src = [IO.File]::Open("\\.\PhysicalDrive$rdn", 'Open', 'Read', 'ReadWrite')
$dst = [IO.File]::Create($img)
try {
    $buf  = New-Object byte[] (4MB)
    $left = [int64]$imgBytes
    while ($left -gt 0) {
        $want = [int][Math]::Min([int64]$buf.Length, $left)
        $got  = $src.Read($buf, 0, $want)
        if ($got -le 0) { Die "raw-чтение остановилось за $left байт до конца образа" }
        $dst.Write($buf, 0, $got)
        $left -= $got
    }
    $dst.Flush($true)
} finally {
    $dst.Close()
    $src.Close()
}
if (-not (Detach-Vhd $vhdx)) { Die 'повторное отсоединение VHDX не удалось — образ записан, но неверен' }
Remove-Item -LiteralPath $vhdx -Force
$realSize = (Get-Item -LiteralPath $img).Length
if ($realSize -ne $imgBytes) { Die "размер .img $realSize, ожидалось $imgBytes" }
Good ("{0}  ({1:N0} байт)" -f (Split-Path $img -Leaf), $realSize)

# ------------------------------------------------------------- 7. хэши и упаковка
Say '[7/7] хэши и упаковка ...'
$imgMd5 = MD5 $img
$imgSha = (Get-FileHash -LiteralPath $img -Algorithm SHA256).Hash

$gzPath = "$img.gz"
$gzSha  = $null
$gzLine = ''
if (-not $NoGzip) {
    # Образ почти целиком нули, поэтому .gz весит ~1 МБ. GZipStream — без
    # внешних 7z/tar, чтобы шаг воспроизводился на голой Windows.
    $in  = [IO.File]::OpenRead($img)
    $out = [IO.File]::Create($gzPath)
    try {
        $gz = [IO.Compression.GZipStream]::new($out, [IO.Compression.CompressionLevel]::Optimal)
        try { $in.CopyTo($gz) } finally { $gz.Dispose() }
    } finally {
        $in.Close(); $out.Close()
    }
    $gzSha  = (Get-FileHash -LiteralPath $gzPath -Algorithm SHA256).Hash
    $gzLine = "{0}  {1}" -f $gzSha.ToLower(), (Split-Path $gzPath -Leaf)
    Good ("{0}  ({1:N0} байт)" -f (Split-Path $gzPath -Leaf), (Get-Item -LiteralPath $gzPath).Length)
}

# Комментарии — по-английски: файл ASCII, и кириллица в нём превратилась бы в
# «??????» ровно так же, как это делает ulogf() в самом загрузчике
# (docs/LOGGING.md §3.3). Пользователь читает SHA256SUMS в любом редакторе.
$sumLines = @(
    "# CMP 70HX Unlock $Version"
    "# generated by out/make-image.ps1, commit $commit, $built"
    "#"
    "# These hashes describe THIS built file. A rebuild produces a different"
    "# md5/sha256 for the image: FAT32 carries a volume serial and timestamps,"
    "# both random. The one reproducible value:"
    "#   loader_md5 $efiMd5   (EFI/BOOT/BOOTX64.EFI, inside the image)"
    "# It is also written to VERSION.txt on the stick."
    "loader_md5 $efiMd5"
    ""
    ("{0}  {1}" -f $imgSha.ToLower(), (Split-Path $img -Leaf))
    ("{0}  {1}" -f $imgMd5.ToLower(), (Split-Path $img -Leaf))
)
if ($gzLine) { $sumLines += $gzLine }
$sumPath = Join-Path $OutDir 'SHA256SUMS'
[IO.File]::WriteAllText($sumPath, ($sumLines -join "`r`n") + "`r`n", [Text.Encoding]::ASCII)
Good "SHA256SUMS"

Write-Host ''
Write-Host '================================================================================' -ForegroundColor Green
Write-Host ' ОБРАЗ СОБРАН' -ForegroundColor Green
Write-Host '================================================================================' -ForegroundColor Green
Write-Host "  image   $img"
Write-Host "  md5     $imgMd5"
Write-Host "  sha256  $imgSha"
Write-Host "  loader  $efiMd5  ($efiSize байт)"
Write-Host "  commit  $commit   release $Version"
Write-Host ''
Write-Host '  ДАЛЬШЕ — НЕ АВТОМАТИЧЕСКИЕ ШАГИ:' -ForegroundColor Yellow
Write-Host '    1. powershell -ExecutionPolicy Bypass -File out\verify-image.ps1' -ForegroundColor Yellow
Write-Host '    2. записать образ на флешку (Rufus в режиме DD / Etcher / dd)' -ForegroundColor Yellow
Write-Host '    3. powershell -ExecutionPolicy Bypass -File out\reset-stick-log.ps1' -ForegroundColor Yellow
Write-Host '       (стереть СТАРЫЙ лог: образ не покрывает LBA 4000000, и без' -ForegroundColor Yellow
Write-Host '        этого шага старый лог выглядел бы как лог новой загрузки)' -ForegroundColor Yellow
Write-Host '    4. powershell -ExecutionPolicy Bypass -File out\assign-stick-letter.ps1' -ForegroundColor Yellow
Write-Host '       (буквы тома не будет — тип раздела 0xEF; для Проводника, не' -ForegroundColor Yellow
Write-Host '        для загрузки и не для снятия лога)' -ForegroundColor Yellow
Write-Host '    5. перезагрузиться, выбрать флешку в boot-меню, дождаться конца' -ForegroundColor Yellow
Write-Host '    6. out\pull-log.ps1 -Tag <метка>, затем out\verify-log.ps1' -ForegroundColor Yellow
Write-Host '    7. out\verify-image.ps1 -CompareTo <образ>  # побайтово сверить запись' -ForegroundColor Yellow
Write-Host ''
Write-Host '  Публиковать релиз можно только после шагов 5-6.' -ForegroundColor Yellow
exit 0