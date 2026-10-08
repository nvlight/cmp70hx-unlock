<#
    flash-exp.ps1 - прошивка ЭКСПЕРИМЕНТАЛЬНОЙ сборки на флешку.

    Зачем отдельный скрипт. flash-build.ps1 прошивает релизную сборку, и
    там ожидание 'GFX_SPEED_SELECT=0x00000004 SET' корректно: значение
    селектора у релиза действительно 0x4. Но рычаг GFX_SPEED_SEL_VALUE
    существует именно для того, чтобы собирать не-0x4 варианты, и вот там
    получилась ошибка, зафиксированная в docs/POWER-SEARCH-LIST.md
    часть 6 §5: скрипт печатал предупреждение о состоянии карты из
    зашитого текста для конкретной сборки, хотя образ задавался
    параметром. При прошивке 0x6 он вывел «селектор = 0x7», то есть
    предупреждение о нерабочем режиме солгало ровно тогда, когда оно
    было нужнее всего.

    Правило здесь: описание состояния выводится ТОЛЬКО из отпечатка
    образа. Отпечатка нет в таблице - значит состояние неизвестно, и
    скрипт так и говорит. Угадывать нельзя: неверное предупреждение о
    том, что карта в рабочем режиме, опаснее отсутствия предупреждения.

    Откат: out\stick-backup-BOOTX64.EFI (v3.52) и out\stick-prev-BOOTX64.EFI
    (предыдущая прошивка). Перезагрузка всегда возвращает рабочее
    состояние, потому что анлок целиком волатилен.

    Пример:
        powershell -ExecutionPolicy Bypass -File out\flash-exp.ps1 `
            -Image gfxsel0x6_oracle.efi
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Image,
    [string]$Stick = '',
    [switch]$NoBackup,
    # Только показать, что за сборка и что будет с картой. Флешка не
    # трогается. Нужен, чтобы узнать состояние ДО прошивки, и чтобы
    # таблицу STATE можно было проверять, не рискуя загрузчиком.
    [switch]$DescribeOnly
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }

$root = Split-Path -Parent $PSScriptRoot
$src  = Join-Path $root "src\$Image"
$prev = Join-Path $root 'out\stick-prev-BOOTX64.EFI'

function Say ($m)  { Write-Host $m -ForegroundColor Cyan }
function Good ($m) { Write-Host "  OK  $m" -ForegroundColor Green }
function Bad ($m)  { Write-Host "  !!  $m" -ForegroundColor Red }
function Die ($m)  { Write-Host "FAIL: $m" -ForegroundColor Red; exit 1 }

# ---------------------------------------------------------------------------
# Таблица состояний. Ключ - md5 образа, значение - что человек должен знать
# про карту после прошивки. Собирается ТОЛЬКО из результатов прогонов на
# железе, задокументированных в docs/POWER-SEARCH-LIST.md.
#
# Новую строку можно добавить лишь после того, как соответствующий образ
# реально прошит, перезагружен и лог снят. Иначе получится ровно тот
# дефект, ради устранения которого написан этот скрипт.
# ---------------------------------------------------------------------------
$STATE = @{
    '8f57880916467d1a940e72659ebdd7a1' = @{
        sel = '0x4'; fps = '50'
        note = 'релизная сборка'
    }
    'ea3b565d54e728dada1e9926951c5005' = @{
        sel = '0x4'; fps = '50'
        note = 'oracle, рабочее значение селектора'
    }
    '5d04caef395edbd4ce2e3d2f00ce65b9' = @{
        sel = '0x6'; fps = '16'
        note = 'oracle на 0x6 - CAND-ID идёт 3->2, градация подтверждена'
    }
    '91ef773eb919a239c7fb34d2fbc8c8e1' = @{
        sel = '0x7'; fps = '9'
        note = 'oracle на 0x7 - CAND-ID остаётся 3, графический путь не встал'
    }
    '6f9b87979f8b777327cfba0ef8b7301a' = @{
        sel = '0x3'; fps = '9'
        note = 'oracle на 0x3 - ШАГ A: различает градацию и арифметику sel-4'
    }
    '659c03b84ec67cd99e6af6f96c288fbb' = @{
        sel = '0x8'
        fps = 'НЕИЗВЕСТНО - значение никогда не мерялось игрой'
        note = 'oracle на 0x8 - ШАГ B: проверка ширины поля. Если поле' + [Environment]::NewLine +
               '  трёхбитное, железо отмаскирует 0x8 в 0, то есть это те же' + [Environment]::NewLine +
               '  базовые 9 fps. Если застряло - поле шире трёх бит.'
    }
}

function Get-MD5 ($path) { (Get-FileHash -LiteralPath $path -Algorithm MD5).Hash.ToLowerInvariant() }

# Сканируем ОБЕ кодировки. Литералы логов - широкие строки, поэтому
# сканирование только по ASCII рапортует «пусто» на заведомо годном
# бинаре. Эта ловушка уже стоила времени в этом проекте, и скрипт,
# который сам на неё наступает, повторил бы её.
function Get-BlobText ($path) {
    $b = [IO.File]::ReadAllBytes($path)
    return ([Text.Encoding]::ASCII.GetString($b)) + "`n" +
           ([Text.Encoding]::Unicode.GetString($b))
}

# --- образ -----------------------------------------------------------------
if (-not (Test-Path $src)) { Die "нет $src" }
$md5   = Get-MD5 $src
$bytes = [IO.File]::ReadAllBytes($src)
if ($bytes.Length -lt 2 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
    Die "$Image не PE-образ (нет 'MZ')"
}

function Show-State ($md5) {
    Say ''
    if ($STATE.ContainsKey($md5)) {
        $s = $STATE[$md5]
        Say '--- СОСТОЯНИЕ КАРТЫ ПОСЛЕ ЭТОЙ ПРОШИВКИ ---' -ForegroundColor Yellow
        Write-Host ("  селектор : {0}" -f $s.sel)
        Write-Host ("  игры     : {0} fps" -f $s.fps)
        Write-Host ("  что это  : {0}" -f $s.note)
        if ($s.sel -notlike '0x4*') {
            Write-Host ''
            Write-Host '  ВНИМАНИЕ: карта будет НЕ на 50 fps.' -ForegroundColor Yellow
            Write-Host '  Вернуть рабочее значение: прошить unlock_v3r.efi или oracle.efi.' -ForegroundColor Yellow
        }
        return $true
    }
    Say '--- СОСТОЯНИЕ КАРТЫ НЕИЗВЕСТНО ---' -ForegroundColor Yellow
    Write-Host ("  md5 {0} нет в таблице STATE этого скрипта." -f $md5)
    Write-Host '  Что будет с fps после этой прошивки, скрипт НЕ утверждает.'
    Write-Host '  Если знаешь значение селектора - добавь его в $STATE в flash-exp.ps1'
    Write-Host '  сразу после прогона на железе, иначе предупреждение соврёт.'
    return $false
}

Say "образ: $Image"
Good ("md5 {0} ({1} bytes)" -f $md5, $bytes.Length)

$txt = Get-BlobText $src

# --- проверка, что образ собран с исправленной проверкой селектора --------
# -DGFX_SPEED_SEL_VALUE обязан менять байты кода. Если образ отличается
# лишь пересборкой, а значением селектора не отличается, то таблица STATE
# ниже описывает не тот селектор, и предупреждение снова соврёт.
if ($txt.Contains('readback 0x%08x, want 0x%08x, retry')) {
    Good 'маркер исправленной проверки селектора найден'
} else {
    Write-Host '  ..  маркера исправленной проверки нет (сборка старее v3.54)' -ForegroundColor DarkGray
}

# --- обязательные маркеры образа ------------------------------------------
# Проверяем ДО записи: если образ не тот, дешевле узнать об этом сейчас.
if ($txt.Contains('CMP 90HX (GA102)')) { Die 'в образе профиль 90HX - это не тот бинарь' }
if (-not $txt.Contains('CMP 70HX (GA104)')) { Die 'в образе нет профиля 70HX' }
Good 'профиль 70HX'
if (-not $txt.Contains('END   ---- end of log ----')) {
    Die 'в образе нет маркера конца лога - лог не будет помечен как завершённый'
}
Good 'маркер конца лога'

if ($DescribeOnly) {
    [void](Show-State $md5)
    Say ''
    Say 'DescribeOnly: флешка не тронута.'
    exit 0
}

# --- флешка ---------------------------------------------------------------
if (-not $Stick) {
    . (Join-Path $root 'out\find-stick.ps1')
    $hit = Find-StickDisk
    if (-not $hit) { Show-StickScan; Die 'флешка не найдена' }
    $part = Get-Partition -DiskNumber $hit.DiskNumber | Select-Object -First 1
    if (-not $part.DriveLetter) {
        Set-Partition -DiskNumber $hit.DiskNumber -PartitionNumber $part.PartitionNumber `
                     -NewDriveLetter ([char][byte][char]'R') | Out-Null
        Start-Sleep -Milliseconds 800
        $part = Get-Partition -DiskNumber $hit.DiskNumber | Select-Object -First 1
    }
    $Stick = [string]$part.DriveLetter
}
$Stick = $Stick.TrimEnd(':', [char]':') + ':'
$target = "$Stick\EFI\BOOT\BOOTX64.EFI"

Say ''
Say "stick $Stick  ->  $target"

# --- откат -----------------------------------------------------------------
if (-not $NoBackup -and (Test-Path $target)) {
    Copy-Item -LiteralPath $target -Destination $prev -Force
    Good ("откат снят: {0}" -f (Get-MD5 $prev))
}

# --- запись ---------------------------------------------------------------
$dir = Split-Path -Parent $target
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
if (Test-Path $target) { Remove-Item -LiteralPath $target -Force }
Copy-Item -LiteralPath $src -Destination $target -Force

$onStick = Get-MD5 $target
if ($onStick -ne $md5) { Die "md5 флешки $onStick != $md5" }
Good "записано, md5 совпал"

# --- СОСТОЯНИЕ КАРТЫ ------------------------------------------------------
# Только здесь и только из таблицы. Нет ключа - нет утверждения.
$known = Show-State $md5
if (-not $known) {
    Write-Host ''
    Write-Host '  ФЛЕШКА УЖЕ ЗАПИСАНА СОБРАНИЕМ, СОСТОЯНИЕ КОТОРОГО НЕ ИЗВЕСТНО.' -ForegroundColor Red
    Write-Host '  Если карта после перезагрузки работает не как ожидалось, откат:' -ForegroundColor Red
    Write-Host ("    Copy-Item `"$prev`" `"$target`" -Force") -ForegroundColor Red
}

Say ''
Say '--- дальше ---'
Write-Host '  1. перезагрузка, выбрать флешку в меню загрузки (F12)'
Write-Host '  2. дождаться END, не прерывать'
Write-Host '  3. out\read-log.ps1 - снять лог'
Write-Host ''
Write-Host '  изменение НЕ проверено, пока лог не вернётся.' -ForegroundColor Yellow
if (-not $known) {
    Write-Host ''
    Write-Host '  таблица STATE устарела: добавь этот образ после прогона.' -ForegroundColor Yellow
}