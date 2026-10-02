#Requires -Version 5.1
<#
    verify-log.ps1 - ПРИЁМКА ПРОГОНА НА ЖЕЛЕЗЕ ПО ФАЙЛУ ЛОГА.

    ЗАЧЕМ ОТДЕЛЬНЫЙ СКРИПТ, ЕСЛИ ЕСТЬ verify_v316.sh.

    verify_v316.sh проверяет СБОРКУ: что строки-маркеры не вырезаны
    оптимизатором. Он ничего не проверяет из того, что важно пользователю,
    а именно: открылись ли маски, встал ли GFX_SPEED_SELECT, работал ли
    FWSEC. Этап 8 (md5 5A1165367234A09EAD2A42334A90C97A) прошёл приёмку
    сборки 52/52, уехал на флешку, был закоммитан как "ожидаем 16,6 с" -
    и сломал рендер: 0 из 8 масок, dbg=0x007E0009 в 86 строках.

    Обнаружить это можно было за секунду, если бы скрипт смотрел на лог.
    Теперь он есть, и он ОБЯЗАТЕЛЕН до записи прогона как VERIFIED.

    ПРАВИЛО: сначала pull-log.ps1 БЕЗ -NoSave, потом verify-log.ps1,
    и только при PASS прогон записывается в out/BUILDS.md как VERIFIED.
    При FAIL прогон всё равно коммитится - как отвергнутый, с разбором.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$LogPath,
    [int]$ExpectWpr2 = 9
)

$ErrorActionPreference = 'Stop'
$fails = @()
function Ok  ($m) { Write-Host ("  OK   " + $m) -ForegroundColor Green }
function Bad ($m) { Write-Host ("  FAIL " + $m) -ForegroundColor Red; $script:fails += $m }
function Note ($m) { Write-Host ("  --   " + $m) -ForegroundColor DarkGray }

if (-not (Test-Path $LogPath)) { throw "log not found: $LogPath" }
$text = [IO.File]::ReadAllText($LogPath)
Write-Host ("=== " + (Split-Path $LogPath -Leaf) + " (" + $text.Length + " байт) ===")

# --- 1. главный признак: рендер-окно открылось целиком ------------------
# Именно это сломалось в v3.23, и именно это пользователь видит.
$m = [regex]::Match($text, 'XVE window open (\d+) of (\d+)')
if (-not $m.Success) {
    Bad "нет строки 'XVE window open' - лог оборван или прогона не было"
} elseif ($m.Groups[1].Value -ne $m.Groups[2].Value) {
    Bad ("XVE window open " + $m.Groups[1].Value + " из " + $m.Groups[2].Value + " - рендер сломан")
} else {
    Ok ("XVE window open " + $m.Groups[1].Value + " из " + $m.Groups[2].Value)
}

# --- 2. главный признак рендера: 50 fps / 135 W --------------------------
if ($text -match 'GFX_SPEED_SELECT=0x00000004 SET') { Ok "GFX_SPEED_SELECT=0x00000004 SET (50 fps / 135 W)" }
else { Bad "GFX_SPEED_SELECT не встал в 0x4 - рендер не включён" }

# --- 3. dbg=0x007E0009 -----------------------------------------------------
# Известное значение из ПРОШЛОЙ регрессии (KNOWN-ISSUES). Именно оно
# заполнило 86 строк в v3.23 и поймало бы тот прогон мгновенно.
$bad9 = ([regex]::Matches($text, 'dbg=0x007E0009')).Count
if ($bad9 -eq 0) { Ok "нет ни одного dbg=0x007E0009" }
else { Bad ("dbg=0x007E0009 встречается " + $bad9 + " раз - ботер не выполняется") }

# --- 4. FWSEC --------------------------------------------------------------
$fails4 = ([regex]::Matches($text, 'FWSEC ours FAIL')).Count
if ($fails4 -eq 0) { Ok "нет ни одного 'FWSEC ours FAIL'" }
else { Bad ("'FWSEC ours FAIL' " + $fails4 + " раз - путь открытия масок не проходит") }

# --- 5. WPR2 ---------------------------------------------------------------
$w = ([regex]::Matches($text, 'WPR2 ESTABLISHED')).Count
if ($w -ge $ExpectWpr2) { Ok ("WPR2 ESTABLISHED " + $w + " раз (ожидалось >= " + $ExpectWpr2 + ")") }
else { Bad ("WPR2 ESTABLISHED всего " + $w + ", ожидалось >= " + $ExpectWpr2 + " - цикл не прошёл") }

# --- 6. маски открылись поимённо ------------------------------------------
$opened = ([regex]::Matches($text, 'became 0xFFFFFFFF OPEN')).Count
$locked = ([regex]::Matches($text, 'remained locked')).Count
if ($locked -eq 0) { Ok ("ни одна маска не осталась закрытой (" + $opened + " открыто)") }
else { Bad ($locked.ToString() + " масок остались закрытыми (открыто " + $opened + ")") }

# --- 7. лог дописан полностью ---------------------------------------------
if ($text -match 'END\s+---- end of log ----') { Ok "маркер END на месте - приложение дописало лог" }
else { Bad "нет маркера END - лог оборван, результат непригоден" }

# --- 8. финальное dbg в END-строке ----------------------------------------
$e = [regex]::Match($text, 'END\s+ss0=.*')
if (-not $e.Success) { Bad "нет END-строки со снимком состояния" }
else {
    if ($e.Value -match 'dbg=0x00000000') { Ok "END: dbg=0x00000000" }
    else { Bad ("END: dbg не нулевой - " + [regex]::Match($e.Value, 'dbg=0x[0-9A-Fa-f]+').Value) }
    if ($e.Value -match 'PLM=0xFFFFFFFF') { Ok "END: PLM=0xFFFFFFFF" }
    else { Note ("END: " + [regex]::Match($e.Value, 'PLM=0x[0-9A-Fa-f]+').Value + " - не 0xFFFFFFFF") }
}

# --- 9. счётчики этапа 9: механизм и время --------------------------------
# Отсутствие QUIESCE - это НЕ отказ железа, а признак того, что сборка
# старше этапа 9 (строка появилась только в нём). Поэтому Note, а не Bad:
# аппаратные критерии 1-8 выше всё равно решают исход. Наличие самой строки
# в бинаре проверяет verify_v316.sh, так что дырки тут не остаётся.
$q = [regex]::Match($text, 'QUIESCE calls=(\d+) fast=(\d+) slow=(\d+) total=(\d+)us max=(\d+)us')
if (-not $q.Success) {
    Note "нет строки QUIESCE - сборка старше этапа 9, измерение покоя в ней не было"
} else {
    Ok ("QUIESCE calls=" + $q.Groups[1].Value + " fast=" + $q.Groups[2].Value +
        " slow=" + $q.Groups[3].Value + " max=" + $q.Groups[5].Value + "us")
    if ($q.Groups[3].Value -eq '0') { Ok "движок усёкся по событию в 100% случаев - версия механизма работает" }
    else { Note ("бюджет исчерпан " + $q.Groups[3].Value + " раз из " + $q.Groups[1].Value + " - см. max=" + $q.Groups[5].Value + "us") }
}
$r = [regex]::Match($text, 'RESETREADY calls=(\d+) skipped=(\d+) early=(\d+) budgetout=(\d+) total=(\d+)us')
if ($r.Success) {
    Note ("RESETREADY calls=" + $r.Groups[1].Value + " skipped=" + $r.Groups[2].Value +
          " early=" + $r.Groups[3].Value + " total=" + $r.Groups[5].Value + "us")
    if ([int]$r.Groups[2].Value -eq 0) {
        Note "skipped=0 - правка этапа 10 не сработала, время не упадёт"
    }
} else {
    Note "нет строки RESETREADY в формате этапа 10 (skipped=) - сборка старше"
}

# --- 10. время прогона -----------------------------------------------------
$last = [regex]::Matches($text, 'TIME  t=(\d+)ms')
if ($last.Count -gt 0) { Note ("счётчик прогона: " + $last[$last.Count-1].Groups[1].Value + " мс") }

Write-Host ""
if ($fails.Count -eq 0) {
    Write-Host "ПРИЁМКА ПРОГОНА ПРОЙДЕНА. Рендер жив, compute жив." -ForegroundColor Green
    Write-Host "Теперь можно записывать прогон в out/BUILDS.md как VERIFIED." -ForegroundColor Green
    exit 0
} else {
    Write-Host ("ПРИЁМКА ПРОГОНА НЕ ПРОЙДЕНА: " + $fails.Count + " пунктов") -ForegroundColor Red
    foreach ($f in $fails) { Write-Host ("  - " + $f) -ForegroundColor Red }
    Write-Host ""
    Write-Host "Прогон всё равно коммитится - как ОТВЕРГНУТЫЙ, с разбором." -ForegroundColor Yellow
    Write-Host "Не прошивать и не помечать VERIFIED." -ForegroundColor Yellow
    exit 1
}
