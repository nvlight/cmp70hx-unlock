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
    # 0 = derive the expectation from the log's own mask count (2*N+2).
    # Pass a positive value only to override that, e.g. when checking a log
    # whose render section is not present at all.
    [int]$ExpectWpr2 = 0
)

$ErrorActionPreference = 'Stop'
$fails = @()
function Ok  ($m) { Write-Host ("  OK   " + $m) -ForegroundColor Green }
function Bad ($m) { Write-Host ("  FAIL " + $m) -ForegroundColor Red; $script:fails += $m }
function Note ($m) { Write-Host ("  --   " + $m) -ForegroundColor DarkGray }

if (-not (Test-Path $LogPath)) { throw "log not found: $LogPath" }
$text = [IO.File]::ReadAllText($LogPath)
Write-Host ("=== " + (Split-Path $LogPath -Leaf) + " (" + $text.Length + " байт) ===")

# --- 1. главный признак: все гейты открылись -------------------------------
# Именно это сломалось в v3.23, и именно это пользователь видит.
# v3.40 переименовал строку: 'XVE window open' -> 'GFX gates open', потому что
# окно XVE вышло из списка целей. Регулярка берёт ОБА имени, иначе новая
# сборка объявила бы свой лог оборванным. Старые логи v3.3x проверяются как есть.
$m = [regex]::Match($text, '(?:XVE window open|GFX gates open) (\d+) of (\d+)')
if (-not $m.Success) {
    Bad "нет строки 'GFX gates open' (ранее 'XVE window open') - лог оборван или прогона не было"
} elseif ($m.Groups[1].Value -ne $m.Groups[2].Value) {
    Bad ("гейты открыты " + $m.Groups[1].Value + " из " + $m.Groups[2].Value + " - рендер сломан")
} else {
    Ok ("гейты открыты " + $m.Groups[1].Value + " из " + $m.Groups[2].Value)
}

# --- 2. главный признак рендера: 50 fps / 135 W --------------------------
if ($text -match 'GFX_SPEED_SELECT=0x00000004 SET') { Ok "GFX_SPEED_SELECT=0x00000004 SET (50 fps / 135 W)" }
else { Bad "GFX_SPEED_SELECT не встал в 0x4 - рендер не включён" }

# --- 2a. ВЕРДИКТ (v3.45) -------------------------------------------------
# Одна строка, которая говорит, что ИТОГ получилось: compute, render или оба.
# Проверяется отдельно от маркеров выше, потому что это единственное место,
# где вывод сведён к одному решению, и именно на него смотрит человек,
# когда загрузка идёт не так.
#
# Требуем полный набор подряд: 'VRC  <имя> : <вердикт>' и следом строка со
# значениями. Если значения нет, вердикт на экране был бы голословным.
$vm = [regex]::Match($text, 'VRC\s+(.+?)\s*:\s*(UNLOCKED \(compute \+ render\)|COMPUTE ONLY \(render not unlocked\)|RENDER ONLY \(compute not unlocked\)|NOT UNLOCKED)\s*\r?\nVRC\s+SS0/SS1 = (0x[0-9A-Fa-f]+) / (0x[0-9A-Fa-f]+)\s+GFX_SPEED_SELECT = (0x[0-9A-Fa-f]+)')
$vfmt = [regex]::Match($text, 'VRCFMT\s+1')
if (-not $vfmt.Success) {
    # Лог старой сборки: баннера вердикта в ней ещё не было. Это не отказ -
    # это отсутствие проверки. Именно поэтому проверка обязана быть
    # необязательной для старых логов: будь она строгой, её отключили бы
    # после первого же historic прогона, и она бы ничего не проверяла.
    Note "лог без VRCFMT - вердикт в этой сборке не печатался, проверка пропущена"
} elseif (-not $vm.Success) {
    Bad "VRCFMT есть, но строки вердикта VRC нет - баннер не напечатался"
} else {
    $vv = $vm.Groups[2].Value
    $vss0 = $vm.Groups[3].Value
    $vss1 = $vm.Groups[4].Value
    $vgfx = $vm.Groups[5].Value
    $comp = (($vss0 -eq '0x88888888') -and ($vss1 -eq '0x00000008'))
    $rend = ($vgfx -eq '0x00000004')

    # Вердикт обязан СООТВЕТСТВОВАТЬ значениям в той же строке. Расхождение
    # означает, что логика печати и логика решения разошлись, - а это хуже
    # любого из двух вариантов по отдельности, потому что оба выглядят
    # осмысленно.
    $want = if ($comp -and $rend) { 'UNLOCKED (compute + render)' }
            elseif ($comp)        { 'COMPUTE ONLY (render not unlocked)' }
            elseif ($rend)        { 'RENDER ONLY (compute not unlocked)' }
            else                  { 'NOT UNLOCKED' }
    if ($vv -eq $want) {
        Ok ("вердикт: " + $vv)
        Note ("  по значениям: compute=" + $comp + " render=" + $rend)
    } else {
        Bad ("вердикт '" + $vv + "' противоречит значениям SS0/SS1=" + $vss0 + "/" + $vss1 + " GFX=" + $vgfx + " - должно быть '" + $want + "'")
    }
}

# --- 2b. ВЕРДИКТ ПРОТИВ ФАКТА ЗАПИСИ СЕЛЕКТОРА (v3.46) -----------------
# Проверка 2a сверяет вердикт с напечатанными значениями, то есть с ним самим.
# Эта сверяет вердикт с НЕЗАВИСИМЫМ свидетельством того, что запись селектора
# состоялась, - со строкой 'G2GFX ... ORDER A ... SET'.
#
# Зачем: на прогоне usb-log-1004-135604 вердикт напечатал
# 'COMPUTE ONLY' при 'G2GFX ... GFX_SPEED_SELECT=0x00000004 SET' в этом же
# логе. Проверка 2a такого не видит по построению - устаревшее значение
# внутренне согласовано само с собой. Единственное, что это поймало бы, -
# сверка с фактом записи.
$gfxSet = $text -match 'ORDER A \(GFX after SS\): GFX_SPEED_SELECT=0x00000004 SET'
if ($vfmt.Success -and $vm.Success -and $gfxSet) {
    if ($vv -eq 'UNLOCKED (compute + render)') {
        Ok "вердикт согласован с фактом записи GFX_SPEED_SELECT"
    } else {
        Bad ("вердикт '" + $vv + "', но в логе есть 'ORDER A ... 0x00000004 SET' - селектор записался, вердикт врёт (значение в VRC устарело?)")
    }
}

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
# Ожидание ВЫВОДИТСЯ ИЗ САМОГО ЛОГА, а не задано константой.
#
#     WPR2 ESTABLISHED = 2 * <число масок> + 2
#
# Проверено на шести прогонах, ноль исключений:
#     2 маски -> 6   (usb-log-1004-021327, usb-log-1004-110443)
#     8 масок -> 18  (usb-log-v337, -v338, -v339, -v340)
# Счётчик линейный по числу масок, и это не совпадение: рендер-цикл делает по
# FLR-минициклу на маску, и каждый миницикл прогоняет путь установки WPR2
# дважды. Плюс два фиксированных: вход в ранний путь и хвост после свипа.
#
# ПОЧЕМУ ЭТО БЫЛО СЛОМАНО. Здесь стоял порог '>= 9', подобранный при списке
# из 8 масок, и комментарий уверял, что пересчитывать его не надо. Это было
# неверно: при 2 масках правильное значение 6, порог 9 стал недостижимым, и
# проверка отвергала ПОЛНОСТЬЮ РАБОЧИЕ прогоны - пользователь смотрел на
# FAIL при работающей игре. Проверка, которая ругается на правильный прогон,
# хуже отсутствующей: она приучает её игнорировать, а она существует как раз
# для того, чтобы ловить тихие регрессии за секунды.
#
# Пункт 6 (маски поимённо) от числа масок не зависит и остаётся основной
# проверкой того, что маски реально открылись.
$w = ([regex]::Matches($text, 'WPR2 ESTABLISHED')).Count
$maskCount = 0
$mg = [regex]::Match($text, '(?:XVE window open|GFX gates open) \d+ of (\d+)')
if ($mg.Success) { $maskCount = [int]$mg.Groups[1].Value }

if ($ExpectWpr2 -gt 0) {
    $want = $ExpectWpr2
    $why = "задано -ExpectWpr2"
} elseif ($maskCount -gt 0) {
    $want = 2 * $maskCount + 2
    $why = ("2*" + $maskCount + "+2, маски взяты из лога")
} else {
    Bad ("не найдено число масок в логе и -ExpectWpr2 не задан: строка 'GFX gates open N of N' отсутствует, проверить WPR2 нечем")
    $want = 0
    $why = "нечем проверить"
}

if ($want -gt 0) {
    if ($w -eq $want) { Ok ("WPR2 ESTABLISHED " + $w + " раз (ровно как предсказано: " + $why + ")") }
    else { Bad ("WPR2 ESTABLISHED " + $w + " раз, ожидалось ровно " + $want + " (" + $why + ") - число минициклов не совпало с числом масок") }
}

# --- 6. маски открылись поимённо ------------------------------------------
$opened = ([regex]::Matches($text, 'became 0xFFFFFFFF OPEN')).Count
$locked = ([regex]::Matches($text, 'remained locked')).Count
if ($locked -eq 0) { Ok ("ни одна маска не осталась закрытой (" + $opened + " открыто)") }
else { Bad ($locked.ToString() + " масок остались закрытыми (открыто " + $opened + ")") }

# --- 7. лог дописан полностью ---------------------------------------------
if ($text -match 'END\s+---- end of log ----') { Ok "маркер END на месте - приложение дописало лог" }
else { Bad "нет маркера END - лог оборван, результат непригоден" }

# --- 8. финальный dbg в END-строке ----------------------------------------
# ВНИМАНИЕ, ИСТОРИЯ ОШИБКИ. Этот пункт раньше требовал dbg=0x00000000 и
# сработал ложной тревогой на прогоне v3.25 - полностью рабочем, 8 из 8,
# GFX_SPEED_SELECT встал, пользователь проверил игру и LLM.
#
# Требование было НЕВЕРНЫМ, и вот почему. dbg = mmio_read32(GSP_BASE+0x94) -
# регистр DEBUGINFO ядра GSP. Код в него НИ РАЗУ НЕ ПИШЕТ: mmio_write32 на
# этот адрес в проекте отсутствует. Это регистр-симптом, значение задаёт сам
# движок.
#
# dbg НЕ является критерием приёмки:
#   - собственный лог проекта пишет 'dbg not checked by driver', то есть
#     драйвер NVIDIA его не проверяет;
#   - значение 0xDA550000 наблюдается в РАБОЧИХ прогонах (18-24 раза в каждом
#     из v321/v322/v324), и docs/70HX-NEXT-STEPS.md §3g фиксирует его рядом с
#     'WPR2 ESTABLISHED' и 'BOOTER iters=5 ... PLM-OPEN';
#   - по прогонам: 0x00000000 x6, 0x00000001 x16-18, 0xDA550000 x18-24 -
#     все в рабочих; 0x007E0009 x86 - ТОЛЬКО в сломанном v3.23.
#
# Единственная полезная роль dbg - отпечаток 'наш ucode выполнялся'.
# 0x007E0009 означает 'ядро стартует и гибнет'; именно он поймал отказ
# v3.23 за секунды. Поэтому проверка живёт выше, в пункте 3, и только она.
#
# Здесь значение печатается для сведения и для сравнения с прошлыми
# прогонами, но PASS/FAIL от него НЕ зависит.
$e = [regex]::Match($text, 'END\s+ss0=.*')
if (-not $e.Success) { Bad "нет END-строки со снимком состояния" }
else {
    $dbgv = [regex]::Match($e.Value, 'dbg=0x[0-9A-Fa-f]+')
    if ($dbgv.Success) {
        if ($dbgv.Value -eq 'dbg=0x007E0009') {
            Bad "END: dbg=0x007E0009 - ядро стартует и гибнет"
        } else {
            Note ("END: " + $dbgv.Value + " - диагностическое значение движка, критерием НЕ является (см. комментарий в скрипте)")
        }
    }
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

# --- 9a. поимённый список медленных мест ---------------------------------
# Добавлен в сборке этапа 11. Без него известно только ЧТО десять мест
# медленные, но не ГДЕ ИМЕННО, а это ровно то, что нужно, чтобы не гадать
# с очередной правкой.
$qs = [regex]::Matches($text, 'QSLOW\s+(\S.*?)\s+cpuctl=0x([0-9A-Fa-f]+)\s+waited=(\d+)us')
if ($qs.Count -eq 0) {
    Note "нет строк QSLOW - сборка старше этапа 11, поимённого списка в ней не было"
} else {
    Ok ("QSLOW: " + $qs.Count + " поимённых медленных мест (это крупнейшая статья бюджета)")
    $g = $qs | ForEach-Object { [pscustomobject]@{ site = $_.Groups[1].Value; cc = $_.Groups[2].Value; us = [int]$_.Groups[3].Value } }
    $g | Group-Object site | Sort-Object Count -Descending | ForEach-Object {
        Note ("  " + $_.Name + "  x" + $_.Count + "  cpuctl=0x" + $_.Group[0].cc +
              "  " + [Math]::Round((($_.Group | Measure-Object us -Sum).Sum) / 1000, 1) + " ms всего")
    }
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

# --- 9c. встал ли BAR0 - функциональный сигнал после FLR ------------------
# Этап 13r. Живость конфигурационного пространства бесполезна (этап 13:
# ответ за 8-9 мкс, значение не меняется). А вот встал ли BAR0 после
# перезаписи - признак функциональный.
#
# ВНИМАНИЕ, ИСТОРИЯ ОШИБКИ. Первая версия этого пункта искала подстроку
# 'NOT STUCK' ПО ВСЕМУ ЛОГУ и на прогоне v3.30 объявила ложную тревогу:
# 'BAR0 НЕ встал в 2 случаях из 8'. На деле все 8 строк читались
#     BARR  bar0 write: want=0xF6000000 got=0xF6000000 STUCK
# а зацепил поиск чужую строку из давней диагностики wpr2_probe, где слова
# 'NOT STUCK' просто стоят в СОБСТВЕННОМ сообщении:
#     PROBE  readback 0x0082380C = 0x00888888 NOT STUCK (probably just reporting)
#
# Это ТРЕТЬЯ ложная тревога от чекера и ВТОРАЯ по той же причине: подстрока
# ищется по всему логу вместо привязки к нужной строке. Первая была с
# dbg=0x00000000. Обе виноваты не железо, а инструмент проверки.
#
# Теперь разбор идёт ТОЛЬКО по строкам, начинающимся с 'BARR'.
$barLines = $text -split "`n" | Where-Object { $_ -match '^\s*BARR\s+bar0 write:' }
$bstuck = 0; $bno = 0
foreach ($bl in $barLines) {
    if ($bl -match 'NOT\s+STUCK') { $bno++ } elseif ($bl -match '\bSTUCK\b') { $bstuck++ }
}
if ($barLines.Count -eq 0) {
    Note "нет строк BARR - сборка старше этапа 13r"
} elseif ($bno -eq 0) {
    Ok ("BARR: BAR0 встал во всех " + $barLines.Count + " случаях (строки разобраны только из BARR)")
} else {
    Bad ("BARR: BAR0 НЕ встал в " + $bno + " случаях из " + $barLines.Count + " - после FLR ждать недостаточно")
}

# --- 9b. готовность устройства после FLR ----------------------------------
# Этап 13. Секция FLR стоит 499,3 мс при бюджете 500 мс, то есть почти
# целиком из двух слепых пауз. Здесь заменена одна из них - та, что стоит
# сразу после инициирования FLR - на ожидание ответа конфигурационного
# пространства. Бюджет остался 200 мс, поэтому худший случай равен прежнему.
$f = [regex]::Match($text, 'FLRREADY calls=(\d+) fast=(\d+) waited=(\d+) never=(\d+) total=(\d+)us max=(\d+)us last_id=0x([0-9A-Fa-f]+) last_raw=0x([0-9A-Fa-f]+)')
if (-not $f.Success) {
    Note "нет строки FLRREADY - сборка старше этапа 13, замер готовности после FLR в ней не было"
} else {
    Ok ("FLRREADY calls=" + $f.Groups[1].Value + " fast=" + $f.Groups[2].Value +
        " waited=" + $f.Groups[3].Value + " never=" + $f.Groups[4].Value +
        " max=" + $f.Groups[6].Value + "us  last_id=0x" + $f.Groups[7].Value)
    if ($f.Groups[4].Value -eq '0') {
        Note ("устройство ответило всегда; max=" + $f.Groups[6].Value + " мкс - это и есть измеренная величина для этапа 14 (пауза 300 мс)")
    } else {
        Note ("устройство НЕ ответило " + $f.Groups[4].Value + " раз из " + $f.Groups[1].Value + " - значит бюджет 200 мс выжигается целиком, замены нет")
    }
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
