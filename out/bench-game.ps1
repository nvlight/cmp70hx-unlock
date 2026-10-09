# SPDX-License-Identifier: GPL-2.0-only
<#
.SYNOPSIS
    Прочитать результаты встроенного бенчмарка Cyberpunk 2077 из summary.json.

.DESCRIPTION
    Зачем этот скрипт
    -----------------
    docs/RENDER-LIMITS.md §2 и docs/POWER-SEARCH-LIST.md часть 13 §2
    требовали закрыть дыру: «50 fps — это не измеренная величина, а
    пересказ», потому что пресет, разрешение, RT и DLSS не были
    зафиксированы нигде.

    Оказалось, фиксировать ничего не нужно: встроенный бенчмарк Cyberpunk
    сам пишет ПОЛНЫЙ набор условий прогона в summary.json рядом с
    frames.csv. Там 45 полей, из них нужные:

        averageFps minFps maxFps time frameNumber
        renderWidth renderHeight        разрешение
        textureQualityPresetLocalizedName   пресет
        rayTracingEnabled rayTracedPathTracingEnabled ...
        DLSSEnabled DLSSQuality DLSSFrameGenEnabled
        DRSEnabled verticalSync fpsClamp windowMode
        gpuName gpuMemory gpuDriverVersion     карта и драйвер
        gameVersion osVersion cpuName systemMemory

    То есть дыра закрывается ЧТЕНИЕМ уже существующих файлов, а новым
    измерением -- нет. Это дешевле и надёжнее ручного пересказа: условия
    пишет сама игра в момент прогона, их нельзя забыть или перепутать
    при записи в документ.

    Чего в summary.json НЕТ
    -----------------------
    Мощности, частот и троттлинга. Их меряет nvidia-smi отдельно, во
    время прогона. Смешивать эти два источника в одну таблицу нельзя, и
    скрипт этого не делает -- он печатает только то, что записала игра.

    Как выбирать прогоны
    -------------------
    Каталог собран с нескольких машин, поэтому прогон бессмыслен без строки об
    условиях. Отбор по умолчанию строгий, по двум признакам:

        -Card '3070 Ti'    имя карты; наша CMP 70HX под драйвером dartraiden
                           отдаёт именно это имя, nvidia-smi показывает
                           'CMP 70HX'
        -Ram 40960         объём памяти машины. cpuName одинаков у всех
                           машин ('Genuine Intel(R) CPU 0000 @ 2.40GHz' --
                           это виртуализация), поэтому различает только RAM.

    Второй признак обязателен: чужие прогоны называют свою карту так же, и без
    отсечения по памяти они попадут в таблицу как наши. -ShowDropped печатает,
    что и почему отсеяно; -AnyMachine снимает отбор по RAM для разбора чужих.

    Проверено на живой системе:
        Win32_ComputerSystem.TotalPhysicalMemory = 39,7 ГБ
        nvidia-smi                               = 616.92, NVIDIA CMP 70HX
        в прогонах                              = systemMemory 40960

    Про fps и разное число кадров
    -----------------------------
    Бенчмарк идёт по таймеру, поэтому число кадров НЕ постоянно: чем
    ниже fps, тем больше времени занимает каждый кадр и тем больше
    кадров набирается за проход. Проверено на frames.csv: профиль кадров
    у 8.9 fps (972 кадра, 109 с) и у 52.1 fps (3347 кадров, 64 с)
    одинаков по форме -- плавный разгон, пик, спад, без обрыва. То есть
    все прогоны полные, а averageFps сопоставим между ними.

    НЕ делать вывод «мало кадров значит прогон оборвался». Оборванные
    прогоны выглядят иначе: у них НЕТ файлов frames.csv/summary.json,
    то есть папка пустая.

.EXAMPLE
    # все прогоны нашей карты, сгруппированные по условиям
    powershell -ExecutionPolicy Bypass -File out\bench-game.ps1

    # подробная таблица по всем прогонам карты
    powershell -ExecutionPolicy Bypass -File out\bench-game.ps1 -Card '3070 Ti' -All

    # только прогоны с выключенными лучами и DLSS (то, что нужно для лестницы)
    powershell -ExecutionPolicy Bypass -File out\bench-game.ps1 -Card '3070 Ti' -NoRT -NoDLSS
#>
param(
    [string]$Root = "$env:USERPROFILE\Documents\CD Projekt Red\Cyberpunk 2077\benchmarkResults",

    # Отбор по карте. Совпадение по подстроке gpuName.
    # '3070 Ti' -- наша CMP 70HX под драйверами dartraiden: драйвер подменяет
    # имя, nvidia-smi показывает 'CMP 70HX'.
    [string]$Card = '3070 Ti',

    # Отбор по конфигурации машины. cpuName одинаков у всех машин
    # ('Genuine Intel(R) CPU 0000 @ 2.40GHz' -- это виртуализация), поэтому
    # различает только объём памяти: Win32_ComputerSystem на этой машине даёт
    # 39,7 ГБ, и в прогонах это записано как systemMemory 40960.
    # Именно этот признак отсекает прогоны с чужих машин, у которых карта
    # называется так же.
    [int]$Ram = 40960,

    # Снять отбор по памяти -- для разбора чужих прогонов
    [switch]$AnyMachine,

    # Показать отсеянное и причину отсева. Отсечение должно быть видно:
    # в проекте уже случалось, что проверка молча фильтровала и рапортовала
    # «всё в порядке» (часть 6 §6.1).
    [switch]$ShowDropped,

    [switch]$NoRT,
    [switch]$NoDLSS,

    # Подробная таблица всех прогонов вместо группировки по условиям
    [switch]$All
)

$ErrorActionPreference = 'Continue'

if (-not (Test-Path $Root)) {
    Write-Output "Каталог не найден: $Root"
    Write-Output 'Укажите путь параметром -Root.'
    exit 1
}

# --- чтение ------------------------------------------------------------------
$runs = @()
$empty = 0
foreach ($d in (Get-ChildItem $Root -Directory | Sort-Object Name)) {
    $sj = Join-Path $d.FullName 'summary.json'
    if (-not (Test-Path $sj)) { $empty++; continue }
    try {
        $j = Get-Content $sj -Raw -Encoding UTF8 | ConvertFrom-Json
        $D = $j.Data
        $runs += [pscustomobject]@{
            Dir      = $d.Name
            Stamp    = $d.Name -replace '^benchmark_', ''
            Gpu      = [string]$D.gpuName
            Mem      = [int]$D.gpuMemory
            Driver   = [string]$D.gpuDriverVersion
            Game     = [string]$D.gameVersion
            Os       = [string]$D.osVersion
            Cpu      = [string]$D.cpuName
            Ram      = [int]$D.systemMemory
            Res      = "$($D.renderWidth)x$($D.renderHeight)"
            Preset   = ([string]$D.textureQualityPresetLocalizedName -split '-')[-1]
            RT       = [bool]$D.rayTracingEnabled
            RTPath   = [bool]$D.rayTracedPathTracingEnabled
            DLSS     = [bool]$D.DLSSEnabled
            FG       = [bool]$D.DLSSFrameGenEnabled
            DRS      = [bool]$D.DRSEnabled
            VSync    = [bool]$D.verticalSync
            Clamp    = [string]$D.fpsClamp
            Avg      = [double]$D.averageFps
            Min      = [double]$D.minFps
            Max      = [double]$D.maxFps
            Frames   = [int]$D.frameNumber
            Time     = [double]$D.time
        }
    } catch {
        Write-Output ("  не разобран: {0} ({1})" -f $d.Name, $_.Exception.Message)
    }
}

Write-Output '====================================================================='
Write-Output 'ИСТОЧНИК УСЛОВИЙ: встроенный бенчмарк Cyberpunk 2077, summary.json'
Write-Output ("каталог       : {0}" -f $Root)
Write-Output ("прогонов      : {0} завершённых, {1} папок без summary.json (прерваны)" -f $runs.Count, $empty)
Write-Output '====================================================================='
Write-Output ''

if ($runs.Count -eq 0) {
    Write-Output 'Ни одного завершённого прогона. Проверьте путь.'
    exit 1
}

# --- отбор: карта И (по умолчанию) конфигурация машины -----------------------
# Причина отбора собирается в поле Reason, чтобы -ShowDropped мог её показать.
$pool = @()
foreach ($r in $runs) {
    $why = @()
    if ($Card -and ($r.Gpu -notlike "*$Card*")) {
        $why += ('другая карта: {0} ({1} МиБ)' -f $r.Gpu, $r.Mem)
    }
    if (-not $AnyMachine -and $Ram -gt 0 -and $r.Ram -ne $Ram) {
        $why += ('другая машина: RAM {0} МиБ (наша {1})' -f $r.Ram, $Ram)
    }
    $r | Add-Member -NotePropertyName Reason -NotePropertyValue ($why -join '; ') -Force
    $pool += $r
}

$sel = @($pool | Where-Object { $_.Reason -eq '' })
$drop = @($pool | Where-Object { $_.Reason -ne '' })

if ($sel.Count -eq 0) {
    Write-Output ("Ничего не прошло отбор: карта '{0}', RAM {1} МиБ." -f $Card, $Ram)
    Write-Output 'Доступные комбинации (имя карты / объём / RAM):'
    $runs | Group-Object Gpu, Mem, Ram | Sort-Object Count -Descending | ForEach-Object {
        Write-Output ("   {0,-30} {1,6} МиБ VRAM  {2,6} МиБ RAM : {3}" -f `
            $_.Group[0].Gpu, $_.Group[0].Mem, $_.Group[0].Ram, $_.Count)
    }
    exit 1
}
if ($NoRT)  { $sel = @($sel | Where-Object { -not $_.RT }) }
if ($NoDLSS){ $sel = @($sel | Where-Object { -not $_.DLSS }) }

$ramStr = if ($AnyMachine) { 'любая машина' } else { "RAM $Ram МиБ" }
Write-Output ("ОТОБРАНО: {0} прогонов -- карта '{1}', {2}{3}{4}" -f `
    $sel.Count, $Card, $ramStr, $(if($NoRT){ ', RT выкл' }), $(if($NoDLSS){ ', DLSS выкл' }))
Write-Output ("ОТСЕЯНО: {0}" -f $drop.Count)
Write-Output ''

if ($ShowDropped -and $drop.Count -gt 0) {
    Write-Output '--- что отсеяно и почему ---'
    $drop | Group-Object Reason | Sort-Object Count -Descending | ForEach-Object {
        Write-Output ("   {0,3}  {1}" -f $_.Count, $_.Name)
    }
    Write-Output ''
}

# --- предупреждение о смешанных машинах --------------------------------------
# При строгом отборе этого быть не должно: остаточная проверка на случай
# -AnyMachine, где машин несколько и сводить их нельзя.
$hosts = @($sel | Group-Object Ram)
if ($hosts.Count -gt 1) {
    Write-Output 'ВНИМАНИЕ: среди отобранных прогонов РАЗНЫЕ конфигурации машин.'
    Write-Output 'Сводить их в одну таблицу нельзя -- это то же сравнение 50 против 80,'
    Write-Output 'только менее заметное. cpuName одинаков у всех и не различает машины.'
    foreach ($h in $hosts) {
        Write-Output ("   RAM {0,6} МиБ : {1} прогонов" -f $h.Group[0].Ram, $h.Count)
    }
    Write-Output ''
}

# --- таблица -----------------------------------------------------------------
if ($All) {
    Write-Output ('{0,-24} {1,6} {2,6} {3,6} {4,6} {5,7} {6,-6} {7,-4} {8,-4} {9,-4} {10,-9} {11}' -f `
        'прогон', 'avg', 'min', 'max', 'кадр', 'время', 'пресет', 'RT', 'DLSS', 'FG', 'драйвер', 'host')
    Write-Output ('-' * 132)
    foreach ($r in $sel) {
        Write-Output ('{0,-24} {1,6:N1} {2,6:N1} {3,6:N1} {4,6} {5,6:N0}с {6,-6} {7,-4} {8,-4} {9,-4} {10,-9} {11}' -f `
            $r.Stamp, $r.Avg, $r.Min, $r.Max, $r.Frames, $r.Time, $r.Preset,
            $(if($r.RT){'RT'}else{'off'}), $(if($r.DLSS){'DLSS'}else{'off'}),
            $(if($r.FG){'FG'}else{'off'}), $r.Driver, $r.Ram)
    }
    Write-Output ''
} else {
    Write-Output 'ГРУППИРОВКА ПО НАБОРУ УСЛОВИЙ. Один набор = одна строка.'
    Write-Output ''
    $groups = @($sel | Group-Object Res, Preset, RT, DLSS, FG, DRS, VSync, Clamp, Game)
    # В колонках обязаны попадать ВСЕ поля группировки, иначе две группы
    # выглядят в таблице одинаковыми, хотя различаются. На этом поймали при
    # разборе чужих прогонов: DRSEnabled=True не выводился, и группа из
    # одного прогона выглядела как дубль соседней из 23.
    Write-Output ('{0,-11} {1,-6} {2,-11} {3,-4} {4,-5} {5,-5} {6,4} {7,6:N1} {8,6:N1} {9,6:N1} {10,7}  {11}' -f `
        'разрешение', 'пресет', 'RT/DLSS/FG', 'DRS', 'vSync', 'clamp', 'маш', `
        'avg', 'min', 'max', 'время', 'fps по прогонам')
    Write-Output ('-' * 145)
    foreach ($g in ($groups | Sort-Object Count -Descending)) {
        $f = $g.Group[0]
        $fpsList = ($g.Group | Sort-Object Stamp | ForEach-Object { '{0:N1}' -f $_.Avg }) -join ', '
        $times = @($g.Group.Time | Sort-Object -Unique)
        $timeStr = if ($times.Count -eq 1) { '{0:N0} с' -f $times[0] } else { '{0:N0}-{1:N0} с' -f $times[0], $times[-1] }
        # Две особенности PowerShell 5.1, обе пойманы на этом файле:
        #   1) 'if' не является выражением (это PowerShell 7+). Нужен $( ).
        #   2) $(... ) с оператором '+' внутри -f нельзя: скобка становится
        #      позиционным аргументом и число аргументов перестаёт совпадать
        #      с числом плейсхолдеров. Поэтому флаги собираем отдельно.
        $flags = $(if ($f.RT) { 'RT' } else { 'off' }) + '/' +
                 $(if ($f.DLSS) { 'DLSS' } else { 'off' }) + '/' +
                 $(if ($f.FG) { 'FG' } else { 'off' })
        $drs = $(if ($f.DRS) { 'ВКЛ' } else { 'off' })
        $vs = $(if ($f.VSync) { 'ВКЛ' } else { 'off' })
        Write-Output ('{0,-11} {1,-6} {2,-11} {3,-4} {4,-5} {5,-5} {6,4} {7,6:N1} {8,6:N1} {9,6:N1} {10,7}  {11}' -f `
            $f.Res, $f.Preset, $flags, $drs, $vs, $f.Clamp,
            $g.Count, $f.Avg, $f.Min, $f.Max, $timeStr, $fpsList)
    }
    Write-Output ''
}

# --- разбор разброса внутри одного набора условий -----------------------------
Write-Output 'РАЗБРОС ВНУТРИ ОДНИХ УСЛОВИЙ (важно: одиночный прогон ничего не значит)'
Write-Output ''
$groups = @($sel | Group-Object Res, Preset, RT, DLSS, FG, Game | Sort-Object Count -Descending)
foreach ($g in $groups) {
    if ($g.Count -lt 2) { continue }
    $v = @($g.Group.Avg | Sort-Object)
    $med = $v[[int][math]::Floor($v.Count / 2)]
    $span = if ($med -ne 0) { 100.0 * ($v[-1] - $v[0]) / $med } else { 0 }
    $f = $g.Group[0]
    $fl = $(if ($f.RT) { 'RT' } else { 'off' }) + '/' +
          $(if ($f.DLSS) { 'DLSS' } else { 'off' }) + '/' +
          $(if ($f.FG) { 'FG' } else { 'off' })
    Write-Output ("  {0} {1} {2} : n={3}  от {4:N1} до {5:N1}  медиана {6:N1}  размах {7:N1} %" -f `
        $f.Res, $f.Preset, $fl,
        $g.Count, $v[0], $v[-1], $med, $span)
    if ($span -gt 5) {
        Write-Output '     -> размах больше 5 %: для сравнения с эталоном брать медиану'
        Write-Output '        и не менее трёх прогонов, иначе это один выброс.'
    }
}
Write-Output ''

# --- что здесь нет ------------------------------------------------------------
Write-Output 'ЧЕГО В ЭТИХ ФАЙЛАХ НЕТ (и почему одного бенчмарка мало)'
Write-Output '  мощность, частоты, троттлинга -- summary.json их не пишет.'
Write-Output '  Их меряет nvidia-smi параллельно с прогоном, и это отдельный замер:'
Write-Output '  docs/POWER-SEARCH-LIST.md часть 12 (201 Вт под майнером против 133 в игре)'
Write-Output '  построен именно на сопоставлении телеметрии с fps из бенчмарка.'
Write-Output ''
Write-Output '  Итог по проекту: условия замера больше не пересказ, они читаются из файла.'
Write-Output '  Но вопрос «достаёт ли графический путь до нагрузки вычислительного»'
Write-Output '  требует ОБОИХ источников: fps из summary.json и ватт из nvidia-smi.'