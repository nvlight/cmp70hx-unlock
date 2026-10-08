# Аудит отпечатков в документе против реальных сборок.
#
# Правило, которое проверяем: любой md5, которого НЕТ на диске, обязан быть
# явно помечен как исторический (тот бинарь, который реально запускался,
# либо отпечаток на момент написания раздела). Непомеченный отсутствующий
# отпечаток - это подмена: через полгода неизвестно, какая сборка дала лог.
#
# Пишем файлом с BOM: кириллица в инлайн-команде PowerShell искажается
# по кодировке канала, и фильтр молча перестаёт совпадать. Это уже
# случалось трижды и один раз дало ложный "всё хорошо".

$ErrorActionPreference = 'Stop'
$root = 'C:\Users\Administrator\Desktop\cmp 70hx\_with_fable_now\cmp_70hx_unlock___fable'
$doc  = Join-Path $root 'docs\POWER-SEARCH-LIST.md'
$src  = Join-Path $root 'src'

$have = @{}
Get-ChildItem "$src\*.efi" | ForEach-Object { $have[$_.BaseName] = (Get-FileHash $_.FullName -Algorithm MD5).Hash.ToLower() }

$lines = Get-Content $doc -Encoding UTF8
$txt   = $lines -join "`n"

# Пометка обязана находиться В ТОЙ ЖЕ СТРОКЕ, что и отпечаток.
#
# Первый вариант аудита искал пометку в соседних строках и насчитал
# "0 помеченных" на документе, где исторические отпечатки помечены
# абзацем ниже. Такой критерий проверяет не документ, а расстояние
# между строками: любая правка формулировки или вставка абзаца молча
# ломает проверку, и она начинает врать. Пометка в той же строке
# разъезжаться не может.
$marks = @('исторический', 'на момент раздела', 'реально запускался',
           'не существует', 'было:', 'прогона 2026-08')

$rows = @()
foreach ($h in ([regex]::Matches($txt, '\b[0-9a-f]{32}\b') | ForEach-Object { $_.Value } | Sort-Object -Unique)) {
    $build = ($have.Keys | Where-Object { $have[$_] -eq $h }) -join ','
    $hits  = @($lines | Select-String -SimpleMatch $h)
    $unlabelled = @()
    foreach ($hh in $hits) {
        $ok = $false
        foreach ($m in $marks) { if ($hh.Line -like "*$m*") { $ok = $true; break } }
        if (-not $ok) { $unlabelled += $hh.LineNumber }
    }
    $rows += [pscustomobject]@{
        md5        = $h.Substring(0, 7)
        build      = $(if ($build) { $build } else { 'НЕТ СБОРКИ' })
        onDisk     = $(if ($build) { 'да' } else { 'НЕТ' })
        mentions   = $hits.Count
        unmarkedLn = $(if ($unlabelled.Count) { $unlabelled -join ',' } else { '-' })
    }
}

$rows | Format-Table -AutoSize | Out-String -Width 200

# Две разные категории, их нельзя смешивать под одним словом "НЕПОМЕЧЕННЫЕ":
#   ЖЁСТКИЙ - отпечатка нет на диске и он не помечен. Это подмена: документ
#              предъявляет бинарь, которого не существует, как будто прогон
#              его делал.
#   МЯГКИЙ  - отпечаток есть на диске, но не помечен. Это норма: сборка
#              текущая, исторической не является.
$fatal  = @($rows | Where-Object { $_.onDisk -eq 'НЕТ' -and $_.unmarkedLn -ne '-' })
$soft   = @($rows | Where-Object { $_.onDisk -eq 'да' -and $_.unmarkedLn -ne '-' })
$okStale = @($rows | Where-Object { $_.onDisk -eq 'НЕТ' -and $_.unmarkedLn -eq '-' })

''
"ЖЁСТКИХ (нет на диске и не помечен) : $($fatal.Count)"
"МЯГКИХ  (есть на диске, не помечен)  : $($soft.Count)   <- это норма"
"ПОМЕЧЕННЫХ исторических             : $($okStale.Count)"

if ($soft.Count) {
    ''
    '--- мягкие: текущие сборки, пометка не требуется ---'
    $soft | Format-Table -AutoSize | Out-String -Width 200
}
if ($fatal.Count -eq 0) {
    ''
    'ИТОГ: ЖЁСТКИХ НЕТ - каждый отпечаток, которого нет на диске, помечен'
    'как исторический в той же строке. Подмены нет.'
} else {
    ''
    "ИТОГ: ЖЁСТКИХ = $($fatal.Count) - документ предъявляет несуществующие сборки."
    $fatal | Format-Table -AutoSize | Out-String -Width 200
    foreach ($b in $fatal) {
        ''
        "--- $($b.md5) строки $($b.unmarkedLn) ---"
        foreach ($n in ($b.unmarkedLn -split ',')) {
            $ln = [int]$n
            "  ${ln}: $($lines[$ln - 1].Trim())"
        }
    }
}