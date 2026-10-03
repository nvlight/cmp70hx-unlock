# ==== Сравнение таблиц меток времени между двумя прогонами ====
#
# ЗАЧЕМ ОТДЕЛЬНЫЙ СКРИПТ. Первый раз я сравнивал секции инлайновым
# PowerShell-скриптом и получил двукратное завышение: показал 720 мс там, где
# правда было 360 мс. Причина: ТАБЛИЦА MK ПЕЧАТАЕТСЯ В ЛОГЕ ДВАЖДЫ (проверено -
# каждая строка встречается ровно 2 раза), и скрипт складывал обе копии.
# Я после этого полез искать загадку в железе, вместо того чтобы заподозрить
# собственный инструмент. Потом исправил скрипт после v3.31 и ПОТЕРЯЛ правку
# при следующем прогоне. Третий раз уже не повторится.
#
# ПРАВИЛО: каждую строку таблицы брать ТОЛЬКО ОДИН РАЗ.
#
# Требования: BOM обязателен (PowerShell 5.1 иначе читает .ps1 как ANSI),
#             CRLF обязателен (WSL-обёртка для build).

param(
    [Parameter(Mandatory=$true)][string]$A,   # старый лог, например usb-log-v334.txt
    [Parameter(Mandatory=$true)][string]$B,   # новый лог
    [int]$Threshold = 20000                    # мкс, ниже разница не показывается
)

$ErrorActionPreference = 'Stop'

function Get-Marks {
    param([string]$Path)
    $acc = @{}
    $seen = @{}
    $rows = Select-String -Path $Path -Pattern 'TIME\s+MK\s+(\S.*?)\s+(\d+)\s+us\s+x\s+(\d+)' |
            ForEach-Object { [pscustomobject]@{
                Name = $_.Matches[0].Groups[1].Value.Trim()
                Us   = [int]$_.Matches[0].Groups[2].Value
                Calls= [int]$_.Matches[0].Groups[3].Value } }
    foreach ($r in $rows) {
        # КЛЮЧЕВАЯ СТРОКА: каждую метку берём один раз, несмотря на то что
        # таблица напечатана дважды. Первую встречу и игнорируем повторы.
        if ($seen.ContainsKey($r.Name)) { continue }
        $seen[$r.Name] = $true
        $acc[$r.Name] = @{ Us = $r.Us; Calls = $r.Calls }
    }
    $dups = ($rows.Count -gt $acc.Count)
    return @{ Acc = $acc; DupTable = $dups; Total = $rows.Count }
}

$ma = Get-Marks $A
$mb = Get-Marks $B

Write-Host "=== $($ma.Acc.Count) меток в $A, $($mb.Acc.Count) в $B ==="
if ($ma.DupTable -or $mb.DupTable) {
    Write-Host "  ВНИМАНИЕ: таблица MK напечатана дважды (всего строк $($ma.Total)/$($mb.Total))." -ForegroundColor Yellow
    Write-Host "  Дубли отброшены. Сложение выполнено ОДИН раз на метку." -ForegroundColor Yellow
} else {
    Write-Host "  Дублей таблицы не обнаружено." -ForegroundColor DarkGray
}

$keys = ($ma.Acc.Keys + $mb.Acc.Keys) | Sort-Object -Unique
Write-Host ""
Write-Host ("{0,-40} {1,10} {2,10} {3,10} {4,6}" -f 'секция','A мкс','B мкс','разница','зв.')
Write-Host ("-" * 82)

foreach ($k in $keys) {
    $x = if ($ma.Acc[$k]) { $ma.Acc[$k].Us } else { 0 }
    $y = if ($mb.Acc[$k]) { $mb.Acc[$k].Us } else { 0 }
    $ca= if ($ma.Acc[$k]) { $ma.Acc[$k].Calls } else { 0 }
    $cb= if ($mb.Acc[$k]) { $mb.Acc[$k].Calls } else { 0 }
    $d = $y - $x
    if ([math]::Abs($d) -ge $Threshold) {
        $tag = if ($d -gt 0) { 'ВЫРОСЛА' } else { 'упала' }
        Write-Host ("{0,-40} {1,10} {2,10} {3,10} {4,6}  {5}" -f $k,$x,$y,$d,"$ca/$cb",$tag)
    }
}

function Get-Total($p) {
    $m = Select-String -Path $p -Pattern 't=(\d+)ms\s+final: before return to firmware' | Select-Object -Last 1
    if ($m) { return [int]$m.Matches[0].Groups[1].Value } else { return -1 }
}
$ta = Get-Total $A; $tb = Get-Total $B
Write-Host ("-" * 82)
Write-Host ("{0,-40} {1,10} {2,10} {3,10}" -f 'ИТОГ ПРОГОНА', $ta, $tb, ($tb - $ta))