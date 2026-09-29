# SPDX-License-Identifier: GPL-2.0-only
<#
.SYNOPSIS
    Is the card power-limited, or workload-limited? Drive it harder and watch.

.DESCRIPTION
    The 220 W figure is a limit (NVML `power.limit`), not a consumption
    measurement. The interesting question is not "how close are we to 220 W"
    but "is anything stopping the card from going faster":

      * power-limited  -> the SW Power Cap throttle bit is set, and the SM
                          clock sits BELOW the card's maximum;
      * workload-limited -> clock pinned at maximum, no power-cap bit, the
                          workload simply does not ask for more watts.

    So: run progressively heavier workloads and record, for each, peak power,
    median SM clock, and the throttle bitmask. If power rises while the clock
    stays at 1545 MHz and no power-cap bit appears, the card is not being
    held back by its power budget.
#>
param(
    [string]$Tag = 'powercurve',
    [int]$Samples = 120
)

$ErrorActionPreference = 'Continue'

$LlamaBin = 'C:\Users\Administrator\Desktop\llama.cpp\llama-b11062-bin-win-cuda-13.4-x64'
$LlamaExe = Join-Path $LlamaBin 'llama-bench.exe'
$repo     = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$outDir   = Join-Path $repo 'out\tools'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$Q = 'power.draw,clocks.sm,temperature.gpu,utilization.gpu,clocks_throttle_reasons.active'

# escalating workloads: each asks for more memory traffic and more live
# compute than the last
$CASES = @(
    @{ name = 'p512 n16 b1 (baseline)'; args = @('-p','512','-n','16') },
    @{ name = 'p2048 n16 b1';           args = @('-p','2048','-n','16') },
    @{ name = 'p512 n16 b4096';         args = @('-p','512','-n','16','-b','4096','-ub','512') },
    @{ name = 'p4096 n64 b4096';        args = @('-p','4096','-n','64','-b','4096','-ub','512') }
)

Write-Output "=== power ceiling probe: $Tag ==="
nvidia-smi --query-gpu=power.limit,enforced.power.limit,clocks.max.sm --format=csv,noheader -i 0 | ForEach-Object { "limits: $_" }
Write-Output ""

$summary = @()

foreach ($c in $CASES) {
    $raw = Join-Path $outDir ("pc-{0}.csv" -f ($c.name -replace '[^A-Za-z0-9]', '_'))
    if (Test-Path $raw) { Remove-Item $raw -Force }

    $job = Start-Job -ScriptBlock {
        param($q, $path, $n)
        for ($i = 0; $i -lt $n; $i++) {
            $l = & nvidia-smi --query-gpu=$q --format=csv,noheader,nounits -i 0 2>$null
            if ($l) { Add-Content -Path $path -Value $l }
            Start-Sleep -Milliseconds 200
        }
    } -ArgumentList $Q, $raw, $Samples

    Start-Sleep -Milliseconds 600

    Push-Location $LlamaBin
    $bench = & $LlamaExe -m 'models\llama-2-7b.Q4_0.gguf' -ngl 99 @($c.args) 2>&1
    Pop-Location

    Stop-Job $job -ErrorAction SilentlyContinue
    Remove-Job $job -Force -ErrorAction SilentlyContinue

    $rows = @()
    if (Test-Path $raw) {
        foreach ($l in Get-Content $raw) {
            $p = $l.Split(',')
            if ($p.Count -lt 5) { continue }
            try {
                $rows += [pscustomobject]@{
                    power = [double]$p[0].Trim(); sm = [double]$p[1].Trim()
                    temp  = [double]$p[2].Trim(); util = [double]$p[3].Trim()
                    thr   = $p[4].Trim()
                }
            } catch { }
        }
    }
    $busy = @($rows | Where-Object { $_.util -ge 50 -and $_.power -ge 40 })

    # pull the pp / tg numbers out of the table
    $pp = ($bench | Select-String -Pattern 'pp\d+').Line
    $tps = @()
    foreach ($ln in @($pp)) {
        if ($ln -match '([\d]+\.[\d]+)\s*$') { $tps += $Matches[1] }
    }

    $peakP = 0.0; $medSm = 0.0; $medT = 0.0; $thrBits = @()
    if ($busy.Count -gt 0) {
        $peakP = ($busy.power | Measure-Object -Maximum).Maximum
        $medSm = @($busy.sm | Sort-Object)[[int]($busy.Count / 2)]
        $medT  = @($busy.temp | Sort-Object)[[int]($busy.Count / 2)]
        $thrBits = @($busy.thr | Sort-Object -Unique)
    }
    $nWatt = $false
    foreach ($b in $thrBits) { try { $v = [uint64]$b; if (($v -band 0x8) -ne 0) { $nWatt = $true } } catch { } }

    $summary += [pscustomobject]@{
        case    = $c.name
        tps     = ($tps -join '/')
        peakW   = [math]::Round($peakP, 1)
        pctLim  = [math]::Round(100.0 * $peakP / 220.0, 1)
        medSM   = [math]::Round($medSm, 0)
        temp    = $medT
        pcBit   = $(if ($nWatt) { 'YES' } else { 'no' })
    }
}

Write-Output ""
Write-Output "=== summary ==="
Write-Output ("{0,-24} {1,-16} {2,8} {3,7} {4,8} {5,6} {6}" -f `
    'case', 't/s (pp/tg)', 'peak W', '%lim', 'med SM', 'temp', 'pwrCap')
Write-Output ("-" * 84)
foreach ($s in $summary) {
    Write-Output ("{0,-24} {1,-16} {2,8} {3,7} {4,8} {5,6} {6}" -f `
        $s.case, $s.tps, $s.peakW, $s.pctLim, $s.medSM, $s.temp, $s.pcBit)
}
Write-Output ""
Write-Output "pwrCap = the SW Power Cap throttle bit (0x8). Set means the card is"
Write-Output "being held back by its 220 W budget. med SM vs max 1545 MHz shows"
Write-Output "whether the clock is being pulled down."
