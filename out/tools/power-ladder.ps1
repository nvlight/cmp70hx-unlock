# SPDX-License-Identifier: GPL-2.0-only
<#
.SYNOPSIS
    Power ladder under sustained load. Answers "can this card reach 220 W?".

.DESCRIPTION
    The earlier numbers came from single llama-bench runs lasting a few
    seconds, which yielded only ~30 samples. This script holds each workload
    for a fixed wall time by looping it, so the NVML sampler gets a real
    population to report on.

    Interpretation, which is the whole point of the ladder:

      * the card is POWER-limited  -> SW Power Cap bit (0x8) set, and the SM
                                      clock falls below the 1545 MHz maximum;
      * the card is WORKLOAD-limited -> clock pinned at maximum, no power-cap
                                      bit, the work simply does not ask for
                                      more watts.

    Ladder rungs go from the plain prompt-processing case up to large batch
    with a long context, which is what actually stresses the datapath and the
    memory system together.

.PARAMETER Seconds
    Wall time to hold each rung. Longer = better statistics, linear cost.
#>
param(
    [string]$Tag = 'ladder',
    [int]$Seconds = 25
)

$ErrorActionPreference = 'Continue'

$LlamaBin = 'C:\Users\Administrator\Desktop\llama.cpp\llama-b11062-bin-win-cuda-13.4-x64'
$LlamaExe = Join-Path $LlamaBin 'llama-bench.exe'
$repo     = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$outDir   = Join-Path $repo 'out\tools'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$Q = 'power.draw,clocks.sm,clocks.mem,temperature.gpu,utilization.gpu,clocks_throttle_reasons.active'

$rungs = @(
    @{ n = 'p512 n16 b1';        a = @('-p','512','-n','16') },
    @{ n = 'p2048 n16 b1';       a = @('-p','2048','-n','16') },
    @{ n = 'p512 n16 b8192';     a = @('-p','512','-n','16','-b','8192','-ub','1024') },
    @{ n = 'p4096 n32 b8192';    a = @('-p','4096','-n','32','-b','8192','-ub','1024') },
    @{ n = 'p8192 n32 b16384';   a = @('-p','8192','-n','32','-b','16384','-ub','2048') }
)

Write-Output "=== power ladder: $Tag ==="
nvidia-smi --query-gpu=power.limit,enforced.power.limit,clocks.max.sm,power.max_limit --format=csv,noheader -i 0 | ForEach-Object { "limits: $_" }
Write-Output ("each rung held {0} s`n" -f $Seconds)

$summary = @()

foreach ($r in $rungs) {
    $raw = Join-Path $outDir ("lad-{0}.csv" -f ($r.n -replace '[^A-Za-z0-9]', '_'))
    if (Test-Path $raw) { Remove-Item $raw -Force }

    $stop = $false
    $job = Start-Job -ScriptBlock {
        param($q, $path, $sb)
        while ($true) {
            $l = & nvidia-smi --query-gpu=$q --format=csv,noheader,nounits -i 0 2>$null
            if ($l) { Add-Content -Path $path -Value $l }
            Start-Sleep -Milliseconds $sb
            if (Test-Path variable:script:stopme) { if ($script:stopme) { break } }
        }
    } -ArgumentList $Q, $raw, 60

    Start-Sleep -Milliseconds 500

    # hold the workload for the requested wall time
    $t0 = Get-Date
    $lastTps = ''
    while (((Get-Date) - $t0).TotalSeconds -lt $Seconds) {
        Push-Location $LlamaBin
        $o = & $LlamaExe -m 'models\llama-2-7b.Q4_0.gguf' -ngl 99 @($r.a) 2>&1
        Pop-Location
        foreach ($ln in $o) {
            if ($ln -match 'pp\d+' -and $ln -match '([\d]+\.[\d]+)\s*(\u00b1[^|]*)?\s*$') { $lastTps = $Matches[1] }
        }
    }

    Stop-Job $job -EA SilentlyContinue
    Remove-Job $job -Force -EA SilentlyContinue

    $rows = @()
    if (Test-Path $raw) {
        foreach ($l in Get-Content $raw) {
            $p = $l.Split(',')
            if ($p.Count -lt 6) { continue }
            try {
                $rows += [pscustomobject]@{
                    power = [double]$p[0].Trim(); sm = [double]$p[1].Trim()
                    mem = [double]$p[2].Trim();  temp = [double]$p[3].Trim()
                    util = [double]$p[4].Trim(); thr = $p[5].Trim()
                }
            } catch { }
        }
    }
    $busy = @($rows | Where-Object { $_.util -ge 50 -and $_.power -ge 40 })

    $peak = 0.0; $med = 0.0; $medSm = 0.0; $medT = 0.0; $pc = $false; $thrSeen = @()
    if ($busy.Count -gt 0) {
        $peak = ($busy.power | Measure-Object -Maximum).Maximum
        $med  = @($busy.power | Sort-Object)[[int]($busy.Count / 2)]
        $medSm = @($busy.sm | Sort-Object)[[int]($busy.Count / 2)]
        $medT  = @($busy.temp | Sort-Object)[[int]($busy.Count / 2)]
        $thrSeen = @($busy.thr | Sort-Object -Unique)
        foreach ($b in $thrSeen) {
            try { if (([uint64]$b -band 0x8) -ne 0) { $pc = $true } } catch { }
        }
    }

    $summary += [pscustomobject]@{
        rung   = $r.n
        tps    = $lastTps
        n      = $busy.Count
        peak   = [math]::Round($peak, 1)
        pct    = [math]::Round(100.0 * $peak / 220.0, 1)
        medP   = [math]::Round($med, 1)
        medSm  = [math]::Round($medSm, 0)
        temp   = $medT
        pc     = $(if ($pc) { 'YES' } else { 'no' })
        thr    = ($thrSeen -join '/')
    }
    Write-Output ("  rung {0,-18} done: n={1} peak={2} W" -f $r.n, $busy.Count, [math]::Round($peak,1))
}

Write-Output ""
Write-Output "=== summary: $Tag ==="
Write-Output ("{0,-18} {1,-9} {2,-5} {3,8} {4,7} {5,8} {6,7} {7,5} {8}" -f `
    'rung', 't/s', 'n', 'peak W', '%lim', 'med W', 'med SM', 'temp', 'pwrCap')
Write-Output ("-" * 90)
foreach ($s in $summary) {
    Write-Output ("{0,-18} {1,-9} {2,-5} {3,8} {4,7} {5,8} {6,7} {7,5} {8}" -f `
        $s.rung, $s.tps, $s.n, $s.peak, $s.pct, $s.medP, $s.medSm, $s.temp, $s.pc)
}
Write-Output ""
Write-Output "pwrCap = SW Power Cap throttle bit (0x8). YES means the 220 W budget"
Write-Output "is actually binding. med SM is the median clock; max is 1545 MHz."
Write-Output "Throttle masks: 0x0 none, 0x1 Idle, 0x2 applications clocks,"
Write-Output "0x4 SW Power Cap is 0x8 in this field, 0x40 HW slowdown."
