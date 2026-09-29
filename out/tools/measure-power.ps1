# SPDX-License-Identifier: GPL-2.0-only
<#
.SYNOPSIS
    Measure real power draw under llama-bench, and report it against the limit.

.DESCRIPTION
    Why this script exists:

    The 55-91 W figures from src/tools/issrate.py are NOT a statement about
    the card's power ceiling. Those kernels are pure-register ALU loops with
    zero memory traffic, and a register-only loop simply does not burn much
    power. The only honest number for "how much does this card draw while
    working" comes from a memory-bound workload, i.e. llama-bench.

    On the premise: 220 W is the value of `power.limit` in NVML, i.e. the
    ceiling the driver enforces on this card. It is a limit, not a
    measurement, and no workload is obliged to reach it. The question worth
    asking is how close a real workload gets, and whether the gap to the
    limit is a power cap or just the workload's appetite.

.SYNOPSIS
    Why a polling loop instead of `nvidia-smi -lms`:
    with stdout redirected to a file, the continuous mode buffers its output
    and the file stays empty until the process exits. Sampling by launching
    nvidia-smi repeatedly costs ~40 ms per sample and always lands.

.EXAMPLE
    measure-power.ps1 -Tag unlocked -Workload bench
#>
param(
    [string]$Tag = 'adhoc',
    [ValidateSet('bench', 'burn')]
    [string]$Workload = 'bench',
    [int]$Samples = 200
)

$ErrorActionPreference = 'Continue'

$LlamaBin = 'C:\Users\Administrator\Desktop\llama.cpp\llama-b11062-bin-win-cuda-13.4-x64'
$LlamaExe = Join-Path $LlamaBin 'llama-bench.exe'

$repo   = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$outDir = Join-Path $repo 'out\tools'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$raw      = Join-Path $outDir "power-raw-$Tag.csv"
$benchOut = Join-Path $outDir "power-bench-$Tag.txt"

$Q = 'power.draw,clocks.sm,clocks.mem,temperature.gpu,utilization.gpu,clocks_throttle_reasons.active'

Write-Output "=== $Tag ==="
Write-Output "power limits from NVML:"
nvidia-smi --query-gpu=power.draw,power.limit,enforced.power.limit,power.default_limit,clocks.max.sm --format=csv,noheader -i 0 | ForEach-Object { "  $_" }

if (Test-Path $raw) { Remove-Item $raw -Force }

# --- sampler: one nvidia-smi per sample, output flushed every time ----------
$sampler = Start-Job -ScriptBlock {
    param($q, $path, $n)
    for ($i = 0; $i -lt $n; $i++) {
        $line = & nvidia-smi --query-gpu=$q --format=csv,noheader,nounits -i 0 2>$null
        if ($line) { Add-Content -Path $path -Value $line }
        Start-Sleep -Milliseconds 60
    }
} -ArgumentList $Q, $raw, $Samples

Start-Sleep -Milliseconds 800

Write-Output ""
Write-Output "--- workload: $Workload ---"
if ($Workload -eq 'bench') {
    Push-Location $LlamaBin
    & $LlamaExe -m 'models\llama-2-7b.Q4_0.gguf' -ngl 99 -p 512 -n 16 *>&1 |
        Tee-Object -FilePath $benchOut | Out-Null
    Pop-Location
    Write-Output "bench output -> $benchOut"
} else {
    Push-Location $repo
    & python (Join-Path $repo 'src\tools\issrate.py') --tag "burn-$Tag" *>&1 |
        Out-Null
    Pop-Location
    Write-Output "burn output discarded (see console)"
}

Stop-Job $sampler -ErrorAction SilentlyContinue
Remove-Job $sampler -Force -ErrorAction SilentlyContinue

# --- analyse ----------------------------------------------------------------
$rows = @()
if (Test-Path $raw) {
    foreach ($l in Get-Content $raw) {
        $p = $l.Split(',')
        if ($p.Count -lt 6) { continue }
        try {
            $rows += [pscustomobject]@{
                power = [double]$p[0].Trim()
                sm    = [double]$p[1].Trim()
                mem   = [double]$p[2].Trim()
                temp  = [double]$p[3].Trim()
                util  = [double]$p[4].Trim()
                thr   = $p[5].Trim()
            }
        } catch { }
    }
}

Write-Output ""
Write-Output "--- NVML samples ---"
if ($rows.Count -eq 0) {
    Write-Output "  NO DATA (nvidia-smi returned nothing)"
    return
}

# Only busy samples: idle ones would drag every statistic toward 12 W and
# answer a question nobody asked.
$busy = @($rows | Where-Object { $_.util -ge 50 -and $_.power -ge 40 })

function Show-Stat([string]$name, $vals) {
    if ($null -eq $vals -or $vals.Count -eq 0) {
        Write-Output ("  {0,-10} no data" -f $name)
        return
    }
    $s = @($vals | Sort-Object)
    $med = $s[[int]($s.Count / 2)]
    Write-Output ("  {0,-10} min {1,7:N1}   med {2,7:N1}   max {3,7:N1}   n={4}" -f `
        $name, $s[0], $med, $s[-1], $s.Count)
}

Write-Output ("  samples total: {0}   busy (util>=50% and P>=40W): {1}" -f $rows.Count, $busy.Count)
Write-Output ""
Show-Stat 'power W'  ($busy.power)
Show-Stat 'SM MHz'   ($busy.sm)
Show-Stat 'mem MHz'  ($busy.mem)
Show-Stat 'temp C'   ($busy.temp)
Show-Stat 'util %'   ($busy.util)

if ($busy.Count -gt 0) {
    $maxP = ($busy.power | Measure-Object -Maximum).Maximum
    $medP = @($busy.power | Sort-Object)[[int]($busy.Count / 2)]
    Write-Output ""
    Write-Output ("  peak {0:N1} W = {1:N1} % of the 220 W limit" -f $maxP, (100.0 * $maxP / 220.0))
    Write-Output ("  median {0:N1} W = {1:N1} % of the limit" -f $medP, (100.0 * $medP / 220.0))
}
$thr = ($busy.thr | Sort-Object -Unique) -join ' '
if (-not $thr) { $thr = 'none' }
Write-Output ("  throttle reasons: {0}" -f $thr)
Write-Output ""
Write-Output "  raw: $raw"
