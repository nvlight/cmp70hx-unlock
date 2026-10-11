# SPDX-License-Identifier: GPL-2.0-only
<#
.SYNOPSIS
    Capture NVML telemetry while the user runs Cyberpunk 2077 benchmarks.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File out\tools\measure-game.ps1 `
        -Tag gr-r3-20261011

    Start three in-game benchmarks, then return to this console and press Enter.
#>
[CmdletBinding()]
param(
    [string] $Tag = 'adhoc',
    [int] $IntervalMs = 250,
    [int] $DurationSeconds = 0,
    [string] $BenchmarkRoot = "$env:USERPROFILE\Documents\CD Projekt Red\Cyberpunk 2077\benchmarkResults",
    [string] $OutputDir = ''
)

$ErrorActionPreference = 'Stop'
if ($IntervalMs -lt 100) { throw 'IntervalMs must be at least 100.' }
if ($DurationSeconds -lt 0) { throw 'DurationSeconds cannot be negative.' }
if ($Tag -notmatch '^[A-Za-z0-9._-]+$') { throw 'Tag may contain only letters, digits, dot, underscore and dash.' }

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $OutputDir) { $OutputDir = Join-Path $repo 'out\tools' }
$OutputDir = [IO.Path]::GetFullPath($OutputDir)
[IO.Directory]::CreateDirectory($OutputDir) | Out-Null
$rawPath = Join-Path $OutputDir "game-telemetry-$Tag.csv"
if (Test-Path -LiteralPath $rawPath) {
    throw "Output already exists: $rawPath"
}

$gpu = & nvidia-smi --query-gpu=name,driver_version,memory.total `
    --format=csv,noheader -i 0 2>$null
if ($LASTEXITCODE -ne 0 -or -not $gpu) { throw 'nvidia-smi cannot query GPU 0.' }

$started = Get-Date
$existing = @{}
if (Test-Path -LiteralPath $BenchmarkRoot) {
    Get-ChildItem -LiteralPath $BenchmarkRoot -Directory | ForEach-Object {
        $existing[$_.FullName] = $true
    }
}

$query = 'timestamp,power.draw,clocks.sm,clocks.mem,temperature.gpu,utilization.gpu,clocks_throttle_reasons.active'
$header = 'timestamp,power_w,sm_mhz,mem_mhz,temp_c,util_pct,throttle_reasons'
[IO.File]::WriteAllText($rawPath, $header + [Environment]::NewLine,
    (New-Object Text.UTF8Encoding $true))

"GPU       : $gpu"
"started   : $($started.ToString('o'))"
"telemetry : $rawPath"
''

$sampler = Start-Job -ScriptBlock {
    param($Query, $Path, $Delay, $Seconds)
    $deadline = if ($Seconds -gt 0) { (Get-Date).AddSeconds($Seconds) } else { $null }
    while (-not $deadline -or (Get-Date) -lt $deadline) {
        $line = & nvidia-smi --query-gpu=$Query --format=csv,noheader,nounits -i 0 2>$null
        if ($line) { Add-Content -LiteralPath $Path -Value $line -Encoding UTF8 }
        Start-Sleep -Milliseconds $Delay
    }
} -ArgumentList $query, $rawPath, $IntervalMs, $DurationSeconds

try {
    if ($DurationSeconds -gt 0) {
        "Sampling for $DurationSeconds seconds..."
        Wait-Job $sampler | Out-Null
    } else {
        'Run three built-in Cyberpunk 2077 benchmarks.'
        'After the third completed run, return here and press Enter.'
        Read-Host | Out-Null
    }
} finally {
    Stop-Job $sampler -ErrorAction SilentlyContinue
    Receive-Job $sampler -ErrorAction SilentlyContinue | Out-Null
    Remove-Job $sampler -Force -ErrorAction SilentlyContinue
}

$rows = @()
foreach ($line in Get-Content -LiteralPath $rawPath | Select-Object -Skip 1) {
    $p = $line.Split(',')
    if ($p.Count -lt 7) { continue }
    try {
        $rows += [pscustomobject]@{
            Power   = [double]$p[1].Trim()
            Sm      = [double]$p[2].Trim()
            Memory  = [double]$p[3].Trim()
            Temp    = [double]$p[4].Trim()
            Util    = [double]$p[5].Trim()
            Throttle = $p[6].Trim()
        }
    } catch { }
}
$busy = @($rows | Where-Object { $_.Util -ge 50 -and $_.Power -ge 40 })

function Show-Stat([string] $Name, $Values) {
    $v = @($Values | Sort-Object)
    if ($v.Count -eq 0) { "  ${Name}: no busy samples"; return }
    $median = $v[[int]($v.Count / 2)]
    ('  {0,-9} min {1,7:N1}  med {2,7:N1}  max {3,7:N1}  n={4}' -f
        $Name, $v[0], $median, $v[-1], $v.Count)
}

''
"samples: total=$($rows.Count), busy=$($busy.Count)"
Show-Stat 'power W' $busy.Power
Show-Stat 'SM MHz' $busy.Sm
Show-Stat 'mem MHz' $busy.Memory
Show-Stat 'temp C' $busy.Temp
$throttle = @($busy.Throttle | Sort-Object -Unique)
"  throttle: $(if ($throttle.Count) { $throttle -join ', ' } else { 'no busy samples' })"

''
'New completed Cyberpunk benchmark results:'
$newRuns = @()
if (Test-Path -LiteralPath $BenchmarkRoot) {
    $newRuns = @(Get-ChildItem -LiteralPath $BenchmarkRoot -Directory |
        Where-Object { -not $existing.ContainsKey($_.FullName) } |
        Sort-Object LastWriteTime)
}
if ($newRuns.Count -eq 0) {
    '  none'
} else {
    foreach ($run in $newRuns) {
        $summary = Join-Path $run.FullName 'summary.json'
        if (-not (Test-Path -LiteralPath $summary)) {
            "  INCOMPLETE $($run.Name): summary.json missing"
            continue
        }
        $data = (Get-Content -LiteralPath $summary -Raw | ConvertFrom-Json).Data
        ('  {0}: avg={1:N3} min={2:N3} max={3:N3} fps, {4}x{5}, RT={6}, DLSS={7}, FG={8}' -f
            $run.Name, $data.averageFps, $data.minFps, $data.maxFps,
            $data.renderWidth, $data.renderHeight, $data.rayTracingEnabled,
            $data.DLSSEnabled, $data.DLSSFrameGenEnabled)
    }
}

if ($newRuns.Count -ne 3) {
    Write-Warning "Expected exactly 3 new benchmark directories, got $($newRuns.Count)."
    exit 2
}
