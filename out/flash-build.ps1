<#
    flash-build.ps1 — one command for the whole "build -> flash -> verify" cycle.

    This exists because the cycle was prose in BUILDING.md §6.1 and
    FLASH-AND-LOG.md §2, and prose gets misread. It happened once: the
    instructions said to copy unlock_v3n_CMP70HX.efi, which is the compute-only
    ROLLBACK, so following them literally would have flashed a card back to
    zero in games. The script refuses to do that.

    Usage:
        powershell -ExecutionPolicy Bypass -File out\flash-build.ps1
        powershell -ExecutionPolicy Bypass -File out\flash-build.ps1 -Stick X:
        powershell -ExecutionPolicy Bypass -File out\flash-build.ps1 -SkipGspCheck

    What it does, in order, stopping at the first failure:
        1. copy the working build from src\ to out\ as the flash reference
        2. verify the ROLLBACK is still byte-identical  (BUILDING.md §6.0)
        3. verify the GSP firmware blob on the stick is untouched
        4. write the loader to <Stick>:\EFI\BOOT\BOOTX64.EFI (remove-then-copy)
        5. verify by md5 AND by strings INSIDE the file on the stick

    What it will NOT do (see BUILDING.md §6.3): reboot, press F12, or write a
    whole-disk image. Those belong to the human. After it finishes, report the
    md5s and stop — the change is not tested until a log comes back.

    Exit codes: 0 ok, 1 verification failed (nothing was written), 2 written
    but verification failed afterwards (treat the stick as suspect).
#>
[CmdletBinding()]
param(
    # Drive letter of the boot stick. Detected when omitted.
    [string]$Stick = '',

    # Skip the GSP md5 check. Only for the rare case the stick legitimately
    # carries a different GSP build; say so in the commit message if used.
    [switch]$SkipGspCheck
)

$ErrorActionPreference = 'Stop'

$root    = Split-Path -Parent $PSScriptRoot
$outDir  = $PSScriptRoot          # this script lives in out\
$srcDir  = Join-Path $root 'src'

# The working build: compute unlock x11.25 AND render unlock (Cyberpunk 50 fps).
# Name in build.sh is unlock_v3r; the out/ reference is named v3w on purpose so
# it cannot be confused with the v3n rollback sitting next to it.
$srcEfi  = Join-Path $srcDir 'unlock_v3r.efi'
$outEfi  = Join-Path $outDir  'unlock_v3w_CMP70HX.efi'
$rollback= Join-Path $outDir  'unlock_v3n_CMP70HX.efi'
$gspRef  = Join-Path $outDir  'gsp_ga10x.bin'

# BUILDING.md §6.0. The rollback is the only way back; it must never change,
# and it has broken silently twice at identical file size, so md5 is the check.
$ROLLBACK_MD5    = '1863C4B1EBB8BF038A5C630001BB671A'
$ROLLBACK_SIZE   = 648192
$WORKING_MD5     = 'DEE0BAAB1B7C222399C091EAD15D071B'   # current tree, verified
$WORKING_SIZE    = 657408
$GSP_MD5         = 'EB9BEB5D062CCBF3295391C926A2D7AD'

# Strings that must survive into the binary. gfx/rmask are the graphics
# markers: without them this is the compute-only rollback and games run at 0.
$REQUIRED = @(
    @{ name = 'profile70'; text = 'CMP 70HX (GA104)'  },
    @{ name = 'probeG';    text = 'FBP-G  readback'   },
    @{ name = 'loghdr';    text = 'CMPUNLOG v1 '      },
    @{ name = 'gfx';       text = 'GFX_SPEED_SELECT'; critical = $true },
    @{ name = 'rmask';     text = 'G2RMS'            ; critical = $true }
)
# Strings that must NOT be there: the 90HX profile means the wrong target.
$FORBIDDEN = @(
    @{ name = 'profile90'; text = 'CMP 90HX (GA102)' }
)

$script:written = $false

function Say  ($m) { Write-Host $m -ForegroundColor Cyan }
function Good ($m) { Write-Host "  OK   $m" -ForegroundColor Green }
function Warn ($m) { Write-Host "  WARN $m" -ForegroundColor Yellow }
function Die  ($m, $code = 1) {
    Write-Host ""
    Write-Host "FAIL: $m" -ForegroundColor Red
    if ($script:written) {
        Write-Host "NOTE: the loader on the stick may now be inconsistent. Re-run," -ForegroundColor Red
        Write-Host "      or flash the rollback by hand: out\unlock_v3n_CMP70HX.efi" -ForegroundColor Red
        exit 2
    }
    Write-Host "      Nothing was written to the stick." -ForegroundColor DarkGray
    exit $code
}

function Get-MD5 ($path) { (Get-FileHash -LiteralPath $path -Algorithm MD5).Hash }

# Read the binary as both ASCII and UTF-16LE. Log literals are wide strings, so
# an ASCII-only scan reports a clean "nothing here" on a perfectly good binary —
# that trap has cost us time before.
function Get-BlobText ($path) {
    $b = [IO.File]::ReadAllBytes($path)
    $ascii = [Text.Encoding]::ASCII.GetString($b)
    $utf16 = [Text.Encoding]::Unicode.GetString($b)
    return @{ bytes = $b; text = $ascii + "`n" + $utf16 }
}

function Test-Blob ($path, $label) {
    $blob = Get-BlobText $path
    $b = $blob.bytes
    if ($b.Length -lt 2 -or $b[0] -ne 0x4D -or $b[1] -ne 0x5A) {
        Die "$label is not a PE image (no 'MZ' magic)."
    }
    $bad = @()
    foreach ($r in $REQUIRED) {
        if ($blob.text.Contains($r.text)) { Good ("$label marker {0,-9} PRESENT  ({1})" -f $r.name, $r.text) }
        else {
            $msg = "$label marker $($r.name) MISSING ($($r.text))"
            if ($r.critical) { Warn $msg; $bad += $msg } else { Warn $msg; $bad += $msg }
        }
    }
    foreach ($f in $FORBIDDEN) {
        if ($blob.text.Contains($f.text)) { $bad += "$label marker $($f.name) PRESENT - wrong card profile" }
        else { Good ("$label marker {0,-9} MISSING (correct)" -f $f.name) }
    }
    if ($bad.Count) {
        foreach ($m in $bad) { Write-Host "    - $m" -ForegroundColor Red }
        if ($label -notlike '*stick*') {
            Die ("the working build in out\ is missing required markers:" + [Environment]::NewLine +
                 "    " + ($bad -join [Environment]::NewLine + "    "))
        }
        Die ("the file ON THE STICK is not the working build. Most likely the" + [Environment]::NewLine +
             "    rollback was flashed, or the copy failed." + [Environment]::NewLine +
             "    Graphics would be OFF. Working build = $WORKING_MD5")
    }
}

try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }

# ---------------------------------------------------------------- detect stick
if (-not $Stick) {
    $cand = Get-Volume | Where-Object { $_.DriveLetter -and $_.DriveLetter -ne 'C' -and
                                         $_.DriveType -eq 'Removable' } |
           Select-Object -ExpandProperty DriveLetter
    if (-not $cand -or @($cand).Count -ne 1) {
        Write-Host "Could not identify exactly one removable volume." -ForegroundColor Yellow
        Write-Host "Pass the drive letter explicitly: -Stick X:" -ForegroundColor Yellow
        exit 1
    }
    $Stick = (@($cand)[0]) + ':'
}
$Stick = $Stick.TrimEnd(':', [char]':') + ':'
$target = "$Stick\EFI\BOOT\BOOTX64.EFI"

if (-not (Test-Path "${Stick}\")) { Die "stick $Stick not found." }

Write-Host ""
Say "=== CMP unlock: build -> flash -> verify ==="
Say "    stick:  $Stick"
Say "    target: $target"
Write-Host ""

# ------------------------------------------------------------ 1. reference copy
Say "[1/5] refreshing the flash reference in out\ ..."
if (-not (Test-Path $srcEfi)) {
    Die "working build not found: $srcEfi  (build it first: WSL, src/build.sh)"
}
Copy-Item -LiteralPath $srcEfi -Destination $outEfi -Force

$srcMd5  = Get-MD5 $srcEfi
$outMd5  = Get-MD5 $outEfi
$outSize = (Get-Item $outEfi).Length
if ($srcMd5 -ne $outMd5) { Die "out\ reference md5 does not match src\ after copy." }
Good "src\unlock_v3r.efi  = $srcMd5  ($outSize bytes)"

# Verify the reference BEFORE touching the stick. Checking after the write
# leaves a compute-only loader on the stick and then reports failure, which is
# strictly worse than not writing at all. The gfx/rmask markers are what
# distinguish the working build from the rollback, and they are cheap to read.
Test-Blob $outEfi 'out\'

if ($outMd5 -eq $WORKING_MD5) {
    Good "matches the build verified on hardware (2026-09-30)."
} else {
    Warn "differs from $WORKING_MD5."
    Warn "Expected if you changed the code; verify the change is intended."
}

# ---------------------------------------------------------- 2. rollback safety
Say ""
Say "[2/5] rollback integrity (the only way back) ..."
if (-not (Test-Path $rollback)) { Die "rollback reference missing: $rollback" }
$rbMd5  = Get-MD5 $rollback
$rbSize = (Get-Item $rollback).Length
if ($rbMd5 -ne $ROLLBACK_MD5) {
    Write-Host ""
    Write-Host "  ROLLBACK HAS CHANGED" -ForegroundColor Red
    Write-Host "    expected $ROLLBACK_MD5  $ROLLBACK_SIZE bytes" -ForegroundColor Red
    Write-Host "    actual   $rbMd5  $rbSize bytes" -ForegroundColor Red
    Write-Host "    A helper function or a log string added outside #ifdef lands in" -ForegroundColor Red
    Write-Host "    EVERY build. See BUILDING.md §6.0." -ForegroundColor Red
    Die "refusing to flash while the rollback is not the known-good image."
}
Good "unlock_v3n (rollback) = $rbMd5  ($rbSize bytes)  unchanged"

# ------------------------------------------------------------------- 3. GSP
if (-not $SkipGspCheck) {
    Say ""
    Say "[3/5] GSP firmware on the stick must be untouched ..."
    $gspOnStick = "$Stick\gsp_ga10x.bin"
    if (-not (Test-Path $gspOnStick)) {
        Warn "no gsp_ga10x.bin on $Stick - the app may not find its firmware."
    } else {
        $g1 = Get-MD5 $gspRef
        $g2 = Get-MD5 $gspOnStick
        if ($g1 -ne $g2) {
            Die ("GSP MISMATCH:`n    out\  $g1`n    stick $g2`n" +
                 "    The GSP blob is NOT ours to modify. Restore it from the" + [Environment]::NewLine +
                 "    610.43.03 package before flashing.")
        }
        if ($g2 -ne $GSP_MD5) { Warn "GSP md5 $g2 differs from the expected $GSP_MD5." }
        else { Good "gsp_ga10x.bin = $g2  matches reference" }
    }
} else {
    Say ""
    Warn "[3/5] GSP check SKIPPED (-SkipGspCheck)."
}

# -------------------------------------------------------------- 4. write loader
Say ""
Say "[4/5] writing the loader ..."
$dir = Split-Path -Parent $target
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

# Order matters: remove first, then copy. A host reboot in the middle of an
# overwrite leaves a corrupt FAT and the firmware silently skips the disk.
if (Test-Path $target) {
    $before = Get-MD5 $target
    Remove-Item -LiteralPath $target -Force
    Good "removed previous loader (was $before)"
}
Copy-Item -LiteralPath $outEfi -Destination $target -Force
$script:written = $true
Good "wrote $(Split-Path $outEfi -Leaf) -> $target"

# ------------------------------------------------------- 5. verify the stick
Say ""
Say "[5/5] verifying what is actually on the stick ..."
$stickMd5 = Get-MD5 $target
if ($stickMd5 -ne $outMd5) {
    Die ("stick md5 does not match what we wrote.`n    wrote  $outMd5`n    stick  $stickMd5")
}
Good "md5 matches out\ reference"
Test-Blob $target 'stick'

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Green
Write-Host " FLASHED AND VERIFIED" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Green
Write-Host "  loader   $WORKING_MD5"
Write-Host "  out\     $outMd5  ($outSize bytes)"
Write-Host "  stick    $stickMd5"
Write-Host "  rollback $rbMd5  (unchanged, flash this to go back)"
Write-Host ""
Write-Host "  Remaining steps are the human's:" -ForegroundColor Yellow
Write-Host "    1. reboot and select the stick from the boot menu (F12)"
Write-Host "    2. wait for the end marker, do not interrupt"
Write-Host "    3. out\pull-log.ps1 -Tag <name>"
Write-Host ""
Write-Host "  The change is NOT tested until that log comes back and shows" -ForegroundColor Yellow
Write-Host "  'G2GFX ... GFX_SPEED_SELECT=0x00000004 ***ВСТАЛ***'." -ForegroundColor Yellow
exit 0