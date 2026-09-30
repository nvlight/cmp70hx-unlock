<#
    flash-build.ps1 — one command for the whole "build -> flash -> verify" cycle.

    Usage:
        powershell -ExecutionPolicy Bypass -File out\flash-build.ps1
        powershell -ExecutionPolicy Bypass -File out\flash-build.ps1 -Stick X:
        powershell -ExecutionPolicy Bypass -File out\flash-build.ps1 -AllowNewBuild

    There is ONE binary. unlock_v3r.efi is both what you flash and the rollback;
    the compute-only build that used to sit next to it was retired 2026-10-01
    after the flash instructions were followed literally and put the card back to
    zero in games while compute kept working.

    The rollback is therefore not a stored file but a REBUILD: the binary must
    reproduce md5 DEE0BAAB… from the sources at git tag rollback-2026-10-01.
    Step 2 is that check, and it refuses to flash if it fails.

        git checkout rollback-2026-10-01 && bash build.sh   ->   DEE0BAAB…

    If you deliberately changed the code, pass -AllowNewBuild. That is the point
    at which you accept that the old rollback is gone and owe two things: re-tag
    after the change is tested, and run the card.

    Steps, stopping at the first failure:
        1. copy src\ -> out\ as the flash reference, then check its md5 and its
           marker strings BEFORE anything is written
        2. the rebuild must still reproduce the reference md5 (the rollback)
        3. the GSP firmware blob on the stick must be untouched
        4. write the loader to <Stick>:\EFI\BOOT\BOOTX64.EFI (remove-then-copy)
        5. verify by md5 AND by strings INSIDE the file on the stick

    What it will NOT do (see BUILDING.md §6.3): reboot, press F12, or write a
    whole-disk image. Those belong to the human. After it finishes, report the
    md5s and stop — the change is not tested until a log comes back.

    Exit codes: 0 ok, 1 refused before writing, 2 written but verification failed
    afterwards (treat the stick as suspect).
#>
[CmdletBinding()]
param(
    # Drive letter of the boot stick. Detected when omitted.
    [string]$Stick = '',

    # Skip the GSP md5 check. Only for the rare case the stick legitimately
    # carries a different GSP build; say so in the commit message if used.
    [switch]$SkipGspCheck,

    # Acknowledge that the tree intentionally no longer builds the reference
    # md5. This retires the previous rollback — see the header before using it.
    [switch]$AllowNewBuild
)

$ErrorActionPreference = 'Stop'

$root   = Split-Path -Parent $PSScriptRoot
$outDir = $PSScriptRoot              # this script lives in out\
$srcDir = Join-Path $root 'src'

$srcEfi = Join-Path $srcDir 'unlock_v3r.efi'
$outEfi = Join-Path $outDir 'unlock_v3r_CMP70HX.efi'
$gspRef = Join-Path $outDir 'gsp_ga10x.bin'

# The single reference. Verified on hardware twice: 2026-09-30 and again after a
# reboot run on 2026-10-01 (G2GFX ... GFX_SPEED_SELECT=0x00000004 ***ВСТАЛ***).
# Pinned by the git tag below. A rebuild that stops matching this md5 means a
# string or a helper leaked in outside an #ifdef — BUILDING.md §6.0.
$REF_MD5       = 'DEE0BAAB1B7C222399C091EAD15D071B'
$REF_SIZE      = 657408
$ROLLBACK_TAG  = 'rollback-2026-10-01'
$GSP_MD5       = 'EB9BEB5D062CCBF3295391C926A2D7AD'

# Strings that must survive into the binary. gfx/rmask are the graphics markers:
# a build without -DRENDER_MASKS still boots and still unlocks compute, so it
# looks healthy while running games at zero. That is what these catch.
$REQUIRED = @(
    @{ name = 'profile70'; text = 'CMP 70HX (GA104)'  },
    @{ name = 'probeG';    text = 'FBP-G  readback'   },
    @{ name = 'loghdr';    text = 'CMPUNLOG v1 '      },
    @{ name = 'gfx';       text = 'GFX_SPEED_SELECT' },
    @{ name = 'rmask';     text = 'G2RMS'            }
)
# Strings that must NOT be there: the 90HX profile means the wrong card. The port
# is 70HX-only as of 2026-10-01.
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
        Write-Host "NOTE: the loader on the stick may now be inconsistent. Re-run this" -ForegroundColor Red
        Write-Host "      script, or check out $ROLLBACK_TAG and rebuild from there." -ForegroundColor Red
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
        if ($blob.text.Contains($r.text)) {
            Good ("$label marker {0,-9} PRESENT  ({1})" -f $r.name, $r.text)
        } else {
            $msg = "$label marker $($r.name) MISSING ($($r.text))"
            Warn $msg
            $bad += $msg
        }
    }
    foreach ($f in $FORBIDDEN) {
        if ($blob.text.Contains($f.text)) {
            $bad += "$label marker $($f.name) PRESENT - this is the wrong card profile"
        } else {
            Good ("$label marker {0,-9} MISSING (correct)" -f $f.name)
        }
    }
    if ($bad.Count) {
        foreach ($m in $bad) { Write-Host "    - $m" -ForegroundColor Red }
        if ($label -like '*stick*') {
            Die ("the file ON THE STICK is not the reference build. Most likely an" + [Environment]::NewLine +
                 "    old or partially written loader. Reference md5 is $REF_MD5" + [Environment]::NewLine +
                 "    Graphics would be OFF if this is a compute-only binary.")
        }
        Die ("the reference in out\ is missing required markers:" + [Environment]::NewLine +
             "    " + ($bad -join [Environment]::NewLine + "    "))
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
    Die "build not found: $srcEfi  (build it: WSL, cd src && BLOBS=`$PWD/blobs bash build.sh)"
}
Copy-Item -LiteralPath $srcEfi -Destination $outEfi -Force

$srcMd5  = Get-MD5 $srcEfi
$outMd5  = Get-MD5 $outEfi
$outSize = (Get-Item $outEfi).Length
if ($srcMd5 -ne $outMd5) { Die "out\ reference md5 does not match src\ after copy." }
Good "src\unlock_v3r.efi  = $srcMd5  ($outSize bytes)"

# Check the markers BEFORE touching the stick. Verifying after the write leaves a
# bad loader on the stick and then reports failure, which is strictly worse than
# not writing at all.
Test-Blob $outEfi 'out\'

# ------------------------------------------------------------ 2. rollback check
Say ""
Say "[2/5] rollback: the rebuild must reproduce the reference md5 ..."
if ($outMd5 -eq $REF_MD5) {
    Good "matches $REF_MD5, verified on hardware twice"
    Good "rollback anchor: git tag $ROLLBACK_TAG"
} elseif ($AllowNewBuild) {
    Write-Host ""
    Write-Host "  REFERENCE MD5 CHANGED - acknowledged via -AllowNewBuild" -ForegroundColor Yellow
    Write-Host "    was $REF_MD5  $REF_SIZE bytes" -ForegroundColor Yellow
    Write-Host "    now $outMd5  $outSize bytes" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  The rollback this md5 backed is now retired. Before you rely on it:" -ForegroundColor Yellow
    Write-Host "    1. flash it, reboot, pull the log, and confirm it is good" -ForegroundColor Yellow
    Write-Host "    2. re-tag the tested commit and update REF_MD5 in this script" -ForegroundColor Yellow
    Write-Host "       git tag -a rollback-YYYY-MM-DD -m '...'" -ForegroundColor Yellow
} else {
    Write-Host ""
    Write-Host "  REFERENCE MD5 CHANGED" -ForegroundColor Red
    Write-Host "    expected $REF_MD5  $REF_SIZE bytes" -ForegroundColor Red
    Write-Host "    actual   $outMd5  $outSize bytes" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Two very different causes, and they must not be confused:" -ForegroundColor Red
    Write-Host "    - you changed the code on purpose" -ForegroundColor Red
    Write-Host "      -> re-run with -AllowNewBuild, then flash and re-tag after testing" -ForegroundColor Red
    Write-Host "    - you did NOT change any code, or only a comment" -ForegroundColor Red
    Write-Host "      -> a string or a helper landed outside an #ifdef and now reaches" -ForegroundColor Red
    Write-Host "         every build. That is what broke the old rollback twice." -ForegroundColor Red
    Write-Host "         See BUILDING.md §6.0." -ForegroundColor Red
    Die "refusing to flash a binary that is not the known-good one."
}

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
Write-Host "  loader   $stickMd5  ($outSize bytes)"
Write-Host "  out\     $outMd5"
if ($outMd5 -eq $REF_MD5) {
    Write-Host "  rollback same file; anchor is git tag $ROLLBACK_TAG" -ForegroundColor Green
} else {
    Write-Host "  rollback RETIRED - retag after this build is tested" -ForegroundColor Yellow
}
Write-Host ""
Write-Host "  Remaining steps are the human's:" -ForegroundColor Yellow
Write-Host "    1. reboot and select the stick from the boot menu (F12)" -ForegroundColor Yellow
Write-Host "    2. wait for the end marker, do not interrupt" -ForegroundColor Yellow
Write-Host "    3. out\pull-log.ps1 -Tag <name>" -ForegroundColor Yellow
Write-Host ""
Write-Host "  The change is NOT tested until that log comes back and shows" -ForegroundColor Yellow
Write-Host "  'G2GFX ... GFX_SPEED_SELECT=0x00000004 ***ВСТАЛ***'." -ForegroundColor Yellow
exit 0