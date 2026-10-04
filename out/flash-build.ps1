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

# The single reference: the fingerprint of the source state we LAST proved on
# metal. A rebuild that stops matching it means a string or a helper leaked in
# outside an #ifdef — BUILDING.md §6.0.
#
# WAS 'DEE0BAAB...' / 657408 - that is tag rollback-2026-10-01, i.e. v3.15. Every
# build since v3.16 has differed from it, so this check has been refusing
# anything unless -AllowNewBuild was passed, which quietly trains the reader to
# pass that flag on reflex and defeats the check. Same bug the build.sh banner
# had. Now it points at the current verified state instead.
#
# 2abf59a8... = v3.40, 2 render masks (0x823800, 0x823B04), the current release.
# Two runs on metal: 8 470 ms (out/usb-log-1004-021327.txt) and 8 451 ms
# (out/usb-log-1004-110443.txt). Markers in both: 'GFX_SPEED_SELECT=0x00000004 SET',
# 'G2RMS ... GFX gates open 2 of 2', 'END' present, verify-log.ps1 PASS.
# Pinned by commit 100f03b. The previous reference 67f7b5a8 (v3.39, 8 masks) is
# what 'git revert 100f03b' brings back.
$REF_MD5       = '2ABF59A0D147B9D5744CFBEC5D58EC65'
$REF_SIZE      = 671744
$ROLLBACK_TAG  = 'rollback-2026-10-04'   # v3.40; 'rollback-2026-10-01' is the older v3.15 image
$GSP_MD5       = 'EB9BEB5D062CCBF3295391C926A2D7AD'

# Strings that must survive into the binary. gfx/rmask are the graphics markers:
# a build without -DRENDER_MASKS still boots and still unlocks compute, so it
# looks healthy while running games at zero. That is what these catch.
$REQUIRED = @(
    @{ name = 'profile70'; text = 'CMP 70HX (GA104)'  },
    # v3.18: было 'FBP-G  readback' - строка внутри fb_access_probe, которая
    # ушла за флаг FX_DIAG_FBPROBE (=0): она стоила ИЗМЕРЕННЫЕ 4,40 с из
    # 57,3 с, то есть 7,7 % прогона, и печатала собственный отрицательный
    # результат (frts-NOT-reachable-via-dma). Теперь обязана присутствовать
    # строка ОТКАЗА, а не отчёт о выполнении: пропуск обязан быть виден в
    # логе (BUILDING 6.0). Проверка не ослаблена - она перенаправлена на
    # строку, которая теперь обязана быть в бинаре.
    @{ name = 'fbpskip';   text = 'FBP    SKIPPED'    },
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
Write-Host "  'G2GFX ... GFX_SPEED_SELECT=0x00000004 SET'." -ForegroundColor Yellow
if ($outMd5 -ne $REF_MD5) {
    Write-Host ""
    Write-Host "  This build differs from the reference md5. Check these lines in the log" -ForegroundColor Yellow
    Write-Host "  (PLAN-SPEED.md has the budget and why each step exists):" -ForegroundColor Yellow
    Write-Host "    1. 'G2RMS ... TOTAL: GFX gates open 2 of 2'     <- unlocks alive" -ForegroundColor Yellow
    Write-Host "    2. 'G2GFX ... GFX_SPEED_SELECT=0x00000004 SET' <- main marker" -ForegroundColor Yellow
    Write-Host "    3. 'END   ss0=0x88888888 ss1=0x00000008 PLM=0xFFFFFFFF'" -ForegroundColor Yellow
    Write-Host "    4. no 'dbg=0x007E0009' anywhere" -ForegroundColor Yellow
    Write-Host "    5. 'render: FLR settle' must be ~500 ms per render iteration, and the" -ForegroundColor Yellow
    Write-Host "       number of iterations must equal the mask count. NOT 15 s - that" -ForegroundColor Yellow
    Write-Host "       means a mark was lost (the delta swallowed the next section)," -ForegroundColor Yellow
    Write-Host "       which is what the old CHECK used to hide." -ForegroundColor Yellow
    Write-Host "    6. 'TIME  t=NNNms' marks - duration of ONE section = delta of two" -ForegroundColor Yellow
    Write-Host "       adjacent marks. The MK SUM may exceed elapsed (marks nest) -" -ForegroundColor Yellow
    Write-Host "       do not read it as a total." -ForegroundColor Yellow
    Write-Host "    7. STAGE 22: line 7520 - the second hot scrub-stall site." -ForegroundColor Yellow
    Write-Host "" -ForegroundColor Cyan
    Write-Host "       One line changed (src/unlock_v2.c:7403). The three inside early_unlock_path" -ForegroundColor Cyan
    Write-Host "       v3.38. This one sits right AFTER the doomed post-WPR2 sec2 ready wait." -ForegroundColor Cyan
    Write-Host "         6689 [E1]  v3.35 PASS, 40.0 ms/call" -ForegroundColor Cyan
    Write-Host "         6772 [E3]  v3.36 PASS, 40.0 ms/call, prediction off by 1 ms" -ForegroundColor Cyan
    Write-Host "         7520       THIS RUN - after rr: post-WPR2 sec2 ready" -ForegroundColor Cyan
    Write-Host "" -ForegroundColor Cyan
    Write-Host "         9 calls x 40 ms = 360 ms" -ForegroundColor Cyan
    Write-Host "         15 303 - 320 = 14 983 ms   -> expect ~15.0 s" -ForegroundColor Cyan
    Write-Host "" -ForegroundColor Cyan
    Write-Host "       NEW FINDING, and it corrects something I said. The pattern" -ForegroundColor Cyan
    Write-Host "         falcon_wait_scrub_done(...)  followed by  Stall(50000)" -ForegroundColor Cyan
    Write-Host "       is a project IDIOM, not a one-off. There are 12 scrub sites and at" -ForegroundColor Cyan
    Write-Host "       least 8 of them still carry a 50 ms stall:" -ForegroundColor Cyan
    Write-Host "         3593 pre-reset | 3818 fbp-reset | 5247 gsp-reset | 6242 sec2-reset" -ForegroundColor Cyan
    Write-Host "         6942 gsp-reset | 7402 gsp-reset | 7489 sec2-reset | 7707 sec2-reset" -ForegroundColor Cyan
    Write-Host "       Attribution was obtained FREE from the log itself: repeated SCRUB tags are" -ForegroundColor Cyan
    Write-Host "       split by the line that follows them. gsp-reset -> DMAQ x9 is 6689 (cut);" -ForegroundColor Cyan
    Write-Host "       gsp-reset -> FWSEC reflashed x9 is THIS site; sec2-reset -> TIME x8 is 7490." -ForegroundColor Cyan
    Write-Host "       sites are hot. NEXT STAGE is to count calls per site BEFORE touching" -ForegroundColor Cyan
    Write-Host "       anything - the tags repeat, so the log cannot attribute them." -ForegroundColor Cyan
    Write-Host "       Batching was measured impossible in v3.34, so 14 s is off the table." -ForegroundColor Yellow
    Write-Host "  ==== AFTER REBOOT, MANDATORY - NOT OPTIONAL ====" -ForegroundColor Cyan
    Write-Host "  1. powershell -ExecutionPolicy Bypass -File out\pull-log.ps1" -ForegroundColor Cyan
    Write-Host "  2. powershell -ExecutionPolicy Bypass -File out\verify-log.ps1 out\usb-log-XXXX.txt" -ForegroundColor Cyan
    Write-Host "  3. powershell -ExecutionPolicy Bypass -File out\cmp-marks.ps1 -A out\usb-log-v338.txt -B out\usb-log-XXXX.txt" -ForegroundColor Cyan
    Write-Host "  Only a PASS from verify-log.ps1 allows 'VERIFIED' in out\BUILDS.md." -ForegroundColor Cyan
    Write-Host "  Baseline: out\usb-log-v339.txt (15.96 s, 8 of 8, md5 67f7b5a8 - last 8-mask build)." -ForegroundColor Cyan
}
exit 0
