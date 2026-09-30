<#
    make-usb-stick.ps1 — rebuilds the CMP 70HX boot stick from scratch.

    Replaces the hand-rolled FAT32 images: this lets WINDOWS make the
    filesystem, which is why the earlier ones were not recognised (a
    hand-written BPB claiming 255 MB on a 15 GB device is malformed).

    Usage (PowerShell as Administrator):
        .\make-usb-stick.ps1
        .\make-usb-stick.ps1 -DiskNumber 2

    It will refuse to touch any disk that is flagged system/boot.
#>
param(
    [int]$DiskNumber = -1,
    [string]$ExpectedModel = 'Kingston'
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
# РАБОЧАЯ СБОРКА (compute + графика, 50 fps). Имя файла не связано с содержимым,
# но исторически unlock_v3n_CMP70HX.efi в out/ — это ОТКАТ (compute-only),
# и его использование здесь выключало бы 3D на свежесозданной флешке.
$efi  = Join-Path $here 'unlock_v3w_CMP70HX.efi'
$fw   = Join-Path $here 'gsp_ga10x.bin'

foreach ($f in @($efi, $fw)) {
    if (-not (Test-Path $f)) { throw "missing payload: $f" }
}

# The stick must carry the graphics build: without these two strings in the
# binary, the EFI app is a compute-only rollback and games run at zero.
$need = @{ 'CMP 70HX (GA104)' = 'profile70'; 'GFX_SPEED_SELECT' = 'gfx (render selector)' }
$blob = [IO.File]::ReadAllBytes($efi)
if ($blob[0] -ne 0x4D -or $blob[1] -ne 0x5A) { throw "not a PE image: $efi" }
$ascii = [Text.Encoding]::ASCII.GetString($blob)
$utf16 = [Text.Encoding]::Unicode.GetString($blob)
foreach ($k in $need.Keys) {
    if ($ascii -notmatch [regex]::Escape($k) -and $utf16 -notmatch [regex]::Escape($k)) {
        throw ("ABORT: marker '{0}' ({1}) MISSING in {2} — this is not the working" -f $k, $need[$k], (Split-Path $efi -Leaf)) +
               " graphics build. Refusing to write a compute-only rollback onto a fresh stick."
    }
}

# ---- pick the stick --------------------------------------------------------
if ($DiskNumber -lt 0) {
    $cand = Get-Disk | Where-Object {
        $_.BusType -eq 'USB' -and -not $_.IsBoot -and -not $_.IsSystem
    }
    if ($cand.Count -ne 1) {
        Write-Host "Found $($cand.Count) candidate USB disks:" -ForegroundColor Yellow
        Get-Disk | Format-Table Number, FriendlyName, BusType, Size, IsBoot, IsSystem -AutoSize
        throw "Pass -DiskNumber explicitly."
    }
    $DiskNumber = $cand.Number
}
$stick = Get-Disk -Number $DiskNumber

# ---- refuse to touch a system disk ----------------------------------------
if ($stick.IsBoot -or $stick.IsSystem) {
    throw "ABORT: Disk $DiskNumber is the system/boot disk."
}
if ($stick.BusType -ne 'USB') {
    throw "ABORT: Disk $DiskNumber is $($stick.BusType), not USB."
}
if ($stick.IsReadOnly) { throw "ABORT: target is read-only." }
if ($stick.FriendlyModel -notlike "*$ExpectedModel*" -and
    $stick.FriendlyName -notlike "*$ExpectedModel*") {
    Write-Host "WARNING: '$($stick.FriendlyName)' does not match '$ExpectedModel'." -ForegroundColor Yellow
    if (-not (Read-Host "Type YES to continue") -eq 'YES') { throw "aborted by user" }
}
$stick | Format-List Number, FriendlyName, Size, BusType | Out-String | Write-Host

# ---- 1. clear --------------------------------------------------------------
Write-Host "[1/5] clearing partition table..." -ForegroundColor Cyan
Clear-Disk -Number $DiskNumber -RemoveData -Confirm:$false
Update-HostStorageCache

# ---- 2. one primary partition --------------------------------------------
# DiskPart puts it at 1 MiB (LBA 2048) by default, which is exactly what we
# need: the FAT boot sector must never land on LBA 0, or it overwrites the MBR.
# (An offset of 0 is what produced the earlier "FAT16, no drive letter" mess.)
Write-Host "[2/5] creating the primary partition (starts at 1 MiB)..." -ForegroundColor Cyan
$dpFile = Join-Path $env:TEMP "cmp70_diskpart.txt"
@"
select disk $DiskNumber
clean
create partition primary
"@ | Set-Content -Path $dpFile -Encoding ASCII
diskpart /s $dpFile | Out-Null

$part = Get-Partition -DiskNumber $DiskNumber
if ($part.Offset -lt 1048576) {
    throw "ABORT: partition starts at $($part.Offset) - it would overwrite the MBR."
}
Write-Host "      offset=$($part.Offset) size=$($part.Size)" -ForegroundColor DarkGray

# ---- 3. FAT32 by Windows --------------------------------------------------
Write-Host "[3/5] formatting FAT32 with Windows' own formatter..." -ForegroundColor Cyan
$vol = $part | Format-Volume -FileSystem FAT32 -NewFileSystemLabel 'CMP70UNLOCK' -Force -Confirm:$false
Start-Sleep -Seconds 3
$vol = Get-Volume -DriveLetter $vol.DriveLetter
if ($vol.FileSystem -ne 'FAT32') { throw "format did not produce FAT32" }
Write-Host "      $($vol.DriveLetter): FAT32 $($vol.Size) bytes" -ForegroundColor DarkGray

# ---- 4. UEFI needs partition type 0xEF ----------------------------------
# Windows writes 0x0C. Rufus/Etcher flip this one byte; the UEFI spec calls
# 0xEF an EFI System Partition and some firmware refuses to enumerate
# anything else on removable media.
Write-Host "[4/5] setting the MBR partition type to 0xEF + boot flag..." -ForegroundColor Cyan
$fs = [System.IO.File]::Open("\\.\PhysicalDrive$DiskNumber", 'Open', 'ReadWrite', 'ReadWrite')
try {
    $buf = New-Object byte[] 512
    $fs.Seek(0, 'Begin') | Out-Null
    $fs.Read($buf, 0, 512) | Out-Null
    $buf[446] = 0x80            # active / bootable
    $buf[450] = 0xEF            # EFI System Partition
    $fs.Seek(0, 'Begin') | Out-Null
    $fs.Write($buf, 0, 512)
    $fs.Flush()
} finally { $fs.Close() }
Update-HostStorageCache

# ---- 5. copy the payload -------------------------------------------------
Write-Host "[5/5] copying the payload..." -ForegroundColor Cyan
$root = "$($vol.DriveLetter):\"
New-Item -ItemType Directory -Path "$root\EFI\BOOT" -Force | Out-Null
Copy-Item $fw  "$root\gsp_ga10x.bin"        -Force
Copy-Item $efi "$root\EFI\BOOT\BOOTX64.EFI" -Force

# ---- verify ---------------------------------------------------------------
$ok = $true
foreach ($pair in @(@("$root\EFI\BOOT\BOOTX64.EFI", $efi), @("$root\gsp_ga10x.bin", $fw))) {
    $a = (Get-FileHash $pair[0] -Algorithm MD5).Hash
    $b = (Get-FileHash $pair[1] -Algorithm MD5).Hash
    Write-Host ("      {0,-24} md5 {1} {2}" -f (Split-Path $pair[0] -Leaf), $a, $(if ($a -eq $b) { 'OK' } else { { $ok = $false; 'MISMATCH' } }))
}
if (-not $ok) { throw "verification failed" }
Write-Host "`nReady. Boot it from the firmware boot menu (F12 / F8 / Del)." -ForegroundColor Green
