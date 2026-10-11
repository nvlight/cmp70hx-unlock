# SPDX-License-Identifier: GPL-2.0-only
<#
.SYNOPSIS
    Create a new experimentally patched copy of nvlddmkm.sys 616.92.

.DESCRIPTION
    Never writes over the input file. Accepts only an allowlisted hash, exact
    version, unique signatures, and stock bytes. Writes a JSON manifest next
    to the output. There is intentionally no Force mode.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File out\gr-driver-patch.ps1 `
        -DriverPath C:\clean\nvlddmkm.sys -Variant Property `
        -OutputDir C:\staging\R1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $DriverPath,
    [Parameter(Mandatory = $true)]
    [ValidateSet('Property', 'Predicates', 'Full')]
    [string] $Variant,
    [Parameter(Mandatory = $true)]
    [string] $OutputDir
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'gr-driver-common.ps1')

function Set-Site([byte[]] $Data, [string] $Key) {
    $site = $script:GrPatchSites[$Key]
    $before = Convert-HexToBytes $site.Before
    $after = Convert-HexToBytes $site.After
    $actual = Get-BytesAt $Data $site.FileOffset $before.Length
    if ((Convert-BytesToHex $actual) -ne $site.Before) {
        throw "${Key}: stock bytes do not match; patching stopped."
    }
    [Array]::Copy($after, 0, $Data, $site.FileOffset, $after.Length)
    return [pscustomobject]@{
        key         = $Key
        purpose     = $site.Name
        file_offset = ('0x{0:X}' -f $site.FileOffset)
        rva         = ('0x{0:X}' -f $site.Rva)
        before      = $site.Before
        after       = $site.After
    }
}

try {
    $audit = Get-GrDriverAudit $DriverPath
    if (-not $audit.Patchable) {
        throw ('Input failed the fail-closed audit: profile={0}, hashApproved={1}, stock={2}, signatures={3}.' -f
            $audit.Profile, $audit.HashApproved, $audit.AllSitesStock, $audit.AllSignaturesSafe)
    }
    $src = $audit.Path
    $outDirResolved = [IO.Path]::GetFullPath($OutputDir)
    [IO.Directory]::CreateDirectory($outDirResolved) | Out-Null
    $suffix = $Variant.ToLowerInvariant()
    $dst = Join-Path $outDirResolved "nvlddmkm-gr-$suffix.sys"
    $manifestPath = Join-Path $outDirResolved "nvlddmkm-gr-$suffix.json"
    if ([IO.Path]::GetFullPath($src) -eq [IO.Path]::GetFullPath($dst)) {
        throw 'Output path equals input path; in-place writes are forbidden.'
    }
    if ((Test-Path -LiteralPath $dst) -or (Test-Path -LiteralPath $manifestPath)) {
        throw "Output already exists: $dst or $manifestPath. Move or remove it explicitly."
    }

    $data = [IO.File]::ReadAllBytes($src)
    $changes = @()
    if ($Variant -in @('Property', 'Full')) {
        $changes += Set-Site $data 'PropertyEntry'
        $changes += Set-Site $data 'PropertyCave'
    }
    if ($Variant -in @('Predicates', 'Full')) {
        $changes += Set-Site $data 'GrPath'
        $changes += Set-Site $data 'GrPresent'
    }

    [IO.File]::WriteAllBytes($dst, $data)
    $newSha = Get-GrSha256 $dst
    foreach ($change in $changes) {
        $site = $script:GrPatchSites[$change.key]
        $actual = Convert-BytesToHex (Get-BytesAt $data $site.FileOffset ((Convert-HexToBytes $site.After).Length))
        if ($actual -ne $site.After) { throw "Output verification failed: $($change.key)." }
    }

    $manifest = [ordered]@{
        schema             = 1
        created_utc        = (Get-Date).ToUniversalTime().ToString('o')
        tool               = 'out/gr-driver-patch.ps1'
        variant            = $Variant
        source_path        = $src
        source_profile     = $audit.Profile
        driver_version     = $audit.FileVersion
        runtime_gsp        = $audit.RuntimeGsp
        source_size        = $audit.Size
        source_sha256      = $audit.Sha256
        output_path        = $dst
        output_size        = (Get-Item -LiteralPath $dst).Length
        output_sha256      = $newSha
        signature_note     = 'Byte patch invalidates the original signature; package/sign only through the external NVIDIA-patcher workflow.'
        changes            = $changes
    }
    $manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

    "CREATED (not installed): $dst"
    "source SHA-256        : $($audit.Sha256)"
    "output SHA-256        : $newSha"
    "variant               : $Variant"
    "manifest              : $manifestPath"
    'The original PE signature is now invalid. Use the external packaging/signing workflow; this script installs nothing.'
} catch {
    Write-Error $_.Exception.Message -ErrorAction Continue
    exit 2
}
