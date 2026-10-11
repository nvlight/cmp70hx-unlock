# SPDX-License-Identifier: GPL-2.0-only
<#
.SYNOPSIS
    Fail-closed audit of nvlddmkm.sys 616.92 before an experimental GR patch.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File out\gr-driver-audit.ps1 `
        -DriverPath C:\path\to\nvlddmkm.sys
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $DriverPath,
    [switch] $Json
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'gr-driver-common.ps1')

try {
    $audit = Get-GrDriverAudit $DriverPath
    if ($Json) {
        $audit | ConvertTo-Json -Depth 6
    } else {
        "file            : $($audit.Path)"
        "version         : $($audit.FileVersion)"
        "size            : $($audit.Size)"
        "SHA-256         : $($audit.Sha256)"
        "profile         : $(if ($audit.Profile) { $audit.Profile } else { 'UNKNOWN' })"
        "observed variant: $($audit.ObservedVariant)"
        "GSP (runtime)   : $($audit.RuntimeGsp)"
        "PE/.text        : $($audit.PeMachine), RVA $($audit.TextRva), raw $($audit.TextRawOffset)"
        ''
        foreach ($s in $audit.Sites) {
            ('{0,-16} {1,-8} file={2,-10} RVA={3,-10} sig={4}' -f
                $s.Key, $s.State, $s.FileOffset, $s.Rva,
                $(if ($s.SignatureUnique) { 'unique/ok' } else { "count=$($s.SignatureCount)" }))
        }
        ''
        "PATCHABLE       : $($audit.Patchable)"
        if (-not $audit.HashApproved) { 'FAIL: hash/size/version are not in the allowlist.' }
        if (-not $audit.AllSitesStock) { 'FAIL: one or more sites are not in stock state.' }
        if (-not $audit.AllSignaturesSafe) { 'FAIL: a semantic signature is ambiguous or missing.' }
    }
    if (-not $audit.Patchable) { exit 2 }
} catch {
    Write-Error $_.Exception.Message -ErrorAction Continue
    exit 2
}
