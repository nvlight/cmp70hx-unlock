# SPDX-License-Identifier: GPL-2.0-only

$script:GrDriverProfiles = @(
    [pscustomobject]@{
        Name    = '616.92-clean'
        Sha256  = '85753A7DDBC8D44C1ECC370BF62B5C68C05022A6D7192034186C0BA93C316BA2'
        Size    = 113949416L
        Version = '32.0.16.1692'
    },
    [pscustomobject]@{
        Name    = '616.92-nvidia-patcher'
        Sha256  = '1F0D932DCE22CE14AB1ED22B7A1F28B616A654783688BEC57D52D8CA83DE7DC2'
        Size    = 113939360L
        Version = '32.0.16.1692'
    }
)

$script:GrPatchSites = [ordered]@{
    PropertyEntry = [pscustomobject]@{
        Name       = 'property-initializer entry (_nv029797rm analogue)'
        FileOffset = 0x5A9A10L
        Rva        = 0x5AA210L
        Before     = '48895C2410'
        After      = 'E9723C7400'
        Signature  = '48895C2410488974241855574156488BEC4883EC30'
    }
    PropertyCave = [pscustomobject]@{
        Name       = 'property code cave (pGpu+0x4410 |= 0x1000)'
        FileOffset = 0xCED687L
        Rva        = 0xCEDE87L
        Before     = 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'
        After      = '48895C241081891044000000100000E97AC38BFF'
        Signature  = 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'
    }
    GrPath = [pscustomobject]@{
        Name       = 'GR init predicate branch (_nv032289rm analogue)'
        FileOffset = 0x37F3BCL
        Rva        = 0x37FBBCL
        Before     = '7514'
        After      = '9090'
        Signature  = '488BD3488BCFFF15F42EA800488BD3488BCF84C07514E86DE1FFFF488B83080F0000'
    }
    GrPresent = [pscustomobject]@{
        Name       = 'GR-present predicate (_nv031940rm analogue)'
        FileOffset = 0xA2BFF0L
        Rva        = 0xA2C7F0L
        Before     = '48895C2418'
        After      = 'B001C39090'
        Signature  = '48895C2418555657415641574883EC50488B0579C17600'
    }
}

function Convert-HexToBytes([string] $Hex) {
    if (($Hex.Length % 2) -ne 0 -or $Hex -notmatch '^[0-9A-Fa-f]*$') {
        throw "Invalid hexadecimal string: $Hex"
    }
    $bytes = New-Object byte[] ($Hex.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16)
    }
    return $bytes
}

function Convert-BytesToHex([byte[]] $Bytes) {
    return -join ($Bytes | ForEach-Object { $_.ToString('X2') })
}

function Get-GrSha256([string] $Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}

function Get-BytesAt([byte[]] $Data, [long] $Offset, [int] $Count) {
    if ($Offset -lt 0 -or ($Offset + $Count) -gt $Data.LongLength) {
        throw ('Offset 0x{0:X} with length {1} is outside the file.' -f $Offset, $Count)
    }
    $result = New-Object byte[] $Count
    [Array]::Copy($Data, $Offset, $result, 0, $Count)
    return $result
}

function Find-BytePattern([byte[]] $Data, [byte[]] $Pattern) {
    $found = New-Object System.Collections.Generic.List[long]
    if ($Pattern.Length -eq 0 -or $Data.Length -lt $Pattern.Length) { return $found }
    $last = $Data.Length - $Pattern.Length
    $i = 0
    while ($i -le $last) {
        $i = [Array]::IndexOf($Data, [byte]$Pattern[0], $i)
        if ($i -lt 0 -or $i -gt $last) { break }
        $same = $true
        for ($j = 1; $j -lt $Pattern.Length; $j++) {
            if ($Data[$i + $j] -ne $Pattern[$j]) { $same = $false; break }
        }
        if ($same) { $found.Add([long]$i) }
        $i++
    }
    return $found
}

function Get-PeFacts([byte[]] $Data) {
    if ($Data.Length -lt 0x100 -or $Data[0] -ne 0x4D -or $Data[1] -ne 0x5A) {
        throw 'The file has no DOS/PE MZ header.'
    }
    $pe = [BitConverter]::ToInt32($Data, 0x3C)
    if ($pe -lt 0 -or ($pe + 0x108) -gt $Data.Length -or
        $Data[$pe] -ne 0x50 -or $Data[$pe + 1] -ne 0x45 -or
        $Data[$pe + 2] -ne 0 -or $Data[$pe + 3] -ne 0) {
        throw 'Invalid PE header.'
    }
    $machine = [BitConverter]::ToUInt16($Data, $pe + 4)
    $sections = [BitConverter]::ToUInt16($Data, $pe + 6)
    $optional = $pe + 24
    $magic = [BitConverter]::ToUInt16($Data, $optional)
    if ($machine -ne 0x8664 -or $magic -ne 0x20B) {
        throw ('Expected PE32+ AMD64, got machine=0x{0:X4}, magic=0x{1:X4}.' -f $machine, $magic)
    }
    $optionalSize = [BitConverter]::ToUInt16($Data, $pe + 20)
    $sectionTable = $optional + $optionalSize
    $text = $null
    for ($i = 0; $i -lt $sections; $i++) {
        $off = $sectionTable + $i * 40
        $name = [Text.Encoding]::ASCII.GetString($Data, $off, 8).Trim([char]0)
        if ($name -eq '.text') {
            $text = [pscustomobject]@{
                Rva       = [BitConverter]::ToUInt32($Data, $off + 12)
                RawSize   = [BitConverter]::ToUInt32($Data, $off + 16)
                RawOffset = [BitConverter]::ToUInt32($Data, $off + 20)
            }
            break
        }
    }
    if (-not $text) { throw 'The PE file has no .text section.' }
    return [pscustomobject]@{ Machine = $machine; Text = $text }
}

function Get-GrObservedVariant($Sites) {
    $state = @{}
    foreach ($site in $Sites) { $state[$site.Key] = $site.State }
    if (@($Sites | Where-Object State -eq 'mismatch').Count -ne 0) {
        return 'UNKNOWN'
    }

    $propertyStock = ($state.PropertyEntry -eq 'stock' -and
                      $state.PropertyCave -eq 'stock')
    $propertyPatched = ($state.PropertyEntry -eq 'patched' -and
                        $state.PropertyCave -eq 'patched')
    $predicatesStock = ($state.GrPath -eq 'stock' -and
                        $state.GrPresent -eq 'stock')
    $predicatesPatched = ($state.GrPath -eq 'patched' -and
                          $state.GrPresent -eq 'patched')

    if ($propertyStock -and $predicatesStock) { return 'R0/Stock' }
    if ($propertyPatched -and $predicatesStock) { return 'R1/Property' }
    if ($propertyStock -and $predicatesPatched) { return 'R2/Predicates' }
    if ($propertyPatched -and $predicatesPatched) { return 'R3/Full' }
    return 'UNKNOWN'
}

function Get-GrDriverAudit([string] $Path) {
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $item = Get-Item -LiteralPath $resolved
    if ($item.PSIsContainer) { throw "Expected a file, got a directory: $resolved" }
    $data = [IO.File]::ReadAllBytes($resolved)
    $sha = Get-GrSha256 $resolved
    $profile = $script:GrDriverProfiles | Where-Object {
        $_.Sha256 -eq $sha -and $_.Size -eq $item.Length -and
        $_.Version -eq $item.VersionInfo.FileVersion
    } | Select-Object -First 1
    $pe = Get-PeFacts $data
    if ($pe.Text.Rva -ne 0x1000 -or $pe.Text.RawOffset -ne 0x800) {
        throw ('Unexpected .text geometry: RVA=0x{0:X}, raw=0x{1:X}.' -f
            $pe.Text.Rva, $pe.Text.RawOffset)
    }

    $sites = @()
    foreach ($entry in $script:GrPatchSites.GetEnumerator()) {
        $site = $entry.Value
        $before = Convert-HexToBytes $site.Before
        $after = Convert-HexToBytes $site.After
        $actual = Get-BytesAt $data $site.FileOffset $before.Length
        $state = if ((Convert-BytesToHex $actual) -eq $site.Before) {
            'stock'
        } elseif ((Convert-BytesToHex $actual) -eq $site.After) {
            'patched'
        } else {
            'mismatch'
        }
        # The cave is deliberately a prefix of a longer INT3 run. The exact
        # offset and stock bytes are authoritative; uniqueness applies to code
        # signatures, while the cave is checked by address and context.
        if ($entry.Key -eq 'PropertyCave') {
            $matches = @()
            $unique = $state -ne 'mismatch'
        } else {
            $signature = Convert-HexToBytes $site.Signature
            $matches = @(Find-BytePattern $data $signature)
            $unique = $matches.Count -eq 1
        }
        $sites += [pscustomobject]@{
            Key             = $entry.Key
            Name            = $site.Name
            FileOffset      = ('0x{0:X}' -f $site.FileOffset)
            Rva             = ('0x{0:X}' -f $site.Rva)
            State           = $state
            Actual          = Convert-BytesToHex $actual
            SignatureCount  = $matches.Count
            SignatureUnique = $unique
        }
    }

    $runtimeGsp = 'unknown (nvidia-smi unavailable or this is not the active driver)'
    try {
        $gspLine = & nvidia-smi -q 2>$null | Select-String -Pattern '^\s*GSP Firmware Version\s*:' | Select-Object -First 1
        if ($gspLine) { $runtimeGsp = (($gspLine.Line -split ':', 2)[1]).Trim() }
    } catch { }

    $allStock = @($sites | Where-Object State -ne 'stock').Count -eq 0
    $allUnique = @($sites | Where-Object SignatureUnique -ne $true).Count -eq 0
    $observedVariant = Get-GrObservedVariant $sites
    return [pscustomobject]@{
        Path              = $resolved
        Size              = $item.Length
        Sha256            = $sha
        FileVersion       = $item.VersionInfo.FileVersion
        ProductVersion    = $item.VersionInfo.ProductVersion
        Profile           = if ($profile) { $profile.Name } else { $null }
        HashApproved      = [bool]$profile
        ObservedVariant   = $observedVariant
        RuntimeGsp        = $runtimeGsp
        PeMachine         = ('0x{0:X4}' -f $pe.Machine)
        TextRva           = ('0x{0:X}' -f $pe.Text.Rva)
        TextRawOffset     = ('0x{0:X}' -f $pe.Text.RawOffset)
        Sites             = $sites
        AllSitesStock     = $allStock
        AllSignaturesSafe = $allUnique
        Patchable         = ([bool]$profile -and $allStock -and $allUnique)
    }
}
