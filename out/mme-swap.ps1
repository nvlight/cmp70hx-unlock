<#
.SYNOPSIS
    Установка и откат пропатченной копии драйверной библиотеки NVIDIA.

.DESCRIPTION
    Копирует подготовленный (пропатченный) файл в DriverStore поверх
    оригинала, предварительно сделав резервную копию, либо возвращает
    оригинал. Обе операции проверяют SHA-256 и отказываются работать,
    если состояние не то, что ожидается.

    Порядок работы (см. docs/MME-THROTTLE.md):
      1. Подготовить пропатченную копию:
           python out\tools\mme_patch.py apply <копия> <смещения> --value 0x01 --apply
      2. Поставить её на место:
           powershell -File out\mme-swap.ps1 -Install <пропатченная копия>
      3. Вернуть как было (одна команда, без переустановки драйвера):
           powershell -File out\mme-swap.ps1 -Restore

.NOTES
    Требует прав администратора.
    Перезагрузка НЕ нужна: DLL перечитывается при старте нового процесса.
#>

[CmdletBinding(DefaultParameterSetName = 'Status')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Install')]
    [string] $Install,

    [Parameter(Mandatory = $true, ParameterSetName = 'Restore')]
    [switch] $Restore,

    [Parameter(ParameterSetName = 'Status')]
    [switch] $Status
)

$ErrorActionPreference = 'Stop'

# Каталог активного пакета драйвера: находим по работающему nvlddmkm.sys,
# а не по имени пакета -- имя меняется от версии к версии.
$svc = Get-CimInstance Win32_SystemDriver -Filter "Name='nvlddmkm'"
if (-not $svc) { throw "Служба nvlddmkm не найдена: драйвер NVIDIA не установлен." }
$pkgDir = Split-Path -Parent $svc.PathName
if (-not (Test-Path -LiteralPath $pkgDir)) { throw "Каталог пакета не найден: $pkgDir" }

$ledgerPath = Join-Path $pkgDir 'mme-swap.json'

function Get-Sha256([string] $Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}

if ($Status -or (-not $Restore -and -not $Install)) {
    "пакет          : $pkgDir"
    "драйвер        : $((Get-Item -LiteralPath $pkgDir).VersionInfo.ProductVersion)"
    "ledger         : $ledgerPath"
    if (Test-Path -LiteralPath $ledgerPath) {
        $led = Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json
        ""
        "=== сохранённая операция ==="
        $led | ConvertTo-Json -Depth 4
    } else {
        "=== операций не зафиксировано (файл менялся вручную) ==="
    }
    return
}

if ($Restore) {
    if (-not (Test-Path -LiteralPath $ledgerPath)) {
        throw "Нет $ledgerPath -- этой утилитой файл не заменялся. Откат невозможен."
    }
    $led = Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json
    foreach ($t in $led.targets) {
        if (-not (Test-Path -LiteralPath $t.backup)) {
            throw "Нет резервной копии $($t.backup)"
        }
        $cur = Get-Sha256 $t.target
        if ($cur -ne $t.sha256_patched) {
            throw ("Файл $($t.target) изменён чем-то ещё (ожидали $($t.sha256_patched), получили $cur). " +
                   "Откат небезопасен, остановился.")
        }
        Copy-Item -LiteralPath $t.backup -Destination $t.target -Force
        $back = Get-Sha256 $t.target
        if ($back -ne $t.sha256_original) {
            throw "После отката хэш не сошёлся для $($t.target)"
        }
        "ОТКАТ $($t.name): sha256 $back -- совпадает с оригиналом"
    }
    Remove-Item -LiteralPath $ledgerPath -Force
    ""
    "Готово. Драйвер в исходном состоянии; перезагрузка не требуется."
    return
}

# ---- Install ----
$src = (Resolve-Path -LiteralPath $Install).Path
$srcSha = Get-Sha256 $src
$staged = Join-Path $pkgDir ('.mme-stage-' + [IO.Path]::GetFileName($src))
Copy-Item -LiteralPath $src -Destination $staged -Force
if ((Get-Sha256 $staged) -ne $srcSha) { throw "Копирование в пакет не сошлось по хэшу." }

# цель по умолчанию -- та же библиотека, что и источник
$targetName = [IO.Path]::GetFileName($src)
$target = Join-Path $pkgDir $targetName
if (-not (Test-Path -LiteralPath $target)) {
    Remove-Item -LiteralPath $staged -Force
    throw "В пакете нет файла $targetName -- укажи корректную библиотеку."
}
if (Test-Path -LiteralPath $ledgerPath) {
    Remove-Item -LiteralPath $staged -Force
    throw "Уже есть неоткаченная операция ($ledgerPath). Сначала -Restore."
}

$backup = Join-Path $pkgDir ($targetName + '.orig')
Copy-Item -LiteralPath $target -Destination $backup -Force
$origSha = Get-Sha256 $backup
Move-Item -LiteralPath $staged -Destination $target -Force

$led = [pscustomobject]@{
    created  = (Get-Date -Format 'yyyy-MM-dd HHMMss')
    source   = $src
    package  = $pkgDir
    targets  = @([pscustomobject]@{
        name            = $targetName
        target          = $target
        backup          = $backup
        sha256_original = $origSha
        sha256_patched  = (Get-Sha256 $target)
    })
}
$led | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ledgerPath -Encoding utf8

"УСТАНОВЛЕНО $targetName"
"  оригинал : $origSha"
"  установлено: $((Get-Sha256 $target))"
"  резервная копия: $backup"
"  ledger: $ledgerPath"
""
"Откат одной командой:"
"  powershell -File out\mme-swap.ps1 -Restore"