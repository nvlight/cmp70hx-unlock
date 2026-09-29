# SPDX-License-Identifier: GPL-2.0-only
#
# nvapi-cores.ps1 - step 1 of the issue-rate study: read the core / SM count
# through NVAPI, without needing a CUDA toolchain.
#
# Why NVAPI: `verify/rm_issue_rate.c` from the 50HX project reads
# GR_INFO_INDEX_GPU_CORE_COUNT over the Linux `NV_ESC_RM_CONTROL` ioctl of
# the *open* NVIDIA kernel driver. There is no public equivalent on Windows.
# NVAPI is the supported Windows interface and it exposes the same
# device attribute (CUDA core count), which is what the question needs.
#
# If the unlock has not changed the core count, this will agree with the
# 3070 Ti identity the patched driver reports. If it has, that is a second
# independent limiter which SS0/SS1 cannot touch by construction.
#
# Usage:  powershell -ExecutionPolicy Bypass -File nvapi-cores.ps1 [-Tag label]

param([string]$Tag = 'adhoc')

$ErrorActionPreference = 'Stop'

$src = @"
using System;
using System.Runtime.InteropServices;

public static class NvAPI {
    // NvAPI_Handle is 64-bit on x64, NvAPI_ShortHandle is 32-bit.
    [DllImport("nvapi64.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int NvAPI_EnumPhysicalGPUs([Out] IntPtr[] handles, ref uint count);

    [DllImport("nvapi64.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int NvAPI_GPU_GetCudaCoreCount(IntPtr physicalGpu, ref uint cores);

    [DllImport("nvapi64.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int NvAPI_GPU_GetGpuCoreClockRange(IntPtr physicalGpu, ref uint minMHz, ref uint maxMHz);

    [DllImport("nvapi64.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int NvAPI_GPU_GetMemoryAmount(IntPtr physicalGpu, ref uint totalMB, ref uint availMB);

    [DllImport("nvapi64.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int NvAPI_GPU_GetActiveBpcCount(IntPtr physicalGpu, ref uint bpc);

    [DllImport("nvapi64.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int NvAPI_GPU_GetBusType(IntPtr physicalGpu, ref uint busType);

    [DllImport("nvapi64.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int NvAPI_GPU_GetPcieLinkWidth(IntPtr physicalGpu, ref uint width);

    [DllImport("nvapi64.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int NvAPI_GPU_GetPcieLinkGeneration(IntPtr physicalGpu, ref uint gen);
}
"@

Add-Type -TypeDefinition $src -Language CSharp

function Show-Call {
    param([string]$Name, [int]$Rc, $Value)
    if ($Rc -eq 0) { "  {0,-34} {1}" -f $Name, $Value }
    else          { "  {0,-34} <NVAPI error 0x{1:X8}>" -f $Name, $Rc }
}

$handles = New-Object IntPtr[] 16
$count = [uint32]16
$rc = [NvAPI]::NvAPI_EnumPhysicalGPUs($handles, [ref]$count)
if ($rc -ne 0) { throw "NvAPI_EnumPhysicalGPUs failed: 0x$($rc.ToString('X8'))" }
Write-Output "NVAPI reports $count physical GPU(s)"

for ($i = 0; $i -lt $count; $i++) {
    $h = $handles[$i]
    Write-Output ""
    Write-Output "=== GPU $i (handle 0x$($h.ToString('X'))) ==="

    [uint32]$cores = 0
    $r = [NvAPI]::NvAPI_GPU_GetCudaCoreCount($h, [ref]$cores)
    Show-Call 'NVAPI_GPU_GetCudaCoreCount' $r $cores
    if ($r -eq 0) {
        Write-Output ("  {0,-34} {1}" -f '=> SM count (cores / 128)', ($cores / 128))
    }

    [uint32]$minMHz = 0; [uint32]$maxMHz = 0
    $r = [NvAPI]::NvAPI_GPU_GetGpuCoreClockRange($h, [ref]$minMHz, [ref]$maxMHz)
    Show-Call 'NVAPI_GPU_GetGpuCoreClockRange' $r "$minMHz .. $maxMHz MHz"

    [uint32]$tot = 0; [uint32]$avail = 0
    $r = [NvAPI]::NvAPI_GPU_GetMemoryAmount($h, [ref]$tot, [ref]$avail)
    Show-Call 'NVAPI_GPU_GetMemoryAmount' $r "total $tot MiB, avail $avail MiB"

    [uint32]$bpc = 0
    $r = [NvAPI]::NvAPI_GPU_GetActiveBpcCount($h, [ref]$bpc)
    Show-Call 'NVAPI_GPU_GetActiveBpcCount' $r "$bpc bpc"

    [uint32]$bus = 0
    $r = [NvAPI]::NvAPI_GPU_GetBusType($h, [ref]$bus)
    Show-Call 'NVAPI_GPU_GetBusType' $r "0x$($bus.ToString('X'))"

    [uint32]$w = 0
    $r = [NvAPI]::NvAPI_GPU_GetPcieLinkWidth($h, [ref]$w)
    Show-Call 'NVAPI_GPU_GetPcieLinkWidth' $r "x$w"

    [uint32]$g = 0
    $r = [NvAPI]::NvAPI_GPU_GetPcieLinkGeneration($h, [ref]$g)
    Show-Call 'NVAPI_GPU_GetPcieLinkGeneration' $r "Gen$g"
}

Write-Output ""
Write-Output "reference: RTX 3070 Ti identity = 46 SM / 6144 CUDA cores, boost 1770 MHz"
Write-Output "note: nvidia-smi reported max SM 1545 MHz earlier in this session"
