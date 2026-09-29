#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
issrate.py - per-unit SM issue-rate probe for the CMP 70HX unlock study.

Covers two of the planned steps, with no compiler required:

  step 1  core / SM count and device attributes, via the CUDA driver API
  step 3  achieved per-unit instruction throughput, via NVRTC-compiled
          kernels launched through the driver API

Why not the obvious tool
-----------------------
The 50HX project's `verify/rm_issue_rate.c` reads RM's cached issue-rate
values through `NV_ESC_RM_CONTROL` (ioctl 0x2a) of the *open* NVIDIA kernel
driver, and reads the core count from `GR_INFO_INDEX_GPU_CORE_COUNT` over
the same interface. That ABI is Linux-only and has no public Windows
equivalent, so it cannot be ported here. `nvapi64.dll` is no help either:
this driver build exports a single dispatcher and zero `NvAPI_*` names, so
P/Invoke by symbol name is impossible.

What this measures instead
--------------------------
The issue rate limits achieved instructions per clock per SM, per datapath
unit. So run a pure-register loop for each unit and divide the achieved
instruction count by (SM count x measured clock). That quotient is
frequency-independent by construction, which is the whole point:

  * one unit lands far below its architectural peak while the others are at
    peak  =>  that unit is still rate-limited, the unlock is partial for it
  * all units are at peak                            =>  nothing per-unit is
    left to lift; the remaining gap is silicon or clock, not SS0/SS1

Why the clock is measured inside each kernel
--------------------------------------------
Throughput alone cannot separate "rate-limited" from "running slower" - both
look like fewer instructions. Every kernel therefore stamps `%globaltimer`
and `%clock64` around its own compute loop; cycles / nanoseconds gives the
actual SM frequency during that kernel, and it is also what
`clocks_throttle_reasons` cannot tell us at idle.

Bendy's field names for the same datapaths (ch.sh, 9 fields):
  DP, FFMA, FMLA16, FMLA32, IMLA0..IMLA4

Usage
-----
    python src/tools/issrate.py --tag locked
    python src/tools/issrate.py --tag unlocked --json out/tools/unlocked.json
"""

import argparse
import ctypes
import json
import os
import statistics
import subprocess
import sys
import threading
import time

# --------------------------------------------------------------------- paths

CUDA_BIN = r"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.3\bin\x64"
CUDA_INC = r"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.3\include"

# ------------------------------------------------------------- driver API

cu = ctypes.WinDLL("nvcuda.dll")


def _sig(name, argtypes, restype=ctypes.c_int):
    fn = getattr(cu, name)
    fn.argtypes = argtypes
    fn.restype = restype
    return fn


def _sig_opt(name, argtypes, restype=ctypes.c_int):
    """Bind a driver entry point if this build exports it, else return None.

    nvcuda.dll does not export the full documented surface: on this driver
    `cuGetErrorLog` is absent, so diagnostic paths must degrade to nothing
    rather than crash at import time.
    """
    try:
        fn = getattr(cu, name)
    except AttributeError:
        return None
    fn.argtypes = argtypes
    fn.restype = restype
    return fn


cuInit = _sig("cuInit", [ctypes.c_uint])
cuDeviceGet = _sig("cuDeviceGet", [ctypes.POINTER(ctypes.c_int), ctypes.c_int])
cuDeviceGetCount = _sig("cuDeviceGetCount", [ctypes.POINTER(ctypes.c_int)])
cuDeviceGetAttribute = _sig(
    "cuDeviceGetAttribute", [ctypes.POINTER(ctypes.c_int), ctypes.c_int, ctypes.c_int])
cuDeviceGetName = _sig("cuDeviceGetName", [ctypes.c_char_p, ctypes.c_int, ctypes.c_int])
cuDeviceTotalMem = _sig("cuDeviceTotalMem_v2", [ctypes.POINTER(ctypes.c_size_t), ctypes.c_int])
cuCtxCreate = _sig("cuCtxCreate_v2", [ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint, ctypes.c_int])
cuCtxDestroy = _sig("cuCtxDestroy_v2", [ctypes.c_void_p])
cuCtxSynchronize = _sig("cuCtxSynchronize", [])
cuModuleLoadData = _sig("cuModuleLoadData", [ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p])
cuModuleLoadDataEx = _sig(
    "cuModuleLoadDataEx", [ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
                           ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p])
cuGetErrorLog = _sig_opt("cuGetErrorLog", [ctypes.c_void_p, ctypes.POINTER(ctypes.c_char_p)])
cuModuleGetFunction = _sig(
    "cuModuleGetFunction", [ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.c_char_p])
cuModuleUnload = _sig("cuModuleUnload", [ctypes.c_void_p])
cuMemAlloc = _sig("cuMemAlloc_v2", [ctypes.POINTER(ctypes.c_ulonglong), ctypes.c_size_t])
cuMemFree = _sig("cuMemFree_v2", [ctypes.c_ulonglong])
cuMemcpyHtoD = _sig("cuMemcpyHtoD_v2", [ctypes.c_ulonglong, ctypes.c_void_p, ctypes.c_size_t])
cuMemcpyDtoH = _sig("cuMemcpyDtoH_v2", [ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_size_t])
cuLaunchKernel = _sig(
    "cuLaunchKernel",
    [ctypes.c_void_p] + [ctypes.c_uint] * 7 +
    [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p])
cuGetErrorName = _sig("cuGetErrorName", [ctypes.c_int, ctypes.POINTER(ctypes.c_char_p)])
cuGetErrorString = _sig("cuGetErrorString", [ctypes.c_int, ctypes.POINTER(ctypes.c_char_p)])


def chk(rc, what):
    if rc != 0:
        name = ctypes.c_char_p()
        s = ctypes.c_char_p()
        try:
            cuGetErrorName(rc, ctypes.byref(name))
            cuGetErrorString(rc, ctypes.byref(s))
            raise SystemExit(
                "%s failed: %d (%s) %s" %
                (what, rc, (name.value or b"?").decode(errors="replace"),
                 (s.value or b"?").decode(errors="replace")))
        finally:
            del name, s
    return rc


# ------------------------------------------------------------------ nvrtc

nvrtc = ctypes.CDLL(os.path.join(CUDA_BIN, "nvrtc64_130_0.dll"))
nvrtc.nvrtcVersion.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int)]
nvrtc.nvrtcVersion.restype = ctypes.c_int
nvrtc.nvrtcCreateProgram.argtypes = [
    ctypes.POINTER(ctypes.c_void_p), ctypes.c_char_p, ctypes.c_char_p,
    ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
nvrtc.nvrtcCreateProgram.restype = ctypes.c_int
nvrtc.nvrtcCompileProgram.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
nvrtc.nvrtcCompileProgram.restype = ctypes.c_int
nvrtc.nvrtcGetPTXSize.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
nvrtc.nvrtcGetPTXSize.restype = ctypes.c_int
nvrtc.nvrtcGetPTX.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
nvrtc.nvrtcGetPTX.restype = ctypes.c_int
nvrtc.nvrtcGetProgramLogSize.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
nvrtc.nvrtcGetProgramLogSize.restype = ctypes.c_int
nvrtc.nvrtcGetProgramLog.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
nvrtc.nvrtcGetProgramLog.restype = ctypes.c_int
nvrtc.nvrtcDestroyProgram.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
nvrtc.nvrtcDestroyProgram.restype = ctypes.c_int


def nvchk(rc, what, prog=None):
    if rc != 0:
        msg = ""
        if prog is not None:
            n = ctypes.c_size_t()
            if nvrtc.nvrtcGetProgramLogSize(prog, ctypes.byref(n)) == 0 and n.value > 1:
                buf = ctypes.create_string_buffer(n.value)
                nvrtc.nvrtcGetProgramLog(prog, buf)
                msg = "\n" + buf.value.decode(errors="replace")
        raise SystemExit("%s failed: %d%s" % (what, rc, msg))


# ------------------------------------------------------ device attributes

ATTRS = [
    (16, "MULTIPROCESSOR_COUNT (SM)"),
    (10, "WARP_SIZE"),
    (39, "MAX_THREADS_PER_SM"),
    (82, "MAX_REGISTERS_PER_SM"),
    (81, "MAX_SHARED_MEMORY_PER_SM"),
    (97, "MAX_SHARED_MEMORY_PER_BLOCK_OPTIN"),
    (38, "L2_CACHE_SIZE (bytes)"),
    (36, "MEMORY_CLOCK_RATE (kHz)"),
    (37, "GLOBAL_MEMORY_BUS_WIDTH (bit)"),
    (40, "ASYNC_ENGINE_COUNT"),
    (41, "UNIFIED_ADDRESSING"),
    (19, "CAN_MAP_HOST_MEMORY"),
    (32, "ECC_ENABLED"),
    (79, "GLOBAL_L1_CACHE_SUPPORTED"),
    (108, "MAX_PERSISTING_L2_CACHE_SIZE"),
    (75, "COMPUTE_CAPABILITY_MAJOR"),
    (76, "COMPUTE_CAPABILITY_MINOR"),
    (13, "CLOCK_RATE (kHz, max)"),
    (33, "PCI_BUS_ID"),
    (34, "PCI_DEVICE_ID"),
    (84, "MULTI_GPU_BOARD"),
    (15, "GPU_OVERLAP"),
]


class Res(ctypes.Structure):
    _fields_ = [
        ("ns0", ctypes.c_ulonglong), ("ns1", ctypes.c_ulonglong),
        ("cy0", ctypes.c_ulonglong), ("cy1", ctypes.c_ulonglong),
        ("sink", ctypes.c_float),
    ]


# ------------------------------------------------------------------- kernels
#
# Eight independent accumulator chains give enough ILP to saturate the
# pipeline; loop-invariant operands keep the body a pure register operation
# with no loads, so what is measured is issue rate and not bandwidth.
# Every accumulator is summed and written out, so nothing can be folded away.

KERNELS = r"""
#include <cuda_fp16.h>
#include <cuda_bf16.h>

struct Res {
    unsigned long long ns0, ns1;
    unsigned long long cy0, cy1;
    float sink;
};

__device__ __forceinline__ unsigned long long rd_ns(void) {
    unsigned long long v; asm volatile("mov.u64 %0, %globaltimer;" : "=l"(v)); return v;
}
__device__ __forceinline__ unsigned long long rd_cy(void) {
    unsigned long long v; asm volatile("mov.u64 %0, %clock64;" : "=l"(v)); return v;
}
__device__ __forceinline__ void emit(Res* o, unsigned long long g,
        unsigned long long a, unsigned long long b,
        unsigned long long c, unsigned long long d, float s) {
    Res r; r.ns0=a; r.ns1=b; r.cy0=c; r.cy1=d; r.sink=s; o[g]=r;
}

extern "C" __global__ void k_ffma32(Res* __restrict__ out, int iters) {
    float a[8];
    const float b = 1.0000001f, c = 0.9999999f;
#pragma unroll
    for (int u = 0; u < 8; ++u) a[u] = (float)(threadIdx.x*8+u) * 1.0000001f + 0.5f;
    const unsigned long long g = blockIdx.x * (unsigned long long)blockDim.x + threadIdx.x;
    const unsigned long long n0 = rd_ns(), y0 = rd_cy();
    for (int i = 0; i < iters; ++i) {
#pragma unroll
        for (int u = 0; u < 8; ++u) a[u] = __fmaf_rn(a[u], b, c);
    }
    const unsigned long long n1 = rd_ns(), y1 = rd_cy();
    float s = 0.f;
#pragma unroll
    for (int u = 0; u < 8; ++u) s += a[u];
    emit(out, g, n0, n1, y0, y1, s);
}

extern "C" __global__ void k_fadd32(Res* __restrict__ out, int iters) {
    float a[8];
    const float b = 1.0000001f;
#pragma unroll
    for (int u = 0; u < 8; ++u) a[u] = (float)(threadIdx.x*8+u) * 1.0000001f + 0.5f;
    const unsigned long long g = blockIdx.x * (unsigned long long)blockDim.x + threadIdx.x;
    const unsigned long long n0 = rd_ns(), y0 = rd_cy();
    for (int i = 0; i < iters; ++i) {
#pragma unroll
        for (int u = 0; u < 8; ++u) a[u] = __fadd_rn(a[u], b);
    }
    const unsigned long long n1 = rd_ns(), y1 = rd_cy();
    float s = 0.f;
#pragma unroll
    for (int u = 0; u < 8; ++u) s += a[u];
    emit(out, g, n0, n1, y0, y1, s);
}

extern "C" __global__ void k_fma16(Res* __restrict__ out, int iters) {
    __half2 a[8];
    const __half2 b = __floats2half2_rn(1.0001f, 0.9999f);
    const __half2 c = __floats2half2_rn(0.5000f, 0.2500f);
#pragma unroll
    for (int u = 0; u < 8; ++u)
        a[u] = __floats2half2_rn((float)(threadIdx.x*8+u) * 1.0001f, 0.5000f);
    const unsigned long long g = blockIdx.x * (unsigned long long)blockDim.x + threadIdx.x;
    const unsigned long long n0 = rd_ns(), y0 = rd_cy();
    for (int i = 0; i < iters; ++i) {
#pragma unroll
        for (int u = 0; u < 8; ++u) a[u] = __hfma2(a[u], b, c);
    }
    const unsigned long long n1 = rd_ns(), y1 = rd_cy();
    float s = 0.f;
#pragma unroll
    for (int u = 0; u < 8; ++u) s += __low2float(a[u]) + __high2float(a[u]);
    emit(out, g, n0, n1, y0, y1, s);
}

extern "C" __global__ void k_fma32bf(Res* __restrict__ out, int iters) {
    __nv_bfloat162 a[8];
    const __nv_bfloat162 b = __floats2bfloat162_rn(1.0001f, 0.9999f);
    const __nv_bfloat162 c = __floats2bfloat162_rn(0.5000f, 0.2500f);
#pragma unroll
    for (int u = 0; u < 8; ++u)
        a[u] = __floats2bfloat162_rn((float)(threadIdx.x*8+u) * 1.0001f, 0.5000f);
    const unsigned long long g = blockIdx.x * (unsigned long long)blockDim.x + threadIdx.x;
    const unsigned long long n0 = rd_ns(), y0 = rd_cy();
    for (int i = 0; i < iters; ++i) {
#pragma unroll
        for (int u = 0; u < 8; ++u) a[u] = __hfma2(a[u], b, c);
    }
    const unsigned long long n1 = rd_ns(), y1 = rd_cy();
    float s = 0.f;
#pragma unroll
    for (int u = 0; u < 8; ++u) s += __low2float(a[u]) + __high2float(a[u]);
    emit(out, g, n0, n1, y0, y1, s);
}

extern "C" __global__ void k_dp4a(Res* __restrict__ out, int iters) {
    int x[8];
    const int p = 0x01010101, q = 0x3f3f3f3f;
#pragma unroll
    for (int u = 0; u < 8; ++u) x[u] = (int)(threadIdx.x*8+u) ^ 0x5a5a5a5a;
    const unsigned long long g = blockIdx.x * (unsigned long long)blockDim.x + threadIdx.x;
    const unsigned long long n0 = rd_ns(), y0 = rd_cy();
    for (int i = 0; i < iters; ++i) {
#pragma unroll
        for (int u = 0; u < 8; ++u) x[u] = __dp4a(x[u], p, q);
    }
    const unsigned long long n1 = rd_ns(), y1 = rd_cy();
    int s = 0;
#pragma unroll
    for (int u = 0; u < 8; ++u) s ^= x[u];
    emit(out, g, n0, n1, y0, y1, (float)(s & 1));
}

extern "C" __global__ void k_iadd32(Res* __restrict__ out, int iters) {
    int x[8];
#pragma unroll
    for (int u = 0; u < 8; ++u) x[u] = (int)(threadIdx.x*8+u) ^ 0x5a5a5a5a;
    const unsigned long long g = blockIdx.x * (unsigned long long)blockDim.x + threadIdx.x;
    const unsigned long long n0 = rd_ns(), y0 = rd_cy();
    for (int i = 0; i < iters; ++i) {
        const int kk = 0x9e3779b9 + i;   // loop-dependent, cannot be hoisted
#pragma unroll
        for (int u = 0; u < 8; ++u) {
            // Inline PTX on purpose. Plain `x[u] = x[u] + k` with a constant k
            // is strength-reduced by NVVM into a closed form (two IMADs per
            // iteration instead of eight adds), which silently turned this
            // "instruction throughput" probe into an algebra benchmark.
            int d;
            asm volatile("add.s32 %0, %1, %2;" : "=r"(d) : "r"(x[u]), "r"(kk));
            x[u] = d;
        }
    }
    const unsigned long long n1 = rd_ns(), y1 = rd_cy();
    int s = 0;
#pragma unroll
    for (int u = 0; u < 8; ++u) s ^= x[u];
    emit(out, g, n0, n1, y0, y1, (float)(s & 1));
}
"""

# name, bendy field, kernel, flops per instruction, peak inst/clk/SM (None = unknown)
#
# The peak column is what makes the numbers readable, so it is only filled in
# where the architectural maximum is actually known for this part:
#   FP32 FMA / FADD   128 inst/clk/SM on GA10x (128 FP32 lanes per SM)
#   HFMA2 (fp16/bf16)  64 inst/clk/SM - a half-rate instruction, but each one
#                      retires 2 elements, so it delivers 2x the FP32 flops
#   DP4A               64 inst/clk/SM
#   INT32             not established here; measured 92 inst/clk/SM, which is
#                     above the 64 the FP32/INT32 shared lanes would allow, so
#                     the real ceiling is genuinely unknown and no % is printed
#
# DP2A is deliberately absent. There is no __dp2a intrinsic in CUDA C, only
# PTX; hand-written `dp2a.u32.u32.u32` asm makes NVVM allocate 278 virtual
# registers for a 256-thread block, which exceeds the 65536 per SM and makes
# the driver refuse the whole module (INVALID_PTX). The datapath classes that
# matter here - FP32, FP16, BF16, DP, INT - are all covered below, so the
# odd unit out is not worth fighting the compiler for.
UNITS = [
    ("FFMA32",  "FFMA",   "k_ffma32",  2.0, 128.0),
    ("FADD32",  "-",      "k_fadd32",  1.0, 128.0),
    ("FMA16",   "FMLA16", "k_fma16",   4.0, 64.0),
    ("FMA32BF", "FMLA32", "k_fma32bf", 4.0, 64.0),
    ("DP4A",    "DP",     "k_dp4a",    0.0, 64.0),
    ("IADD32",  "IMLA0",  "k_iadd32",  0.0, None),
]

UNROLL = 8
THREADS = 256
TARGET_NS = 100_000_000      # per-launch window; also the NVML sampling window
REPEATS = 3                  # median of these, so one noisy window cannot win


class SmiSampler(threading.Thread):
    """Sample NVML SM clock and power draw while kernels run.

    Needed because %clock64 is useless as a clock source on this part: it
    ticks at a fixed ~4.5 GHz reference and reported 4495 MHz against a
    device maximum of 1545 MHz. NVML is the only trustworthy clock we have
    from the OS side, and it hands us power draw under compute load for the
    same run, which is what the 75 W graphics figure is not.
    """

    def __init__(self, dev=0, interval_ms=50):
        threading.Thread.__init__(self, daemon=True)
        self.dev = dev
        self.interval_ms = interval_ms
        self.samples = []          # (t_end, sm_mhz, power_w, throttle_flags)
        self._stop = False
        self.proc = None

    def run(self):
        cmd = ["nvidia-smi",
               "--query-gpu=clocks.sm,power.draw,clocks_throttle_reasons.active",
               "--format=csv,noheader,nounits",
               "-i", str(self.dev), "-lms", str(self.interval_ms)]
        try:
            self.proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1)
            for line in self.proc.stdout:
                if self._stop:
                    break
                parts = [x.strip() for x in line.split(",")]
                if len(parts) < 3:
                    continue
                try:
                    sm = float(parts[0])
                    pw = float(parts[1])
                except ValueError:
                    continue
                self.samples.append((time.perf_counter(), sm, pw, parts[2]))
        except Exception as e:                      # sampler must never kill the run
            print("  (smi sampler stopped: %s)" % e)

    def stop(self):
        self._stop = True
        if self.proc is not None:
            try:
                self.proc.terminate()
            except Exception:
                pass

    def in_window(self, t0, t1):
        """Median SM clock and power over samples that finished inside [t0,t1]."""
        sel = [s for s in self.samples if t0 <= s[0] <= t1]
        if not sel:
            return None
        return (statistics.median(s[1] for s in sel),
                statistics.median(s[2] for s in sel),
                sorted({s[3] for s in sel}),
                len(sel))


def compile_module(arch):
    prog = ctypes.c_void_p()
    nvchk(nvrtc.nvrtcCreateProgram(ctypes.byref(prog), KERNELS.encode(),
                                   b"issrate.cu", 0, None, None), "nvrtcCreateProgram")
    opts = [
        ("--gpu-architecture=compute_%s" % arch).encode(),
        ("-I" + CUDA_INC).encode(),
        b"--std=c++14",
    ]
    arr = (ctypes.c_char_p * len(opts))(*opts)
    nvchk(nvrtc.nvrtcCompileProgram(prog, len(opts), arr),
          "nvrtcCompileProgram", prog)
    n = ctypes.c_size_t()
    nvchk(nvrtc.nvrtcGetPTXSize(prog, ctypes.byref(n)), "nvrtcGetPTXSize", prog)
    buf = ctypes.create_string_buffer(n.value)
    nvchk(nvrtc.nvrtcGetPTX(prog, buf), "nvrtcGetPTX", prog)
    nvchk(nvrtc.nvrtcDestroyProgram(ctypes.byref(prog)), "nvrtcDestroyProgram")
    return buf.raw


def load_module(ptx, ctx):
    """JIT the PTX, and on failure print the driver's own log.

    A bare cuModuleLoadData only returns 218 (INVALID_PTX), which says
    nothing about the offending line, so the Ex form plus cuGetErrorLog is
    what makes this debuggable at all.
    """
    mod = ctypes.c_void_p()
    rc = cuModuleLoadDataEx(ctypes.byref(mod), ptx, 0, None, None)
    if rc != 0:
        detail = ""
        if cuGetErrorLog is not None:
            log = ctypes.c_char_p()
            if cuGetErrorLog(ctx, ctypes.byref(log)) == 0 and log.value:
                detail = log.value.decode(errors="replace")
        n = ctypes.c_char_p()
        cuGetErrorName(rc, ctypes.byref(n))
        raise SystemExit("PTX JIT failed: %d %s\n%s"
                         % (rc, (n.value or b"?").decode(errors="replace"), detail))
    return mod


def read_window(dptr, host, nthreads):
    """Return (min ns0, max ns1, min cy0, max cy1) over all threads."""
    chk(cuMemcpyDtoH(host, dptr, nthreads * ctypes.sizeof(Res)), "cuMemcpyDtoH")
    lo_ns, hi_ns, lo_cy, hi_cy = (1 << 64) - 1, 0, (1 << 64) - 1, 0
    sink = 0.0
    for i in range(nthreads):
        r = host[i]
        if r.ns0 < lo_ns: lo_ns = r.ns0
        if r.ns1 > hi_ns: hi_ns = r.ns1
        if r.cy0 < lo_cy: lo_cy = r.cy0
        if r.cy1 > hi_cy: hi_cy = r.cy1
        sink += r.sink
    return lo_ns, hi_ns, lo_cy, hi_cy, sink


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default="adhoc", help="label recorded in the output")
    ap.add_argument("--dev", type=int, default=0)
    ap.add_argument("--json", default=None, help="write machine-readable results here")
    ap.add_argument("--dump-ptx", default=None, help="write the generated PTX here")
    args = ap.parse_args()

    chk(cuInit(0), "cuInit")
    ndev = ctypes.c_int()
    chk(cuDeviceGetCount(ctypes.byref(ndev)), "cuDeviceGetCount")
    dev = ctypes.c_int()
    chk(cuDeviceGet(ctypes.byref(dev), args.dev), "cuDeviceGet")

    name = ctypes.create_string_buffer(256)
    chk(cuDeviceGetName(name, 256, dev), "cuDeviceGetName")

    print("=" * 72)
    print("issrate.py  tag=%s  device=%d/%d" % (args.tag, args.dev, ndev.value))
    print("=" * 72)
    print("name: %s" % name.value.decode(errors="replace"))
    print("")

    # ---------------------------------------------------------- step 1
    print("=" * 72)
    print("STEP 1 - device attributes (core / SM count)")
    print("=" * 72)
    attrs = {}
    for code, label in ATTRS:
        v = ctypes.c_int(-1)
        rc = cuDeviceGetAttribute(ctypes.byref(v), code, dev)
        if rc == 0:
            attrs[label] = v.value
            print("  %-32s %s" % (label, v.value))
        else:
            print("  %-32s <error %d>" % (label, rc))
    mem = ctypes.c_size_t()
    if cuDeviceTotalMem(ctypes.byref(mem), dev) == 0:
        attrs["TOTAL_MEMORY_MiB"] = mem.value // (1024 * 1024)
        print("  %-32s %.0f" % ("TOTAL_MEMORY_MiB", mem.value / 1048576.0))

    sms = attrs.get("MULTIPROCESSOR_COUNT (SM)")
    if sms is None:
        raise SystemExit("cannot read SM count")
    print("")
    print("  ==> SM count        : %d" % sms)
    print("  ==> CUDA cores @128 : %d" % (sms * 128))
    print("  reference (RTX 3070 Ti identity): 48 SM / 6144 cores")
    print("  ratio cores/6144   : %.4f" % (sms * 128 / 6144.0))
    print("")

    # ---------------------------------------------------------- step 3
    ctx = ctypes.c_void_p()
    chk(cuCtxCreate(ctypes.byref(ctx), 0, dev), "cuCtxCreate")
    try:
        major = attrs.get("COMPUTE_CAPABILITY_MAJOR", 8)
        minor = attrs.get("COMPUTE_CAPABILITY_MINOR", 6)
        ptx = compile_module("%d%d" % (major, minor))
        if args.dump_ptx:
            with open(args.dump_ptx, "wb") as f:
                f.write(ptx)
            print("ptx: %s" % args.dump_ptx)
        mod = load_module(ptx, ctx)

        # Threads per SM must respect the device limit: 8 blocks x 256 = 2048
        # would exceed the 1536 this card reports, and the launch would fail
        # with CUDA_ERROR_LAUNCH_OUT_OF_RESOURCES. 1024 is plenty of
        # occupancy to saturate a pure-register ALU loop.
        max_thr_sm = attrs.get("MAX_THREADS_PER_SM", 1536)
        blocks_per_sm = max(1, min(8, max_thr_sm // THREADS))
        blocks = sms * blocks_per_sm
        nthreads = blocks * THREADS

        dptr = ctypes.c_ulonglong()
        chk(cuMemAlloc(ctypes.byref(dptr), nthreads * ctypes.sizeof(Res)), "cuMemAlloc")
        host = (Res * nthreads)()

        # Warm up: context, JIT, clock ramp. Results discarded on purpose.
        for (_n, _b, kname, _f, _pk) in UNITS:
            fn = ctypes.c_void_p()
            chk(cuModuleGetFunction(ctypes.byref(fn), mod, kname.encode()),
                "cuModuleGetFunction " + kname)
            a0 = ctypes.c_ulonglong(dptr.value)
            a1 = ctypes.c_int(256)
            pa = (ctypes.c_void_p * 2)()
            pa[0] = ctypes.addressof(a0)
            pa[1] = ctypes.addressof(a1)
            chk(cuLaunchKernel(fn, blocks, 1, 1, THREADS, 1, 1, 0, None, pa, None),
                "cuLaunchKernel(warmup) " + kname)
        chk(cuCtxSynchronize(), "cuCtxSynchronize")

        print("=" * 72)
        print("STEP 3 - per-unit issue rate")
        print("=" * 72)
        print("grid %d x %d = %d threads over %d SM, UNROLL %d, target %.0f ms"
              % (blocks, THREADS, nthreads, sms, UNROLL, TARGET_NS / 1e6))
        print("")
        print("%-8s %-7s %10s %9s %8s %7s %12s %8s %7s"
              % ("unit", "bendy", "G inst/s", "TFLOP/s", "MHz", "W", "inst/clk/SM", "%peak", "throt"))
        print("-" * 78)

        sampler = SmiSampler(args.dev, interval_ms=40)
        sampler.start()
        time.sleep(0.8)                 # let NVML spin up and take a baseline

        try:
            results = []
            for (uname, bendy, kname, flops, peak) in UNITS:
                fn = ctypes.c_void_p()
                chk(cuModuleGetFunction(ctypes.byref(fn), mod, kname.encode()),
                    "cuModuleGetFunction " + kname)

                def launch(iters):
                    a0 = ctypes.c_ulonglong(dptr.value)
                    a1 = ctypes.c_int(iters)
                    pa = (ctypes.c_void_p * 2)()
                    pa[0] = ctypes.addressof(a0)
                    pa[1] = ctypes.addressof(a1)
                    t0 = time.perf_counter()
                    chk(cuLaunchKernel(fn, blocks, 1, 1, THREADS, 1, 1, 0, None, pa, None),
                        "cuLaunchKernel " + kname)
                    chk(cuCtxSynchronize(), "cuCtxSynchronize")
                    t1 = time.perf_counter()
                    lo_ns, hi_ns, lo_cy, hi_cy, sk = read_window(dptr, host, nthreads)
                    return lo_ns, hi_ns, lo_cy, hi_cy, sk, t1 - t0, t0, t1

                # Calibrate iters so every unit runs for the same wall time,
                # otherwise the slower units get a short, noisy window.
                iters = 256
                for _ in range(12):
                    lo_ns, hi_ns, _lc, _hc, _sk, _w, _a, _b = launch(iters)
                    if (hi_ns - lo_ns) > TARGET_NS:
                        break
                    scale = (TARGET_NS / max(hi_ns - lo_ns, 1)) * 1.2
                    nxt = int(iters * scale) + 1
                    if nxt <= iters:
                        nxt = iters + 1
                    if nxt > 50_000_000:
                        nxt = 50_000_000
                    iters = nxt

                inst_total = float(iters) * UNROLL * float(nthreads)

                # Repeat and take the median: a single 100 ms window is still
                # noisy on a shared PCIe/host, and the NVML sampler runs at
                # 40 ms, so each window must be long enough to land samples.
                #
                # The first repeat is a discard. NVML publishes SM clock only
                # once a sample has been taken, and the value it carries is
                # stale right after a long gap: the very first unit otherwise
                # reported 420 MHz, which would have implied 387 inst/clk/SM
                # and 302% of peak. The kernel itself only takes a few ms to
                # reach steady clocks, but the reader needs a sample first.
                g_list, wall_list, gt_list, sink = [], [], [], 0.0
                t_lo, t_hi = None, None
                for r in range(REPEATS + 1):
                    lo_ns, hi_ns, lo_cy, hi_cy, sk, wall, t0, t1 = launch(iters)
                    sink = sk
                    t_lo = t0 if t_lo is None else min(t_lo, t0)
                    t_hi = t1 if t_hi is None else max(t_hi, t1)
                    if r == 0:
                        continue                    # discard, clock not settled
                    g_list.append(inst_total / wall / 1e9)
                    wall_list.append(wall)
                    gt_list.append(((hi_ns - lo_ns) * 1e-9) / wall)

                g_inst = statistics.median(g_list)
                wall = statistics.median(wall_list)
                gt_ratio = statistics.median(gt_list)
                smi = sampler.in_window(t_lo, t_hi)
                tflops = g_inst * flops / 1e3 if flops > 0 else 0.0

                # A clock that disagrees with the device maximum by more than
                # a few percent means the NVML sample is stale or the card
                # moved states; refuse to print a derived number rather than
                # publish a physically impossible one.
                max_khz = attrs.get("CLOCK_RATE (kHz, max)")
                clock_sane = True
                if smi and smi[0] > 0 and max_khz:
                    lo_ok, hi_ok = 0.5 * (max_khz / 1e3), 1.15 * (max_khz / 1e3)
                    clock_sane = lo_ok <= smi[0] <= hi_ok

                # inst/clk/SM needs the real SM clock, which comes from NVML.
                # If NVML gave us nothing for this window, print '-' rather
                # than a number derived from the ~4.5 GHz clock64 reference.
                if smi and smi[0] > 0 and clock_sane:
                    mhz, watts, thr, nsamp = smi
                    per_sm = g_inst * 1e9 / (float(sms) * mhz * 1e6)
                    pct = (100.0 * per_sm / peak) if peak else None
                    mf = "%8.0f" % mhz
                    wf = "%7.1f" % watts
                    sf = "%12.2f" % per_sm
                    pf = ("%6.1f%%" % pct) if pct is not None else "%7s" % "-"
                    bits = 0
                    for t in thr:
                        try:
                            bits |= int(t, 16)
                        except ValueError:
                            pass
                    thf = "-" if bits == 0 else "0x%x" % bits
                else:
                    mhz = watts = per_sm = pct = None
                    nsamp = smi[3] if smi else 0
                    mf = sf = pf = thf = "%7s" % "-"
                    wf = ("%7.1f" % smi[1]) if (smi and smi[1] > 0) else "%7s" % "-"

                tfs = ("%.3f" % tflops) if flops > 0 else "-"
                print("%-8s %-7s %10.2f %9s %s %s %s %s %7s"
                      % (uname, bendy, g_inst, tfs, mf, wf, sf, pf, thf))
                results.append(dict(unit=uname, bendy=bendy, g_inst=g_inst,
                                    tflops=tflops, inst_per_clk_per_sm=per_sm,
                                    sm_mhz=mhz, power_w=watts, pct_peak=pct,
                                    peak_per_sm=peak, iters=iters, wall_s=wall,
                                    gt_over_wall=gt_ratio, nvml_samples=nsamp,
                                    g_inst_spread=(max(g_list) - min(g_list)) / g_inst))
        finally:
            sampler.stop()

        print("")
        print("inst/clk/SM = (G inst/s) / (SM count x NVML SM clock), frequency-")
        print("corrected by construction. %peak uses the architectural maximum of")
        print("each unit: 128 inst/clk/SM for FP32, 64 for HFMA2 (it is a half-")
        print("rate instruction that moves 2x the flops) and 64 for DP4A.")
        print("IADD32 has no %peak: the INT32 ceiling on this part is not")
        print("established here, and 128 would be a guess.")
        print("median gt/wall = %.3f confirms %%globaltimer is nanoseconds."
              % statistics.median(r["gt_over_wall"] for r in results))
        print("median NVML samples per unit window = %d"
              % statistics.median(r["nvml_samples"] or 0 for r in results))
        print("sink checksum %g (guards against dead-code elimination)" % sink)

        if args.json:
            payload = dict(tag=args.tag, device=args.dev, sm_count=sms,
                           attrs=attrs, units=results)
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            print("json: %s" % args.json)

        chk(cuMemFree(dptr), "cuMemFree")
        chk(cuModuleUnload(mod), "cuModuleUnload")
    finally:
        cuCtxDestroy(ctx)


if __name__ == "__main__":
    main()
