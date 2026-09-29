#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
pcie-bw.py - host<->device bandwidth and a link-generation reading under load.

Why this exists
---------------
Every Gen2 verdict so far in this project was taken from
`nvidia-smi --query-gpu=pcie.link.gen.current` read while the card was
idle. xrip's Windows tool documents that this reading is not a verdict:
"GPU-Z / check shows Gen1 at idle - normal power-saving downshift. judge
by the GPU's LNKCTL2 TLS target". A card configured for Gen2 will still
report gen.current = 1 at idle, so that number cannot tell us whether the
link is configured, only what it is doing at that instant.

So the criterion has to change from a register reading to a physical
measurement. If the link is really Gen1 x16, no amount of DMA can exceed
about 4 GB/s useful (2.5 GT/s signalling, 8b/10b, ~250 MB/s per lane per
direction). At Gen2 x16 the ceiling is about 8 GB/s, and xrip measured
6.3-6.4 GB/s with a plain pinned-host CUDA DMA test on an unlocked 90HX.

The three outcomes this distinguishes:

  ~2 GB/s                 - the link is not even x16 electrically
  3.5-4.0 GB/s            - Gen1 x16, i.e. the thing we are fighting
  6.0-7.0 GB/s            - Gen2 x16, working, regardless of what gen.current
                            happened to say at idle

Method
------
Pinned host memory (cuMemHostAlloc, so pages are really DMA-able and not
copied through an internal staging buffer), one device buffer, and async
copies queued back to back on a non-blocking stream so the measurement is
bandwidth-bound rather than launch-bound. A watcher thread samples
`pcie.link.gen.current` throughout, so the generation is read *while the
link is loaded* - that is the whole point of this tool.

Usage
-----
    python src/tools/pcie-bw.py --tag idle
    python src/tools/pcie-bw.py --tag unlocked --json out/tools/pcie-bw.json
"""

import argparse
import ctypes
import json
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


cuInit = _sig("cuInit", [ctypes.c_uint])
cuDeviceGet = _sig("cuDeviceGet", [ctypes.POINTER(ctypes.c_int), ctypes.c_int])
cuDeviceGetCount = _sig("cuDeviceGetCount", [ctypes.POINTER(ctypes.c_int)])
cuDeviceGetName = _sig("cuDeviceGetName", [ctypes.c_char_p, ctypes.c_int, ctypes.c_int])
cuCtxCreate = _sig("cuCtxCreate_v2", [ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint, ctypes.c_int])
cuStreamCreate = _sig("cuStreamCreate", [ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint])
cuStreamSynchronize = _sig("cuStreamSynchronize", [ctypes.c_void_p])
cuMemAlloc = _sig("cuMemAlloc_v2", [ctypes.POINTER(ctypes.c_ulonglong), ctypes.c_size_t])
cuMemFree = _sig("cuMemFree_v2", [ctypes.c_ulonglong])
cuMemHostAlloc = _sig("cuMemHostAlloc", [ctypes.POINTER(ctypes.c_void_p), ctypes.c_size_t, ctypes.c_uint])
cuMemFreeHost = _sig("cuMemFreeHost", [ctypes.c_void_p])
cuMemHostRegister = _sig("cuMemHostRegister", [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint])
cuMemsetD8 = _sig("cuMemsetD8_v2", [ctypes.c_ulonglong, ctypes.c_ubyte, ctypes.c_size_t])
cuMemcpyHtoDAsync = _sig(
    "cuMemcpyHtoDAsync_v2",
    [ctypes.c_ulonglong, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p])
cuMemcpyDtoHAsync = _sig(
    "cuMemcpyDtoHAsync_v2",
    [ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_size_t, ctypes.c_void_p])
cuDeviceTotalMem = _sig("cuDeviceTotalMem_v2", [ctypes.POINTER(ctypes.c_size_t), ctypes.c_int])

CU_MEMHOSTALLOC_PORTABLE = 0x01
CU_STREAM_NON_BLOCKING = 0x01
CREATE_NO_WINDOW = 0x08000000

KIB = 1024
MIB = 1024 * 1024
GIB = 1024 * 1024 * 1024


def chk(rc, what):
    if rc != 0:
        raise SystemExit("CUDA error %d at %s" % (rc, what))


# ------------------------------------------------------------- link watcher

class LinkWatcher(threading.Thread):
    """Sample pcie.link.gen.current / width while the link is busy.

    This exists because the at-idle reading is a downshift artefact, so the
    only generation that means anything is the one observed under load.
    """

    def __init__(self, dev, period=0.30):
        threading.Thread.__init__(self, daemon=True)
        self.dev = dev
        self.period = period
        self.samples = []
        # NOT self._stop: threading.Thread already has an internal _stop
        # method, and shadowing it breaks Thread.join().
        self._done = threading.Event()

    def stop(self):
        self._done.set()

    def run(self):
        q = "pcie.link.gen.current,pcie.link.width.current"
        while not self._done.is_set():
            try:
                out = subprocess.run(
                    ["nvidia-smi", "--query-gpu=" + q, "--format=csv,noheader,nounits",
                     "-i", str(self.dev)],
                    capture_output=True, text=True, timeout=10,
                    creationflags=CREATE_NO_WINDOW)
                parts = [p.strip() for p in out.stdout.strip().split(",")]
                if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                    self.samples.append((time.time(), int(parts[0]), int(parts[1])))
            except Exception:
                pass
            self._done.wait(self.period)


def smi_static(dev):
    """gen.max / width.max / name - configuration, not the live link state."""
    q = "pcie.link.gen.max,pcie.link.width.max,name"
    try:
        out = subprocess.run(
            ["nvidia-smi", "--query-gpu=" + q, "--format=csv,noheader", "-i", str(dev)],
            capture_output=True, text=True, timeout=20,
            creationflags=CREATE_NO_WINDOW)
        return [p.strip() for p in out.stdout.strip().split(",")]
    except Exception:
        return ["?", "?", "?"]


# ------------------------------------------------------------------ bench

def run_size(hptr, hbuf, dptr, nbytes, iters, stream, direction):
    """Time iters copies of nbytes on an already-busy stream."""
    fn = cuMemcpyHtoDAsync if direction == "h2d" else cuMemcpyDtoHAsync
    src, dst = (hbuf, dptr) if direction == "h2d" else (dptr, hbuf)
    # warm the path so the first timed copy does not pay page-table setup
    for _ in range(2):
        chk(fn(dst, src, nbytes, stream), "warmup " + direction)
    chk(cuStreamSynchronize(stream), "warmup sync")

    t0 = time.perf_counter()
    for _ in range(iters):
        chk(fn(dst, src, nbytes, stream), direction)
    chk(cuStreamSynchronize(stream), "sync " + direction)
    dt = time.perf_counter() - t0
    total = float(nbytes) * iters
    return total / dt / 1e9, dt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default="adhoc", help="label recorded in the output")
    ap.add_argument("--dev", type=int, default=0)
    ap.add_argument("--json", default=None, help="write machine-readable results here")
    ap.add_argument("--max-gib", type=float, default=1.0,
                    help="size of the largest single transfer")
    args = ap.parse_args()

    chk(cuInit(0), "cuInit")
    ndev = ctypes.c_int()
    chk(cuDeviceGetCount(ctypes.byref(ndev)), "cuDeviceGetCount")
    dev = ctypes.c_int()
    chk(cuDeviceGet(ctypes.byref(dev), args.dev), "cuDeviceGet")

    name = ctypes.create_string_buffer(256)
    chk(cuDeviceGetName(name, 256, dev), "cuDeviceGetName")
    stat = smi_static(args.dev)

    print("=" * 74)
    print("pcie-bw.py  tag=%s  device=%d/%d" % (args.tag, args.dev, ndev.value))
    print("=" * 74)
    print("name          : %s" % name.value.decode(errors="replace"))
    print("gen.max/width : %s / %s" % (stat[0], stat[1]))
    print("")

    mem = ctypes.c_size_t()
    cuDeviceTotalMem(ctypes.byref(mem), dev)
    maxbuf = int(min(args.max_gib, 0.40) * GIB)
    maxbuf -= (maxbuf % MIB)
    if maxbuf < 4 * MIB:
        raise SystemExit("device too small for the requested buffer")

    ctx = ctypes.c_void_p()
    chk(cuCtxCreate(ctypes.byref(ctx), 0, dev), "cuCtxCreate")
    stream = ctypes.c_void_p()
    chk(cuStreamCreate(ctypes.byref(stream), CU_STREAM_NON_BLOCKING), "cuStreamCreate")

    dptr = ctypes.c_ulonglong()
    chk(cuMemAlloc(ctypes.byref(dptr), ctypes.c_size_t(maxbuf)), "cuMemAlloc")
    hptr = ctypes.c_void_p()
    chk(cuMemHostAlloc(ctypes.byref(hptr), ctypes.c_size_t(maxbuf),
                       CU_MEMHOSTALLOC_PORTABLE), "cuMemHostAlloc")

    print("pinned host   : %.0f MiB" % (maxbuf / MIB))
    print("device buffer : %.0f MiB" % (maxbuf / MIB))
    print("")

    # Touch both sides so neither is lazily faulted mid-measurement, and so
    # the host page is a real distinct pattern (no all-zero fast path).
    ctypes.memset(hptr, 0xA5, maxbuf)
    chk(cuMemsetD8(dptr, 0x5A, ctypes.c_size_t(maxbuf)), "cuMemsetD8")
    chk(cuStreamSynchronize(stream), "presync")

    # ------------------------------------------------------------- sweep
    sizes = [s for s in (4 * KIB, 64 * KIB, MIB, 16 * MIB, 256 * MIB, maxbuf)
             if s <= maxbuf]
    rows = []
    print("%-12s %-6s %10s %10s %9s %9s" %
          ("size", "dir", "GB/s", "seconds", "GiB", "gen seen"))
    print("-" * 74)

    for n in sizes:
        # aim for a few seconds per point regardless of size
        iters = int(max(64, min(4096, (4.0 * GIB) / n)))
        for direction in ("h2d", "d2h"):
            w = LinkWatcher(args.dev)
            w.start()
            gbps, dt = run_size(hptr, hptr, dptr.value, n, iters, stream, direction)
            w.stop()
            w.join(timeout=2.0)
            gens = [s[1] for s in w.samples]
            gen_seen = ("%d" % max(set(gens))) if gens else "?"
            rows.append({"bytes": n, "dir": direction, "gbps": gbps,
                         "seconds": dt, "gib": float(n) * iters / GIB,
                         "gen_under_load": sorted(set(gens))})
            print("%-12s %-6s %10.3f %10.3f %9.2f %9s" %
                  (_h(n), direction, gbps, dt, float(n) * iters / GIB, gen_seen))

    print("")
    print("-" * 74)

    # ------------------------------------------------- sustained window
    print("SUSTAINED 1 GiB x 24 (link kept busy for a clear generation reading)")
    w = LinkWatcher(args.dev, period=0.25)
    w.start()
    gbps, dt = run_size(hptr, hptr, dptr.value, maxbuf, 24, stream, "d2h")
    w.stop()
    w.join(timeout=2.0)
    gens = [s[1] for s in w.samples]
    gset = sorted(set(gens))
    print("  D2H  %.3f GB/s over %.2f s, %d samples" % (gbps, dt, len(gens)))
    if gens:
        print("  gen.current observed under load: %s (mode %d, samples %s)"
              % (gset, max(set(gens), key=gens.count),
                 " ".join(str(g) for g in gens)))
    rows.append({"bytes": maxbuf, "dir": "d2h-sustained", "gbps": gbps,
                 "seconds": dt, "gib": float(maxbuf) * 24 / GIB,
                 "gen_under_load": gset})

    # ------------------------------------------------------------ verdict
    best = max(r["gbps"] for r in rows)
    print("")
    print("=" * 74)
    print("VERDICT")
    print("=" * 74)
    print("  best transfer rate : %.3f GB/s" % best)
    print("  Gen1 x16 ceiling   : ~4.0 GB/s")
    print("  Gen2 x16 ceiling   : ~8.0 GB/s")
    print("  xrip 90HX Gen2 ref : 6.33 h2d / 6.40 d2h GB/s")
    if best >= 5.5:
        verdict = "Gen2-class: the link IS running above Gen1 whatever gen.current says at idle"
    elif best >= 3.3:
        verdict = "Gen1-class: the link is on Gen1 - our target"
    elif best >= 1.7:
        verdict = "Gen1-class but under x16: the link is also not at full width"
    else:
        verdict = "below Gen1 x16: link width is degraded, Gen2 is not the first problem"
    print("  ==> %s" % verdict)
    print("")
    print("  NOTE: gen.max = %s is a capability, not a state. It stays 2 whatever" % stat[0])
    print("  the link does. The transfer rate above is the physical measurement.")

    chk(cuMemFreeHost(hptr), "cuMemFreeHost")
    chk(cuMemFree(dptr.value), "cuMemFree")

    if args.json:
        out = {
            "tag": args.tag,
            "device": args.dev,
            "name": name.value.decode(errors="replace"),
            "gen_max": stat[0],
            "width_max": stat[1],
            "best_gbps": best,
            "verdict": verdict,
            "rows": rows,
        }
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)
        print("json: %s" % args.json)


def _h(n):
    if n >= GIB:
        return "%.0f GiB" % (n / GIB)
    if n >= MIB:
        return "%.0f MiB" % (n / MIB)
    return "%d KiB" % (n / KIB)


if __name__ == "__main__":
    main()
