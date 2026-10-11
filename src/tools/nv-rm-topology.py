#!/usr/bin/env python3
"""Query NVIDIA RM's effective GA104 GR topology without SET controls.

This deliberately uses only RM GET commands.  It still creates an ordinary
RM client plus device/subdevice objects, so run it only after the NVIDIA
kernel modules have initialized the card.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import platform
import subprocess
import sys
from typing import Any, Callable


PINNED_TINYGRAD = "2ff83c7f9081aef1f6e557d4b842f465885fdd5f"
TARGET_VENDOR = 0x10DE
TARGET_DEVICE = 0x248A
GPC_COUNT = 6


def fail(message: str) -> "None":
    raise SystemExit(f"ERROR: {message}")


def git_head(path: Path) -> str | None:
    try:
        return subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None


def hex32(value: int) -> str:
    return f"0x{int(value):08X}"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Query-only NVIDIA RM census for CMP 70HX (10de:248a)."
    )
    parser.add_argument("--tinygrad", type=Path, required=True,
                        help="tinygrad checkout pinned by docs/RM-TOPOLOGY.md")
    parser.add_argument("--index", type=int, default=0,
                        help="NVIDIA RM-visible GPU index (default: 0)")
    parser.add_argument("--allow-unpinned", action="store_true",
                        help="permit a tinygrad commit other than the tested pin")
    args = parser.parse_args()

    if platform.system() != "Linux":
        fail("native Linux is required")
    try:
        release = Path("/proc/sys/kernel/osrelease").read_text(encoding="ascii").lower()
    except OSError as exc:
        fail(f"cannot identify the kernel: {exc}")
    if "microsoft" in release or "wsl" in release:
        fail("WSL is not supported; boot native Linux with the NVIDIA kernel driver")
    for node in ("/dev/nvidiactl", "/dev/nvidia-uvm"):
        if not Path(node).exists():
            fail(f"missing {node}; load a compatible NVIDIA driver first")

    tinygrad = args.tinygrad.resolve()
    if not (tinygrad / "tinygrad" / "runtime" / "ops_nv.py").is_file():
        fail(f"not a tinygrad checkout: {tinygrad}")
    head = git_head(tinygrad)
    if head != PINNED_TINYGRAD and not args.allow_unpinned:
        fail(f"tinygrad HEAD is {head or 'unknown'}, expected {PINNED_TINYGRAD}; "
             "use --allow-unpinned only after reviewing API compatibility")
    sys.path.insert(0, str(tinygrad))

    try:
        import tinygrad.runtime.ops_nv as ops  # type: ignore
    except Exception as exc:
        fail(f"cannot import tinygrad NVIDIA runtime: {exc}")

    # NVKIface performs ordinary RM/UVM client initialization.  Unlike
    # NVDevice, this path does not create a graphics channel or issue
    # PERF_BOOST.  Only device/subdevice handles needed by GET controls follow.
    try:
        iface = ops.NVKIface(None, args.index)
        nv = ops.nv_gpu
        card = iface.gpus_info[args.index]
    except Exception as exc:
        fail(f"NVIDIA RM initialization failed: {exc}")

    vendor_id, device_id = int(card.pci_info.vendor_id), int(card.pci_info.device_id)
    bdf = (f"{int(card.pci_info.domain):04x}:{int(card.pci_info.bus):02x}:"
           f"{int(card.pci_info.slot):02x}.{int(card.pci_info.function)}")
    if (vendor_id, device_id) != (TARGET_VENDOR, TARGET_DEVICE):
        fail(f"GPU index {args.index} is {vendor_id:04x}:{device_id:04x} at {bdf}, "
             "not the CMP 70HX target 10de:248a")

    try:
        dev_params = nv.NV0080_ALLOC_PARAMETERS(
            deviceId=iface.gpu_instance, hClientShare=iface.root,
            vaMode=nv.NV_DEVICE_ALLOCATION_VAMODE_OPTIONAL_MULTIPLE_VASPACES,
        )
        nvdevice = iface.rm_alloc(iface.root, nv.NV01_DEVICE_0, dev_params)
        subdevice = iface.rm_alloc(nvdevice, nv.NV20_SUBDEVICE_0,
                                   nv.NV2080_ALLOC_PARAMETERS())
    except Exception as exc:
        fail(f"cannot allocate query handles: {exc}")

    results: dict[str, Any] = {
        "format": 1,
        "target": {
            "index": args.index, "bdf": bdf,
            "vendor_id": f"0x{vendor_id:04X}",
            "device_id": f"0x{device_id:04X}",
        },
        "tinygrad": {"head": head, "pinned": head == PINNED_TINYGRAD},
        "kernel": release.strip(),
        "queries": {},
        "errors": {},
    }

    def query(name: str, cmd: int, params: Any,
              extract: Callable[[Any], Any]) -> None:
        try:
            out = iface.rm_control(subdevice, cmd, params)
            results["queries"][name] = extract(out)
        except Exception as exc:
            results["errors"][name] = str(exc)

    query("gpc_mask", nv.NV2080_CTRL_CMD_GR_GET_GPC_MASK,
          nv.NV2080_CTRL_GR_GET_GPC_MASK_PARAMS(),
          lambda p: {"gpcMask": hex32(p.gpcMask)})
    query("phys_gpc_mask", nv.NV2080_CTRL_CMD_GR_GET_PHYS_GPC_MASK,
          nv.NV2080_CTRL_GR_GET_PHYS_GPC_MASK_PARAMS(physSyspipeId=0),
          lambda p: {"physSyspipeId": int(p.physSyspipeId),
                     "gpcMask": hex32(p.gpcMask)})
    query("gfx_gpc_tpc", nv.NV2080_CTRL_CMD_GR_GET_GFX_GPC_AND_TPC_INFO,
          nv.NV2080_CTRL_GR_GET_GFX_GPC_AND_TPC_INFO_PARAMS(),
          lambda p: {"physGfxGpcMask": hex32(p.physGfxGpcMask),
                     "numGfxTpc": int(p.numGfxTpc)})
    query("rop_info", nv.NV2080_CTRL_CMD_GR_GET_ROP_INFO,
          nv.NV2080_CTRL_GR_GET_ROP_INFO_PARAMS(),
          lambda p: {"ropUnitCount": int(p.ropUnitCount),
                     "ropOperationsFactor": int(p.ropOperationsFactor),
                     "ropOperationsCount": int(p.ropOperationsCount)})
    query("zcull_info", nv.NV2080_CTRL_CMD_GR_GET_ZCULL_INFO,
          nv.NV2080_CTRL_GR_GET_ZCULL_INFO_PARAMS(),
          lambda p: {field: int(getattr(p, field)) for field in (
              "widthAlignPixels", "heightAlignPixels", "pixelSquaresByAliquots",
              "aliquotTotal", "zcullRegionByteMultiplier", "zcullRegionHeaderSize",
              "zcullSubregionHeaderSize", "subregionCount",
              "subregionWidthAlignPixels", "subregionHeightAlignPixels")})

    for gpc in range(GPC_COUNT):
        query(f"gpc{gpc}_tpc_mask", nv.NV2080_CTRL_CMD_GR_GET_TPC_MASK,
              nv.NV2080_CTRL_GR_GET_TPC_MASK_PARAMS(gpcId=gpc),
              lambda p, gpc=gpc: {"gpcId": gpc, "tpcMask": hex32(p.tpcMask)})
        query(f"gpc{gpc}_tpc_reconfig", nv.NV2080_CTRL_CMD_GR_GET_TPC_RECONFIG_MASK,
              nv.NV2080_CTRL_GR_GET_TPC_RECONFIG_MASK_PARAMS(gpc=gpc),
              lambda p, gpc=gpc: {"gpc": gpc,
                                  "tpcReconfigMask": hex32(p.tpcReconfigMask)})
        query(f"gpc{gpc}_zcull_mask", nv.NV2080_CTRL_CMD_GR_GET_ZCULL_MASK,
              nv.NV2080_CTRL_GR_GET_ZCULL_MASK_PARAMS(gpcId=gpc),
              lambda p, gpc=gpc: {"gpcId": gpc,
                                  "zcullMask": hex32(p.zcullMask)})

    def global_sm(p: Any) -> dict[str, Any]:
        count = min(int(p.numSm), len(p.globalSmId))
        return {
            "numSm": int(p.numSm), "numTpc": int(p.numTpc),
            "order": [{field: int(getattr(p.globalSmId[i], field)) for field in (
                "gpcId", "localTpcId", "localSmId", "globalTpcId",
                "virtualGpcId", "migratableTpcId", "ugpuId",
                "physicalCpcId", "virtualTpcId")} for i in range(count)],
        }

    query("global_sm_order", nv.NV2080_CTRL_CMD_GR_GET_GLOBAL_SM_ORDER,
          nv.NV2080_CTRL_GR_GET_GLOBAL_SM_ORDER_PARAMS(), global_sm)

    # These answers are sufficient to compare RM's graphics topology with the
    # UEFI census.  GET_PHYS_GPC_MASK may require elevated privileges and
    # GET_TPC_RECONFIG_MASK is not implemented on every GA104 RM branch; those
    # failures remain visible in JSON but do not make a complete core census
    # fail.  ROP/ZCULL are useful ancillary facts, not part of the 15-TPC
    # acceptance criterion.
    required = {"gpc_mask", "gfx_gpc_tpc", "global_sm_order"}
    required.update(f"gpc{gpc}_tpc_mask" for gpc in range(GPC_COUNT))
    missing = sorted(required - results["queries"].keys())
    results["verdict"] = {
        "coreTopologyComplete": not missing,
        "missingRequiredQueries": missing,
        "optionalQueryErrors": sorted(results["errors"].keys()),
    }

    print(json.dumps(results, indent=2, sort_keys=True))
    return 2 if missing else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
