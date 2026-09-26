# Known issues & unsolved problems

An honest list of what does **not** work or remains unverified, as of the
v3.03 release (2026-08-25) plus the CMP 70HX port. See also `docs/GOTCHAS.md`
(platform quirks digest), `docs/REGISTERS.md` (framebuffer/WPR2 geometry) and
`docs/DIAG-REPORT-2026-08-25-CODE43.md` (the Code 43 root cause).

## Fundamental

1. **The unlock is volatile.** Any full reboot (POST re-runs VBIOS) re-locks
   the card. You must boot from the USB stick every cold start. No persistent
   mechanism was found — the masks survive FLR but not POST by design.

2. **PCIe stays at Gen1 x16 in the current release.** The card is silicon-
   clamped to 5 GT/s max, and raising the link requires a pre-OS gen2 config
   phase (`PCIE_GEN2_REJOIN` without `FULL_NOGEN2`, i.e. the v3.02-full
   build) that is currently **excluded** because of issue 3. Measured cost:
   ~3.3 GB/s host↔GPU transfer instead of ~6.6 GB/s at Gen2 x16.

3. **Code 43 regression history of v3.02-full.** Its fire-path could hand
   Windows a GPU with latched WPR2 + live SEC2 ROP spinner → GSP-RM fails to
   start → bugcheck 0x1B0/C000009A → Code 43. Root-caused and fixed in
   v3.03 (tail cleanup: kill SEC2, final FLR, no MMIO after FLR, no NVRAM
   access). The gen2 domain stays disabled until it is re-proven separately.

4. **v3.03 render path was QEMU-confirmed, not yet confirmed on real
   hardware** at release time. Compute-only v3.01 and the general flow are
   real-HW proven; report your results if you run v3.03 on metal.

## Constraints

5. **Secure Boot must be disabled** — the loader is unsigned. There are no
   plans to sign it (Microsoft would not sign this anyway).

6. **Gaming is not what this card is for.** The CMP cards have no display
   outputs, run PCIe Gen1 x16 here, and rendering additionally requires a
   community-patched NVIDIA driver ([dartraiden/NVIDIA-patcher](https://github.com/dartraiden/NVIDIA-patcher)).
   It works (see README test results) but treat it as a bonus, not the use
   case. Compute/AI is the target.

7. **One card per boot iteration in multi-card systems.** `MULTI_CARD`
   unlocks cards sequentially using NVRAM iteration + return-to-firmware;
   all cards end up unlocked without rebooting, but it takes one pass each.
   Note: in v3.03 the fire path (render-mask table) did not advance the
   card index, so on systems that enter fire mode the cycle froze after the
   first fire card — remaining cards stayed locked. Fixed in the current
   source (the fire path now advances the index, and a cold boot restarts
   the cycle at card 0); rebuild required to pick up the fix.

## Unsolved / workaround-in-place

8. **SimpleFileSystem hangs on AMI F37d (X570 GAMING X).** Any SFS call from
   a loaded application can hang the firmware. Worked around with our own
   FAT32-over-BlockIo parser and a "return to firmware" exit instead of
   chainloading. Never root-caused inside AMI.

9. **NVRAM writes hang the platform once the GPU is in post-unlock state**
   (SMM touches the GPU). Exit-time `SetVariable`/BootNext had to be removed
   (lesson v2.99o). This is why the app simply returns into BDS.

10. **Mask-table stragglers.** Some protected registers only take their
    exact `0xFFFFFFFF` value on a second/third multipass attempt, the OPTB
    block (`0x8200d0..f4`) hard-hangs guests when written (skipped, matching
    upstream cmpunlocker findings), and the `0x8E1DC`/XVE_D* family reads
    back RO patterns regardless — cosmetic, functionally irrelevant.

11. **A live GSP guards the PCIe link registers** on the QEMU stand (writes
    to TLS/LNKCTL2 are discarded after the OS driver starts GSP). Pre-OS
    configuration avoids this on real hardware; post-OS Gen2 recovery from a
    fully cold state remains out of scope.

12. **Host-side quirk:** `nvidia-persistenced` does not work with driver 610
    on this card ("Failed to query NVIDIA devices"); use legacy persistence
    mode (`nvidia-smi -pm 1`) instead.

## Scope

13. **This tree targets the CMP 70HX (GA104, 8 GB, `10de:248a`)**, and the
    CMP 90HX (GA102, 10 GB, `10de:220d`) is still one `TARGET=90HX` away. All
    framebuffer-derived constants live in one `TARGET PROFILE` block at the top
    of `src/unlock_v2.c` and are *derived*, not hand-copied — see
    `docs/REGISTERS.md`. Other CMP SKUs (90HXA, 170HX, GA103/GA106/GA107…)
    are not covered: add a line to that block and rebuild.

14. **The 70HX port is unverified on metal.** What is solid: the framebuffer
    geometry is the driver's own formula applied to an 8 GB FB
    (`frtsOffset=0x1FFE00000`), the register offsets are shared GA10x-wide,
    and both target builds compile and produce a structurally valid PE. What
    is *inferred*, from a single measurement on the 10 GB card: the WPR2
    encoding (`lo = frtsOffset>>8`, `hi = lo+0xE00`). If the FWSEC WPR2 poll
    times out on a 70HX, the log prints the observed `wpr2lo`/`wpr2hi` every
    200 ms — paste those two numbers into `TARGET_WPR2_LO/HI` and rebuild.

15. **The GSP firmware blob still has to come from the right package.** The
    app reads `gsp_ga10x.bin` off the stick; the chip is picked inside that
    image, so the same file serves GA102 and GA104. The `.fwimage` offset and
    size are now parsed out of its ELF instead of being hardcoded, so a
    differently-sized firmware from another driver package also works as long
    as it fits the 0x5060000 read window.

16. **`.rodata` must survive the final objcopy.** gcc puts every `Print()`
    literal in `.rodata`; if the PE is built without it the app runs but
    prints *nothing* — no banner, no WPR2/PLM values. `src/build.sh` lists the
    sections explicitly for this reason. Do not "simplify" that back to a
    `.rel*`/`.rela*` glob: it pulls in `.rela.plt`, whose 9-character name does
    not fit a PE section header, and objcopy emits a bogus `/4` name.
