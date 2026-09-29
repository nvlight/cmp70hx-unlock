# 🎮 NVIDIA CMP Unlock for Windows — CMP 70HX / 90HX

🇬🇧 English | [🇷🇺 Русский](README.ru.md)

Unlock the full computing and graphics power of the **NVIDIA CMP 70HX** (GA104, 8 GB, PCI ID `10de:248a`) or **CMP 90HX** (GA102, 10 GB, `10de:220d`) on any system with Windows — using a simple USB stick, an EFI bootloader, and **no reboots**.

The unlock runs **before any OS boots**, so Windows simply starts with the card already at full power.

> ℹ️ **Scope of this tree.** The source started out targeting the CMP 90HX. This
> port targets the **CMP 70HX**; the original 90HX is one command away
> (`TARGET=90HX bash build.sh`). Every card-specific number lives in a single
> `TARGET PROFILE` block at the top of `src/unlock_v2.c` and is *derived* from
> the framebuffer size. What is field-proven versus extrapolated is spelled out
> in [KNOWN-ISSUES.md](KNOWN-ISSUES.md) §13–16.

> ## 🚧 CMP 70HX status as of 2026-09-29 — UNLOCK CONFIRMED
>
> Measured with `llama-bench -m llama-2-7b.Q4_0.gguf -ngl 99 -p 512 -n 16`,
> same model, same card, clean runs:
>
> | | pp512 | tg16 |
> |---|---|---|
> | without the unlock (plain Windows boot) | 201.85 t/s | 32.50 t/s |
> | **with the unlock (EFI + USB stick)** | **2262.22 t/s** | **102.38 t/s** |
> | gain | **x11.25** | **x3.16** |
>
> Compute is unlocked. The earlier 3D measurements (GPU-Z render test at
> **75 W**, Cyberpunk at 9 FPS) are *not* affected by the unlock and were
> never a valid success criterion: PGRAPH on CMP parts is gated by the
> compute-only GSP-RM firmware, independently of the selectors
> (bendy2's BAR0 analysis of five cards: PGRAPH top config is byte-identical
> to an RTX 3090, so the silicon is there and simply is not initialised).
>
> ```
> STG    selectors: want SS0=0x88888888 SS1=0x00000008 | got SS0=0x88888888 SS1=0x00000008 written OK
> END    ss0=0x88888888 ss1=0x00000008 PLM=0xFFFFFFFF
> ```
>
> Those two lines alone prove nothing — `is_selectors_written()` is a
> tautology and the application prints ТАВТОЛОГИЯ itself. The proof is the
> table above. What is still open (second card, graphics, the 2262-vs-3705
> gap to the 90HX) is in
> [docs/70HX-PORT-STATUS.md](docs/70HX-PORT-STATUS.md).
>
> The figures quoted below are from the field-proven **90HX** build.
> PCIe Gen2 is off by default ([PORT-STATUS §3a](docs/70HX-PORT-STATUS.md));

> ⚠️ **Honest expectations:** this is a mining card, and it is *not* a gaming
> GPU replacement — no display outputs, PCIe Gen1 ×16 in the current release,
> and gaming requires a community-patched driver (see below). Compute/AI is
> what it excels at after the unlock. Details in [KNOWN-ISSUES.md](KNOWN-ISSUES.md).

## What are the CMP 70HX / 90HX?

Both are GA10x dies sold by NVIDIA as **"mining-only" cards**. NVIDIA crippled them in firmware: performance is a fraction of what the die can do. The typical locked card delivers ~230 t/s on llama-bench; an unlocked 90HX delivers **~3700 t/s** (16× more).

This project re-enables the die's **compute** performance using an EFI application that runs from the bootable USB, before the OS loads. **It is open source** — see [`src/`](src/) and [BUILDING.md](BUILDING.md).

**What is actually unlocked on the 70HX** ([PORT-STATUS §1k](docs/70HX-PORT-STATUS.md)):

| | state |
|---|---|
| compute | **unlocked**, ×11.25 on `pp512` |
| lock mechanism | **issue-rate cap of 1/32** on FP32 and DP4A, fully lifted |
| peripheral issue rate | **91–99.8 % of architectural peak**, no residual limits |
| clock | 1545 MHz under load, no throttling, not the limiting factor |
| cores | 3840 CUDA cores of 6144; the A/B is **done — the unlock does not change it** |
| graphics | **not unlocked**: 75 W, 9 FPS. Blocked by firmware, independently of the selectors |

The A/B is the key result: a locked card delivers exactly **1/32** of peak
on FP32 and DP4A (3.99 of 128, 2.00 of 64), while FP16, BF16 and INT32 are
never limited at all. So the lock is an issue-rate cap, not disabled cores,
and this unlock removes it completely.

That is the "compute limitations only" class, the same one bendy2 targets. For comparison, an unlocked **CMP 50HX** (GA107) on dartraiden's patched drivers also loses the graphics lock: 230 W under load, 3D playable, LLMs fast. So 50HX is ahead on graphics, and closing that on 70HX looks like separate work.

## How the unlock works

1. **Preload.** The Windows boot manager (`bootmgfw.efi`) is read into RAM using raw block I/O and a built-in FAT32 parser. (No UEFI SimpleFileSystem is used — it hangs on some AMI boards.)
2. **Unlock.** A custom EFI application drives the GPU's SEC2 (Falcon) microcontroller through its secure boot sequence:
   - opens the memory-write-protection registers (WPR2),
   - loads a signed "canary" payload (V67) into the SEC2 booter,
   - opens the GPU's protected mode (PLM),
   - sets the compute selectors (SS0/SS1) and render masks.
3. **Reset.** A Function Level Reset (FLR) clears the latched protection registers while the compute selectors survive.
4. **Boot.** The app returns into the firmware without a POST, and Windows loads with the card already unlocked. **The system is never rebooted** — a POST would reset the GPU and drop the unlock.

The exploit itself: the NVIDIA-signed SEC2 booter has a stack-canary bug (Jon Pry, *"A Canary in the Crypto Mine"*). When it validates our oversized 64 KB "signature", execution runs into a ROP chain that performs arbitrary privileged register writes — including PLM open.

## What happens after you pick the USB in the boot menu (F12)

| Scenario | Result |
|---|---|
| **Windows boots** | The unlock ran, and Windows loads with the card at full power. ✅ |
| **Back to the boot menu** | If the chainload path can't proceed, the app returns to the firmware **without rebooting**, so you can pick any other boot device. The unlock state persists until the next full reboot (POST). |

## Test results

Verified on two real systems.

### llama-bench (CUDA, llama-2-7B Q4_0, `-ngl 99`)
```
| model        | size     | params | backend | ngl | test  | t/s              |
| llama 7B Q4_0| 3.56 GiB | 6.74 B | CUDA    | 99  | pp512 | 3705.40 ± 410.21 |
| llama 7B Q4_0| 3.56 GiB | 6.74 B | CUDA    | 99  | tg16  | 139.20 ± 2.56    |
```
Device 0: NVIDIA CMP 90HX, compute capability 8.6, VRAM: **10239 MiB** (full 10 GB).

### Gaming (with caveats!)

**Resident Evil Requiem** was tested and is playable when streamed via Moonlight (screenshot and HWiNFO log in [`tests/`](tests/)):

| Metric | Value |
|---|---|
| FPS | **31 – 63**, average **48.7** |
| GPU core clock | **1875 MHz** (full boost) |
| VRAM in use | up to **6.9 GB** of 10 GB |
| GPU power draw | up to **145 W** |
| GPU temperature | 44 – 57 °C |

That session used soldered capacitors (hardware mod) and PCIe Gen 1 ×16. Treat gaming as a bonus: no display outputs on the card, limited link bandwidth, and a patched driver is mandatory.

### Modified driver for rendering/gaming

The stock NVIDIA driver still blocks CMP cards from rendering (the restriction lives in the driver too, not only the firmware). To run graphics after the unlock, install a patched NVIDIA driver:

👉 **[https://github.com/dartraiden/NVIDIA-patcher](https://github.com/dartraiden/NVIDIA-patcher)**

## Requirements

- NVIDIA CMP 70HX (PCI ID `10de:248a`) **or** CMP 90HX (`10de:220d`)
- UEFI motherboard with a boot menu (F12)
- Windows installed on a GPT disk with an EFI System Partition
- **Secure Boot disabled** (the loader is unsigned)
- A USB stick (≥ 256 MB)
- `gsp_ga10x.bin` from the NVIDIA **610.43.03** driver package on the stick,
  next to `BOOTX64.EFI`

## Installation

1. Download the latest release image from the [Releases](https://github.com/WildFlash1st/cmp90hx-unlock-for-windows/releases) page.
2. Write the image to the USB stick with [Balena Etcher](https://etcher.balena.io/), [Rufus](https://rufus.ie/) (DD mode), or `dd`:
   ```bash
   dd if=<image>.img of=/dev/sdX bs=4M status=progress
   ```
   ⚠️ Double-check the device name — this wipes the target stick!
3. Verify the md5 against the one published with the release.
4. Reboot, press **F12** (or your board's boot-menu key), select the USB stick.
5. The unlock runs automatically — Windows loads at full power. No keys to press, nothing to configure.
6. *(For rendering/games only)* Install the patched NVIDIA driver from [NVIDIA-patcher](https://github.com/dartraiden/NVIDIA-patcher).

### Re-applying after a reboot

The unlock is **volatile**: a full reboot (POST) resets the GPU. To unlock again, simply boot from the USB stick again and let it chainload Windows. That's it.

## Building from source

```bash
git clone https://github.com/WildFlash1st/cmp90hx-unlock-for-windows
cd cmp90hx-unlock-for-windows/src
BLOBS=/path/to/blobs bash build.sh               # CMP 70HX (default)
TARGET=90HX BLOBS=/path/to/blobs bash build.sh   # original CMP 90HX
```

`TARGET` selects the card profile in the `TARGET PROFILE` block at the top of
`unlock_v2.c` (PCI ID, framebuffer size, and the derived FRTS/WPR2 geometry)
and links the matching FWSEC blob. The boot banner always names the card, its
PCI ID, FB size, FRTS offset and WPR2 pair — if that line does not say
`CMP 70HX (GA104) 10de:248A`, the wrong build is on the stick.

See **[BUILDING.md](BUILDING.md)** for prerequisites, blob provenance, the
objcopy section-list trap, and the USB-image recipe. **[BUILDING.md §6](BUILDING.md)**
is normative for the build→flash→pull-log loop: after any source change the
stick is rewritten and verified, and after every boot the log is pulled and
read — both without asking. Known limitations and
unsolved problems live in **[KNOWN-ISSUES.md](KNOWN-ISSUES.md)**.

## Repository layout

- `src/unlock_v2.c` — the entire EFI application (all build variants come from
  it); the `TARGET PROFILE` block at the top is the only place with
  card-specific constants
- `src/build.sh` — build script (gnu-efi, `TARGET=70HX|90HX`); `src/tools/` — firmware extraction helpers
- `docs/` — platform gotchas, register/geometry notes, Code 43 diagnostic report, blob patching procedure
- `docs/70HX-FINAL-SUMMARY.md` — **where the CMP 70HX port stands**: what is proven, what was disproved, what is left
- `docs/70HX-PORT-STATUS.md` — **CMP 70HX port status**: what works, what doesn't, the `WPR2` blocker
- `docs/70HX-VBIOS-ANALYSIS.md` — **teardown of the 70HX VBIOS**: FWSEC signatures, the `DMEM_MAPPER_V3` layout
- `docs/70HX-NEXT-STEPS.md` — **step plan** with a success criterion for every experiment
- `docs/70HX-DRIVER-ANALYSIS.md` — **teardown of the 610.43.03 driver**: formula confirmations and the found `WPR_END_MARGIN`
- `docs/FLASH-AND-LOG.md` — **procedure**: writing the loader to the stick, verifying it, pulling the log
- `docs/LOGGING.md` — **logging mechanics**: on-disk format, the write path in `unlock_v2.c`, the read path in `out/read-log.ps1`, the keep-in-sync contract between them, log diagnostics
- `tests/` — proof artifacts: game screenshot, HWiNFO log, llama-bench output
- `out/` — `.efi` builds produced here for both cards
- Release images are attached to the [Releases](https://github.com/WildFlash1st/cmp90hx-unlock-for-windows/releases) page

## Credits

This unlock builds on years of public research and tooling. Special thanks to:

- **[bendy2](https://github.com/bendy2/cmp90hx)** — the V67 exploit and the direct-compute patch for driver `580.159.03` — *the key that opened PLM*
- **Jon Pry (Zenodo)** — *"A Canary in the Crypto Mine: Defeating Stack Protection in a GPU Secure Coprocessor"* ([DOI: 10.5281/zenodo.20916112](https://zenodo.org/records/20916112)) — the debug-booter overflow disclosure
- **[cmpunlocker](https://github.com/jdowning100/cmpunlocker)** — the rejoin16 PLM/render-mask method and Gen2 research this project ports
- **d3dx9** — the Python Falcon emulator & ROP chain

## Donations

This project took many nights of reverse engineering. If it helped you, consider supporting further development:

- **TON (Gram):** `UQCuMe07ZsrRpo6q5UdXw4y-AANG2nN8QJGpM8IZkf9M78yH`
- **Litecoin:** `LTC1QTA33QANK4L6JLDVRCR9WP4C8MT555V3FA0RX5M`

Thank you! 🙏

## Disclaimer

This project is for **educational and research purposes**. It modifies GPU behavior, may void warranties, and interacts with signed firmware in ways NVIDIA did not intend. Use at your own risk. The authors are not responsible for any damage, instability, or loss caused by using this software.
