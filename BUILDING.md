# Building from source

All build variants come from a single source file, `src/unlock_v2.c`, compiled
with [gnu-efi](https://github.com/ncroxon/gnu-efi). Build flags are
load-bearing: they decide which phases even exist in the binary (see the flag
table below — v3.01 was accidentally compute-only because one flag was
missing).

**Target.** The default build targets the **CMP 70HX (GA104, 8 GB,
`10de:248a`)**. `TARGET=90HX` rebuilds the original **CMP 90HX (GA102, 10 GB,
`10de:220d`)**. Everything card-specific — PCI ID, framebuffer size, FRTS
offset, the WPR2 window FWSEC has to latch — lives in one `TARGET PROFILE`
block at the top of `unlock_v2.c` and is derived from the FB size, so the two
targets cannot drift apart. See `docs/REGISTERS.md` for the geometry and
`KNOWN-ISSUES.md` for what is proven on metal vs inferred.

## 1. Prerequisites

```bash
# Debian/Ubuntu
apt install build-essential gnu-efi python3
```

Tested with gcc 12 and gnu-efi 3.0.15 on x86_64 Linux; also builds clean with
gnu-efi 4.0.0 / binutils 2.42 (that combination needs the explicit objcopy
input format and section list described in §3).

## 2. Firmware/payload blobs (not distributed here)

The blobs are embedded into the binary at link time. They are **not** in this
repository: most of them are extracted from NVIDIA's signed driver/VBIOS
images, and one is an exploit payload. You have to produce them yourself:

| Blob | Size | What it is / where it comes from |
|---|---|---|
| `v67_payload.bin` | `0xFA00` | The oversized "signature" that trips the booter canary bug. From bendy2's public CMP90HX research (see README credits). |
| `booter_ucode_prod_patched.bin` | `0xEC00` | SEC2 booter ucode from driver **bindata** (`BINDATA_LABEL_IMAGE_PROD`), with `SIG_PROD[0]` patched at offset `0x8A10`. Procedure: [docs/RE-PATCH-PROCEDURE.md](docs/RE-PATCH-PROCEDURE.md). |
| `booter_ucode_dbg_patched.bin` | `0xEC00` | Same for the DBG variant (`BINDATA_LABEL_IMAGE_DBG` + `SIG_DBG[0]`). Rejected by PROD fuses in the real flow, but still linked/referenced. |
| `gsp_rm_boot_dbg.bin` | `0x6000` | GSP bootloader (GspRmBoot) extracted from the driver. |
| `fwsec_ga104.bin` + `fwsec_ga104_sig.bin` | `0xEA00` + `0x180` | FWSEC ucode + signature from a **GA104** VBIOS, with [`src/tools/extract_fwsec_ga104.py`](src/tools/extract_fwsec_ga104.py). **Must match the build target** — this blob is per-die. For `TARGET=90HX` use `fwsec_ga102*.bin` from [`extract_fwsec.py`](src/tools/extract_fwsec.py) instead. |
| `sec2_ucode_vbios_49_patched.bin` / `_89_` | ~20 KB each | SEC2 ucode appid `0x49`/`0x89` from VBIOS, sig[2] patched. Only used by dev-experiment stages. |

Put the files into a directory and point the build at it. `build.sh` picks the
right FWSEC pair from `TARGET`, so the default (70HX) layout is:

```
blobs/
├── v67_payload.bin
├── booter_ucode_dbg_patched.bin
├── booter_ucode_prod_patched.bin
├── gsp_rm_boot_dbg.bin
├── fwsec_ga104.bin
├── fwsec_ga104_sig.bin
├── sec2_ucode_vbios_49_patched.bin
└── sec2_ucode_vbios_89_patched.bin
```

Additionally you need `gsp_ga10x.bin` at runtime (NOT embedded) — copy it from
the NVIDIA **610.43.03** package (`/lib/firmware/nvidia/610.43.03/gsp_ga10x.bin`)
to the USB stick next to `BOOTX64.EFI`.

## 3. Build

```bash
cd src
BLOBS=/path/to/blobs bash build.sh              # CMP 70HX / GA104 / 8 GB (default)
TARGET=90HX BLOBS=/path/to/blobs bash build.sh  # CMP 90HX / GA102 / 10 GB
```

`TARGET` selects the card profile in the `TARGET PROFILE` block at the top of
`unlock_v2.c` (device ID, framebuffer size, and the derived FRTS/WPR2
geometry) and picks the matching FWSEC blob. The banner printed at boot always
names the card, its PCI ID, FB size, FRTS offset and WPR2 pair — if that line
does not say `CMP 70HX (GA104) 10de:248A`, you flashed the wrong build.

Outputs (all built from the same `unlock_v2.c`):

| Binary | Flags | Notes |
|---|---|---|
| `unlock_v3n.efi` | `RELEASE_BUILD MULTI_CARD PCIE_GEN2_REJOIN FULL_NOGEN2` | **Current release (v3.03)** — use this on real hardware |
| `unlock_v3f.efi` | `…PCIE_GEN2_REJOIN` | v3.02-full: adds gen2 link config; known Code 43 issue, see KNOWN-ISSUES |
| `unlock_v3.efi` | `RELEASE_BUILD MULTI_CARD` | v3.01: compute-only (no render table!) |
| `unlock_v2.efi` | dev | Interactive pauses, gen experiments |
| `unlock_v2_test.efi`, `unlock_v3n_test.efi` | +`EFI_AUTOTEST` | QEMU test stand |
| `unlock_v2_wr.efi` | `ENDGAME_WARMRESET` | Plan-B endgame, unused |

Checksums differ from the published 90HX releases — the source has changed
since v3.04 and `build.sh` now emits `.rodata` (see below). Compare the
printed banner, not the md5.

### objcopy section list — do not "simplify" it

The final ELF→PE step lists sections **explicitly**:

```bash
objcopy -I elf64-x86-64 \
    -j .text -j .sdata -j .data -j .rodata \
    -j .dynamic -j .dynsym -j .reloc -j .rela \
    -O pei-x86-64 --subsystem=10 --image-base=0 ...
```

* `.rodata` holds every `Print()` literal. Omit it and the app still runs but
  prints **nothing** — no banner, no WPR2/PLM/SS0 values. That output is the
  only way to tell a 70HX apart from a 90HX and to read the FWSEC poll.
* Do not replace the list with `-j .rel*` / `-j .rela*`: that also matches
  `.rela.plt`, whose 9-character name does not fit a PE section header, so
  objcopy writes a bogus `/4` string-table reference into the section table.
* `-I elf64-x86-64` is required on binutils ≥ 2.40; without it objcopy guesses
  the input format and fails with `file format not recognized`.
* Use `-O pei-x86-64`, not the long `--target=` form, with `-j` in between.

## 4. Make the USB image

Classic **MBR + FAT32 with partition type `0xEF`** — both details matter:
GPT images break on sticks with stale backup-GPT tails, and some AMI firmwares
refuse to enumerate removable USB as a boot option unless the MBR partition
type is EFI System.

```bash
IMG=cmp70hx-unlock.img
truncate -s 256M $IMG
printf 'label: dos\nunit: sectors\n\n%s1 : start=2048, size=522240, type=ef, bootable\n' "$IMG" | sfdisk $IMG
LOOP=$(losetup -P -f --show $IMG)
mkfs.vfat -F 32 -n CMP70UNLOCK "${LOOP}p1"
mount "${LOOP}p1" /mnt/img
mkdir -p /mnt/img/EFI/BOOT
cp unlock_v3n.efi /mnt/img/EFI/BOOT/BOOTX64.EFI
cp /lib/firmware/nvidia/610.43.03/gsp_ga10x.bin /mnt/img/
sync && umount /mnt/img && losetup -d "$LOOP"
```

Write with `dd` to the whole stick (Rufus DD-mode / balenaEtcher also work).

## 5. Verify before flashing

Historical trap: an "updated" image shipped with the OLD bootloader inside.
Always check the content of the image, not just the file:

```bash
LOOP=$(losetup -P -f --show $IMG); mount "${LOOP}p1" /mnt/img
md5sum /mnt/img/EFI/BOOT/BOOTX64.EFI          # == md5sum unlock_v3n.efi
# must be True: proves the target profile AND that .rodata (the Print strings)
# survived the objcopy. If it is False the image is a stale or stripped build.
python3 -c "print('CMP 70HX (GA104)'.encode('utf-16-le') in open('/mnt/img/EFI/BOOT/BOOTX64.EFI','rb').read())"
umount /mnt/img; fsck.vfat -n "${LOOP}p1"; losetup -d "$LOOP"
```

The same check in one line, for either target:

```bash
python3 -c "import sys;d=open('unlock_v3n.efi','rb').read();\
print('card profile embedded:', 'CMP 70HX (GA104)' if 'CMP 70HX (GA104)'.encode('utf-16-le') in d else ('CMP 90HX (GA102)' if 'CMP 90HX (GA102)'.encode('utf-16-le') in d else 'MISSING -> .rodata was dropped'))"
```

## 6. Standing obligations after every build and every boot

**This section is normative. Whoever drives the build-and-test loop — a human
or an AI agent — follows it without asking for permission each time.** These
steps are the difference between a verified change and a change that is merely
compiled. Skipping them makes logs lie: you end up reading a log written by
the *previous* build and drawing conclusions from it.

### 6.0 The rollback must stay byte-identical — CHECK IT EVERY BUILD

`unlock_v3n.efi` is the only way back. Expected:

```
md5    1863C4B1EBB8BF038A5C630001BB671A
size   648192 bytes
```

**This breaks silently and without a size change.** In one session it broke
twice, and both times the file was still exactly 648192 bytes — only the
md5 differed. Causes, in order of likelihood:

1. a `ulogf()` line added outside `#ifdef` — the string is compiled into
   every build, including the rollback;
2. a helper function or table added without a build flag — it lands in
   every build too.

So: **any probe, scan or diagnostic must be behind a flag that defaults to
0 and is set to 1 only in `unlock_v3r`.** An `#else` branch may be empty,
but it must not contain code or log strings. Verify the content, not just
the file: search both binaries for the probe's marker string (note the log
strings are UTF-16, so an ASCII search finds nothing and reports a false
all-clear).

### 6.1 After any change to `src/unlock_v2.c` → flash the stick, unasked

Once a build of `unlock_v3n.efi` exists, the following **must** happen
immediately, **without asking the user first**:

```powershell
cd <корень проекта>

# a) обновить эталон в out/ (build.sh этого не делает)
Copy-Item src\unlock_v3n.efi out\unlock_v3n_CMP70HX.efi -Force

# b) убедиться, что GSP на флешке не тронут
Get-FileHash out\gsp_ga10x.bin -Algorithm MD5   # EB9BEB5D062CCBF3295391C926A2D7AD
Get-FileHash X:\gsp_ga10x.bin -Algorithm MD5   # должен совпасть

# c) записать загрузчик. ПОРЯДОК НЕ МЕНЯТЬ: старый файл сносят целиком,
#    иначе ребут хоста посреди cp = битый FAT (docs/GOTCHAS.md)
Remove-Item X:\EFI\BOOT\BOOTX64.EFI -Force
Copy-Item  out\unlock_v3n_CMP70HX.efi X:\EFI\BOOT\BOOTX64.EFI -Force

# d) обязательная проверка СОДЕРЖИМОГО, а не только файла-эталона
Get-FileHash X:\EFI\BOOT\BOOTX64.EFI -Algorithm MD5   # == md5 out\...
```

Then verify the **strings inside the file on the stick** — profile marker,
probe markers, and any marker that proves *this specific* fix landed:

```powershell
python -c "
d=open(r'X:\EFI\BOOT\BOOTX64.EFI','rb').read()
print('size', len(d), 'PE', d[:2])
for t,n in [('profile70','CMP 70HX (GA104)'),('profile90','CMP 90HX (GA102)'),
            ('probeA','FBP-A  sysmem->dmem ok'),('probeG','FBP-G  readback'),
            ('verdict','FBP    VERDICT'),('loghdr','CMPUNLOG v1 ')]:
    print(f'  {t:10s}', 'PRESENT' if (n.encode('utf-16-le') in d or n.encode() in d) else 'MISSING')
"
```

Expected: `profile70 PRESENT`, `profile90 MISSING`, all probe markers
`PRESENT`, `PE b'MZ'`. Add a marker per fix when a change is log-visible (e.g.
after the `%llu` fix, `bootCount=0x%llx` must be `PRESENT` and `bootCount=%llu`
`MISSING`). **A build that compiles but is not on the stick is not tested.**

Finally, report both md5s and state plainly that a reboot is needed. Do not
imply the change is verified — it is not, until a log comes back from the new
binary.

### 6.2 After every boot from the stick → pull and read the log, unasked

After the user reboots and runs the unlock from the stick, the log is pulled
**by whoever drives the loop**, again without being asked:

```powershell
powershell -ExecutionPolicy Bypass -File out\pull-log.ps1 -Tag <метка>
```

Give every run an explicit `-Tag` so logs do not overwrite each other, then
actually read it and check, in this order:

1. **Is the run complete?** Is there `END   ---- end of log ----`? If the
   reader stopped with `сектор N не записан` and there is no marker, the run
   was cut short — the tail was never written, and nothing about the stages
   after the cut may be concluded.
2. **Which build wrote this?** The header carries `profile=`, `frts=`,
   `wpr2=`. Compare against the `TARGET PROFILE` in the source. If they
   disagree, the log is from a different build than you think.
3. **Did the intended change show up?** Look for the specific marker.
4. **Is the verdict data-backed?** See `docs/LOGGING.md` §8 — several log
   lines that read as success are tautologies.

### 6.3 What must NOT be done automatically

These require the human, and no agent should attempt them:

* **rebooting** the machine, **pressing F12**, or **power-cycling** the
  workstation — the reboot and the boot-menu selection are the user's;
* **interrupting a run** mid-flight. The log is written as it goes and the
  final partial sector is never flushed, so cutting power loses the tail;
* touching `X:\gsp_ga10x.bin` or any other file on the stick;
* writing the USB image (`dd`/Etcher) or repartitioning — that is a separate,
  destructive operation the user must trigger deliberately.

So the split is: **build, flash, verify, pull, read, analyse — automatic.
Reboot and press F12 — the user's.** Announce the md5s, then stop and wait.
