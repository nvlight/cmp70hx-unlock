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

   **On the 70HX the flash stick carries a log**, so the stick must be
   writeable at UEFI time and left alone: the log lives in raw sectors at
   LBA 4 000 000, which FAT32 does not use. Copying large files onto the
   stick can land in that area and clobber an old log. If that happens the
   app simply rewrites the log on the next boot — nothing breaks, the old
   log is just gone.

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

17. **The bundled FWSEC signature does not match the GA104 image** — the most
    likely reason the 70HX stayed locked after the v2.6x FWSEC attempts. The
    FWSEC *code* is byte-identical between GA102 and GA104 (0 differing bytes
    out of 57856); only 34 DMEM bytes differ, and `DMEM+0x0A..0x0B` is the
    PCI device ID (`0x220D` vs `0x248A`), so the image itself is the right
    one. But `fwsec_ga102_sig.bin` and `fwsec_ga104_sig.bin` are the *same*
    384 bytes (md5 `7e33dad7…`). An RSA signature is computed over the image
    content, so two different images cannot share one valid signature — at
    least one pairing is invalid, and it is not the GA102 one (that target is
    field-proven). Symptom matches exactly: `STARTCPU` is accepted
    (`CPUCTL=0x10`), the signature check then fails, `DEBUGINFO=0x780009`, and
    WPR2 stays at its POST value `0x1FFFFE00`. The extraction script is also
    suspect: it takes the signature as `sigs[-384:]`, a window that is *not*
    aligned to the 0x180 record boundary.

    Workaround in place: `fwsec_preloaded_gsp()` starts the FWSEC **already
    resident in GSP IMEM** — the copy the card's own VBIOS loaded and signed —
    writing no bytes to IMEM at all (see the v2.40 note in `fwsec_boot_gsp`:
    writing below 0xE400 breaks that code, which is how we know it is there and
    survives `kflcnReset`). Its DMEM already carries an FRTS command built for
    this card's real framebuffer, so it needs neither a valid signature nor a
    correct `frtsOffset` from us. It runs first, before our own image.
    Getting a *correct* GA104 signature would need a GA104-family VBIOS dump;
    the tree only ships `GA102.rom`.

18. **Logs go to the USB stick as raw sectors, not as a file.** `log_init()`
    writes to LBA 4 000 000 (~1.9 GB in; ~85 MB of files, so the area is
    unused). No `SimpleFileSystem` (issue 8) and no NVRAM (issue 9). Read it
    back with `out\read-log.ps1`.

    Three traps, all hit for real, all now covered by an automated check:

    * **Identifying the stick: two approaches failed, the third works.** (a)
      "first MBR with an 0xEF FAT32 partition" picked the *wrong* 14 GB USB
      device — the firmware hands out BlockIo for more than one, and the
      impostor's partition starts at LBA 0xB00 instead of 0x800. (b) Requiring
      `EFI\BOOT\BOOTX64.EFI` to be present, by walking the FAT32 directory
      with our own parser, **hung the boot on real hardware** — it reads the
      volume's data area ~16 MB in, and no such access from USB had ever been
      proven on this board (`fw-read` only ever reads LBA 0, and
      `SimpleFileSystem` already hangs the firmware — issue 8). (c) Resolving
      the boot device through the loaded image's `DevicePath` — the path this
      firmware returns from `DeviceHandle` did not parse
      (`log_parent_path_size()` returned 0), so it is now only *dumped* as a
      diagnostic. What actually runs is the geometry `out/make-usb-stick.ps1`
      produces: MBR, exactly one `0xEF` partition **at LBA 2048**, `FAT32`,
      >= 4 GB — and the LBA-2048 requirement is precisely what separates our
      stick from the other USB device. Verified against the real disks on
      this host. It does at most two 512-byte reads, no more than `fw-read`.
    * **`FilSysType` lives at BPB offset `0x52`, not `0x54`.** Reading 0x54
      yields the tail of the field (`"T32   3?"`), which silently failed the
      comparison and rejected the stick. Note the volume label on this stick
      is `NO NAME    `, not `CMP70UNLOCK` — do not match on it.
    * **`LOG_LBA` is written in decimal for a reason.** It was `0x3E8000`,
      which is 4 096 000, while the reader used 4 000 000 — a 48 MB gap, so
      the log could never be found even with the right device. `lba_sync.py`
      now compares the two and fails the build on a mismatch.

    Rule of thumb this produced: **nothing in the logging path may touch the
    disk beyond single-sector reads, and may not touch the filesystem at
    all.** A hang before the GPU is even opened costs a whole boot cycle
    and tells us nothing.

    Also: `read-log.ps1` **must stay UTF-8 with BOM** (Windows PowerShell 5.1
    reads a BOM-less `.ps1` as ANSI and the Russian strings break the parse),
    and the log payload **must stay pure ASCII** — the reader decodes with
    `[Text.Encoding]::ASCII`, which turns any byte >= 0x80 into `?`. That is
    why the end marker is `END   ---- end of log ----` and not a Russian
    phrase: as Cyrillic it became `?????? ????`, went unmatched, and the
    script then crashed on `Substring(-1)`. `log_write()` now sanitises
    every non-printable/non-ASCII byte to `?` so the class of bug is closed.

    Host-side note for testing only: Windows buffers raw writes to a *mounted*
    volume and refuses the final flush (`Access denied`), so a host-side
    self-test of the write path is not possible while `X:` is mounted. The
    writer/reader *format contract* is verified separately on a synthetic
    image; the on-metal write path is the real `BlockIo WriteBlocks`, which
    needs no OS driver at all.

---

## 19. gnu-efi CopyMem/SetMem/CompareMem в этой сборке НЕ КОПИРУЮТ ПАМЯТЬ (v3n, критично)

`legacy.h` делает `CopyMem` макросом на `CopyMem_1`, а тот — обёрткой над
runtime-сервисом `RtCopyMem`. Дизасм готового `unlock_v3n.so`:

```
<CopyMem_1>:  jmp <RtCopyMem>
<RtCopyMem>:  movzbl (%rdx,%rax,1),%r9d   ; src читается по rdx
              mov    %r9b,(%rcx,%rax,1)   ; dst пишется  по rcx
              cmp    %rax,%r8              ; длина из r8
```

Аргументы читаются как **rcx/rdx/r8** (соглашение Microsoft x64), тогда как
программа собрана под System V (**rdi/rsi/rdx**). Функция получает мусор и
почти всегда выходит сразу. `SetMem` сломана так же.

ПОСЛЕДСТВИЕ: ни одна загрузка блоба в приложении не работала — V67, FWSEC,
GspRmBoot, radix-образ, патч подписи, таблицы страниц. FWSEC стартовал с
нулями и всегда давал `dbg=0x00780009`.

Доказательство с железа (`MEM` самопроверка): прямые обращения
`*(volatile UINT32*)` в буфер попадали, `CopyMem` — нет; CRC32 буфера не
совпадал с блобом.

Фикс: свои `app_memcpy`/`app_memset`/`app_memcmp` + `#undef`/`#define` сразу
после `#include`. `build.sh` компилирует только `unlock_v2.c`, поэтому
перекрыты все вызовы. В `.so` остаётся 6 вызовов `Rt*Mem` — они внутри
самого efilib (`Print`, `LibLocateProtocol`) и в критическом пути не участвуют.

**НЕ УДАЛЯТЬ этот блок и не «чинить» gnu-efi — переопределение обязательно.**

## 20. secure-DMA в IMEM на 70HX отклоняется (0xDEAD5EC1)

При `imemSec=1` чтение IMEM через порт GSP возвращает `0xDEAD5EC1` —
осознанный отказ «secure memory access». При `imemSec=0` отказа нет и код
ложится: `imem_ours=0xEC547D23`. Поэтому `g_fwsecImemSec` по умолчанию 0,
а порядок попыток — SEC=0 первым.

Побочно: отказ залипает и на не-secure чтение (`imem_ns`), так что
`imem_ns` нельзя использовать как признак успеха.

## 21. Текущее состояние прогона FWSEC на 70HX (v3n)

Подтверждено логом:
- образ FWSEC ложится в IMEM (`imem_ours=0xEC547D23`), CRC32 блоб==буфер;
- DMEM заполняется верно: `cmd_in_buffer_offset=0x7C0`, `init_cmd=0x15`,
  подпись `sig[2]=0x0745DD25` на месте;
- FWSEC буфер команды ЧИТАЕТ и обнуляет (0x7C0 после прогона пуст);
- `dbg=0x00000000` — ошибок не сообщает, но `wpr2` остаётся
  `0x1FFFFE00/0x00000000` вместо `0x01FFE000/0x01FFEE00`;
- эксплойт канарейки частично работает: `SS0=0x05173106`, `SS1=0x00000007`
  (раньше были нули), `PLM` поднялся с `0xFFFFFE8E` до `0xFFFFFF8F`.

Гипотеза следующего шага: FRTS-область кадрового буфера по смещению
`0x1FFE00000` никогда не заполняется. `FWSEC_FRTS_OFFSET` в коде встречается
только как число в дескрипторе команды (`c[8] = FRTS>>12, c[9]=0x100,
c[10]=2`), сам регион не пишется. FWSEC получает верный адрес и молча упирается
в пустоту. Нужно заполнить регион из `GA104.rom`, но для этого требуется
отображение кадрового буфера в адресное пространство CPU.

## 22. Ограничения прошивки: крупные операции с флешкой вешают систему

Первая попытка сделать лог «незатираемым» — прочитать всю область лога (1 МБ)
одним запросом, чтобы найти первый пустой сектор — **повесила загрузку**
(напечатался `кандидат #0`, дальше тишина). Тот же эффект раньше давало
чтение 84-МБ образа.

Рабочий вариант: указатель «с какого сектора писать» в секторе 0 области,
`"CMPN"` + 4 байта. Обе операции — ровно 512 байт.

**ПРАВИЛО: с этой флешки допустимы только операции размером в один сектор.**

## 23. Свип gen2 ограничен тремя проходами (это не бесконечный цикл)

`RJ16_N` = 37, не 41. `gen2[37/37]` — последняя запись (`0x00088084`
LINK_CAP), дальше срабатывает SKIP и начинается граница прохода
(`for (pass = 0; pass < 3 ...)`). Выглядело бесконечным потому, что
`early_unlock_path` вызывался на КАЖДОЙ из 36 записей, где маска ещё не FF:
36 x 3 = 108 полных FWSEC-загрузок. Теперь FWSEC в свипе один раз
(`g_fwsecOnce`), лестница FLR + ботер#2 не тронута.

## 24. PROBE карты не работает: BAR0 не отображён

`chip/gfw/fbsz/plm/wpr2` читаются как `0xFFFFFFFF` для обеих карт
(bus=2 и bus=16), потому что `bar0=0xF6000000` и не поднят `PCIE_CMD`
(mem-enable). Нужно включать decode перед чтением BAR0, иначе нельзя
определить, какая из двух перечисленных карт — реальный кремний, а какая
призрак от прежней работы с 50HX.
