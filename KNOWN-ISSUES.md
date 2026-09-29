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

    The full mechanics — on-disk format, the write path in `unlock_v2.c`, the
    read path in the host scripts, the keep-in-sync contract between the two
    and log diagnostics — are documented in
    [docs/LOGGING.md](docs/LOGGING.md).

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

---

## 25. Кадровый буфер НЕ отображён в адресное пространство CPU (v3n)

`scan_bars()` декодирует все шесть BAR'ов (запись 0xFFFFFFFF, маскирование,
восстановление исходного значения). Замер на 70HX:

```
BAR0=0xF6000000 type=0 size=0x1000000    16 МБ
BAR1=0xF800000C type=C size=0x4000000    64 МБ  (64-битный prefetchable)
BAR3=0xFC00000C type=C size=0x2000000    32 МБ  (64-битный prefetchable)
```

Крупнейший — 64 МБ, кадровый буфер — 8 ГБ (0x200000000). **FB физически
недоступен из CPU** — ни писать, ни читать. Это убивает план «загрузить
GA104.rom в FRTS-регион по указателю».

ВАЖНО про декодирование BAR: 64-битный BAR — это биты [2:1] = 10b, то есть
`(type & 0x6) == 0x4`, а НЕ `== 0x6` (оба бита — зарезервированное значение).
Размер 32-битного BAR считается в 32-БИТНОЙ арифметике: `~(probe & ~0xF) + 1`
в 32 бита даёт 0x01000000 (256 МБ), а в 64 бита — мусор 0xFFFFFFFF01000000.

## 26. Что даёт gen2-свип и почему он не доходит до FF (v3n)

Свип gen2 — это та же эксплойт-канарейка V67, что и основной путь: она пишет
0xFFFFFFFF в 37 защищённых регистров из таблицы g_rj16 (0x00823804 = PLM,
0x00088fe8, 0x0008e1b0 и т.д.). Это механизм «rejoin16» из вышестоящего
cmpunlocker. Цель — полностью открыть PLM и маски.

Замер на 70HX: свип выполняется полностью (3 прохода × 36 записей = 108
минициклов), но маски застревают на 0xFFFFFFCF / 0xFFFFFF8F и НИ РАЗУ не
доходят до 0xFFFFFFFF. Записи частично липнут: биты 0x30 / 0x70 не выставляются.
Это не сломанный код — это реакция регистров именно 70HX.

Замер времени поллинга ботера: `iters=5 за 68мс HALT`. Ботер останавливается
почти мгновенно, поэтому подозрение на поллинг в 200000 итераций НЕВЕРНО — он не
узкое место. Реальная раскладка 13 минут печатается новыми метками `TIME`
(см. пункт 28).

## 27. VROM найден, но это не тот образ, что читает FWSEC (v3n, путь C)

`dump_vrom()` ищет option-ROM: сначала PCI-регистр 0x30 (Expansion ROM Base
Address), при выключенном — сканирует BAR0 по сигнатуре 55 AA. Замер:

```
VROM  expBAR(0x30)=0x00000000        ← BAR выключен
VROM  found @0xF6300000              ← внутри BAR0, на +0x300000 (3 МБ)
VROM  hdr: 55 aa 7f eb 4b 37 34 30 30 e9 4c 19 77 cc 56 49
VROM  CRC32 первых 4КБ = 0x31F7E28C  ← GA104.rom даёт 0xb07f143b, НЕ совпадает
```

Вывод: VBIOS карты состоит из ДВУХ образов — legacy option ROM (в VROM,
55 AA, ~65 КБ, для CSM) и UEFI GOP VBIOS (GA104.rom, NVGIP, ~976 КБ). Это
разные файлы, поэтому CRC не совпал.

Плохое: FWSEC читает НЕ VROM — в его команде frtsRegionMediaType=2 (FB), регион
по смещению 0x1FFE00000 в кадровом буфере. Путь C закрыт как способ решить FRTS:
мы не можем ни писать, ни читать FB.

## 28. Метки времени TIME в логе (v3n)

В лог добавлены замеры через PTIMER (свободно идущие GPU-часы, нс):

```
TIME  t=0мс — старт отсчёта
TIME  t=...мс  до раннего пути
TIME  t=...мс  ранний путь завершён
TIME  t=...мс  FWSEC-попытки закончены
TIME  t=...мс  gen2 проход 1/2/3 завершён
TIME  t=...мс  финал: возврат в прошивку
BOOTER iters=... за ...мс HALT/PLM-OPEN/timeout-5s   ← на каждый вызов ботера
```

ЛОВУШКА: `log_t0()` должен вызываться ПОСЛЕ `set_gpu_time()`. PTIMER до его
инициализации равен 0, поэтому `g_t0 == 0` и все `log_ms()` молча выходили по
проверке `if (g_t0 == 0) return` — в логе была только строка t=0. Порядок именно
такой: set_gpu_time() → log_t0().

## 29. Состояние после фикса CopyMem: эксплойт РАБОТАЕТ (v3n)

Ключевые подтверждения из лога на 70HX:

- образ FWSEC ложится в IMEM: `imem_ours=0xEC547D23`, CRC32 блоб == буфер;
- DMEM заполняется верно: `cmd_in_buffer_offset=0x7C00`, `init_cmd=0x15`,
  подпись sig[2]=0x0745DD25 на месте после прогона;
- FWSEC буфер команды ЧИТАЕТ и обнуляет (0x7C0 после прогона пуст);
- `dbg=0x00000000` — ошибок не сообщает;
- эксплойт канарейки РАБОТАЕТ: SS0=0x05173106, SS1=0x00000007 (раньше были
  нули), PLM поднялся с 0xFFFFFE8E до 0xFFFFFF8F.

Осталось: WPR2 не защёлкивается (0x1FFFFE00/0x00000000 вместо 0x01FFE000/
0x01FFEE00). Причина: FRTS-регион в FB по 0x1FFE00000 никогда не заполняется,
а писать в FB нельзя (пункт 25). Дамп DMEM после прогона (все ненулевые слова)
показывает, что микрокод дошёл до конца команды, но WPR2 не ставит.

Также: secure-DMA в IMEM при SEC=1 отклоняется (0xDEAD5EC1), поэтому
g_fwsecImemSec по умолчанию 0 и порядок попыток — SEC=0 первым (пункт 20).

---

# ЧАСТЬ II. РЕЗУЛЬТАТЫ РАЗБОРА ПОРТА 70HX (2026-09-28)

Эти пункты появились после того, как в репозиторий попал **дамп VBIOS
реальной карты владельца** (`GA104.rom`, 999 424 байта, UEFI GOP VBIOS,
снят GPU-Z) и **реальный лог прогона** (`out/usb-log.txt`). Полный разбор
VBIOS — в [docs/70HX-VBIOS-ANALYSIS.md](docs/70HX-VBIOS-ANALYSIS.md),
сводка по порту — в [docs/70HX-PORT-STATUS.md](docs/70HX-PORT-STATUS.md),
план дальнейших шагов — в [docs/70HX-NEXT-STEPS.md](docs/70HX-NEXT-STEPS.md).

## 30. §17 ОПРОВЕРГНУТ: подпись FWSEC валидна

Пункт 17 утверждал, что «подпись FWSEC не соответствует образу GA104» и что
именно поэтому 70HX оставалась залоченной. **Это неверно.** Разбор дампа
показывает:

* `fwsec_ga102.bin` и `fwsec_ga104.bin` — **один и тот же файл** (окно
  `0x4000..0x4040` обеих копий лежит в ROM по одному адресу `0x4E8B4`);
* `fwsec_ga104_prod.bin` **побайтово равен** коду FWSEC PROD из ROM
  этой карты (md5 `5305c91316d3afafc669d79c77adeaca`), DBG — тоже;
* в дескрипторе FWSEC `sigCount = 3`, и подписи — это
  `sig[0]` = 384 байта **нулей**, `sig[1]`, `sig[2]`; драйвер берёт `sig[2]`;
* `fwsec_ga104_sig.bin` и все три `fwsec_ga104_prod_sigN.bin` совпадают
  с соответствующими слотами из ROM **точно**.

Подпись считается по содержимому, содержимое одинаково — значит подпись
обязана совпадать, и она совпадает. Подозрение «окно `sigs[-384:]` не
выровнено по границе 0x180» снимается: при `descSize = 0x4AC` область
подписей равна ровно `1152 = 3 × 384` байт.

**Ветка «подпись невалидна» закрыта как ложная.**

**Побочно:** попытка №3 в очереди FWSEC подставляет `sig[0]`, то есть
384 байта нулей, и бесполезно тратит ~13 с (см. §34).

## 31. §17 ОПРОВЕРГНУТ (вторая часть): IMEM после POST пуст

`fwsec_preloaded_gsp()` строился на гипотезе, что после POST в IMEM GSP
лежит подписанный самой картой FWSEC, который достаточно просто
перезапустить. Лог это опровергает:

```
PRE   imem_card=0x00000000 imem_ours=0xEC547D23 match=0
```

IMEM после POST **пуст**. Обходного пути не существует: читать нечего,
стабильность `kflcnReset` на нём держаться не может. Ветку можно
убирать, но время на неё тратить не надо.

## 32. §21 ОПРОВЕРГНУТ: FRTS-регион не обязан быть заполнен заранее

Пункт 21 предполагал: «FRTS-область в FB никогда не заполняется, FWSEC
упирается в пустоту, надо загрузить туда данные из `GA104.rom`».

**Смысл задачи был понят неверно.** `frtsRegionMediaType = 2` означает
«регион находится в кадровом буфере», и работа маппера состоит как раз в
**построении** таблиц в этом регионе. Пустой регион на входе — нормальное
состояние, а не признак ошибки.

Проверка на самом ROM: в поставляемом FWSEC-образе **буфер команд пуст**
(`dmem[0x7C0..0x800]` = нули) — FRTS-команду собирает GFW в рантайме
POST, в ROM её физически нет. Поиск образа FRTS в дампе результатов не
дал.

**Следствие:** задача «загрузить `GA104.rom` в FRTS-регион» не просто
сложнее — она **неверна по смыслу**. ROM этих данных не содержит.

## 33. НОВОЕ: расшифрована структура `DMEM_MAPPER_V3` в FWSEC

Из образа FWSEC PROD в вашем ROM (`docs/70HX-VBIOS-ANALYSIS.md` §5):

* `dmem[0x0000] = 0x00100001` — magic верхнего заголовка;
* `dmem[0x0008] = 0x248A0003` — **device ID именно этой карты**;
* `dmem[0x0030..0x01AF]` — подпись, `sig[2]`, 0x180 байт;
* `dmem[0x0560] = 0x50414D44` — **magic `"DMAP"`**;
* `dmem[0x0568] = 0x000007C0` — `cmdInBufferOffset`;
* `dmem[0x056C] = 0x00000040` — `cmdInBufferSize` = 64 байта;
* `dmem[0x058C] = 0x00000000` — `initCmd` (сюда пишется `0x15`).

Обе точки, куда пишет код, **корректны**: `cmdInBufferOffset = 0x7C0`
совпадает с §21, `initCmd` по `0x58C` — ровно тот, что использует
`fwsec_boot_gsp_sig()`. Собираемая команда — 44 байта, буфер — 64,
переполнения нет.

Значение `0x7C00` в §29 — **опечатка в логе**, правильное `0x7C0`.

## 34. Тайминг прогона и бесполезная попытка FWSEC

По меткам `TIME` из реального лога:

| Метка | t, мс |
|---|---|
| старт | 0 |
| до раннего пути | 15 014 |
| проба FB завершена | 28 567 |
| промежуточная стадия | 53 915 |
| начало FWSEC-стадии | 93 510 |
| FWSEC-попытки закончены | 134 639 |

**FWSEC-стадия занимает 41 с** из ~135 с. Из них попытка №3
(`sigIndex=0`, см. §30) подставляет нулевую подпись и результата не даёт
никогда. Её следует убрать из очереди.

`BOOTER iters=5 за 68.039мс HALT` — ботер останавливается почти мгновенно,
что окончательно опровергает старую гипотезу §26 о «долгом поллинге
200000 итераций».

Одна итерация эксперимента ≈ 2,5 минуты плюс перезагрузка — это влияет
на планирование: см. [docs/70HX-NEXT-STEPS.md](docs/70HX-NEXT-STEPS.md) §0.

## 35. ГЛАВНЫЙ БЛОКЕР УТОЧНЁН: FWSEC отрабатывает, но WPR2 молчит

Ключевая строка лога:

```
FWSEC ours FAIL wpr2=0x1FFFFE00/0x00000000 cpuctl=0x00000010
                 dbg=0x00000000 scratch0e=0x00000000 imem_ours=0xEC547D23
```

* `CPUCTL = 0x10` — `STARTCPU` принят, ядро стартовало и остановилось штатно;
* `dbg = 0`, `scratch0e = 0` — FWSEC **не сообщил ни об одной ошибке**;
* буфер команды прочитан и обнулён — команда **исполнена**;
* `WPR2` не изменился.

Отказ не «падение», а **молчаливое несовпадение условий**. Кандидаты,
по убыванию правдоподобия:

1. **Неверно заполнено поле `gfwImageSize`.** В коде `c[4] = 0`
   (`gfwImageSize = 0`) при `c[5] = 2` (`flags = 2`). Дескриптор называется
   `readVbiosDesc` — «прочитать дескриптор VBIOS»; говорить «прочитать
   0 байт» при ненулевом `flags` — сильный кандидат на молчаливый выход.
   **Наиболее вероятный фикс**, и он требует только чтения значений из
   `kgspPopulateWprMeta` в open-gpu-kernel-modules 610.x.
2. **Кодировка WPR2 неверна.** Правило `lo = frts>>8, hi = lo+0xE00`
   экстраполировано с **одного** замера на 10 ГБ. Постуровое `0x1FFFFE00`
   не следует из него ни для какой геометрии — возможно, мы ждём не того
   значения.
3. **`fbsz` заблокирован** (`0xBADF1100`), PLM на момент FWSEC ещё закрыт
   (`0xFFFFFF8F`). Мапперу может не хватать прав.
4. **Читается не тот регистр** — `NV_PFB_PRI_MMU_WPR2_LO/HI` на 70HX может
   транслироваться иначе.
5. **Расхождение последовательности стадий** с рабочей 90HX.

## 39. `WPR2` подтверждён: обе проверки драйвера пройдены

`out/usb-log-okchk.txt`:

```
OKCHK  frtsErrCode=0x00000000 (want 0x00000000) NONE
OKCHK  wpr2Hi=0x01F7EE00 (driver needs != 0) OK
OKCHK  wpr2Lo=0x01F7E000 expected=0x01F7E000 OK
```

Это ровно те проверки, которые делает драйвер
(`kernel_gsp_frts_tu102.c:489-525`). Обе пройдены.

### 39.1 `privLevelMask != 0` НЕ означает, что `WPR2` не записан

Я записал `privLevelMask = 0x0004CB8F` как «успех может быть ложным».
Это неверно. Маска возвращает **фиксированное** значение — ПОСТ-дефолт
`0x1FFFFE00`, который и стоял во всех прошлых прогонах. Совпадение
`lo=0x01F7E000`/`hi=0x01F7EE00` с расчётом от `frtsOffset` при
фиксированной маске невозможно, значит запись состоялась.

Плюс: драйвер при FWSEC `PLM` не трогает вовсе — в
`kernel_gsp_falcon_ga102.c` нет ни одного обращения к `PLM`/`PRIV`.

Общее правило: «прикрыто маской» и «записано верное значение» —
не взаимоисключающие утверждения, если известно, что возвращает маска.
Прежде чем сомневаться в результате, надо проверить, какое значение маска
подставляет.

### 39.2 После secure-загрузки порты IMEM/DMEM отдают отказ

| | до исправления бита | после |
|---|---|---|
| `dmem[0]` | `0x00100001` OK | `0xDEAD5EC2` |
| `imem[0]` | `0x00000000` | `0xDEAD5EC1` |

`0xDEAD5EC1` (IMEM) и `0xDEAD5EC2` (DMEM) — отказ порта, отличаются
младшим битом. Появились **после** того, как secure-код реально загрузился.

Практическое следствие: **все измерения состояния GSP после `STARTCPU`
через порты IMEM/DMEM недостоверны.** Мерить нужно до старта или после
опускания привилегий.

### 39.3 Моя ошибка в блоке `OKCHK`

```
OKCHK  cmdIn[0]=0xDEAD5EC2 at dmem+0xDEAD5EC2
```

Смещение и значение совпали — в строку попал результат чтения вместо
смещения. Вывод «маппер не выполнял команду» из этого **не доказан**:
если порт не отдаёт данные, судить о содержимом нельзя. Исправлено:
печатаются `dmem[0]`, `dmem[0x560]` (магия `DMAP` = `0x50414D44`) и
`dmem[0x568]` (ожидается `0x7C0`) раздельно.

Общее правило: диагностический вывод должен сопровождаться проверкой
самой диагностики. Прежде чем заключать «данных нет», убедись, что порт
вообще отдаёт данные.

## 38. `WPR2` ВСТАЛ — исходный блокер снят

`out/usb-log-sec1.txt`:

```
IVER   empty=0 matched=0 occupied=9  *** IMEM OCCUPIED ***
WAIT   t=0ms wpr2=0x01F7E000/0x01F7EE00 expect=0x01F7E000/0x01F7EE00
WAIT   *** WPR2 УСТАНОВЛЕН lo=0x01F7E000 hi=0x01F7EE00 после 0 ms ***
```

| | |
|---|---|
| ПОСТ-дефолт (все прошлые прогоны) | `lo=0x1FFFFE00  hi=0x00000000` |
| сейчас | `lo=0x01F7E000  hi=0x01F7EE00` |
| `frtsOffset >> 8` | `0x01F7E000` — совпадает |

`WPR2` защёлкнулся на первом витке опроса, сразу после `STARTCPU`.
`BOOTER iters=5 за 68.040мс PLM-OPEN` — цикл ботера тоже вышел по своему
условию успеха.

### Что было причиной

Один бит в команде `DMATRFCMD` (см. §36): `IMEM=1` стоял на позиции `SEC`,
поэтому код FWSEC в IMEM не грузился **никогда**. Плюс неверное расшифрование
`0xDEAD5EC1` как «secure-доступ закрыт» (см. §37), из-за которого все три
попытки шли с `SEC=0`.

### 38.1 Проверок на пути успеха не было

Все проверки (`CMDIN`, `DMAP`, `PLMM`, `SCR`) жили в ветке ПРОВАЛА. На
успехе их не было вообще, поэтому первый успешный прогон вышел с одним
доказательством — «`WPR2` равен ожидаемому».

Это опасно: при `privLevelMask != 0` (он и был `0x0004CB8F`) значение
`WPR2` прикрыто, и совпадение с ожиданием **не доказывает** запись.
Добавлен блок `OKCHK` на пути успеха: `FRTS_ERR_CODE`, `wpr2Hi != 0`,
`wpr2Lo == expected`, `privLevelMask`, `CMDIN` (выполнял ли маппер команду).

Общее правило: набор проверок не должен зависеть от ветки. Успех и провал
требуют одинакового объёма доказательств.

### 38.2 Что подтверждено и что нет

**Подтверждено:** FWSEC грузится, стартует и защёлкивает `WPR2` на
правильное значение.

**Не подтверждено:** полный анлок. Лог обрывается на стадии `GEN2`
(`enable=0`) без маркера `END`. Что происходит дальше по цепочке ботера —
неизвестно.

Цифры производительности в README относятся к проверенной сборке 90HX,
не к 70HX.

## 37. ОПРОВЕРГНУТО: «на 70HX secure-IMEM недоступен» — вывод из ошибочной расшифровки

В коде долго стояло:

```c
/* v3n: по умолчанию НЕ-secure. Лог показал: при imemSec=1 чтение IMEM
 * через порт GSP возвращает 0xDEAD5EC1 — осознанный отказ GSP. То есть
 * бит SEC в DMATRFCMD на этой карте запрещён, и DMA кода в IMEM просто
 * не происходит. */
static UINTN g_fwsecImemSec = 0;
static const UINTN secOrder[3] = { 0, 0, 0 };
```

### Почему это неверно

**1. Замер шёл при неверной команде DMA.** При `0x604` бит `IMEM=1` стоял
на позиции `SEC` (см. §36), то есть в IMEM не писалось ничего. `0xDEAD5EC1`
тогда означало «IMEM пуст, вы прочитали пустое защищённое место», а не
«запись защищённого кода отклонена».

**2. `IMEMC.SECURE` (28:28) — признак защиты чтения, не запрет записи.**
`0xDEAD5EC1` = «DEAD SEC1» — отказ читать защищённую ячейку без
достаточного уровня привилегий. Это признак **успешной** загрузки
защищённого кода.

### Что показал исправленный замер

При правильной команде `0x614` (IMEM=1, SEC=1) все 9 проб IMEM дают
`0xDEAD5EC1`, ни одна не даёт `0x00000000`:

```
IVER   empty=0 matched=0 occupied=9
```

**IMEM занят.** До правки бита все девять давали ноль.

### Исправлено

* `g_fwsecImemSec = 1` — как в `kernel_gsp_falcon_ga102.c:229`;
* `secOrder[3] = {1, 0, 0}` — перебор снова осмыслен (было `{0,0,0}`,
  то есть три одинаковые попытки);
* `DMA_CMD_IMEM` считается из флага: `0x614` при SEC=1, `0x610` при SEC=0;
* `IMEM=1` теперь всегда — именно это и было исправлено в §36.

### 37.1 Цена ошибки

Неверный вывод стоил **трёх прогонов подряд** (`secOrder = {0,0,0}` —
это не перебор, а одно действие, повторённое трижды) плюс месяца
гипотез, строющихся на «secure-путь на этой карте закрыт».

Общее правило: вывод «оборудование не поддерживает X» нельзя делать по
наблюдению, полученному при **непроверенной** команде. Сначала нужно
доказать, что команда вообще делает то, что от неё ожидается.

### 37.2 `ulogf` не понимает `%u`

```
IVER   0 probe point(s), 3014351520 empty
```

`3014351520` = `0xB40175E0` — мусор из стека. Форматная строка требовала
`%u` (беззнаковое), а передавалось знаковое `int`. Формат и тип аргументов
разошлись, и вместо значения напечатался адрес. Исправлено упаковкой
статистики в три байта и выводом через `%d`.

Общее правило: в этом проекте для `ulogf` использовать только `%d`/`%x`
с явным приведением типа; никаких `%u`, `%llx` без приведения.

> ⚠️ **УТОЧНЕНИЕ 2026-09-29.** Сверка с логом показала, что §37.2
> переоценивает и недодоценивает проблему. Проверено по прогону
> `0929-023826` — форматы печатают верные значения:
>
> | Формат | Где | Результат в логе |
> |---|---|---|
> | `%u` | `BOOTER iters=%u` | `iters=5` — **верно** |
> | `%03u` | `BOOTER за %u.%03uмс` | `68.064` — **верно** |
> | `%lld` | `TIME t=%lldмс` | `t=4243`, растёт монотонно — **верно** |
> | `%d` + `(INTN)` | везде | **верно** |
> | `%llx` | `META frts=0x%llx` и др. | `0x1F7E00000` — **верно** |
> | `%llu` | `META bootCount=%llu` | **не проверен** (см. §42/43) |
> | `%s` с узкой строкой | `stick … by=%s` | **ломает строку** (см. §42/45) |
> | любая строка > 199 символов | `META` целиком | **обрезается** (§42/43) |
>
> То есть §37.2 читать как «`%u`/`%llx` непроверенны и потому подставлять
> нельзя», а **не** как «`%u` не работает». Практическое правило прежнее —
> только `%d` с `(INTN)` и `%x`/`%llx` с приведением, — но причина прежняя
> («не понимает») была сформулирована слишком широко. Реальная причина
> обрыва строк оказалась вовсе не в форматах — см. §42/43.

### 42/43. `ulogf` резал строки на 199-м символе (BufferSize в байтах, а не в символах)

`ulogf()` вызывал `UnicodeVSPrint(wbuf, sizeof(wbuf)/sizeof(wbuf[0]), …)` —
то есть передавал **число символов** (400). Функция в gnu-efi 4.0.0 ждёт
размер **в байтах** и сама переводит его в символы. Проверено дизассемблированием
`libefi.a` — функция начинается с:

```
shr    $1,%rsi        ; BufferSize / 2
sub    $0x1,%rsi      ; минус 1 на завершающий NUL
```

Итого мы передавали 400, функция считала `400/2 − 1 = 199` символов, и
**любая строка лога длиннее 199 молча обрывалась** — без перевода строки,
и следующая строка приклеивалась к обрывку:

```
META  … bootBin=0x1F7DFA000 bootCounGEOM  margin=0x8000000 (128 MB) …
```

Ровно 199 символов до обрыва — независимая проверка длины из лога
совпала с арифметикой `400/2 − 1`.

**Почему это так долго вводило в заблуждение.** Оборванная строка заканчивается
посреди спецификатора (`bootCoun|t=0x%llx`), и это выглядит как «сломанный
формат». Первая версия была «`%llu` не поддержан» — и она была **не доказана**:
проверить не удалось (стенд для проверки форматов — линковка `print.o` из
gnu-efi в хостовую программу — не пошёл из-за несовместимости ABI на границе).
Настоящая причина нашлась позже и оказалась не в формате вовсе. Исправлено
на `UnicodeVSPrint(wbuf, sizeof(wbuf), …)`.

**Побочный эффект правки `%llu` → `0x%llx`:** изменение оставлено (остальные
поля этой строки тоже hex, так что строка стала однородной), но **обоснование
в комментарии вычищено** — утверждение «`%llu` сломан» не доказано и на
проверку не тянется.

> **Проверенно рабочие форматы** (по логу от 2026-09-29): `%d` с приведением
> к `INTN`, `%x`, `%llx`, `%u`, `%03u`, `%lld`. Про `%llu` — см. выше.

**Длинные строки собираются из нескольких вызовов.** Строки `MEM … слова:` в
том же логе длиннее 199 и целые — они печатаются как заголовок плюс цикл
маленьких `ulogf`. Предел действует на **каждый вызов по отдельности**, а не на
лог целиком.

**Правило на будущее:** в gnu-efi второй аргумент `UnicodeVSPrint` — это
размер буфера **в байтах**. Не `sizeof/sizeof`, а `sizeof`.

### 42/44. `zcrc` затенялся и считал не то же число блоков, что `crc`

В `fb_access_probe()` переменная `zcrc` была объявлена **дважды**: один раз в
области функции, второй раз внутри блока `{ … }` с инициализацией. Вторая
затеняла первую, и в `ulogf` уходило **неинициализированное** значение. Это
стало видно сразу после исправления затенения — и выявило **вторую** ошибку,
которую затенение до этого маскировало:

```
FBP-E  crc32=0x38E3FFEE  zerocrc=0x47C1A880  (DIFFERS from zerocrc …)
```

Арифметика сходится точно:

| | блоков | CRC (без финального XOR) |
|---|---|---|
| `crc` | 16 × 256 = 4096 | `0x38E3FFEE` ← значение в логе |
| `zcrc` | 1 + 16 = **17** × 256 = 4352 | `0x47C1A880` ← значение в логе |

(`crc32(4096 нулей) = 0xC71C0011`, `crc32(4352 нулей) = 0x9A21E28F`;
`crc32_upd` не делает финальный XOR, поэтому `^ 0xFFFFFFFF`.)

То есть инициализатор `zcrc` считал **один лишний блок**, и сравнивались 16
блоков против 17 — расхождение было гарантировано независимо от содержимого
региона. Исправлено на `zcrc = 0xFFFFFFFFU` + 16 итераций, как в цикле `crc`.

Прежний комментарий, объяснявший расхождение «остатками предыдущей
DMA-передачи в DMEM», был построен на этом баге и сам по себе не проверяем.
После правок вердикт «(all zero, consistent with C)» означает ровно то, что
читает тест C.

**Правило:** не заводить переменную с именем, уже объявленным во внешней
области видимости; и число блоков в эталоне обязано совпадать с числом блоков
в сравниваемом прогоне.

### 42/45. Узкая строка в `%s` — ДОКАЗАНО и исправлено

`log_start()` принимал `const CHAR8 *how`, и `"geometry"` уходило в `%s`
`UnicodeVSPrint`, который читает `%s` как `CHAR16*`. Узкие байты `'g','e'`
читались как символ `0x6567` — вне `0x20..0x7E`, и `ulogf()` превращал его в
`'?'`:

```
было:  stick  lastLba=0x1CD1A59 partLba=0x800 logLba=0x3D0900 sec=1 by=????????T????
стало: stick  lastLba=0x1CD1A59 partLba=0x800 logLba=0x3D0900 sec=1 by=geometry
```

`????????` — это «geometry», прочитанная по два байта как wide; дальше хвост
мусора, потому что обход не остановился на границе литерала. Та же беда
описана в комментарии над `ulogf` про `AsciiVSPrint`, но при переходе на
`UnicodeVSPrint` её повторили: **узкая строка в `%s` недопустима в обоих**.

Исправлено: `const CHAR16 *how` + вызов `L"geometry"`; там же
`"LOCKED"/"READABLE"` → `L"LOCKED"/L"READABLE"` (строка `FBIOS`).

**Проверка на железе сработала** — прогон `after-fix` от 2026-09-29 дал
`by=geometry` и `FBIOS … READABLE` вместо `????????`. Это единственная из трёх
правок первого захода, эффект которой виден в логе сразу и однозначно.

### 42/46. Маркер `END` никогда не попадал на флешку — не финальный сброс буфера

**Это была не зависание, а потеря данных при записи.** Разобрано 2026-09-29.

Структура была такая:

```c
log_flush_sector(TRUE);            // сбрасывает буфер с 'STG reached done' и 'STG post-FLR'
ulogf(L"END   ss0=…");             // -> свежий буфер, НЕ сброшен
ulogf(L"END   ---- end of log ----\n");
}                                   // -> Print, Stall, return в прошивку
```

Приложение возвращалось в BDS с ~230 байтами лога в ОЗУ. Дальше дописать
нечем: управление ушло прошивке.

**Доказательство, что дело не в зависании и не в отказе записи.** Лог на
флешке обрывался *чистым переводом строки*:

```
STG   reached 'done' label\r\n
STG   post-FLR: MMIO недоступен, …\r\n
<дальше на флешке пусто>
```

Чтобы этот текст оказался на носителе, должен был отработать именно
`log_flush_sector(TRUE)` перед блоком `END` — а он отработал, значит
приложение дошло до этой строки. Зависание дало бы обрыв *раньше* (тогда
`STG reached done` и `STG post-FLR` тоже не попали бы на флешку, потому что
лежали бы в несброшенном буфере). Отказа записи тоже не было: сброс перед
`END` успешен.

**Почему это так долго выглядело как зависание.** Лог всегда обрывался на
границе сброса, поэтому «лог оборвался» и «приложение не дописало» были
неразличимы — оба случая давали один и тот же вид. Из-за этого в код была
внесена метка `done:` с комментарием про неразличимость — то есть
workaround на симптом, порождённый этим же багом.

**Масштаб:** маркера `END` не было **ни в одном прогоне** репозитория —
`sec1`, `okchk`, `stages`, `verify-fixes`, `after-fix`. Его отсутствие
никогда не было признаком зависания.

**Исправлено:** `log_flush_sector(TRUE)` сразу после маркера `END`, плюс
страховочный `log_flush_sector(FALSE)` перед `return EFI_SUCCESS` — на
случай, если вывод добавится после блока `END`. Все пути `goto done` сходятся
в одну точку, так что других мест выхода из `efi_main` нет.

**Как заметить в следующий раз:** ридер печатает `Останов на: сектор N не
записан» — это нормально, когда лог короче области. Признак обрыва —
отсутствие `END   ---- end of log ----`. После фикса маркер обязан
присутствовать; если его нет при новой сборке — значит появился новый путь
потери, и «хвост не записан» снова нельзя читать как «приложение зависло».

## 36. НАЙДЕН КОРЕНЬ: бит 4 в `DMATRFCMD` — это `IMEM`, а не `SEC`

**Код FWSEC никогда не грузился в IMEM.** За всю историю проекта.

### 42/47. `WPR2` после V67 не восстанавливается записью из EFI

Проверка 2026-09-29: работающая реализация
bendy2 (`0001-58015903-cmp90hx-direct-compute.patch`) **явно
сохраняет и восстанавливает `WPR2`
вокруг V67**:

```c
wpr2Lo = GPU_REG_RD32(pGpu, 0x001fa824U);
wpr2Hi = GPU_REG_RD32(pGpu, 0x001fa828U);
for (attempt = 0; attempt < 2; attempt++) {
    GPU_REG_WR32(pGpu, 0x001fa824U, wpr2Lo);   // перед V67
    GPU_REG_WR32(pGpu, 0x001fa828U, wpr2Hi);
    ...ExecuteBooterLoad...                     // V67
}
GPU_REG_WR32(pGpu, 0x001fa824U, wpr2Lo);       // после V67
GPU_REG_WR32(pGpu, 0x001fa828U, wpr2Hi);
// и только потом — SS1, SS0
```

Это ровно тот эффект, который здессь
измерен: V67 меняет `WPR2_LO` `0x01F7E000 → 0x01EAD000`.
Значит это **известная особенность
эксплойта, которую эталон обходит**,
а не наша находка.

Восстановление по эталону внесено
(`E5-после-восстановления` + `FLRX WPR2
восстановлен`) — и **не сработало**:

```
FLRX   WPR2 восстановлен после V67:
       lo 0x01F7E000->0x01EAD000  hi 0x01F7EE00->0x01F7EE00
       *** НЕ УДЕРЖАЛОСЬ ***
```

Запись `0x01F7E000` в `0x001FA824` после V67 **не липнет**.
Возможное объяснение: `WPR2` ставит FWSEC —
привилегированный код на GSP через
команду `FRTS`, — а хостская запись в
этот регистр после V67 игнорируется.
В эталоне запись делает ядренный
драйвер, контекст иной, поэтому
проверить, липнет там запись или нет,
нельзя.

**Чего это НЕ доказывает**, что
испорчённый `WPR2` и есть причина
отказа анлока. Все строки `OKCHK … OK`
снимаются **до** ботера, то есть
описывают состояние, которое к
моменту загрузки Windows уже не
существует. Но `WPR2` в Windows **никто не
читали**: следующий шаг — чтение
`0xF61FA824`/`0xF61FA828` через RWEverything (`BAR0 = 0xF6000000`).

**Правило:** перед тем, как «чинить»
эффект, измерить его на принимающей
стороне. Мы два раза строили
выводы по логу EFI, тогда как вопрос
был про поведение в Windows.

### Симптомы, которые это объясняет разом

```
imem_ns=0x00000000 want=0xEC547D23 MISMATCH
CMDIN  *** buffer UNCHANGED -> fwsec did NOT execute the command
FWSEC ours FAIL wpr2=0x1FFFFE00/0x00000000 dbg=0x00000000 scratch0e=0x00000000
PLMM   privLevelMask=0x0004CB8F -> wpr2 reads are priv-masked
```

### Причина

Поля `FALCON_DMATRFCMD` (`dev_falcon_v4.h`):

```
SEC = 3:2    IMEM = 4:4    WRITE = 5:5    SIZE = 10:8    CTXDMA = 14:12
```

Было:

```c
0 | (6 << 8) | (0 << 12) | (fwsecImemSec << 4) | (1 << 2)
```

`fwsecImemSec` — переменная с именем «secure» — попадала в бит 4, который
`IMEM`. При `fwsecImemSec = 0` в карту уходило `0x604` = `IMEM:0, SEC:1`,
то есть DMA писала в **DMEM**.

Эталон — `kgspExecuteHsFalcon_GA102` (`kernel_gsp_falcon_ga102.c:213-272`),
единственная реализация FWSEC для GA10x (на 90HX с ней анлок работает):

| | `SIZE` | `CTXDMA` | `IMEM` | `SEC` | cmd |
|---|---|---|---|---|---|
| IMEM | 256B | 0 | **1** | **1** | `0x614` |
| DMEM | 256B | 0 | **0** | **0** | `0x600` |

### Что из этого следует

* `dbg=0` и `FRTS_ERR_CODE=0` **не означали успеха** — коду нечего было
  выполнять, и он не запускался. Прежняя трактовка «FWSEC отработал, но
  записал не туда» была неверна.
* Ни «высота FRTS», ни «маржа `WPR_END`», ни «версия подписи» не могли
  ничего дать: до запуска кода дело не доходило.
* `WPR2` нельзя было использовать как критерий: `__PRIV_LEVEL_MASK`
  (`0x1FA7CC`) = `0x0004CB8F` ≠ 0, чтение прикрыто.

### Исправлено

* команды DMA приведены к `0x614` / `0x600`, `fwsecImemSec` не используется;
* добавлена проверка `IVER` — чтение IMEM в 9 точках после DMA. Её не
  было, и поэтому пустой IMEM был **неотличим** от «DMA не работает»;
* `BOOTVEC` документирован как `imemVa` (`IMEMVirtBase`), согласованный с
  `imemPa` — при совпадении значений в 0 это не видно, но обязательно.

### 36.1 Урок: сверять имена с битовыми полями, а не с интуицией

Ошибка стоила месяцев прогонов и выглядела безобидно: переменная называлась
`fwsecImemSec`, стояла в позиции «похоже на secure», и лог печатал
`imem_sec_bit=0` — то есть **сам лог подтверждал ошибочное значение, а не
исправлял его**. Расхождение было видно только при сравнении с полями
регистра из заголовка драйвера.

Общее правило: когда значение уходит в аппаратный регистр, источник
истины — описание поля (`DRF_SHIFTMASK`), а не имя переменной.

---

## 35e. `WPR2` НЕ РЕАГИРУЕТ НИ НА ЧТО — и мы не могли это увидеть

Прогон `out/usb-log-margin128-fix.txt`: рассинхрон устранён (`GEOM profile
and wpr meta agree`, `meta.frtsOffset=0x1F7E00000`), и `WPR2` всё равно не
встал. Сравнение двух прогонов, где менялась только мета:

| прогон | `meta.frtsOffset` | `WPR2` после |
|---|---|---|
| `margin128` | `0x1FFE00000` | `0x1FFFFE00/0x00000000` |
| `margin128-fix` | `0x1F7E00000` (сдвиг 128 МБ) | `0x1FFFFE00/0x00000000` |

**Значение побайтово одинаково** при сдвиге `frtsOffset` на 128 МБ, при том
что FWSEC рапортует `dbg=0` и `FRTS_ERR_CODE=0` (`scratch0e=0x00000000`).

### Почему это нельзя было увидеть раньше

Дамп DMEM после прогона обрезается на 110 словах (смещение `0x1C4`), а:

* `DMAP` лежит на `0x560`;
* буфер команды — на `0x7C0`;
* `cmd_out_buffer` — рядом.

То есть **свидетель состояния FWSEC не печатался вообще**. Отсюда была
неразличимость двух гипотез:

* (а) FWSEC исполнился, но записал результат не туда;
* (б) FWSEC не исполнился вовсе, а `dbg=0` — состояние после старта.

### Что добавлено

Метки `DMAP`, `CMDIN`, `CMDOUT`, `SCR`, `PLMM` в `fwsec_boot_gsp_sig()`
(сборка `md5 726d21bf664e97520274cce36e135839`). Ключевая — `CMDIN`:
если буфер команды обнулён, FWSEC исполнил команду и проблема в записи
`WPR2`; если не изменён — не исполнил.

Отдельно проверяется `NV_PFB_PRI_MMU_WPR2_ADDR_LO__PRIV_LEVEL_MASK`
(`0x1FA7CC`): **если он ненулевой, все наши чтения `WPR2` были
недостоверны с самого начала** — регистр прикрыт, и «не встал» могло
означать «не читается». Это проверяется впервые.

## 35d. НАЙДЕН РАССИНХРОН: `build_wpr_meta()` считала геометрию мимо профиля

Прогон с `TARGET_WPR_END_MARGIN = 0x08000000` (`out/usb-log-margin128.txt`)
**не защёлкнул `WPR2`**, но вскрыл настоящую причину, почему маржа не могла
сработать. Лог показывает расхождение двух источников правды:

```
META  ... frtsOffset=0x1FFE00000  wprEnd=0x1FFF00000 ...
GEOM  margin=0x8000000 (128 MB)  wprEnd=0x1F7F00000  frts=0x1F7E00000 ...
```

В `build_wpr_meta()` геометрия считалась **заново, мимо `TARGET PROFILE`**:

```c
wprEnd = m->vgaWorkspaceOffset & ~0x1FFFFULL;   /* маржа НЕ вычиталась */
m->frtsOffset = m->gspFwWprEnd - m->frtsSize;
```

Поэтому добавление маржи изменило баннер, строку `GEOM` и FWSEC-команду, но
**не** `GspFwWprMeta`, которая реально уходит в FWSEC и booter. Два
источника правды для одной величины; рассинхрон был **молчаливым** — обе
строки выглядели правдоподобно.

### Исправлено

* `build_wpr_meta()` берёт геометрию из профиля:
  `wprEnd = (vgaWorkspaceOffset - TARGET_WPR_END_MARGIN) & ~0x1FFFF`;
* в лог добавлена явная сверка (чтобы такое больше не прошло молча):

```
GEOM  profile and wpr meta agree
GEOM  *** MISMATCH: meta frts=... vs profile frts=... - BUILD BUG
```

Проверено для марж 0/64/128/256 МБ — `meta_frts == profile_frts`.

### Следствие для плана

**Маржа 128 МБ ещё не проверена по-настоящему**: в прошлом прогоне она
дошла только до FWSEC-команды, а мета осталась старой. Следующий прогон
ставит задачу FWSEC согласованно впервые.

### 35d.1 Гипотеза «FRTS попадает в область bootBin» ослаблена

FWSEC при любой марже отдаёт `dbg=0` и `FRTS_ERR_CODE=0`
(`scratch0e=0x00000000`) — то есть **сам считает, что отработал нормально**.
Если бы запрос лочил WPR2 поверх чужого региона, ожидаем ненулевой код
ошибки. Значит гипотеза о неверной высоте FRTS менее вероятна, и смотреть
надо в другое место:

* `cmd_out_buffer` из `DMAP` (`dmem[0x570]`, размер `dmem[0x574]`, 64 Б) —
  драйвер его не читает, но FWSEC может писать туда результат;
* `NV_PBUS_VBIOS_SCRATCH(0x15)`, биты `15:0` = `SB_ERR_CODE`;
* сырое значение `WPR2` вместе с `__PRIV_LEVEL_MASK` (`0x1FA7CC`) — чтобы
  отличить реальную запись от PLM-прикрытого чтения.

## 35c. РАЗБОР ДРАЙВЕРА 610.43.03: найдена `WPR_END_MARGIN` — единственная ошибка

Исходники `NVIDIA-kernel-module-source-610.43.03` нашлись на машине
(`Desktop\unlock - наработки\`), версия совпадает с нашим
`gsp_ga10x.bin`. Для GA102/GA104 диспетчеризация идёт в HAL `_TU102`, так
что разбор `turing` — это разбор нашего чиста. Полный разбор с
построчными ссылками: [docs/70HX-DRIVER-ANALYSIS.md](docs/70HX-DRIVER-ANALYSIS.md).

### Что ОКАЗАЛОСЬ ВЕРНЫМ (и это важно)

* Команда FRTS совпала с драйвером **побайтово**, все 11 полей.
  `gfwImageSize = 0` и `flags = 2` — **штатные значения драйвера**
  (`s_prepareForFwsec_TU102`, строки 311–315). Гипотеза §35 п.1
  («поставить настоящий `gfwImageSize`») **мертва**: настоящий и есть ноль.
* Формула `WPR2_LO = frts >> 8` — **тождество** формуле драйвера
  `(frts >> ALIGNMENT=0xC) << 4`, где `VAL` лежит в битах `31:4`.
  Это не экстраполиция с одного замера на 10 ГБ.
* Смещения `WPR2` (`0x1FA824`/`0x1FA828`) и scratch `0x1438` совпали
  с `dev_fb.h` и `dev_bus.h`. Адреса не перепутаны.
* Структура `DMAP` — поле в поле, включая `initCmd` по `+0x2C` от
  начала структуры (абсолютный `0x58C`) и `cmdInBufferOffset = 0x7C0`.

### Что НАЙДЕНО

`kernel_gsp_tu102.c:817`:

```c
gspFwWprEnd = NV_ALIGN_DOWN64(vbiosReservedOffset
                               - kgspGetWprEndMargin(pGpu, pKernelGsp),
                               WPR_ALIGNMENT);
frtsOffset  = gspFwWprEnd - frtsSize;
```

`kgspGetWprEndMargin` (`kernel_gsp.c:6552`) при незаданном реестровом
оверрайде складывает `pmuReserved + frtsSize(1M) +
gspRmBootUcodeSize(0x6000) + sizeOfRadix3Elf(~84M) + fwHeap + nonWprHeap`.

**Наш `TARGET PROFILE` маржу не вычитал вовсе** — это была
`WPR_END = (FB - PRAMIN) & ~0x1FFFF`. По нашим реальным величинам
(`.fwimage` = 84 МБ из лога) маржа составляет порядка **100–150 МБ**.

FRTS обязан лежать **над** `bootBin` и ELF GSP. Если попросить FWSEC
защёлкнуть `WPR2` слишком высоко, под защиту попадёт чужой регион, и
FWSEC **молча откажется** — ровно наблюдаемое поведение (`dbg=0`,
`scratch0e=0`, `WPR2` не изменился).

### Внедрено

`TARGET_WPR_END_MARGIN` (по умолчанию `0x08000000` = 128 МБ), печать
геометрии в лог строкой `GEOM`, две проверки времени компиляции
(маржа ≤ половины FB; `frtsOffset` ниже `vgaWorkspaceOffset`) —
проверены на живость, обе срабатывают.

Драйвер допускает задать маржу реестром (`RM_GSP_WPR_END_MARGIN`),
то есть значение подбирается экспериментально — отсюда перебор.

### 35c.1 Постовое `0x1FFFFE00` — это НЕ FRTS-WPR2

```
WPR2_LO = 0x1FFFFE00  ->  VAL (31:4) = 0x1FFFFE0  ->  frts = 0x1FFFFE0000 = 128 ГБ
```

Никакая геометрия FB такого не даёт. Значит это постуровое состояние
регистра вообще не про FRTS, и сравнивать его с расчётным `frts` не имело
смысла. Отсюда же — почему оно не менялось: FWSEC туда не пишет.

### 35c.2 FWSEC отчитывается об успехе

`NV_PBUS_VBIOS_SCRATCH(0x0E)`, биты `31:16` = `FRTS_ERR_CODE`; драйвер
требует `== 0`. В логе `scratch0e=0x00000000` — **старшие 16 бит нулевые**.

То есть вопрос не «почему FWSEC упал», а «почему он, сообщив об успехе,
не защёлкнул WPR2». Драйвер затем требует `wpr2HiVal != 0` («WPR2 найден»);
у нас HI = `0x00000000` — **ровно этот случай**. Именно поэтому проверять
падение FWSEC бессмысленно, и проверять надо геометрию.

## 35b. ШАГ 1 ЗАКРЫТ: кадровый буфер недостижим для DMA-движка GSP

Два прогона (`out/usb-log-step1.txt`, `out/usb-log-step1-fix.txt`).

Первый дал `ctrlA=FAIL` — см. [§35a](#35a-первый-прогон-шага-1-ctrlafail--виновата-проба-а-не-железо).
После исправления окна DMEM контроль прошёл:

```
FBP-A  sysmem->dmem ok  got=0xEC547D23 want=0xEC547D23  PASS
FBP-A  w[1]=0x9E41D714 w[2]=0xAB4D9CAC w[3]=0xA04AC0FB  or=0xFF5FFFFF
FBP-B  sysmem->dmem bad  addr=0x600000000 -> нули
FBP-C  frts@0x1FFE00000: нули x8  ZERO
FBP-D  wprEnd / midfb: нули
FBP-G  readback 0x6C617470 0x00080008 0x00000090 0x00000000  MISMATCH
FBP    VERDICT ctrlA=PASS frtsRead=zero write=sent roundTrip=FAIL
                 conclusion=frts-NOT-reachable-via-dma
```

Три слова после первого совпали с началом `src/blobs/fwsec_ga104.bin`
(`23 7d 54 ec | 14 d7 41 9e | ac 9c 4d ab | fb c0 4a a0`), то есть
механизм `sysmem → DMEM` заведомо исправен. Отрицательный контроль B
тоже корректен: неиспользуемый адрес даёт нули, а не мусор.

**ВЫВОД: `0x1FFE00000` не адресуется DMA-движком GSP ни на чтение, ни на
запись.** Ветка «заполнить FRTS-регион напрямую» закрыта, и вместе с ней
закрывается план «скопировать `GA104.rom` в кадровый буфер» (он всё равно
был бессмысленен — ROM этих данных не содержит, §6 VBIOS-анализа).

Круг подозреваемых в `WPR2` сузился до трёх пунктов (§35): `gfwImageSize`,
кодировка `WPR2`, последовательность стадий.

### 35b.1 Ненулевой «readback» — это мусор DMEM, а не данные адреса

`FBP-G` вернул `0x6C617470` («ptal»/«lapt»), `0x00080008`, `0x00000090` —
похоже на маленький дескриптор, и это соблазнительно принять за содержимое
FRTS. **Это мусор.** `FBP-C` за миллисекунды до этого прочитал по тому же
адресу нули, а `FBP-E` показал совпадение всего блока с CRC нулей.

Причина: `DMATRF` адресуется с точностью `0x200`, поэтому при
перекрывающихся чтениях движок отдаёт прежнее содержимое буфера. Проба
теперь различает «наш паттерн вернулся» / «мусор» / «нули» тремя разными
сообщениями, чтобы такое нельзя было принять за находку.

### 35b.2 Правило: CRC != zerocrc ≠ «есть данные»

Первая версия печатала `(has data)` только по расхождению CRC с нулём, и
на прогоне это дало ложное срабатывание. Признак «в регионе что-то есть» —
**исключительно** ненулевое ИЛИ первых прочитанных слов (тест C).

## 35a. Первый прогон шага 1: `ctrlA=FAIL` — виновата проба, а не железо

Проба отработала за ~1,2 с (`TIME t=4265 → t=5455`) и дала:

```
FBP-A  sysmem->dmem ok  got=0x00000000 want=0xEC547D23  FAIL
FBP    VERDICT ctrlA=FAIL frtsRead=zero write=sent roundTrip=FAIL
```

**`ctrlA=FAIL` обесценивает все результаты C–G.** Вывод «FB недоступен»
делать нельзя. Скрипт чтения лога теперь печатает об этом предупреждение,
и сам код пробы добавляет строку `FBP NOTE: ctrlA=FAIL invalidates C-G`.

Причина — **ненулевое смещение окна DMEM в самой пробе**. Первая версия
читала по `0x300`/`0x400` через второй аргумент `gsp_dma_transfer`
(→ `DMATRFFBOFFS`). Ни один рабочий вызов в коде так не делает: все
используют `memOff = 0`, включая подтверждённый в логе:

```
DMA   dmem_hdr=0x00100001 want=0x00100001 OK
```

Исправлено: одно окно `0x000` на вход, выход и обратное чтение.

### 35a.1 Проверка «есть ли данные» была фиктивной

```
FBP-E  frts[0..0x1000] crc32=0x38E3FFEE  (has data)   <- ЛОЖЬ
```

Критерий `(crc == 0) || (crc == 0xFFFFFFFF)`, а CRC32 4 КБ нулей равен
ровно `0x38E3FFEE`. Проверка объявляла «есть данные» на **полностью
нулевом** буфере, то есть не работала никогда. Исправлено: нулевой CRC
считается на месте и печатается рядом для сравнения.

### 35a.2 `imemSec=1` смывает ВЕСЬ DMEM (хуже, чем считалось)

[§20](KNOWN-ISSUES.md) говорил, что secure-DMA в IMEM «отклоняется»
с `0xDEAD5EC1`. На самом деле ущерб шире — попытка FWSEC №2
(`sigIndex=1, imemSec=1`) забивает **весь** DMEM значением `0xDEAD5EC2`
(512 слов подряд) и даёт `dbg=0x007E0009`:

```
FWSEC   dmem[0x000]=0xDEAD5EC2
FWSEC   dmem[0x004]=0xDEAD5EC2
...
FWSEC   ????? ????? DMEM (???????? ????: 512)
```

То есть попытка не просто бесполезна — она оставляет GSP в худшем
состоянии и портит всё, что идёт после. Её следует убрать из очереди
(см. [docs/70HX-NEXT-STEPS.md](docs/70HX-NEXT-STEPS.md) §2).

## 36. Проба доступа к кадровому буферу переписана (ШАГ 1)

Прежняя `test_fb_read()` дала `0x00000000 ×4`, и это сочли за «FB
недоступен». **Вывод был неверен.** У пробы было четыре дефекта:

* нет положительного контроля — неизвестно, работает ли чтение из DMEM;
* нет отрицательного контроля — «ноль» неотличим от «DMA не исполнилась»;
* читалось всего 4 слова — пустой регион и нерабочая DMA неразличимы;
* вызывалась **после** неудачного FWSEC, на грязных GSP и DMEM.

Заменена на `fb_access_probe()` — семь тестов (A–G) с положительным и
отрицательным контролем и записью с read-back, на чистом GSP до
основного флоу. F/G дают ответ независимо от исходного содержимого FB.
Пока WPR2 не защёлкнут, регион не защищён, поэтому запись безопасна.

Результат предыдущей пробы в логе (`FBTEST ... 0x00000000 ×4`) следует
считать **недействительным**, а не отрицательным ответом.

## 38. ЛОВУШКА: `read-log.ps1` был тихо сломан и печатал «лог = 1 байт»

Ридер лога **молча** не работал: лог на флешке был полный (47 секторов,
23 725 байт), а скрипт выдавал «ЛОГ С ФЛЕШКИ (1 байт)» и останавливался на
первом секторе с сообщением «нет перевода строки».

Причина — тип, а не логика. Срез байтового массива в PowerShell — это
`object[]`, а не `byte[]`, и `IndexOf` у `object[]` сравнивает значения
**без приведения типа**:

```powershell
$raw[0..511][0..299].IndexOf(10)          # -> -1   ВСЕГДА (ищет Int32(10))
$raw[0..511][0..299].IndexOf([byte]10)    # ->  9   правильно
```

Было сломано две строки `out/read-log.ps1`: проверка «есть ли перевод
строки в начале сектора» и обрезка сектора по первому нулю — обе всегда
возвращали `-1`. Заменены на `[Array]::IndexOf(..., [byte]N)`.

**ПРАВИЛО:** в `read-log.ps1` не пользоваться `.IndexOf(<число>)` по срезу
байтов. Только `[Array]::IndexOf(..., [byte]N)`. Полное описание формата лога
и работы ридера — в [docs/LOGGING.md](docs/LOGGING.md).

Симптом вводил в заблуждение: выглядел как «приложение не записало лог».
Из-за него легко было потратить заход на пустую перезагрузку.

**Побочно:** подсказка «ожидается 577024 байта» устарела (размер изменился)
— заменена на сверку md5 с эталоном. В секцию «ключевые строки» добавлены
префиксы `FBP`, `TIME`, `BOOTER`, `GEN2`, и разбор вердикта пробы FB.

## 39. Процедура записи на флешку и снятия лога

Процедура записи на флешку и снятия лога

Полная инструкция для этой машины (метка `CMP70UNLOCK`, том `X:`) —
в [docs/FLASH-AND-LOG.md](docs/FLASH-AND-LOG.md). Кратко:

```powershell
Remove-Item X:\EFI\BOOT\BOOTX64.EFI -Force
Copy-Item  out\unlock_v3n_CMP70HX.efi X:\EFI\BOOT\BOOTX64.EFI -Force
# ... перезагрузка, F12, флешка, ждать ~2.5 минуты ...
powershell -ExecutionPolicy Bypass -File out\pull-log.ps1 -Tag <метка>
```

`pull-log.ps1` печатает лог и сохраняет копию в `out\usb-log-<метка>.txt`,
так что заходы не перетирают друг друга.

## 48. МОЯ «ПОПРАВКА» КРИТЕРИЯ ТОЖЕ БЫЛА НЕВЕРНОЙ

Сначала я решил, что 3D-метрика непригодна: мол, анлок про compute, а
CMP — карта с урезанной 3D, значит 75 Вт и 9 FPS ничего не значат.

**Пользователь опроверг, и прав был.** В `README.md` есть раздел
«Модифицированный драйвер для рендера/игр»: стоковый драйвер блокирует
CMP в рендере, и для графики ставится патченный
[NVIDIA-patcher](https://github.com/dartraiden/NVIDIA-patcher). При его
наличии ограничение снимается **на стороне драйвера**, и 3D-метрика
становится корректной.

У пользователя патченный драйвер **установлен**, карта определяется как
**RTX 3070 Ti**, и эталон 90HX с тем же драйвером тянет игры (в `tests/`
скриншот Resident Evil Requiem и лог HWiNFO).

**Значит 75–85 Вт и 9 FPS — валидный отрицательный признак, и анлок на
70HX не состоялся.**

### 48.1 Итог по исключениям

| гипотеза | как исключена |
|---|---|
| драйвер Windows перезаписывает селекторы | чтение `0x82381C/0x823820` из Windows |
| запись не доходит до ОС | там же |
| FLR стирает селекторы | там же |
| пишем не в те регистры | в fuse-блоке `0x823800..0x823838` изменяемых ровно два, и мы пишем в оба |
| `0x82380C` — настоящий селектор | запись не удержалась → отчётность |
| метрика непригодна | патченный драйвер делает 3D-метрику корректной |
| **анлок состоялся** | **НЕТ** |

### 48.2 Что я делал неправильно трижды подряд

1. **§3j** — принял `is_unlocked()=1` за доказательство анлока. Это тавтология.
2. **§37 / §46** — принял молчание нерелевантных регистров
   (`0xDEAD5EC1`, `FEATURE_READOUT`) за отказ.
3. **§48 (этот)** — объявил корректную метрику непригодной, не проверив
   README проекта, где прямо написано про патченный драйвер.

Общее правило по итогу: **прежде чем объявить результат негативным или
метрику непригодной, прочитать документацию проекта целиком.** README
лежал рядом и содержал прямой ответ на мой вопрос.

## 47. ЗНАЧЕНИЙ СЕЛЕКТОРОВ НЕТ НИ В ОДНОМ VBIOS — проверено на обоих чипах

Сравнил `GA102.rom` (90HX) с `GA104.rom` (70HX).

| константа | `GA102.rom` | `GA104.rom` |
|---|---|---|
| `0x88888888` | 1 вхождение | 1 вхождение |
| `0x00888888` | **0** | **0** |
| `0x002AAAAA` | **0** | **0** |

### 47.1 Единственное совпадение `0x88888888` — ложный след

```
0x08F64E  00 00 00 00 11 11 11 11 22 22 22 22 33 33 33 33
0x08F65E  44 44 44 44 55 55 55 55 66 66 66 66 77 77 77 77
0x08F66E  88 88 88 88 99 99 99 99 aa aa aa aa bb bb bb bb  <<<
0x08F67E  cc cc cc dd dd dd dd ee ee ee ee ff ff ff ff
```

Это **тестовый паттерн ОЗУ** `00 11 22 … FF`, повторённый в каждом байте.
В `GA104.rom` — тот же паттерн со сдвигом 2696 байт.

Почему это важно зафиксировать: поиск «значения селекторов в VBIOS»
выглядел многообещающе — константа нашлась, ровно один раз, почти на
одном месте в двух ROM. **Контекст оказался мусором.** Ещё один пример
того, что само совпадение ничего не значит без проверки окружения.

### 47.2 Прочие сравнения

| | |
|---|---|
| размер обоих ROM | 999 424 байта |
| различающихся байтов | 193 459 (19,36 %) — образы разные |
| `FWSEC`-блобы | 59 904 байта, различие **34 байта (0,1 %)** |

FWSEC между чипами почти идентичен, что согласуется с его успешной
работой.

### 47.3 Исчерпаны офлайн-источники

| источник | результат |
|---|---|
| заголовки драйвера 610.43.03 | `0x008238xx` не описан, кроме `0x823814` (ECC_DRAM) |
| VBIOS 70HX | значений нет |
| VBIOS 90HX | значений нет |
| FWSEC | различие 0,1 %, селекторов не касается |

Значения `0x88888888` / `0x00000008` имеют **единственный** источник —
эмпирический опыт 90HX. Для GA104 они не подтверждены ничем.

### 47.4 Две оставшиеся гипотезы

**A. Драйвер Windows перезаписывает селекторы обратно.** Объяснила бы всё
наблюдаемое: fuse-shadow — тупик без обратной связи, запись липнет и
читается, а при инициализации ОС драйвер возвращает блокировку. Тогда
анлок из EFI принципиально недостижим. Проверяется **только чтением
`0x0082381C/0x00823820` из Windows** — нужен инструмент с доступом к MMIO.

**B. `0x82380C` / `0x82382C` — настоящие селекторы.** В снимке там уже
`0x00888888` и `0x00000008`. Проверяется записью плюс замером.

Общее правило: **прежде чем тратить прогоны, исчерпай дешёвые офлайн-
источники.** Здесь их было три, и все три сказали «нет».

## 46. `FEATURE_READOUT` — НЕ ТОТ ПРИЗНАК, КОТОРЫЙ Я ПРИНЯЛ ЗА НЕГО

Прогон `out/usb-log-fuse.txt`. Снимок блока fuse до и после записи
селекторов показал `0x823814` неизменным, и я записал в коде: «значения
не включают признаков на GA104».

**Это неверно.** Заголовок драйвера:

```c
#define NV_FUSE_FEATURE_READOUT                    0x00823814 /* R--4R */
#define NV_FUSE_FEATURE_READOUT_ECC_DRAM            16:16
```

Документировано **одно** поле — `ECC_DRAM` бит 16. Это «включён ли ECC для
DRAM», а не «какие признаки включены». Он и не обязан двигаться от записи
селекторов. Молчание ничего не доказывает.

### 46.1 Повторяющийся паттерн моих ошибок

Третий раз одно и то же:

| раз | что принял за отказ | что это было |
|---|---|---|
| §3j | `is_unlocked()=1` | тавтология, эхо собственной записи |
| §3h | `privLevelMask != 0` | фиксированное значение маски, не данные |
| §46 | `FEATURE_READOUT` не изменился | регистр про ECC_DRAM, к селекторам не относится |

Общее правило: **прежде чем объявить показатель негативным результатом,
проверить, что он вообще относится к проверяемому.** Молчание метрики
неинформативно, если метрика не про то, что мы проверяем. В коде
сообщение переписано так, чтобы это повторение не выглядело как вывод.

### 46.2 Что снимок всё же дал

**Побочный эффект:** `0x00823818` изменился `0x016DB6ED -> 0x00000000`,
хотя мы туда не писали. Запись в селекторы имеет последствия за их
пределами. Регистр в драйвере не описан.

**Похожие значения по другим адресам:**

| адрес | значение | наш «аналог» |
|---|---|---|
| `0x0082380C` | `0x00888888` | `0x88888888` пишем в `0x0082381C` |
| `0x0082382C` | `0x00000008` | `0x00000008` пишем в `0x00823820` |

Гипотеза, не вывод: возможно, это fuse-отчётность, а не регистры записи.

### 46.3 Смена подхода: собирать структуру

Окно расширено с 12 до 48 регистров (`0x00823780..0x0082383C`), diff
печатается целиком, всё изменившееся **помимо** двух наших адресов
помечается `UNREQUESTED SIDE EFFECT`. Только чтение.

Причина: драйвер не описывает `0x008238xx` почти никак — из всего окна
найдено одно определение. Дальнейшее угадывание значений стоило прогоны;
полезнее собрать структуру.

## 45. `SKIP_FLR` НЕЖИЗНЕСПОСОБЕН: без сброса WPR2 не возвращается в постовой вид

Прогон `out/usb-log-skipflr.txt`, 2026-09-29. Карта перестала
инициализироваться. `PREFLR` показал причину:

| | с FLR | без FLR |
|---|---|---|
| `WPR2_LO` | `0x01F7E000` | `0x01EAD000` (уехал на `0xD1000`) |
| `cpuctl` | `0x00000000` | `0xBADF5620` |
| `GFW` | `0xBADF5040` | `0xBADF1100` |

Без сброса GSP остаётся в `BADF`-состоянии, `WPR2` не чистый, драйвер
падает. Это подтверждает предупреждение в коде (`frts_err=0xbe`).

**`SKIP_FLR=0` возвращён.** Вопрос «переживают ли селекторы FLR» этим
не закрыт — карта не поднялась, мерить нечего.

### 45.1 Побочно: `SINGLE_CARD_ONLY` работает

`BootNext` не пишется, повторного POST нет. Ловушка §44 закрыта. Заодно
видно, что multi-card цикл проходит **обе карты за одну загрузку**
(две строки `MC`: `g_mcIndex=1`, затем `g_mcIndex=0`).

### 45.2 Следующий принцип: измерять эффект, а не эхо

`is_unlocked()` перечитывает только что записанные регистры — тавтология
(§43). Чтобы проверить верность значений, добавлен снимок блока fuse
**до и после** записи с печатью diff, с акцентом на документированный
`NV_FUSE_FEATURE_READOUT = 0x00823814` (R--4R): если запись включает
признаки, readout обязан сдвинуться. Если нет — значения для GA104 не
подходят.

Общее правило: **проверка «запись применилась» и проверка «изменение
произошло» — разные проверки.** Первая всегда проходит для тупиковых
регистров вроде fuse-shadow, вторая — единственная, что что-то значит.

## 44. ЛОВУШКА: `BootNext` на саму флешку = POST = стирание анлока

Замеры пользователя 2026-09-29: GPU-Z render test **75 Вт**, Cyberpunk
2077 **9 FPS / 85 Вт**. Перезапуска между прогоном и замером не было —
значит fuse-shadow не стирался POST'ом, и причина в коде.

### 44.1 Механизм

```c
g_mcAdvance = (g_mcCount > 0) && (g_mcIndex + 1 < g_mcCount);   /* 2 карты -> TRUE */
...
mc_set_bootnext_self(ImageHandle);   /* пишет BootNext = наш EFI на флешке */
```

Прошивка загружает флешку повторно. Это **полный POST**, а `fuse-shadow`
с `SS0`/`SS1` обнуляется. Анлок записывается и тут же стирается.

### 44.2 Почему это не видели

Второй прогон затирает первый (область лога чистится каждый раз) и
выглядит **идентично**: тоже пишет селекторы, тоже читает их обратно,
тоже печатает `*** UNLOCKED ***`. Отличить «анлок пережил» от «анлок
затёрт вторым POST'ом» по логу невозможно. Ни одна строка не сообщала,
писался ли `BootNext`.

### 44.3 Исправлено

Флаг `SINGLE_CARD_ONLY` убирает **все три** вызова
`mc_set_bootnext_self` (основной финал, путь «карта уже разлочена»,
fire-путь). Проверено по бинарю: строки `NVIDIA CMP unlock` и `v2.90-WR`
отсутствуют, размер упал 643 072 → 636 928 байт. Ни одного пути
перезагрузки не осталось.

### 44.4 Общее правило

**Механизм, помогающий одной задаче, может незаметно уничтожать результат
другой.** Здесь: «обработать все карты» (задача multi-card) против
«анлок должен дожить до Windows» (основная задача). Побочное действие —
перезагрузка — необратимо стирало основной результат, при этом
отображалось как полный успех.

Правило: перед любым действием, переживающим перезагрузку, спрашивать —
**сохранит ли это то, ради чего мы здесь**. Если нет — действие
выключается, даже если само по себе полезно.

### 44.5 Смежное: почему пропадал маркер `END`

`done:` вызывал `snapshot_state()` при `!g_snapOk`, а та читает MMIO.
После `do_flr()` функция «мертва» — чтение зависало. Отсюда логи без
`END`. Добавлен флаг `g_postFlr`, при котором этот вызов пропускается,
а всё нужное снимается строками `PREFLR` **до** сброса.

## 43. ЛОЖНОЕ УТВЕРЖДЕНИЕ ИСПРАВЛЕНО: `is_unlocked()=1` ≠ анлок состоялся

Я написал в пяти местах документации «АНЛОК РАБОТАЕТ» на основании
`is_unlocked()=1`. **Это было неверно.**

Пользователь, 2026-09-29: render test в GPU-Z — **75 Вт**, что на анлок
не похоже. И он справедливо уточнил, что говорил только про определение
карты в системе, а не про анлок.

### 43.1 Почему `is_unlocked()` ничего не доказывает

```c
return (mmio_read32(REG_FEAT_OVR_SM_SPD)   == VAL_SS0_UNLOCKED &&
        mmio_read32(REG_FEAT_OVR_SM_SPD_1) == VAL_SS1_UNLOCKED);
```

**Тавтология по построению:** это перечитывание двух регистров, в которые
код только что записал. Показывает «запись липнет», а не «карта
разблокирована». Функция не обращается ни к чему, что отражало бы
фактическое состояние вычислительных блоков.

### 43.2 После FLR состояние не проверялось никогда

`src/unlock_v2.c` ~8045, сразу после записи селекторов:

```c
do_flr();
```

Комментарий в коде: *«функция "мертва" до конца загрузки ОС»* — MMIO
после FLR не читается. Значит:

| момент | проверен? |
|---|---|
| до FLR, селекторы приняли запись | **да** (`STG selectors ... *** UNLOCKED ***`) |
| после FLR, селекторы уцелели | **нет** — слепая зона |
| анлок в Windows | **нет** — слепая зона |

Утверждение кода «селекторы переживают FLR (доказано 2 раза)» — эмпирика
**90HX**. На 70HX не проверялось.

### 43.3 Лог обрывается без маркера `END`

Последняя строка прогона — `STG reached 'done' label`. Итоговая сводка
не дописана, то есть прогон не завершился штатно. Вероятная причина —
обращение к устройству после FLR, но это тоже не проверено.

### 43.4 Что реально подтверждено

| утверждение | статус |
|---|---|
| FWSEC грузится и исполняет команду FRTS | **да** — `WPR2` защёлкнут, обе проверки драйвера пройдены |
| Регистры `SS0`/`SS1` принимают запись | **да** |
| Определение карты в системе изменилось | **да** (со слов пользователя) |
| **Анлок состоялся** | **нет** — 75 Вт |

### 43.5 Главный урок

**Показание прибора внутри того же контура, который мы проверяем, не
является независимым доказательством.** `is_unlocked()` читает регистры,
которые только что записал, — это проверка «дошёл ли мой приказ», а не
«сработало ли что-нибудь».

Требования к функции вида «is_X()», которой мы хотим верить:

1. читать то, что **не писал сам**, либо
2. измерять **наблюдаемый эффект** (мощность, частота, пропускная
   способность), либо
3. явно называть то, что она проверяет: `is_selectors_written()`, а не
   `is_unlocked()`.

**Переименовать `is_unlocked()` в `is_selectors_written()`.** Имя функции
должно описывать проверку, а не hoped-for результат.

### 43.6 Побочно: константы селекторов общие для двух чипов

`VAL_SS0_UNLOCKED = 0x88888888` и `VAL_SS1_UNLOCKED = 0x00000008` стоят
вне блока `TARGET`, тогда как вся остальная геометрия профиля раздельная.
Значение подтверждено на **GA102**; для **GA104** перенесено без проверки.
Запись при этом липнет — регистр не проверяет смысл, — что и даёт
наблюдаемую картину «всё хорошо, анлока нет». См. NEXT-STEPS §3k.

## 43. ЛОЖНОЕ УТВЕРЖДЕНИЕ ИСПРАВЛЕНО: `is_unlocked()=1` ≠ анлок состоялся

`out/usb-log-selectors.txt`:

```
G2NVR  CMP90G2=37 есть, но свип выключен -> fire-режим НЕ включаем
STG    reached selector block success=0 direct=0 early=1 gen2Fire=0
STG    PLM 0xFFFFFFFF -> 0xFFFFFFFF readback 0xFFFFFFFF OPEN
STG    selectors: want SS0=0x88888888 SS1=0x00000008 | got SS0=0x88888888 SS1=0x00000008 *** UNLOCKED ***
STG    is_unlocked()=1
```

**Подтверждено пользователем 2026-09-29: видеокарта начала правильно
определяться системой.** Это независимое подтверждение со стороны хоста.

| признак | до | после |
|---|---|---|
| `WPR2` | `0x1FFFFE00/0x00000000` | **`0x01F7E000/0x01F7EE00`** |
| `SS0` | `0x05173106` | **`0x88888888`** |
| `SS1` | `0x00000007` | **`0x00000008`** |
| `is_unlocked()` | `0` | **`1`** |

### Три исправления, каждое — одно

| # | Исправление | Раздел |
|---|---|---|
| 1 | бит `IMEM` в `DMATRFCMD` (`0x604` → `0x614`) | §36 |
| 2 | `g_fwsecImemSec = 1` (было `0`) | §37 |
| 3 | fire-режим не входит при выключенном свипе | §42 |

Первые два убрали неверную расшифровку регистра и ошибочный вывод из неё.
Третье — блокировку состояния в NVRAM, из-за которой рабочий путь
анлока был недостижим при `WPR2`, уже защёлкнутом.

### 43.1 Что осталось открытым

* **PCIe Gen2** не восстановлен (свип выключен рубильником) — на анлок не
  влияет, ограничивает host↔GPU.
* **Порты IMEM/DMEM отказывают** после `STARTCPU`. «Что изменил маппер в
  DMEM» неразрешимо текущими средствами: три разных адреса дают одно
  значение `0xDEAD5EC2`, то есть это отказ порта, а не содержимое.
* **Замер производительности 70HX не делался.** Цифры ~3700 t/s в README —
  от проверенной сборки 90HX.

### 43.2 Урок по трём правкам

Все три ошибки были одного класса: **сообщение от asserted-ного кода
интерпретировалось как отказ, хотя код работал.**

| код | сообщение | как читалось | что означало |
|---|---|---|---|
| `0xDEAD5EC1` | отказ читать secure-IMEM | «secure-доступ закрыт» | IMEM защищён, код загружен |
| `0xDEAD5EC2` | отказ читать secure-DMEM | «буфер команды не изменён» | порт отказал, содержимое неизвестно |
| `CMP90G2=37` | есть счётчик незавершённых циклов | «идёт gen2-свип» | блокирует обычный путь |

Общее правило: **`DEAD` в имени значения — это ответ на запрос, а не
сообщение об отказе выполнить действие.** Прежде чем объявлять
оборудование неспособным, нужно установить, что именно этот код
сообщает и на каком уровне привилегий задан вопрос.

## 42. ВЗАИМНАЯ БЛОКИРОВКА: счётчик `CMP90G2` подавлял запись селекторов

`out/usb-log-stages.txt`:

```
PRE   ... SS0=0x05173106 SS1=0x00000007        (начало прогона)
STG   gen2: no branch taken (have2=1 success=0 direct=0 early=1)
STG   reached 'chainload'
STG   is_unlocked()=0 (SS0=0x05173106 SS1=0x00000007)   (конец)
STG   reached 'done' label
```

**`SS0/SS1` не изменились ни на бит.** Нужные для анлока значения —
`SS0=0x88888888`, `SS1=0x00000008` (`VAL_SS0_UNLOCKED`/`VAL_SS1_UNLOCKED`).
Из-за этого `is_unlocked()=0` и вердикт «НЕ РАЗБЛОКИРОВАН», хотя `WPR2`
защёлкнут и `earlyOk=1`.

### Цепочка

| строка | условие | результат |
|---|---|---|
| ~6743 | `have2 && gi <= RJ16_N` | **TRUE** → `g_gen2Fire = TRUE` |
| ~7515 | `g_gen2Fire && have2 && g_gen2Enable` | FALSE — свип выключен рубильником |
| ~7910 | `!have2 && (успех)` | FALSE — `have2=1` |
| ~7960 | `(успех) && !g_gen2Fire` | **FALSE** — селекторы пропущены |

Счётчик `CMP90G2` остался в NVRAM от прежней работы с 90HX. Он означает
«свип в процессе», свип выключен, а из-за счётчика не выполняется
обычный путь — тот самый, который записывает `SS0/SS1`.

**Взаимная блокировка:** выполняется только FWSEC, признак анлока не
выставляется никогда, и это выглядит как «FWSEC не помог», хотя он
отработал.

### Исправлено

```c
if (g_gen2Enable && have2 && gi <= RJ16_N && g_mcCount > 0) {
```

Пока свип выключен, счётчик не входит в силу и не подавляет обычный путь.
Ручная чистка NVRAM не требуется.

Общее правило: **состояние, которое управляет отключённой подсистемой,
не должно блокировать включённую.** Иначе выключатель превращается в
тупик, а не в ускоритель работы.

### 42.1 Побочно: строка лога ломала сборку

`ulogf` с `g_gen2Fire` стоял в общем коде, вне `#ifdef PCIE_GEN2_REJOIN`.
Сборки без этого флага падали с `g_gen2Fire undeclared`. Исправлено
макросом `GEN2_FIRE_STATE()`.

### 42.2 Порты DMEM отказывают после secure-загрузки — вопрос закрыт

```
OKCHK  dmem[0]=0xDEAD5EC2
OKCHK  dmem[0x560]=0xDEAD5EC2 (DMAP)
OKCHK  cmdInBufferOffset(dmem[0x568])=0xDEAD5EC2
```

Три разных адреса — одно значение. Это **отказ порта**, а не содержимое
буфера. Значит «выполнял ли маппер команду» по `CMDIN` установить
невозможно: чтение не работает в принципе.

### 42.3 `%clock64` — не тактовая частота SM, а опорный счётчик

Первая версия `inst/clk/SM` считала так: каждое ядро само измеряет
тактовую частоту вокруг своего рабочего цикла, чтобы instruction
throughput был нормирован на такты. Так вот `%clock64` на этой карте
считает **не в тактовой частоте SM**, а в фиксированном опорном
эталоне **≈4,5 ГГц**:

```
inst/clk/SM = 387.10   ->   %peak = 302.4%
```

Столбцы, которые с этого выросли, физически невозможны: 387
инструкций за такт на SM при архитектурном потолке 128, и частота выше
максимума, который у самой NVIDIA указан как 1545 МГц. Число, не
согласованное с физическим пределом, — не результат, а повод
остановиться и искать, а не публиковать.

**`%globaltimer` при этом надёжен.** Сверка с реальным временем на хосте
даёт почти единицу: `gt/wall = 0.999`. Из двух счётчиков PTX годится
только `globaltimer`; `clock64` для частоты использовать нельзя.

**Исправление:** частота берётся из NVML
(`nvidia-smi --query-gpu=clocks.sm`) в том же окне замера, а
правдоподобие проверяется против `CLOCK_RATE` устройства (§42.4).

### 42.4 NVML отдаёт протухшую частоту

Первый юнит таблицы выдал **420 МГц** при пустой остановке ядра и отсёк
сразу после: из этого следовало 387 inst/clk/SM и 302 % от пика (§42.3).
Ядро выходит на установившуюся частоту за единицы миллисекунд, но
NVML-сервер к этому моменту ещё не снял свежий показатель и отдаёт
предыдущий.

Что вошло в код:

* первый повтор каждого юнита **отбрасывается** как прогрев;
* из оставшихся берётся **медиана**, а не первый попавшийся;
* частота проверяется на правдоподобие против `CLOCK_RATE` устройства
  (допуск ±50 % сверху, ×0,5 снизу);
* если проверка не пройдена, в строке печатается **прочерк, а не число** —
  публиковать производное от заведомо негодной частоты хуже, чем не
  публиковать ничего.

Отдельно: окно замера должно быть длиннее интервала сэмплера NVML.
При 20 мс окна и 40 мс интервала сэмплер не попадал в окно вовсе,
и питание в колонке W было шумом. Сейчас окно 100 мс, повторов 3.

### 42.5 Компилятор свёрнул замер в замкнутую формулу

`x[u] = x[u] + k` с константой `k` NVVM сводит в
замкнутую форму: восемь сложений за итерацию превращаются в два IMAD.

Из-за этого замер IADD32 дал **144 % от пика** — физически невозможное
значение. Причина не в железе: тест мерил не скорость инструкций, а
скорость сокращения выражения компилятором. Сложение с константой
выносится вперёд и пересчитывается одним умножением.

Исправление: `asm volatile("add.s32 ...")`, где второй операнд зависит от
счётчика цикла, — так NVVM не может вынести его из цикла. `volatile`
обязателен: без него компилятор вправе переставлять asm относительно
тела цикла.

Общий класс — «компилятор сворачивает тест, а замер честно показывает
свёртку». Отличить от настоящего ограничения можно только опорным
значением из другой системы; здесь это пиковая частота инструкций из
документации по архитектуре.

**Общий класс для всех четырёх ложных показаний** (§42.3–§42.6), а не
только для этого: четыре замера подряд выглядели как результат, и все
четыре оказались негодными — опорный счётчик, протухшая частота,
компилятор и отсутствующий интринсик. Правило, которое из этого следует:
**замер, у которого нет независимого опорного значения, — не замер.**

### 42.6 `__dp2a` не существует — и раздувает весь модуль

В CUDA C нет встроенного `__dp2a`; `dp2a` существует только как PTX
(с `sm_61`). Написанная вручную строка `dp2a.u32.u32.u32` раздувает ядро
до **278 виртуальных регистров** при 256 потоках в блоке.

278 × 256 = 71 168 > 65 536 регистров на SM, поэтому драйвер отказал
`INVALID_PTX` на **весь модуль**, а не только на это ядро:

```
PTX JIT failed: 218 CUDA_ERROR_INVALID_PTX
```

Одно отравленное ядро убивало остальные пять, которые были в порядке.
`volatile` и `compute_86` вместо `sm_86` не помогли — размер PTX не
менялся ни на байт.

Диагностика пришла почти вслепую: `cuGetErrorLog` в `nvcuda.dll` этой
сборки **не экспортируется**, поэтому сообщение JIT не содержит ни номера
строки, ни имени символа — только код 218. Что помогло — кумулятивная
биссекция: NVRTC-компиляция преамбулы + накопленных ядер, по одному, с
проверкой JIT после каждого шага. Первые пять прошли, шестое упало —
виновник найден за шесть итераций, тогда как `ptxas` искал слепо.

Обход: юнит убран. Классы конвейера, которые важны здесь — FP32, FP16,
BF16, DP, INT — покрыты и без него. Драться с компилятором за
наименее показательный юнит невыгодно.

### 42.7 Часть диагностики печатается в консоль и в лог не попадает

`Print` пишет в консоль, `ulogf` — в область лога на флешке.
Несколько важных диагностик используют `Print`:

* `gsp_dma_wait_not_full` / `gsp_dma_wait_idle` (`src/unlock_v2.c:2004`,
  `:2014`) — «ВНИМАНИЕ DMA queue FULL», «ВНИМАНИЕ DMA не IDLE»;
* `diag_one` / `diag_regs` (`:1200-1222`) — дампы `SEC2_*` и прочие
  `0xBADFxxxx`.

**Следствие, в которое я попал.** Я проверил 24 сохранённых лога на
`DMA queue FULL`, не нашёл ни одного вхождения и написал пользователю,
что «раньше не встречалось, это новое поведение». **Вывод был
бездоказателен:** этих строк в логах нет и не могло быть, потому что
они туда не пишутся. Их отсутствие доказывало только то, что их туда
не пишут.

Правильный вывод потребовал бы консоли того прогона, а её у нас нет:
при каждой загрузке мы видим только экран.

**Как проверить такие вещи.** Сначала найти, какой функцией печатается
сообщение, и только потом искать его в логах. `Select-String` по всем
`out/usb-log-*.txt` даёт уверенное «ноль вхождений» и легко читается
как «этого никогда не было» — а означает совсем другое.

Полезная поправка к тем же двум функциям: оба предупреждения печатаются
после исчерпания 20000 итераций опроса, и **код после них не
останавливается** — он продолжает работу. Поэтому в прогоне
`dmafull` при них карта всё равно загрузила FWSEC, `WPR2` встал за 0 мс
и все `OKCHK` прошли.

**Диагностика, которые стоит сделать:** писать `GSP_DMATRFCMD` в лог
через `ulogf`, а не только в консоль, иначе состояние DMA-очереди
при сбое невозможно расследовать постфактум.

**Сделано 2026-09-29.** Обе функции теперь пишут и на экран, и в лог,
префикс `DMAQ`, с порядковым номером таймаута и разбором битов:

```
DMAQ   FULL timeout #1 cmd=0x00000615 (bit0=FULL стоит, bit1=IDLE снят)
DMAQ   IDLE timeout #1 cmd=0x00000615 (bit1=IDLE стоит, bit0=FULL снят)
```

Номера важны сами по себе: они показывают, **сколько** раз опрос
исчерпал 20000 итераций, а по экрану это видно только если считать
строки вручную. Счётчики `g_dmaFullTo`/`g_dmaIdleTo` и последние
значения `cmd` продублированы в сводной строке `SEC2S`, так что
состояние DMA видно вместе с окном SEC2.

### 42.8 `0xBADF5xxx` в дампах SEC2 — это не данные, а «двери заперты»

Пользователь спросил про строки вида:

```
0x840310 = 0xBADF5108
...
0x840340 = 0xBADF5108
0x840344 = 0xBADF5720
0x840370 = 0x001C0004      <- единственное без префикса BADF
0x840374 = 0xBADF5720
```

**Адреса `0x8400xx` — это SEC2**, а не видеоблок: база
`NV_PSEC = 0x840000` (`src/unlock_v2.c:565`, `:730`). Значения
`0xBADF5xxx` — проектный sentinel на «узел заперт», а не содержимое
регистров. В коде то же самое формулируется словами: `GSP залочен
(0xBADF)`, `(0xBADF = lockdown не снят)`.

Проверять по таким значениям нечего: это подтверждение блокировки,
а не показатель состояния. Ровно тот же класс, что и `FEAT_OVR_SM_SPD`,
который не читается по той же причине (п. 1b).

**Единственное исключение — `0x840370 = 0x001C0004`.** Это единственное
значение в блоке без префикса `BADF`, то есть единственное похожее на
настоящие данные, и стоит оно между `0xBADF5720` и `0xBADF5720`.
Похоже на островок читаемого регистра в запертом регионе. Проверка не
сделана; по одному значению поле опознать нельзя, нужен соседний дамп
с тем же адресом в разблокированном состоянии.

**Уточнение от 2026-09-29, после проверки исходников.** Эти строки
**не выдаются нашим приложением.** Дампа диапазона `0x840310..0x840374`
в `src/unlock_v2.c` нет: определения SEC2 заканчиваются на
`0x1C4`/`0x3C0`, а `diag_one` печатает только именованные адреса в
формате `rd ИМЯ (0x…)... = 0x…`, а не `адрес = значение`. Формат
пользователя — чистый `адрес = значение` по строке на слово, то есть
это **внешнее чтение физического адреса из Windows** (дамп такого
вида), а не вывод нашего логгера.

**Следствие для A/B, которое чуть не испортило дело.** Сравнивать
внешний дамп с нашим нельзя: это два разных инструмента, и «значение
поменялось» может означать «поменялся инструмент». Поэтому окно
теперь читает **наш же код** и пишет в лог (`sec2_window_dump`,
префиксы `SEC2W`/`SEC2S`) на границах стадий `E2-до-fwsec`,
`E2-после-fwsec`, `после-раннего-пути`, `END-финал`. Оба состояния
читаются одним кодом в один лог.

Строка `SEC2S` кроме самого окна считает `BADF=` и `live=` и печатает
текущий `dmatrfcmd` вместе со счётчиками таймаутов — чтобы сравнение
было по числам, а не по двадцати шести глазу. Значение `0x001C0004`
помечается маркером `<<0x001C0004`, чтобы в следующем логе его снова
не приняли за обычный BADF-шум.

## 41. Стадия PCIe Gen2 отключена рубильником — 83 % времени прогона

По просьбе пользователя gen2-свип сделан **опциональным**, потому что он
делал прогоны неприемлемо долгими.

Место в коде — `src/unlock_v2.c:1633`:

```c
/* v3n: gen2 по умолчанию ВЫКЛЮЧЕН. Замер времени показал: свип съедает
 * ~10.8 минут из 13 и при этом не доходит до FF (маски на 0xFFFFFFCF/8F).
 * Пока не решён вопрос WPR2, отладка идёт без gen2 — цикл сжимается до
 * ~2.2 минуты. Включать осознанно, когда WPR2 защёлкивается и понадобится
 * полный PLM. */
static BOOLEAN g_gen2Enable = FALSE;
```

Проверка — `src/unlock_v2.c:7515`:
`if (g_gen2Fire && have2 && g_gen2Enable)`.

| | |
|---|---|
| полный прогон | ~13 мин |
| из них свип gen2 | ~10,8 мин (**83 %**) |
| без свипа | ~2,2 мин |
| результат свипа | не достигает `0xFFFFFFFF` (маски `0xFFFFFFCF`/`8F`) |

Отключено не просто «медленное», а **медленное и неработающее**. Включать
осознанно можно после того, как `WPR2` защёлкнут (это уже произошло,
§38/§39) и нужен полный `PLM` для домена PCIe-Gen2.

Подробности, включая список мест, завязанных на `g_gen2Fire`, — в
[docs/70HX-PORT-STATUS.md §3a](docs/70HX-PORT-STATUS.md#3a-стадия-pcie-gen2--выключена-рубильником-решение-по-времени).

### 41.1 Та же причина — вторая оптимизация: `g_fwsecOnce`

`src/unlock_v2.c:7587`. Раньше `early_unlock_path()` звался на каждой
записи таблицы, где маска ещё не FF: 3 прохода × 41 запись = до **120
полных FWSEC-загрузок**, каждая с секундными паузами. FWSEC открывает
secure-путь и не зависит от повторов, поэтому выполняется **один раз**.

Общий принцип обеих оптимизаций: **не повторять дорогое действие,
результат которого не зависит от числа повторов.** Дешёвая проверка
результата (чтение регистра) повторяется всегда; дорогое действие — нет.

## 40. Расхождение блобов SEC2

`sec2_ucode_vbios_{49,89}_patched.bin` (20 480 байт) **не совпадают** с
кодом SEC2 из вашего ROM (19 712 байт). Используются только
dev-стадиями (`riscv_direct_start()`), в релизный путь не входят, но при
следующем использовании переизвлекаются из `GA104.rom`.

