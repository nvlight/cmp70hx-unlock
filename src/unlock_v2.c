/*
 * unlock_v2.c — NVIDIA CMP 70HX (GA104) full unlock — UEFI application
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * ORIGIN AND LICENSE — read this before redistributing.
 *
 * This file is a PORT. Upstream it targeted the CMP 90HX and came from
 * WildFlash1st/cmp90hx-unlock-for-windows, which carries NO license; the V67
 * canary exploit it performs descends from bendy2/cmp90hx, also unlicensed.
 * Absent a grant, "no license" means all rights reserved. The project ships this
 * under GPL-2.0-only because porting from a GPL project (jdowning100/
 * cmpunlocker, rejoin16 method) demands it - not because it makes the situation
 * above go away. Full statement in NOTICE; full text in LICENSE.
 *
 * PORT NOTE: upstream this file targeted the CMP 90HX (GA102, 10 GB). This
 * tree is the CMP 70HX (GA104, 8 GB GDDR6) port. Everything that depends on
 * the framebuffer size now comes from ONE place — the TARGET PROFILE block
 * below — so the two cards can no longer drift apart (that drift is what
 * breaks the WPR layout and the booter aborts with exit 0x91).
 *
 * One binary does two things, in this order:
 *   1. Unlock the card (protocol below).
 *   2. Hand the machine to the OS WITHOUT any reset, so the unlocked state
 *      survives into Windows — a POST/VBIOS re-init would re-lock it.
 *
 * Target hardware : NVIDIA CMP 70HX — GA104 die, 8 GB GDDR6, PCI 10de:248a,
 *                   sold as a mining-only card: compute and render engines
 *                   are fused off by firmware protection registers.
 * Toolchain       : gnu-efi 3.0+ / gcc — see BUILDING.md and src/build.sh
 *
 * ---------------------------------------------------------------------------
 * Why this works (the V67 canary exploit)
 * ---------------------------------------------------------------------------
 * The feature masks — PLM (protected-layer mask) and speed-selects SS0/SS1 —
 * live in fuse-shadow registers on BAR0 and are writable only from GPU-side
 * privileged firmware. The NVIDIA-signed SEC2 "booter" microcode has a stack
 * protector canary bug (Jon Pry, "A Canary in the Crypto Mine",
 * DOI 10.5281/zenodo.20916112): when it processes an oversized "signature"
 * blob (our 0xFA00-byte V67 payload instead of the stock 4 KB), execution
 * runs into a ROP gadget chain that performs arbitrary privileged register
 * writes — including PLM open and SS0/SS1 unlock.
 *
 * ---------------------------------------------------------------------------
 * Unlock protocol (ported from open-gpu-kernel-modules 610.43.03 init flow)
 * ---------------------------------------------------------------------------
 *   1. GFW (GPU firmware booted by VBIOS at POST) is running: verify it via
 *      GFW_BOOT_OK, then kill it with a Falcon ENGINE reset — while GFW
 *      lives, SEC2 answers 0xBADF56xx (priv lockdown).
 *   2. Seed PTIMER with wall-clock time (PLM anti-replay rejects writes
 *      while GPU time is bogus).
 *   3. Build WPR meta (256 B), field-for-field like kgspPopulateWprMeta:
 *      radix3 page-table over .fwimage (~84 MB read from USB via BlockIo),
 *      V67 payload as the "signature", bootloader offsets, heap/FRTS
 *      geometry for a 10 GB framebuffer.
 *   4. Early path (the one that works): BL(ucodeId=1) on GSP -> FWSEC(FRTS)
 *      on GSP latches WPR2 -> ResetIntoRiscv + LibosBootArgs -> run the
 *      SEC2 booter load FIRST on the fresh SEC2 (see early_unlock_path).
 *   5. The booter trips over the canary bug while checking the signature;
 *      the ROP chain opens PLM (0x823804 <- 0xFFFFFFFF) — and, in
 *      fire-mode builds, applies the render-mask table entry by entry.
 *   6. Write compute selectors SS0=0x88888888 / SS1=0x00000008.
 *   7. Cleanup: kill the still-spinning SEC2 ROP engine, then issue PCIe
 *      FLR — the ONLY reset that clears a latched WPR2 (masks/selectors
 *      survive FLR). No MMIO access after the FLR.
 *   8. Return to the firmware without touching NVRAM/SFS (both hang this
 *      platform once the GPU is in post-unlock state). Firmware BDS then
 *      boots Windows from BootOrder — no POST happens, unlock stays alive.
 *
 * ---------------------------------------------------------------------------
 * Build flags — they decide which phases even exist in the binary!
 * ---------------------------------------------------------------------------
 *   RELEASE_BUILD        release behaviour: no pauses, return-to-firmware
 *   MULTI_CARD           enumerate every target card; NVRAM iteration between
 *                        cards
 *   TARGET_CMP70HX       (default, and the only target that is built)
 *                        CMP 70HX / GA104 / 8 GB / 10de:248a. CMP 90HX / GA102
 *                        was dropped as a build target on 2026-10-01; the block
 *                        below is kept only so this tree still parses, and the
 *                        alt deviced ID at TARGET_PCI_DEV_ALT1 remains a known
 *                        latent hazard (see KNOWN-ISSUES).
 *   PCIE_GEN2_REJOIN     include render-mask table + fire machinery.
 *                        WITHOUT IT THE RENDER PHASE IS NOT EVEN COMPILED
 *                        (that is how v3.01 shipped compute-only by mistake)
 *   FULL_NOGEN2          v3.03: keep render table, drop the PCIe-gen2 link
 *                        domain, add tail cleanup (SEC2 kill + final FLR);
 *                        fixes the Code 43 of v3.02-full
 *   EFI_AUTOTEST         QEMU test-stand behaviour: auto-advance, extra dumps
 *   PCIE_GEN_EXPERIMENT  dev-only Gen2/Gen3 register experiments
 *   XP3G_GATE_V67        experiment E-A: one privileged V67 write of
 *                        0xFFFFFFFF into the XP3G privilege gate 0x8E1B0,
 *                        with 0x8E1B4 as positive control. Requires
 *                        RENDER_MASKS. Touches no link bit, no functional bit.
 *                        Acceptance markers: XGATE phase0 / phase1 / phase2 /
 *                        XGATE VERDICT. See docs/70HX-XP3G-GATE-V67.md
 *   ENDGAME_WARMRESET    plan-B endgame (BootNext + warm reset), unused
 *
 *   v3.01 = RELEASE_BUILD + MULTI_CARD                       (compute only)
 *   v3.02 = + PCIE_GEN2_REJOIN                               (Code 43 bug)
 *   v3.03 = + PCIE_GEN2_REJOIN + FULL_NOGEN2                 (current release)
 *
 * ---------------------------------------------------------------------------
 * Embedded blobs (objcopy'd in by src/build.sh; NOT distributed in git)
 * ---------------------------------------------------------------------------
 *   v67_payload.bin                canary exploit payload (bendy2 research)
 *   booter_ucode_prod_patched.bin  SEC2 booter ucode from driver bindata,
 *                                  SIG_PROD[0] patched at offset 0x8A10
 *   gsp_rm_boot_dbg.bin            GSP bootloader (GspRmBoot), 0x6000 bytes
 *   fwsec_ga104.bin (+_sig)        FWSEC ucode + signature, extracted from a
 *                                  GA104 VBIOS. PER-DIE: this blob belongs to
 *                                  GA104 only and must never be paired with
 *                                  another profile (see KNOWN-ISSUES on 0x1555).
 *   sec2_ucode_vbios_{49,89}_patched.bin  preloaded-ucode experiments (dev)
 *   gsp_ga10x.bin                  NOT embedded: read from USB at runtime.
 *                                  Take it from the NVIDIA 610.43.03 package!
 *                                  Serves every GA10x die; .fwimage offset
 *                                  and size are parsed out of its ELF.
 *
 * Runtime messages are intentionally Russian; the version banner printed at
 * start identifies the exact build variant. Deep inline comments kept their
 * original Russian wording and historical experiment tags (v2.xx) — they
 * encode hard-won platform knowledge; see docs/GOTCHAS.md for the digest.
 */

#include <efi.h>
#include <efilib.h>
#include <efipciio.h>
#include <efiprot.h>
#include <efifs.h>
#include <efidevp.h>

/* ==== СВОИ memcpy/memset/memcmp — ОБЯЗАТЕЛЬНО, НЕ УДАЛЯТЬ ====
 *
 * В ЭТОЙ СБОРКЕ gnu-efi функции CopyMem/SetMem/CompareMem НЕ копируют
 * память. legacy.h превращает CopyMem в макрос на CopyMem_1, а тот —
 * на RuntimeServices-обёртку RtCopyMem. Дизассемблирование готового
 * unlock_v3n.so:
 *
 *   <CopyMem_1>:  jmp <RtCopyMem>
 *   <RtCopyMem>:  movzbl (%rdx,%rax,1),%r9d   ; src  читается по rdx
 *                 mov    %r9b,(%rcx,%rax,1)   ; dst  пишется  по rcx
 *                 cmp    %rax,%r8              ; длина берётся из r8
 *
 * То есть аргументы читаются как rcx/rdx/r8 — это соглашение Microsoft x64,
 * тогда как программа собрана под System V (rdi/rsi/rdx). Функция получает
 * мусор: чаще всего len оказывается 0/мусором и она выходит сразу, ничего не
 * сделав. SetMem сломана так же (значение берёт из r8d, пишет в rcx).
 *
 * ПОСЛЕДСТВИЕ БЫЛО КАТАСТРОФИЧЕСКИМ: ни одна загрузка блоба в приложении не
 * работала. Ни V67, ни FWSEC, ни GspRmBoot, ни radix-образ, ни патч
 * подписи, ни таблицы страниц. Доказательство из лога на реальном железе:
 *
 *   MEM   fwsec addr=0xC1051000 W/R ок (плохих 0)
 *   MEM   fwsec CRC32 блоб=0xE735DD44 буфер=0x648A9C97 РАСХОЖДЕНИЕ
 *   MEM   fwsec слова: 0x0000:EC547D23/0F0F0F0F  0x1D40:1B7EF0D4/00000000
 *
 * Прямые обращения (*(volatile UINT32*)...) в буфер попадали, а CopyMem —
 * нет. Отсюда FWSEC стартовал с нулями и всегда давал dbg=0x00780009.
 *
 * Ниже определяем настоящие функции и переопределяем имена макросами.
 * Файл компилируется один (build.sh собирает только unlock_v2.c), поэтому
 * переопределение действует на все вызовы без исключения. */
static VOID *app_memcpy(VOID *d, CONST VOID *s, UINTN n)
{
    UINT8 *dd = (UINT8 *)d;
    CONST UINT8 *ss = (CONST UINT8 *)s;
    UINTN i;
    if (d == NULL || s == NULL || n == 0) return d;
    if (dd < ss) {                       /* вперёд — безопасно при перехлёсте */
        for (i = 0; i < n; i++) dd[i] = ss[i];
    } else if (dd > ss) {
        for (i = n; i > 0; i--) dd[i - 1] = ss[i - 1];
    }
    return d;
}

static VOID *app_memset(VOID *d, UINT8 v, UINTN n)
{
    UINT8 *dd = (UINT8 *)d;
    UINTN i;
    if (d == NULL) return d;
    for (i = 0; i < n; i++) dd[i] = v;
    return d;
}

static INTN app_memcmp(CONST VOID *a, CONST VOID *b, UINTN n)
{
    CONST UINT8 *aa = (CONST UINT8 *)a, *bb = (CONST UINT8 *)b;
    UINTN i;
    if (aa == NULL || bb == NULL) return (aa == bb) ? 0 : (aa ? 1 : -1);
    for (i = 0; i < n; i++)
        if (aa[i] != bb[i]) return (INTN)aa[i] - (INTN)bb[i];
    return 0;
}

#undef  CopyMem
#undef  SetMem
#undef  CompareMem
#define CopyMem(d, s, n)     app_memcpy((VOID *)(UINTN)(d), (CONST VOID *)(UINTN)(s), (UINTN)(n))
#define SetMem(d, v, n)      app_memset((VOID *)(UINTN)(d), (UINT8)(v), (UINTN)(n))
#define CompareMem(a, b, n)  app_memcmp((CONST VOID *)(UINTN)(a), (CONST VOID *)(UINTN)(b), (UINTN)(n))

/* ==== ЛОГ НА ФЛЕШКУ ====
 * Раньше всё уходило только в Print() на экран, из-за чего ключевые
 * значения (WPR2, DEBUGINFO, fb size) приходилось снимать с видео.
 * Теперь те же строки пишутся на флешку СЫРЫМИ СЕКТОРАМИ через
 * BlockIo — без SimpleFileSystem (он на этой плате вешает прошивку)
 * и без NVRAM (тем более). Реализация у блока cmp90_bio_read. */
static void ulogf(const CHAR16 *fmt, ...);
static void log_ms(const CHAR16 *tag);   /* v3.16: метки времени; нужна и до определения */
static void log_flush_sector(BOOLEAN force);
static void ulogf(const CHAR16 *fmt, ...);
static UINTN g_logFlushFails;
static void log_init(EFI_HANDLE ImageHandle);
static void log_store_ptr(EFI_BLOCK_IO_PROTOCOL *bio, UINT32 next);
static UINT32 log_load_ptr(EFI_BLOCK_IO_PROTOCOL *bio);
static VOID *cmp90_alloc(UINTN size);
static void cmp90_free(VOID *p);
/* v3n: дамп окна SEC2 вызывается в двух местах. Первое — в самом начале,
 * до единой записи в регистры GPU, и именно оно даёт ЗАБЛОКИРОВАННОЕ
 * состояние (см. §1n: A/B нельзя получить двумя перезагрузками, потому
 * что без флешки наше приложение не запускается и лог не пишется). */
static void sec2_window_dump(const CHAR16 *tag);
/* v3n: дамп Gen2-регистров и масок, строго на чтение (§1o). */
static void gen2_readonly_dump(const CHAR16 *tag);
static void fwsec_set_imem_sec(UINTN sec);
static UINT32 crc32_upd(UINT32 crc, const UINT8 *p, UINTN n);
static void log_buf_check(const CHAR16 *tag, const UINT8 *src, UINT64 addr,
                          UINTN size);
static void log_mem_selftest(const CHAR16 *tag, const UINT8 *src, UINT64 addr,
                             UINTN size);
/* v3.17: используются блоком учёта вывода выше, определены ниже. */
static UINT64 fx_now_us(void);
static void log_putc(CHAR8 c);
extern UINTN fx_rmDirect;
extern UINTN fx_rmNeedBooter;
extern UINTN fx_rmFast;
extern UINTN fx_rmFastMiss;
extern BOOLEAN fx_rmFirstOk;

/* ==================================================================== *
 * v3.17: СТОИМОСТЬ ВЫВОДА — измерение и буферизация
 *
 * ЗАЧЕМ. Измеренный бюджет прогона 3:40 показывает, что на итерацию
 * рендер-цикла (7,61 с) приходится около 290 вызовов Print() и около
 * 142 строк файлового лога, и НИ ОДНОЙ из них нет в фазовом учёте,
 * потому что Print пишет напрямую в ConOut мимо нашего счётчика.
 *
 * ЧТО ИЗМЕРЕНО, а не прикинуто:
 *   sweep_all(POST) = 11,86 с, и при этом он даёт НОЛЬ строк в файловом
 *   логе (sweep_regs печатает только в консоль). 580 чтений MMIO не могут
 *   стоить 11,86 с. Значит время - это печать.
 *
 * ПОЧЕМУ НЕЛЬЗЯ ПРОСТО ЗАГЛУШИТЬ Print. ConsoleOutput - единственный
 * канал, который виден пользователю на экране. Полностью тихая сборка
 * выглядит как зависшая. Поэтому:
 *   - каждый вызов копируется в кольцевой буфер в ОЗУ (для разбора);
 *   - раз в 512 вызовов на настоящую консоль идёт одна короткая строка
 *     «пульса», чтобы прогресс был виден;
 *   - в финале кольцо выгружается в файловый лог целиком.
 *
 * ЦЕНА ИЗМЕРЕНИЯ. Проба консоли делается ОДИН раз, 20 строк. При цене
 * 26 мс на вызов это 0,5 с на весь прогон - приемлемо, и это единственный
 * способ узнать цену вывода, не заплатив её целиком.
 * ==================================================================== */
typedef VOID (*FX_PRINT_FN)(CHAR16 *fmt, ...);
/* Адрес настоящей Print берётся ДО определения макроса ниже. */
static FX_PRINT_FN fx_print_real = (FX_PRINT_FN)Print;

#define FX_PR_RING_CHARS   (64*1024)    /* 128 КБ кольца = 256 секторов лога */
#define FX_PR_BEAT_EVERY   512

static CHAR16 *g_prRing = NULL;
static UINTN   g_prCap    = 0;
static UINTN   g_prHead   = 0;     /* куда писать дальше */
static UINTN   g_prFilled = 0;     /* сколько символов занято всего */
static UINTN   g_prCalls  = 0;
static UINTN   g_prUsPerCall = 0;  /* измеренная цена одного вызова, мкс */
static BOOLEAN g_prUsMeasured = FALSE; /* TRUE = проба выполнена, FALSE = взято из константы */
static UINTN   g_ulogCalls = 0;
static UINT64  g_ulogUs    = 0;
static UINTN   g_logSectors = 0;
/* v3.19: сколько раз реально дошло до выгрузки кольца, и сколько секторов
 * при этом записано. Без этого выгрузка неотличима от «функция не вызвана».
 * См. комментарий у fx_pr_dump. */
/* v3.47: СЧЁТЧИК ВХОДОВ, а не успешных выгрузок.
 *
 * Изначально g_prDumpCalls++ стоял ПОСЛЕ трёх ранних выходов, то есть
 * показывал «выгрузка прошла», а не «выгрузку вызвали». Для диагностики
 * «вызвали или нет» это бесполезно: ранний выход даёт 0 точно так же, как
 * отсутствие вызова. Счётчик входов эти два случая различает. */
static UINTN   g_prDumpCalls = 0;
static UINTN   g_prDumpSecBefore = 0;
/* v3.18: сколько раз запись на флешку сорвалась. Ноль в норме. */
static UINTN   g_logFlushFails = 0;

/* ============ v3.47: ВЫВОД ДО ВЫДЕЛЕНИЯ КОЛЬЦА ============
 *
 * БЫЛО (fx_print): «если кольца нет - пиши прямо в консоль». Из этого
 * следовало, что на экране всегда есть ~11 строк, которые нигде больше не
 * существуют: баннер профиля и весь разбор device path из log_init идут
 * ДО выделения кольца, попадают на консоль напрямую и в файловый лог не
 * попадают ВООБЩЕ (проверено на прогоне 1004-151011: строк '[log] device
 * path' в логе нет ни одной). То есть на экране шум, а в логе пусто.
 *
 * ПОЧЕМУ НЕ «ПРОСТО ЗАГЛУШИТЬ». Заглушить — значит выбросить единственную
 * копию этих строк. Выбор флешки подробно не записан больше никуда, а по
 * нему видно, куда уехал лог.
 *
 * ПОЧЕМУ НЕ «ПЕРЕНЕСТИ ВЫДЕЛЕНИЕ КОЛЬЦА В НАЧАЛО efi_main». Тогда эти
 * строки попадут в кольцо, а кольцо не выгружается в лог: fx_pr_dump не
 * даёт ни байта ни в одном прогоне начиная с v3.17. То есть они просто
 * перестанут существовать. Тише, но потеряно.
 *
 * СТОРОНА РЕШЕНИЯ. Маленький буфер на 2 КБ, который копится до кольца и
 * как только лог на флешке - СРАЗУ выгружается в файл через log_write.
 * Тот же путь записи, что у всех работающих строк лога, поэтому он не
 * зависит от починенности fx_pr_dump.
 *
 * Что с буфером, если он переполнится: строки отбрасываются, и это
 * СЧИТАЕТСЯ (g_prPreDropped печатается в лог). Молчаливая потеря -
 * худший вариант, потому что её не видно. */
#define FX_PR_PRE_CHARS 2048
static CHAR16  g_prPre[FX_PR_PRE_CHARS];
static UINTN   g_prPreLen = 0;      /* сколько символов занято */
static UINTN   g_prPreDropped = 0;  /* сколько символов НЕ влезло */
static BOOLEAN g_prPreFlushed = FALSE; /* буфер уже выгружен в лог */
static BOOLEAN g_prNoRing = FALSE;  /* AllocatePool не удался - прямой вывод */

static VOID fx_print(CHAR16 *fmt, ...);
static BOOLEAN g_logOn;        /* лог на флешку; определён ниже */
static UINT32  g_logSec;       /* текущий сектор записи; определён ниже */
static UINTN   g_logFill;      /* заполнение буфера секторов; определён ниже */
static VOID fx_console_raw(CHAR16 *s);
static VOID fx_pr_dump(void);
static VOID fx_pr_console_dump(void);
static VOID fx_io_report(void);
static VOID fx_console_cost_probe(void);
static VOID fx_pr_pre_flush(void);
static VOID fx_pr_pre_put(CHAR16 *s);
#define Print(...) fx_print(__VA_ARGS__)

/* Настоящий вызов в консоль мимо буфера. Используется и пробой, и пульсом.
 *
 * v3.47: здесь же считаются ПРЯМЫЕ выводы. Раньше вывод в консоль не
 * оставлял следа НИГДЕ - не в кольце, не в файловом логе, - поэтому по
 * логу невозможно было доказать, что рамка вердикта вообще дошла до
 * экрана. Счётчик пишется в лог строкой SCREEN, и verify-log.ps1 может
 * потребовать ожидаемое число. Это не доказывает, что каждая строка
 * дошла, но доказывает, что приложение их вызвало, - а это уже половина
 * непроверяемого. */
static UINTN g_rawCalls = 0;
static VOID
fx_console_raw(CHAR16 *s)
{
    g_rawCalls++;
    fx_print_real(s);
}

/* v3.47: накопление вывода, произошедшего ДО выделения кольца. */
static VOID
fx_pr_pre_put(CHAR16 *s)
{
    UINTN i;
    for (i = 0; s[i]; i++) {
        if (g_prPreLen >= FX_PR_PRE_CHARS) { g_prPreDropped++; continue; }
        g_prPre[g_prPreLen++] = s[i];
    }
}

static VOID
fx_print(CHAR16 *fmt, ...)
{
    CHAR16 tmp[512];
    va_list ap;
    UINTN i;

    va_start(ap, fmt);
    /* Размер - в БАЙТАХ (см. длинный комментарий в ulogf): gnu-efi сам
     * переводит BufferSize/2 - 1 в символы. */
    UnicodeVSPrint(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);

    if (!g_prRing) {
        /* v3.47: НЕ НА КОНСОЛЬ. Раньше здесь был прямой вывод, и он давал
         * ~11 строк шума на экране без единой копии в логе.
         *
         * Исключение - случай, когда кольцо не выделилось: тогда прямой
         * вывод это единственный путь, куда вообще может пойти текст, и
         * терять его нельзя (плюс об этом предупреждает сообщение
         * «allocation FAILED»). */
        if (g_prNoRing) { fx_console_raw(tmp); return; }
        fx_pr_pre_put(tmp);
        return;
    }
    g_prCalls++;
    for (i = 0; tmp[i] && i < 512; i++) {
        if (g_prHead >= g_prCap) g_prHead = 0;      /* кольцо: затираем старое */
        g_prRing[g_prHead++] = tmp[i];
        if (g_prFilled < g_prCap) g_prFilled++;
    }
    /* Пульс на настоящей консоли: пользователь должен видеть, что идёт
     * процесс. Одна строка на 512 вызовов - при 3000 вызовах это 6 строк.
     *
     * v3.47: В РЕЛИЗЕ ВЫКЛЮЧЕН. Строка '... console 512 calls buffered'
     * говорит про буфер, а не про карту: человек, который ждёт анлок, должен
     * видеть «Unlocking», а не счётчик вызовов. Плюс хвост экрана и так
     * содержит вердикт. В dev-сборках пульс остаётся - там вывод идёт
     * медленно и без индикации совсем нечем понять, что процесс жив. */
#ifndef RELEASE_BUILD
    if ((g_prCalls % FX_PR_BEAT_EVERY) == 0) {
        CHAR16 beat[128];
        UnicodeSPrint(beat, sizeof(beat),
                      L"  ... console %d calls buffered\r\n", g_prCalls);
        fx_console_raw(beat);
    }
#endif
}

/* Разовая проба цены одного вывода в консоль. Делается на НАСТОЯЩЕЙ
 * консоли, иначе она измеряла бы цену собственной буферизации.
 *
 * ============ v3.47: В РЕЛИЗЕ ПРОБА НЕ ВЫПОЛНЯЕТСЯ ============
 *
 * Она печатает 20 строк на НАСТОЯЩУЮ консоль, то есть 20 x 16,83 мс =
 * 337 мс внутри измеренного прогона - и двадцать строк '[probe] console cost
 * measurement' на экране у человека, который ждёт анлок.
 *
 * Покупатель этого числа ровно один: строка 'est_if_unbuffered' в
 * fx_io_report. Это справочная величина, а не элемент логики анлока, и она
 * уже измерена - 16 830 мс/вызов, совпало до единицы на прогонах v3.17 и
 * v3.18, то есть величина стабильная, а не случайная. Платить 337 мс за
 * переизмерение стабильной справочной величины на каждом бут - расточительство.
 *
 * В РЕЛИЗЕ число НЕ МАРКЕТСЯ: g_prUsMeasured = FALSE, и отчёт прямо пишет
 * 'assumed' вместо 'measured'. Иначе документированное измерение выдавалось бы
 * за измеренное сегодня.
 *
 * Если кому-то понадобится проверить, что прошивка не замедлилась, -
 * собрать без RELEASE_BUILD: проба выполнится, и в логе будет 'measured'. */
#define FX_CONSOLE_US_ASSUMED 16830
static VOID
fx_console_cost_probe(void)
{
#ifdef RELEASE_BUILD
    g_prUsPerCall   = FX_CONSOLE_US_ASSUMED;
    g_prUsMeasured = FALSE;
#else
    UINT64 t0, t1;
    UINTN i;
    if (!g_prRing || !fx_now_us()) return;   /* часы не откалиброваны - пропуск */
    t0 = fx_now_us();
    for (i = 0; i < 20; i++)
        fx_console_raw(L"[probe] console cost measurement, dummy line\r\n");
    t1 = fx_now_us();
    if (t1 > t0) { g_prUsPerCall = (UINTN)((t1 - t0) / 20); g_prUsMeasured = TRUE; }
#endif
}

/* Итог по выводу. Печатается ПОСЛЕ ulogf-счётчиков снятых, иначе строка
 * сама себя учтёт.
 *
 * v3.47: добавлены две вещи, обе про честность отчёта.
 *
 * 1) 'measured' или 'assumed'. В релизе проба не выполняется (337 мс ради
 *    справочной цифры), и без пометки документированное измерение
 *    выдавалось бы за измеренное только что.
 * 2) SCREEN: сколько строк ушло на НАСТОЯЩУЮ консоль в обход кольца.
 *    Прямой вывод не оставляет следа нигде, и по логу нельзя было доказать,
 *    что рамка вердикта дошла до экрана. Теперь можно. */
static VOID
fx_io_report(void)
{
    UINTN uc = g_ulogCalls;
    UINT64 uu = g_ulogUs;
    UINTN ls = g_logSectors;
    UINT64 est = g_prUsPerCall ? (UINT64)g_prCalls * g_prUsPerCall : 0;

    ulogf(L"TIME  I/O: Print n=%d us/call=%d (%s) "
          L"est_if_unbuffered=%lldms | ulogf n=%d cost=%lldus sectors=%d\n",
          g_prCalls, g_prUsPerCall, g_prUsMeasured ? L"measured" : L"assumed",
          (INT64)(est / 1000ULL),
          uc, (INT64)uu, ls);
    ulogf(L"TIME  SCREEN raw console lines=%d BEFORE verdict frame "
          L"(это число НЕ включает рамку - она печатается ниже; "
          L"итоговое считается сразу после неё)\n",
          (INTN)g_rawCalls);
    ulogf(L"TIME  render masks: fast=%d fast_miss=%d direct=%d booter=%d\n",
          fx_rmFast, fx_rmFastMiss, fx_rmDirect, fx_rmNeedBooter);
}

/* Выгрузка кольца консоли в файловый лог. Порядок: если кольцо не
 * переполнилось - с начала; если переполнилось - от g_prHead (там самое
 * старое) до конца, потом от нуля. */
static VOID
fx_pr_dump(void)
{
    UINTN i;
    /* v3.47: счётчик ВХОДОВ, до всех ранних выходов.
     *
     * Стоял ниже трёх проверок, то есть показывал «выгрузка прошла», а не
     * «выгрузку вызвали». Для вопроса «вызвали или нет» это ровно то же
     * самое число, что и отсутствие вызова: оба дают 0. Различает их
     * только счётчик входов. */
    g_prDumpCalls++;
    /* v3.19: ПОЧЕМУ ПРОШЛЫЕ ВЫГРУЗКИ НЕ ДОШЛИ. Кламп в log_flush_sector
     * починен в v3.18, но заголовка PRN в логе всё равно нет ни в одном из
     * двух прогонов. Значит причина не в размере пакета, и угадывать её
     * бесполезно - это ровно тот класс ошибки, который в этом проекте уже
     * стоил двух регрессий.
     *
     * Здесь стояло:
     *     if (!g_prRing || g_prFilled == 0) return;
     *     if (!g_logOn) return;
     * то есть ПРИЧИНА НИКОГДА НЕ ПЕЧАТАЛАСЬ, и по логу было невозможно
     * отличить «кольцо пустое» от «лог выключен» от «выгрузка прошла, но
     * ничего не записалось».
     *
     * Теперь причина печатается ВСЕГДА и всегда первой строкой. Ровно это
     * и должно было быть сделано изначально: пропуск обязан быть виден
     * (BUILDING 6.0). Счётчик g_prDumpCalls обязателен по той же причине -
     * вызов существует, и это видно только по счётчику. */
    if (!g_prRing) {
        ulogf(L"PRN   console ring NOT DUMPED: ring never allocated "
              L"(AllocatePool failed at efi_main entry)\r\n");
        return;
    }
    if (!g_logOn) {
        ulogf(L"PRN   console ring NOT DUMPED: g_logOn=0, logging already "
              L"stopped (see 'write FAILED' above), %d chars lost\r\n",
              (INTN)g_prFilled);
        return;
    }
    if (g_prFilled == 0) {
        ulogf(L"PRN   console ring NOT DUMPED: ring allocated but empty "
              L"(every Print went direct - before log_init?)\r\n");
        return;
    }

    ulogf(L"PRN   ==== console ring: %d calls, %d chars, "
          L"measured %dus/call, dump starts at sec=%d fill=%d/4096 ====\r\n",
          g_prCalls, g_prFilled, g_prUsPerCall, (INTN)g_logSec,
          (INTN)g_logFill);

    for (i = 0; i < g_prFilled; i++) {
        CHAR16 c = g_prRing[(g_prFilled < g_prCap) ? i
                           : ((g_prHead + i) % g_prCap)];
        log_putc((c == L'\n' || c == L'\r') ? '\n'
                 : ((c < 0x20 || c > 0x7E) ? '?' : (CHAR8)c));
    }
    ulogf(L"PRN   ==== console ring end: %d chars dumped, log advanced "
          L"%d sectors ====\r\n",
          (INTN)g_prFilled, (INTN)(g_logSectors - g_prDumpSecBefore));
    g_prDumpSecBefore = g_logSectors;
}

/* Выгрузка кольца НА НАСТОЯЩУЮ КОНСОЛЬ.
 *
 * ИСТОРИЯ. Функция добавлена в v3.17 вместе с буферизацией: мол, во время
 * прогона печать идёт в буфер ради скорости, а пользователь увидит отчёт
 * в конце. Проблема в том, что это ПРОТИВОРЕЧИТ СОБСТВЕННОЙ ЦЕЛИ.
 *
 * ИЗМЕРЕНО: цена одного вызова консоли = 16 834 мкс (строка
 *   I/O: Print n=1388 measured=16834us/call
 * в прогонах v3.17 и v3.18 - совпало до единицы, то есть это стабильная
 * величина, а не случайность).
 *
 * Кольцо содержит 541 строку. Печать их обратно на консоль стоит
 *     541 x 16,8 мс = 9,1 с
 * и эта 9,1 с НИКОГДА не попадала в счётчик, потому что она целиком
 * происходит ПОСЛЕ строки 'final: before return to firmware'. Отсюда и
 * загадка '20,7 с вне счётчика':
 *     стенометр 86 с - счётчик 65,3 с = 20,7 с
 *     из них  ~9,1 с  эта выгрузка
 *             ~2,0 с  Stall(2000000) перед возвратом в прошивку
 *             ~9,6 с  всё, что происходит ДО efi_main: POST, инициализация
 *                   UEFI, поиск и запуск нашего образа
 * То есть «неучтённые 20,7 с» - это не загадка, а почти на треть POST.
 *
 * РЕШЕНИЕ. Расплачиваться за распечатанный отчёт НЕЧЕГО: кольцо уже
 * лежит в файловом логе, его и читает out\read-log.ps1. Настоящая консоль
 * получает ТОЛЬКО итоговые строки, которых человек ждёт на экране.
 *
 * Что показывать на экране: баннер профиля карты (он и так первый),
 * итог разблокировки и время. Размётка по диагностике — в файловом логе,
 * для этого он и существует.
 *
 * ЧТО НЕ ДЕЛАЕМ: не печатаем «дамп последних N строк». Любое N здесь
 * означает оплату N x 16,8 мс, и никакого «немного дешевле» тут нет -
 * * либо печатаем итог, либо не печатаем ничего.
 */
static VOID
fx_pr_console_dump(void)
{
#ifdef RELEASE_BUILD
/* v3.47: В РЕЛИЗЕ НА КОНСОЛЬ НИЧЕГО, КРОМЕ ТРЁХ СТРОК.
 *
 * Комментарий выше, на который этот дамп отвечает, гласит: «ЧТО НЕ ДЕЛАЕМ:
 * не печатаем дамп последних N строк. Любое N здесь означает оплату
 * N x 16,8 мс, и никакого «немного дешевле» тут нет - либо печатаем итог,
 * либо не печатаем ничего». Код делал ровно то, от чего предостерегал:
 * N = 12, то есть 202 мс и тринадцать строк диагностики перед вердиктом.
 *
 * Человек, который пришёл посмотреть, разблокировалась ли карта, получал
 * 30 строк шума и одну нужную в самом низу. Заголовки 'unlock done' и
 * 'last N lines' ушли в ulogf: они описывают механизм буферизации, а не
 * карту, и на экране им не место.
 *
 * Диагностика никуда не делась - она в файловом логе, ради которого он и
 * существует. Экран теперь отвечает на один вопрос: что с картой. */
    ulogf(L"TIME  screen: console dump suppressed in RELEASE_BUILD "
          L"(%d ring chars are in the file log)\n", (INTN)g_prFilled);
#else
    UINTN i, n = 0, shown = 0;
    CHAR16 tmp[512];
    CHAR16 hdr[160];

    if (!g_prRing || g_prFilled == 0) return;

    UnicodeSPrint(hdr, sizeof(hdr),
                  L"\n=== unlock done: %d console calls buffered, "
                  L"%d chars are in the file log ===\n",
                  g_prCalls, g_prFilled);
    fx_console_raw(hdr);
    UnicodeSPrint(hdr, sizeof(hdr),
                  L"=== last %d lines (full log: out\\pull-log.ps1) ===\n",
                  FX_SCREEN_LINES);
    fx_console_raw(hdr);

    /* Идём с конца кольца: последние строки интереснее первых. */
    for (i = g_prFilled; i > 0 && shown < FX_SCREEN_LINES; i--) {
        UINTN src = (g_prFilled < g_prCap) ? (i - 1)
                                            : ((g_prHead + i - 1) % g_prCap);
        UINTN lineStart;
        CHAR16 c = g_prRing[src];
        if (c == L'\n' || c == L'\r') continue;   /* пустые переводы пропускаем */
        /* Идём назад до начала строки. */
        lineStart = src;
        while (lineStart > 0) {
            UINTN p = (lineStart == 0) ? 0 : lineStart - 1;
            CHAR16 q = g_prRing[p];
            if (q == L'\n' || q == L'\r') break;
            lineStart = p;
            if (src - lineStart > 400) break;    /* строка длиннее - обрезаем */
        }
        n = 0;
        while (lineStart <= src) {
            CHAR16 q = g_prRing[lineStart];
            tmp[n++] = (q < 0x20 || q > 0x7E) ? '.' : q;
            if (lineStart == src) break;
            lineStart++;
            if (n >= 400) break;
        }
        tmp[n] = 0;
        fx_console_raw(tmp);
        shown++;
    }
#endif /* RELEASE_BUILD */
}

/* ==== TARGET PROFILE — the ONLY place that carries chip-specific numbers ====
 *
 * Adding support for another CMP SKU = add a line here. The framebuffer
 * layout, the FRTS offset, the WPR2 window the FWSEC is supposed to latch and
 * every readback check are DERIVED below, so there is nothing else to hunt for
 * (getting any one of them wrong makes the booter abort with exit 0x91 or
 * 0x780009, long before it ever touches the signature).
 *
 * Verified geometry (kgspPopulateWprMeta_TU102 / kgspGetFrtsSize, 610.43.03):
 *   vgaWorkspaceOffset = fbSize - PRAMIN(1 MB)      (CMP: no display fuse)
 *   gspFwWprEnd        = vgaWorkspaceOffset & ~0x1FFFF
 *   frtsOffset         = gspFwWprEnd  - frtsSize(1 MB)
 *
 *   8 GB  (70HX/GA104): vgaWS=0x1FFF00000  wprEnd=0x1FFF00000  frts=0x1FFE00000
 *  10 GB  (90HX/GA102): vgaWS=0x27FF00000  wprEnd=0x27FF00000  frts=0x27FE00000
 *
 * (The 10 GB row is the field-proven one — frts_offset=0x27fe00000 in the
 * working unlock's dmesg. The 8 GB row is the same formula applied to an
 * 8 GB framebuffer, and has NOT been confirmed on metal yet.)
 *
 * WPR2 (NV_PFB_PRI_MMU_WPR2_LO/HI) is written by FWSEC once FRTS has run, and
 * the unlock then has to reproduce it. Measured once, on the 10 GB card:
 * frts=0x27FE00000 -> lo=0x027FE000, hi=0x027FEE00, i.e. lo = frts>>8 and
 * hi = lo+0xE00. The encoding is not published anywhere, so that rule is
 * INFERRED from a single sample. If the FWSEC WPR2 poll on a 70HX times out,
 * the poll already prints the observed lo/hi every 200 ms — drop those two
 * numbers in here and rebuild. Everything else (FB geometry) is formula-based
 * and independent of this.
 *
 * UNVERIFIED on a 70HX: the Device ID (0x248a comes from the pci.ids
 * database, not from NVIDIA), the WPR2 encoding above, and the register
 * "open" values in docs/REGISTERS.md. Everything in the FB-geometry rows is
 * the driver's own formula, just fed a different framebuffer size.
 */
#if defined(TARGET_CMP90HX)
# define TARGET_NAME            L"CMP 90HX (GA102)"
# define TARGET_PCI_DEV         0x220DU       /* 10de:220d */
# define TARGET_FB_SIZE         0x280000000ULL /* 10 GB */
#elif defined(TARGET_CMP70HX)
# define TARGET_NAME            L"CMP 70HX (GA104)"
# define TARGET_PCI_DEV         0x248AU       /* 10de:248a */
# define TARGET_FB_SIZE         0x200000000ULL /* 8 GB */
#else
/* default = the card this tree is ported to */
# define TARGET_NAME            L"CMP 70HX (GA104)"
# define TARGET_PCI_DEV         0x248AU
# define TARGET_FB_SIZE         0x200000000ULL
#endif

/* How much of gsp_ga10x.bin to pull off the stick: the whole 610.43.03 file
 * is 0x505F898 (ELF section table ends at ~0x505F400), so 0x5060000 covers
 * it with room to spare. The offsets inside are parsed out of the ELF, so a
 * differently-sized firmware from another driver package still works as long
 * as it fits in this window. */
#define GSP_FW_READ_WINDOW     0x5060000ULL

/* Extra device IDs the enumerator also accepts: same die AND same framebuffer
 * size as the primary target, so the whole profile stays valid.
 *   0x1555  — the second ID NVIDIA ships for the CMP 90HX (per bendy2)
 *   0x248c  — the GA104 board variant nearest 0x248a
 * A GeForce card that happens to share a die is NOT accepted unless its ID is
 * listed here: an unlocked retail card must never be run through this. */
#define TARGET_PCI_DEV_ALT1     0x1555U
#define TARGET_PCI_DEV_ALT2     0x248CU

#define TARGET_PCI_VENDOR       0x10DEU

/* Which FWSEC ucode is linked in. The blob is chip-specific (extracted from
 * that die's VBIOS), so it must match the target profile — see
 * src/tools/extract_fwsec_ga104.py / extract_fwsec.py. */
#ifndef FWSEC_BLOB_NAME
# define FWSEC_BLOB_NAME        L"fwsec_ga104.bin"
#endif

/* --- derived framebuffer / WPR layout (do not hand-edit) ---
 * NOTE: every leaf macro is parenthesised. `&` binds looser than `-`, so an
 * unparenthesised 0x100000 would silently fold into the mask of the line
 * above and produce a plausible-looking but wrong frtsOffset. */
#define TARGET_MB               (0x100000ULL)
#define TARGET_PRAMIN           TARGET_MB
#define TARGET_FRTS_SIZE        TARGET_MB
#define TARGET_VGA_WS_OFFSET    (TARGET_FB_SIZE - TARGET_PRAMIN)

/* --- WPR END MARGIN (найдено 2026-09-28, docs/70HX-DRIVER-ANALYSIS.md §5) ---
 *
 * Драйвер 610.43.03 считает конец распребительной области так
 * (kernel_gsp_tu102.c:817):
 *
 *     gspFwWprEnd = ALIGN_DOWN(vgaWS - kgspGetWprEndMargin(), 128K)
 *     frtsOffset  = gspFwWprEnd - frtsSize
 *
 * а kgspGetWprEndMargin (kernel_gsp.c:6552) при незаданном реестровом
 * оверрайде складывает ВОТ ЭТО:
 *
 *     pmuReserved + frtsSize(1M) + gspRmBootUcodeSize(0x6000)
 *                 + sizeOfRadix3Elf (~84M) + fwHeap + nonWprHeap
 *
 * То есть наш прежний TARGET_WPR_END = vgaWS & ~0x1FFFF БЕЗ этого
 * вычитания — единственная найденная арифметическая ошибка в профиле.
 * FRTS обязан лежать над bootBin и ELF GSP; если попросить FWSEC
 * защёлкнуть WPR2 слишком высоко, под защиту попадёт чужой регион, и
 * FWSEC молча откажется — ровно то, что наблюдается.
 *
 * ТОЧНОЕ значение маржи вычисляется в драйвере из размеров куч и
 * pmuReserved, которые в EFI мы не знаем. Драйвер же допускает задать её
 * реестром (RM_GSP_WPR_END_MARGIN), то есть значение подбирается
 * экспериментально — что и делаем: TARGET_WPR_END_MARGIN задаётся здесь,
 * а ниже печатается в баннер, чтобы по логу было видно, что на флешке.
 *
 * Ориентиры перебора: 0 (заведомо неверно, прежнее поведение),
 * 64/96/128/160/256 МБ. Подробности и критерий успеха — в
 * docs/70HX-NEXT-STEPS.md §3a. */
#ifndef TARGET_WPR_END_MARGIN
# define TARGET_WPR_END_MARGIN   (0x08000000ULL)   /* 128 MB */
#endif

#define TARGET_WPR_END_RAW      (TARGET_VGA_WS_OFFSET - TARGET_WPR_END_MARGIN)
#define TARGET_WPR_END          (TARGET_WPR_END_RAW & ~(0x1FFFFULL))
#define TARGET_FRTS_OFFSET      (TARGET_WPR_END - TARGET_FRTS_SIZE)
/* FWSEC's FRTS command carries the offset in 4 KB pages (cmd = frts>>12).
 *
 * Формула WPR2_LO = frts>>8 проверена ТОЖДЕСТВЕННО по заголовкам драйвера
 * (docs/70HX-DRIVER-ANALYSIS.md §4):
 *     NV_PFB_PRI_MMU_WPR2_ADDR_LO_ALIGNMENT = 0xC
 *     NV_PFB_PRI_MMU_WPR2_ADDR_LO_VAL      = 31:4
 *     ожидаемое_значение_в_регистре = (frts >> 0xC) << 4 == frts >> 8
 * Это НЕ экстраполиция с одного замера, а тождество. */
#define TARGET_FRTS_OFFSET_PG   (TARGET_FRTS_OFFSET >> 12)
#define TARGET_WPR2_LO          ((UINT32)(TARGET_FRTS_OFFSET >> 8))
/* Драйвер проверяет только wpr2Hi != 0 ("WPR2 найден"), точное HI не
 * сверяет, поэтому это значение влияет только на наше условие успеха. */
#define TARGET_WPR2_HI          (TARGET_WPR2_LO + 0xE00U)

/* A misaligned FRTS offset means a wrong fbSize in the profile, and the
 * booter aborts (0x91) long before it touches the signature. Catch it at
 * compile time instead of on the mining rig. */
#if (TARGET_FRTS_OFFSET & 0xFFF) != 0
# error "TARGET_FRTS_OFFSET not 4 KB aligned — check TARGET_FB_SIZE"
#endif
/* The >>8 encoding keeps a 10 GB card's FRTS offset inside 32 bits, so the
 * window cannot wrap for any sane framebuffer size. Assert it anyway, on the
 * uncast values (a cast is not allowed in a preprocessor expression). */
#if (TARGET_FRTS_OFFSET >> 8) + 0xE00 < (TARGET_FRTS_OFFSET >> 8)
# error "WPR2 window wraps 32 bits — unsupported framebuffer size"
#endif
/* Маржа не должна съесть больше половины кадрового буфера: FRTS обязан
 * остаться внутри FB, иначе WPR2 будет защёлкнут на несуществующем
 * регионе и FWSEC откажется (или, что хуже, защитит что-то не то). */
#if TARGET_WPR_END_MARGIN > (TARGET_FB_SIZE / 2)
# error "TARGET_WPR_END_MARGIN exceeds half the framebuffer — nonsense"
#endif
/* FRTS должен лежать НИЖЕ VGA workspace, иначе это не FRTS. */
#if TARGET_FRTS_OFFSET >= TARGET_VGA_WS_OFFSET
# error "frtsOffset is not below vgaWorkspaceOffset — check the margin"
#endif

/* ==== GA10x registers (BAR0 MMIO) ====
 * PLM/SS0/SS1 are the actual lock bits; the rest is referenced by the
 * unlock flow or diagnostics. Offsets come from the open-gpu-kernel-modules
 * GA102 regmaps and are shared by GA102/GA103/GA104/GA106/GA107 — the driver
 * serves every GA10x consumer die from the same kernel_gsp_ga102.c HAL and
 * the same published/ampere/ga102 register headers, so the feature-override
 * block at 0x82xxxx and the XVE window at 0x88xxxx land at the same BAR0
 * offsets on the 70HX. */
#define REG_FEAT_OVR_PLM        0x00823804UL   /* PLM: 0xffffffff = open */
#define REG_FEAT_OVR_SM_SPD     0x0082381CUL   /* SS0: 0x88888888 = full */
#define REG_FEAT_OVR_SM_SPD_1   0x00823820UL   /* SS1: 0x00000008 = full */

/* ==== SM_ISSUE_RATE_MOD — эксперимент 2026-09-29 ===================
 *
 * Источник: отчёт bendy2 «CMP 90HX 相对 GA102 消费卡的图形阉割分析报告»,
 * раздел 4 «已排除的次要项» (анализ BAR0 пяти карт):
 *
 *     SM_ISSUE_RATE_MOD @0x504204:  90HX=0x7   3090=0x5
 *     «SM 调度节流，是算力域，非图形»
 *
 * Заблокированная карта -> 0x7, полностью разлоченная потребительская -> 0x5.
 * В отличие от FUSE_SS_* (fuse OTP, физически не переписывается) это
 * обычный MMIO-регистр домена SM.
 *
 * Зачем пробуем: вычислительный замер 2026-09-29 дал 233.89 t/s, то есть
 * заблокированную базу, при том что SS0/SS1 в Windows доставлены верно.
 * Значит ограничитель вычислительной скорости — не только эти поля.
 *
 * ГРАНИЦЫ ВЫВОДА, чтобы не переоценить: сравнение в отчёте сделано на
 * GA102 (90HX / 3090 / 3080Ti), у нас GA104. Диэны разные, поэтому
 * перенос значения 0x5 — гипотеза. Назначение битов не документировано.
 * Поэтому пишем ровно наблюдавшееся у рабочей карты значение и не трогаем
 * соседей. Критерий успеха — llama-bench снаружи, не показание в логе. */
#define REG_SM_ISSUE_RATE_MOD   0x00504204UL
#define ISSUE_RATE_MOD_UNLOCKED 0x00000005UL

#ifndef PROBE_ISSUE_RATE_MOD
/* v3n: 2026-09-29 — ВРЕМЕННО ВЫКЛЮЧЕНО ради A/B-теста.
 *
 * Что произошло. С этой записью включённой llama-bench дал
 * 2271.71 t/s против 233.89 t/s на сборке без неё — в 9.7 раза.
 * НО замер показал, что регистр УЖЕ БЫЛ 0x00000005 ДО записи:
 *
 *     IRM before 0x504200=0x00090000 0x504204=0x00000005 ...
 *     IRM write  0x00504204 = 0x00000005 -> readback 0x00000005 STUCK
 *
 * То есть по read-back запись — no-op, и «IRM разблокировал карту» было бы
 * ровно той же ошибкой, что и is_unlocked(): показание без механизма.
 *
 * Возможны два объяснения, и их надо развести:
 *   (а) запись 0x5 имеет НЕНАБЛЮДАЕМЫЙ побочный эффект (сброс защёлкнутого
 *       троттлинга), и read-back этого не показывает;
 *   (б) 233.89 t/s были сняты в иных условиях (прошивка/драйвер/процессы),
 *       и выросло не.register write, а окружение.
 *
 * A/B с выключенной записью разводит их: если вернётся ~233 t/s — виновата
 * запись (вариант (а)); если останется ~2270 — виновато окружение (б).
 * После теста это значение надо вернуть в 1, если сработает (а). */
#define PROBE_ISSUE_RATE_MOD 0
#endif

/* v3.15: privLevelMask (NV_PFB_MMU_WPR2_PLM).
 *
 * Комментарий в okchk_check() в нашем же коде говорит: «без его нуля
 * значение WPR2 может быть прикрытым, и "успех" окажется ложным».
 * То есть самый старый и самый непрочитанный прямой регистр анлока.
 *
 * Текущее значение по логу: 0x0004CB8F / 0x0045CB8F (то есть НЕ ноль,
 * и не нулевое ни в младшей, ни в старшей половине).
 *
 * Ставим ПОСЛЕ того, как compute-разблокировка уже отработала и
 * проверена, и ПЕРЕД записью GFX_SPEED_SELECT. Порядок важен: обнуление
 * не должно иметь возможности сломать уже работающий путь FWSEC, а
 * посмотреть на GFX_SPEED_SELECT надо уже после изменения масок.
 *
 * Критерий - только fps в игре и неизменность OKCHK. Если FWSEC
 * рассыплется, это будет видно по wpr2Lo/wpr2Hi/frtsErrCode, а не
 * «заметим позже». */
#ifndef PROBE_PRIV_LEVEL_MASK
#define PROBE_PRIV_LEVEL_MASK 0
#endif

/* v3.15: скан BAR0 на размер кристалла.
 *
 * ВАЖНО, ПОЧЕМУ ЗА ФЛАГОМ: функция ниже не пустая, и если её оставить
 * безусловной, она меняет КАЖДУЮ сборку, включая откатную unlock_v3n.
 * Откат обязан оставаться побайтово тем же самым - это единственная
 * точка возврата. Ошибка ровно такого класса уже дважды ловила нас
 * молча, поэтому проверяем md5 отката в каждом цикле. */
#ifndef CHIP_SIZE_SCAN
#define CHIP_SIZE_SCAN 0
#endif


#define REG_PCIE_FUSE_OVR       0x00823810UL
#define REG_PFB_MMU_WPR2_LO     0x001FA824UL
#define REG_PFB_MMU_WPR2_HI     0x001FA828UL
/* Общий регистр уровня привилегий для WPR2 (dev_fb.h:
 * NV_PFB_PRI_MMU_WPR2_ADDR_LO__PRIV_LEVEL_MASK). Нулевое значение означает,
 * что чтение WPR2 отдаёт реальную запись; ненулевое — запись прикрыта, и
 * тогда наше «wpr2 не встал» может быть ложным. */
#define REG_PFB_MMU_WPR2_PLM    0x001FA7CCU
/* NV_PBUS_VBIOS_SCRATCH(i) = 0x1400 + i*4. Драйвер читает 0x0E
 * (FWSECLIC_FRTS_ERR_CODE = 31:16) и 0x15 (SB_ERR_CODE = 15:0). */
#define NV_PBUS_VBIOS_SCRATCH  0x00001400UL
#define FWSECLIC_SCRATCH_FRTSE 0x0EU
#define FWSECLIC_SCRATCH_SBE   0x15U
#define REG_PCIE_LINK_CTRL      0x0008C000UL
#define REG_GFW_BOOT_OK         0x00118234UL   /* 0xff == GFW booted */

/* Device-ID matcher, used by both the single- and the multi-card enumerator. */
static BOOLEAN
is_target_gpu(UINT32 Id)
{
    UINT16 ven = (UINT16)(Id & 0xFFFF);
    UINT16 dev = (UINT16)((Id >> 16) & 0xFFFF);

    if (ven != TARGET_PCI_VENDOR) return FALSE;
    if (dev == TARGET_PCI_DEV)    return TRUE;
    if (dev == TARGET_PCI_DEV_ALT1) return TRUE;
    if (dev == TARGET_PCI_DEV_ALT2) return TRUE;
    return FALSE;
}


#define VAL_PLM_OPEN            0xFFFFFFFFUL
#define VAL_SS0_UNLOCKED        0x88888888UL
#define VAL_SS1_UNLOCKED        0x00000008UL

/* ==== РЕШАЮЩИЙ ЭКСПЕРИМЕНТ: переживают ли селекторы FLR (2026-09-29) ====
 *
 * Установка: render test GPU-Z — 75 Вт, Cyberpunk 2077 — 85 Вт при 9 FPS.
 * Анлока нет. Перезапуска между прогоном и замером не было, значит
 * fuse-shadow не сбрасывался POST'ом, и виноват не он.
 *
 * Гипотезы, которые надо разделить:
 *   (а) селекторы не переживают do_flr() — в Windows приходит ноль;
 *   (б) селекторы переживают, но 0x88888888 для GA104 не то значение.
 *
 * Проверка: убрать FLR. Если (а) — мощность вырастет. Если (б) — останется
 * прежней. Различить можно одним прогоном.
 *
 * Цена: FLR был нужен, чтобы сбросить защёлкнутый WPR2 — комментарий в
 * коде говорит, что без него драйвер падает с frts_err=0xbe. То есть в
 * варианте без FLR карта может вообще не подняться. Это ожидаемо и
 * информативно: если карта пропадёт — значит без FLR нельзя, и вопрос
 * закрывается в пользу (б).
 *
 * Значение по умолчанию: 0 — FLR ВЫПОЛНЯЕТСЯ.
 *
 * РЕЗУЛЬТАТ ЭКСПЕРИМЕНТА (прогон skipflr, 2026-09-29): SKIP_FLR=1
 * НЕЖИЗНЕСПОСОБЕН. Карта перестала инициализироваться, и PREFLR показал
 * почему:
 *
 *     PREFLR WPR2=0x01EAD000/0x01F7EE00   (ожидалось 0x01F7E000/...)
 *            cpuctl=0xBADF5620  <- движок в плохом состоянии
 *            GFW=0xBADF1100
 *
 * LO уехал на 0xD1000, cpuctl не 0x10 — то есть без сброса WPR2 не
 * возвращается в постовый вид, и Windows-драйвер падает. Ровно то, о чём
 * предупреждает комментарий в коде (frts_err=0xbe).
 *
 * Значит: FLR обязателен, и вопрос «переживают ли селекторы FLR» этим
 * экспериментом НЕ закрыт — карта не поднялась, мощность мерить не на чем.
 * Следующий шаг — другой: искать правильные значения селекторов, а не
 * отменять сброс. */
#ifndef SKIP_FLR
#define SKIP_FLR 0
#endif
/* ==== ЛОВУШКА, КОТОРАЯ МОГЛА СЪЕСТЬ ВЕСЬ АНЛОК (2026-09-29) ============
 *
 * Многокарточный режим при g_mcCount=2 ставит g_mcAdvance=TRUE для карты 0
 * (условие: g_mcIndex+1 < g_mcCount). А в финале вызывается
 * mc_set_bootnext_self(), которая пишет BootNext = путь НАШЕГО EFI на
 * флешке. То есть прошивка загружает флешку ещё раз.
 *
 * Это ПОЛНЫЙ POST. А fuse-shadow (где живут SS0/SS1) при POST обнуляется —
 * ради этого весь Unlock и делается ДО загрузки ОС, минуя POST.
 *
 * Итог: анлок записывается, затем прошивка делает POST, и карта приходит в
 * Windows заблокированной. Ровно наблюдаемая картина: лог показывает
 * «SS0/SS1 встали, всё хорошо», а мощность 75-85 Вт.
 *
 * И это НЕВИДИМО в логе: второй прогон затирает первый (область лога
 * очищается каждый прогон), а второй прогон выглядит идентично — он тоже
 * записывает селекторы и читает их обратно. Отличить «анлок пережил» от
 * «анлок затёрт вторым POST'ом» по логу нельзя.
 *
 * SINGLE_CARD_ONLY: не перезагружаться на флешку, работать с первой
 * найденной картой и отдать BootOrder прошивке. Вторая 10de:248A на
 * bus 16 считается призраком от прежней работы (docs/70HX-PORT-STATUS).
 * Если после этого мощность вырастет — причина найдена.
 *
 * Обоснование: перезагрузка ради второй карты несовместима с задачей
 * «анлок должен дожить до Windows». Побеждает второе. */
#ifndef SINGLE_CARD_ONLY
#define SINGLE_CARD_ONLY 1
#endif

/* ==== ГИПОТЕЗА B: настоящий селектор живёт в 0x0082380C (2026-09-29) ===
 *
 * Чтение из Windows (RWEverything, сессия через флешку) дало:
 *
 *     0x0082380C = 0x00888888   <- стояло ДО нас, стоит и сейчас
 *     наш SS0    = 0x88888888   <- пишем в 0x0082381C
 *
 * Разница РОВНО в старшем байте. Плюс 0x00823810 = 0x002AAAAA (чередующиеся
 * биты) — тоже не меняется. Похоже на fuse-отчётность.
 *
 * Тем не менее стоит проверить: если 0x82380C — настоящий селектор
 * SM-скорости, ему не хватает верхнего байта. Эксперимент дешёвый и
 * обратимый в том же смысле, в каком уже доказано: запись в 0x82381C
 * уцелела в Windows и ничего не сломала.
 *
 * Щадящий режим: если PROBE_FUSE_NEIGHBOUR=0, ничего не пишем, только
 * читаем. По умолчанию был 1 — эксперимент.
 *
 * ============ v3.44: ВЫКЛЮЧЕНО, ГИПОТЕЗА ОПРОВЕРГНУТА НА ЖЕЛЕЗЕ ============
 *
 * Замер v3.43 (usb-log-1004-130611.txt, 5 343 мс) дал три независимых
 * свидетельства, что запись бесполезна:
 *
 *   1) сама проверка: 'PROBE readback 0x0082380C = 0x00888888 NOT STUCK
 *      (probably just reporting)' - верхний байт не залипает;
 *   2) список изменений FUSE: 'FUSE CHANGED' перечисляет только 0x00823818,
 *      0x0082381C и 0x00823820. 0x0082380C В СПИСКЕ НЕТ - то есть запись не
 *      изменила вообще ничего, ни одного бита;
 *   3) до и после прогона значение то же: 0x0082380C = 0x00888888.
 *
 * Стоила эта гипотеза 100 мс безусловного Stall(100000) на КАЖДОЙ загрузке,
 * и это был единственный безусловный сон в блоке селекторов, который не был
 * нужен для анлока. Анлок - это SS0/SS1 (0x0082381C / 0x00823820) и
 * GFX_SPEED_SELECT (0x00823830); 0x0082380C в нём не участвует.
 *
 * ВНИМАНИЕ, ТОЧНО ЧТО ДЕЛАЕТ #if=0: за #ifdef стоит ВЕСЬ блок, включая
 * чтения и строки PROBE, - то есть они исчезают из лога тоже. Гипотеза при
 * этом не теряется: она уже измерена и опровергнута (три свидетельства
 * выше), а чтобы перепроверить её, достаточно вернуть 1. Комментарий
 * «щадящий режим - только читаем» относился к другой, более ранней редакции
 * этого блока и сейчас неверен. */
#ifndef PROBE_FUSE_NEIGHBOUR
#define PROBE_FUSE_NEIGHBOUR 0
#endif
#define REG_FUSE_SEL_CAND     0x0082380CUL   /* кандидат: сейчас 0x00888888 */
#define REG_FUSE_ROUTINE      0x00823810UL   /* сопровождающий, 0x002AAAAA */
static BOOLEAN g_postFlr = FALSE;

/* v3.29, ЭТАП 13: замер готовности устройства после FLR.
 *
 * Секция 'render: FLR + 300ms settle' измеряется 499,3 мс при бюджете
 * 500 мс, а внутри стоят ДВЕ слепые паузы подряд: Stall(200000) в do_flr()
 * сразу после инициирования FLR, и Stall(300000) в вызывающем коде.
 * Обход PCIe-capability около нуля. То есть 499 мс - чистое ожидание, и это
 * 22 % прогона.
 *
 * Кандидат на событие: после инициирования FLR конфигурационное пространство
 * не отвечает (читается 0xFFFFFFFF), и снова отвечает, когда устройство
 * отошло. Это ровно то, что нужно измерять, а не угадывать.
 *
 * Бюджет остаётся 200 мс, то есть ХУДШИЙ СЛУЧАЙ РАВЕН СЕГОДНЯШНЕМУ: если
 * устройство не ответит, мы потратим те же 200 мс. */
#define FX_FLR_BUDGET_US  200000   /* раньше был слепой Stall(200000) */
#define FX_FLR_POLL_US    1000     /* период опроса конфигурационного чтения */
static UINTN  fx_flrCalls = 0;      /* вызовов do_flr() */
static UINTN  fx_flrFast = 0;       /* ответил сразу, без ожидания */
static UINTN  fx_flrWaited = 0;     /* ответил после ожидания */
static UINTN  fx_flrNever = 0;      /* не ответил за бюджет */
static UINT64 fx_flrUs = 0;         /* суммарно мкс */
static UINT64 fx_flrUsMax = 0;       /* максимум по одному вызову */
static UINT32 fx_flrLastId = 0;     /* последний прочитанный vendor/device id */
static UINT32 fx_flrLastRaw = 0;    /* последнее сырое значение чтения */   /* после do_flr() MMIO не читать */

/* ==== SEC2 Falcon microcontroller — hosts the signed "booter" ucode ====
 * This is where the exploit runs: we craft its IMEM/DMEM via DMA and let
 * its own signature check trip the canary bug (V67 payload). */
#define NV_PSEC_BASE            0x00840000UL
#define NV_PSEC_FBIF_BASE       0x00840600UL
#define NV_FALCON2_SEC_BASE     0x00841000UL

#define SEC2_MAILBOX0           (NV_PSEC_BASE + 0x040)
#define SEC2_MAILBOX1           (NV_PSEC_BASE + 0x044)
#define SEC2_IRQSTAT            (NV_PSEC_BASE + 0x008)
#define SEC2_IRQSCLR            (NV_PSEC_BASE + 0x004)
#define SEC2_DEBUGINFO          (NV_PSEC_BASE + 0x094)
#define SEC2_CPUCTL             (NV_PSEC_BASE + 0x100)
#define SEC2_BOOTVEC            (NV_PSEC_BASE + 0x104)
#define SEC2_DMACTL             (NV_PSEC_BASE + 0x10C)
#define SEC2_DMATRFBASE         (NV_PSEC_BASE + 0x110)
#define SEC2_DMATRFMOFFS        (NV_PSEC_BASE + 0x114)
#define SEC2_DMATRFCMD          (NV_PSEC_BASE + 0x118)
#define SEC2_DMATRFFBOFFS       (NV_PSEC_BASE + 0x11C)
#define SEC2_DMATRFBASE1        (NV_PSEC_BASE + 0x128)
#define SEC2_ENGINE             (NV_PSEC_BASE + 0x3C0)
#define SEC2_FBIF_CTL           (NV_PSEC_FBIF_BASE + 0x24)
#define SEC2_FBIF_TRANSCFG0     (NV_PSEC_FBIF_BASE + 0x00)
#define SEC2_BCR_CTRL           (NV_FALCON2_SEC_BASE + 0x668)  /* CORE_SELECT: 0=FALCON, 1=RISCV */
#define SEC2_RM                 (NV_PSEC_BASE + 0x084)  /* chipId0 (v2.24) */
/* Порты чтения IMEM/DMEM (v2.17 диагностика DMA) */
#define SEC2_IMEMC0             (NV_PSEC_BASE + 0x180)
#define SEC2_IMEMD0             (NV_PSEC_BASE + 0x184)
#define SEC2_DMEMC0             (NV_PSEC_BASE + 0x1C0)
#define SEC2_DMEMD0             (NV_PSEC_BASE + 0x1C4)

/* ==== GSP Falcon registers ====
 * The kernel driver resets GSP before the SEC2 booter load:
 * Драйвер перед SEC2 booter load РЕСЕТИТ GSP (kflcnReset в _kgspBootGspRm) —
 * живой GFW из POST держит SEC2 залоченным (0xBADF5620). ENGINE (0x1103C0)
 * доступен из EFI → убиваем GFW тем же способом, что и драйвер. */
#define GSP_BASE                0x00110000UL
#define GSP_ENGINE              (GSP_BASE + 0x3C0)
#define GSP_MAILBOX0            (GSP_BASE + 0x040)
#define GSP_MAILBOX1            (GSP_BASE + 0x044)
#define SEC2_MOD_SEL            (NV_FALCON2_SEC_BASE + 0x180)
#define SEC2_BROM_CURR_UCODE_ID (NV_FALCON2_SEC_BASE + 0x198)
#define SEC2_BROM_ENGIDMASK     (NV_FALCON2_SEC_BASE + 0x19C)
#define SEC2_BROM_PARAADDR0     (NV_FALCON2_SEC_BASE + 0x210)

#define NV_PFALCON_FALCON_CPUCTL_STARTCPU_TRUE   0x2   /* bit 1 */
#define NV_PFALCON_FALCON_CPUCTL_HALTED_TRUE     0x10  /* bit 4 */
#define NV_PFALCON_FALCON_ENGINE_RESET_TRUE      0x1   /* bit 0 */
#define NV_PFALCON_FALCON_DMATRFCMD_SEC_SHIFT    2
#define NV_PFALCON_FALCON_DMATRFCMD_IMEM_SHIFT   4
#define NV_PFALCON_FALCON_DMATRFCMD_WRITE_SHIFT  5
#define NV_PFALCON_FALCON_DMATRFCMD_SIZE_SHIFT   8
#define NV_PFALCON_FALCON_DMATRFCMD_CTXDMA_SHIFT 12
#define NV_PFALCON_FALCON_DMATRFCMD_SIZE_256B    6
#define NV_PFALCON_FALCON_DMATRFCMD_SET_DMTAG    0x10000
#define FLCN_BLK_ALIGNMENT                       256

#define NV_PTIMER_TIME_0        0x00009400UL
#define NV_PTIMER_TIME_1        0x00009410UL

/* ==== Boot (SEC2) ucode layout constants — ground truth from bindata ====
 * IMEM gets image[0x100..0x89FF] (0x8900 B), DMEM gets image[0x8A00..]
 * (0x6200 B); the RSA signature therefore lands on DMEM[0x10] by
 * construction (patchLoc 0x8A10 - dataOffset 0x8A00). Smaller sizes seen
 * in an early trace were rate-limit artifacts and do NOT work. */
#define BOOTER_UCODE_SIZE       0x0000EC00UL  /* 60416 */
#define BOOTER_APP_CODE_OFFSET  0x00000100UL  /* appCodeOffset (imemVa) */
#define BOOTER_APP_CODE_SIZE    0x00008900UL  /* appCodeSize  (imem) */
#define BOOTER_OS_DATA_OFFSET   0x00008A00UL  /* osDataOffset (data) */
#define BOOTER_OS_DATA_SIZE     0x00006200UL  /* osDataSize   (dmem) */
#define BOOTER_HS_SIG_DMEM_ADDR 0x00000010UL  /* patchLoc(0x8a10) - dataOffset(0x8a00) */
#define BOOTER_UCODE_ID         3
#define BOOTER_ENGINE_ID_MASK   1

/* ==== V67 payload — oversized "signature" that trips the canary ====
 * 0xFA00 bytes vs stock 0x1000; overflow -> ROP chain -> priv writes. */
#define V67_SIZE                0x0000FA00UL

/* ==== WPR meta (256 B) — boot argument block for the GSP bootloader ====
 * Field-for-field replica of GspFwWprMeta; geometry formulas live in
 * build_wpr_meta() further below. */
#define WPR_META_SIZE           256
#define GSP_FW_WPR_META_MAGIC   0xdc3aae21371a60b3ULL
#define GSP_FW_WPR_META_REVISION 1
#define GSP_FW_WPR_META_VERIFIED 0xa0a0a0a0a0a0a0a0ULL


typedef struct {
    UINT64 magic;
    UINT64 revision;
    UINT64 sysmemAddrOfRadix3Elf;
    UINT64 sizeOfRadix3Elf;
    UINT64 sysmemAddrOfBootloader;
    UINT64 sizeOfBootloader;
    UINT64 bootloaderCodeOffset;
    UINT64 bootloaderDataOffset;
    UINT64 bootloaderManifestOffset;
    union {
        struct { UINT64 sysmemAddrOfSignature; UINT64 sizeOfSignature; };
        struct { UINT32 gspFwHeapFreeListWprOffset; UINT32 unused0; UINT64 unused1; };
    };
    UINT64 gspFwRsvdStart;
    UINT64 nonWprHeapOffset;
    UINT64 nonWprHeapSize;
    UINT64 gspFwWprStart;
    UINT64 gspFwHeapOffset;
    UINT64 gspFwHeapSize;
    UINT64 gspFwOffset;
    UINT64 bootBinOffset;
    UINT64 frtsOffset;
    UINT64 frtsSize;
    UINT64 gspFwWprEnd;
    UINT64 fbSize;
    UINT64 vgaWorkspaceOffset;
    UINT64 vgaWorkspaceSize;
    UINT64 bootCount;
    union {
        struct {
            UINT64 partitionRpcAddr;
            UINT16 partitionRpcRequestOffset;
            UINT16 partitionRpcReplyOffset;
            UINT32 elfCodeOffset;
            UINT32 elfDataOffset;
            UINT32 elfCodeSize;
            UINT32 elfDataSize;
            UINT32 lsUcodeVersion;
        };
        struct {
            UINT32 partitionRpcPadding[4];
            UINT64 sysmemAddrOfCrashReportQueue;
            UINT32 sizeOfCrashReportQueue;
            UINT32 lsUcodeVersionPadding;
        };
    };
    UINT8  gspFwHeapVfPartitionCount;
    UINT8  flags;
    UINT8  padding[2];
    UINT32 pmuReservedSize;
    UINT64 verified;
} GspFwWprMeta;

/* radix3 */
#define RADIX_PAGE_LOG2  12
#define RADIX_PAGE_SIZE  (1ULL << RADIX_PAGE_LOG2)
#define RADIX_ENTRIES_LOG2 (RADIX_PAGE_LOG2 - 3)
#define RADIX_ENTRIES    (1ULL << RADIX_ENTRIES_LOG2)  /* 512 */

/* ==== Embedded blobs (linked by build.sh via objcopy --redefine-sym) ====
 * The extern symbol names MUST match --redefine-sym targets in build.sh,
 * otherwise references stay unresolved and the code dereferences NULL.
 * Blob provenance and extraction: see BUILDING.md. */
extern const UINT8 v67_payload_bin[];
extern const UINT8 booter_ucode_dbg[];      /* DBG (отвергается PROD-физами: 0x780009) */
extern const UINT8 booter_ucode_prod[];     /* PROD (стоковый, sig 0x303c3b1f — v2.57) */
extern const UINT8 gsp_rm_boot_dbg[];      /* BL (GspRmBoot, GA10x), 0x6000 */
#define GSP_RM_BOOT_SIZE  0x6000UL

/* FWSEC ucode, extracted from the target die's own VBIOS ROM (v2.28; the
 * 10de:220d capture is V2-27-FWSEC-CAPTURED.md):
 *   0xEA00 = code(0xE200) + data(0x800);
 *   sig[2] = 0x180 bytes RSA3K — the fuse variant (sigOffset=0x300).
 * The SYMBOL names are fixed by build.sh (--redefine-sym) so the same C code
 * links against either die's blob; only the file that gets embedded changes.
 * These geometry constants below are identical for GA102 and GA104 (same
 * Falcon ucode descriptor layout — extract_fwsec_ga104.py asserts it). */
extern const UINT8 fwsec_ga104_bin[];
extern const UINT8 fwsec_ga104_sig[];
/* Три подписи FWSEC из VBIOS самой карты (src/blobs/fwsec_ga104_prod_sigN).
 * Подпись НЕ вычисляется по образу (у GA102 и GA104 она байт-в-байт
 * одинакова при разных образах) — это разные версии под разные fuse-ревизии.
 * Для 90HX верна sig[2]; ревизия 70HX может отличаться, поэтому перебираем
 * все три и смотрим, на какой WPR2 встаёт. */
extern const UINT8 fwsec_ga104_prod_sig0[];
extern const UINT8 fwsec_ga104_prod_sig1[];
extern const UINT8 fwsec_ga104_prod_sig2[];

/* v2.54: SEC2 ucode из VBIOS (appid 0x49 DBG / 0x89 PROD): ucodeId=10,
 * engmask=1, imemLoad=0x4400, dmemLoad=0x8F4, pkc=0x6DC; sig[2] патчен. */
extern const UINT8 sec2_ucode_vbios_49[];
extern const UINTN sec2_ucode_vbios_49_size;
extern const UINT8 sec2_ucode_vbios_89[];
extern const UINTN sec2_ucode_vbios_89_size;

/* ==== GSP Falcon2/BROM registers + FWSEC constants (boot-rom params) ====
 * Falcon2 window bases are shared across GA10x (dev_falcon_second_pri.h:
 * NV_FALCON2_GSP_BASE 0x00111000, NV_FALCON2_SEC_BASE 0x00841000), as are
 * the SEC/GSP instance bases (dev_sec_pri.h NV_PSEC 0x840000,
 * dev_gsp.h NV_PGSP 0x110000). */
#define GSP_FALCON2_BASE        0x00111000UL   /* NV_FALCON2_GSP_BASE (GA10x) */
#define GSP_BCR                 (GSP_FALCON2_BASE + 0x668)
#define GSP_BROM_PARAADDR0      (GSP_FALCON2_BASE + 0x210)
#define GSP_BROM_ENGIDMASK      (GSP_FALCON2_BASE + 0x19C)
#define GSP_BROM_CURR_UCODE_ID  (GSP_FALCON2_BASE + 0x198)
#define GSP_MOD_SEL             (GSP_FALCON2_BASE + 0x180)
#define GSP_CPUCTL              (GSP_BASE + 0x100)
#define GSP_BOOTVEC             (GSP_BASE + 0x104)
#define GSP_DMATRFBASE          (GSP_BASE + 0x110)
#define GSP_DMATRFBASE1         (GSP_BASE + 0x128)
#define GSP_DMATRFMOFFS         (GSP_BASE + 0x114)
#define GSP_DMATRFFBOFFS        (GSP_BASE + 0x11C)
#define GSP_DMATRFCMD           (GSP_BASE + 0x118)
#define GSP_FBIF_TRANSCFG0      (GSP_BASE + 0x600)
#define GSP_FBIF_CTL            (GSP_BASE + 0x624)
#define GSP_DMACTL              (GSP_BASE + 0x10C)
#define GSP_RM                  (GSP_BASE + 0x084)

#define FWSEC_SIZE              0x0000EA00UL
#define FWSEC_CODE_SIZE         0x0000E200UL   /* imemSize */
#define FWSEC_DATA_OFF          0x0000E200UL   /* dataOffset */
#define FWSEC_DMEM_SIZE         0x00000800UL   /* dmemSize */
#define FWSEC_SIG_DMEM_ADDR     0x000005A4UL   /* hsSigDmemAddr */
#define FWSEC_IFACE_OFF         0x0000001CUL   /* interfaceOffset */
#define FWSEC_UCORE_ID          9
#define FWSEC_ENGID_MASK        0x400
/* FRTS offset handed to FWSEC = derived from TARGET_FB_SIZE above.
 * GA104/CMP70HX 8 GB: wprEnd=0x1FFF00000, frtsOffset=0x1FFE00000
 * GA102/CMP90HX 10GB: wprEnd=0x27FF00000, frtsOffset=0x27FE00000 */
#define FWSEC_FRTS_OFFSET       TARGET_FRTS_OFFSET
#define FWSEC_CMD_FRTS          0x15           /* DMEM_MAPPER_V3_CMD_FRTS */
#define FWSEC_SIG_SIZE          0x180

/* ==== Tiny hand-written RISC-V program (dev experiments only) ====
 * Writes through the SEC2 core's CSB mechanism (same primitive the V67
 * chain uses): csrrw 0x7c8 = data port, csrrw 0x7cc = address + commit.
 * Used by riscv_direct_start(); not part of the release path.
 * Прямая запись через CSB-механизм ядра SEC2 (как V67-цепочка в Linux):
 *   csrrw zero, 0x7c8, data_reg   — данные
 *   csrrw zero, 0x7cc, addr_reg   — адрес BAR0 + commit
 * Программа: PLM=0xffffffff @0x823804, SS0=0x88888888 @0x82381c,
 * SS1=0x8 @0x823820, затем self-loop. 17 слов (68 байт). */
static const UINT32 own_code_67[] = {
    0xfff00513,  /* addi a0, zero, -1        x10 = 0xffffffff */
    0x7c851073,  /* csrw 0x7c8, a0           data */
    0x008245b7,  /* lui  a1, 0x824           x11 = 0x824000 */
    0xe0458593,  /* addi a1, a1, -0x7fc      x11 = 0x823804 */
    0x7cc59073,  /* csrw 0x7cc, a1           commit -> PLM = 0xffffffff */
    0x88889537,  /* lui  a0, 0x88889         x10 = 0x88889000 */
    0x88850513,  /* addi a0, a0, -0x778      x10 = 0x88888888 */
    0x7c851073,  /* csrw 0x7c8, a0 */
    0x008245b7,  /* lui  a1, 0x824 */
    0xe1c58593,  /* addi a1, a1, -0x7e4      x11 = 0x82381c */
    0x7cc59073,  /* csrw 0x7cc, a1           commit -> SS0 = 0x88888888 */
    0x00800513,  /* addi a0, zero, 8         x10 = 0x8 */
    0x7c851073,  /* csrw 0x7c8, a0 */
    0x008245b7,  /* lui  a1, 0x824 */
    0xe2058593,  /* addi a1, a1, -0x7e0      x11 = 0x823820 */
    0x7cc59073,  /* csrw 0x7cc, a1           commit -> SS1 = 0x8 */
    0x0000006f   /* j 0                       self-loop */
};

/* ==== PCI access layer: root-bridge config space + BAR0 MMIO ====
 * The firmware does NOT expose EFI_PCI_IO_PROTOCOL for a GPU that has
 * no UEFI driver bound (no GOP here), so config space is reached via
 * PCI Root Bridge IO protocols. gRb/gBus/gDev/gFn = current card;
 * gBar0Base = BAR0 base used by mmio_read32/mmio_write32.
 * EFI_PCI_IO_PROTOCOL НЕ выставляется для GPU без UEFI-драйвера (нет GOP)
 * на реальных прошивках → сканируем config space через root bridge.
 */
static EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *gRb = NULL;
static UINTN gBus = 0, gDev = 0, gFn = 0;
static UINT32 gBar0Base = 0;

static EFI_STATUS
pci_cfg_read(UINTN Reg, UINT32 *Out)
{
    /* BDF-адрес по спецификации UEFI: reg:12, fn:3<<12, dev:5<<15, bus:8<<20 */
    UINT64 Addr = ((UINT64)gBus << 20) | ((UINT64)gDev << 15) |
                  ((UINT64)gFn << 12) | ((UINT64)Reg & 0xFFF);
    return uefi_call_wrapper(gRb->Pci.Read, 5, gRb,
        EfiPciIoWidthUint32, Addr, 1, Out);
}

static EFI_STATUS
pci_cfg_write(UINTN Reg, UINT32 Value)
{
    UINT64 Addr = ((UINT64)gBus << 20) | ((UINT64)gDev << 15) |
                  ((UINT64)gFn << 12) | ((UINT64)Reg & 0xFFF);
    return uefi_call_wrapper(gRb->Pci.Write, 5, gRb,
        EfiPciIoWidthUint32, Addr, 1, &Value);
}

static UINT32
mmio_read32(UINTN offset)
{
    volatile UINT32 *p = (volatile UINT32 *)(UINTN)(gBar0Base + offset);
    return *p;
}

static void
mmio_write32(UINTN offset, UINT32 value)
{
    volatile UINT32 *p = (volatile UINT32 *)(UINTN)(gBar0Base + offset);
    *p = value;
}

static UINT32
cfg_read32(UINTN offset)
{
    UINT32 val = 0;
    if (gRb)
        pci_cfg_read(offset, &val);
    return val;
}

static void
cfg_write32(UINTN offset, UINT32 val)
{
    if (gRb)
        pci_cfg_write(offset, val);
}

/* ==== Config-space access to ARBITRARY BDF + PCIe capability helpers ====
 * Needed by the gen2 phase: retraining the link requires setting target
 * speed AND issuing Retrain Link on the UPSTREAM BRIDGE, not just GPU.
 * Нужны для phase3 референса: переобучение линка требует target speed
 * и Retrain Link на АПСТРИМ-БРИДЖЕ, не только на стороне GPU. */
static UINT32
pci_cfg_rd_bdf(UINTN bus, UINTN dev, UINTN fn, UINTN Reg)
{
    UINT32 val = 0xFFFFFFFFU;
    UINT64 Addr;
    if (!gRb) return val;
    Addr = ((UINT64)bus << 20) | ((UINT64)dev << 15) |
           ((UINT64)fn << 12) | ((UINT64)Reg & 0xFFF);
    uefi_call_wrapper(gRb->Pci.Read, 5, gRb,
        EfiPciIoWidthUint32, Addr, 1, &val);
    return val;
}

static void
pci_cfg_wr_bdf(UINTN bus, UINTN dev, UINTN fn, UINTN Reg, UINT32 v)
{
    UINT64 Addr;
    if (!gRb) return;
    Addr = ((UINT64)bus << 20) | ((UINT64)dev << 15) |
           ((UINT64)fn << 12) | ((UINT64)Reg & 0xFFF);
    uefi_call_wrapper(gRb->Pci.Write, 5, gRb,
        EfiPciIoWidthUint32, Addr, 1, &v);
}

/* ==== Multi-root-bridge support ====
 * On real HW bus 0 (home of the GPU's upstream bridge) may belong to a
 * DIFFERENT root bridge than the card's own bus; probing only gRb made
 * the bridge invisible. rb_collect() gathers up to 8 RBs; reads try
 * each until one answers non-0xFFFFFFFF, writes go to the RB index
 * recorded at discovery (a write through the wrong RB can alias
 * another device!).
 * На реальном HW шина 0 (апстрим-бридж GPU) может принадлежать ДРУГОМУ
 * RB, чем шина карты. v2.99l на реальном железе бридж не нашёлся именно
 * поэтому — find_bridge_to ходил только через gRb. */
#define V2100_RB_MAX 8
static EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *gRbAll[V2100_RB_MAX];
static UINTN gRbAllN = 0;
static INTN  gBrIdx = -1;   /* индекс RB, отвечающего за шину бриджа */

static void
rb_collect(void)
{
    EFI_HANDLE *H = NULL;
    UINTN N = 0, i;
    if (gRbAllN) return;
    if (EFI_ERROR(uefi_call_wrapper(BS->LocateHandleBuffer, 5, ByProtocol,
            &gEfiPciRootBridgeIoProtocolGuid, NULL, &N, &H)))
        return;
    for (i = 0; i < N && gRbAllN < V2100_RB_MAX; i++) {
        EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *rb = NULL;
        if (!EFI_ERROR(uefi_call_wrapper(BS->HandleProtocol, 3, H[i],
                &gEfiPciRootBridgeIoProtocolGuid, (VOID**)&rb)) && rb)
            gRbAll[gRbAllN++] = rb;
    }
}

/* чтение через первый RB, который отвечает НЕ FFFFFFFF без ошибки */
static UINT32
pci_cfg_rd_any(UINTN bus, UINTN dev, UINTN fn, UINTN Reg)
{
    UINTN i;
    for (i = 0; i < gRbAllN; i++) {
        UINT64 Addr = ((UINT64)bus << 20) | ((UINT64)dev << 15) |
                      ((UINT64)fn << 12) | ((UINT64)Reg & 0xFFF);
        UINT32 val = 0xFFFFFFFFU;
        if (!EFI_ERROR(uefi_call_wrapper(gRbAll[i]->Pci.Read, 5, gRbAll[i],
                EfiPciIoWidthUint32, Addr, 1, &val)) && val != 0xFFFFFFFFU)
            return val;
    }
    return 0xFFFFFFFFU;
}

/* запись по ЗАРАНЕЕ найденному индексу RB (не «первому отвечающему» —
 * запись через чужой RB может алиаситься на другое устройство!) */
static BOOLEAN
pci_cfg_wr_idx(INTN idx, UINTN bus, UINTN dev, UINTN fn, UINTN Reg, UINT32 v)
{
    UINT64 Addr;
    if (idx < 0 || (UINTN)idx >= gRbAllN) return FALSE;
    Addr = ((UINT64)bus << 20) | ((UINT64)dev << 15) |
           ((UINT64)fn << 12) | ((UINT64)Reg & 0xFFF);
    return !EFI_ERROR(uefi_call_wrapper(gRbAll[idx]->Pci.Write, 5, gRbAll[idx],
        EfiPciIoWidthUint32, Addr, 1, &v));
}

static UINT32
pci_cfg_rd_idx(INTN idx, UINTN bus, UINTN dev, UINTN fn, UINTN Reg)
{
    UINT64 Addr;
    if (idx < 0 || (UINTN)idx >= gRbAllN) return 0xFFFFFFFFU;
    Addr = ((UINT64)bus << 20) | ((UINT64)dev << 15) |
           ((UINT64)fn << 12) | ((UINT64)Reg & 0xFFF);
    {
        UINT32 val = 0xFFFFFFFFU;
        if (EFI_ERROR(uefi_call_wrapper(gRbAll[idx]->Pci.Read, 5, gRbAll[idx],
                EfiPciIoWidthUint32, Addr, 1, &val)))
            return 0xFFFFFFFFU;
        return val;
    }
}

/* найти PCI Express Capability (ID 0x10) у устройства; 0 = нет */
static UINTN
find_pcie_cap(UINTN bus, UINTN dev, UINTN fn)
{
    UINTN pos, guard = 0;
    if (pci_cfg_rd_bdf(bus, dev, fn, 0x00) == 0xFFFFFFFFU)
        return 0;
    /* Capabilities Pointer лежит по ФИКСИРОВАННОМУ адресу 0x34 (стандартный
     * PCI header) и НЕ входит в dword по 0x04 — там Command (0x04-05) и
     * Status (0x06-07).
     *
     * ОШИБКА, БЫВШАЯ ДО 2026-10-10. Здесь стояло:
     *   «v2.99i FIX: CapPtr — байт 0x07 (старший байт dword@0x04);
     *    раньше брали >>8 (байт 0x05) и всегда промахивались»
     * и pos = (rd(0x04) >> 24) & 0xFF. Байт 0x07 — старший байт STATUS,
     * он по спецификации всегда ноль, поэтому обход цепочки не мог
     * начаться НИКОГДА. «v2.99i FIX» чинил один сдвиг на другой внутри
     * неверной посылки, поэтому мимо.
     *
     * Подтверждено замером из Windows через WinRing0 (2026-10-10,
     * docs/70HX-XP3G-GATE-V67.md §4a.11.8):
     *   GPU 01:00.0  CapPtr=0x60
     *     0x60 PM -> 0x68 MSI -> 0x78 PCIe -> 0xB4 Vendor -> 0x00
     *   bridge 00:1b.0  CapPtr=0x40  -> 0x40 PCIe -> 0x80 MSI -> ...
     * Побочный эффект бага — «CapPtr=0» в E-D и «pcie_cap not found» во
     * всех шести прогонах GEN2C: это был он, а не свойство карты. */
    pos = pci_cfg_rd_bdf(bus, dev, fn, 0x34) & 0xFF;
    while (pos >= 0x40 && guard++ < 48) {
        UINT32 cdw = pci_cfg_rd_bdf(bus, dev, fn, pos & ~3U);
        UINTN off = pos & 3;
        UINTN id = (cdw >> (off * 8)) & 0xFF;
        UINTN next = (cdw >> (off * 8 + 8)) & 0xFF;
        if (id == 0x10) return pos;
        pos = next;
    }
    return 0;
}

/* найти мост, чья secondary bus == target_bus (для апстрима GPU).
 * v2.100: сканируем ВСЕ root bridges — на реальном HW шина 0 может жить
 * в другом RB, чем шина GPU (v2.99l: «бридж не нашёлся»). Индекс RB,
 * через который найден бридж, сохраняется в gBrIdx для записей phase3. */
static BOOLEAN
find_bridge_to(UINTN target_bus, UINTN *ob, UINTN *od, UINTN *of)
{
    static const struct { UINTN d, f; } cand[] = {
        {1,0}, {28,0}, {28,1}, {28,2}, {28,3},
        {28,4}, {28,5}, {28,6}, {28,7}, {2,0}, {3,0}
    };
    UINTN ri, ci, b, d, f;
    rb_collect();
    if (!gRbAllN) {
        Print(L"gen2: нет ни одного root bridge!\n");
        return FALSE;
    }
    Print(L"gen2: probe 00:01.0=%08x 00:1c.0=%08x (%d RB)\n",
          pci_cfg_rd_any(0, 1, 0, 0x00), pci_cfg_rd_any(0, 28, 0, 0x00),
          (INTN)gRbAllN);
    /* быстрые кандидаты (q35 root port 00:01.0, PCH 00:1c.x) на bus 0 */
    for (ri = 0; ri < gRbAllN; ri++)
        for (ci = 0; ci < sizeof(cand)/sizeof(cand[0]); ci++) {
            UINT64 A = ((UINT64)cand[ci].d << 15) | ((UINT64)cand[ci].f << 12);
            UINT32 dv = 0xFFFFFFFFU, ht = 0xFFFFFFFFU, br = 0xFFFFFFFFU;
            if (EFI_ERROR(uefi_call_wrapper(gRbAll[ri]->Pci.Read, 5, gRbAll[ri],
                    EfiPciIoWidthUint32, A, 1, &dv)) || dv == 0xFFFFFFFFU || dv == 0)
                continue;
            if (EFI_ERROR(uefi_call_wrapper(gRbAll[ri]->Pci.Read, 5, gRbAll[ri],
                    EfiPciIoWidthUint32, A | 0x0C, 1, &ht)) ||
                ((ht >> 16) & 0x7F) != 1)
                continue;                       /* header type 1 = мост */
            if (EFI_ERROR(uefi_call_wrapper(gRbAll[ri]->Pci.Read, 5, gRbAll[ri],
                    EfiPciIoWidthUint32, A | 0x18, 1, &br)) ||
                ((br >> 16) & 0xFF) != target_bus)
                continue;
            *ob = 0; *od = cand[ci].d; *of = cand[ci].f;
            gBrIdx = (INTN)ri;
            return TRUE;
        }
    /* полный скан по каждому RB */
    for (ri = 0; ri < gRbAllN; ri++)
        for (b = 0; b < 256; b++)
            for (d = 0; d < 32; d++)
                for (f = 0; f < 8; f++) {
                    UINT64 A = ((UINT64)b << 20) | ((UINT64)d << 15) |
                               ((UINT64)f << 12);
                    UINT32 dv = 0xFFFFFFFFU, ht = 0xFFFFFFFFU, br = 0xFFFFFFFFU;
                    if (EFI_ERROR(uefi_call_wrapper(gRbAll[ri]->Pci.Read, 5,
                            gRbAll[ri], EfiPciIoWidthUint32, A, 1, &dv)) ||
                        dv == 0xFFFFFFFFU || dv == 0)
                        continue;
                    if (EFI_ERROR(uefi_call_wrapper(gRbAll[ri]->Pci.Read, 5,
                            gRbAll[ri], EfiPciIoWidthUint32, A | 0x0C, 1, &ht)) ||
                        ((ht >> 16) & 0x7F) != 1)
                        continue;
                    if (EFI_ERROR(uefi_call_wrapper(gRbAll[ri]->Pci.Read, 5,
                            gRbAll[ri], EfiPciIoWidthUint32, A | 0x18, 1, &br)) ||
                        ((br >> 16) & 0xFF) != target_bus)
                        continue;
                    *ob = b; *od = d; *of = f;
                    gBrIdx = (INTN)ri;
                    return TRUE;
                }
    return FALSE;
}

/* Выделение страниц ниже 4ГБ для DMA.
 * ВАЖНО: для AllocateMaxAddress входное значение *Phys = МАКСИМАЛЬНЫЙ адрес,
 * иначе (0) → EFI_OUT_OF_RESOURCES.
 *
 * ПОРТ: на этой плате первый же запрос (max=0xFFFFFFFF) зависал — процесс
 * доходил до "alloc meta" и дальше не печатал ничего. Поэтому пробуем
 * несколько верхних границ по убыванию и ВСЕГДА печатаем результат: без
 * этого невозможно отличить зависание AllocatePages от тихого отказа. */
static EFI_STATUS
alloc_below_4g(UINTN Pages, EFI_PHYSICAL_ADDRESS *Phys)
{
    static const UINT64 maxes[] = {
        0xFFFFFFFFULL, 0xC0000000ULL, 0xA0000000ULL,
        0x80000000ULL, 0x60000000ULL, 0x40000000ULL,
    };
    UINTN i;
    EFI_STATUS last = EFI_OUT_OF_RESOURCES;

    for (i = 0; i < sizeof(maxes)/sizeof(maxes[0]); i++) {
        *Phys = maxes[i];
        last = uefi_call_wrapper(BS->AllocatePages, 4, AllocateMaxAddress,
                                 EfiReservedMemoryType, Pages, Phys);
        if (!EFI_ERROR(last)) {
            Print(L"alloc<4G: OK @0x%lx (max=0x%llx)\n", *Phys, maxes[i]);
            return EFI_SUCCESS;
        }
        Print(L"alloc<4G: max=0x%llx → %r\n", maxes[i], last);
    }
    return last;
}

/* v2.62 ставил буферы выше 4ГБ (драйвер грузит с 0x110BB0000). На 70HX
 * это оказалось нерабочим: адрес используется ОДНОВРЕМЕННО как виртуальный
 * (CopyMem образа) и как физический (DMA GSP), а выше 4ГБ прошивка не
 * отображает память тождественно. Доказательство из лога:
 *     blobIMEM0=0xEC547D23  bufIMEM0=0x00000001
 *     phys=0x113025000
 * То есть CPU писал в одну страницу, а GSP читал другую — образ физически
 * НЕ попадал в буфер, и FWSEC стартовал с мусором (dbg=0x780009).
 *
 * Ниже 4ГБ VA==PA по определению, поэтому для буферов, которые CPU
 * заполняет, а DMA читает, адрес должен быть ниже 4ГБ. */
static UINT64 cmp90_next_high_slot = 0x110000000ULL;   /* v2.63: след. своб. слот */
static EFI_STATUS
alloc_fwsec_buffer(UINTN Pages, EFI_PHYSICAL_ADDRESS *Phys)
{
    /* v2.63: ДИНАМИЧЕСКИЕ слоты — каждый вызов получает СВОЙ адрес
     * (шаг 16МБ), чтобы ВСЕ SEC-буферы (fwsec/v67/ucode/bl/wprmeta)
     * разместились выше 4ГБ. На залоченной карте ботер сам читает
     * WPR meta/V67 из sysmem — из <4ГБ чтение блокировано (exit 0x91)! */
    EFI_STATUS st;
    UINTN i;
    for (i = 0; i < 12; i++) {
        *Phys = cmp90_next_high_slot + i * 0x1000000ULL;
        st = uefi_call_wrapper(BS->AllocatePages, 4, AllocateAddress,
                               EfiReservedMemoryType, Pages, Phys);
        if (!EFI_ERROR(st)) {
            cmp90_next_high_slot = *Phys + ((UINT64)Pages << 12) + 0x1000000ULL;
            Print(L"alloc_high: OK @0x%lx (%d стр)\n", *Phys, (UINT32)Pages);
            return EFI_SUCCESS;
        }
    }
    {
        static const UINT64 cand[] = {
            0x1A0000000ULL, 0x1C0000000ULL, 0x1E0000000ULL,
        };
        for (i = 0; i < sizeof(cand)/sizeof(cand[0]); i++) {
            *Phys = cand[i];
            if (!EFI_ERROR(uefi_call_wrapper(BS->AllocatePages, 4, AllocateAddress,
                                             EfiReservedMemoryType, Pages, Phys))) {
                Print(L"alloc_high: OK (статик) @0x%lx\n", *Phys);
                return EFI_SUCCESS;
            }
        }
    }
    Print(L"alloc_high: выше 4ГБ не вышло — фолбэк ниже 4ГБ\n");
    return alloc_below_4g(Pages, Phys);
}

/* Включить MEM_EN + BUS_MASTER в command-регистре GPU.
 * У устройства без UEFI-драйвера (нет GOP) прошивка может оставить
 * command=0 → все MMIO-чтения BAR0 возвращают 0xFFFFFFFF. */
static void
enable_mem_decode(void)
{
    UINT32 cmd = cfg_read32(0x04);
    Print(L"cfg 0x04 (command) до  = 0x%08x\n", cmd);
    cfg_write32(0x04, cmd | 0x6);   /* bit1=Memory Space, bit2=Bus Master */
    cmd = cfg_read32(0x04);
    Print(L"cfg 0x04 (command) после = 0x%08x\n", cmd);
}

/* ==== Quick state snapshot + "already unlocked" check ==== */
static void
dump_regs(const CHAR16 *Tag)
{
    Print(L"%s: PLM=0x%08x SS0=0x%08x SS1=0x%08x GFW=0x%08x WPR2lo=0x%08x\n",
        Tag,
        mmio_read32(REG_FEAT_OVR_PLM),
        mmio_read32(REG_FEAT_OVR_SM_SPD),
        mmio_read32(REG_FEAT_OVR_SM_SPD_1),
        mmio_read32(REG_GFW_BOOT_OK),
        mmio_read32(REG_PFB_MMU_WPR2_LO));
}

/* Снимок ключевых регистров ДО FLR. После FLR функция мертва и MMIO
 * отдаёт мусор, поэтому сводку в конце печатаем из этого снимка, а не
 * живым чтением. */
static BOOLEAN g_snapOk = FALSE;
static UINT32  g_snapPlm, g_snapSs0, g_snapSs1, g_snapWLo, g_snapWHi,
                g_snapDbg, g_snapCpu, g_snapSc0;
/* v3.45: GFX_SPEED_SELECT в снимке. Без него вердикт на экране после FLR
 * не мог сказать ничего о графике: MMIO там уже мёртв, живут только g_snap*.
 * Само значение и признак «селектор встал» вычисляет gen2_gfx_try() и кладёт
 * в g_gfxVal / g_gfxOk, потому что он умеет проверять и ORDER B. */
static UINT32  g_snapGfx;
static UINT32  g_gfxVal = 0xFFFFFFFFU;   /* фактическое readback */

/* v3.51: ОЖИДАЕМЫЙ WPR2_LO, КОТОРЫЙ ПОСТАВИТ GSP - ИЗ НАШЕЙ ЖЕ МЕТЫ.
 *
 * WPR2 имеет ДВА законных значения, и до v3.51 их путали:
 *   TARGET_WPR2_LO/HI = FRTS>>8 … +0xE00   - окно FRTS, пишем МЫ;
 *   g_expGspWprLo                            - окно GSP, ставит САМ GSP.
 *
 * GSP берёт нижнюю границу из поля gspFwWprStart нашей мета-структуры
 * (gspFwWprStart = gspFwHeapOffset − 1 МБ, см. заполнение меты). Проверено
 * на прогоне 1004-171751: heapOff=0x1EAE00000 -> wprStart=0x1EAD00000 ->
 * WPR2_LO=0x01EAD000, что и наблюдалось, до единицы.
 *
 * Верхняя граница окна GSP эмпирически равна TARGET_WPR2_HI; её вывод внутри
 * GSP не установлен, и он не нужен: для записи в FRTS важно лишь, чтобы окно
 * СОДЕРЖАЛО окно FRTS, а не совпадало с ним.
 *
 * Зачем это отдельное значение: строка 'WPR2=… *** UNEXPECTED ***' вводила в
 * заблуждение шесть дней подряд, потому что сравнивала два разных числа и
 * ничего не сообщала о том, каким должно быть второе. */
static UINT32  g_expGspWprLo = 0;
/* v3.52: геометрия окна печатается ОДИН раз за прогон.
 *
 * Промежуточная проверка в v3.51 печатала её из cmp90_meta_low(), который
 * вызывается 16 раз за прогон, - и строка вышла 32 раза, раздув дамп кольца.
 * Значение одно, печать и нужна одна. Проверка же САМОЙ меты в
 * cmp90_meta_low() остаётся на каждом вызове: она по-прежнему проверяет
 * копию, просто подробная строка печатается при первом успехе, а при любой
 * неудаче - всегда. */
static BOOLEAN g_metaGeomPrinted = FALSE;
static BOOLEAN g_metaLowPrinted = FALSE;
static BOOLEAN g_gfxOk  = FALSE;          /* 0x4 реально залип */

static void
snapshot_state(void)
{
    g_snapPlm = mmio_read32(0x00823804U);
    g_snapSs0 = mmio_read32(REG_FEAT_OVR_SM_SPD);
    g_snapSs1 = mmio_read32(REG_FEAT_OVR_SM_SPD_1);
    g_snapWLo = mmio_read32(REG_PFB_MMU_WPR2_LO);
    g_snapWHi = mmio_read32(REG_PFB_MMU_WPR2_HI);
    g_snapDbg = mmio_read32(GSP_BASE + 0x94);
    g_snapCpu = mmio_read32(GSP_CPUCTL);
    g_snapSc0 = mmio_read32(0x001438);
    /* Рендер-снимок НЕ перезаписывает g_gfxVal: если gen2_gfx_try() не
     * дошёл (анлок раннего пути не прошёл), вердикт должен показать то, что
     * регистр содержал на самом деле, а не затирать его «неизвестно».
     *
     * ВНИМАНИЕ, ПОРЯДОК ВЫЗОВОВ (v3.46): этот снимок делается ДО
     * gen2_gfx_try(), то есть ДО записи GFX_SPEED_SELECT. Поэтому значение
     * здесь — «как было», а не «как стало». Актуальное «как стало»
     * приходит из gen2_gfx_try(), который кладёт проверенный результат и в
     * g_gfxVal, и в g_snapGfx. На первом прогоне с баннером это не было
     * учтено, и вердикт напечатал 0x00000000 при вставшем 0x4. */
    g_snapGfx = g_gfxOk ? g_gfxVal : mmio_read32(0x00823830U);
    g_snapOk  = TRUE;
}

static BOOLEAN
is_unlocked(void)
{
    return (mmio_read32(REG_FEAT_OVR_SM_SPD) == VAL_SS0_UNLOCKED &&
            mmio_read32(REG_FEAT_OVR_SM_SPD_1) == VAL_SS1_UNLOCKED);
}

/* ==== ВЕРДИКТ ДЛЯ ЧЕЛОВЕКА (v3.45) ====
 *
 * ЧТО ЭТО ДЕЛАЕТ. Даёт один-единственный ответ о том, что реально получилось,
 * и показывает его на экране в рамке — последним, что человек видит перед
 * возвратом в прошивку. Отдельная строка со значениями идёт под вердиктом
 * всегда, потому что вердикт без чисел невозможно оспорить: видно, ИМЕННО
 * что не сошлось.
 *
 * ПОЧЕМУ ЧЕТЫРЕ СОСТОЯНИЯ, А НЕ ДВА. Пользователь различает «compute + render»
 * и «только compute». Третье состояние теоретически невозможно: ORDER A пишет
 * GFX_SPEED_SELECT после SS0/SS1, то есть селектор зависит от compute. Но если
 * оно всё-таки случится, это факт о железе, и молчать о нём нельзя.
 *
 * ПОЧЕМУ ТОЛЬКО ASCII. ulogf переводит всё вне 0x20..0x7E в '?', поэтому
 * кириллица в логе нечитаема. На экране UTF-16 и она безопасна, но тогда текст
 * на экране и в логе будет разным, а лог читают как эталон. Одна ASCII-строка
 * в обоих местах — единственный способ исключить расхождение.
 *
 * ПОЧЕМУ ЗНАЧЕНИЯ ИЗ СНИМКА, А НЕ ЖИВЫМ ЧТЕНИЕМ. Баннер печатается после
 * done:, то есть в том числе после do_flr(), где MMIO мёртв и отдаёт мусор.
 * Единственный честный источник — g_snap*, снятый до FLR. */
#define VERDICT_RULE       L"----------------------------------------------------------------------"

/* Значение селектора графики, которое мы пишем.
 *
 * Перенесено из селекторного блока (было около строки 4891) сюда, потому
 * что вердикт ниже обязан сверяться с тем, что реально записывается, а не
 * с константой 0x4, объявленной ниже по файлу. Это третий и последний
 * случай того же дефекта; см. комментарий у unlock_verdict_text().
 *
 * При значении по умолчании машинный код идентичен прежнему.
 *
 * ШИРИНА ПОЛЯ ТЕПЕРЬ ИЗМЕРЕНА (закрыто 2026-10, шаг B), проверка возвращена
 * к 0x7.
 *
 * Хронология, потому что это и есть содержание ширины поля.
 *
 * Изначально здесь стоял отказ собирать вне 0x0..0x7, и обоснованием было
 * «поле трёхбитное». Это утверждение было написано мной же и ни разу не
 * сверялось с железом: видеть восемь значений в переборе не значит проверить
 * границу. Тот же класс ошибки проект ловил уже дважды -- «поле трёхбитное»
 * звучало как измерение, но было экстраполяцией из перебора, а «стоковое 0x3»
 * оказалось не в том регистре.
 *
 * Поэтому перед прогоном 0x8 верхняя граница проверки была поднята до 0xFF.
 * Это было СПЕЦИАЛЬНО разрешающим проверку, а не утверждением ширины: шаг B
 * должен был записать 0x8 и посмотреть, что вернёт readback.
 *
 * Шаг B выполнен (gfxsel_0x8_oracle, 659c03b8...): железо отмаскировало 0x8
 * в 0x0, то есть бит 3 не записываем, и при обычном маскировании биты 4-7
 * тоже не записываемы. Поле физически трёхбитное, лестница 0x0..0x7 закрыта
 * измерением, и проверка возвращена к 0x7.
 *
 * Отличать «поле трёхбитное» от «железо замаскировало это значение» без
 * прогона нельзя, поэтому проверку ослабляли только на время прогона. */
#ifndef GFX_SPEED_SEL_VALUE
# define GFX_SPEED_SEL_VALUE 0x00000004U
#endif
#if (GFX_SPEED_SEL_VALUE & ~0x7U) != 0
# error "GFX_SPEED_SEL_VALUE: поле трёхбитное, допустимы 0x0..0x7"
#endif

static const CHAR16 *
unlock_verdict_text(UINT32 ss0, UINT32 ss1, UINT32 gfx)
{
    BOOLEAN c = (ss0 == VAL_SS0_UNLOCKED && ss1 == VAL_SS1_UNLOCKED);
    /* Сверяемся с ЗАПИСАННЫМ значением, а не с константой 0x4.
     *
     * Третье место с тем же дефектом, что и порядок A/B (часть 6 §2).
     * На прогоне gfxsel0x6_oracle баннер печатал
     *   VRC : COMPUTE ONLY (render not unlocked)
     * при CAND-ID = 2, то есть рендер частично встал и игра даёт 16 fps,
     * а не базовые 9. Баннер врал, и врал тем хуже, что его читает
     * человек и принимает на веру - это ведь единственное место, где
     * вывод сведён к одному решению.
     *
     * Про релизную линию: у неё GFX_SPEED_SEL_VALUE всегда 0x4, поэтому
     * сравнение с константой и со значением дают РОВНО тот же результат.
     * Правка делает честными экспериментальные сборки и не меняет
     * ничего в релизной. */
    BOOLEAN r = (gfx == GFX_SPEED_SEL_VALUE);
    if (c && r) return L"UNLOCKED (compute + render)";
    if (c && !r) return L"COMPUTE ONLY (render not unlocked)";
    if (!c && r) return L"RENDER ONLY (compute not unlocked)";
    return L"NOT UNLOCKED";
}

/* Определение unlock_verdict_banner() намеренно живёт НЕ здесь, а после
 * блока логирования: ему нужны LOG_LBA/LOG_SECTORS и ulogf(), а они
 * объявлены ниже по файлу. Здесь только прототип, чтобы порядок вызовов в
 * efi_main не зависел от расположения определения. */
static void unlock_verdict_banner(void);

/* ==== Read-only diagnostics dump (dev builds pause between sections) ====
 * Never touches file protocols here (they hang some AMI firmwares);
 * RELEASE_BUILD/EFI_AUTOTEST compile out the key waits:
 * БЕЗ файлового протокола (висит на любых прошивках с этой флешкой).
 * Только чтения, поэтапно; между секциями — ожидание клавиши. */
static void
pause_screen(EFI_SYSTEM_TABLE *ST)
{
#if defined(EFI_AUTOTEST) || defined(RELEASE_BUILD)
    Print(L"[паузы отключены]\n");
#else
    Print(L"\n[Enter] — дальше...\n");
    uefi_call_wrapper(ST->ConIn->Reset, 2, ST->ConIn, FALSE);
    WaitForSingleEvent(ST->ConIn->WaitForKey, 0);
    uefi_call_wrapper(ST->ConIn->Reset, 2, ST->ConIn, FALSE);
#endif
}

static void
diag_one(const CHAR16 *name, UINT32 addr)
{
    UINT32 v;
    Print(L"rd %s (0x%08x)...", name, addr);
    v = mmio_read32(addr);
    Print(L" = 0x%08x\n", v);
}

static void
diag_regs(EFI_SYSTEM_TABLE *ST)
{
    Print(L"\n--- DIAG v2.10 SEC2 ---\n");
    diag_one(L"SEC2_MBOX0", 0x840040);
    diag_one(L"SEC2_MBOX1", 0x840044);
    diag_one(L"SEC2_IRQSTAT", 0x840008);
    diag_one(L"SEC2_DEBUGINFO", 0x840094);
    diag_one(L"SEC2_CPUCTL", 0x840100);
    diag_one(L"SEC2_DMACTL", 0x84010c);
    diag_one(L"SEC2_DMATRFCMD", 0x840118);
    diag_one(L"SEC2_ENGINE", 0x8403c0);
    diag_one(L"SEC2_FBIF_CTL", 0x840624);
    pause_screen(ST);

    Print(L"--- DIAG v2.10 GSP (только чтения) ---\n");
    diag_one(L"GSP_MBOX0", 0x110040);
    diag_one(L"GSP_MBOX1", 0x110044);
    diag_one(L"GSP_CPUCTL", 0x110100);
    diag_one(L"GSP_ENGINE", 0x1103c0);
    diag_one(L"PGSP_MAILBOX", 0x110804);
    diag_one(L"GSP_0x110c38", 0x110c38);
    diag_one(L"GSP_0x110c3c", 0x110c3c);
    diag_one(L"PTIMER0", 0x9400);
    diag_one(L"PLM", REG_FEAT_OVR_PLM);
    diag_one(L"SS0", REG_FEAT_OVR_SM_SPD);
    diag_one(L"SS1", REG_FEAT_OVR_SM_SPD_1);
    diag_one(L"GFW", REG_GFW_BOOT_OK);
    Print(L"--- DIAG v2.10 ЗАВЕРШЕНА ---\n");
    pause_screen(ST);
}

static BOOLEAN cmp90_eqi(const CHAR16 *a, const CHAR16 *b);

#ifdef ENDGAME_WARMRESET
/* v2.90-WR: найти Boot#### с описанием "Windows Boot Manager" и выставить
 * BootNext. TRUE = переменная записана (далее ResetSystem Warm). */
static BOOLEAN set_bootnext_windows(void)
{
    static EFI_GUID gvGuid = EFI_GLOBAL_VARIABLE;
    UINT16 opt;

    Print(L"v2.90-WR: скан Boot#### (Windows Boot Manager)...\n");
    for (opt = 0; opt < 0xFFFF; opt++) {
        CHAR16 name[12];
        static UINT8 buf[2048];
        UINTN sz = sizeof(buf);
        UINT32 attr = 0;
        EFI_STATUS st;

        UnicodeSPrint(name, sizeof(name), L"Boot%04X", opt);
        st = uefi_call_wrapper(RT->GetVariable, 5, name, &gvGuid,
                               &attr, &sz, buf);
        /* v2.99o: прогресс каждые 256 слотов — видно, где застряли */
        if ((opt & 0xFF) == 0)
            Print(L"v2.90-WR: скан %04X...\n", opt);
        if (EFI_ERROR(st) || sz < 6) continue;
        {
            /* EFI_LOAD_OPTION: u32 Attributes, u16 FilePathListLength,
             * Description (CHAR16, NUL-терминированная) */
            CHAR16 *desc = (CHAR16 *)(buf + 6);
            if (cmp90_eqi(desc, L"Windows Boot Manager")) {
                Print(L"v2.90-WR: найден Boot%04X, пишу BootNext...\n", opt);
                st = uefi_call_wrapper(RT->SetVariable, 6, L"BootNext", &gvGuid,
                    EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |
                    EFI_VARIABLE_RUNTIME_ACCESS, 2, &opt);
                Print(L"v2.90-WR: Boot%04X = Windows Boot Manager; BootNext: %r\n",
                      opt, st);
                return !EFI_ERROR(st);
            }
        }
    }
    Print(L"v2.90-WR: Boot#### с Windows Boot Manager не найден\n");
    return FALSE;
}
#endif

/* ==== MULTI-CARD: unlock several 220d cards without rebooting ====
 * Each app run unlocks ITS card (index in an NVRAM variable), sets
 * BootNext to its own Boot#### entry and returns to firmware — no POST
 * happens, the unlock survives, firmware re-runs us from USB for the
 * next card. Last iteration clears variables and lets Windows boot.
 * Scans every root bridge / bus 0..255 so slot width does not matter.
 * Каждая итерация приложения анлочит СВОЮ карту (индекс в NVRAM), затем
 * BootNext -> собственная Boot####-запись -> возврат в прошивку БЕЗ
 * перезагрузки (POST не происходит, анлок живёт) -> прошивка снова запускает
 * нас с флешки за следующей картой. Последняя итерация чистит переменные и
 * chainload'ит Windows как обычно. Работает через любые линии (x16/x4/x1),
 * т.к. скан обходит ВСЕ root bridge'и и шины 0..255. */
#ifdef MULTI_CARD
#define MC_MAX_CARDS 16
typedef struct {
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *rb;
    UINTN bus, dev, fn;
} MC_CARD;
static MC_CARD g_mcCards[MC_MAX_CARDS];
static UINTN g_mcCount = 0;
static UINTN g_mcIndex = 0;
static BOOLEAN g_mcAdvance = FALSE;   /* после этой карты есть ещё */
static EFI_GUID mcGuid =
    {0x9a3b7c41,0x2e5d,0x4f68,{0xa1,0xb2,0xc3,0xd4,0xe5,0xf6,0x17,0x28}};

static VOID mc_var_set(CHAR16 *name, UINT32 val)
{
    uefi_call_wrapper(RT->SetVariable, 6, name, &mcGuid,
        EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS,
        4, &val);
}

static UINT32 mc_var_get(CHAR16 *name, BOOLEAN *ok)
{
    UINT32 v = 0;
    UINTN sz = sizeof(v);
    UINT32 attr = 0;
    EFI_STATUS st = uefi_call_wrapper(RT->GetVariable, 5, name, &mcGuid,
                                      &attr, &sz, &v);
    if (ok) *ok = (!EFI_ERROR(st) && sz == sizeof(v));
    return v;
}

static VOID mc_vars_clear(void)
{
    uefi_call_wrapper(RT->SetVariable, 6, L"CMP90IDX", &mcGuid, 0, 0, NULL);
    uefi_call_wrapper(RT->SetVariable, 6, L"CMP90CNT", &mcGuid, 0, 0, NULL);
}

/* Как find_cmp90hx, но собирает ВСЕ целевые карты (без раннего выхода) */
static void
find_all_cmp90hx(void)
{
    EFI_HANDLE *RbHandles = NULL;
    UINTN RbCount = 0, i;

    if (EFI_ERROR(uefi_call_wrapper(BS->LocateHandleBuffer, 5, ByProtocol,
            &gEfiPciRootBridgeIoProtocolGuid, NULL, &RbCount, &RbHandles)))
        return;

    for (i = 0; i < RbCount && g_mcCount < MC_MAX_CARDS; i++) {
        EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *rb = NULL;
        UINTN Bus, Dev, Fn;

        if (EFI_ERROR(uefi_call_wrapper(BS->HandleProtocol, 3, RbHandles[i],
                &gEfiPciRootBridgeIoProtocolGuid, (VOID**)&rb))) continue;

        for (Bus = 0; Bus <= 255 && g_mcCount < MC_MAX_CARDS; Bus++) {
            UINT32 Id = 0;
            UINT64 A0 = ((UINT64)Bus << 20);

            if (EFI_ERROR(uefi_call_wrapper(rb->Pci.Read, 5, rb,
                    EfiPciIoWidthUint32, A0, 1, &Id)) || Id == 0xFFFFFFFF)
                continue;

            for (Dev = 0; Dev < 32 && g_mcCount < MC_MAX_CARDS; Dev++) {
                UINTN MaxFn = 1;
                UINT32 Hdr = 0;
                UINT64 AD = ((UINT64)Bus << 20) | ((UINT64)Dev << 15);

                if (EFI_ERROR(uefi_call_wrapper(rb->Pci.Read, 5, rb,
                        EfiPciIoWidthUint32, AD, 1, &Id)) || Id == 0xFFFFFFFF)
                    continue;
                if (!EFI_ERROR(uefi_call_wrapper(rb->Pci.Read, 5, rb,
                        EfiPciIoWidthUint32, AD | 0x0C, 1, &Hdr)) && (Hdr & 0x80))
                    MaxFn = 8;

                for (Fn = 0; Fn < MaxFn && g_mcCount < MC_MAX_CARDS; Fn++) {
                    UINT64 AF = AD | ((UINT64)Fn << 12);
                    if (EFI_ERROR(uefi_call_wrapper(rb->Pci.Read, 5, rb,
                            EfiPciIoWidthUint32, AF, 1, &Id)) ||
                        Id == 0xFFFFFFFF) continue;
                    if (is_target_gpu(Id)) {
                        g_mcCards[g_mcCount].rb  = rb;
                        g_mcCards[g_mcCount].bus = Bus;
                        g_mcCards[g_mcCount].dev = Dev;
                        g_mcCards[g_mcCount].fn  = Fn;
                        /* печатаем КАЖДУЮ найденную карту: если их больше,
                         * чем ожидал пользователь, адреса видны сразу */
                        Print(L"PCI: карта #%d = 10de:%04X bus=%d dev=%d fn=%d (root bridge #%d)\n",
                              (INTN)g_mcCount, (INTN)((Id >> 16) & 0xFFFF),
                              (INTN)Bus, (INTN)Dev, (INTN)Fn, (INTN)i);
                        g_mcCount++;
                        ulogf(L"FIND  target 10de:%04x bus=%d dev=%d fn=%d rb=%d card#%d "
                             "fb=0x%llx frts=0x%llx wpr2=0x%08x/0x%08x\n",
                             (INTN)((Id >> 16) & 0xFFFF), (INTN)Bus, (INTN)Dev,
                             (INTN)Fn, (INTN)i, (INTN)(g_mcCount - 1),
                             TARGET_FB_SIZE, TARGET_FRTS_OFFSET,
                             TARGET_WPR2_LO, TARGET_WPR2_HI);
                    } else if ((Id & 0xFFFF) == TARGET_PCI_VENDOR) {
                        Print(L"PCI: игнорирую 10de:%04X (bus=%d dev=%d fn=%d) — "
                              L"не %s\n",
                              (INTN)((Id >> 16) & 0xFFFF), (INTN)Bus, (INTN)Dev,
                              (INTN)Fn, TARGET_NAME);
                        /* в лог пишем ВСЕ карты NVIDIA — так проверяется,
                         * что выбрана именно CMP, а не GeForce с тем же ID */
                        ulogf(L"FIND  other 10de:%04x bus=%d dev=%d fn=%d\n",
                              (INTN)((Id >> 16) & 0xFFFF), (INTN)Bus,
                              (INTN)Dev, (INTN)Fn);
                    }
                }
            }
        }
    }
    FreePool(RbHandles);
    ulogf(L"FIND  total targets=%d (MC_MAX=%d)\n", (INTN)g_mcCount, (INTN)MC_MAX_CARDS);
}

/* v3n: путь C — читаем VROM (VBIOS) карты.
 *
 * Зачем: FWSEC читает данные из кадрового буфера, а писать в FB мы НЕ можем —
 * все BAR'ы слишком маленькие (см. BARSCN: максимум 64 МБ при 8 ГБ FB).
 * Прежде чем идти в копировальный движок, проверяем дешёвую гипотезу: может,
 * данные уже лежат в FB (их оставил VBIOS при POST), и проблема не в пустоте
 * региона, а в параметрах нашей FRTS-команды.
 *
 * VBIOS карты лежит в VROM-апертуре — отображённой памяти, которую можно
 * читать напрямую. Адрес берём из PCI-регистра 0x30 (Expansion ROM Base
 * Address, бит0=enable, адрес 1МБ-выровненный). Если он выключен — сканируем
 * BAR0 по сигнатуре option-ROM 55 AA.
 *
 * Печатаем первые 64 байта (там заголовок: сигнатура, длина, указатель на
 * инициализацию, строка "VBIOS") и CRC32 первых 4 КБ — по нему сверяем с
 * GA104.rom на хосте. */
static void
dump_vrom(void)
{
    static const UINT8 hex[] = "0123456789abcdef";
    UINT32 romBar = cfg_read32(0x30);
    UINT64 base = 0;
    volatile UINT8 *p;
    UINTN i, j;
    static UINT8 buf[4096];

    ulogf(L"VROM  expBAR(0x30)=0x%08x\n", romBar);
    if ((romBar & 1u) != 0)
        base = (UINT64)(romBar & ~0x3FFu);   /* 1 МБ alignment */

    if (base == 0) {
        /* сканируем BAR0 (16 МБ) по сигнатуре 55 AA шагом 4 КБ */
        for (i = 0; i < 0x1000000ULL; i += 0x1000ULL) {
            if (*(volatile UINT16 *)(UINTN)(gBar0Base + i) == 0xAA55u) {
                base = gBar0Base + i;
                break;
            }
        }
    }
    if (base == 0) {
        ulogf(L"VROM  not found (0x30 disabled, no 55 AA in BAR0)\n");
        return;
    }

    p = (volatile UINT8 *)(UINTN)base;
    ulogf(L"VROM  found @0x%llx\n", base);

    /* первые 16 байт: сигнатура 55 AA, длина, указатель инициализации */
    ulogf(L"VROM  hdr:");
    for (j = 0; j < 16; j++) {
        UINT8 v = p[j];
        ulogf(L" %c%c", hex[v >> 4], hex[v & 0xF]);
    }
    ulogf(L"\n");

    /* CRC32 первых 4 КБ — отпечаток для сверки с GA104.rom на хосте */
    for (i = 0; i < 4096; i++)
        buf[i] = p[i];
    ulogf(L"VROM  CRC32 first 4KB = 0x%08x (compare with GA104.rom)\n",
          crc32_upd(0xFFFFFFFFu, buf, 4096));
}

/* v3n: разведка всех шести BAR'ов карты.
 *
 * Зачем: FWSEC читает FRTS-регион из кадрового буфера, а мы его не заполняем
 * (FWSEC_FRTS_OFFSET в коде встречается только как число в дескрипторе
 * команды). Чтобы заполнить, нужно знать, отображён ли FB в CPU-адресное
 * пространство — и если да, то каким BAR'ом.
 *
 * Декодирование по спецификации PCI:
 *   bit0 = 0 → memory BAR, 1 → I/O BAR;
 *   bits1-2: 0 = 32-битный, 2 = 64-битный, 1 = зарезервирован;
 *   размер: записать 0xFFFFFFFF, прочитать обратно, замаскировать, восстановить.
 *
 * Запись 0xFFFFFFFF — штатная процедура определения размера BAR, она ничего
 * не ломает: значение сразу восстанавливается. BAR с orig==0 пропускаем
 * (не реализован). */
static void
scan_bars(const CHAR16 *tag)
{
    static const struct { UINTN reg; const CHAR16 *nm; } bars[] = {
        { 0x10, L"BAR0" }, { 0x14, L"BAR1" }, { 0x18, L"BAR2" },
        { 0x1C, L"BAR3" }, { 0x20, L"BAR4" }, { 0x24, L"BAR5" },
    };
    UINTN b;

    for (b = 0; b < sizeof(bars)/sizeof(bars[0]); b++) {
        UINTN reg = bars[b].reg;
        UINT32 orig = 0, probe = 0, origHi = 0, probeHi = 0;
        UINT64 size = 0;
        UINT32 type;

        if (EFI_ERROR(pci_cfg_read(reg, &orig)) || orig == 0) {
            ulogf(L"BARSCN %s %s=0 (not implemented)\n", tag, bars[b].nm);
            continue;
        }
        type = orig & 0xFU;
        if (type & 1U) {
            ulogf(L"BARSCN %s %s=0x%08x (I/O BAR, skipping)\n",
                  tag, bars[b].nm, orig);
            continue;
        }
        /* v3n: 64-битный BAR — это биты [2:1] = 10b, то есть (type & 0x6) == 0x4.
         * Проверка == 0x6 (оба бита) — зарезервированное значение, из-за неё
         * BAR1/BAR3 (0xF800000C, 0xFC00000C) уходили в отбраковку, а это как
         * раз апертуры кадрового буфера. */
        if ((type & 0x6U) == 0x4U) {
            /* 64-битный: старшая половина — следующий регистр */
            UINT32 origHi = 0, probeHi = 0;
            pci_cfg_read(reg + 4, &origHi);
            pci_cfg_write(reg, 0xFFFFFFFFU);
            pci_cfg_write(reg + 4, 0xFFFFFFFFU);
            pci_cfg_read(reg, &probe);
            pci_cfg_read(reg + 4, &probeHi);
            pci_cfg_write(reg + 4, origHi);
            pci_cfg_write(reg, orig);
            size = ~(((UINT64)probeHi << 32) | (UINT64)(probe & ~0xFU)) + 1ULL;
        } else if ((type & 0x6U) == 0x0U) {
            pci_cfg_write(reg, 0xFFFFFFFFU);
            pci_cfg_read(reg, &probe);
            pci_cfg_write(reg, orig);
            /* v3n: размер считается в 32-БИТНОЙ арифметике — иначе ~0xFF000000+1
             * даёт 0xFFFFFFFF01000000 вместо 0x01000000 (256 МБ) */
            size = (UINT64)(UINT32)(~(UINT32)(probe & ~0xFU) + 1U);
        } else {
            ulogf(L"BARSCN %s %s=0x%08x (type=%x - reserved)\n",
                  tag, bars[b].nm, orig, type);
            continue;
        }
        ulogf(L"BARSCN %s %s=0x%08x type=%x size=0x%llx%s\n",
              tag, bars[b].nm, orig, type, size,
              size >= 0x20000000ULL ? L"  <-- FB-APERTURE CANDIDATE" : L"");
    }
}

static BOOLEAN mc_pick(UINTN idx)
{
    if (idx >= g_mcCount) return FALSE;
    gRb  = g_mcCards[idx].rb;
    gBus = g_mcCards[idx].bus;
    gDev = g_mcCards[idx].dev;
    gFn  = g_mcCards[idx].fn;
    ulogf(L"PICK  card#%d of %d -> bus=%d dev=%d fn=%d\n",
          (INTN)idx, (INTN)g_mcCount, (INTN)gBus, (INTN)gDev, (INTN)gFn);
    /* v3.47: ПЕРВЫЕ ДВЕ СТРОКИ ЭКРАНА - ЗДЕСЬ, И МИМО КОЛЬЦА.
     *
     * Человек выбрал флешку и смотрит на пустой экран около пяти секунд.
     * Раньше за это время он не видел НИЧЕГО осмысленного: весь Print
     * буферизуется в кольцо, в консоль уходят только проба и пульс, а если
     * приложение зависнет на середине, кольцо не выгрузится и экран не
     * покажет вообще ничего. То есть на экране нет ни единого признака, что
     * процесс жив.
     *
     * Отсюда две строки: какая карта выбрана (если их две, человек должен
     * знать, какая именно разблокируется) и что анлок пошёл. Второе -
     * единственный индикатор зависания, который вообще возможен: после
     * этой точки Print уже ничего не покажет.
     *
     * fx_console_raw, а не Print: прямой вывод переживает зависание, кольцо -
     * нет. */
    {
        CHAR16 s[256];
        UnicodeSPrint(s, sizeof(s), L"%s  PCI 10de:%04x  bus=%d dev=%d fn=%d\r\n",
                      TARGET_NAME, (UINTN)TARGET_PCI_DEV,
                      (INTN)gBus, (INTN)gDev, (INTN)gFn);
        fx_console_raw(s);
        UnicodeSPrint(s, sizeof(s),
                      L"Unlocking (takes a few seconds)...\r\n");
        fx_console_raw(s);
    }
    return TRUE;
}

/* ==== ЗОНД КАЖДОЙ НАЙДЕННОЙ КАРТЫ (ТОЛЬКО ЧТЕНИЕ) ====
 *
 * Зачем: на машине с одной физической CMP 70HX перечисление даёт ДВЕ
 * функции с одинаковым ID 10de:248A (bus=2 и bus=16). Либо вторая
 * карта есть, либо это фантом, оставшийся от манипуляций с анлоком
 * CMP 50HX. Пока непонятно, КАКАЯ из них настоящая, а всё дальнейшее
 * анлок делает на bus=2 (card#0) — если это фантом, маски уходят
 * в никуда и карта остаётся заблокированной.
 *
 * Зонд ничего не пишет: только PCI-конфиг и несколько MMIO-чтений.
 * Настоящий кристалл отвечает правдоподобными значениями (WPR2, GFW,
 * PLM), фантом — нулями или 0xFFFFFFFF/0xBADFxxxx.
 *
 * v3n: ПЕРЕД зондом включаем MEM_EN — раньше зонд читал MMIO при
 * command=0, поэтому chip/gfw/fbsz/plm были 0xFFFFFFFF у ОБЕИХ карт и
 * отличить реальный кристалл от фантома было нельзя (KNOWN-ISSUES 24).
 * Плюс сканируем ВСЕ BAR'ы: без этого неизвестно, отображён ли кадровый
 * буфер в CPU-адресное пространство, а это единственный способ заполнить
 * FRTS-регион, из-за пустоты которого FWSEC не защёлкивает WPR2. */
static void
mc_probe_all(void)
{
    UINTN i;
    for (i = 0; i < g_mcCount; i++) {
        EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *rb = g_mcCards[i].rb;
        UINTN bus = g_mcCards[i].bus, dev = g_mcCards[i].dev, fn = g_mcCards[i].fn;
        UINT32 id = 0, cls = 0, bar0 = 0;
        UINT32 sBus, sDev, sFn, sBar;
        EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *sRb;
        EFI_STATUS st;

        sRb = gRb; sBus = gBus; sDev = gDev; sFn = gFn; sBar = gBar0Base;
        gRb = rb; gBus = (UINT32)bus; gDev = (UINT32)dev; gFn = (UINT32)fn;

        st = pci_cfg_read(0x00, &id);
        if (!EFI_ERROR(st)) pci_cfg_read(0x08, &cls);
        if (!EFI_ERROR(st)) pci_cfg_read(0x10, &bar0);

        /* v3n: BAR'ы смотрим ДО включения decode (это read-only операция,
         * command-регистр не трогаем), затем включаем MEM_EN — и только
         * после этого читаем MMIO: при command=0 все чтения давали 0xFFFFFFFF,
         * из-за чего обе карты выглядели одинаково и фантом было не отличить. */
        scan_bars(L"card");
        enable_mem_decode();

        gBar0Base = bar0 & ~0xFU;

        /* v3n: VROM (VBIOS) — читаем, чтобы понять, где карта ждёт данные
         * и совпадает ли её VBIOS с GA104.rom */
        dump_vrom();

        Print(L"[probe] card#%d bus=%d dev=%d fn=%d: 10de:%04X class=%06X "
              L"BAR0=0x%08x\n", (INTN)i, (INTN)bus, (INTN)dev, (INTN)fn,
              (INTN)((id >> 16) & 0xFFFF), (INTN)((cls >> 8) & 0xFFFFFF), bar0);
        ulogf(L"PROBE card#%d bus=%d dev=%d fn=%d id=10de:%04x class=%06x "
              "bar0=0x%08x\n", (INTN)i, (INTN)bus, (INTN)dev, (INTN)fn,
              (INTN)((id >> 16) & 0xFFFF), (INTN)((cls >> 8) & 0xFFFFFF), bar0);

        if (gBar0Base != 0) {
            UINT32 chip = mmio_read32(0x00000000);
            UINT32 gfw   = mmio_read32(0x00020F70);
            UINT32 fbsz  = mmio_read32(0x00100440);
            UINT32 plm   = mmio_read32(0x00823804);
            UINT32 wlo   = mmio_read32(REG_PFB_MMU_WPR2_LO);
            UINT32 whi   = mmio_read32(REG_PFB_MMU_WPR2_HI);
            Print(L"[probe]   chip=0x%08x gfw=0x%08x fbsz=0x%08x plm=0x%08x "
                  L"wpr2=0x%08x/0x%08x\n", chip, gfw, fbsz, plm, wlo, whi);
            ulogf(L"PROBE   chip=0x%08x gfw=0x%08x fbsz=0x%08x plm=0x%08x "
                  "wpr2=0x%08x/0x%08x\n", chip, gfw, fbsz, plm, wlo, whi);
            /* v3n: ЗАБЛОКИРОВАННОЕ состояние снимаем здесь — до первой же
             * записи в регистры GPU. Выше в этом цикле стоит только
             * enable_mem_decode() (это запись в конфиг PCI, а не в GPU), так
             * что карта ещё в POST, то есть заблокирована. Именно этот
             * дамп, а НЕ «загрузка без флешки», даёт вторую половину A/B.
             * Без флешки наше приложение не запускается и лог не пишется
             * вовсе, так что сравнивать два прогона бессмысленно: второй
             * просто повторяет первый (проверено 2026-09-29 — логи
             * различались только в 10 строках TIME t=). */
            if (i == 0) sec2_window_dump(L"POST-locked");
            /* v3n: те же «до любых записей» основания, что и у SEC2W: карта
             * ещё в POST, то есть заблокирована. Даёт вторую половину A/B по
             * маскам Gen2 и регистрам скорости. */
            if (i == 0) gen2_readonly_dump(L"POST-locked");
        } else {
            Print(L"[probe]   BAR0 = 0 — MMIO недоступна, это НЕ рабочая карта\n");
            ulogf(L"PROBE   bar0=0 -> MMIO unavailable, NOT a working card\n");
        }

        gRb = sRb; gBus = (UINT32)sBus; gDev = (UINT32)sDev;
        gFn = (UINT32)sFn; gBar0Base = sBar;
    }
}

/* Boot#### на САМОГО себя (по DevicePath загруженного образа) + BootNext.
 * Запись ищется по описанию и переиспользуется (не плодим слоты). */
static BOOLEAN mc_set_bootnext_self(EFI_HANDLE ImageHandle)
{
    static EFI_GUID gvGuid = EFI_GLOBAL_VARIABLE;
    static UINT8 opt[1024];
    UINTN off = 0;
    EFI_LOADED_IMAGE_PROTOCOL *li = NULL;
    EFI_DEVICE_PATH_PROTOCOL *dp = NULL, *e;
    UINTN dpSize = 0;
    UINT32 attrs = 0x1;               /* LOAD_OPTION_ACTIVE */
    UINT16 fpl;
    CHAR16 desc[] = L"NVIDIA CMP unlock";
    UINT16 optNo;
    EFI_STATUS st;
    CHAR16 name[12];

    if (EFI_ERROR(uefi_call_wrapper(BS->HandleProtocol, 3, ImageHandle,
            &gEfiLoadedImageProtocolGuid, (VOID**)&li)) || !li->FilePath) {
        Print(L"multi-card: нет LoadedImage/FilePath\n");
        return FALSE;
    }
    dp = li->FilePath;
    for (e = dp; ; e = (EFI_DEVICE_PATH_PROTOCOL *)
             ((UINT8 *)e + (e->Length[0] | (e->Length[1] << 8)))) {
        UINTN len = e->Length[0] | (e->Length[1] << 8);
        dpSize += len;
        if (e->Type == 0x7F && e->SubType == 0xFF) break;
        if (len == 0) return FALSE;
    }
    fpl = (UINT16)dpSize;

    CopyMem(opt + off, &attrs, 4);                      off += 4;
    CopyMem(opt + off, &fpl, 2);                        off += 2;
    CopyMem(opt + off, desc, (StrLen(desc) + 1) * 2);   off += (StrLen(desc) + 1) * 2;
    CopyMem(opt + off, dp, dpSize);                     off += dpSize;

    /* найти существующую нашу запись или свободный слот Boot%04X.
     * v2.99b: break только по NOT_FOUND (свободный слот); прочие ошибки
     * (BufferTooSmall на крупной чужой записи и т.п.) = слот занят, ищем
     * дальше — раньше цикл уезжал на Boot0000 и перезаписывал UiApp
     * (Invalid Parameter). */
    {
        UINTN dbg = 0;
        for (optNo = 0; optNo < 0xFFFF; optNo++) {
            static UINT8 scr[4096];
            UINTN sz = sizeof(scr);
            UINT32 attr = 0;
            BOOLEAN ours;

            UnicodeSPrint(name, sizeof(name), L"Boot%04X", optNo);
            st = uefi_call_wrapper(RT->GetVariable, 5, name, &gvGuid,
                                   &attr, &sz, scr);
            if (dbg < 12)
                Print(L"mc-slot[%02d] st=%r attr=%x sz=%d\n",
                      (INTN)optNo, st, attr, (INTN)sz);
            dbg++;
            if (st == EFI_NOT_FOUND) break;           /* свободный слот */
            if (EFI_ERROR(st)) continue;              /* занят, но нечитаем */
            ours = (sz > 8) && StrnCmp((CHAR16 *)(scr + 6), desc,
                                       StrLen(desc)) == 0;
            if (ours) break;                          /* переиспользуем */
        }
        Print(L"mc: выбран слот %d, opt=%d байт (fpl=%d, dp=%d)\n",
              (INTN)optNo, (INTN)off, fpl, (INTN)dpSize);
    }

    st = uefi_call_wrapper(RT->SetVariable, 6, name, &gvGuid,
        EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |
        EFI_VARIABLE_RUNTIME_ACCESS, off, opt);
    if (EFI_ERROR(st)) {
        Print(L"multi-card: Boot%04X запись: %r\n", (INTN)optNo, st);
        return FALSE;
    }
    st = uefi_call_wrapper(RT->SetVariable, 6, L"BootNext", &gvGuid,
        EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |
        EFI_VARIABLE_RUNTIME_ACCESS, 2, &optNo);
    Print(L"multi-card: BootNext -> Boot%04X (сами): %r\n", (INTN)optNo, st);
    return !EFI_ERROR(st);
}
#endif /* MULTI_CARD */

/* ==== Render/priv mask table + fire-mode loop (rejoin16 method) ====
 * The Gen1 link cap and closed XVE/XP3G windows are PLM-protected
 * shadow registers, NOT fuses: with PLM open they become writable — but
 * the V67 chain fires exactly TWICE per boot cycle (#1 stock payload
 * opens PLM, #2 carries ONE crafted {addr,value} pair), and each pair
 * needs its own FLR-separated mini-cycle. Table = 37 pairs. After the
 * last pair the final pass applies GFX_SPEED_SELECT/SS0/SS1 and
 * (unless FULL_NOGEN2) the gen2 link configuration.
 * jdowning100/pearlfortune: Gen1 cap = PLM-защита XVE/XP3G (НЕ fuse!).
 * V67-цепь срабатывает ОДИН раз за FLR-разделённую загрузку → одна запись
 * {addr,value} за прогон. Таблица 36 пар из их rejoin16-apply-all.sh.
 * Цикл итерации: FLR на входе (разделение) → восстановление BAR0 →
 * полный ранний путь с пропатченным payload → verify readback до cleanup.
 * Финальная итерация: маски открыты → Gen2-конфиг хостом + GFX_SPEED_SELECT.
 * Требует MULTI_CARD (mc_var_get/set, mc_set_bootnext_self, mc_vars_clear).
 *
 * ПОРТ НА 70HX: адреса масок НЕ переносились насильно — они лежат в двух
 * окнах, общих для всех GA10x: окно XVE (0x88xxx, «дверь» GFX_SPEED_SELECT)
 * и priv-домен 0x82xxx/0x8Exxx (feature-override). Драйвер отдаёт GA102 и
 * GA104 из одного HAL kernel_gsp_ga102.c и одних header'ов
 * published/ampere/ga102, поэтому смещения совпадают. Эмпирика
 * (docs/REGISTERS.md) снималась на 90HX — на 70HX значения читаются
 * как «открыто/закрыто» по тому же признаку FF-на-против-битовой-маски.
 * Если на 70HX какой-то адрес вернёт 0xBADFxxxx — он PLM-прикрытый и
 * должен быть открыт РАНЬШЕ (см. порядок: PLM идёт первым в таблице). */
#ifdef PCIE_GEN2_REJOIN
static const struct { UINT32 addr, val; } g_rj16[] = {
    {0x00823804U,0xffffffffU},{0x00088fe8U,0xffffffffU},{0x00088fecU,0xffffffffU},
    {0x00088ff0U,0xffffffffU},{0x00088ff4U,0xffffffffU},{0x00088ff8U,0xffffffffU},
    {0x00088ab4U,0xffffffffU},{0x0008e1b0U,0xffffffffU},{0x0008e1b4U,0xffffffffU},
    {0x0008e1b8U,0xffffffffU},{0x0008e1bcU,0xffffffffU},{0x0008e1c0U,0xffffffffU},
    {0x0008e1c4U,0xffffffffU},{0x0008e1c8U,0xffffffffU},{0x0008e1ccU,0xffffffffU},
    {0x0008e1d0U,0xffffffffU},{0x0008e1d4U,0xffffffffU},{0x0008e1d8U,0xffffffffU},
    {0x0008e1dcU,0xffffffffU},{0x0008e1e0U,0xffffffffU},{0x0008e1e4U,0xffffffffU},
    {0x0008e1e8U,0xffffffffU},{0x0008e1ecU,0xffffffffU},{0x0008e1f0U,0xffffffffU},
    {0x008200d0U,0xffffffffU},{0x008200d4U,0xffffffffU},{0x008200d8U,0xffffffffU},
    {0x008200dcU,0xffffffffU},{0x008200e0U,0xffffffffU},{0x008200e4U,0xffffffffU},
    {0x008200e8U,0xffffffffU},{0x008200ecU,0xffffffffU},{0x008200f0U,0xffffffffU},
    {0x008200f4U,0xffffffffU},{0x00823800U,0xffffffffU},{0x00823b04U,0xffffffffU},
    /* v2.100: LINK_CAP = Gen2 (0x...02). Проба Gen3 (v2.99k) отклонена:
     * кремний жёстко клампит max_speed на 5 GT/s (запись 03 -> readback 02,
     * подтверждено и на хосте). Пишем детерминированное значение — свип
     * проходит, LnkCap анонсирует 5 GT/s («card advertises Gen2»). */
    {0x00088084U,0x00453d02U},
};
#define RJ16_N ((INTN)(sizeof(g_rj16)/sizeof(g_rj16[0])))
static BOOLEAN g_gen2Fire = FALSE;
/* v3n: FWSEC в свипе gen2 нужен один раз, а не на каждой записи таблицы */
static BOOLEAN g_fwsecOnce = FALSE;
/* v3n: gen2 по умолчанию ВЫКЛЮЧЕН. Замер времени показал: свип съедает
 * ~10.8 минут из 13 и при этом не доходит до FF (маски на 0xFFFFFFCF/8F).
 * Пока не решён вопрос WPR2, отладка идёт без gen2 — цикл сжимается до
 * ~2.2 минуты. Включать осознанно, когда WPR2 защёлкивается и понадобится
 * полный PLM. */
static BOOLEAN g_gen2Enable = FALSE;
static BOOLEAN g_gen2Quick = FALSE;   /* v2.99h: маски уже открыты — сразу конфиг */
static UINT32 g_gen2Addr = 0, g_gen2Val = 0;
/* v3n: читаемое состояние fire-режима для кода ВНЕ #ifdef PCIE_GEN2_REJOIN.
 * Раньше строка лога с g_gen2Fire стояла в общем коде, и сборки без
 * PCIE_GEN2_REJOIN падали с 'g_gen2Fire undeclared'. */
#define GEN2_FIRE_STATE()  ((INTN) g_gen2Fire)
#else
#define GEN2_FIRE_STATE()  ((INTN) 0)
#endif /* PCIE_GEN2_REJOIN */

/* ==== GPU wall-clock (PTIMER) ====
 * PLM anti-replay validation needs sane GPU time: seed PTIMER from RTC
 * (constant fallback) BEFORE touching any protected register. */
static void
set_gpu_time(void)
{
    EFI_TIME t;
    UINT64 ns;
    BOOLEAN bOk = FALSE;

    if (uefi_call_wrapper(ST->RuntimeServices->GetTime, 2, &t, NULL) == EFI_SUCCESS &&
        t.Year >= 2015 && t.Year < 2100)
    {
        Print(L"time: RTC %d-%02d-%02d %02d:%02d:%02d\n",
              t.Year, t.Month, t.Day, t.Hour, t.Minute, t.Second);
        bOk = TRUE;
    }
    else
    {
        /* RTC мёртв/не задан в EFI-контексте → константа 2026-08-19 00:00 UTC */
        Print(L"time: GetTime недоступен/мусор — константа 2026-08-19\n");
        t.Year = 2026; t.Month = 8; t.Day = 19;
        t.Hour = 0; t.Minute = 0; t.Second = 0;
    }

    if (bOk) {
        /* EFI_TIME → unix ns (примерное: без високосных поправок — достаточно) */
        UINTN days = 0;
        static const UINTN mdays[12] = {31,28,31,30,31,30,31,31,30,31,30,31};
        UINTN y, m;
        for (y = 1970; y < t.Year; y++)
            days += 365 + (((y % 4 == 0) && (y % 100 != 0)) || (y % 400 == 0));
        for (m = 0; m < t.Month - 1; m++)
            days += mdays[m];
        if (t.Month > 2 && (((t.Year % 4 == 0) && (t.Year % 100 != 0)) || (t.Year % 400 == 0)))
            days++;
        ns = ((UINT64)days * 86400ULL + (UINT64)t.Hour * 3600ULL +
              (UINT64)t.Minute * 60ULL + t.Second) * 1000000000ULL;
    } else {
        ns = 1787011200000000000ULL;  /* 2026-08-19 00:00:00 UTC в наносекундах */
    }
    mmio_write32(NV_PTIMER_TIME_1, (UINT32)(ns >> 32));
    mmio_write32(NV_PTIMER_TIME_0, (UINT32)(ns & 0xFFFFFFFF));
    Print(L"time: GPU time set (ns>>32=0x%08x)\n", (UINT32)(ns >> 32));
}

/* ==== Falcon DMA engine primitives (SEC2) ====
 * 256-byte block transfers through DMATRF registers; wait helpers poll
 * the FULL/IDLE bits of DMATRFCMD. */
/* ==================================================================== *
 * v3.16 — ЧАСЫ И ПРИМИТИВ ОПРОСА С ПОТОЛКОМ ПО ВРЕМЕНИ
 * ==================================================================== *
 *
 * ЧАСЫ. RDTSC не требует отображения BAR0 и на x86-64 гарантирован
 * (IA32_TSC), поэтому отсчёт идёт с самой загрузки. NV_PTIMER
 * (cmp90_ptimer64) для этого не годится: это MMIO, он читается только
 * после enable_mem_decode(). Из-за этого старый log_t0() стоял позже, и
 * первые строки efi_main шли без хронометража.
 *
 * Блок живёт здесь, а не рядом с log_t0, потому что им пользуются функции
 * ожидания DMA ниже по файлу — C требует объявления до использования.
 *
 * ПРИМИТИВ fx_poll32. Ждёт, пока (reg & mask) == want, и выходит по
 * трём условиям:
 *   1) условие наступило          — обычный выход, ничего не меняется;
 *   2) регистр не менялся stuckAt чтений подряд — «замер»;
 *   3) прошло maxUs микросекунд   — потолок по ВРЕМЕНИ.
 *
 * ПОЧЕМУ ИМЕННО ТАК. Старый код считал ИТЕРАЦИИ, а не время:
 *     for (i = 0; i < 20000; i++) чтение DMATRFCMD;
 * Счётчик итераций — не ограничение по времени. Измеренная цена одного
 * чтения BAR0 на этой плате — 773 нс, так что 20 000 итераций это 15 мс;
 * на другой машине то же число итераций стоило бы иначе. Счётчик
 * итераций — машинно-зависимый бюджет, и это дефект сам по себе,
 * независимо от его величины.
 *
 * Условие 2 применимо ТОЛЬКО там, где регистр описывает состояние
 * «дела идут / дела нет», а не «работа идёт». Для DMA-очереди это так:
 * по логу cmd=0x00000615 на ВСЕХ таймаутах, значение не двигается
 * вообще. Там, где регистр описывает ВЫПОЛНЯЕМУЮ работу (скраб IMEM,
 * RESET_READY), тишина означает «работа идёт», и ранний выход бросает
 * следующий шаг раньше времени — см. FX_NEVER_STUCK и комментарий у
 * falcon_wait_scrub_done.
 *
 * ------------------------------------------------------------------ */
static UINT64
fx_rdtsc(void)
{
    UINT32 lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((UINT64)hi << 32) | lo;
}

static UINT64 fx_tscPerUs = 0;   /* тиков TSC в микросекунде */
static UINT64 fx_mark = 0;       /* TSC, от которого считает fx_now_us */

static UINT64
fx_now_us(void)
{
    if (fx_tscPerUs == 0) return 0;
    return (fx_rdtsc() - fx_mark) / fx_tscPerUs;
}

/* Пауза. Крупные — через BS->Stall (отдаёт процессор, не жжёт циклами);
 * мелкие — спинном по TSC, потому что Stall на сотнях микросекунд
 * округляет и добавляет свою погрешность. */
static VOID
fx_sleep_us(UINT64 us)
{
    UINT64 dl;
    if (us == 0) return;
    if (us >= 3000) {
        uefi_call_wrapper(BS->Stall, 1, (UINTN)us);
        return;
    }
    dl = fx_now_us() + us;
    while (fx_now_us() < dl)
        __asm__ __volatile__("pause");
}

/* «Никогда не считать замершим». Ставится там, где тишина НЕ является
 * доказательством готовности: молчаливый ранний выход там означал бы
 * действие раньше, чем железо закончило. */
#define FX_NEVER_STUCK     0xFFFFFFFFU

typedef struct {
    UINT32 value;       /* последнее прочитанное значение       */
    UINTN  reads;       /* сколько чтений сделано               */
    UINT64 us;          /* сколько микросекунд заняло           */
    UINTN  stuck;       /* выход по «регистр не меняется»       */
    UINTN  overtime;    /* выход по потолку времени             */
} FX_POLL;

/* Ждёт (reg & mask) == want. maxIter — старый бюджет ИТЕРАЦИЙ (оставлен
 * как верхняя граница на случай, если часы недоступны), maxUs — новый
 * бюджет ВРЕМЕНИ, stuckAt — выход по «замер». */
static VOID
fx_poll32(UINTN reg, UINT32 mask, UINT32 want, UINTN maxIter, UINTN stuckAt,
          UINT64 maxUs, FX_POLL *out)
{
    UINTN i;
    UINT32 v = 0, prev = 0xFFFFFFFFU;
    UINTN same = 0;
    UINT64 t0 = fx_now_us();
    BOOLEAN haveT = (t0 != 0);

    out->stuck = 0;
    out->overtime = 0;
    for (i = 0; i < maxIter; i++) {
        v = mmio_read32(reg);
        if ((v & mask) == want) break;
        if (stuckAt != FX_NEVER_STUCK && v == prev) {
            if (++same >= stuckAt) { out->stuck = 1; break; }
        } else {
            prev = v;
            same = 0;
        }
        if (haveT && fx_now_us() - t0 >= maxUs) { out->overtime = 1; break; }
    }
    out->value = v;
    out->reads = i + 1;
    out->us = haveT ? (fx_now_us() - t0) : 0;
}

/* Потолок для DMA-очередей.
 *
 * Старый код ждал 20 000 итераций (gsp_*) и 1 000 000 итераций (falcon_*).
 * На этой карте очередь не разгружается НИКОГДА: cmd=0x00000615 на всех
 * таймаутах, 1656 штук за прогон. Значит все эти итерации — ожидание
 * заведомо неизменимого состояния.
 *
 * FX_DMAQ_STUCK = 16: при 773 нс на чтение это ~12 мкс тишины. Значение
 * одно и то же значит и ждать нечего — очередь не медленная, а замершая.
 * Живая очередь, которая разгружается на 3-м чтении, выходит раньше и
 * поведение её не меняется; это проверяется машинно, см.
 * src/tools/poll_model.c.
 *
 * FX_DMAQ_MAX_US = 4 мс — страховка на случай, если регистр МЕДЛЕННО
 * меняется (тогда «замер» не наступает, но и ждать бесконечно нельзя).
 */
#define FX_DMAQ_STUCK      16
#define FX_DMAQ_MAX_US     4000
/* Потолок ожидания скраба IMEM: 30 000 x Stall(100мкс) = 3 с, как и было.
   Равен прежнему бюджету итераций, НЕ ускоряет ничего — добавлен только */
#define FX_SCRUB_MAX_US    300000

static VOID
falcon_dma_wait_not_full(void)
{
    /* v3.16: было for (i=0;i<1000000;i++) — минуты на один зависший вызов.
     * Бюджет итераций оставлен как верхняя граница, добавлены потолок по
     * времени и выход по «регистр замер». */
    FX_POLL p;
    fx_poll32(SEC2_DMATRFCMD, 0x1u, 0x0u, 1000000, FX_DMAQ_STUCK,
              FX_DMAQ_MAX_US, &p);
    if ((p.value & 0x1u) == 0) return;
    ulogf(L"DMAQ2  SEC2 queue FULL, gave up after %d reads / %lldus "
          L"(stuck=%d overtime=%d) cmd=0x%08x\n",
          (INTN)p.reads, (INT64)p.us, (INTN)p.stuck, (INTN)p.overtime,
          (INTN)p.value);
}

/* ---- Ворота для дорогих диагностических экспериментов (v2.43/v2.45) ---
 *
 * Эксперименты лежат на пути УСПЕХА и повторяются 24 раза за прогон.
 * Ответы не зависят от номера маски, а цена вопроса высока: фазовый учёт
 * 2026-10-02 показал 6,1 с + 17,6 с = 23,7 с из 113 с, то есть 21 %.
 *
 * Правило то же, что у fx_repeat_gate: пропуск не молчит, а считается —
 * иначе «оптимизация» выглядит бы как «эксперимент перестал существовать».
 * Подробности и цена решения — в комментарии перед блоком v2.43.
 *
 * FX_DIAG_EVERY — на сколько вызовов приходится один запуск. При 24 это
 * один полный эксперимент на прогон, то есть ровно те данные, ради которых
 * блоки написаны. Значение 1 возвращает прежнее поведение.
 *
 * ОШИБКА, БЫЛА В ПЕРВОЙ ВЕРСИИ: стояло FX_DIAG_EVERY = 1 при условии
 *     (calls % FX_DIAG_EVERY) == 1 || FX_DIAG_EVERY == 1
 * то есть при 1 условие всегда истинно и ворота пропускали ВСЕ вызовы —
 * экономии не было, но выглядело как «оптимизировано».
 */
#define FX_DIAG_EVERY   24
static UINTN fx_diagCalls = 0;
static UINTN fx_diagDone  = 0;

/* v3.17: FX_DIAG_SWEEPS - по умолчанию 0 (BUILDING 6.0: любая проверка за
 * флагом, который по умолчанию равен 0). Свип регистровых блоков читает 580
 * регистров и печатает ненулевые; ИЗМЕРЕННАЯ цена одного вызова sweep_all -
 * 11,86 с, из них на MMIO приходится ничто, всё остальное - консоль. */
#ifndef FX_DIAG_SWEEPS
#define FX_DIAG_SWEEPS 0
#endif
/* v3.18: FX_DIAG_FBPROBE - по умолчанию 0. Проба доступа к кадровому
 * буферу ТОЛЬКО ЧИТАЕТ и печатает в лог «frts-NOT-reachable-via-dma»,
 * то есть признаёт собственное отрицательное свой результат. ИЗМЕРЕННАЯ
 * стоимость - 4,40 с из 57,3 с (7,7 % прогона). Возврат:
 * -DFX_DIAG_FBPROBE=1 в build.sh. */
#ifndef FX_DIAG_FBPROBE
#define FX_DIAG_FBPROBE 0
#endif

/* v3.17: итог бесплатной прямой записи масок (render_open_gfx_masks).
 * Печатается в финале рядом с остальными итогами: пропуск не молчит, а
 * считается — по тому же правилу, что у fx_repeat_gate и fx_diag_gate.
 * Смысл цифр: direct = маска открылась обычной записью хоста, ботер не
 * понадобился; booter = прямая запись не липнула, сработал прежний путь
 * с FLR и ботером#2. Второе число не является поломкой, это
 * самопроверяющий откат. */
UINTN fx_rmDirect = 0;
UINTN fx_rmNeedBooter = 0;

/* v3.33, ЭТАП 16: флаг диагностического блока v2.43+v2.45, по умолчанию 0.
 *
 * Блок НЕ является частью последовательности анлока - это эксперимент,
 * который сообщает про PLM/WPR2 во время подготовки FWSEC. Измеренная цена
 * в хорошем прогоне v3.30 - 705 мс из 18 084, то есть 3,9% всего времени.
 *
 * Почему он вообще выполнялся: fx_diag_gate() с FX_DIAG_EVERY = 24 отдаёт
 * первый вызов из каждых 24, и в прогоне v3.30 он как раз сработал. Платить
 * 705 мс за диагностику, которую мы уже забрали, незачем.
 *
 * Всё, что блок сообщает, уже записано в out/BUILDS.md и в логи. Включить
 * обратно для нового эксперимента - поставить здесь 1.
 *
 * fx_diag_gate() вызывается РОВНО ИЗ ОДНОГО МЕСТА (проверено), поэтому флаг
 * не задевает никакую другую диагностику. */
UINTN fx_diagV245 = 0;

/* v3.18: итог быстрого пути рендер-цикла.
 *   fast    - маска открылась ОДНИМ дополнительным ботером#2, без FLR и
 *             без полного early_unlock_path (выигрыш ~4,2 с на маску);
 *   miss    - не открылась, сработал откат на полный путь (цена ошибки
 *             ~1,2 с за попытку, разблокировка не пострадала);
 *   firstOk - состояние SEC2 подтверждено полным путём, быстрый путь
 *             разрешён для следующих масок.
 * Печатаются все три по тому же правилу, что и остальные итоги. */
UINTN fx_rmFast = 0;
UINTN fx_rmFastMiss = 0;
BOOLEAN fx_rmFirstOk = FALSE;

static BOOLEAN
fx_diag_gate(void)
{
    fx_diagCalls++;
    if ((fx_diagCalls % FX_DIAG_EVERY) == 1 || FX_DIAG_EVERY == 1) {
        fx_diagDone++;
        return TRUE;
    }
    return FALSE;
}
/* ==================================================================== *
 * v3.21: ФАЗЫ УБРАНЫ. ОСТАЛИСЬ ТОЛЬКО МЕТКИ ВРЕМЕНИ.
 *
 * Это не пятая попытка починить фазовый учёт, а решение его удалить.
 *
 * ПОЧЕМУ УДАЛИТЬ, А НЕ ПОЧИНИТЬ. Фазовый учёт работал в шести прогонах
 * подряд и НИ РАЗ не дал верного числа:
 *
 *   v3.17  ручная метка вложенности (fx_ph_end vs fx_ph_end_in) соврала
 *          в трёх местах: [E1]+[E2]+[E3] считались верхним уровнем при
 *          родителе render: early_unlock_path.
 *          SUM top-level 78 152 783 мкс при прогоне 57 316 мкс.
 *
 *   v3.18  «починка» перевела вложенность на счётчик глубины fx_phDepth,
 *          но сам счётчик никто не инкрементировал - все фазы стали
 *          верхними, таблица удвоилась.
 *
 *   v3.19  лишний fx_ph_end уводил глубину в минус, после чего dep>0
 *          получали ВСЕ фазы. 16 из 16 (inside), SUM top-level = 0.
 *
 *   v3.20  лишние fx_ph_begin в render_open_gfx_masks и fwsec_boot_gsp_sig.
 *          15 из 15 (inside), SUM top-level = 0.
 *
 *   v3.21  непарная пара в теле цикла k: begin после
 *          'render: ROP write + poll' не закрыт, а 'render: FLR + 300ms
 *          settle' закрывает фазу, открытую ДО цикла.
 *          UNDERFLOW x7, LEAK x8; фаза FLR показывала 15,5 с вместо 4,0.
 *
 * КАЖДЫЙ РАЗ механизм проверки ломался ВМЕСТЕ с самой таблицей, то есть
 * защитить его было нечем: строка 'depth OK' рапортовала о сломанной
 * таблице. Это и есть главный вывод - проверка не может защитить код,
 * который она же и разбирает.
 *
 * КОРЕНЬ ПРОБЛЕМЫ ОДИН И НЕ МЕНЯЛСЯ ШЕСТЬ ПРОГОНОВ: фазы спаривались
 * вручную, через отдельную переменную fx_ph и две функции end/end_in.
 * Спаривание нигде не проверялось на уровне структуры, поэтому любой
 * забытый вызов тихо ломал всю таблицу. Убрать ручное спаривание -
 * значит убрать и весь класс ошибок, а не очередной его симптом.
 *
 * ЧТО ОСТАЁТСЯ ВМЕСТО. Метки времени. Они не требуют синхронизации
 * ничего: fx_mk_acc печатает текущее время и имя участка, а разница
 * между соседними метками и есть длительность участка. За шесть прогонов
 * они дали разброс +-7 мс на итерацию (5477 мс в v317 и v317 мс в v320,
 * т.е. 5477 и 5477) и ни разу не соврали.
 *
 * ЦЕНА ОТКАЗА, СКАЗАННАЯ ЧЕСТНО. Метки не умеют складываться в иерархию:
 * нельзя спросить «сколько всего на верхнем уровне». Этого и не
 * требовалось - все решения принимались по разности соседних меток. Что
 * действительно теряется: автоматическая проверка «всё ли время учтено».
 * Её заменяет другое свойство - забытый вызов fx_mk_acc виден СРАЗУ, как
 * неправдоподобно большой скачок между двумя соседними метками t=.
 *
 * ЧТО ТЕПЕРЬ ВИДНО. Прежде early_unlock_path была чёрным ящиком на 3,7 с.
 * Теперь внутри неё стоят метки [E1], [E2], [E3] и четыре части ботера, то
 * есть время прогона разложено по именам без единого счётчика глубины.
 *
 * ЗАТРАТЫ НА САМ ЗАМЕР. ~115 дополнительных строк лога по 26 мкс = 3 мс на
 * прогон из 55 900. Замерено, не прикинуто: цена вызова ulogf после
 * пакетной записи измерена как 26 мкс в прогонах v3.17 и v3.19.
 * ==================================================================== */
/* --- счётчики falcon_wait_reset_ready -----------------------------------
 *
 * v3.21, этап 7 плана (PLAN-SPEED.md §8). Функция устроена так:
 *
 *     for (i = 0; i < 10000; i++) {
 *         if (mmio_read32(hwcfg2Reg) & (1u << 31)) return;
 *         Stall(100);
 *     }
 *
 * То есть бюджет РОВНО 1,000 с, и вернуться раньше можно только если
 * выставится HWCFG2[31]. В прогоне v321 в логе 29 строк SCRUB, и во всех
 * hwcfg2=0x000067F7 - бит 31 не выставлен ни разу.
 *
 * При этом содержимое блоков по ~1,2 с измерено как ~90 мс: scrub 103 мкс,
 * Stall(50000) 50 мс, falcon settle 22,8 мс, Print 17 мс. Остальные ~1,1 с
 * на блок ничем не объяснены, и этот бюджет - единственная гипотеза,
 * которая объясняет.
 *
 * ЧТО ЗДЕСЬ ВАЖНО: это счётчики ПРОВЕРКИ ГИПОТЕЗЫ, а не оптимизация.
 * Поведение функции не меняется ни на одну строку - добавлены только
 * замеры. Итоговая строка печатается в fx_mk_report и читается напрямую:
 *     calls=N early=M total=T us
 * Если early=0 и total ≈ 1000000*N, гипотеза подтверждена и следующим
 * этапом сокращается бюджет. Если early>0 - гипотеза опровергнута, и
 * сокращать нечего. */
/* v3.23, этап 8 (ОТВЕРГНУТ, см. ниже и out/BUILDS.md): бюджет
 * falcon_wait_reset_ready был сокращён с 10 000 итераций (1,000 с) до 500
 * (50 мс). Основание было измерение прогона v3.22: calls=37 early=0
 * total=41538580us, то есть все 37 вызовов выжигали полную секунду, а признак
 * HWCFG2[31] не выставился ни разу.
 *
 * ОСНОВАНИЕ ОКАЗАЛОСЬ НЕПОЛНЫМ. Прогон v3.23 дал 58 535 мс и 0 из 8 масок.
 * early=0 доказывало, что условие HWCFG2[31] не выставляется, - и НИЧЕГО
 * НЕ ГОВОРИЛО о том, нужна ли сама задержка. Она оказалась необходима.
 * Ниже бюджет возвращён к 10 000, а перед ним добавлено ожидание события.
 */

/* v3.24, этап 9: бюджет СЛЕПОГО ожидания восстановлен на прежние 10 000
 * (1,000 с), и ПЕРЕД ним добавлено ожидание РЕАЛЬНОГО события.
 *
 * Почему слепой бюджет вернулся. Этап 8 сократил его до 500 (50 мс) на
 * основании того, что условие HWCFG2[31] не выставляется ни разу (0 из 37).
 * Прогон v3.23 показал: этого недостаточно, render сломан, 0 из 8 масок.
 * Механизм, измеренный по двум прогонам: FWSEC грузится при CPUCTL=0x00000000
 * (18 из 18 строк WAIT в v322) и не грузится при CPUCTL=0x00000010=HALTED
 * (64 из 64 в v323). То есть секунда ждала не признак, а УХОДА CPUCTL в
 * нулевое состояние перед сбросом движка.
 *
 * То есть слепой цикл по HWCFG2[31] бесполезен (это осталось верным), но
 * ЗАДЕРЖКА, которую он случайно давал, необходима. Значит надо ждать
 * состояние, а не константу - и слепой бюджет равен прежнему, чтобы
 * худший случай совпал с заведомо рабочим v322.
 *
 * Определения здесь, а не над функцией: и это значение, и счётчики
 * печатаются в fx_mk_report, которая объявлена раньше функции. */
#define FX_RR_ITERS      10000   /* слепой опрос HWCFG2[31], полный: 1,000 с.
                                   * v3.25: НЕ ИСПОЛЬЗУЕТСЯ как источник
                                   * задержки, оставлен для справки */
#define FX_RR_SLOW_ITERS 500     /* v3.25, этап 10: слепой цикл на медленном
                                   * пути (событие не наступило). ШАГ 1 уже
                                   * израсходовал свои 1,000 с, то есть
                                   * прежнюю полную стоимость, поэтому вторая
                                   * секунда не нужна - остаётся страховка */
#define FX_RQ_BUDGET_US  250000  /* v3.33, ЭТАП 16: ВОЗВРАЩЕНО 150 -> 250 мс.
                                    *
                                    * ГРАНИЦА ПОРОГА, ТЕПЕРЬ ТОЧНА. v3.32
                                    * поставил 150 мс и сломал рендер (1 из 8,
                                    * 54,1 с), при этом обе операции сработали
                                    * точно по расчёту: медленный вызов стоил
                                    * 160 855 мкс вместо ожидаемых 160,5 мс.
                                    * То есть механика режет время корректно,
                                    * просто 150 мс ниже порога:
                                    *
                                    *     50 мс = 0 из 8   (этап 12)
                                    *    150 мс = 1 из 8   (v3.32)
                                    *    250 мс = 8 из 8   (v3.28, v3.30)
                                                                                                                                                                                                                                                                                                                                    *    500 мс = 8 из 8   (v3.27)
                                                                                                                                                                                                                                                                                                                                    *   1000 мс = 8 из 8   (v3.24-26)
                                                                                                                                                                                                                                                                                                                                    *
                                                                                                                                                                                                                                                                                                                                    * Порог в (150 мс; 250 мс]. Качество падает
                                                                                                                                                                                                                                                                                                                                    * монотонно: 0 -> 1 -> 8.
                                                                                                                                                                                                                                                                                                                                    *
                                                                                                                                                                                                                                                                                                                                    * ПОЧЕМУ НЕ 200 мс, ВЕДЬ ЭТО СЕРЕДИНА. В
                                                                                                                                                                                                                                                                                                                                    * этой же сборку v3.33 добавлена отключение
                                                                                                                                                                                                                                                                                                                                    * диагностики v2.43/v2.45 на -705 мс. Ставить
                                                                                                                                                                                                                                                                                                                                    * ТУДА ЖЕ ещё и 200 мс (ещё 0,5 с) - значит
                                                                                                                                                                                                                                                                                                                                    * два риска в одной сборке после двух
                                                                                                                                                                                                                                                                                                                                    * сломанных прогонов подряд. Безопасную 0,7 с
                                                                                                                                                                                                                                                                                                                                    * банкуем сейчас; 200 мс пойдёт отдельным
                                                                                                                                                                                                                                                                                                                                    * gambit С РАБОТАЮЩЕЙ базы, где откат тривиален.
                                                                                                                                                                                                                                                                                                                                    *
                                                                                                                                                                                                                                                                                                                                    * BAR0 - ещё раз не предиктивен: в v3.32 встал
                                                                                                                                                                                                                                                                                                                                    * 8 из 8 при рендере 1 из 8. Второе
                                                                                                                                                                                                                                                                                                                                    * подтверждение подряд, кандидат закрыт.
                                                                                                                                                                                                                                                                                                                                    *
                                                                                                                                                                                                                                                                                                                                    * Ниже сохранена история этапа 15.
                                                                                                                                                                                                                                                                                                                                    *
                                                                                                                                                                                                                                                                                                                                    * --- ЭТАП 15, ЭТАП 14 ---
                                                                                                                                                                                                                                                                                                                                    *
                                                                                                                                                                                                                                                                                                                                    * ГЛАВНАЯ НАХОДКА ЭТАПА 14. ВСЕ 10
                                    * медленных вызовов QUIESCE, без единого
                                    * исключения, пишут в QSLOW: 'budget
                                    * exhausted, engine did NOT quiesce',
                                    * cpuctl=0x00000010. То есть ожидание НИ
                                    * РАЗУ не срабатывает: код 10 x 260 мс =
                                    * 2,6 с (14% прогона) ждёт условие,
                                    * которое не выполнилось ни разу, и всё
                                    * равно идёт дальше.
                                    *
                                    * ПОЧЕМУ НЕ УДАЛИТЬ ЖДАНИЕ ЦЕЛИКОМ, а резать
                                    * бюджет. Этап 12 измерил 50 мс как FAIL, а
                                    * 250 мс как PASS. Если ожидание никогда не
                                    * срабатывает, бюджет не должен влиять - а
                                    * влияет. Значит важно само ПРОШЕДШЕЕ ВРЕМЯ,
                                    * а не условие. Удаление ожидания - ровно тот
                                    * класс ошибки, который уже трижды обманул
                                    * (стадии 3, 2, 13): выбрать
                                    * правдоподобное условие и поверить ему
                                    * вместо измерения. Сначала граница,
                                    * потом удаление.
                                    *
                                    * ИЗМЕРЕННЫЕ ТОЧКИ (железо, verify-log.ps1):
                                    *    50 мс   = FAIL, рендер сломан, 0 из 8
                                    *   150 мс  = шаг 1, сейчас
                                    *   250 мс  = PASS, 18 084 мс (v3.28, v3.30)
                                    *   500 мс  = PASS, 20 575 мс (v3.27)
                                    *   1000 мс = PASS, 25 603 мс (v3.24-26)
                                    *
                                    * Делю интервал (50; 250] пополам. Порог
                                    * где именно - НЕ ЗНАЮ и не притворяюсь:
                                    * если он вплотную к 250, выигрыш будет
                                    * 0,1 с, а не 1,0 с. Если 150 не пройдёт,
                                    * следующий шаг 200 мс, а не возврат к 250:
                                    * точек интервала станет три, а не две.
                                    *
                                    * Считаю ОТ ИЗМЕРЕННОЙ СТОИМОСТИ ОДНОГО
                                    * ВЫЗОВА, а не от итога прогона. При
                                    * бюджете 250 мс один медленный вызов стоит
                                    * 260,5 мс (250 + запас 10 + ~0,5
                                    * накладных), и QSLOW это подтвердил.
                                    * При бюджете 150 мс ожидаю ~160,5 мс.
                                    *
                                    *   150 мс -> 160,5 мс на вызов
                                    *          10 вызовов = 1,61 с (было 2,61)
                                    *          18 084 - 1 000 = 17 084 мс
                                    *
                                    * Ожидание ~17,1 с. Одна строка вычитания,
                                    * проверяемая. Специально НЕ прибавляю
                                    * экономию - знак уже путал дважды.
                                    *
                                    * --- ниже сохранена история этапа 12, из
                                    * которой взят принцип подсчёта ---
                                   *
                                   * ИЗМЕРЕННЫЕ ТОЧКИ (жлезо, verify-log.ps1):
                                   *    50 мс   = FAIL, рендер сломан, 0 из 8
                                   *    250 мс  = шаг 2, сейчас
                                   *    500 мс  = PASS, 20 575 мс (v3.27)
                                   *   1000 мс  = PASS, 25 603 мс (v3.24-26)
                                   *
                                   * Считаю ОТ ИЗМЕРЕННОЙ СТОИМОСТИ ОДНОГО
                                   * ВЫЗОВА, а не от итога прогона. При
                                   * бюджете 500 мс один медленный вызов
                                   * стоит 510,5 мс (500 + запас 10 + ~0,5
                                   * накладных), и QSLOW это показал: 4 084
                                   * мс на восемь вызовов = 510,5 каждый.
                                   *
                                   *   250 мс -> 260,5 мс на вызов
                                   *          10 вызовов = 2,61 с (было 5,10)
                                   *          20 575 - (5 100 - 2 610)
                                   *          = 20 575 - 2 490 = 18 085 мс
                                   *
                                   * Ожидание ~18,1 с. В предыдущем шаге я
                                   * написал 30,7 с вместо 20,6 с, потому что
                                   * ПРИБАВИЛ экономию вместо того чтобы её
                                   * вычесть, и вписал это число в подсказку
                                   * прошивки. Здесь ожидание посчитано
                                   * показанным выше способом, и оно
                                   * проверяемо: одна строка сложения. */
#define FX_RQ_POLL_US    1000    /* период опроса CPUCTL */
#define FX_RQ_SETTLE_US  10000   /* v3.25: запас после срабатывания события.
                                   * На порядок ниже fx_settle (22,8 мс),
                                   * на который код уже опирается.
                                   * Стоит 27 x 10 мс = 0,27 с за прогон */

static UINTN  fx_rrCalls = 0;      /* вызовов за прогон */
static UINTN  fx_rrEarly = 0;      /* вышли пораньше, по HWCFG2[31] */
static UINTN  fx_rrBudgetOut = 0;  /* вышли по исчерпанию бюджета */
static UINT32 fx_rrLast = 0;       /* последнее прочитанное HWCFG2 */
static UINTN  fx_rrSkipped = 0;   /* v3.25: слепой цикл пропущен, потому что
                                   * движок уже был в покое на первом чтении */
static UINTN  fx_rqCalls = 0;      /* ожиданий покоя CPUCTL */
static UINTN  fx_rqFast = 0;       /* усёклись по событию, до бюджета */
static UINTN  fx_rqSlow = 0;       /* бюджет исчерпан, CPUCTL не ушёл в 0 */
static UINT64 fx_rqUs = 0;         /* суммарно мкс */
static UINT64 fx_rqUsMax = 0;      /* максимум по одному вызову */
static UINT32 fx_rqLastCpu = 0;    /* последний прочитанный CPUCTL */
static UINT64 fx_rrUs    = 0;      /* суммарно мкс */

/* v3.21 (этап 7): разрыв между 'early path finished' и входом в рендер.
 *
 * Из прогона v321: 3530 мс между двумя метками, из них 499 мс - сама фаза
 * FLR, то есть 3031 мс в коде, печатающем несколько строк и ни одной
 * метки. Разрыв перекрывает область, слишком широкую для локальной
 * переменной (она от efi_main до render_open_gfx_masks), поэтому метка
 * ставится в двух местах. efi_main выполняется один раз, так что статик
 * здесь безопасен. */
static UINT64 fx_gapT0 = 0;

#define FX_MK_MAX 48
static const CHAR16 *fx_mkName[FX_MK_MAX];
static UINT64 fx_mkUs[FX_MK_MAX];      /* накоплено, мкс */
static UINTN  fx_mkCalls[FX_MK_MAX];
static UINTN  fx_mkNext = 0;

/* Закрыть участок: напечатать метку времени и накопить её в сводку.
 *
 * Заменяет fx_ph_end и fx_ph_end_in одновременно. Различия между ними
 * больше нет и не нужно: вложенность была единственной причиной
 * расхождений, а вместе с ней исчез и повод их различать.
 *
 * ВАЖНО, ЧТО ЗАБЫТЫЙ ВЫЗОВ ТЕПЕРЬ НЕВИДИМ НЕ БУДЕТ. Забытая метка даёт
 * не «сломанную таблицу», а неправдоподобно большую дельту между двумя
 * соседними строками t= в логе. Это видно глазом сразу, тогда как
 * сломанная таблица фаз четыре прогона подряд выглядела правдоподобно. */
static VOID
fx_mk_acc(UINT64 t0, const CHAR16 *name)
{
    UINT64 now = fx_now_us();
    UINTN i;
    log_ms(name);                      /* метка в лог - главный результат */
    if (!t0) return;                   /* часы не откалиброваны */
    for (i = 0; i < fx_mkNext; i++)
        if (fx_mkName[i] == name) break;
    if (i == fx_mkNext) {
        if (fx_mkNext >= FX_MK_MAX) return;
        fx_mkName[i] = name;
        fx_mkUs[i] = 0;
        fx_mkCalls[i] = 0;
        fx_mkNext++;
    }
    if (now > t0) fx_mkUs[i] += now - t0;
    fx_mkCalls[i]++;
}

/* Сводка по накопленным меткам. Печатается всегда, даже если участок
 * встретился один раз: неизвестный участок должен быть виден, а не
 * молча слит с соседним. */
static VOID
fx_mk_report(void)
{
    UINTN i;
    UINT64 tot = 0;
    for (i = 0; i < fx_mkNext; i++) tot += fx_mkUs[i];
    ulogf(L"TIME   === accumulated marks (order: see 'TIME t=' lines) ===\n");
    for (i = 0; i < fx_mkNext; i++) {
        if (!fx_mkCalls[i]) continue;
        ulogf(L"TIME   MK  %-32s %9lld us  x%-4d %3lld%%\n",
              fx_mkName[i], (INT64)fx_mkUs[i], (INTN)fx_mkCalls[i],
              (INT64)(tot ? fx_mkUs[i] * 100 / tot : 0));
    }
    ulogf(L"TIME   MK  %-32s %9lld us\n", L"SUM of marks (not a total)",
          (INT64)tot);
    /* v3.21, этап 7: ИТОГ ПО falcon_wait_reset_ready.
     *
     * Это ответ на один вопрос, поставленный прогоном v321 (PLAN-SPEED.md
     * §7.2), поэтому строка печатается ВСЕГДА, даже если вызовов не было:
     * нулевое значение должно читаться как «проверено, вызовов нет», а не
     * как «забыли напечатать».
     *
     * ЧТО ОЗНАЧАЮТ ЧИСЛА:
     *   early > 0  - функция возвращается по HWCFG2[31], бюджет не
     *                выжигается, и сокращать нечего. Гипотеза опровергнута.
     *   early = 0 и total ≈ calls*1000000
     *              - бюджет выжигается целиком, это и есть та секунда,
     *                которую искали. Следующий этап сокращает бюджет.
     *
     * Печатается ДО строки NOTE, чтобы её не потерять при беглом чтении. */
    ulogf(L"TIME   RESETREADY calls=%d skipped=%d early=%d budgetout=%d "
          L"total=%lldus avg=%lldus last_hwcfg2=0x%08x (slow_iters=%d x 100us)\n",
          (INTN)(fx_rrCalls + fx_rrSkipped), (INTN)fx_rrSkipped,
          (INTN)fx_rrEarly, (INTN)fx_rrBudgetOut,
          (INT64)fx_rrUs,
          (INT64)fx_rrCalls ? fx_rrUs / fx_rrCalls : 0,
          fx_rrLast, FX_RR_SLOW_ITERS);
    /* ШАГ 1 ожидания - то, ради чего всё затевалось. max= это число, по
     * которому этап 10 ставит бюджет. slow>0 означает: движок не ушёл в ноль
     * за секунду, то есть версия о причине неполна и сокращать нельзя. */
    ulogf(L"TIME   QUIESCE calls=%d fast=%d slow=%d total=%lldus "
          L"max=%lldus last_cpuctl=0x%08x (budget=%dus)\n",
          (INTN)fx_rqCalls, (INTN)fx_rqFast, (INTN)fx_rqSlow,
          (INT64)fx_rqUs, (INT64)fx_rqUsMax, fx_rqLastCpu,
          (INTN)FX_RQ_BUDGET_US);
    /* v3.29: сводка по готовности устройства после FLR. Это предмет этапа 14:
     * max= здесь измеренная величина, по которой ставится бюджет паузы
     * 300 мс в вызывающем коде, вместо того чтобы брать её по аналогии. */
    ulogf(L"TIME   FLRREADY calls=%d fast=%d waited=%d never=%d "
          L"total=%lldus max=%lldus last_id=0x%04x last_raw=0x%08x "
          L"(budget=%dus)\n",
          (INTN)fx_flrCalls, (INTN)fx_flrFast, (INTN)fx_flrWaited,
          (INTN)fx_flrNever, (INT64)fx_flrUs, (INT64)fx_flrUsMax,
          fx_flrLastId, fx_flrLastRaw, (INTN)FX_FLR_BUDGET_US);
    ulogf(L"TIME   NOTE: SUM is NOT a phase total and may EXCEED elapsed, "
          L"because marks are nested. For ONE duration use the difference "
          L"of two adjacent 'TIME t=' lines.\n");
}


/* Потолок фазы «реагирует ли CPU». СМ. ВНИЗЕ — почему именно 100 мс.
 *
 * ВНИМАНИЕ, ЭТО ЧИСЛЕННЫЙ ПАРАМЕТР ИЗ ОДНОГО ПРОГОНА. Проверено на
 * карте 2026-10-02: CPUCTL после STARTCPU ведёт себя так —
 *   [E1] BL        : 0x00000000 всё время, НИ РАЗУ не стал STARTCPU
 *   v2.43 cmd scan : 0x00000000 первые ~113 мс, потом 0x00000010
 * То есть 100 мс хватает, чтобы поймать и «вообще не отреагировал», и
 * «отреагировал с задержкой»; для v2.43 потолок срезает ожидание с
 * 113 мс до 100 мс, что несущественно (этот блок теперь выполняется
 * один раз за прогон, а не 24).
 *
 * Если на другой карте CPU отвечает медленнее 100 мс, ожидание срежется
 * и в логе появится verdict=no-response вместе с cpuctl=0x00000000 — по
 * этим двум полям видно, что потолок мал, и его надо поднять. Именно
 * поэтому вердикт печатается всегда, а не только в отладочном виде.
 */
/* v3.17: 100000 -> 22800. ИЗМЕРЕНО, а не оценено.
 *
 * FX_WAKE_MAX_US — это потолок фазы A «проснулся ли CPU». Он зовётся 48 раз
 * за прогон (по 2 на каждую итерацию рендер-цикла), и до этой правки на
 * карте он всегда выдавал полный потолок:
 *     TIME [[E1]] BL settle 100197us   (48 x 100 мс = 4,8 с)
 * При этом сборка V316-OK-113с, где тот же участок занимал 22,8 мс, дала
 * ИДЕНТИЧНЫЙ результат разблокировки (24 из 25, те же строки лога). То есть
 * пауза здесь vestigial: она не влияет на результат.
 *
 * Взят не «на глаз», а значение, измеренное на железе в прогоне
 * usb-log-2026-10-02-V316-OK-113s.txt:
 *     TIME [E1] BL settle 22794us of budget 1000000us
 *     48 вызовов, сумма 1,1 с
 * Разница с 100 мс = 48 x 77 мс = 3,7 с на прогон.
 *
 * ВЕРХНЯЯ ГРАНИЦА СОХРАНЕНА: если на какой-то карте CPU отвечает медленнее,
 * ожидание срежется и в логе появится verdict=no-response вместе с
 * cpuctl=0x00000000. По этим двум полям видно, что потолок мал, и его надо
 * поднять. Поэтому вердикт печатается всегда, а не только в отладочном виде.
 */
#define FX_WAKE_MAX_US    22800
/* ---- Ждать отработки Falcon после CPUCTL=STARTCPU --------------------
 * ПОТОЛКОВ ДВА, И ЭТО СУТЬ ИСПРАВЛЕНИЯ ПОСЛЕ ПРОГОНА 2026-10-02.
 *   нечего: выходим сразу.
 * ИСПОЛЬЗУЕТСЯ ТОЛЬКО ЗДЕСЬ. Ни в одном другом ожидании этот примитив
 * неприменим: см. предупреждение в fx_wait_falcon_halt.
 *
 * Порядок действий, и он неarbitrary:
 *   (1) дождаться, пока CPUCTL == STARTCPU — значит запись защёлкнулась и
 *       Falcon действительно стартовал;
 *   (2) дождаться, пока CPUCTL из STARTCPU уйдёт — значит Falcon отработал.
 *
 * Что НЕЛЬЗЯ делать: ждать «CPUCTL != STARTCPU». Запись CPUCTL=STARTCPU
 * является posted — сразу после неё чтение ещё возвращает старое
 * значение, и это условие истинно с первой итерации. Такая версия
 * выходила через 0-2 мкс вместо 200 мс, и прогон 2026-10-02 это показал
 * строкой «falcon settle 0us (budget 200000us)»: 200 мс ожидания после
 * каждого STARTCPU пропали, WPR2 защёлкнулся 8 раз вместо 24,
 * dbg=0x007E0009, маски открылись 5 из 25 вместо 24.
 *
 * Значение 0x00000000 НЕ считается «отработал»: это либо запись ещё не
 * дошла, либо CPU снят с запуска. Ненулевое значение, отличное от
 * STARTCPU (0x00000010 HALTED, 0xBADF5620 lockdown), читается как
 * «отработал / упал» — там ранний выход оправдан.
 *
 * Бюджет СОХРАНЁН как потолок: если на какой-то карте код считает
 * нужным ждать дольше, он и будет ждать дольше. Фактически затраченное
 * печатается, чтобы недооборот был виден в логе, а не замаскирован.
 */
static UINT64
fx_wait_falcon_halt(UINTN cpuctlReg, UINT64 budgetUs, const CHAR16 *what)
{
    UINT64 t0 = fx_now_us();
    UINT64 wakeDl;                    /* потолок фазы «проснулся ли»   */
    UINT32 cc = 0;
    BOOLEAN started = FALSE;
    const CHAR16 *verdict;

    if (!t0) {                    /* часы не откалиброваны: старый режим */
        uefi_call_wrapper(BS->Stall, 1, (UINTN)budgetUs);
        return budgetUs;
    }

    /* ---- ФАЗА A: реагирует ли CPU вообще ------------------------------
     *
     * Вопрос не «работает ли ещё Falcon», а «заметил ли CPUCTL нашу
     * запись». Если запись не защёлкнулась, CPU не стартует, и ждать
     * дальше бессмысленно: ждать нечего.
     *
     * Именно эту фазу потеряла первая версия. Там был ОДИН потолок на
     * всё, значение 0x00000000 не считалось реакцией, и на [E1] BL
     * цикл отрабатывал полную секунду — 48 раз за прогон:
     *     FWL  [E1]: falcon settle 1023071us (budget 1000000us,
     *                                          cpuctl=0x00000000, started=0)
     *     сумма за прогон: 49,1 с
     * Для сравнения, в сборке FC40F49F тот же участок стоил 1,1 с
     * (48 x 22,8 мс), и результат разблокировки был ИДЕНТИЧЕН: 24 из 25.
     * То есть пауза здесь vestigial — она не влияет на результат, и
     * ждать секунду, доказывая, что ничего не происходит, — чистый расход.
     */
    wakeDl = t0 + FX_WAKE_MAX_US;
    for (;;) {
        cc = mmio_read32(cpuctlReg);
        if (cc == NV_PFALCON_FALCON_CPUCTL_STARTCPU_TRUE) {
            started = TRUE;                 /* старт защёлкнулся */
            break;
        }
        if (cc != 0 && cc != 0xFFFFFFFFU) {
            /* Ненулевое, отличное от STARTCPU: 0x00000010 HALTED или
             * 0xBADF5620 lockdown. CPU отреагировал и уже закончил. */
            verdict = L"finished-immediately";
            goto report;
        }
        if (fx_now_us() >= wakeDl) {
            verdict = L"no-response";
            goto report;
        }
        fx_sleep_us(200);
    }

    /* ---- ФАЗА B: ждём окончания ---------------------------------------
     * Сюда попадаем только если действительно видели STARTCPU. */
    {
        UINT64 dl = t0 + budgetUs;
        for (;;) {
            cc = mmio_read32(cpuctlReg);
            if (cc != NV_PFALCON_FALCON_CPUCTL_STARTCPU_TRUE) break;
            if (fx_now_us() >= dl) {
                Print(L"%s: HALT не дождались за %lldмкс "
                      L"(cpuctl=0x%08x)\n", what, (INT64)budgetUs, (INTN)cc);
                verdict = L"started-timeout";
                goto report;
            }
            fx_sleep_us(200);
        }
        verdict = L"started-then-finished";
    }

report:
    {
        UINT64 spent = fx_now_us() - t0;
        ulogf(L"FWL    %s: falcon settle %lldus (wake=%dus budget=%lldus, "
              L"cpuctl=0x%08x, started=%d, verdict=%s)\n",
              what, (INT64)spent, (INTN)FX_WAKE_MAX_US, (INT64)budgetUs,
              (INTN)cc, (INTN)started, verdict);
        return spent;
    }
}

/* Пауза после STARTCPU там, где раньше была слепая Stall(1 секунда).
 *
 * Пауза нужна, «чтобы код отработал». Но «отработал» — это наблюдаемое
 * событие, а код просто спал фиксированное время независимо от
 * результата. Заменяем на ожидание самого события через
 * fx_wait_falcon_halt, бюджет 1 с сохранён как потолок.
 *
 * Оба таких места вызываются по 24 раза за прогон (по разу на маску),
 * то есть слепая пауза стоила 24 секунды из пяти с половиной минут.
 */
static VOID
fx_settle_after_startcpu(const CHAR16 *tag)
{
    UINT64 spent = fx_wait_falcon_halt(GSP_CPUCTL, 1000000, tag);
    /* v3.17: было "[%s]" при tag = L"[E1]" — в лог уходило "[[E1]]".
     * Формат и тег не совпадали по обрамлению. Тег печатается как есть:
     * строка FWL с тем же tag выглядит как «FWL [E1]:», значит и здесь
     * квадратные скобки должны быть ровно одни. */
    ulogf(L"TIME   %s BL settle %lldus of budget 1000000us\n", tag,
          (INT64)spent);
}

static VOID
falcon_dma_wait_idle(void)
{
    FX_POLL p;
    fx_poll32(SEC2_DMATRFCMD, 0x2u, 0x2u, 1000000, FX_DMAQ_STUCK,
              FX_DMAQ_MAX_US, &p);
    if (p.value & 0x2u) return;
    ulogf(L"DMAQ2  SEC2 queue not IDLE, gave up after %d reads / %lldus "
          L"(stuck=%d overtime=%d) cmd=0x%08x\n",
          (INTN)p.reads, (INT64)p.us, (INTN)p.stuck, (INTN)p.overtime,
          (INTN)p.value);
}

/* ==== Post-reset scrub wait (driver-equivalent, MANDATORY) ====
 * Mirrors kflcnPreResetWait/kflcnWaitForScrubbingToFinish: after an
 * ENGINE reset the Falcon scrubs IMEM/DMEM with DEAD5EC* patterns;
 * DMA issued during scrubbing races the scrubber and gets erased
 * ("DEAD5EC1 everywhere", halts). Wait for DMACTL[2:1]==0 && HWCFG2[12]==0:
 * Драйвер: kflcnPreResetWait_GA102 (HWCFG2.RESET_READY до сброса) +
 * kflcnWaitForResetToFinish_GA102 + _kflcnWaitForScrubbingToFinish
 * (DMACTL[2:1]=IMEM/DMEM скраббинг идёт, HWCFG2[12]=MEM_SCRUBBING идёт;
 * 0 = готово). После сброса Фалкон ЗАЧИЩАЕТ IMEM/DMEM паттерном DEAD5EC* —
 * без ожидания DMA-записи соревнуются со скраббером и стираются!
 * Именно это давало «DEAD5EC1 везде», «SEC=1 DMA не доставляет» и halt'ы. */
#define SEC2_HWCFG2             (NV_PSEC_BASE + 0x0F4)
#define GSP_HWCFG2              (GSP_BASE  + 0x0F4)
/* ЗДЕСЬ РАННИЙ ВЫХОД ПО «РЕГИСТРЫ НЕ МЕНЯЮТСЯ» НЕДОПУСТИМ.
 *
 * Это ожидание работы железа, а не ожидание состояния. После ENGINE-reset
 * Falcon затирает IMEM/DMEM паттерном DEAD5EC*; DMA, отправленная во время
 * затирания, соревнуется со скраббером и стирается. Отсюда «DEAD5EC1
 * везде», «SEC=1 DMA не доставляет» и halt'ы.
 *
 * Почему «не меняется» здесь НЕ значит «готово». Пауза между итерациями
 * 100 мкс, то есть несколько одинаковых чтений — это десятки мкс тишины.
 * Скраб IMEM объёмом 0xE200 длится дольше, и всё это время регистры стоят
 * одинаковыми: сначала DMACTL[2:1] выставляется, память затирается, и
 * только потом биты снимаются. То есть ровно в том окне, где скраб ещё
 * ИДЁТ, регистры и не меняются.
 *
 * В первой версии v3.16 здесь стоял выход «оба регистра 64 чтения подряд не
 * меняются -> вернуть FALSE». Он срабатывал именно в этом окне, FALSE
 * игнорировался вызывающим кодом, и DMA уходила в затираемую память.
 * Симптом на прогоне 2026-10-02 ровно предсказуемый:
 *     WPR2 ESTABLISHED  8 раз  (было 24)
 *     dbg=0x007E0009            (было 0x00000000) — ядро стартует и гибнет
 *     IVER empty=1 x4           — DMA не доставила
 *     маски открылись 5 из 25   (было 24 из 25)
 *
 * Здесь «жди или умирай» — единственно правильное поведение. Ускорить это
 * нельзя: это ожидание реальной работы, а не пустое вращение (в отличие от
 * gsp_dma_wait_*, где регистр замирает намертво).
 *
 * Потолок по времени FX_SCRUB_MAX_US равен прежнему бюджету итераций
 * (30 000 x 100 мкс = 3 с) и ничего не ускоряет — он только выражает
 * ограничение в единицах, не зависящих от машины. Фактическое время
 * печатается в лог: это те данные, которых раньше не было. */
static BOOLEAN
falcon_wait_scrub_done(UINT32 dmactlReg, UINT32 hwcfg2Reg, const CHAR16 *tag)
{
    UINTN i;
    UINT32 dct = 0xFFFFFFFF, hcfg = 0xFFFFFFFF;
    UINT64 t0 = fx_now_us();
    for (i = 0; i < 30000; i++) {
        dct = mmio_read32(dmactlReg);
        if ((dct & 0x6) == 0) {
            hcfg = mmio_read32(hwcfg2Reg);
            if (!(hcfg & (1 << 12)))
                goto done;
        }
        if (t0 && fx_now_us() - t0 >= FX_SCRUB_MAX_US) break;
        uefi_call_wrapper(BS->Stall, 1, 100);
    }
    Print(L"%s: scrub-wait ТАЙМАУТ dmactl=0x%08x hwcfg2=0x%08x\n", tag, dct, hcfg);
done:
    ulogf(L"SCRUB  %s: %lldus (%d polls) dmactl=0x%08x hwcfg2=0x%08x %s\n",
          tag, (INT64)(fx_now_us() - t0), (INTN)i, (INTN)dct, (INTN)hcfg,
          ((dct & 0x6) == 0 && !(hcfg & (1 << 12))) ? L"done" : L"NOT done");
    return ((dct & 0x6) == 0 && !(hcfg & (1 << 12)));
}

/* ждать RESET_READY (HWCFG2[31]) ДО сброса — как kflcnPreResetWait_GA102
 *
 * ============================ v3.23, ЭТАП 8 ============================
 *
 * БЫЛО: for (i = 0; i < 10000; i++) { if (HWCFG2 & (1<<31)) return;
 *                                           Stall(100); }
 *       то есть бюджет 10 000 x 100 мкс = РОВНО 1,000 с, и вернуться
 *       раньше можно ТОЛЬКО если выставится HWCFG2[31].
 *
 * ИЗМЕРЕНО НА ЖЕЛЕЗЕ (прогон v3.22, md5 47C3F0E68ACEB494D10E2E3FE9E942B8,
 * usb-log-v322.txt):
 *
 *     TIME  RESETREADY calls=37 early=0 total=41538580us avg=1122664us
 *
 * 37 вызовов, НОЛЬ ранних выходов, 41,54 с из 56,08 с прогона - то есть
 * 74,1 % времени уходило в эту функцию. За все 37 вызовов бит 31 не
 * выставился ни разу; в логе 29 строк SCRUB, и во всех hwcfg2=0x000067F7,
 * то есть бит 31 не выставлен и в замерах scrub.
 *
 * СТАЛО: 500 итераций = 50 мс.
 *
 * ПОЧЕМУ ИМЕННО 50 МС, А НЕ 10 И НЕ 20. У этой функции ДВА эффекта, и их
 * нельзя смешивать:
 *   1) опрос признака готовности - на этой карте он бесполезен, признак
 *      не выставляется (0 из 37), то есть сокращать его не жалко;
 *   2) ПАУЗА между предыдущей MMIO-записью и сбросом движка - а вот её
 *      сокращать опасно, потому что в коде рядом стоит Stall(50000)
 *      ровно с этой же ролью, и он считается достаточным.
 * Взять тот же порядок, что и у уже работающего Stall(50000), - значит
 * не вносить новую величину, а использовать проверенную. Экономия при
 * этом 39,5 с; при 20 мс была бы 40,7 с, то есть на 1,2 с больше ценой
 * непроверенной величины.
 *
 * ЧТО ПРОВЕРЯЕТСЯ. Каждый выход пораньше печатается и считается в fx_rrEarly.
 * Если HWCFG2[31] начнёт выставляться, это сразу видно в сводке, и бюджет
 * можно вернуть обратно - уже с пониманием, на сколько. Настоящая же
 * проверка результата - readback каждой маски и приёмка: 8 из 8 плюс
 * GFX_SPEED_SELECT=0x00000004 плюс dbg=0x00000000. Если 50 мс не хватит,
 * маски просто не откроются и приёмка упадёт сразу.
 *
 * ЧЕГО ЭТА ПРАВКА НЕ ДЕЛАЕТ. Не меняет ни порядок, ни значения записей в
 * регистры. Не убирает вызовы, только их бюджет. Не трогает
 * falcon_wait_scrub_done - тот ждёт РЕАЛЬНОЕ событие и отрабатывает за
 * 103 мкс (замерено), то есть трогать его нечего.
 *
 * ИТОГ ПРАВКИ: 41,54 с -> 2,08 с, то есть прогон 56,1 с -> ожидалось
 * 16,6 с.
 *
 * ============================ v3.24, ЭТАП 9 ============================
 *
 * ЭТОТ ПРОГОН ОПРОВЕРГ ПРАВКУ ВЫШЕ, И ЭТО ЗАСЛУЖЕННЫЙ ОТКАЗ.
 *
 * Факт: v3.23 (md5 5A1165367234A09EAD2A42334A90C97A, usb-log-v323.txt)
 * дал 58 535 мс - МЕДЛЕННЕЕ v3.22 - и 0 из 8 масок. Счётчик при этом
 * сработал точно по расчёту: RESETREADY calls=29 early=0 budgetout=29
 * total=1629959us avg=56205us.
 *
 *   v322 (рабочий)             v323 (сломан)
 *   WPR2 ESTABLISHED   18      2
 *   FWSEC ours FAIL     0     16
 *   XVE window open  8 из 8    0 из 8
 *
 * МЕХАНИЗМ, ИЗМЕРЕННЫЙ ПО ДВУМ ПРОГОНАМ. Строки WAIT показывают CPUCTL на
 * момент загрузки FWSEC:
 *   v322: cpuctl=0x00000000 в 18 из 18   -> FWSEC выполняется
 *   v323: cpuctl=0x00000010 в 64 из 64   -> FWSEC не выполняется
 * По собственному словарю кода (строка 2707) 0x00000010 = HALTED.
 *
 * То есть секунда ждала НЕ признака, а УХОДА CPUCTL в нулевое состояние
 * перед сбросом движка. Слепой цикл по HWCFG2[31] действительно бесполезен
 * (это осталось верным), но задержка, которую он случайно давал,
 * НЕОБХОДИМА. Мой вывод 'функция ни на что не влияет, кроме ожидания' был
 * верен - и я из него не сделал правильного следующего шага: я проверил
 * стоимость и НЕ проверил необходимость.
 *
 * ЧТО СДЕЛАНО В ЭТАПЕ 9. Перед слепым циклом добавлено ожидание НАСТОЯЩЕГО
 * события: CPUCTL уходит в 0x00000000 либо в BADF-лок. Бюджет этого
 * ожидания - 1 с, то есть ровно прежняя полная стоимость.
 *
 * СВОЙСТВО, КОТОРОЕ ДЕЛАЕТ ЭТОТ ШАГ БЕЗОПАСНЫМ: худший случай равен v322.
 * Если движок не уйдёт в ноль за секунду, будет потрачено ровно то же, что
 * тратилось в заведомо рабочем прогоне. То есть хуже рабочего состояния
 * уйти НЕЛЬЗЯ - даже если моя версия механизма ошибочна. Если верна, выход
 * происходит по событию и время падает.
 *
 * САМОПРОВЕРКА. Считаются: сколько раз событие наступило (rqFast), сколько
 * раз бюджет исчерпан (rqSlow), суммарное и максимальное время, последний
 * прочитанный CPUCTL. Если rqSlow заметно ненулевой, значит механизм не в
 * том, и это будет видно сразу, а не по обрыву масок.
 *
 * ============================ v3.27, ЭТАП 12 ============================
 *
 * ЭТАП 12: ПОИСК ПОРОГА. Бюджет FX_RQ_BUDGET_US делится пополам, потому что
 * измерены две точки: 50 мс = FAIL (v3.23, рендер сломан, 0 из 8),
 * 1000 мс = PASS (v3.24/25/26). Порог лежит в (50 мс; 1000 мс].
 *
 * Прогон v3.26 показал, что бюджет тратят только ТРИ места из десяти
 * медленных вызовов:
 *     rr: [E1] BL reset-ready        x8  cpuctl=0x00000010   8083,9 мс
 *     rr: [E3] ResetIntoRiscv ready  x1  cpuctl=0x00000010   1010,9 мс
 *     rr: post-WPR2 sec2 ready       x1  cpuctl=0x00000010   1010,2 мс
 * То есть 80 % этой статьи - восемь повторов одного места перед сбросом GSP
 * в early_unlock_path. Остальные 27 мест из 37 отвечают мгновенно.
 *
 * ЧЕГО ЭТОТ ЭТАП НЕ ДЕЛАЕТ. Он НЕ добавляет 0x00000010 в условие покоя,
 * хотя очень хочется: 'CPU остановился' выглядит как покой, и одной строкой
 * это дало бы 25,6 -> 15,5 с. Это ровно то, что сломало рендер в этапе 8:
 * при удалённой задержке на этих местах FWSEC грузился при cpuctl=0x00000010
 * и давал dbg=0x007E0009, то есть 0 из 8 масок. Задержка здесь несущая, а
 * HALTED условием покоя не является.
 * ===================================================================== */

/* Один шаг ожидания покоя CPUCTL. Возвращает TRUE, когда движок ушёл.
 *
 * Условие покоя - CPUCTL читается как 0x00000000 либо как BADF-лок.
 * 0x00000000 означает, что CPU не выполняет ничего; 0x00000010 означает
 * HALTED, то есть CPU отработал и держит состояние - по измерению
 * прогона v3.23 именно это состояние ломает загрузку FWSEC.
 * BADF-лок тоже считаем покоем: там управление не наше, ждать бессмысленно,
 * и именно это проверяется условием (cc & 0xBADF0000) == 0xBADF0000 в трёх
 * местах кода. */
static BOOLEAN
fx_engine_quiesced(UINT32 cc)
{
    if (cc == 0) return TRUE;
    if ((cc & 0xBADF0000) == 0xBADF0000) return TRUE;
    return FALSE;
}

/* Ожидание покоя движка перед его сбросом. Это ТО, что делала секунда,
 * только по событию, а не по константе.
 *
 * Возвращает TRUE, если движок УЖЕ В ПОКОЕ на первом же чтении, то есть
 * задержка не была нужна вовсе. Эта правка - весь этап 10.
 *
 * ПОЧЕМУ ЭТО РЕШАЕТ ПРОБЛЕМУ, ИЗМЕРЕННУЮ В ПРОГОНЕ v3.24:
 *     QUIESCE calls=37 fast=27 slow=10 total=10006154us max=1000952us
 * 27 мест из 37 отвечают МГНОВЕННО (~0,1 мс): движок уже в покое, и секунда
 * слепого ожидания там ждала впустую. 10 мест не отвечают никогда и стоят
 * по ~1,0003 с. То есть секунда нужна ровно на 10 местах из 37, а платилась
 * на всех 37.
 *
 * ЗАПАС ПОСЛЕ СОБЫТИЯ. Даже когда движок уже в покое, даётся короткий
 * запас FX_RQ_SETTLE_US. Это не «магическое число»: 10 мс на порядок ниже
 * fx_settle (22,8 мс), на который этот же код уже опирается как на
 * достаточный. Стоит 0,27 с на весь прогон.
 */
static BOOLEAN
falcon_wait_engine_quiesced(const CHAR16 *tag, UINT32 cpuctlReg)
{
    UINT64 t0 = fx_now_us(), dl;
    UINT32 cc;
    BOOLEAN already = FALSE, wasSlow = FALSE;
    if (!t0) return FALSE;              /* часы не откалиброваны */
    fx_rqCalls++;
    cc = mmio_read32(cpuctlReg);
    if (fx_engine_quiesced(cc)) {
        /* ДВИЖОК УЖЕ В ПОКОЕ. Никакой задержки не требуется: читаем один
         * раз и выходим. Именно эти 27 мест в прогоне v3.24 ждали по
         * секунде впустую. */
        already = TRUE;
        fx_rqFast++;
        goto out;
    }
    dl = t0 + FX_RQ_BUDGET_US;
    for (;;) {
        if (fx_now_us() >= dl) {        /* бюджет: худший случай = v322 */
            fx_rqSlow++;
            wasSlow = TRUE;
            cc = mmio_read32(cpuctlReg);   /* финальное чтение для лога */
            goto out;
        }
        uefi_call_wrapper(BS->Stall, 1, FX_RQ_POLL_US);
        cc = mmio_read32(cpuctlReg);
        if (fx_engine_quiesced(cc)) {
            fx_rqFast++;
            goto out;
        }
    }
out:
    /* Запас после срабатывания события - в обоих случаях. Раньше здесь стояло
     * условие 'already || fx_rqFast == 0', но fx_rqFast - глобальный счётчик,
     * который эта же строка только что увеличила, то есть условие было всегда
     * ложно и запас не давался никогда. Замечено при чтении правки, до
     * прогона: проверка 'всегда ложно' делается в уме, а не на железе. */
    uefi_call_wrapper(BS->Stall, 1, FX_RQ_SETTLE_US);
    {
        UINT64 d = fx_now_us() - t0;
        fx_rqUs += d;
        if (d > fx_rqUsMax) fx_rqUsMax = d;
        fx_rqLastCpu = cc;
        /* v3.26: ПОИМЯННЫЙ СПИСОК МЕДЛЕННЫХ МЕСТ.
         *
         * Сводка QUIESCE сливает все 37 вызовов в три числа, поэтому из
         * прогона v3.25 известно только ЧТО десять мест медленные, но не
         * ГДЕ ИМЕННО. Любая правка после этого была бы прикидкой - ровно
         * та ошибка, которая стоила этапу 8 сломанного рендера, а этапу 9
         * десяти лишних секунд.
         *
         * Поэтому каждый медленный вызов печатает отдельную строку: имя
         * места, состояние CPUCTL, на котором ожидание остановилось, и
         * сколько ждали. Десять строк за прогон по 10 мкс - то есть ничего.
         *
         * Имя места - это tag вызывающего кода, то есть ровно то, что
         * уже видно в строках 'rr: ...' из этапа 7. */
        if (wasSlow)
            ulogf(L"QSLOW  %s cpuctl=0x%08x waited=%lldus "
                  L"(budget exhausted, engine did NOT quiesce)\n",
                  tag, cc, (INT64)d);
        /* Метка ставится по ТОЙ ЖЕ схеме, что и раньше, но теперь видно и
         * время ожидания события, и сколько раз бюджет исчерпан. */
        fx_mk_acc(t0, tag);
    }
    return already;
}

static void
falcon_wait_reset_ready(const CHAR16 *tag, UINT32 hwcfg2Reg, UINT32 cpuctlReg)
{
    UINT64 t0;
    BOOLEAN already;

    /* ШАГ 1: ждать НАСТОЯЩЕЕ событие - уход CPUCTL в ноль либо BADF-лок.
     *
     * Здесь же берётся ЗАПАЗА 10 мс (внутри функции), то есть место, где
     * движок уже в покое, получает и паузу, и проверку. */
    already = falcon_wait_engine_quiesced(tag, cpuctlReg);

    /* ШАГ 2: слепой цикл по HWCFG2[31]. На этой карте условие не выставляется
     * ни разу (0 из 37 в v3.22 и 0 из 37 в v3.24), то есть цикл функцией не
     * является и остаётся только ради другого кремния.
     *
     * ============ v3.25, ЭТАП 10: ЦИКЛ БОЛЬШЕ НЕ ЗАПУСКАЕТСЯ ВПУСТУЮ =========
     *
     * В прогоне v3.24 платились ОБА ожидания подряд, и на 10 местах, где
     * событие не наступает, выходило по 2 секунды вместо одной. Отсюда
     * регрессия 56,1 -> 66,2 с при полностью рабочей графике.
     *
     * Теперь, если движок уже в покое (already=TRUE), задержку даёт ШАГ 1
     * плюс его 10 мс запаса, и слепой цикл пропускается целиком. Именно эти
     * 27 мест в v3.24 ждали по секунде впустую.
     *
     * Если событие НЕ наступило, ШАГ 1 уже израсходовал свои 1,000 с - то
     * есть ровно прежнюю полную стоимость, - и цикл с полным бюджетом
     * поверх этого давал бы вторую секунду. Поэтому здесь он оставлен с
     * коротким бюджетом 500 итераций (50 мс) как страховка, а не как
     * источник задержки.
     *
     * ИТОГ, СЧИТАЯ ЧЕСТНО. На медленных местах проходит 1,000 с (бюджет
     * ШАГ 1) + 10 мс (запас) + 56 мс (страховка) = 1,066 с. Заведомо
     * рабочий v3.22 на этих местах давал 1,123 с. То есть на 57 мс МЕНЬШЕ,
     * а не больше.
     *
     * Разница целиком объяснима: старый цикл делал 10 000 MMIO-чтений по
     * 12,3 мкс = 123 мс накладных расходов сверх бюджета, новый делает
     * 500 чтений = 6 мс. Минус 117 мс накладных плюс 10 мс запаса = минус
     * 57 мс. Содержательная часть задержки - те же самые 1,000 с.
     *
     * Утверждать 'не меньше рабочего состояния' здесь нельзя: это было бы
     * приукрашиванием на 5 %. Правильная формулировка: содержательная
     * задержка совпадает с рабочей, отличается лишь накладной расход
     * чтений, и он уменьшен.
     *
     * Ожидание: 51,6 с -> 10,9 с, прогон 66,2 с -> ожидается 25,5 с.
     */
    if (already) {
        fx_rrSkipped++;
        return;
    }
    t0 = fx_now_us();
    UINTN i;
    fx_rrCalls++;
    for (i = 0; i < FX_RR_SLOW_ITERS; i++) {
        if (mmio_read32(hwcfg2Reg) & (1u << 31)) {
            /* v3.21: выход пораньше СОБЫТИЕ. Значит бюджет не выжигается.
             * Считаем и печатаем, чтобы сокращение не осталось незамеченным. */
            fx_rrEarly++;
            fx_rrUs += fx_now_us() - t0;
            fx_mk_acc(t0, tag);
            return;
        }
        uefi_call_wrapper(BS->Stall, 1, 100);
    }
    /* v3.21: ЦИКЛ ИСЧЕРПАН, БЮДЖЕТ ИЗРАСХОДОВАН ЦЕЛИКОМ. Ровно этот путь
     * и есть предмет гипотезы §7.2 плана. Ничего не меняем - только
     * считаем, чтобы прогон дал число вместо догадки. */
    fx_rrUs += fx_now_us() - t0;
    fx_rrLast = mmio_read32(hwcfg2Reg);   /* v3.23: последнее прочитанное */
    fx_rrBudgetOut++;
    fx_mk_acc(t0, tag);
}

static void
falcon_dma_transfer(UINT32 dest, UINT32 memOff, UINT64 srcPhys, UINT32 size, UINT32 dmaCmd)
{
    UINT32 bytesXfered = 0;

    falcon_dma_wait_not_full();
    mmio_write32(SEC2_DMATRFBASE, (UINT32)(srcPhys >> 8));
    mmio_write32(SEC2_DMATRFBASE1, (UINT32)((srcPhys >> 8) >> 32) & 0x1FF);

    while (bytesXfered < size) {
        falcon_dma_wait_not_full();
        mmio_write32(SEC2_DMATRFMOFFS, dest);
        mmio_write32(SEC2_DMATRFFBOFFS, memOff);
        mmio_write32(SEC2_DMATRFCMD, dmaCmd);
        bytesXfered += FLCN_BLK_ALIGNMENT;
        dest       += FLCN_BLK_ALIGNMENT;
        memOff     += FLCN_BLK_ALIGNMENT;
    }
    falcon_dma_wait_idle();
}

/* ==== Legacy: ucode upload via IMEMC/DMEMD debug ports (diagnostics) ====
 * When the DMA engine is priv-locked the window ports still answer, so
 * images can be poked word-by-word (IMEM needs the SECURE bit28, like
 * SEC=1 DMA). Not used by the release flow:
 * DMATRF-движок залочен привилегированным доступом (как WPR2 — v2.16:
 * запись не прилипает; v2.17: IMEM заскраблен DEAD5EC1 — DMA не передал).
 * Порты IMEMC/IMEMD (0x840180/4) и DMEMC/DMEMD (0x8401C0/4) доступны
 * (v2.17 прочитал через них DEAD5EC1). Грузим образ напрямую. */
static void
sec2_load_image_via_ports(UINT64 ucodePhys)
{
    const UINT8 *img = (const UINT8*)(UINTN)ucodePhys;
    UINTN i;
    UINT32 imemSec;

    /* v2.20: IMEM пишем с IMEMC_SECURE (bit28) — как DMA с SEC=1! Драйвер
     * грузит код secure-передачей; v2.19: сигнатура (DMEM non-secure) прошла,
     * но код в non-secure IMEM — BROM читает SECURE IMEM (пуст) → dbg=0x0. */
    imemSec = (1 << 28);            /* IMEMC_SECURE */
    Print(L"booter: загрузка IMEM через порты (SECURE, %d слов)...\n",
          BOOTER_APP_CODE_SIZE / 4);
    mmio_write32(SEC2_IMEMC0, imemSec | (1 << 24));  /* SECURE | AINCW */
    for (i = 0; i < BOOTER_APP_CODE_SIZE / 4; i++)
        mmio_write32(SEC2_IMEMD0, *(UINT32*)(img + BOOTER_APP_CODE_OFFSET + i * 4));

    /* DMEM: данные image[0x8A00..] → DMEM 0..0x6200 (dmemPa=0), SEC=0 как в DMA */
    Print(L"booter: загрузка DMEM через порты (%d слов)...\n",
          BOOTER_OS_DATA_SIZE / 4);
    mmio_write32(SEC2_DMEMC0, (1 << 24));  /* AINCW */
    for (i = 0; i < BOOTER_OS_DATA_SIZE / 4; i++)
        mmio_write32(SEC2_DMEMD0, *(UINT32*)(img + BOOTER_OS_DATA_OFFSET + i * 4));

    /* верификация: IMEM читаем с SECURE, DMEM без */
    mmio_write32(SEC2_IMEMC0, imemSec);   /* SECURE, addr 0 */
    Print(L"booter: IMEM[0x00]=%08x (ожидаю %08x)\n",
          mmio_read32(SEC2_IMEMD0), *(UINT32*)(img + BOOTER_APP_CODE_OFFSET));
    mmio_write32(SEC2_IMEMC0, imemSec | 0x100);
    Print(L"booter: IMEM[0x100]=%08x (ожидаю %08x)\n",
          mmio_read32(SEC2_IMEMD0), *(UINT32*)(img + BOOTER_APP_CODE_OFFSET + 0x100));
    mmio_write32(SEC2_DMEMC0, 0x10);
    Print(L"booter: DMEM[0x10]=%08x (ожидаю sig %08x)\n",
          mmio_read32(SEC2_DMEMD0), *(UINT32*)(img + BOOTER_OS_DATA_OFFSET + 0x10));
}

/* ==== Kill GFW — the GPU-firmware instance booted by VBIOS at POST ====
 * kgspResetHw_TU102 replica: ENGINE._RESET=TRUE -> reads -> FALSE.
 * While GFW lives, SEC2 answers 0xBADF5620 (priv lockdown); the driver
 * kills it right before the booter load:
 * kgspResetHw_TU102: NV_PGSP_FALCON_ENGINE._RESET=TRUE → чтения → FALSE.
 * Живой GFW (загруженный VBIOS при POST) держит SEC2 в priv-lock
 * (0xBADF5620 на CPUCTL/DMATRF/FBIF). Драйвер убивает его до booter load. */
static void
gsp_engine_reset(void)
{
    UINTN i;

    Print(L"gsp: ENGINE reset (0x1103C0) — убиваю GFW из POST...\n");
    mmio_write32(GSP_ENGINE, NV_PFALCON_FALCON_ENGINE_RESET_TRUE);
    for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
    mmio_write32(GSP_ENGINE, 0);
    for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
}

/* ==== FWSEC HS-boot on GSP -> FRTS command -> WPR2 latched ====
 * Replica of kgspExecuteHsFalcon_GA102 + s_prepareForFwsec_TU102:
 * kflcnReset(GSP) -> patch DMEM (sig@0x5A4 + FRTS cmd interface) ->
 * FBIF/DMA setup -> DMA IMEM(SEC=1, 0xE200)+DMEM(SEC=0, 0x800) ->
 * BROM params (PKC RSA3K) -> BOOTVEC=0 -> STARTCPU -> poll WPR2
 * (FRTS programs NV_PFB_PRI_MMU_WPR2). With WPR2 up, the subsequent
 * SEC2 booter load proceeds. Driver reference values: frts_err=0,
 * Репликация kgspExecuteHsFalcon_GA102 + s_prepareForFwsec_TU102 (610.43.03):
 *   kflcnReset(GSP) → патчинг DMEM (sig@0x5A4 + FRTS-интерфейс) → TRANSCFG →
 *   DMA IMEM(SEC=1, 0xE200) + DMEM(SEC=0, 0x800) → BROM params (PKC RSA3K) →
 *   BOOTVEC=0 → STARTCPU → ждём WPR2 (FRTS ставит NV_PFB_PRI_MMU_WPR2).
 * Результат: WPR2 установлен → SEC2 booter load (v2.24) пройдёт (dbg≠0).
 * (В драйвере подтверждено: frts_err=0, wpr2=[frtsOffset, frtsOffset+0xE00]
 *  — то есть ровно TARGET_WPR2_LO/TARGET_WPR2_HI.) */
/* v3n: счётчики таймаутов опроса DMA (2026-09-29).
 * Предупреждения об этих таймаутах печатались через Print(), то есть
 * ТОЛЬКО на экран, и в область лога на флешке не попадали ни разу за всю
 * историю проекта. Из-за этого «этих строк нет ни в одном логе» читалось
 * как «их никогда не было», хотя правильный вывод был «их туда не пишут»
 * (KNOWN-ISSUES §42.7). Теперь пишем и на экран, и в лог: без лога
 * состояние DMA-очереди при сбое невозможно расследовать постфактум. */
static UINTN g_dmaFullTo  = 0;   /* таймаутов ожидания «не FULL» */
static UINTN g_dmaIdleTo  = 0;   /* таймаутов ожидания «IDLE» */
static UINTN g_dmaFullLast = 0;  /* значение cmd в последнем таком таймауте */
static UINTN g_dmaIdleLast = 0;

static void
gsp_dma_wait_not_full(void)
{
    /* v3.16: было for (i=0;i<20000;i++) без потолка по времени.
     * По логу очередь на этой карте не разгружается НИКОГДА
     * (cmd=0x00000615 на всех 1656 таймаутах), то есть все 20 000
     * чтений были ожиданием неизменимого состояния. Теперь тот же бюджет
     * итераций остаётся верхней границей, но добавлены потолок по
     * времени и выход по «регистр замер». Фактическая цена каждого
     * ожидания печатается в лог. */
    FX_POLL p;
    fx_poll32(GSP_DMATRFCMD, 0x1u, 0x0u, 20000, FX_DMAQ_STUCK,
              FX_DMAQ_MAX_US, &p);
    if ((p.value & 0x1u) == 0) return;
    g_dmaFullTo++;
    g_dmaFullLast = p.value;
#ifdef RENDER_MASKS
    /* v3.13: ПРОБЕЛ БУДИЛЬНИКА. На 17 вызовах early_unlock_path набралось
     * 1704 строки DMAQ - 80 % кольцевого лога, из-за чего начало прогона
     * затиралось. Счётчики g_dmaFullTo/g_dmaIdleTo и их итоговая печать
     * остаются, поэтому данные не теряются: полные первые 2 события,
     * дальше каждая 32-я. Под #ifdef RENDER_MASKS - см. предупреждение
     * в wpr2_probe: без ограждения откат v3n перестаёт быть тем бинарём,
     * который дал x11.25, и это происходит МОЛЧА. */
    if (g_dmaFullTo > 2 && (g_dmaFullTo % 32) != 0) return;
#endif
    Print(L"fwsec: ВНИМАНИЕ DMA queue FULL (cmd=0x%08x)\n", g_dmaFullLast);
    ulogf(L"DMAQ   FULL timeout #%d cmd=0x%08x (bit0=FULL set, bit1=IDLE "
          L"clear) cost=%d reads/%lldus exit=%s\n",
          (INTN)g_dmaFullTo, (INTN)g_dmaFullLast, (INTN)p.reads, (INT64)p.us,
          p.stuck ? L"stuck" : (p.overtime ? L"overtime" : L"iterations"));
}

static void
gsp_dma_wait_idle(void)
{
    FX_POLL p;
    fx_poll32(GSP_DMATRFCMD, 0x2u, 0x2u, 20000, FX_DMAQ_STUCK,
              FX_DMAQ_MAX_US, &p);
    if (p.value & 0x2u) return;
    g_dmaIdleTo++;
    g_dmaIdleLast = p.value;
#ifdef RENDER_MASKS
    /* см. комментарий в gsp_dma_wait_not_full: тот же пробел будильника
     * и то же обязательное ограждение RENDER_MASKS */
    if (g_dmaIdleTo > 2 && (g_dmaIdleTo % 32) != 0) return;
#endif
    Print(L"fwsec: ВНИМАНИЕ DMA не IDLE (cmd=0x%08x)\n", g_dmaIdleLast);
    ulogf(L"DMAQ   IDLE timeout #%d cmd=0x%08x (bit1=IDLE set, bit0=FULL "
          L"clear) cost=%d reads/%lldus exit=%s\n",
          (INTN)g_dmaIdleTo, (INTN)g_dmaIdleLast, (INTN)p.reads, (INT64)p.us,
          p.stuck ? L"stuck" : (p.overtime ? L"overtime" : L"iterations"));
}

static void
gsp_dma_transfer(UINT32 dest, UINT32 memOff, UINT64 srcPhys, UINT32 size, UINT32 dmaCmd)
{
    UINT32 bytesXfered = 0;

    gsp_dma_wait_not_full();
    mmio_write32(GSP_DMATRFBASE, (UINT32)(srcPhys >> 8));
    mmio_write32(GSP_DMATRFBASE1, (UINT32)((srcPhys >> 8) >> 32) & 0x1FF);

    while (bytesXfered < size) {
        gsp_dma_wait_not_full();
        mmio_write32(GSP_DMATRFMOFFS, dest);
        mmio_write32(GSP_DMATRFFBOFFS, memOff);
        mmio_write32(GSP_DMATRFCMD, dmaCmd);
        bytesXfered += FLCN_BLK_ALIGNMENT;
        dest       += FLCN_BLK_ALIGNMENT;
        memOff     += FLCN_BLK_ALIGNMENT;
    }
    gsp_dma_wait_idle();
}

/* Физический адрес нашего FWSEC-буфера — нужен только для сверки с тем,
 * что реально лежит в IMEM карты. */
static UINT64 g_fwsecPhys = 0;

/* ==== FWSEC без DMA: запустить тот, что карта загрузила сама ====
 *
 * ПОРТ НА 70HX. Наш FWSEC-образ — правильный (DMEM+0x0A содержит 0x248A,
 * то есть именно этот кристалл), но ПРИЛОЖЕННАЯ К НЕМУ ПОДПИСЬ невалидна:
 * fwsec_ga104_sig.bin побайтово равен fwsec_ga102_sig.bin, а образы разные
 * (различаются device ID и 32-байтный блоб по 0x540). RSA-подпись считается
 * по содержимому — одинаковой у разных образов она быть не может.
 * Симптом ровно такой: BROM стартует ядро (CPUCTL=0x10), проверка подписи
 * проваливается, DEBUGINFO=0x780009, WPR2 остаётся постуровым 0x1FFFFE00.
 *
 * Обход: НЕ грузить свой образ вообще. После POST в IMEM GSP уже лежит
 * ФИРМЕННЫЙ FWSEC, загруженный VBIOS карты (см. v2.40 в fwsec_boot_gsp:
 * запись в IMEM до 0xE400 ломает этот код — значит он там и сидит, и он же
 * переживает kflcnReset). Он подписан самой картой, его подпись заведомо
 * валидна, и в его DMEM FRTS-команда уже собрана под РЕАЛЬНЫЙ кадровый буфер
 * этой карты — то есть нам не нужно знать ни frtsOffset, ни подпись.
 *
 * Делаем ровно то, что делает драйвер: reset -> FBIF/DMACTL/TRANSCFG ->
 * BROM-параметры (sig@0x5A4, ucodeId=9) -> BOOTVEC=0 -> STARTCPU -> ждём WPR2.
 * Ни одного байта в IMEM не пишем.
 */
static BOOLEAN
fwsec_preloaded_gsp(void)
{
    UINTN i;
    UINT32 data;
    UINT32 lo0, hi0;

    Print(L"\n--- FWSEC ПРЕДЗАГРУЖЕННЫЙ (без DMA, подпись карты) ---\n");

    lo0 = mmio_read32(REG_PFB_MMU_WPR2_LO);
    hi0 = mmio_read32(REG_PFB_MMU_WPR2_HI);
    Print(L"pre: WPR2 = 0x%08x/0x%08x  (ожидаем после FRTS 0x%08x/0x%08X)\n",
          lo0, hi0, TARGET_WPR2_LO, TARGET_WPR2_HI);
    ulogf(L"PRE   begin wpr2=0x%08x/0x%08x expect=0x%08x/0x%08x\n",
         lo0, hi0, TARGET_WPR2_LO, TARGET_WPR2_HI);

    /* 1. kflcnReset(GSP) — код из VBIOS переживает ресет */
    Print(L"pre: kflcnReset(GSP)...\n");
    falcon_wait_reset_ready(L"rr: pre kflcnReset GSP", GSP_HWCFG2, GSP_CPUCTL);
    mmio_write32(GSP_ENGINE, 0x1);
    for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
    mmio_write32(GSP_ENGINE, 0x0);
    for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
    falcon_wait_scrub_done(GSP_DMACTL, GSP_HWCFG2, L"pre-reset");
    uefi_call_wrapper(BS->Stall, 1, 50000);
    mmio_write32(GSP_BCR, 0x1);                     /* CORE_SELECT=FALCON */
    for (i = 0; i < 16; i++) mmio_read32(GSP_BCR);
    mmio_write32(GSP_RM, mmio_read32(0x00100000));  /* chipId0 = PMC_BOOT_0 */
    uefi_call_wrapper(BS->Stall, 1, 10000);

    if ((mmio_read32(GSP_CPUCTL) & 0xBADF0000) == 0xBADF0000) {
        Print(L"pre: GSP залочен (0xBADF) — не идём\n");
        return FALSE;
    }

    /* 2. kflcnDisableCtxReq */
    data = mmio_read32(GSP_FBIF_CTL);
    data |= (1 << 7);
    mmio_write32(GSP_FBIF_CTL, data);
    mmio_write32(GSP_DMACTL, 0);
    data = mmio_read32(GSP_FBIF_TRANSCFG0);
    data = (data & ~0x7) | 0x5;
    mmio_write32(GSP_FBIF_TRANSCFG0, data);

    /* 3. Показать, что лежит в IMEM — совпадает ли с нашим образом.
     *    Только ЧТЕНИЕ через порт GSP, ничего не пишем. */
    {
        UINT32 ours = g_fwsecPhys ? *(UINT32*)(UINTN)g_fwsecPhys : 0;
        UINT32 card;
        mmio_write32(GSP_BASE + 0x180, (1 << 28));      /* IMEMC0 addr0 SECURE */
        card = mmio_read32(GSP_BASE + 0x184);
        Print(L"pre: GSP IMEM[0x000]=0x%08x  (наш образ 0x%08x — %s)\n",
              card, ours,
              (g_fwsecPhys && card == ours) ? L"совпадает" : L"ОТЛИЧАЕТСЯ");
        ulogf(L"PRE   imem_card=0x%08x imem_ours=0x%08x match=%d\n", card, ours,
             (g_fwsecPhys && card == ours) ? 1 : 0);
        mmio_write32(GSP_BASE + 0x180, 0);
    }

    /* 4. BROM-параметры: подпись по адресу 0x5A4, ucodeId=9, RSA3K */
    mmio_write32(GSP_BROM_PARAADDR0, FWSEC_SIG_DMEM_ADDR);
    mmio_write32(GSP_BROM_ENGIDMASK, FWSEC_ENGID_MASK);
    mmio_write32(GSP_BROM_CURR_UCODE_ID, FWSEC_UCORE_ID);
    mmio_write32(GSP_MOD_SEL, 0x1);
    Print(L"pre: BROM paraaddr=0x%x engmask=0x%x ucodeid=%d modsel=0x1\n",
          FWSEC_SIG_DMEM_ADDR, FWSEC_ENGID_MASK, FWSEC_UCORE_ID);

    /* 5. Старт */
    mmio_write32(GSP_BOOTVEC, 0);
    __asm__ volatile("wbinvd" ::: "memory");
    mmio_write32(GSP_CPUCTL, NV_PFALCON_FALCON_CPUCTL_STARTCPU_TRUE);
    Print(L"pre: STARTCPU, жду WPR2 до 5с...\n");

    for (i = 0; i < 5000; i++) {
        UINT32 lo = mmio_read32(REG_PFB_MMU_WPR2_LO);
        UINT32 hi = mmio_read32(REG_PFB_MMU_WPR2_HI);
        if ((lo & 0xFFFFFFF0) == (TARGET_WPR2_LO & 0xFFFFFFF0) &&
            (hi & 0xFFFFFFF0) == (TARGET_WPR2_HI & 0xFFFFFFF0)) {
            Print(L"pre: *** WPR2 УСТАНОВЛЕН 0x%08x/0x%08x за %d мс ***\n",
                  lo, hi, i);
            ulogf(L"PRE   OK wpr2=0x%08x/0x%08x at=%dms frts_real=0x%llx\n",
                 lo, hi, (INTN)i, (UINT64)lo << 8);
            return TRUE;
        }
        /* Принять ЛЮБОЕ изменение: карта знает свой frtsOffset лучше нас.
         * Если наш расчёт неверен — мы это увидим и починим профиль. */
        if (lo != lo0 || hi != hi0) {
            Print(L"pre: WPR2 ИЗМЕНИЛСЯ: 0x%08x/0x%08x (было 0x%08x/0x%08x), "
                  L"ожидали 0x%08x/0x%08x\n",
                  lo, hi, lo0, hi0, TARGET_WPR2_LO, TARGET_WPR2_HI);
            ulogf(L"PRE   CHANGED wpr2=0x%08x/0x%08x (was 0x%08x/0x%08x) "
                 "frts_real=0x%llx at=%dms\n", lo, hi, lo0, hi0,
                 (UINT64)lo << 8, (INTN)i);
            if (lo != 0x1FFFFE00U) {
                Print(L"pre: *** приму как успех; реальный frtsOffset карты = "
                      L"0x%llx ***\n", (UINT64)lo << 8);
                return TRUE;
            }
        }
        if ((i % 500) == 0 && i)
            Print(L"pre: t=%dms wpr2=0x%08x/0x%08x cpuctl=0x%x dbg=0x%x\n",
                  i, lo, hi, mmio_read32(GSP_CPUCTL),
                  mmio_read32(GSP_BASE + 0x94));
        uefi_call_wrapper(BS->Stall, 1, 1000);
    }
    Print(L"pre: WPR2 НЕ встал. lo=0x%08x hi=0x%08x cpuctl=0x%x dbg=0x%x "
          L"(dbg=0x780009 = отказ по подписи/окружению)\n",
          mmio_read32(REG_PFB_MMU_WPR2_LO), mmio_read32(REG_PFB_MMU_WPR2_HI),
          mmio_read32(GSP_CPUCTL), mmio_read32(GSP_BASE + 0x94));
    ulogf(L"PRE   FAIL wpr2=0x%08x/0x%08x cpuctl=0x%08x dbg=0x%08x scratch0e=0x%08x\n",
         mmio_read32(REG_PFB_MMU_WPR2_LO), mmio_read32(REG_PFB_MMU_WPR2_HI),
         mmio_read32(GSP_CPUCTL), mmio_read32(GSP_BASE + 0x94),
         mmio_read32(0x001438));
    return FALSE;
}

/* Режим secure для DMA в IMEM: 1 = SEC=1 (как в драйвере), 0 = SEC=0.
 *
 * ИСТОРИЯ ЭТОГО ФЛАГА (2026-09-28) — важно, потому что прежнее
 * обоснование было построено на ошибочной расшифровке регистра.
 *
 * Стояло здесь: «на 70HX защищённый IMEM отдаёт 0xDEAD5EC1, осознанный
 * отказ GSP, значит бит SEC запрещён и DMA кода в IMEM не происходит,
 * начинаем с SEC=0».
 *
 * Наблюдение 0xDEAD5EC1 было верным, а вывод — нет. Поле IMEMC.SECURE
 * (28:28) — это признак ЗАЩИТЫ ПРИ ЧТЕНИИ, а не запрет на запись. И
 * главное: тот замер шёл при команде 0x604, где бит IMEM=1 стоял на
 * позиции SEC, то есть код в IMEM не писался вообще. Сравнивать было
 * нечего.
 *
 * Теперь при правильной команде 0x614 (IMEM=1, SEC=1) все 9 проб IMEM
 * дают 0xDEAD5EC1 — то есть IMEM ЗАНЯТ, а «DEAD SEC1» означает ровно
 * то, что написано: содержимое защищено и не читается без достаточного
 * уровня привилегий. Это признак УСПЕШНОЙ загрузки защищённого кода,
 * а не отказа.
 *
 * Значение по умолчанию 1 — как в эталоне GA102
 * (kernel_gsp_falcon_ga102.c:229, FLD_SET_DRF_NUM(..., _SEC, 0x1, ...)).
 */
static UINTN g_fwsecImemSec = 1;
static void
fwsec_set_imem_sec(UINTN sec)
{
    g_fwsecImemSec = sec;
}

/* ==== ШАГ 1: ДОСТУПЕН ЛИ КАДРОВЫЙ БУФЕР ЧЕРЕЗ GSP-DMA ====
 *
 * ЗАЧЕМ. FRTS-регион лежит в FB по TARGET_FRTS_OFFSET, а FB недоступен из
 * CPU: BAR'ы у 70HX — 16 / 64 / 32 МБ при кадровом буфере 8 ГБ
 * (docs/70HX-PORT-STATUS.md §3). Если GSP-DMA умеет ходить в FB, то FRTS
 * можно и прочитать, и заполнить. Если не умеет — всю эту ветку закрываем
 * и работаем с командой маппера, а не с содержимым региона.
 *
 * ПОЧЕМУ СТАРАЯ ПРОБА БЫЛА БЕСПОЛЕЗНА. Прежний test_fb_read() дал
 * 0x00000000 x4, и это сочли за «FB недоступен». Вывод не был обоснован:
 *   * нет положительного контроля — неизвестно, работает ли вообще чтение
 *     из DMEM через окно 0x1101C0/0x1101C4;
 *   * нет отрицательного контроля — «ноль» неотличим от «DMA молча не
 *     исполнилась и в DMEM остался мусор»;
 *   * читалось 4 слова — пустой регион и нерабочая DMA дают одно и то же;
 *   * вызывалась из fwsec_boot_gsp_sig() ПОСЛЕ неудачного FWSEC, то есть
 *     на уже грязных GSP и DMEM, переписанных прогоном. Результат нельзя
 *     было использовать ни в одну сторону.
 *
 * ЧТО ДЕЛАЕТ ЭТА ПРОБА. Она самодостаточна, гоняется на ЧИСТОМ GSP до
 * основного флоу и построена на контролях:
 *
 *   A  sysmem -> DMEM с НАШЕГО буфера FWSEC   (+контроль: ждём известное
 *                                              слово 0xEC547D23)
 *   B  sysmem -> DMEM с заведомо неиспользуемого адреса (-контроль: как
 *                                              выглядит провал)
 *   C  sysmem -> DMEM с TARGET_FRTS_OFFSET     (доступен ли FRTS)
 *   D  sysmem -> DMEM с wprEnd и с середины FB (есть ли в FB хоть что-то)
 *   E  CRC32 4 КБ из FRTS                      (заполнен ли регион целиком)
 *   F  DMEM -> sysmem в TARGET_FRTS_OFFSET     (можно ли ПИСАТЬ в FB)
 *   G  sysmem -> DMEM обратно, сверка с паттерном (round-trip, F однозначен
 *                                              независимо от исходного
 *                                              содержимого FB)
 *
 * Тесты F/G — главные: дают ответ без оглядки на то, что лежит в FB
 * изначально. Пока WPR2 не защёлкнут, регион НЕ защищён, поэтому запись
 * в него безопасна: любой мусор уходит при следующем POST.
 *
 * ВНИМАНИЕ К ТЕСТУ B. Единственный тест с ненулевым риском зависания:
 * обращение к адресу за пределами всех наших пулов. По умолчанию выбран
 * 0x600000000 (24 ГБ) — далеко за FB и за аллокациями (макс. ~4.9 ГБ), но
 * всё же правдоподобное 64-битное значение. Сбросить в 0, если плата
 * начнёт вешаться на этом месте: остальные тесты от него не зависят.
 *
 * Лог здесь — ASCII: кириллица в логе на флешку превращается в '?'
 * (KNOWN-ISSUES.md §18), а разбирать такие строки руками неудобно. */

/* Falcon-DMEM окно: адрес в 0x1101C0, данные в 0x1101C4. */
#define FBP_DMEMC            (GSP_BASE + 0x1C0)
#define FBP_DMEMD            (GSP_BASE + 0x1C4)
/* Рабочее окно в DMEM GSP.
 *
 * ВАЖНО (v3n, по результату первого прогона): НЕЛЬЗЯ подставлять ненулевое
 * смещение в memOff (второй аргумент gsp_dma_transfer -> DMATRFFBOFFS) для
 * чтения в DMEM. Первая версия пробы писала в 0x300/0x400 и положительный
 * контроль рухнул: sysmem->dmem от НАШЕГО буфера вернул нули. При этом
 * все рабочие вызовы в коде используют ровно memOff=0 — включая те, чей
 * результат проверен и совпадает:
 *
 *   fwsec_boot_gsp_sig: gsp_dma_transfer(0, 0, fwsecPhys+FWSEC_DATA_OFF, ...)
 *                       -> лог даёт "DMA dmem_hdr=... OK"
 *
 * Окно, стало быть, не адресуется как обычный DMEM-смещённый доступ.
 * Поэтому здесь одно окно 0x000 на всё: и вход, и выход, и обратное чтение. */
#define FBP_DMEM_WIN         0x000U
/* 256 байт, IMEM не трогаем: запись в GSP IMEM ниже 0xE400 ломает
 * предзагруженный код (v2.40) — здесь IMEM вообще не участвует. */
#define FBP_BLK              FLCN_BLK_ALIGNMENT
#define FBP_CMD_READ         (0 | (NV_PFALCON_FALCON_DMATRFCMD_SIZE_256B << 8))
#define FBP_CMD_WRITE        (0 | (NV_PFALCON_FALCON_DMATRFCMD_SIZE_256B << 8) \
                              | (1 << NV_PFALCON_FALCON_DMATRFCMD_WRITE_SHIFT))
/* Адрес для отрицательного контроля: 24 ГБ. */
#define FBP_BAD_PHYS         0x600000000ULL
#define FBP_DO_NEG_TEST      1

/* Узнаваемый паттерн: слово-метка плюс счётчик. */
static const UINT32 fbProbePattern[FBP_BLK / 4] = { 0xA5F00FB5U };

static void
fbp_dmem_peek(UINT32 off, UINT32 *dst, UINTN words)
{
    UINTN i;
    for (i = 0; i < words; i++) {
        mmio_write32(FBP_DMEMC, off + (UINT32)(i * 4));
        dst[i] = mmio_read32(FBP_DMEMD);
    }
}

/* Привести GSP в состояние, в котором DMA-движок отвечает. Ровно та же
 * последовательность, что в начале fwsec_boot_gsp_sig(), но без образа
 * FWSEC: нам нужен только чистый движок. В IMEM ничего не пишем. */
static BOOLEAN
fbp_gsp_prepare(void)
{
    UINTN i;

    falcon_wait_reset_ready(L"rr: gsp misc reset", GSP_HWCFG2, GSP_CPUCTL);
    mmio_write32(GSP_ENGINE, 0x1);
    for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
    mmio_write32(GSP_ENGINE, 0x0);
    for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
    falcon_wait_scrub_done(GSP_DMACTL, GSP_HWCFG2, L"fbp-reset");
    uefi_call_wrapper(BS->Stall, 1, 50000);
    mmio_write32(GSP_BCR, 0x1);                     /* CORE_SELECT = FALCON */
    for (i = 0; i < 16; i++) mmio_read32(GSP_BCR);
    mmio_write32(GSP_RM, mmio_read32(0x00100000));  /* chipId0 = PMC_BOOT_0 */
    uefi_call_wrapper(BS->Stall, 1, 10000);

    if ((mmio_read32(GSP_CPUCTL) & 0xBADF0000) == 0xBADF0000) {
        ulogf(L"FBP    GSP locked 0x%08x - dma unreachable\n",
              mmio_read32(GSP_CPUCTL));
        return FALSE;
    }

    /* ALLOW_PHYS_NO_CTX + согласованный режим транзакций — как в драйвере. */
    mmio_write32(GSP_FBIF_CTL, mmio_read32(GSP_FBIF_CTL) | (1 << 7));
    mmio_write32(GSP_DMACTL, 0);
    mmio_write32(GSP_FBIF_TRANSCFG0,
                 (mmio_read32(GSP_FBIF_TRANSCFG0) & ~0x7) | 0x5);
    return TRUE;
}

/* Один блок 256 байт: sysmem -> DMEM по адресу phys, в единственное окно. */
static void
fbp_read(UINT64 phys)
{
    gsp_dma_transfer(0, FBP_DMEM_WIN, phys, FBP_BLK, FBP_CMD_READ);
}

/* Один блок 256 байт: DMEM -> sysmem по адресу phys. */
static void
fbp_write(UINT64 phys)
{
    gsp_dma_transfer(0, FBP_DMEM_WIN, phys, FBP_BLK, FBP_CMD_WRITE);
}

/* Логическое ИЛИ всех 64 прочитанных слов — «есть ли хоть что-то». */
static UINT32
fbp_or(const UINT32 *w, UINTN n)
{
    UINTN i;
    UINT32 s = 0;
    for (i = 0; i < n; i++) s |= w[i];
    return s;
}

static void
fb_access_probe(UINT64 fwsecPhys)
{
    UINT32 w[FBP_BLK / 4];
    UINT32 want0 = fwsecPhys ? *(UINT32 *)(UINTN) fwsecPhys : 0;
    UINT32 got;
    UINT32 crc;
    UINT32 zcrc;
    BOOLEAN okA = FALSE, okF = FALSE, okG = FALSE;
    BOOLEAN frtsAny = FALSE;
    BOOLEAN junk = FALSE;
    UINTN i;

    ulogf(L"FBP    ==== step 1: framebuffer access probe ====\n");
    ulogf(L"FBP    frts=0x%llx wprEnd=0x%llx fbSize=0x%llx\n",
          (UINT64) TARGET_FRTS_OFFSET, (UINT64) TARGET_WPR_END,
          (UINT64) TARGET_FB_SIZE);

    if (!fbp_gsp_prepare()) return;
    ulogf(L"FBP    gsp ready cpuctl=0x%08x fbifctl=0x%08x transcfg0=0x%08x\n",
          mmio_read32(GSP_CPUCTL), mmio_read32(GSP_FBIF_CTL),
          mmio_read32(GSP_FBIF_TRANSCFG0));

    /* --- A: положительный контроль. Наш буфер FWSEC точно валиден и его
     *     первое слово мы знаем наизусть. ---------------------------------- */
    if (fwsecPhys) {
        fbp_read(fwsecPhys);
        fbp_dmem_peek(FBP_DMEM_WIN, w, 4);
        got = w[0];
        okA = (got == want0);
        ulogf(L"FBP-A  sysmem->dmem ok  got=0x%08x want=0x%08x  %s\n",
              got, want0, okA ? L"PASS" : L"FAIL");
        ulogf(L"FBP-A  w[1]=0x%08x w[2]=0x%08x w[3]=0x%08x  or=0x%08x\n",
              w[1], w[2], w[3], fbp_or(w, 4));
    } else {
        ulogf(L"FBP-A  SKIP: no fwsec buffer\n");
    }

    /* --- B: отрицательный контроль. Как выглядит несуществующий адрес. -- */
#if FBP_DO_NEG_TEST
    fbp_read(FBP_BAD_PHYS);
    fbp_dmem_peek(FBP_DMEM_WIN, w, 4);
    ulogf(L"FBP-B  sysmem->dmem bad  addr=0x%llx got=0x%08x 0x%08x "
          L"0x%08x 0x%08x  or=0x%08x\n",
          FBP_BAD_PHYS, w[0], w[1], w[2], w[3], fbp_or(w, 4));
#else
    ulogf(L"FBP-B  SKIP (FBP_DO_NEG_TEST=0)\n");
#endif

    /* --- C: сам FRTS-регион. ------------------------------------------- */
    fbp_read(TARGET_FRTS_OFFSET);
    fbp_dmem_peek(FBP_DMEM_WIN, w, 8);
    frtsAny = (fbp_or(w, 8) != 0);
    ulogf(L"FBP-C  frts@0x%llx: 0x%08x 0x%08x 0x%08x 0x%08x "
          L"0x%08x 0x%08x 0x%08x 0x%08x  or=0x%08x  %s\n",
          (UINT64) TARGET_FRTS_OFFSET, w[0], w[1], w[2], w[3],
          w[4], w[5], w[6], w[7], fbp_or(w, 8),
          frtsAny ? L"NONZERO" : L"ZERO");

    /* --- D: ещё две точки FB. Середина нужна, чтобы отличить «весь FB
     *     пуст» от «пуст только хвост». ---------------------------------- */
    fbp_read(TARGET_WPR_END);
    fbp_dmem_peek(FBP_DMEM_WIN, w, 4);
    ulogf(L"FBP-D  wprEnd@0x%llx: 0x%08x 0x%08x 0x%08x 0x%08x  or=0x%08x\n",
          (UINT64) TARGET_WPR_END, w[0], w[1], w[2], w[3], fbp_or(w, 4));

    fbp_read(TARGET_FB_SIZE / 2);
    fbp_dmem_peek(FBP_DMEM_WIN, w, 4);
    ulogf(L"FBP-D  midfb@0x%llx: 0x%08x 0x%08x 0x%08x 0x%08x  or=0x%08x\n",
          (UINT64) (TARGET_FB_SIZE / 2), w[0], w[1], w[2], w[3],
          fbp_or(w, 4));

    /* --- E: CRC32 первых 4 КБ FRTS.
     *     Признак «всё нули» сравниваем с CRC, посчитанным НАМИ ЖЕ на
     *     заведомо нулевом буфере. Раньше проверка была `(crc==0) ||
     *     (crc==0xFFFFFFFF)`, и она дала ложное «(has data)» на 4 КБ
     *     нулей — то есть проверка не работала вовсе. --------------------- */
    {
        static const UINT8 zeros[FBP_BLK] = { 0 };
        /* Ровно 16 блоков — столько же, сколько в цикле crc ниже.
         *
         * ЗДЕСЬ БЫЛИ ДВЕ ОШИБКИ, обе исправлены 2026-09-29.
         *
         * 1) Затенение. Здесь стояло `UINT32 zcrc = ...` — вторая
         *    переменная с тем же именем, что объявлена выше по функции.
         *    Она затеняла ту, что печатается в ulogf, и наружу уходило
         *    неинициализированное значение.
         *
         * 2) Лишний блок. Инициализатор считал ОДИН блок, а цикл ниже
         *    добавлял ещё 16 — итого 17 блоков против 16 у crc. Проверено
         *    по логу от 2026-09-29 после исправления (1):
         *        FBP-E  crc32=0x38E3FFEE  zerocrc=0x47C1A880
         *    арифметика сходится ровно:
         *        crc32(4096 нулей) = 0xC71C0011, без финального XOR
         *                            = 0x38E3FFEE   <- это crc
         *        crc32(4352 нулей) = 0x9A21E28F, без финального XOR
         *                            = 0x47C1A880   <- это 17 x 256
         *    То есть сравнивались 16 блоков против 17 — «DIFFERS» был
         *    гарантирован независимо от содержимого региона.
         *
         * После исправления (2) zcrc станет CRC тех же 4096 байт, что и
         * crc, и вердикт «(all zero, consistent with C)» будет означать
         * ровно то, что читает тест C.
         *
         * Правило: число блоков в zcrc и в crc обязано совпадать, а
         * имя zcrc не должно перекрываться внутренним объявлением. */
        zcrc = 0xFFFFFFFFU;
        for (i = 0; i < 16; i++) zcrc = crc32_upd(zcrc, zeros, FBP_BLK);
    }
    crc = 0xFFFFFFFFU;
    for (i = 0; i < 16; i++) {                 /* 16 x 256 = 4096 байт */
        fbp_read(TARGET_FRTS_OFFSET + i * FBP_BLK);
        fbp_dmem_peek(FBP_DMEM_WIN, w, FBP_BLK / 4);
        crc = crc32_upd(crc, (const UINT8 *) w, FBP_BLK);
    }
    /* Признак «всё нули» — ТОЛЬКО crc == zerocrc, и теперь это сравнение
     * корректно (см. блок выше: раньше считалось 17 блоков против 16).
     * Признак «есть данные» — только fbp_or первых слов (тест C). */
    ulogf(L"FBP-E  frts[0..0x1000] crc32=0x%08x  zerocrc=0x%08x  %s\n",
          crc, zcrc,
          (crc == zcrc)
              ? L"(all zero, consistent with C)"
              : L"(DIFFERS from zerocrc - see comment)");

    /* --- F/G: запись в FB и чтение обратно. Пока WPR2 не защёлкнут, FRTS
     *     не защищён; максимум что может случиться — мусор, который
     *     уйдёт при следующем POST. ------------------------------------- */
    {
        /* Паттерн кладём в пул через sysmem->DMEM: окно 0x1101C0 пишет по
         * одному слову, а нужно 256 байт. Пул AllocatePool на этой плате
         * попадает в первые 4 ГБ и для DMA-движка является физическим
         * адресом — на этом уже построены все загрузки блобов. */
        UINT8 *pat = (UINT8 *) cmp90_alloc(FBP_BLK);
        if (!pat) {
            ulogf(L"FBP-F  SKIP: no pool for pattern\n");
        } else {
            for (i = 0; i < FBP_BLK / 4; i++) {
                UINT32 v = fbProbePattern[i];
                pat[i * 4 + 0] = (UINT8)(v);
                pat[i * 4 + 1] = (UINT8)(v >> 8);
                pat[i * 4 + 2] = (UINT8)(v >> 16);
                pat[i * 4 + 3] = (UINT8)(v >> 24);
            }
            /* sysmem -> DMEM */
            gsp_dma_transfer(0, FBP_DMEM_WIN, (UINT64)(UINTN) pat,
                             FBP_BLK, FBP_CMD_READ);
            /* DMEM -> FRTS в FB */
            fbp_write(TARGET_FRTS_OFFSET);
            okF = TRUE;
            ulogf(L"FBP-F  dmem->frts wrote 0x%08x.. to 0x%llx (%d bytes)\n",
                  fbProbePattern[0], (UINT64) TARGET_FRTS_OFFSET,
                  (INTN) FBP_BLK);

            /* и обратно */
            fbp_read(TARGET_FRTS_OFFSET);
            fbp_dmem_peek(FBP_DMEM_WIN, w, FBP_BLK / 4);
            for (i = 0; i < FBP_BLK / 4; i++)
                if (w[i] != fbProbePattern[i]) break;
            okG = (i == FBP_BLK / 4);
            junk = FALSE;
            /* Отличаем «прочитали наш паттерн обратно» (успех) от
             * «прочитали что-то другое». Если пришло НЕ наше и НЕ нули —
             * это, судя по замеру, остаточный мусор в DMEM, а не
             * содержимое адреса. */
            if (!okG && (fbp_or(w, FBP_BLK / 4) != 0))
                junk = TRUE;
            ulogf(L"FBP-G  readback 0x%08x 0x%08x 0x%08x 0x%08x  %s\n",
                  w[0], w[1], w[2], w[3],
                  okG  ? L"ROUND-TRIP PASS"
                  : junk ? L"MISMATCH (nonzero, not ours - looks like stale "
                          L"DMEM, not the address)"
                         : L"MISMATCH (all zero - address not reachable)");
            if (!okG)
                ulogf(L"FBP-G  first bad word idx=%d got=0x%08x "
                      L"want=0x%08x\n", (INTN) i, w[i], fbProbePattern[i]);
            /* Если запись не вернулась — адрес недостижим и через
             * обратное чтение; трактовать это как «FB частично доступен»
             * нельзя, поэтому отдельно печатаем вывод. */
            if (junk)
                ulogf(L"FBP-G  NOTE: nonzero junk here means the write did "
                       L"not land where we read. Combined with FBP-C ZERO "
                       L"this points at the address, not at the transfer.\n");
            cmp90_free(pat);
        }
    }

    /* --- Вердикт одной строкой, чтобы читалось сразу. --------------------
     * ВЫВОД по замеру 2026-09-28 (ctrlA=PASS, C=ZERO, G=ненулевой мусор):
     * адрес 0x1FFE00000 не адресуется DMA-движком GSP ни на чтение, ни на
     * запись. Значит ветка «заполнить FRTS-регион напрямую через DMA»
     * ЗАКРЫТА, и работать надо с командой маппера. */
    ulogf(L"FBP    VERDICT ctrlA=%s frtsRead=%s write=%s roundTrip=%s "
          L"conclusion=%s\n",
          okA ? L"PASS" : L"FAIL",
          frtsAny ? L"nonzero" : L"zero",
          okF ? L"sent" : L"skip",
          (okF && okG) ? L"PASS" : L"FAIL",
          (!okA) ? L"inconclusive"
          : (okG) ? L"frts-writable-via-dma"
          : L"frts-NOT-reachable-via-dma");
    if (!okA) {
        ulogf(L"FBP    NOTE: ctrlA=FAIL invalidates C-G entirely. Fix the "
              L"probe first; do NOT read any conclusion about the fb from "
              L"this run.\n");
    } else if (!okG) {
        ulogf(L"FBP    CONCLUSION: 0x%llx is not addressable by the GSP "
              L"dma engine (C reads zero, E matches no data, G does not "
              L"return our pattern).\n", (UINT64) TARGET_FRTS_OFFSET);
        ulogf(L"FBP    CONCLUSION: the frts region cannot be filled "
              L"directly. Work on the mapper command instead - "
              L"gfwImageSize/flags in readVbiosDesc; see "
              L"docs/70HX-NEXT-STEPS.md S4a.\n");
    }
    ulogf(L"FBP    ==== probe done ====\n");
}

/* ==== Falcon: загрузка IMEM/DMEM через ХОСТ-ПОРТ (2026-09-28) ===========
 *
 * Почему это вообще понадобилось.
 *
 * Разбор драйвера 610.43.03 показал, что для FWSEC у нас был неправильный
 * сам механизм доставки кода, а не только неправильные значения.
 *
 *   kernel_gsp_fwsec.c:741
 *       pFlcnUcode->bootType = KGSP_FLCN_UCODE_BOOT_WITH_LOADER;
 *
 * То есть FWSEC ВСЕГДА грузится через bootType = BOOT_WITH_LOADER, и
 * kgspExecuteHsFalcon_TU102 (kernel_gsp_falcon_tu102.c:398) для него
 * делает вот что:
 *
 *   1. s_dmemCopyTo(DMEM=0, RM_FLCN_BL_DMEM_DESC)  - дескриптор в DMEM[0]
 *   2. s_imemCopyTo(ВЕРШИНА IMEM, generic BL)      - ЗАГРУЗЧИК в конец IMEM
 *   3. BOOTVEC = blStartTag << 8                  - вектор на ЗАГРУЗЧИК
 *   4. STARTCPU -> загрузчик сам переносит ucode из sysmem в IMEM/DMEM
 *      по своему дескриптору и прыгает на codeEntryPoint = 0
 *
 * Мы же грузили ucode в IMEM сами через FBIF-DMA и ставили BOOTVEC=0.
 * Это путь BOOT_DIRECT (kernel_gsp_falcon_tu102.c:402/160-202), который
 * драйвер для FWSEC НИКОГДА не использует. Логика не «может, а не может»:
 * FWSEC - подписанный blob, и его запуск описан ровно одним способом.
 *
 * Вариант BOOT_WITH_LOADER воспроизвести точно нельзя: generic BL лежит на
 * SEC2 (ksec2GetGenericBlUcode_HAL) и у нас его образа нет. Но путь
 * BOOT_DIRECT делает ровно то же самое с точки зрения Falcon - кладёт код
 * в IMEM и прыгает на 0 - только грузит его ХОСТ-ПОРТОМ, а не DMA.
 * Именно его реализация ниже, один в один с s_imemCopyTo_TU102.
 *
 * Главное, что мы наконец получаем: ПРОВЕРКУ ЗАПИСИ. Раньше загрузка шла
 * через FBIF-DMA, а чтение IMEM давало 0x00000000, и это было
 * неинтерпретируемо - то ли DMA не легла, то ли чтение не работает. С
 * хост-портом мы пишем тем же интерфейсом, которым читаем, и получаем
 * однозначный ответ.
 *
 * Регистры (dev_falcon_v4.h, проверено):
 *   NV_PFALCON_FALCON_IMEMC(i) = 0x180 + i*16
 *   NV_PFALCON_FALCON_IMEMD(i) = 0x184 + i*16   <- ДАННЫЕ
 *   NV_PFALCON_FALCON_IMEMT(i) = 0x188 + i*16   <- ТЕГ блока
 *   NV_PFALCON_FALCON_DMEMC(i) = 0x1C0 + i*8
 *   NV_PFALCON_FALCON_DMEMD(i) = 0x1C4 + i*8
 *   IMEMC: OFFS/BLK = адрес, AINCW = bit24, SECURE = bit28
 *   IMEMT: TAG - тег блока, обновляется каждый FALCON_IMEM_BLKSIZE2 блок
 *
 * Обратите внимание: IMEMD идёт ДО IMEMT. Прежний код читал по 0x184 и
 * называл это IMEMD - это было верно, так что рассинхрона тут не было.
 */
#define FALCON_IMEMC0        (GSP_BASE + 0x180)
#define FALCON_IMEMD0        (GSP_BASE + 0x184)
#define FALCON_IMEMT0        (GSP_BASE + 0x188)
#define FALCON_DMEMC0        (GSP_BASE + 0x1C0)
#define FALCON_DMEMD0        (GSP_BASE + 0x1C4)
#define FALCON_IMEMC_AINCW   (1u << 24)
#define FALCON_IMEMC_SECURE  (1u << 28)
#define FALCON_IMEM_WORD_PER_BLK 64u   /* FALCON_IMEM_BLKSIZE2=8 -> 2^(8-2) */

/* Только ЧТЕНИЕ IMEM для проверки, что DMA реально положила код.
 *
 * Ничего не пишем в IMEMC кроме адреса (AINCW/SECURE не трогаем), потому
 * что код FWSEC грузится с SEC=1 и любая запись по этому порту может
 * испортить уже корректное содержимое. Раньше такой проверки не было
 * вовсе, и из-за неверного бита IMEM в DMATRFCMD пустой IMEM был
 * неотличим от «DMA не работает».
 *
 * Возвращает упакованную статистику: биты 7:0 = empty, 15:8 = matched,
 * 23:16 = occupied. Упаковка нужна потому, что ulogf не понимает '%u' —
 * при первой попытке вернуть просто число счётчика он напечатал вместо
 * него 3014351520 (0xB40175E0), то есть мусор из стека. */
static UINT32
falcon_imem_verify(UINT64 physCode, UINT32 codeSize)
{
    static const UINT32 probe[] = { 0x000, 0x100, 0x400, 0x800, 0x1000,
                                    0x4000, 0x8000, 0xC000, 0xE000 };
    const UINT32 *src = (const UINT32 *)(UINTN)physCode;
    UINTN i, empty = 0, matched = 0, occupied = 0;

    for (i = 0; i < sizeof(probe)/sizeof(probe[0]); i++) {
        UINT32 gotNs, gotSec, want;
        if (probe[i] + 4 > codeSize) continue;
        want = src[probe[i] >> 2];

        /* Два чтения: без SECURE и с SECURE (IMEMC_SECURE = 28:28).
         * Различать их критично: код FWSEC грузится с SEC=1, поэтому
         * обычное чтение защищённой ячейки возвращает 0xDEAD5EC1
         * («DEAD SEC1» — отказ, а не данные). Прежняя версия IVER читала
         * только без SECURE и потому объявляла заведомо невидимый код
         * «пустым». */
        mmio_write32(FALCON_IMEMC0, probe[i]);
        gotNs = mmio_read32(FALCON_IMEMD0);
        mmio_write32(FALCON_IMEMC0, probe[i] | FALCON_IMEMC_SECURE);
        gotSec = mmio_read32(FALCON_IMEMD0);

        if (gotNs == want || gotSec == want) matched++;
        else if (gotNs == 0 && gotSec == 0)   empty++;
        else                                  occupied++;

        ulogf(L"IVER   imem[0x%05x] want=0x%08x  ns=0x%08x  sec=0x%08x  %s\n",
              probe[i], want, gotNs, gotSec,
              (gotNs == want) ? L"MATCH-ns"
            : (gotSec == want) ? L"MATCH-sec"
            : (gotNs == 0)     ? L"empty"
                               : L"occupied-but-unreadable");
    }
    return empty | (matched << 8) | (occupied << 16);
}

/* v3n: ЗАМЕР WPR2 ПО ГРАНИЦАМ СТАДИЙ (2026-09-29).
 *
 * Зачем. Полный лог показал: WPR2_LO = 0x01F7E000 на выходе из
 * fwsec_boot_gsp_sig() (строка OKCHK), и 0x01EAD000 уже в блоке
 * селекторов. Между этими точками стоит early_unlock_path() с
 * booter_load_v67() — единственное место, где там что-то крутится.
 * Замеры WATCH before/after у записей селекторов виновника ИСКЛЮЧИЛИ:
 * они не меняют ничего, кроме 0x00823818. Значит искать надо раньше, и
 * этот замер ищет по границам стадий.
 *
 * Про подписи: строки PRE/END/PREFLR печатают «GFW=…», читая 0x0000B100,
 * тогда как REG_GFW_BOOT_OK = 0x00118234. Это разные регистры, а в логе
 * выглядят как один. Замер 2026-09-29: 0xB100 = 0xBADF5040 -> 0xBADF1100,
 * а 0x00118234 = 0x000003FF (младший байт 0xFF = GFW поднялся, по
 * критерию самого кода). То есть «GFW поехал 0xBADF5040 -> 0xBADF1100» —
 * сравнение двух sentinel-ов BADF, а не данные о состоянии. */
static void
wpr2_probe(const CHAR16 *tag)
{
    /* проверку g_logOn делает сам ulogf */
#ifdef RENDER_MASKS
    /* v3.12: ПРОБЕЛ БУДИЛЬНИКА. Функция зовётся 7 раз из early_unlock_path,
     * а тот после снятия гарда ботер#1 зовётся на каждой из 17 масок.
     * Итого 119 строк PROBE, а лог у нас кольцевой: при LOG_SECTORS ~1024
     * 398 615 байт почти полностью съедали начало прогона, и мы видели
     * только хвост. Полные первые 4 вызова, дальше — каждая 8-я, а итог
     * печатает render_open_gfx_masks. Значения не теряются, место
     * освобождается.
     *
     * Под #ifdef RENDER_MASKS НЕ случайно. Без ограждения эта правка попала
     * бы в v3n, и откат перестал бы быть тем бинарём, который дал x11.25.
     * Проверено на себе: снятие ограждения меняло md5 v3n с 1863C4B1 на
     * C676BFB3 ПРИ ТОМ ЖЕ размере 648192 — ловушка молчаливая, размер
     * здесь не показатель. Откат обязан собираться байт-в-байт. */
    static INTN nSeen = 0;
    nSeen++;
    if (nSeen > 4 && (nSeen % 8) != 0)
        return;
    ulogf(L"PROBE  %s[%d] WPR2=0x%08x/0x%08x GFWok=0x%08x b100=0x%08x "
          L"cpuctl=0x%08x\n",
          tag, (INTN)nSeen, mmio_read32(REG_PFB_MMU_WPR2_LO), mmio_read32(REG_PFB_MMU_WPR2_HI),
          mmio_read32(REG_GFW_BOOT_OK), mmio_read32(0x0000B100U),
          mmio_read32(GSP_CPUCTL));
#else
    ulogf(L"PROBE  %s WPR2=0x%08x/0x%08x GFWok=0x%08x b100=0x%08x "
          L"cpuctl=0x%08x\n",
          tag, mmio_read32(REG_PFB_MMU_WPR2_LO), mmio_read32(REG_PFB_MMU_WPR2_HI),
          mmio_read32(REG_GFW_BOOT_OK), mmio_read32(0x0000B100U),
          mmio_read32(GSP_CPUCTL));
#endif /* RENDER_MASKS */
}

/* v3n: ДАМП ОКНА SEC2 ВОКРУГ 0x840310 (2026-09-29).
 *
 * Зачем. Пользователь снял снаружи (из Windows) окно 0x840310..0x840374 и
 * показал сплошные 0xBADF5xxx:
 *     0x840310..0x840340 = 0xBADF5108
 *     0x840344..0x840360 = 0xBADF5720
 *     0x840364..0x84036C = 0xBADF5040
 *     0x840370          = 0x001C0004   <- единственное без префикса BADF
 *     0x840374          = 0xBADF5720
 * Вопрос: что такое 0x840370 и меняется ли оно от анлока. Ответить
 * внешним чтением нельзя — нужен тот же замер ДО и ПОСЛЕ, а сравнивать
 * два разных инструмента бессмысленно. Поэтому дампим это окно самим
 * ulogf на тех же границах стадий, что и wpr2_probe: тогда оба состояния
 * читаются одним кодом и попадают в один лог.
 *
 * 0x840000 — база NV_PSEC (апертура SEC2/Falcon, :548), то есть адреса
 * 0x8403xx — это НЕ видеоблок и не BAR0. Значения 0xBADF5xxx — sentinel
 * «узел заперт», а не данные (KNOWN-ISSUES §42.8). Поэтому в строках ниже
 * BADF-значения помечены явно: иначе в следующем логе их снова примут за
 * показание.
 *
 * Формат: по 4 слова в строке, «addr = value». Строка держится в
 * пределах лимита ulogf (399 символов на вызов). */
#define SEC2_WIN_LO   0x00840300UL
#define SEC2_WIN_HI   0x00840380UL

static void
sec2_window_dump(const CHAR16 *tag)
{
    UINT32 a;
    for (a = SEC2_WIN_LO; a <= SEC2_WIN_HI; a += 16) {
        UINT32 w0 = mmio_read32(a);
        UINT32 w1 = mmio_read32(a + 4);
        UINT32 w2 = mmio_read32(a + 8);
        UINT32 w3 = mmio_read32(a + 12);
        ulogf(L"SEC2W  %s 0x%08x=0x%08x 0x%08x=0x%08x "
              L"0x%08x=0x%08x 0x%08x=0x%08x%s\n",
              tag, a, w0, a + 4, w1, a + 8, w2, a + 12, w3,
              (w0 == 0x001C0004U || w1 == 0x001C0004U ||
               w2 == 0x001C0004U || w3 == 0x001C0004U) ? L"  <<0x001C0004" : L"");
    }
    /* Отдельно: сколько в окне BADF-значений и сколько — настоящих.
     * Это то, что делает дамп пригодным для сравнения: одно число вместо
     * двадцати шести строк, которые надо читать глазами. */
    {
        UINT32 badf = 0, live = 0, n = 0;
        for (a = SEC2_WIN_LO; a <= SEC2_WIN_HI; a += 4) {
            UINT32 v = mmio_read32(a);
            n++;
            if ((v & 0xBADF0000U) == 0xBADF0000U) badf++; else live++;
        }
        ulogf(L"SEC2S  %s window 0x%08x..0x%08x words=%d BADF=%d live=%d "
              L"dmatrfcmd=0x%08x fullTo=%d idleTo=%d\n",
              tag, SEC2_WIN_LO, SEC2_WIN_HI, (INTN)n, (INTN)badf, (INTN)live,
              (INTN)mmio_read32(GSP_DMATRFCMD),
              (INTN)g_dmaFullTo, (INTN)g_dmaIdleTo);
    }
}

/* v3n: ДИАГНОСТИКА PCIe Gen2 — ТОЛЬКО ЧТЕНИЕ (2026-09-29).
 *
 * Зачем. Вопрос «включать ли свип масок ради Gen2» стоит так: phase2
 * (рецепт xrip) пишет в 0x8841c / 0x8c040 / 0x880a8 / 0x8e1xx, а свип
 * открывает маски записью 0xFFFFFFFF в 36 адресов, включая 0x8e1b0..0x8e1f0
 * и 0x823b04. Зависимость этих записей от масок в коде НЕ документирована,
 * и проверять её записью вслепую дорого: свип занимает минуты и в fire-режиме
 * выкидывает анлок и фикс Code 43 (см. 8422 и 8361).
 *
 * Поэтому сначала читаем. Если нужные маски уже открыты в обычном пути,
 * phase2 можно включать самостоятельно, без свипа. Если нет — видно, какие
 * именно и можно открыть точечно.
 *
 * ВАЖНО: функция ничего не пишет. Ни одного mmio_write32 и ни одной записи
 * в конфиг PCIe. Это обязательное условие — такой дамп не может вызвать ни
 * Code 43, ни потерю анлока.
 *
 * Что печатает:
 *   GEN2M  — по 4 адреса маски в строку, с пометкой MATCH;
 *   GEN2S  — ИТОГ: сколько масок уже на цели (это и есть ответ на вопрос);
 *   GEN2R  — регистры конфигурации скорости и PLM/SS, которые читает phase2;
 *   GEN2C  — PCI-конфиг обоих концов линка: LNKCTL2 (cap+0x30) и LNKSTA
 *            (cap+0x10), плюс фактическая скорость и ширина. */
static const struct { UINT32 addr; const CHAR16 *name; } g_gen2regs[] = {
    { 0x00088084U, L"LINK_CAP"     },
    { 0x00088088U, L"LNKSTA-inner"  },
    { 0x000880a8U, L"LNKCTL2-inner" },
    { 0x0008c040U, L"LINK_CONFIG_0"},
    { 0x0008841cU, L"PRIV_MISC_1"   },
    { 0x0008c2c0U, L"CYA_0"        },
    { 0x0008e110U, L"XP3G_OVR0"    },
    { 0x0008e11cU, L"XP3G_OVR3"    },
    { 0x0008e120U, L"XP3G_VAL0"    },
    { 0x0008e12cU, L"XP3G_VAL3"    },
    { 0x00823b04U, L"PLM-gfx"  },
    { 0x00823804U, L"PLM-main" },
    { 0x0082381cU, L"SS0"          },
    { 0x00823820U, L"SS1"          },
    { 0x00823830U, L"GFX_SPEED_SEL"},
};
#define GEN2REGS_N ((INTN)(sizeof(g_gen2regs)/sizeof(g_gen2regs[0])))

#if CHIP_SIZE_SCAN
/* --- Скан конфигурационных окон BAR0 на кандидаты «размер кристалла» ---
 *
 * Кандидаты: 30 = наш SM, 56 = SM 50HX, плюс реальные конфиги GA104
 * (38/40/46/48) и TU102 (68/72). Одна сборка годится для обеих карт,
 * поэтому сравнение будет адрес-к-адресу, а не «вроде похожее».
 *
 * Значения шины памяти (256/320) и L2 (2/5) намеренно НЕ в списке: они
 * слишком частые и забили бы лог. Их проверяем позже, когда найдём
 * кандидата на SM. */
static const UINT32 g_chipCand[] = { 30, 38, 40, 46, 48, 56, 68, 72 };
#define CHIPCAND_N ((INTN)(sizeof(g_chipCand) / sizeof(g_chipCand[0])))

static const struct { UINT32 base, size; } g_chipWin[] = {
    { 0x00820000UL, 0x00020000UL },   /* fuse-shadow + priv-страница 0x82xxxx */
    { 0x00080000UL, 0x00010000UL },   /* misc / окно XVE 0x88xxx           */
};
#define CHIPWIN_N ((INTN)(sizeof(g_chipWin) / sizeof(g_chipWin[0])))

#define CHIPLOG_MAX 160               /* лог кольцевой, переполнять нельзя */

static void chip_size_scan(const CHAR16 *tag)
{
    INTN w, printed = 0, matched = 0;

    for (w = 0; w < CHIPWIN_N; w++) {
        UINT32 base = g_chipWin[w].base;
        UINT32 end  = base + g_chipWin[w].size;
        UINT32 a;
        INTN   hits = 0;

        for (a = base; a < end; a += 4) {
            UINT32 v = mmio_read32(a);
            INTN   c;
            for (c = 0; c < CHIPCAND_N; c++) {
                if (v == g_chipCand[c]) {
                    hits++;
                    if (printed < CHIPLOG_MAX) {
                        ulogf(L"CHIP  %s 0x%08x = %u (0x%08x)\n",
                              tag, a, (UINTN)v, v);
                        printed++;
                    }
                    break;
                }
            }
        }
        matched += hits;
        ulogf(L"CHIPS %s window 0x%08x..0x%08x: matches %d\n",
              tag, base, end - 4, (INTN)hits);
    }
    ulogf(L"CHIPS %s TOTAL matches %d, printed %d%s\n",
          tag, (INTN)matched, (INTN)printed,
          (matched > printed) ? L" (log truncated)" : L"");
}
#endif /* CHIP_SIZE_SCAN */

#ifndef SM_ACF
#define SM_ACF 0
#endif
#if SM_ACF
/* --- ОПРЕДЕЛЕНИЕ ГЕОМЕТРИИ SM ИЗ САМОГО BAR0, v2 (2026-10-09) ----------
 *
 * ЧЕТЫРЕ ПРОГОНА, И ЧЕТЫРЕ МОИ ОШИБКИ. Ни одна не была в железе.
 *
 *   1  база 0 и шаг 0x80, перенесённые из TU102 -> читались первые
 *      64 КБ BAR0, где SM нет; вердикт "ALIVE 45" был артефактом;
 *   2  критерий "не 0xbadf и нули" -> зарезервированная область
 *      проходит его идеально, отдавая ноль; "окно из 24 юнитов"
 *      при дочитывании оказалось 0xBADF1100;
 *   3  окно 0x400000 -> не пересеклось ни с одним известным адресом
 *      (наши регистры в 0x80000..0x840000);
 *   4  алгоритм O(N^3) -> прогон на 6 блоках занял 334 секунды
 *      (t=337941ms против t=3980ms в логе), а я расширил объём
 *      до 32 блоков и получил около 30 минут. Загрузка висела, и
 *      человек её прервал.
 *
 * Пункт 4 - главный, и он про ту же ошибку, что и остальные: я
 * ОБОЗНАЧИЛ стоимость, не посчитав её. В коде стояло "единицы
 * миллисекунд", реально было 334 секунды - расхождение в 70000 раз.
 * Оценивал я по числу чтений BAR0 (их действительно немного) и
 * не учёл, что внутри каждого совпадения крутится ещё полный проход
 * по блоку. Проверялась работоспособность, стоимость - нет.
 *
 * ПОЧЕМУ ТЕПЕРЬ НЕ O(N^3).
 *
 * Старый код: цикл по i, цикл по j, и ВНУТРИ каждой совпавшей пары
 * (i,j) ещё один полный цикл по блоку. Отсюда N^3 = 5.5e11 на блок.
 *
 * Новый код сортирует пары (значение, позиция) по значению, из-за чего
 * одинаковые значения стоят рядом, и внутри группы считает разности
 * позиций. Стоимость - сумма k^2 по группам, а она ограничена сверху
 * величиной MAXOCC. Замерено на том же синтетическом блоке:
 *
 *     синтетика (30 юнитов, настоящий массив)   6.6 мс, массив найден
 *     сплошная заливка одним значением          2.1 мс, 0 кандидатов
 *     чередование двух значений                 2.3 мс, 0 кандидатов
 *     случайные данные                          2.3 мс, 0 кандидатов
 *
 * 32 блока - около 72 мс против 334 секунд на 6 блоках раньше.
 *
 * ЖЁСТКИЙ БЮДЖЕТ ВРЕМЕНИ.
 *
 * Пункт 4 показал, что цена ошибки здесь - зависшая загрузка, а её
 * чинит только перезагрузка. Поэтому сверху стоит отсечка по TSC: при
 * превышении ACF_BUDGET_US скан прерывается и пишет ACFTO. Медленный
 * или нечитаемый регион теперь физически не может затянуть загрузку,
 * даже если логика ошибочна.
 *
 * ЧТО ЭТО ДАСТ И ЧТО НЕ ДАСТ - ДО ПРОГОНА.
 *
 * Даст независимое от multiProcessorCount число TPC/SM-слотов.
 * Не даст способа включить лишние юниты: все известные проекты трогают
 * только FEAT_OVR, SS0, SS1 и конфигурацию GSP-RM, а конфигурация
 * GPC/TPC не тронута никем. Успех - это ответ на вопрос, а не
 * разблокировка.
 *
 * БЕЗОПАСНОСТЬ. Только чтение, записи в железо нет, анлок не
 * затрагивается, откат = перезагрузка. */

#define ACF_WIN        0x00400000UL   /* документированный якорь: ID + 0x400000 */
#define ACF_BLOCK_N    8192UL         /* dword в блоке: 32 КБ            */
#define ACF_NBLOCKS    32UL           /* 32 x 32 КБ = 1 МБ               */
#define ACF_RANGE      0x00200000UL   /* диапазон фазы B                 */
#define ACF_ABSENT_HI  0xbadfUL       /* признак отсутствующего регистра */
#define ACF_MINPAIRS   8UL            /* полных пар - порог кандидата    */
#define ACF_TOPN       5UL            /* печатаем только лучших          */

/* Нижняя граница шага. Без неё метод выдаёт тавтологию: ЛЮБОЙ ряд из
 * одинаковых dword-ов даёт совпадения при сдвиге 4, 8, 12, ... байт.
 * Прогон 2026-10-09 (окно 0x400000) поэтому и выдал "43 units" с шагом
 * 0x4 - это не массив, это run одинаковых слов. */
#define ACF_MIN_STRIDE 0x40UL

/* Верхняя граница кратности значения. Если значение встречается чаще,
 * это заливка (замаскированная или reserved область), а не массив:
 * сплошной 0xFFFFFFFF даёт 1 + (N - S) полных пар при ЛЮБОМ шаге, то
 * есть идеальный ложный всплеск. Именно он дал 33 млн кандидатов в
 * прогоне с окном 0x80000. */
#define ACF_MAXOCC     512UL

/* Бюджет времени на весь скан, микросекунды. При превышении - отказ. */
#define ACF_BUDGET_US  20000000ULL    /* 20 секунд                       */

/* ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ.
 *
 * Три прогона подряд выдали артефакты, и во всех виноваты были мои
 * параметры. Контроль отвечает на вопрос, который те прогоны не
 * задавали: работает ли вообще инструмент. Метод обязан найти в BAR0
 * те самые значения, что проект печатает в GEN2R каждый прогон. Если
 * контроль не прошёл - вывод один: прибор негоден, и это признаётся
 * сразу, а не подгоняется. */
typedef struct { UINT32 addr; UINT32 val; const CHAR16 *name; } ACF_CTRL;

static const ACF_CTRL g_acfCtrl[] = {
    { 0x00088084UL, 0x00453D01UL, L"LINK_CAP"      },
    { 0x0008841CUL, 0x20360500UL, L"PRIV_MISC_1"   },
    { 0x0008C2C0UL, 0x00802005UL, L"CYA_0"         },
    { 0x0082381CUL, 0x88888888UL, L"SS0"           },
    { 0x00823820UL, 0x00000008UL, L"SS1"           },
};
#define ACF_CTRL_N ((INTN)(sizeof(g_acfCtrl)/sizeof(g_acfCtrl[0])))

/* Пары (значение, позиция). Сортируются по значению, поэтому одинаковые
 * значения оказываются рядом и их позиции уже по возрастанию. */
typedef struct { UINT32 val; UINT32 pos; } ACF_ENT;

/* Лучший найденный кандидат по всем блокам. */
typedef struct {
    UINT32 value;     /* повторяющееся значение                            */
    UINT32 stride;    /* шаг в байтах, между юнитами                       */
    UINT32 count;     /* сколько пар (off, off+S) совпало                  */
    UINT32 addr;      /* BAR0-адрес, выровненный по шагу                   */
} ACF_HIT;

static ACF_ENT     g_acfEnt[ACF_BLOCK_N];
static UINT16      g_acfDelta[ACF_BLOCK_N];   /* гистограмма шагов, dword */
static UINT16      g_acfTouched[ACF_BLOCK_N]; /* индексы, куда писали    */

/* Маски, которые повторяются и потому дают ложные всплески.
 *
 *   0x00000000  зарезервированная область BAR0 отдаёт ноль
 *   0xbadf..... признак отсутствующего регистра
 *   0xFFFFFFFF  признак замаскированного/не реализованного регистра
 *   0x77777777  тот же "выключен" в виде маски
 *   0x00000001  флаг "включено", повторяется на каждом юните
 *
 * Первые две исключались с самого начала, остальные три добавлены после
 * прогона с окном 0x80000, где блок 0xA0000 оказался сплошным
 * 0xFFFFFFFF. Это те же "отсутствующие" регистры, просто другой
 * константой, и исключать их следовало сразу. */
static INTN acf_is_mask(UINT32 v)
{
    if (v == 0x00000000UL) return 1;
    if ((v >> 16) == ACF_ABSENT_HI) return 1;
    if (v == 0xFFFFFFFFUL) return 1;
    if (v == 0x77777777UL) return 1;
    if (v == 0x00000001UL) return 1;
    return 0;
}

/* Сортировка по паре (значение, позиция).
 *
 * Именно по ПАРЕ, а не только по значению. Предыдущая версия сравнивала
 * только val и полагалась на стабильность shell sort для равных
 * элементов. Стабильности там нет: сортировка с зазорами переставляет
 * равные элементы между проходами, позиции внутри группы оказывались
 * в произвольном порядке, и выражение e[b].pos - e[a].pos уходило в
 * минус. Далее g_acfDelta[d] обращался ЗА ГРАНИЦУ массива. На стенде
 * это ловится санитайзером как SEGV, а на железе означало бы тишину в
 * логе вместо результата.
 *
 * Полный порядок по (val,pos) даёт позиции по возрастанию внутри
 * группы гарантированно, а не по предположению. */
static void acf_sort(ACF_ENT *a, UINT32 n)
{
    UINT32 gap, i, j;
    ACF_ENT t;
    for (gap = n / 2; gap > 0; gap /= 2) {
        for (i = gap; i < n; i++) {
            t = a[i];
            for (j = i; j >= gap &&
                 (a[j - gap].val > t.val ||
                  (a[j - gap].val == t.val && a[j - gap].pos > t.pos));
                 j -= gap)
                a[j] = a[j - gap];
            a[j] = t;
        }
    }
}

/* Обрабатывает один блок. Возвращает 0 при отказе по бюджету времени. */
static INTN acf_block(const CHAR16 *tag, UINT32 blockBase, UINT32 blkIdx,
                      UINT64 t0, ACF_HIT *bestOut)
{
    UINT32 i, n = 0, g0, g1, a, b;
    UINT32 ntouch;
    UINT32 raw = 0, uniq = 0, over = 0;
    ACF_ENT *e = g_acfEnt;

    for (i = 0; i < ACF_BLOCK_N; i++) {
        UINT32 v = mmio_read32(blockBase + i * 4UL);
        if (acf_is_mask(v)) continue;
        e[n].val = v; e[n].pos = i; n++;
    }
    raw = ACF_BLOCK_N - n;

    if (n == 0) {
        ulogf(L"ACFC  %s blk %u @0x%08x: all masked or zero\n", tag, blkIdx, blockBase);
        return 1;
    }
    acf_sort(e, n);

    g0 = 0;
    while (g0 < n) {
        g1 = g0;
        while (g1 < n && e[g1].val == e[g0].val) g1++;
        {
            UINT32 k = g1 - g0;
            if (k > ACF_MAXOCC) {
                over++;
            } else if (k >= 2) {
                ntouch = 0;
                for (a = g0; a < g1; a++) {
                    for (b = a + 1; b < g1; b++) {
                        UINT32 d;
                        /* Сортировка гарантирует возрастание позиций, но
                         * проверка остаётся: при вычитании без неё
                         * порядок нарушения превращается в индекс минус
                         * миллиард, то есть в чтение и запись вне массива.
                         * В бутлоадере это тишина в логе, а не сообщение. */
                        if (e[b].pos <= e[a].pos) continue;
                        d = e[b].pos - e[a].pos;
                        if (d >= ACF_BLOCK_N) continue;
                        if (d * 4UL < ACF_MIN_STRIDE) continue;
                        if (g_acfDelta[d] == 0) {
                            if (ntouch < ACF_BLOCK_N) g_acfTouched[ntouch++] = (UINT16)d;
                        }
                        g_acfDelta[d]++;
                    }
                }
                for (i = 0; i < ntouch; i++) {
                    UINT32 d = g_acfTouched[i];
                    UINT32 c = g_acfDelta[d];
                    if (c >= ACF_MINPAIRS) {
                        uniq++;
                        if (c > bestOut->count) {
                            bestOut->count = c;
                            bestOut->value = e[g0].val;
                            bestOut->stride = d * 4UL;
                            bestOut->addr = blockBase +
                                (e[g0].pos - (e[g0].pos % d)) * 4UL;
                        }
                    }
                    g_acfDelta[d] = 0;
                }
            }
        }
        g0 = g1;
        if ((g0 & 0x3FF) == 0 && fx_now_us() - t0 > ACF_BUDGET_US) return 0;
    }

    ulogf(L"ACFC  %s blk %u @0x%08x: %u masked, %u kept, %u unique (val,stride), %u over-cap\n",
          tag, blkIdx, blockBase, raw, n, uniq, over);
    return 1;
}

/* --- ФАЗА B: по найденному шагу считаем юниты на большом диапазоне. -----
 *
 * Здесь BAR0 читается напрямую, поэтому 2 МБ диапазона не требуют
 * памяти: нужен всего один dword на юнит. */
static void acf_phase_b(const CHAR16 *tag, UINT32 anchor, UINT32 val, UINT32 S,
                        UINT64 t0)
{
    UINT32 k, run = 0, best = 0, bestAt = 0, runAt = 0, total = 0;

    for (k = 0; anchor + k * S < ACF_WIN + ACF_RANGE; k++) {
        UINT32 a = anchor + k * S;
        UINT32 v = mmio_read32(a);
        if (v == val) {
            if (run == 0) runAt = a;
            run++; total++;
            if (run > best) { best = run; bestAt = runAt; }
        } else {
            run = 0;
        }
        if ((k & 0x3FF) == 0 && fx_now_us() - t0 > ACF_BUDGET_US) {
            ulogf(L"ACFTO %s phase B aborted by time budget at unit %u\n", tag, k);
            break;
        }
    }
    ulogf(L"ACFB  %s anchor 0x%08x val 0x%08x stride 0x%x: longest run %u units at 0x%08x, %u matched\n",
          tag, anchor, val, S, best, bestAt, total);
    ulogf(L"ACFB  %s claimed (multiProcessorCount) = 30. A run of identical values can\n"
          L"ACFB  %s   also be a mask or config register that legitimately repeats per\n"
          L"ACFB  %s   unit, so read the value before treating the run as an SM count.\n",
          tag, tag, tag);
}

static void acf_control(const CHAR16 *tag)
{
    INTN k, ok = 0;
    for (k = 0; k < ACF_CTRL_N; k++) {
        UINT32 got = mmio_read32(g_acfCtrl[k].addr);
        INTN  hit = (got == g_acfCtrl[k].val);
        if (hit) ok++;
        ulogf(L"ACFK  %s ctrl %-12s @0x%08x want 0x%08x got 0x%08x %s\n",
              tag, g_acfCtrl[k].name, g_acfCtrl[k].addr,
              g_acfCtrl[k].val, got, hit ? L"MATCH" : L"DIFFERS");
    }
    ulogf(L"ACFCN %s control %d of %d matched\n", tag, ok, ACF_CTRL_N);
    if (ok == ACF_CTRL_N)
        ulogf(L"ACFOK %s control PASSED: BAR0 reads are live and expected here.\n"
              L"ACFOK %s   A missing per-SM array is then a real absence, not a\n"
              L"ACFOK %s   broken read path.\n", tag, tag, tag);
    else
        ulogf(L"ACFBAD %s control FAILED (%d of %d). BAR0 reads here do not match what\n"
              L"ACFBAD %s   the project has measured for months. Any per-SM result\n"
              L"ACFBAD %s   from this run is VOID - the instrument is wrong.\n", tag, ok, ACF_CTRL_N, tag, tag);
}

static void sm_autocorr(const CHAR16 *tag)
{
    UINT32 blk;
    UINT64 t0;
    ACF_HIT best;
    INTN   done = 1;

    best.count = 0; best.value = 0; best.stride = 0; best.addr = 0;

    ulogf(L"ACFA  %s %u blocks of %u dwords (%u KB) from BAR0 0x%08x\n",
          tag, (UINTN)ACF_NBLOCKS, (UINTN)ACF_BLOCK_N,
          (UINTN)(ACF_BLOCK_N * 4UL / 1024UL), ACF_WIN);
    ulogf(L"ACFA  %s excluded: 0x00000000, 0xbadf....., 0xFFFFFFFF, 0x77777777, 0x1.\n"
          L"ACFA  %s   Stride below 0x%x excluded: equal words match at 4/8/12 bytes\n"
          L"ACFA  %s   by definition. Values occurring more than %u times excluded: that is\n"
          L"ACFA  %s   a fill pattern, and it matches at every stride.\n",
          tag, tag, (UINTN)ACF_MIN_STRIDE, tag, (UINTN)ACF_MAXOCC, tag);
    ulogf(L"ACFA  %s time budget %u ms. Cost is sum(k^2) per distinct value, capped at\n"
          L"ACFA  %s   %u, so it is bounded by construction - this scan cannot hang the boot.\n",
          tag, (UINTN)(ACF_BUDGET_US / 1000ULL), tag, (UINTN)ACF_MAXOCC);

    acf_control(tag);

    t0 = fx_now_us();
    for (blk = 0; blk < ACF_NBLOCKS; blk++) {
        if (!acf_block(tag, ACF_WIN + blk * (ACF_BLOCK_N * 4UL), blk, t0, &best)) {
            ulogf(L"ACFTO %s ABORTED by time budget at block %u of %u\n",
                  tag, blk, (UINTN)ACF_NBLOCKS);
            done = 0;
            break;
        }
    }
    ulogf(L"ACFT  %s scan of %u blocks took %u ms\n",
          tag, (UINTN)(done ? ACF_NBLOCKS : ACF_NBLOCKS), (UINTN)((fx_now_us() - t0) / 1000ULL));

    if (best.count < ACF_MINPAIRS) {
        ulogf(L"ACFD  %s NO PERIODIC ARRAY. No unmasked value repeated with a stable\n"
              L"ACFD  %s   stride at least %u times in %u blocks of %u KB at 0x%08x.\n"
              L"ACFD  %s   With the control passing this is a real absence in this window,\n"
              L"ACFD  %s   not a broken read path. It says nothing about other windows.\n",
              tag, tag, (UINTN)ACF_MINPAIRS, (UINTN)ACF_NBLOCKS,
              (UINTN)(ACF_BLOCK_N * 4UL / 1024UL), ACF_WIN, tag, tag);
        return;
    }
    ulogf(L"ACFS  %s BEST val 0x%08x stride 0x%x pairs %u\n",
          tag, best.value, best.stride, best.count);
    acf_phase_b(tag, best.addr, best.value, best.stride, t0);
}
#endif /* SM_ACF */

static void
gen2_readonly_dump(const CHAR16 *tag)
{
    INTN k;

#ifdef PCIE_GEN2_REJOIN
    {
        INTN i, ok = 0, first = -1, nbad = 0;
        for (i = 0; i < RJ16_N; i++) {
            UINT32 cur = mmio_read32(g_rj16[i].addr);
            if (cur == g_rj16[i].val) ok++;
            else {
                if (first < 0) first = i;
                nbad++;
            }
        }
        /* Компактно, по 4 слова на строку. Индексы обязательно зажимаются:
         * RJ16_N = 37 (sizeof от g_rj16[]), а i идёт с шагом 4, так что на
         * последней итерации i+1 в границах, а i+2 и i+3 — уже за массивом.
         * Без зажима это чтение за пределами таблицы (GCC на это ругается
         * правильно). */
        for (i = 0; i < RJ16_N; i += 4) {
            INTN i1 = (i + 1 < RJ16_N) ? i + 1 : i;
            INTN i2 = (i + 2 < RJ16_N) ? i + 2 : i;
            INTN i3 = (i + 3 < RJ16_N) ? i + 3 : i;
            UINT32 v0 = mmio_read32(g_rj16[i].addr);
            UINT32 v1 = mmio_read32(g_rj16[i1].addr);
            UINT32 v2 = mmio_read32(g_rj16[i2].addr);
            UINT32 v3 = mmio_read32(g_rj16[i3].addr);
            ulogf(L"GEN2M  %s [%2d..%2d] 0x%08x=0x%08x%s 0x%08x=0x%08x%s "
                  L"0x%08x=0x%08x%s 0x%08x=0x%08x%s\n",
                  tag, (INTN)i, (INTN)(i + 3),
                  g_rj16[i].addr, v0, (v0 == g_rj16[i].val) ? L"*" : L"!",
                  g_rj16[i1].addr, v1, (v1 == g_rj16[i1].val) ? L"*" : L"!",
                  g_rj16[i2].addr, v2, (v2 == g_rj16[i2].val) ? L"*" : L"!",
                  g_rj16[i3].addr, v3, (v3 == g_rj16[i3].val) ? L"*" : L"!");
        }
        ulogf(L"GEN2S  %s masks on target %d of %d, not on target %d, first %d\n",
              tag, (INTN)ok, (INTN)RJ16_N, (INTN)nbad, (INTN)first);
    }
#endif /* PCIE_GEN2_REJOIN */

    for (k = 0; k < GEN2REGS_N; k++)
        ulogf(L"GEN2R  %s %-14s 0x%08x = 0x%08x\n",
              tag, g_gen2regs[k].name, g_gen2regs[k].addr,
              mmio_read32(g_gen2regs[k].addr));

    /* PCI-конфиг обоих концов: тут пишет phase3, поэтому его состояние —
     * главный вопрос для Gen2. Только чтение. */
    {
        UINTN gc = find_pcie_cap(gBus, gDev, gFn);
        if (gc) {
            UINT32 lk = pci_cfg_rd_bdf(gBus, gDev, gFn, gc + 0x10);
            UINT32 lc2 = pci_cfg_rd_bdf(gBus, gDev, gFn, gc + 0x30);
            ulogf(L"GEN2C  %s GPU   cap@0x%02lx LNKCTL2=0x%04x TLS=%u "
                  L"LNKCTL=0x%04x speed=%u width=%u\n",
                  tag, (INTN)gc, (INTN)(lc2 & 0xFFFF), (INTN)(lc2 & 0xFu),
                  (INTN)(lk & 0xFFFF), (INTN)((lk >> 16) & 0xFu),
                  (INTN)((lk >> 20) & 0xFu));
        } else {
            ulogf(L"GEN2C  %s GPU   pcie_cap not found\n", tag);
        }
    }
    {
        UINTN bb = 0, bd = 0, bf = 0;
        if (find_bridge_to(gBus, &bb, &bd, &bf)) {
            UINTN bc = find_pcie_cap(bb, bd, bf);
            if (bc) {
                UINT32 lk = pci_cfg_rd_idx(gBrIdx, bb, bd, bf, bc + 0x10);
                UINT32 lc2 = pci_cfg_rd_idx(gBrIdx, bb, bd, bf, bc + 0x30);
                ulogf(L"GEN2C  %s BRIDGE cap@0x%02lx LNKCTL2=0x%04x TLS=%u "
                      L"LNKCTL=0x%04x speed=%u width=%u\n",
                      tag, (INTN)bc, (INTN)(lc2 & 0xFFFF), (INTN)(lc2 & 0xFu),
                      (INTN)(lk & 0xFFFF), (INTN)((lk >> 16) & 0xFu),
                      (INTN)((lk >> 20) & 0xFu));
            } else {
                ulogf(L"GEN2C  %s BRIDGE pcie_cap not found\n", tag);
            }
        } else {
            ulogf(L"GEN2C  %s BRIDGE not found\n", tag);
        }
    }
}

/* v3.07: GFX_SPEED_SELECT — РЕНДЕР-СЕЛЕКТОР (2026-09-30). ШАГ 1.
 *
 * ПРЕДЫСТОРИЯ, ПОЧЕМУ ВООБЩЕ ЭТОТ РЕГИСТР.
 *
 * Проект с самого начала был compute-only (docs/70HX-PORT-STATUS.md §2,
 * строка «реализация 3D | не начата»). Анлок открывал только compute:
 * V67 -> PLM (0x823804) -> SS0/SS1 (0x88888888 / 0x00000008). Рендер
 * трогать было нечем, потому что он включается ОТДЕЛЬНЫМ механизмом.
 *
 * Референсный репозиторий, с которого мы начинали
 * (WildFlash1st/cmp90hx-unlock-for-windows, та же линия bendy2), разделяет
 * это прямо в docs/REGISTERS.md:
 *
 *   Compute (открывает early-unlock V67, переживает загрузку ОС)
 *   Render / движки (открывает ТОЛЬКО таблица масок через ботер#2)
 *
 * и даёт сам рычаг:
 *
 *   0x823830  GFX_SPEED_SELECT   открыто 0x00000004   сток 0x3
 *             «главный рычаг рендера (~19×)»
 *
 * Наш собственный код этот рычаг УЖЕ УМЕЕТ (unlock_v2.c:8458 в fire-пути),
 * с комментарием: «Бин 0x4 открывает следующий gfx-бин (на хосте это дало
 * 214.7 -> 4236.7 fps в vkrenderbench)». То есть это ровно тот рычаг,
 * который нам нужен, лежит готовый и был выключен вместе с fire-режимом.
 *
 * ПОЧЕМУ ИМЕННО СЕЛЕКТОР, А НЕ ЧИСЛО ЯДЕР.
 * Мы строили план на «включить 18 секторов из 48». Это опровергнуто
 * замером. GPU-Z Advanced на обеих картах, сопоставление:
 *
 *                    70HX (наша)        50HX (3D работает, 80 fps)
 *   Shaders          3840 = 30 SM/48     3584 = 28 SM/48
 *   ROP/TMU          64 / 120            80 / 224
 *   Boost            1395 MHz            1545 MHz
 *   Texture Fillrate 167.4 GTexels/s     346.1 GTexels/s
 *
 * Вычислительных юнитов у НАС БОЛЬШЕ, чем у карты, которая тянет 80 fps.
 * Значит дефицит ёмкости не может быть причиной, и цель «48 SM / 6144
 * ядер» неверна. (Прогноз «1545 -> 1875 MHz» тоже был неверен: у 50HX
 * буст тоже 1545 MHz; 1875 было у 90HX, другого поколения.)
 *
 * Единственное внутреннее противоречие нашей карты, не зависящее от
 * спорных чисел топологии: nvidia-smi clocks.max.sm = 1545 MHz, а GPU-Z
 * Boost = 1395 MHz. 50HX сидит на своём потолке, мы — на 11% ниже своего.
 * GFX_SPEED_SELECT — это буквально селектор бин Frequency. Карта в низком
 * бине при более высоком собственном потолке.
 *
 * ОРАКУЛ ДЛЯ ПРОВЕРКИ — БЕСПЛАТНЫЙ, БЕЗ БЕНЧМАРКА.
 * Формулы GPU-Z проверены арифметически на обеих картах, совпало точно:
 *     Texture Fillrate = TMU x Boost        Pixel Fillrate = ROP x Boost
 *       120 x 1395 = 167.4 (GPU-Z 167.4)   64 x 1395 = 89.3 (GPU-Z 89.3)
 *       224 x 1545 = 346.1 (GPU-Z 346.1)   80 x 1545 = 123.6 (GPU-Z 123.6)
 * Отсюда ТОЧНОЕ ПРЕДСКАЗАНИЕ. Если сдвинется только бин frequency при той же
 * топаологии, Texture Fillrate обязан стать 120 x 1545 = 185.4 GTexels/s.
 * Если бин поднимет ещё и TMU — будет больше 185.4. Если число осталось
 * 167.4 — запись не встала, и запускать игру не нужно.
 * Второй, независимый признак: FEAT_READOUT_0 (0x00823814), бит 8.
 * Референс: PGRAPH отключён => FEAT_READOUT_0 bit8 = 0.
 *
 * ЧЕГО ЭТОТ ПРОГОН НЕ ДЕЛАЕТ. Ничего опасного для линка: только запись в
 * селектор и чтение обратно. Ни масок (они всё равно не открываются с
 * хоста, §1r), ни кика, ни TLS, ни ретрейна, ни NVRAM. Анлок не
 * затрагивается. Единственное, что пишется кроме селектора — SS0/SS1
 * ПОВТОРНО теми же значениями (идемпотентно), см. комментарий в теле.
 */

/* ==== РУЧКА: значение GFX_SPEED_SELECT (эксперимент E3, 2026-10-06) =======
 *
 * ЗАЧЕМ. Это единственный рычаг рендера в проекте с измеренным эффектом
 * (~19x к стоковому) и единственный, где ответ зависит от ЗНАЧЕНИЯ, а не от
 * факта записи.
 *
 * ИЗМЕРЕННАЯ ЛЕСТНИЦА (Cyberpunk 2077, встроенный бенчмарк, High, без лучей,
 * один и тот же пресет, неизменявшийся; 2026-10-05..06):
 *
 *     значение   fps    Вт    МГц
 *     0x1         9    92   1545
 *     0x2         9     -     -
 *     0x3         9     -     -
 *     0x4        50   135   1545    <-- единственный рабочий
 *     0x5        26     -     -
 *     0x6        16     -     -
 *     0x7         9     -     -
 *
 * ИЗМЕНЕНО 2026-10-06: ВОСЕМЬ значений, семь измерено, и ВСЕ КРОМЕ ОДНОГО
 * дают ровно 9 fps, причём исключение стоит в середине диапазона.
 *
 * ОПРОВЕРГНУТО ТРИ ПРЕДСТАВЛЕНИЯ, все три - замером, не рассуждением.
 *
 * (1) "Отклик нелинеен, значит выше 0x4 есть ступень вверх". Нет: выше 0x4
 *     отклик падает монотонно, 50 -> 26 -> 16 -> 9.
 *
 * (2) "Это селектор частотного бина" (утверждение выше). Нет, и это видно
 *     ПРЯМО: при 0x1 - 9 fps и 92 Вт - частота SM 1545 МГц, РОВНО та же,
 *     что при 0x4 и 50 fps. Частота не переменная здесь вообще: различаются
 *     в 5.5 раза fps и в 1.47 раза ватты, а частота ни на герц.
 *
 * (3) Мотивация, с которой начиналось измерение: "GPU-Z Boost=1395 против
 *     clocks.max.sm=1545, карта в низком бине". Неверно - карта и в базовом
 *     режиме на 1545. GPU-Z показывал статическое поле описания платы, а не
 *     текущее состояние.
 *
 * ВЫВОД. Поле не градуирует скорость, а переключает структуру графического
 * пути: 0x4 включает быстрый путь, остальные значения оставляют карту на
 * базовом уровне 9 fps / 92 Вт. Разница 43 Вт при одинаковой частоте
 * означает, что меняется объем работы, а не темп её выполнения. Побочно:
 * базовые 9 fps - не "совсем ноль", 92 Вт против 75-85 Вт у полностью
 * заблокированной, часть графической работы всё же идёт.
 *
 * ПОЛЕ ИСЧЕРПАНО. Не проверено только 0x0, а ноль - это "нечего включать".
 *
 * ПРАВИЛО. Значение подбирается ТОЛЬКО по измеренному fps в игре. Регистр
 * принимает любое значение и ничего этим не доказывает - ровно эта ошибка
 * стоила нам 9 fps на 0x7 (§9.6). «Застрявший» селектор - это не отказ, а
 * отсутствие эффекта; читать это как отказ нельзя.
 *
 * При значении по умолчании машинный код идентичен текущему, md5 откатного
 * бинаря не меняется.
 *
 * Определение самого макроса перенесено выше, к VERDICT_RULE, вместе с
 * проверкой диапазона 0x0..0x7: вердикт ниже обязан видеть записываемое
 * значение. */

#ifdef GEN2_LINK_TRY
static void
gen2_gfx_try(const CHAR16 *tag)
{
    UINT32 v, feat0, feat1, m800, mb04;
    INTN t, okA = 0, okB = 0;

    feat0 = mmio_read32(0x00823814U);       /* NV_FUSE_FEATURE_READOUT_0 */
    m800  = mmio_read32(0x00823800U);       /* PLM страницы 0x8238xx     */
    mb04  = mmio_read32(0x00823B04U);       /* маска рендера             */
    v     = mmio_read32(0x00823830U);       /* GFX_SPEED_SELECT          */
    /* Подпись "сток 0x3" убрана намеренно: она неправда. При открытых
     * масках регистр приходит то 0x00000003, то 0x00000000 (e1fam,
     * binscan, bin7, bin5 -> 0x0; rmasks, noguard, bin4ok -> 0x3).
     * Это нестабильное состояние железа, а не константа "сток", и
     * подпись обещала больше, чем показывала. Значение само по себе
     * печатается рядом - судить надо по нему. */
    ulogf(L"G2GFX  %s BEFORE : GFX_SPEED_SELECT=0x%08x (actual, not 0x3)  "
          L"0x823800=0x%08x  0x823B04=0x%08x\n", tag, v, m800, mb04);
    ulogf(L"G2GFX  %s BEFORE : FEAT_READOUT_0=0x%08x  bit8 PGRAPH=%u\n",
          tag, feat0, (INTN)((feat0 >> 8) & 1u));

    /* ---- ПОРЯДОК A: GFX_SEL после SS0/SS1 (наш обычный путь) ----------
     *
     * Референс делает наоборот — GFX_SEL ПЕРЕД SS0/SS1, и его код
     * комментирует: «Порядок: до phase3, как GFX_SEL выше». В нашем
     * обычном пути селекторы пишутся раньше, на несколько тысяч строк
     * выше, и переставлять их — значит рисковать работающим compute-анлоком.
     * Поэтому проверяем ОБА порядка в одном прогоне, иначе отрицательный
     * результат был бы неоднозначен: не встало из-за маски или из-за
     * порядка. */
    /* СРАВНИВАЕМ С ТЕМ, ЧТО РЕАЛЬНО ЗАПИСАЛИ, А НЕ С КОНСТАНТОЙ 0x4.
     *
     * Найдено 2026-08-08 на прогоне gfxsel0x7_oracle: стояло
     *     if (v == 0x00000004U) { okA = 1; break; }
     * то есть проверка требовала ВСЕГДА 0x4, независимо от того, что писал
     * рычаг GFX_SPEED_SEL_VALUE. Следствия, все ложные:
     *   - 'ORDER A ... NOT SET' и 'ORDER B ... NOT SET' при фактически
     *     успешной записи (FTPO3 подтверждал 0x823830 = 0x7);
     *   - 'readback 0x00000007 *** DID NOT HOLD ***' - запись держала;
     *   - 10 бессмысленных повторов: 5 попыток в порядке A плюс весь
     *     порядок B, потому что okA остался 0. Отсюда 5,2 с вместо 4,2.
     *
     * Это ровно тот случай, о котором предупреждает правило проекта:
     * «не объявлять успех по факту принятия записи» - и наоборот, не
     * объявлять провал, когда запись прошла. Рычаг GFX_SPEED_SEL_VALUE
     * предназначен для перебора значений, значит проверка обязана
     * сверяться с записываемым значением, иначе она бесполезна на всех
     * значениях, кроме дефолтного. */
    for (t = 0; t < 5; t++) {
        mmio_write32(0x00823830U, GFX_SPEED_SEL_VALUE);
        uefi_call_wrapper(BS->Stall, 1, 50000);
        v = mmio_read32(0x00823830U);
        if (v == GFX_SPEED_SEL_VALUE) { okA = 1; break; }
        /* ОТМАСКИРОВАННОЕ ЗНАЧЕНИЕ НЕ ПОВТОРЯЕМ (2026-10).
         *
         * Если просили ненулевое, а вернули ноль, железо отмаскировало
         * значение в 0. Повторять ту же запись бессмысленно: отмаскирование
         * выполняется на стороне железа, и результат не изменится.
         *
         * На прогоне gfxsel_0x8_oracle это стоило 10 х 100 мс впустую:
         * запись 0x8 дала readback 0x0, и цикл отработал все пять попыток,
         * после чего точно так же сработал и ORDER B. На значении, которое
         * железо принимает, это не срабатывает -- условие требует именно
         * readback == 0 при ненулевом запросе. */
        if (v == 0 && GFX_SPEED_SEL_VALUE != 0) {
            ulogf(L"G2GFX  %s order A: write 0x%08x masked to 0x%08x, "
                  L"stop retrying\n", tag, (UINT32)GFX_SPEED_SEL_VALUE, (UINT32)v);
            break;
        }
        ulogf(L"G2GFX  %s order A attempt %d: readback 0x%08x, want 0x%08x, "
              L"retry\n", tag, (INTN)t + 1, v, (UINT32)GFX_SPEED_SEL_VALUE);
        uefi_call_wrapper(BS->Stall, 1, 50000);
    }
    ulogf(L"G2GFX  %s ORDER A (GFX after SS): GFX_SPEED_SELECT=0x%08x %s\n",
          tag, v, okA ? L"SET" : L"NOT SET");

    /* ---- ПОРЯДОК B: SS0/SS1 заново, потом GFX_SEL ---------------------- */
    if (!okA) {
        /* идемпотентная перезапись тех же значений, которые уже проверил
         * блок селекторов; анлок при этом не меняется */
        mmio_write32(REG_FEAT_OVR_SM_SPD, 0x88888888u);
        mmio_write32(REG_FEAT_OVR_SM_SPD_1, 0x00000008u);
        uefi_call_wrapper(BS->Stall, 1, 50000);
        for (t = 0; t < 5; t++) {
            mmio_write32(0x00823830U, GFX_SPEED_SEL_VALUE);
            uefi_call_wrapper(BS->Stall, 1, 50000);
            v = mmio_read32(0x00823830U);
            if (v == GFX_SPEED_SEL_VALUE) { okB = 1; break; }
            /* то же, что в порядке A: отмаскированное значение не повторяем */
            if (v == 0 && GFX_SPEED_SEL_VALUE != 0) {
                ulogf(L"G2GFX  %s order B: write 0x%08x masked to 0x%08x, "
                      L"stop retrying\n", tag, (UINT32)GFX_SPEED_SEL_VALUE, (UINT32)v);
                break;
            }
            ulogf(L"G2GFX  %s order B attempt %d: readback 0x%08x, want 0x%08x, "
                  L"retry\n", tag, (INTN)t + 1, v, (UINT32)GFX_SPEED_SEL_VALUE);
            uefi_call_wrapper(BS->Stall, 1, 50000);
        }
        ulogf(L"G2GFX  %s ORDER B (GFX before SS): GFX_SPEED_SELECT=0x%08x %s\n",
              tag, v, okB ? L"SET" : L"NOT SET");
    }

    /* v3.45: РЕЗУЛЬТАТ РЕНДЕРА БОЛЬШЕ НЕ ВЫБРАСЫВАЕТСЯ.
     *
     * До этого okA/okB были локальными: функция печатала SET/NOT SET в лог и
     * отдавала наружу void. Экранный вердикт не мог сказать ничего о графике,
     * потому что единственный носитель результата исчезал на выходе из
     * функции, а повторное чтение после FLR невозможно - MMIO мёртв.
     *
     * ORDER B имеет смысл учитывать наравне с A: если когда-нибудь встанет
     * B, это всё равно разблокированная графика, и вердикт обязан сказать
     * UNLOCKED, а не NOT.
     *
     * ============ v3.46: g_snapGfx ОБНОВЛЯЕТСЯ ЗДЕСЬ ============
     *
     * Баг, найденный на первом же прогоне с баннером (usb-log-1004-135604):
     * вердикт печатал COMPUTE ONLY при том, что рендер встал.
     *
     *     G2GFX  ORDER A ... GFX_SPEED_SELECT=0x00000004 SET
     *     VRC    ... GFX_SPEED_SELECT = 0x00000000
     *
     * Причина в порядке вызовов, а не в логике. snapshot_state() стоит на
     * строке ~11823, а эта функция - на ~11876, то есть СНИМОК СДЕЛАН ДО
     * ЗАПИСИ СЕЛЕКТОРА. В snapshot_state() стояло
     *     g_snapGfx = g_gfxOk ? g_gfxVal : mmio_read32(0x00823830U);
     * и на момент снимка g_gfxOk ещё был FALSE, поэтому брался живой
     * readback - корректное значение ДО записи. Лог это подтверждает:
     * 'G2GFX BEFORE : GFX_SPEED_SELECT=0x00000000'. Потом селектор записался,
     * g_gfxVal стал 0x4, но обновить g_snapGfx уже никто не стал: дальше
     * do_flr(), MMIO мёртв, и вердикт напечатал устаревшее 0.
     *
     * Раньше я проверил, что запись селектора происходит ДО FLR, и на этом
     * основании решил, что снимок её увидит. Не следовало: из «запись до
     * FLR» не следует «снимок после записи».
     *
     * Теперь значение, проверенное здесь, кладётся и в снимок. MMIO в этой
     * точке жив, а после FLR перечитывать уже нечем. */
    g_gfxOk  = (BOOLEAN)(okA || okB);
    g_gfxVal = v;
    g_snapGfx = v;

    /* Скан 0x0..0x7 УДАЛЁН (v3.14).
     *
     * Что он дал: все восемь значений ПРИНИМАЮТСЯ, readback точно совпал с
     * записанным в каждом случае. То есть это обычный 3-битный RW-регистр,
     * а не enable-флаг с валидацией, и референсное 0x4 — не «единственно
     * верное», а просто то, что получилось у автора на 90HX.
     * FEAT_READOUT_0 оставался 0x00000033 (bit8=0) на всех восьми, то есть
     * bit8 с этим селектором не связан. SS0=0x88888888 и SS1=0x00000008 не
     * сбились ни на одном шаге.
     *
     * Что стоило: замер в игре показал 0x4 -> 50 fps, а 0x7 -> 9 fps.
     * Подбирать значения вслепую нельзя: это не «разгон вверх», а разные
     * состояния, часть из которых хуже. Поэтому скан убран и оставлено
     * единственное измеренно рабочее значение. Проверять 0x5 и 0x6 стоит
     * только отдельной задачей и только если игра вернётся к 50 fps. */
    ulogf(L"G2SCN  %s bin scan disabled after measurement: 0x4 = 50 fps, "
          L"0x7 = 9 fps (degradation), all 8 values were accepted\n", tag);

    /* Возврат к ПОДТВЕРЖДЁННО РАБОЧЕМУ значению.
     *
     * ЗАМЕР v3.14, замер в игре — ВАЖНЕЕ ВСЕГО ОСТАЛЬНОГО:
     *     GFX_SPEED_SELECT = 0x4 -> 50 fps, 135 Вт
     *     GFX_SPEED_SELECT = 0x7 ->  9 fps
     * То есть 0x7 — не «ещё быстрее», а ДЕГРАДАЦИЯ в 5.5 раза, при том
     * что регистр значение принял (readback 0x00000007 OK) и FEAT_READOUT_0
     * не изменился. Значит бины выше 4 не «разгон», а другое состояние
     * с худшей конфигурацией рендера, и подбирать их вслепую нельзя.
     *
     * Отсюда решение: скан 0x0..0x7 УБРАН. Он свою задачу выполнил —
     * показал, что это обычный 3-битный RW-регистр, что все значения
     * принимаются, и что bit8 FEAT_READOUT_0 с ним не связан. Оставлять
     * восемь записей в селектор ради уже известного ответа незачем, а
     * лишнее окно для расхождений с 0x4 — лишний риск.
     *
     * ПОЛНАЯ КАРТА ЗАМЕРОВ В ИГРЕ (встроенный бенчмарк Cyberpunk 2077,
     * одинаковые настройки, замеры сопоставимы между собой):
     *     0x2 ->  9 fps
     *     0x4 -> 50 fps, 135 Вт   (подтверждено трижды)
     *     0x5 -> 26 fps
     *     0x7 ->  9 fps
     *
     * ГЛАВНЫЙ ВЫВОД: это НЕ убывающая функция, то есть никакой лестницы
     * «выше значение - ниже частота» здесь нет. 0x5 (26 fps) ЛУЧШЕ и 0x2
     * (9 fps), и 0x7 (9 fps). Моя прежняя модель «селектор бин Frequency,
     * где 4 - верх полезного диапазона» этим опровергнута и была неверной.
     *
     * Что на самом деле: 0x4 - ЕДИНСТВЕННЫЙ рабочий режим, а остальные
     * значения - разные неполные конфигурации. 9 fps это пол, то есть
     * «графика фактически выключена»; 0x5 даёт частично включённый режим
     * (четверть от 50). Переход 0x3 -> 0x4 и есть та разблокировка, про
     * которую писал референс.
     *
     * ПРАКТИЧЕСКИЙ ВЫВОД: значения 0x0, 0x1, 0x3 и 0x6 проверять НЕЧЕГО.
     * Диапазон 0x0..0x3 заведомо мёртвый пол (0x2 = 9 fps, 0x3 = сток с
     * нулевой игровой производительностью), а 0x6 заведомо хуже 0x5.
     * Тратить на них перезагрузки - значит тратить их ради подтверждения
     * очевидного. Вопрос по этому регистру ЗАКРЫТ: 0x4 это потолок, и
     * 50 -> 80 fps через него не получить ни при каком значении.
     *
     * Отдельно зафиксировано: значение ДО нашей записи нестабильно. При
     * открытых масках (render_open_gfx_masks на строке 9022 идёт ДО
     * gen2_gfx_try на 9259) регистр приходил то 0x00000003, то
     * 0x00000000, поэтому 0x3 - не «сток», а одно из двух состояний,
     * которые железо выбирает само. На результаты это не влияет: мы всегда
     * пишем своё значение и всегда проверяем readback.
     *
     * Во всех прогонах с ненулевым значением селектора карта вела себя
     * одинаково, то есть 9/26 fps - следствие значения, а не побочки:
     * те же 25 из 37 масок, SS0=0x88888888, SS1=0x00000008,
     * OKCHK frtsErrCode=0, wpr2Lo/wpr2Hi OK.
     *
     * Критерий отбора во всех этих пробах - ТОЛЬКО fps в игре. Регистр
     * принимает любое значение 0x7, но принятие значения ничего не значит
     * (это стоило нам 9 fps на 0x7 и 9 fps на 0x2). */
    mmio_write32(0x00823830U, GFX_SPEED_SEL_VALUE);
    uefi_call_wrapper(BS->Stall, 1, 100000);
    v     = mmio_read32(0x00823830U);
    feat1 = mmio_read32(0x00823814U);
     ulogf(L"G2SUM  %s wrote GFX_SPEED_SELECT=0x%08x (kartina: 0x2=9fps, "
          L"0x4=50fps/135W, 0x5=26fps, 0x7=9fps - lestnicy net, 0x4 "
          L"edinstvennyi rabochii): readback 0x%08x %s; "
          L"FEAT_READOUT_0=0x%08x bit8=%u; DMAQ full=%d idle=%d; "
          L"SS0=0x%08x SS1=0x%08x\n",
          tag, (UINT32)GFX_SPEED_SEL_VALUE, v,
          (v == GFX_SPEED_SEL_VALUE) ? L"HELD" : L"*** DID NOT HOLD ***",
          feat1, (INTN)((feat1 >> 8) & 1u),
          (INTN)g_dmaFullTo, (INTN)g_dmaIdleTo,
          mmio_read32(REG_FEAT_OVR_SM_SPD),
          mmio_read32(REG_FEAT_OVR_SM_SPD_1));
}
#endif /* GEN2_LINK_TRY */

/* v3.08: ОТКРЫТИЕ ДВУХ МАСОК, КОТОРЫЕ ЗАПИРАЮТ GFX_SPEED_SELECT (2026-09-30).
 *
 * ЗАМЕР v3.07 дал чистый отрицательный результат:
 *   ДО    : GFX_SPEED_SELECT=0x00000003  0x823800=0xFFFFFF8F  0x823B04=0xFFFFFF8F
 *           FEAT_READOUT_0=0x00000033  bit8 PGRAPH=0
 *   пор. A (GFX после SS): 5 попыток, все readback 0x00000003   НЕ ВСТАЛ
 *   пор. B (GFX перед SS): 5 попыток, все readback 0x00000003   НЕ ВСТАЛ
 *   ПОСЛЕ : GFX_SPEED_SELECT=0x00000003, FEAT_READOUT_0 не изменился
 *
 * Оба порядка дали идентичный отказ, 10 записей, ноль эффекта — порядок не
 * был помехой, отрицательный результат однозначен. Причина одна: обе маски-
 * предусловия заперты. Референс: 0x823800 «без него GFX_SEL не пишется».
 * Наш комментарий (стр. 8461): «липнет только при открытом PLM 0x823b04».
 * Совпадает с 1r: с хоста не открывается ни одна из 36.
 *
 * ВАЖНОЕ УТОЧНЕНИЕ, КОТОРОЕ МЕНЯЕТ ПЛАН. V67-ROP ПАРАМЕТРИЗОВАН. В цикле
 * таблицы адрес и значение не зашиты в payload, а берутся из его памяти:
 *     pv = v67Phys + 0xf948  -> значение
 *     pa = v67Phys + 0xf960  -> адрес
 * То есть payload умеет писать ЛЮБОЙ регистр, и расширять его НЕ НУЖНО.
 * Это снимает вопрос, стоявший после 1r («нужно ли добывать исходник V67») —
 * исходник не нужен, обобщённый примитив уже есть.
 *
 * ПОЧЕМУ ТОЛЬКО ДВЕ ЗАПИСИ, А НЕ ВСЯ ТАБЛИЦА.
 * 1) Это ровно те два адреса, без которых GFX_SPEED_SELECT не встаёт.
 *    Остальные 34 к рендер-селектору отношения не имеют.
 * 2) У референса наблюдался ОДИН зависший гость на ~30 минициклах подряд
 *    (GOTCHAS.md). Вся таблица = 36 записей, это заведомо за его порогом.
 *    Две записи на проход, до 3 проходов = максимум 6 минициклов, с запасом.
 * 3) Быстро: два миницикла вместо 10.8 минут полного свипа.
 *
 * ПОРЯДОК. Ставим ДО блока селекторов: референс делает именно так
 * (маски -> GFX_SEL -> SS0/SS1), и GFX_SEL липнет только при открытых
 * масках. Заодно не трогаем ни g_gen2Fire (селекторы продолжат выполняться),
 * ни фикс Code 43 в обычном хвосте — обе причины, по которым полный свип
 * был уведён в fire-режим.
 *
 * БЕЗОПАСНОСТЬ. WPR2 сохраняется и восстанавливается вокруг каждого вызова
 * booter (42.10: booter_load_v67() портит WPR2 настоящим образом, сдвиг
 * -836 КБ, и восстановление может не удержаться — поэтому результат проверяем
 * и пишем в лог). После FLR BAR0 и command восстанавливаем сами, как в
 * боевом цикле таблицы. NVRAM не пишем.
 */
#ifdef RENDER_MASKS
/* Определения этих трёх лежат НИЖЕ по файлу, а наша функция стоит выше,
 * поэтому нужны forward-декларации — иначе implicit declaration и
 * conflicting types. */
static EFI_STATUS do_flr(void);
static EFI_STATUS early_unlock_path(UINT64 ucodePhys, UINT64 fwsecPhys,
                                    UINT64 wprMetaPhys);
static EFI_STATUS booter_load_v67(UINT64 wprMetaPhys, UINT64 ucodePhys);

static void
render_open_gfx_masks(const CHAR16 *tag, UINT64 wprMetaPhys, UINT64 ucodePhys,
                      UINT64 fwsecPhys, UINT64 v67Phys)
{
    UINT64 fx_ph;   /* разложение рендер-цикла: именно здесь живут 179 с */
    /* ВНИМАНИЕ, ЭТОТ БЛОК ОПИСЫВАЕТ БЫЛОЕ СОСТОЯНИЕ, И ОН УТВЕРЖДАЛ НЕПРАВДУ.
     *
     * ОКНО XVE здесь было названо «дверью» GFX_SPEED_SELECT. Это неверно, и
     * опровергнуто на железе (v3.40, два прогона). Пять масок
     * 0x88FE8…0x88FF8 и 0x88AB4 — это PCIe-домен, к рендеру отношения не
     * имеют: с их удалением из списка GFX_SPEED_SELECT встаёт в 0x4, Cyberpunk
     * идёт с теми же 50 fps / 135 Вт, а прогон сократился с 15 964 до
     * 8 470 мс. Апстрим 90HX (71db92c, v3.05) был прав, когда написал в
     * REGISTERS.md «XVE/XP3G — это PCIe, а не render»; мы ему не поверили,
     * потому что у нас было железо под рукой, а у него только QEMU, — и
     * металл в итоге согласился с апстримом, а не с нами.
     *
     * ЧТО ТЕПЕРЬ ОТКРЫВАЕТСЯ: 0x823800 и 0x823B04, оба нужны. Что не нужно:
     * XVE и семейство 0x8E1B0..0x8E1F0. Итог: 8 из 8 больше не нужно, хватает
     * 2 из 2.
     *
     * История ниже сохранена, потому что показывает, КАК была получена ложная
     * уверенность: каждый шаг выглядел разумным, и вывод делался из замеров
     * («первая цель открылась»), а не из измерения того, что эти адреса дают.
     *
     * Первый прогон (v3.08) целился в 0x823B04 по комментарию v2.100
     * («липнет только при открытом PLM 0x823b04») и в 0x823800. Итог:
     *   0x00823800 -> 0xFFFFFFFF ОТКРЫТА (polls=0)   механизм рабочий
     *   0x00823B04 -> 0xFFFFFF8F   3 попытки по 1000 polls, не сдвинулась
     * То есть v2.100-комментарий про 0x823B04 — единственный источник этого
     * требования, и на 70HX он не подтвердился. А 0x823800, который
     * референс называет вполне достаточным («без него GFX_SEL не пишется»),
     * открылся — и GFX_SPEED_SELECT всё равно не встал. Значит дверь
     * другая, и наш собственный комментарий называл её прямо.
     *
     * v3.10 (состав из 8 адресов): первые 6 открылись с polls=0, и
     * GFX_SPEED_SELECT ВСТАЛ = 0x00000004. Итог прогона — 8 из 8. Это первая
     * работающая игровая разблокировка в проекте: Cyberpunk 2077 50 fps,
     * 135 Вт в игре, раньше было ноль.
     *
     * ЧТО ОСТАЛОСЬ ДО 50HX (28 SM / 80 ROP / 224 TMU / 80 fps / 230 Вт).
     * Не открыто 17 масок семейства 0x8E1B0..0x8E1F0 — референс прямо пишет
     * про первые четыре: «0x8E1B0..BC | PLM-маски (4 шт) | открывают записи
     * в 0x8e1xx». Блок OPTB 0x8200D0..F4 пропускаем: он стабильно валит
     * гостя в ресет (наши итерации [29-31], и референс пишет то же).
     * 0x88084 пропускаем: LINK_CAP, заведомо RO. Итого 17 + 1 (0x88AB4,
     * который уже открыт) — гоняем все 18, лишний отработает за polls=0.
     * 17 минициклов против ~30, на которых референс ловил зависание гостя.
     *
     * ГЛАВНОЕ ИСПРАВЛЕНИЕ ЭТОГО ПРОГОНА: снят гард «ботер#1 только один
     * раз». Замер v3.09 дал безупречный по позициям паттерн:
     *   цель #1  -> ОТКРЫТА  (polls=0)
     *   цели #2..#6 -> заперты (polls=1000), и во втором проходе тоже
     * и в прошлом прогоне ровно то же: 1-я открылась, 2-я нет.
     * Срабатывает ТОЛЬКО ПЕРВАЯ запись прогона. Причина — гард, который
     * стоит и в историческом свипе (unlock_v2.c:8542, `if (!g_fwsecOnce)`):
     * ботер#1 не зовётся со второй итерации, а после FLR именно он заново
     * открывает PLM и сбрасывает счётчик выстрелов. Комментарий рядом
     * утверждает «FWSEC от запуска не зависит: образ уже залит в IMEM» —
     * это верно про FWSEC и неверно про ботер: early_unlock_path зовёт всю
     * цепочку BL->FWSEC->WPR2->RISCV->ботер#1, и без неё ботер#2 после
     * FLR не имеет к чему целиться. Этим же, вероятно, объясняется и
     * «свип не доходит до FF» из v3n: за прогон реально писалась ровно
     * одна запись таблицы, а остальные циклы уходили впустую.
     */
    /* Размер МЕНЯЕТСЯ САМ, через sizeof. Раньше здесь стояло число, и когда
     * список вырос с 8 до 25, компилятор тихо отбросил 7 хвостовых
     * элементов с warning 'excess elements in array initializer' — то есть
     * ровно тот класс молчаливого отказа, из-за которого селектор и не
     * вставал. Считать элементы руками больше нельзя. */
    //
    /* ---------------------------------------------------------------------
     * v3.17: СПИСОК СОКРАЩЁН С 25 ДО 8. Это доказанная эквивалентность,
     * а не компромисс ради скорости.
     *
     * ЗАМЕР НА ЖЕЛЕЗЕ, а не рассуждение:
     *   v3.10 (эти 8 адресов)  -> GFX_SPEED_SELECT=0x4 ***ВСТАЛ***
     *                            -> Cyberpunk 2077 50 fps / 135 Вт
     *   v3.11 (+17 адресов)    -> пользователь: 50 fps, 135 Вт, ТО ЖЕ
     *   цитата (docs/70HX-PORT-STATUS.md §1u): «Добавление 17 масок
     *   семейства 0x8E1xx не дало эффекта. Значит маски — необходимое,
     *   но не достаточное условие.»
     *
     * ЗАЧЕМ ВООБЩЕ БЫЛИ 17 ЭТО АДРЕСОВ: референс прямо пишет про первые
     * четыре — «PLM-маски, открывают записи в 0x8e1xx». То есть они нужны
     * ИСКЛЮЧИТЕЛЬНО для записи в 0x8e1xx, а это регистры PCIe-возможностей,
     * то есть PCIe Gen2. В этой сборке Gen2 выключен дважды:
     *     -DFULL_NOGEN2 в build.sh
     *     g_gen2Enable = FALSE (unlock_v2.c:1838)
     * У референса xrip/cmp50hx-unlock он удалён полностью (issue #25:
     * предзагрузочный ретрейн вешал платы Intel X99/X299; гейт XP3G
     * 0x8e1b0 на предзагрузочной стадии читается 0xffffff8f — закрыт,
     * и открывает его GSP-RM уже внутри ОС).
     *
     * ЦЕНА ВОПРОСА: 17 итераций по 7,61 с = 121 секунда из 3 мин 40 с,
     * то есть 55 % времени прогона, на то, что замер показывает
     * бесполезным.
     *
     * ---------------------------------------------------------------------
     * v3.40: СПИСОК СОЖАТ С 8 ДО 2. ГИПОТЕЗА БЫЛА; ПОДТВЕРЖДЕНА НА МЕТАЛЛЕ.
     * Два прогона: 8 470 и 8 451 мс (было 15 964 / 15 958). Рендер не
     * пострадал: GFX_SPEED_SELECT=0x4, те же 50 fps / 135 Вт.
     *
     * ЧТО ЗА ПОВОДОМ. Апстрим 90HX (WildFlash1st/cmp90hx-unlock-for-windows,
     * коммит 71db92c, v3.05) в той же задаче оставил ровно эти два адреса:
     * его NOGEN2-сборка идёт только по FEAT-PLM 0x823804 / 0x823800 /
     * 0x823b04, а 34 маски XVE/XP3G/OPTB объявлены PCIe-доменом, а не
     * рендером, и выкинуты. Его третий адрес (0x823804) открывает стоковый
     * payload ботера#1, поэтому в наш список он не входит и раньше.
     *
     * НАШИ 6 ОТБРАННЫХ — ровно то, что он выбросил: пять 0x88FE8..0x88FF8
     * и 0x88AB4. То есть комментарий выше («окно XVE — дверь к
     * GFX_SPEED_SELECT») и его REGISTERS.md («XVE/XP3G — это PCIe, а не
     * render») противоречат друг другу. Разбираться надо на железе, а не
     * выбирать сторону по апстриму: у него рендер подтверждён только в
     * QEMU (KNOWN-ISSUES #4), у нас на 8 масках есть металл — 50 fps /
     * 135 Вт.
     *
     * ЦЕНА ВОПРОСА. Рендер-цикл — 8 итераций по 1,24 с (usb-log-v339, метки
     * TIME) и есть ~10,0 с из 15,96 с. Шесть итераций из них обслуживают
     * адреса, которые мы НИКОГДА не проверяли по отдельности: v3.09 показал
     * лишь, что первой целью открывается первая запись, а цели 2..6 нет —
     * и это списали на гард ботера, а не на сами адреса.
     *
     * ОТКАТ, ЕСЛИ НЕ ВСТАЛО: вернуть эти 6 адресов, они рабочие. md5
     * рабочей 8-масочной сборки — 67f7b5a84f8efeba5a4718004b0589ed.
     * НЕ ПОНАДОБИЛСЯ: подтверждено, откат не выполнялся. */
    static const UINT32 tgt[] = {
        /* PLM страницы 0x8238xx и гейт GFX_SPEED_SELECT — оба открылись в
         * v3.10, и на них держится GFX_SPEED_SELECT = 0x4 */
        0x00823800U, 0x00823B04U };
/* БЫЛО 25 (v3.10), потом 8 (v3.17), теперь 2 (v3.40). Первые 8 были рабочие
 * на железе; 6 из них отброшены в v3.40 как гипотеза. Остальные 17 НЕ пишутся
 * и НЕ нужны, потому что единственная их функция — разрешить запись в
 * 0x8e1xx (PCIe Gen2), а он выключен:
 *     0x0008E1B0U, 0x0008E1B4U, 0x0008E1B8U, 0x0008E1BCU, 0x0008E1C0U,
 *     0x0008E1C4U, 0x0008E1C8U, 0x0008E1CCU, 0x0008E1D0U, 0x0008E1D4U,
 *     0x0008E1D8U, 0x0008E1DCU, 0x0008E1E0U, 0x0008E1E4U, 0x0008E1E8U,
 *     0x0008E1ECU, 0x0008E1F0U
 * Замер их открытия: 24 из 25, polls=0 — механика работает. Их эффект:
 * ноль fps и ноль ватт (PORT-STATUS §1u).
 *
 * ВНИМАНИЕ, ПРЕДПИСАНИЕ ОТОЗВАНО (2026-10-10). Раньше здесь стояло «если Gen2
 * когда-нибудь будет включён обратно, эти 17 адресов надо вернуть ПЕРВЫМИ».
 * Это больше не так, и предписание снято замерами, а не мнением:
 *   - референс iatethelogs/cmp90hx_pwner (единственный найденный инструмент,
 *     где PCIe Gen2 реально работает) держит ровно ДВЕ маски —
 *     MASK_XVE=0x00088fe8 и MASK_FEAT=0x00823800. Адреса 0x8E1xx он не
 *     трогает нигде: ни в масках, ни в policy set;
 *   - наш же PORT-STATUS §1p (Хабр 1082724, тот же автор) даёт ту же пару;
 *   - E-B: семь полей policy set встали после открытия ОДНОГО гейта 0x8E1B0,
 *     без остальных шестнадцати;
 *   - E-G: записи в соседний блок 0x8200D0..0xF4 ВАЛЯТ гостя в ресет
 *     (прогоны 29-31, три подряд).
 * Список масок при возврате стадии — {0x00823800, 0x00088FE8}.
 * Разбор: KNOWN-ISSUES.md §51.7, порядок и офсеты PCI config —
 * docs/70HX-XP3G-GATE-V67.md §4a.11. Код здесь не менялся. */
#define NTGT ((INTN)(sizeof(tgt) / sizeof(tgt[0])))
    volatile UINT32 *pv = (volatile UINT32 *)(UINTN)(v67Phys + 0xf948);
    volatile UINT32 *pa = (volatile UINT32 *)(UINTN)(v67Phys + 0xf960);
    INTN pass, k, tries, done;
    UINT32 v, saveBar, wLo, wHi;

    /* v3.21 (этап 7): преамбула рендера была немаркированной дырой в 3031 мс.
     *
     * Что известно из прогона v321: между меткой 'early path finished' и
     * первой меткой 'render: FLR' проходит 3530 мс, из которых сама фаза
     * FLR стоит 499 мс. То есть 3031 мс уходит в код, который печатает
     * всего несколько строк и ни одной метки времени.
     *
     * Метка ниже закрывает ровно эту преамбулу: заголовок плюс восемь
     * чтений BEFORE. Если она окажется пустой, значит время в вызывающем
     * коде до входа в функцию, и следующий замер ставится там. */
    {
        UINT64 tq = fx_now_us();
        UINTN g2Suspect = 0;
    ulogf(L"G2RMK  %s === opening GFX_SPEED_SELECT gates: "
          L"FEAT PLMs only, XVE window dropped in v3.40 (hypothesis) ===\n",
          tag);
    for (k = 0; k < NTGT; k++) {
        UINT32 g2Bv = mmio_read32(tgt[k]);
        ulogf(L"G2RMK  %s BEFORE  0x%08x = 0x%08x\n", tag, tgt[k], g2Bv);
        if (g2Bv == 0xFFFFFFFFU) g2Suspect++;
    }
        /* v3.53, НАХОДКА 1: 0xFFFFFFFF БЫВАЕТ НЕ «МАСКА ОТКРЫТА», А «BAR0 МЁРТВ».
         *
         * Источник - Linux-инструмент iatethelogs/cmp90hx_pwner, rejoin16-cycle.sh,
         * сформулировано буквально: "After `modprobe -r` the device drops into a
         * low-power state (BAR0 reads back 0xffffffff, every write REJECTED)".
         * То есть чтение неотображённого BAR в PCIe даёт все единицы, а не fault,
         * и значение 0xFFFFFFFF двусмысленно:
         *
         *   0xFFFFFF8F - устройство живо, маска закрыта (наше нормальное)
         *   0xFFFFFFFF - маска открыта ЛИБО BAR0 мёртв
         *
         * ЧТО ЭТО ЗНАЧИТ У НАС. mmio_read32() - голое разыменование без всякой
         * проверки (стр. 1365). Если BAR0 умрёт, то по цепочке:
         *   - цикл k ПОСчитает маску открытой и уйдёт в continue (стр. 5374),
         *     ботер#2 не выстрелит;
         *   - пересчёт done увидит то же значение;
         *   - G2RMS напечатает "GFX gates open 2 of 2" - правдоподобно и неверно;
         *   - GFX_SPEED_SELECT не встанет, и в логе не будет НИ ОДНОЙ строки
         *     о том, что BAR0 мёртв.
         *
         * ЧТО ДЕЛАЕМ. Только Print. Свидетель УЖЕ есть в логе и печатался всегда:
         * строка BEFORE даёт 0xFFFFFF8F = «живо, но закрыто». Считаем прямо в
         * этом цикле, то есть НУЛЕВЫЕ дополнительные чтения MMIO.
         *
         * НОРМАЛЬНОЕ СОСТОЯНИЕ - 0xFFFFFF8F, проверено на железе:
         * usb-log-1004-183613.txt строки 277-278. Ни одна сборка после этого
         * не должна печатать BAR0 SUSPECT; если напечатала, прогон ничего не
         * доказал и первым делом смотреть сюда. */
        if (g2Suspect)
            ulogf(L"G2RMS  %s BAR0 SUSPECT: %d of %d targets already read "
                  L"0xFFFFFFFF before the sweep - indistinguishable from an "
                  L"OPEN mask on a DEAD BAR0. If GFX_SPEED_SELECT does not "
                  L"stick, read this line first.\n",
                  tag, (INTN)g2Suspect, (INTN)NTGT);
        else
            ulogf(L"G2RMS  %s BAR0 alive: all %d targets read a partial mask, "
                  L"so 0xFFFFFFFF later means really open\n",
                  tag, (INTN)NTGT);
        fx_mk_acc(tq, L"render: preamble BEFORE reads");
    }

    /* v3.17: ОДИН проход по 8 целям. Прежде здесь стоял один проход по 25,
     * из которых 17 — это 0x8E1B0..0x8E1F0, открывавшие запись в 0x8e1xx
     * (PCIe Gen2). Замер: они не дали ни одного fps и ни одного ватта
     * сверх этих восьми (PORT-STATUS §1u), а стоили 121 с. */
    for (pass = 0; pass < 1; pass++) {
        /* v3.20: ЗДЕСЬ СТОЯЛ ЛИШНИЙ fx_ph_begin(), И ЭТО БЫЛА ТРЕТЬЯ
         * ПОДРЯД ПОЛОМКА ТАБЛИЦЫ ФАЗ.
         *
         * Он открывал фазу в теле цикла pass, и закрытия для этого begin
         * НИГДЕ не было. Счётчик глубины рос на 1 при каждом вызове
         * функции, и после нескольких итераций КАЖДАЯ следующая фаза
         * получала dep>0, то есть помечалась «вложенной» и исчезала из
         * верхнего итога.
         *
         * Наблюдалось в прогоне v3.19 (usb-log-v319.txt) ровно так:
         *     SUM top-level 0 us
         *     CHECK 0 us (phases vs elapsed 55937285 us: unaccounted 100%)
         *     все 15 фаз помечены (inside)
         *
         * Подтверждение из самого лога: 'booter: reset+scrub x8' при 15
         * вызовах booter_load_v67 - внутренние фазы перекрываются, и
         * накопленный перекос глубины их замикает.
         *
         * Начинать фазу здесь незачем: в теле цикла k все фазы уже
         * открываются и закрываются попарно (см. fx_ph_end ниже). */
        done = 0;
        for (k = 0; k < NTGT; k++) {
            /* v3.34, ЭТАП 17: СКОЛЬКО МАСОК УЖЕ ОТКРЫТО В НАЧАЛЕ ИТЕРАЦИИ.
             *
             * ЗАЧЕМ. Рендер-цикл стоит 10,9 с из 17,4 - это 8 масок, и на
             * каждую свой FLR-цикл (500 мс паузы + 689 мс early_unlock_path
             * + 95 мс booter + 75 мс ROP = 1,36 с). Если на одну маску нужен
             * один цикл - батчить нельзя и 17,4 с это ПОТОЛОК. Если часть
             * масок открывается сама - цикл можно делать раз в несколько
             * масок, и выигрыш доходит до 7 с, то есть уход НИЖЕ 14 с.
             *
             * ЧТО УЖЕ ИЗВЕСТНО И НЕ ОТВЕЧАЕТ НА ВОПРОС:
             *   перед стартом цикла  - все 8 закрыты (строки G2RMK BEFORE)
             *   после своей итерации - каждая маска OPEN, polls ~79
             *                          (строки G2RMK ... became)
             *   состояние В НАЧАЛЕ итерации - не логировалось
             *
             * ЧТО ДАЁТ ОТВЕТ:
             *   уже открыто ровно k  -> каждый FLR-цикл открывает ровно одну
             *                            маску, батчить нельзя, потолок 17,4 с
             *   уже открыто больше k -> батчить можно
             *
             * ЧТО ЭТО НЕ МЕНЯЕТ. Только чтения и Print. Ни логика, ни
             * тайминги не затронуты: 8 чтений x 8 итераций x 12,3 мкс = 0,8 мс.
             * Риск для железа нулевой.
             *
             * Заметьте: механизм батчинга в коде УЖЕ ЕСТЬ, строкой ниже -
             * открытая маска пропускается через continue. Вопрос только в
             * том, срабатывает ли он, а лог этого не показывал. */
            {
                UINTN g2Pre = 0;
                UINTN g2J;
                UINT32 g2S0, g2S1;
                for (g2J = 0; g2J < NTGT; g2J++)
                    if (mmio_read32(tgt[g2J]) == 0xFFFFFFFFU) g2Pre++;
                ulogf(L"G2RMC %s top of iter %d: already open %d of %d\n",
                      tag, (INTN)k, (INTN)g2Pre, (INTN)NTGT);
                /* v3.53, НАХОДКА 2: ГЕЙТ КАНАРЕЙКИ ПО SS0/SS1.
                 *
                 * Тот же cmp90hx_pwner, rejoin16-cycle.sh, дважды:
                 *   "Re-lock the compute selectors BEFORE unloading, while BAR0
                 *    is still accessible" и "the V67 canary saw 'already
                 *    present' and skipped the Booter chain entirely
                 *    ('(no REJOIN16 lines!)' + PCIe FAIL every cycle)".
                 *
                 * Механика: цепочка V67 срабатывает ТОЛЬКО если SS0/SS1 ещё не
                 * полные. У них при входе в ОС селекторы всегда полные, поэтому
                 * они ПРИНУДИТЕЛЬНО обнуляют 0x0082381c/0x00823820 перед выгрузкой
                 * модуля и проверяют readback - функция relock().
                 *
                 * У НАС ПРЕДУСЛОВИЕ ВЫПОЛНЯЕТСЯ БЕСПЛАТНО. Цикл масок идёт ДО
                 * блока селекторов (вызов render_open_gfx_masks стоит выше
                 * "--- Селекторы ---"), и на железе SS0/SS1 в этот момент
                 * 0x00000000: usb-log-1004-183613.txt даёт PRE SS0=0x00000000,
                 * а "FUSE before 0x0082381C = 0x00000000 <- SS0 (we write here)"
                 * печатается уже ПОСЛЕ цикла масок.
                 *
                 * ЭТО НЕ СВОЙСТВО КОДА, А ПОБОЧНЫЙ ЭФФЕКТ ПОРЯДКА. Ровно в эту
                 * ловушку они и попали, и потратили месяцы: сломалось не железо -
                 * apt --fix-broken подтянул другие libnvidia, пересобрал
                 * initramfs и изменил power management, после чего цепочка
                 * перестала стрелять молча.
                 *
                 * ПОЧЕМУ ЭТО ВАЖНО ИМЕННО СЕЙЧАС. Ближайшая задача - вернуть PCIe
                 * Gen2, а его конфиг по архитектуре идёт в КОНЕЦ прогона, то есть
                 * ПОСЛЕ блока селекторов. Любой рефакторинг, который сдвинет
                 * рендер-цикл за селекторы, тихо сломает предусловие: ботер
                 * перестанет стрелять, маски останутся 0xFFFFFF8F, и единственная
                 * строка, которая об этом скажет, - новая, эта.
                 *
                 * Ничего не меняется: два чтения MMIO на итерацию, ~25 мкс на двух
                 * итерациях. Только печать. Строка G2RMC выше остаётся байт в
                 * байт - на неё ссылается приёмка (PLAN-SPEED.md §4.1), и
                 * flash-build.ps1 завязан на её текст. */
                g2S0 = mmio_read32(REG_FEAT_OVR_SM_SPD);
                g2S1 = mmio_read32(REG_FEAT_OVR_SM_SPD_1);
                ulogf(L"G2RCC %s iter %d canary precondition: SS0=0x%08x "
                      L"SS1=0x%08x %s\n", tag, (INTN)k, g2S0, g2S1,
                      ((g2S0 == 0) && (g2S1 == 0))
                          ? L"ZERO, V67 canary runs the Booter"
                          : L"NONZERO, V67 canary may SKIP the Booter");
            }
            if (mmio_read32(tgt[k]) == 0xFFFFFFFFU) { done++; continue; }

            /* --- v3.18: СНАЧАЛА ПРОСТО БОТЕР, ПОЛНЫЙ ПУТЬ ТОЛЬКО ЕСЛИ НЕ
             * ОТКРЫЛОСЬ. Это главная правка этапа, и она самопроверяема.
             *
             * ИЗМЕРЕННЫЙ ПРОГОН v3.17 (57,3 с), разложение одной итерации:
             *     render: early_unlock_path   3703 мс   68 %
             *     render: FLR + 300ms settle   499 мс    9 %
             *     render: booter_load_v67 #2  1196 мс   22 %
             * То есть 4,2 с из 5,48 с на итерацию тратится НЕ на открытие
             * маски, а на подготовку: FLR, пауза 300 мс, затем полный
             * early_unlock_path = BL + FWSEC + WPR2 + RISCV + ботер#1.
             *
             * ЗАЧЕМ ЭТО ВООБЩЕ ДЕЛАЛОСЬ. Ради одного ограничения: за один
             * бут-цикл ботер исполняется ровно ДВА раза - #1 с обычным
             * payload открывает PLM, #2 с нашей парой пишет адрес. Третий
             * и далее, по замерам v2.99e, не срабатывали. FLR был
             * разделением прогонов: после него счётчик выстрелов
             * обнуляется, и ботер#1 снова проходит.
             *
             * НО МАСКИ ПЕРЕЖИВАЮТ FLR. Это уже доказано в этом проекте и
             * наоборот не мешает: то, что нам нужно пережить - открытые
             * маски, и им FLR не страшен. Значит вопрос не «нужен ли
             * FLR», а «работает ли ботер третий раз подряд в одном
             * состоянии SEC2». Это вопрос к ЖЕЛЕЗУ, а к коду, и раньше
             * его никто не задавал, потому что цикл всегда делал FLR.
             *
             * ПОЧЕМУ ЭТО НЕ МОЖЕТ УХУДШИТЬ РЕЗУЛЬТАТ. Проверка readback
             * идёт после ботера в обоих случаях. Если третий выстрел
             * открыл маску - мы выиграли 4,2 с. Если нет - код ДЕЛАЕТ
             * ровно то, что делал раньше: FLR, 300 мс, полный
             * early_unlock_path, ботер#2 повторно. То есть худший случай -
             * это v3.17 плюс одна неудачная попытка ботера (~1,2 с).
             *
             * Первая маска идёт прежним путём целиком: после неё
             * состояние SEC2 ещё не проверено, и начинать с оптимистичной
             * ветки на непроверенной почве незачем.
             */
            /* =================================================================
             * v3.19: БЫСТРЫЙ ПУТЬ УДАЛЁН - ГИПОТЕЗА ОПРОВЕРГНУТА НА ЖЕЛЕЗЕ.
             *
             * Что стояло здесь в v3.18: попытка открыть маску ОДНИМ
             * дополнительным ботером#2, без FLR и без полного
             * early_unlock_path, с откатом на полный путь при промахе.
             * Ожидалось -4,2 с на маску.
             *
             * ЧТО ПРОИЗОШЛО. Прогон v3.18 (out/usb-log-v318.txt, md5
             * 10450A16, стенометр 1:26):
             *     FAST 0x00088FEC MISSED (0xFFFFFFCF, polls=100)  ... 7 из 7
             *     TIME  render masks: fast=0 fast_miss=7
             * Ни одного попадания. Каждая попытка стоила 1417 мс, из них
             * ~100 мс - бесполезный опрос readback 100 раз по 1 мс при
             * синхронной записи ROP. Итого 9,9 с расхода впустую.
             *
             * ЧТО ЭТО ЗНАЧИТ. Наблюдение v2.99e («за бут-цикл ботер
             * исполняется ровно два раза, третий и далее - никогда»)
             * ПОДТВЕРЖДЕНО на железе и доведено до конца. Это не настройка
             * и не недостаток паузы: ограничение структурное. Значит FLR
             * перед каждой маской НЕ УДАЛЯЕМ - он не «перестраховка», а
             * условие того, чтобы ботер#2 вообще сработал.
             *
             * Почему не оставлять «одну попытку ради проверки»: она стоит
             * 1417 мс КАЖДЫЙ прогон, чтобы узнать то, что уже известно с
             *емикрах ошибки. Платить 1,4 с за повторное подтверждение
             * отрицательного результата - неправильный размен.
             *
             * ЧТО ВМЕСТО ЭТОГО. Полный путь на каждой маске, как в v3.17.
             * Ожидаемое время по счётчику: 65,3 -> ~56 с.
             *
             * И СЛЕДСТВИЕ ДЛЯ БОЛЬШИХ ПЛАНОВ. Разбор ROP-цепочки (пять масок
             * 0x88FE8..0x88FF8 идут подряд, один выстрел мог бы открыть их
             * все) ОТЛОЖЕН: пока третий выстрел ботера не работает,
             * последовательные выстрелы не станут дешёвыми, и исследование
             * не окупится. Этот вопрос закрыт отрицательно, см.
             * out/BUILDS.md.
             * ============================================================== */

            /* --- FLR-разделение, 1:1 как в боевом цикле таблицы --------- */
            /* v3.21: ЗДЕСЬ БЫЛ ПРОПУЩЕННЫЙ ШТАМП, И ИМЕННО ОН ДАВАЛ
             * 'FLR + 300ms settle 15,5 с' в прогоне v3.20.
             *
             * Что происходило: в v3.20 я снёс fx_ph_begin(), стоявший в
             * теле цикла pass, потому что он не закрывался. Снял правильно,
             * но не заметил, что единственный оставшийся 'begin' для фазы
             * FLR был ДО цикла k. То есть fx_ph к моменту FLR относился к
             * прошлой итерации, и в замер попадала вся разница: хвост
             * предыдущего ROP write + poll плюс промах мимо уже открытых
             * масок на следующей итерации.
             *
             * Отсюда и счётчик: UNDERFLOW x7 - семь раз, когда итерация
             * начиналась с уже открытой маски (continue минует FLR), так
             * что к моменту next FLR глубина уходила не туда.
             *
             * Теперь метка ставится ЗДЕСЬ, на первом же полезном действии
             * итерации. Это структурно верно: участок FLR начинается с
             * чтения BAR0, а не в конце предыдущей итерации. */
            fx_ph = fx_now_us();
            saveBar = cfg_read32(0x10) & ~0xF;
            do_flr();
            /* v3.18: слепая пауза 300 мс. ИЗМЕРЕНО: вся фаза стоит 499 мс,
             * из них ровно 300 мс - Stall. Пауза оставлена как есть: она
             * стоит после сброса Function Level Reset, и единственное,
             * что можно было бы ждать (готовность BAR0) проверяется
             * сразу следом через enable_mem_decode() и чтение. Менять её
             * на событие здесь рискованнее, чем оставить: падение
             * readback маски обрабатывается самопроверкой ниже, но
             * ЗАМЕНА ПАУЗЫ ЭКОНОМИТ 300 мс x 7 = 2,1 с, и это
             * сопоставимо с ценой ошибки. Отложено отдельным замером. */
            /* v3.32, ЭТАП 15: ВОЗВРАЩЕНО Stall(300000). В v3.31 здесь стояло 200000, и
             * суммарное ожидание после FLR было 400 мс - рендер сломался,
             * 3 из 8 (usb-log-v331.txt). Границы интервала, обе проверены
             * на железе:
             *
             *   300 мс суммарно (0 + 300)     = FAIL, 0 из 8   (v3.29)
             *   400 мс суммарно (200 + 200)   = FAIL, 3 из 8   (v3.31)
             *   500 мс суммарно (200 + 300)   = PASS, 8 из 8   (v3.28, v3.30)
             *
             * ВЫВОД: ОБЕ паузы несущие, убрать любую - ломается. Рычаг стоил
             * максимум 0,8 с и фактически мёртв - рабочая точка 500 мс. Шаг
             * в 50 мс вниз рисковал вернуть 8-часовой цикл ремонта ради
             * 0,4 с выигрыша.
             *
             * Срез при этом сработал точно: 499,3 -> 399,3 мс на итерацию,
             * ровно 100 мс. Значит механизм режет время корректно, просто
             * 400 мс уже недостаточно. Это в пользу будущих бисекций.
             *
             * ВНИМАНИЕ, НЕ СТРОИТЬ ОПРОС ПО BARR. В v3.31 BAR0 встал 8 из 8
             * при сломанном рендере (3 из 8). BAR0 НЕ является признаком
             * готовности - это четвёртый кандидат, убитый измерением, после
             * стадий 3, 2 и 13. BARR остаётся только как измерение. */
            uefi_call_wrapper(BS->Stall, 1, 300000);
            cfg_write32(0x10, saveBar);
            enable_mem_decode();
            gBar0Base = saveBar;
            /* v3.30, ЭТАП 13r: ФУНКЦИОНАЛЬНЫЙ сигнал вместо живости.
             *
             * Этап 13 показал, что конфигурационное пространство отвечает
             * через 8-9 мкс и это бесполезно как условие готовности. А вот
             * ЭТОТ признак другой природы: встала ли перезапись BAR0. Если
             * функция ещё не вернулась, BAR0 не примет значение, и это прямо
             * означает, что ждать раньше было рано.
             *
             * Ничего не меняется: паузы те же, поведение то же. Только
             * читаем обратно и печатаем. 8 вызовов за прогон, цена ноль.
             *
             * Вопрос, на который это отвечает: в v3.28 после суммарных
             * 500 мс BAR0 вставал (рендер работал), а в v3.29 после 300 мс -
             * не вставал (0 из 8). Значит порог где-то между. Это число и
             * есть предмет этапа 14: сколько реально нужно ждать. */
            {
                UINT32 want = saveBar, got = cfg_read32(0x10);
                ulogf(L"BARR  bar0 write: want=0x%08x got=0x%08x %s\n",
                      want, got, (got == want) ? L"STUCK" : L"*** NOT STUCK ***");
            }
            fx_mk_acc(fx_ph, L"render: FLR settle");
            fx_ph = fx_now_us();

            /* --- ботер#1: КАЖДЫЙ РАЗ, без гарда ---------------------------
             * Гард стоял здесь и в историческом свипе (стр. 8542). Замер
             * показал, что из-за него за прогон писалась РОВНО ОДНА запись
             * таблицы: первая (ботер#1 ещё не выстреливал) — успевала,
             * все последующие — нет, потому что после FLR нужен новый
             * ботер#1, чтобы заново открыть PLM и сбросить счётчик
             * выстрелов. Комментарий «FWSEC от запуска не зависит» верен
             * про образ в IMEM, но early_unlock_path зовёт всю цепочку
             * BL->FWSEC->WPR2->RISCV->ботер#1, и это не то же самое, что
             * «FWSEC уже загружен». */
            CopyMem((VOID *)(UINTN)v67Phys, v67_payload_bin, V67_SIZE);
            __asm__ volatile("wbinvd" ::: "memory");
            early_unlock_path(ucodePhys, fwsecPhys, wprMetaPhys);
            /* v3.16: метки времени на каждой итерации рендер-цикла.
             * Без них 24 одинаковых миницикла выглядят в логе как одна
             * расплывчатая стадия: в прогоне 2026-10-02 не смогли назвать
             * полное время, потому что финальной метки не было. Чисто
             * измерение, на поведение не влияет.
             * v3.17: здесь была ДУБЛИРУЮЩАЯСЯ строка (вызов повторялся два
             * раза подряд). Убрана: в логе это читалось как две разные
             * стадии, а на деле стадия одна. */
            log_ms(L"render masks: booter#1 done (early path)");
            fx_mk_acc(fx_ph, L"render: early_unlock_path");
            fx_ph = fx_now_us();
            ulogf(L"G2RMK  %s pass%d booter#1: PLM=0x%08x\n", tag, (INTN)pass + 1,
                  mmio_read32(0x00823804U));

            /* --- ботер#2: параметризованный ROP пишет наш адрес --------- */
            wLo = mmio_read32(REG_PFB_MMU_WPR2_LO);
            wHi = mmio_read32(REG_PFB_MMU_WPR2_HI);
            *pv = 0xFFFFFFFFU;      /* значение */
            *pa = tgt[k];           /* адрес  */
            __asm__ volatile("wbinvd" ::: "memory");
            ulogf(L"G2RMK  %s pass%d booter#2: 0x%08x <- 0xffffffff "
                  L"(now 0x%08x)\n", tag, (INTN)pass + 1, tgt[k],
                  mmio_read32(tgt[k]));
            (VOID)booter_load_v67(wprMetaPhys, ucodePhys);
            log_ms(L"render masks: booter#2 done (ROP write)");
            fx_mk_acc(fx_ph, L"render: booter_load_v67 #2");
            fx_ph = fx_now_us();
            /* 42.10: ботер портит WPR2. Восстанавливаем и ПИШЕМ РЕЗУЛЬТАТ,
             * потому что восстановление может не удержаться. */
            mmio_write32(REG_PFB_MMU_WPR2_LO, wLo);
            mmio_write32(REG_PFB_MMU_WPR2_HI, wHi);

            /* Успешные записи в обоих прогонах читались с polls=0, то есть
             * ROP пишет синхронно. Ждать 1000 мс имеет смысл только если
             * запись асинхронна; 400 мс — с запасом, и не сжигает минуты
             * на заведомо мёртвые адреса. */
            v = mmio_read32(tgt[k]);
            for (tries = 0; v != 0xFFFFFFFFU && tries < 400; tries++) {
                uefi_call_wrapper(BS->Stall, 1, 1000);
                v = mmio_read32(tgt[k]);
            }
            fx_mk_acc(fx_ph, L"render: ROP write + poll");
            ulogf(L"G2RMK  %s pass%d 0x%08x became 0x%08x %s (polls=%d)\n",
                  tag, (INTN)pass + 1, tgt[k], v,
                  (v == 0xFFFFFFFFU) ? L"OPEN" : L"remained locked",
                  (INTN)tries);
            if (v == 0xFFFFFFFFU) done++;
            /* v3.18: полный путь отработал - значит состояние SEC2 после
             * него заведомо пригодно для быстрой ветки на следующей
             * маске. Ставится именно здесь, а не в начале итерации:
             * первая маска всегда идёт полным путём, а решение о быстром
             * пути принимается по факту УСПЕХА полного, а не по
             * предположению. */
            fx_rmFirstOk = TRUE;
        }
        ulogf(L"G2RMK  %s pass %d: open %d of %d\n", tag,
              (INTN)pass + 1, (INTN)done, (INTN)NTGT);
        if (done == NTGT) break;
        uefi_call_wrapper(BS->Stall, 1, 20000);
    }

    for (k = 0; k < NTGT; k++)
        ulogf(L"G2RMK  %s AFTER 0x%08x = 0x%08x %s\n", tag, tgt[k],
              mmio_read32(tgt[k]),
              (mmio_read32(tgt[k]) == 0xFFFFFFFFU) ? L"OPEN" : L"locked");

    /* 0x823800 открылся в прошлом прогоне и этого тоже недостаточно —
     * показываем, что он по-прежнему открыт. 0x823B04 для информации:
     * он не подтвердился как условие (3 попытки, ноль). */
    done = 0;
    for (k = 0; k < NTGT; k++)
        if (mmio_read32(tgt[k]) == 0xFFFFFFFFU) done++;
    v = mmio_read32(0x00823800U);
    {
    /* v3.51: УСЛОВИЕ ПРОВЕРКИ ИСПРАВЛЕНО - ТРЕБОВАЛОСЬ РАВЕНСТВО, А НУЖНО
     * ВЛОЖЕНИЕ.
     *
     * Стояло: (WPR2_LO == TARGET_WPR2_LO && WPR2_HI == TARGET_WPR2_HI), иначе
     * '*** UNEXPECTED ***'. Это ловило нормальную работу GSP: он ставит окно
     * [gspFwWprStart, …], а не [FRTS, …]. На прогоне 1004-171751 читалось
     * 0x01EAD000/0x01F7EE00, и подпись 'UNEXPECTED' шесть дней приглашала
     * искать неисправность в прошивке.
     *
     * Что происходит на самом деле: gspFwWprStart = gspFwHeapOffset − 1 МБ
     * (заполнение меты), то есть нижняя граница окна GSP идёт от его heap'а.
     * Наблюдённое 0x01EAD000 есть gspFwWprStart>>8 ровно, а наш код не может
     * записать это число - он пишет либо TARGET_WPR2_LO, либо значение,
     * прочитанное строкой перед. Значит окно ставит GSP, по нашей же мете.
     *
     * Для записи в FRTS важно одно: чтобы окно СОДЕРЖАЛО окно FRTS. Тогда
     * сверху точное равенство (общая верхняя граница), снизу - LO не больше
     * нашего. Именно это и проверяется. */
    UINT32 wlo = mmio_read32(REG_PFB_MMU_WPR2_LO);
    UINT32 whi = mmio_read32(REG_PFB_MMU_WPR2_HI);
    ulogf(L"G2RMS  %s TOTAL: GFX gates open %d of %d | 0x823800=0x%08x | "
          L"0x823B04=0x%08x | WPR2=0x%08x/0x%08x | GFX-gate %s\n", tag,
          (INTN)done, (INTN)NTGT, v, mmio_read32(0x00823B04U), wlo, whi,
          (done > 0) ? L"open, GFX_SPEED_SELECT can engage"
                     : L"closed, GFX_SPEED_SELECT will not engage");
    if (whi == TARGET_WPR2_HI && wlo <= TARGET_WPR2_LO) {
        ulogf(L"G2RMS  WPR2 window contains the FRTS window - OK: "
              L"0x%08x/0x%08x vs FRTS 0x%08x/0x%08x%s\n", wlo, whi,
              (UINT32)TARGET_WPR2_LO, (UINT32)TARGET_WPR2_HI,
              (wlo == TARGET_WPR2_LO) ? L" (exactly the FRTS window)"
                                     : (g_expGspWprLo == wlo)
                                       ? L" (GSP window from our meta wprStart)"
                                       : L" (wider than FRTS)");
    } else if (whi == TARGET_WPR2_HI && g_expGspWprLo != 0 && wlo == g_expGspWprLo) {
        ulogf(L"G2RMS  WPR2 = 0x%08x/0x%08x is the GSP window from our meta "
              L"wprStart (expected 0x%08x/0x%08x), but it is NOT a superset "
              L"of the FRTS window 0x%08x/0x%08x - writes to FRTS are not "
              L"guaranteed\n", wlo, whi, (UINT32)g_expGspWprLo,
              (UINT32)TARGET_WPR2_HI, (UINT32)TARGET_WPR2_LO,
              (UINT32)TARGET_WPR2_HI);
    } else {
        ulogf(L"G2RMS  *** WPR2 WINDOW WRONG *** got 0x%08x/0x%08x, want a "
              L"superset of 0x%08x/0x%08x (GSP window from our meta would be "
              L"lo=0x%08x)\n", wlo, whi, (UINT32)TARGET_WPR2_LO,
              (UINT32)TARGET_WPR2_HI, (UINT32)g_expGspWprLo);
    }
    }
    log_ms(L"render masks: sweep finished");
#undef NTGT
}

#ifdef FUSE_ORACLE
/* ==== FUSE_ORACLE (2026-10-08) — проверка отчётчика селектора ============
 *
 * САМЫЙ ДЕШЁВЫЙ ЭКСПЕРИМЕНТ ИЗ ВСЕХ, ЧТО ДЕЛАЛИСЬ. Ноль новых записей.
 *
 * Установленный факт (прогон fusetab2): мы пишем SS0=0x88888888 в
 * 0x82381C, а рядом 0x82380C читается 0x00888888 и записи не принимает.
 * Это очень похоже на схему «регистр-команда + регистр-отчётчик», где
 * отчётчик повторяет значение команды. Тот же вид и у селектора:
 * мы пишем 0x823830=0x4, а 0x823834 стабильно читается 0x3 и не пишется.
 *
 * ГИПОТЕЗА: 0x823834 — отчётчик активного бина графики. Если после записи
 * селектора он станет 0x4, то:
 *   - механизм GFX_SPEED_SELECT мы понимаем правильно;
 *   - появляется ORACLE — способ узнать вступивший бин чтением регистра,
 *     без запуска игры и без замера fps. Сейчас единственный способ
 *     такой проверки - игра, то есть минуты на цикл и ручной замер;
 *   - лестницу значений селектора можно будет перебирать дешево.
 *
 * ПОЧЕМУ ЭТО ДЕШЁВО. Селекторы и так пишутся штатным путём в каждом
 * прогоне. Мы добавляем ТОЛЬКО ЧТЕНИЯ: 21 регистр до записи и 21 после.
 * Секунды на прогон, ноль риска, ноль отката - если что-то сломается,
 * виноват будет не этот код, а штатный путь селекторов.
 *
 * ЧТО ПЕЧАТАЕТСЯ. Только ИЗМЕНИВШИЕСЯ регистры, с именами. Неизменившиеся
 * молчат - иначе получится 42 строки шума, а нужны две.
 * ======================================================================== */

#define FTP_SNAP_BASE 0x00823800UL
#define FTP_SNAP_N    17          /* 0x823800..0x823840 */

/* Имена. Совпадают с FUSE_NB, но этот блок должен собираться и без
 * FUSE_TABLE_PROBE, поэтому таблица тут своя. */
static const struct { UINT32 a; const CHAR16 *n; } ftp_snapnames[] = {
    { 0x00823800UL, L"PLM-page-mask"   },
    { 0x00823804UL, L"PLM"            },
    { 0x00823808UL, L"?"              },
    { 0x0082380CUL, L"?(ro) 88888888" },
    { 0x00823810UL, L"FUSE_OVERRIDE?" },
    { 0x00823814UL, L"FEATURE_READOUT"},
    { 0x00823818UL, L"?"              },
    { 0x0082381CUL, L"SS0 (cmd)"      },
    { 0x00823820UL, L"SS1 (cmd)"      },
    { 0x00823824UL, L"?"              },
    { 0x00823828UL, L"?"              },
    { 0x0082382CUL, L"?(=SS1 val)"    },
    { 0x00823830UL, L"GFX_SPEED_SEL"  },
    { 0x00823834UL, L"?(=3) CAND-ID"  },
    { 0x00823838UL, L"?"              },
    { 0x0082383CUL, L"?"              },
    { 0x00823840UL, L"page+0x40"      },
};

static UINT32 ftp_snap[FTP_SNAP_N];

/* Индекс в ftp_snap по АДРЕСУ, а не константой. Магические индексы
 * разъедутся, если кто-то вставит строку в таблицу имён, и тогда мы
 * будем молча печатать не те регистры - худший вид отказа здесь. */
static INTN
ftp_snap_idx(UINT32 addr)
{
    UINTN i;
    for (i = 0; i < FTP_SNAP_N; i++)
        if (ftp_snapnames[i].a == addr) return (INTN)i;
    return -1;
}

static void
ftp_snap_take(const CHAR16 *tag)
{
    UINTN i;
    for (i = 0; i < FTP_SNAP_N; i++)
        ftp_snap[i] = mmio_read32(FTP_SNAP_BASE + (UINT32)i * 4);
    ulogf(L"FTPO0 %s SNAPSHOT %s, %d registers, read-only\n", tag, "pre-sel",
          (INTN)FTP_SNAP_N);
    for (i = 0; i < FTP_SNAP_N; i++)
        ulogf(L"FTPO1 %s %08x = %08x  %s\n", tag,
              ftp_snapnames[i].a, ftp_snap[i], ftp_snapnames[i].n);
}

static void
ftp_snap_diff(const CHAR16 *tag)
{
    UINTN i, changed = 0;
    UINT32 now;
    UINT32 selWas, selNow, candWas, candNow;
    INTN   si, ci;

    si = ftp_snap_idx(0x00823830UL);
    ci = ftp_snap_idx(0x00823834UL);
    selWas = (si >= 0) ? ftp_snap[si] : 0xDEADBEEFU;
    candWas = (ci >= 0) ? ftp_snap[ci] : 0xDEADBEEFU;
    selNow = mmio_read32(0x00823830UL);
    candNow = mmio_read32(0x00823834UL);
    if (si < 0 || ci < 0)
        ulogf(L"FTPO4 %s *** snapshot table lookup failed sel=%d cand=%d, "
              L"values below are raw reads ***\n", tag, (INTN)si, (INTN)ci);

    ulogf(L"FTPO2 %s DIFF vs snapshot, changed registers only\n", tag);
    for (i = 0; i < FTP_SNAP_N; i++) {
        now = mmio_read32(FTP_SNAP_BASE + (UINT32)i * 4);
        if (now == ftp_snap[i]) continue;
        changed++;
        ulogf(L"FTPO3 %s CHANGED %08x = %08x -> %08x  %s\n", tag,
              ftp_snapnames[i].a, ftp_snap[i], now, ftp_snapnames[i].n);
    }
    ulogf(L"FTPO4 %s %d of %d registers changed after the selector write\n",
          tag, (INTN)changed, (INTN)FTP_SNAP_N);
    /* Прямой вопрос A2, без интерпретаций.
     *
     * Печатаем ДО и ПОСЛЕ для обоих регистров, а не только изменившиеся.
     * Причина: если при нерабочем значении селектора 0x823834 не изменится
     * вовсе, строки FTPO3 для неё не будет вообще, и значение потеряется
     * именно там, где оно нужнее всего - в опровержении гипотезы.
     * Поэтому строка самодостаточна и не зависит от наличия FTPO3. */
    ulogf(L"FTPO5 %s SELECTOR 0x823830: %08x -> %08x    CAND-ID 0x823834: "
          L"%08x -> %08x    %s\n", tag,
          selWas, selNow, candWas, candNow,
          (candNow == candWas)
              ? ((candNow == 0U) ? L"UNCHANGED and now 0" : L"UNCHANGED")
              : L"CHANGED");
}
#endif /* FUSE_ORACLE */

#ifdef FUSE_TABLE_PROBE
/* ==== FUSE_TABLE_PROBE — A1 + A3 (2026-10-08) ============================
 *
 * ОДИН прогон, две гипотезы, строго по возрастанию риска. Порядок фаз
 * выбран так, чтобы ЗАВИСАНИЕ от фазы быть невозможно: фаза 0 ничего не
 * пишет и идёт ПЕРВОЙ, поэтому даже жёсткое зависание гостя в фазе 1
 * оставит в логе на флешке полный дамп - то есть прогон не пропадёт.
 *
 * ---------------------------------------------------------------------------
 * ЧТО ЭТО ЗА ЭКСПЕРИМЕНТ (docs/POWER-SEARCH-LIST.md, пункты A1 и A3).
 *
 * A3 - блок OPTB 0x8200D0..0x8200F4 (10 регистров). Вычеркнут из проекта с
 * формулировкой «валит гостя в ресет» (KNOWN-ISSUES #10, PORT-STATUS 1u).
 * Этот вердикт вынесен ДО v3.40, где нашли баг гарда «ботер#1 срабатывает
 * только на первой записи прогона» (см. комментарий выше, v3.17/v3.40).
 * Тот же класс молчаливого отказа стоил 7 масок рендера. Значит «валит
 * гостя» могло быть свойством этого бага, а не самого блока.
 * Перепроверяем РАБОЧИМ способом: тем же циклом FLR -> ботер#1 -> ботер#2,
 * каким открываются маски 0x823800/0x823B04.
 *
 * A1 - страница физов 0x820Cxx, где chip_size_scan нашёл пять регистров со
 * значением 48 (usb-log-1004-183613.txt:560-564). 48 = полное число SM у
 * GA104 (RTX 3070 Ti). У нас multiProcessorCount = 30. В той же странице
 * NVIDIA называет 0x820C04 = NV_FUSE_STATUS_OPT_DISPLAY (dev_fuse.h:137),
 * то есть это фича-фузы, а не случайный config. Ни один из этих пяти
 * адресов в проекте не записывался.
 *
 * ---------------------------------------------------------------------------
 * ГЛАВНОЕ, ЧТО РЕШАЕТСЯ ФАЗОЙ 0. Мы НЕ ЗНАЕМ, ЧТО ЛЕЖИТ В 0x820Cxx.
 * Фаза 1 открывает доступ к странице, но не отвечает на вопрос «что эти
 * пять регистров означают». Ответ на это - разбор раскладки страницы,
 * и он получается БЕСПЛАТНО, одним чтением. Поэтому фаза 0 печатает
 * страницу целиком и отдельным списком все значения, похожие на счётчик
 * (1..64), с двумя соседями: если это таблица, счётчик будет виден по
 * равномерному шагу адресов.
 *
 * ---------------------------------------------------------------------------
 * ПРАВИЛА, КОТОРЫЕ ЗДЕСЬ СОБЛЮДЕНЫ.
 *
 * 1. Порядок по риску: чтение -> открытие известного блока -> контрольная
 *    запись в безобидное поле -> ОДНА возмущаемая запись. Ничего не
 *    откатывается одним куском, каждый шаг печатается ДО действия.
 * 2. 0x823800/0x823B04 в этом же прогоне открываются штатно, и их строки
 *    «became 0xFFFFFFFF OPEN» и есть положительный контроль механики
 *    ботера для всей фазы 1 - отдельный контроль не нужен и не делается.
 * 3. Ни одна строка не пишет 48 поверх 48: это неотличимо от «не
 *    записалось». Единственный способ узнать, что регистр пишется, -
 *    изменить значение. Поэтому возмущается ровно ОДИН регистр, и он
 *    восстанавливается в том же прогоне.
 * 4. Значение возмущения - 0x2E = 46. Это НЕ выдуманное число: 46 SM -
 *    реальная конфигурация того же кристалла GA104 (RTX 3070, 5888 ядер).
 *    Если регистр всё же окажется счётчиком SM, запрос 46 - это просьба о
 *    существующей конфигурации, а не о несуществующей. Если это отчётность -
 *    запись не липнет, и мы получим ответ без побочных эффектов.
 * 5. Контрольная запись идёт в 0x820C04 (NV_FUSE_STATUS_OPT_DISPLAY,
 *    документирован R-I4R) по двум причинам: он в ТОЙ ЖЕ странице, что и
 *    цель, и он функционально безобиден - у карты нет выхода изображения
 *    (nvidia-smi: Display Active: Disabled), бит 0 по NVIDIA это «дисплей
 *    ВЫКЛЮЧЕН», то есть мы пишем в «уже выключено» и сразу
 *    восстанавливаем.
 * 6. Ни одного %u в ulogf (KNOWN-ISSUES #37.2), все строки - ASCII
 *    (ulogf заменяет не-ASCII на '?', и читать такой лог с флешки нельзя).
 *
 * ОТКАТ: анлок волатилен, откат = перезагрузка. Экспериментальные бинари
 * в out/ не кладутся (docs/RENDER-LIMITS.md §6), откатная сборка не тронута.
 * ======================================================================== */

#define FTP_PAGE_LO   0x00820C00UL
#define FTP_PAGE_HI   0x00820DFFUL
#define FTP_OPTB_LO   0x008200D0UL
#define FTP_OPTB_N    10
#define FTP_DISPLAY   0x00820C04UL      /* NV_FUSE_STATUS_OPT_DISPLAY, R-I4R */
#define FTP_TGT_A     0x00820C14UL      /* первый из пяти "48" */
#define FTP_TGT_B     0x00820C44UL
#define FTP_TGT_C     0x00820C48UL
#define FTP_TGT_D     0x00820C4CUL
#define FTP_TGT_E     0x00820D38UL
#define FTP_EXPECT48  0x00000030UL      /* 48 в виде dword */
#define FTP_PROBE_VAL 0x0000002EUL      /* 46 = реальная конфигурация GA104 */
#define FTP_MAXCNT    64               /* сколько count-like напечатать */

static UINT64 ftp_v67, ftp_uc, ftp_fw, ftp_meta;

/* Сколько регистров подряд от базы сейчас читаются как 0xffffffff.
 * Только чтение, используется для вердикта фазы 1. */
static UINTN
ftp_count_open(UINT32 base, UINTN n)
{
    UINTN i, k = 0;
    for (i = 0; i < n; i++)
        if (mmio_read32(base + (UINT32)i * 4) == 0xFFFFFFFFU) k++;
    return k;
}

/* Фаза 0: полный дамп страницы + поиск «похожих на счётчик». Только чтение. */
static void
ftp_dump_page(const CHAR16 *tag)
{
    UINT32 a, v[8];
    UINTN  j, nZero = 0, nOnes = 0, nBadf = 0, nCnt = 0, nPrint = 0, lines = 0;

    ulogf(L"FTP0  %s DUMP 0x%08x..0x%08x, 8 dwords per line, read-only\n",
          tag, (UINT32)FTP_PAGE_LO, (UINT32)FTP_PAGE_HI);
    for (a = FTP_PAGE_LO; a <= FTP_PAGE_HI; a += 32) {
        for (j = 0; j < 8; j++) v[j] = mmio_read32(a + (UINT32)j * 4);
        ulogf(L"FTP1  %08x %08x %08x %08x %08x %08x %08x %08x\n",
              v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]);
        lines++;
        for (j = 0; j < 8; j++) {
            UINT32 x = v[j];
            if (x == 0x00000000U)            { nZero++; continue; }
            if (x == 0xFFFFFFFFU)            { nOnes++; continue; }
            if ((x & 0xFFFF0000U) == 0xBADF0000U) { nBadf++; continue; }
            if (x >= 1U && x <= 64U) {
                nCnt++;
                if (nPrint >= FTP_MAXCNT) continue;
                ulogf(L"FTP2  count-like %08x = %d (0x%02x)  prev=%08x "
                      L"next=%08x\n",
                      a + (UINT32)j * 4, (INTN)x, (INTN)(x & 0xFF),
                      mmio_read32(a + (UINT32)j * 4 - 4),
                      mmio_read32(a + (UINT32)j * 4 + 4));
                nPrint++;
            }
        }
    }
    ulogf(L"FTP3  %s DUMP done: %d lines, zero=%d ones=%d badf=%d "
          L"count-like=%d (printed %d)\n", tag, (INTN)lines, (INTN)nZero,
          (INTN)nOnes, (INTN)nBadf, (INTN)nCnt, (INTN)nPrint);
}

/* ==== FUSE_NB — уровень 2 (2026-10-08), по итогам прогона fusetab ====
 *
 * Первый прогон дал три результата, и каждый меняет следующий шаг.
 *
 * (1) A3 ЗАКРЫТ ПОЛОЖИТЕЛЬНО. Все 10 регистров OPTB открылись рабочим
 *     способом (polls=78..81), зависания не было. Значит вердикт «валит
 *     гостя» был следствием бага гарда ботера, найденного в v3.40.
 *     НО итоговая перепроверка дала «8 of 10» при том, что все десять
 *     индивидуально напечатали OPEN. Два не удержали. Адреса тех двух
 *     лог не печатал - это пробел инструментации, и он же главный
 *     вопрос этого уровня.
 *
 * (2) A1 ЗАКРЫТ ОТРИЦАТЕЛЬНО. 0x820C14 не изменился (polls=400). Дамп
 *     объяснил: страница на 47 из 128 регистров = BADF5040, то есть
 *     sentinel «узел заперт», и на 55 = ноль. Живых значений всего 25.
 *     Это не таблица счётчиков, а в основном незадействованный регион.
 *     Наш исходный «48 = полное число SM» может быть просто неверным
 *     прочтением: 48 = 0b00110000 это два бита, а 49 рядом = три бита.
 *
 * (3) КОНТРОЛЬ ФАЗЫ 2 БЫЛ ПЛОХОЙ. Мы писали в 0x820C04 =
 *     NV_FUSE_STATUS_OPT_DISPLAY, а он документирован R-I4R, то есть
 *     только для чтения. «NOT STUCK» из него ничего не следует.
 *
 * Что делает этот уровень:
 *
 *   NB0 - дамп ВСЕЙ страницы физов 0x823800..0x823B0F с именами. Первый
 *         прогон её не смотрел, а там лежит и загадка A2 («стоковый 0x3»
 *         физически находится по адресу 0x823834, а мы пишем в 0x823830),
 *         и вопрос A4 (в NV_FUSE_FEATURE_READOUT расходятся ДВА бита, 8 и
 *         9, а обсуждался только 8). Оба закрываются чтением.
 *   NB1 - вторая попытка по тем OPTB, что не удержались, с печатью
 *         адресов. Прецедент «нужен второй проход» есть в самом проекте
 *         (KNOWN-ISSUES #10).
 *   NB2 - новый контроль writability на ЖИВОМ регистре той же страницы:
 *         0x820C08 держит 15, пишем 14 и возвращаем. Прежний контроль был
 *         на заведомо RO-поле, это исправление той ошибки.
 *   NB3 (A2) - ОДНО возмущение 0x823834: пишем 0x00000004 и возвращаем.
 *         Почему 4: ровно это значение мы доказано пишем в 0x823830, и
 *         оно ОТЛИЧАЕТСЯ от текущего 0x3, то есть запись различима.
 *         Если 0x823834 - настоящий селектор, а 0x823830 нет, то это
 *         единственный способ это различить.
 */

#define FTP_SS_LO     0x00823800UL
#define FTP_SS_HI     0x00823B0FUL

/* Опережающая декларация: функции уровня 2 стоят ВЫШЕ определения
 * ftp_booter_write, а вызывают его. */
static UINT32 ftp_booter_write(UINT32 addr, UINT32 want, INTN *polls);

/* Имена регистров страницы физов. Неизвестные помечены знаком '?' -
 * это честнее, чем выдумывать. Источники: docs/REGISTERS.md (PLM/SS0/SS1/
 * GFX_SPEED_SELECT), NVIDIA dev_fuse.h (NV_FUSE_FEATURE_READOUT). */
static const struct { UINT32 a; const CHAR16 *n; } ftp_nbnames[] = {
    { 0x00823800UL, L"PLM-page-mask"  },
    { 0x00823804UL, L"PLM"           },
    { 0x00823808UL, L"?"             },
    { 0x0082380CUL, L"?(ro)"         },
    { 0x00823810UL, L"FUSE_OVERRIDE?" },
    { 0x00823814UL, L"FEATURE_READOUT" },
    { 0x00823818UL, L"?"             },
    { 0x0082381CUL, L"SS0"           },
    { 0x00823820UL, L"SS1"           },
    { 0x00823824UL, L"?"             },
    { 0x00823828UL, L"?"             },
    { 0x0082382CUL, L"?"             },
    { 0x00823830UL, L"GFX_SPEED_SEL" },
    { 0x00823834UL, L"?(stock-3)"    },
    { 0x00823838UL, L"?"             },
    { 0x0082383CUL, L"?"             },
};
#define FTP_NBN_N ((INTN)(sizeof(ftp_nbnames) / sizeof(ftp_nbnames[0])))

/* NB0: дамп страницы физов с именами + разбор FEATURE_READOUT по битам. */
static void
ftp_dump_fuse_page(const CHAR16 *tag)
{
    UINTN i;
    UINT32 v, fr;
    static const struct { UINTN b; const CHAR16 *m; } feat[] = {
        { 0, L"0" }, { 1, L"1" }, { 2, L"2" }, { 3, L"3" },
        { 4, L"4" }, { 5, L"5" }, { 6, L"6" }, { 7, L"7" },
        { 8, L"8 PGRAPH" }, { 9, L"9 ?" }, { 16, L"16 ECC_DRAM" },
    };
    UINTN f;

    ulogf(L"FTPN0 %s FUSE PAGE 0x%08x..0x%08x, named, read-only\n", tag,
          (UINT32)FTP_SS_LO, (UINT32)FTP_SS_HI);
    for (i = 0; i < FTP_NBN_N; i++) {
        v = mmio_read32(ftp_nbnames[i].a);
        ulogf(L"FTPN1 %s %08x = %08x  %s\n", tag, ftp_nbnames[i].a, v,
              ftp_nbnames[i].n);
    }
    /* хвост страницы 0x823840..0x823B0F — печатаем только ненулевое */
    {
        UINT32 a;
        UINTN n = 0;
        for (a = 0x00823840UL; a <= FTP_SS_HI; a += 4) {
            v = mmio_read32(a);
            if (v == 0 || v == 0xFFFFFFFFU
                || (v & 0xFFFF0000U) == 0xBADF0000U) continue;
            n++;
            if (n > 24) { ulogf(L"FTPN2 %s tail: ... truncated\n", tag); break; }
            ulogf(L"FTPN2 %s %08x = %08x\n", tag, a, v);
        }
        ulogf(L"FTPN3 %s tail 0x00823840..%08x: %d non-trivial words\n", tag,
              (UINT32)FTP_SS_HI, (INTN)n);
    }
    /* A4: FEAT_READOUT_0 против RTX 3090.
     *
     * ИСПРАВЛЕНИЕ 2026-10. Здесь стояло «расходятся биты 8 и 9».
     * Арифметически неверно: 0x33 xor 0x233 = 0x200, то есть расходится
     * РОВНО ОДИН бит - девятый. Бит 8 пуст у обеих карт, включая 3090,
     * которая рендерит нормально, поэтому называть его PGRAPH /
     * graphics-engine-functional было неверно: у полной GA102 он пуст.
     *
     * Практически это важно вдвойне: до исправления аргумент «у нас
     * графика не функциональна на уровне признака» опирался на
     * несуществующее различие, а после него остаётся ровно один
     * неопознанный признак - бит 9. Он и есть единственная настоящая
     * разница между 70HX и полной GA102.
     *
     * Само сравнительное число 0x233 взято из docs/70HX-PORT-STATUS.md
     * и в SDK не подтверждается (документирован только ECC_DRAM, бит 16),
     * поэтому оно само требует перепроверки. Печатаем xor, чтобы это
     * было видно в логе без пересчёта на глаз. */
    fr = mmio_read32(0x00823814UL);
    ulogf(L"FTPN4 %s FEAT_READOUT_0=%08x  ours vs 3090=%08x  xor=%08x "
          L"(0x200 = bit 9 only, bit 8 is 0 on BOTH)\n",
          tag, fr, 0x00000233U, fr ^ 0x00000233U);
    for (f = 0; f < sizeof(feat) / sizeof(feat[0]); f++)
        ulogf(L"FTPN5 %s   bit %s = %d\n", tag, feat[f].m,
              (INTN)((fr >> feat[f].b) & 1U));
}

/* NB1: кто из OPTB не удержался + второй проход по нему. */
static void
ftp_optb_second_pass(const CHAR16 *tag)
{
    UINTN i, bad = 0, polls;
    UINT32 a, v;

    ulogf(L"FTPN6 %s === NB1: which OPTB did not hold, second pass ===\n", tag);
    for (i = 0; i < FTP_OPTB_N; i++) {
        a = FTP_OPTB_LO + (UINT32)i * 4;
        v = mmio_read32(a);
        if (v != 0xFFFFFFFFU) {
            bad++;
            ulogf(L"FTPN7 %s NOT HOLDING: OPTB[%d] 0x%08x = 0x%08x "
                  L"(expected ffffffff)\n", tag, (INTN)i, a, v);
        }
    }
    ulogf(L"FTPN8 %s NB1: %d of %d did not hold\n", tag, (INTN)bad,
          (INTN)FTP_OPTB_N);
    if (!bad) return;
    for (i = 0; i < FTP_OPTB_N; i++) {
        a = FTP_OPTB_LO + (UINT32)i * 4;
        if (mmio_read32(a) == 0xFFFFFFFFU) continue;
        ulogf(L"FTPN9 %s second pass OPTB[%d] 0x%08x -> write ffffffff\n",
              tag, (INTN)i, a);
        v = ftp_booter_write(a, 0xFFFFFFFFU, &polls);
        ulogf(L"FTPN9 %s second pass OPTB[%d] 0x%08x = 0x%08x %s (polls=%d)\n",
              tag, (INTN)i, a, v,
              (v == 0xFFFFFFFFU) ? L"OPEN NOW" : L"STILL LOCKED", (INTN)polls);
    }
    bad = 0;
    for (i = 0; i < FTP_OPTB_N; i++)
        if (mmio_read32(FTP_OPTB_LO + (UINT32)i * 4) != 0xFFFFFFFFU) bad++;
    ulogf(L"FTPNB %s after second pass: %d of %d still locked\n", tag,
          (INTN)bad, (INTN)FTP_OPTB_N);
}

/* NB2: контроль writability на живом регистре 0x820C08 (15 -> 14 -> 15). */
static void
ftp_ctrl_live(const CHAR16 *tag)
{
    UINT32 before, after;
    INTN  polls;
    UINT64 t;

    before = mmio_read32(0x00820C08UL);
    ulogf(L"FTPNC %s === NB2: control on LIVE register 0x00820C08, "
          L"before=0x%08x (%d dec) ===\n", tag, before, (INTN)before);
    if (before != 0x0000000FU) {
        ulogf(L"FTPNC %s value is not 15, control skipped\n", tag);
        return;
    }
    t = fx_now_us();
    after = ftp_booter_write(0x00820C08UL, 0x0000000EU, &polls);
    ulogf(L"FTPND %s wrote 0x0000000e -> 0x%08x %s (polls=%d)\n", tag, after,
          (after == 0x0000000EU) ? L"STUCK" : L"NOT STUCK", (INTN)polls);
    ulogf(L"FTPND %s verdict: live register in 0x820Cxx is %s\n", tag,
          (after == 0x0000000EU)
              ? L"WRITABLE - so 0x820C14 is register-specific, not page-wide"
              : L"read-only - the whole page is a readout zone");
    if (after == 0x0000000EU) {
        after = ftp_booter_write(0x00820C08UL, before, &polls);
        ulogf(L"FTPND %s restored 0x%08x -> 0x%08x %s\n", tag, before, after,
              (after == before) ? L"OK" : L"MISMATCH");
    }
    fx_mk_acc(t, L"ftp: NB2 live-register control");
}

/* NB3 (A2): одно возмущение 0x823834 - «стоковый 0x3». */
static void
ftp_nb_selector(const CHAR16 *tag)
{
    UINT32 before, after;
    INTN  polls;
    UINT64 t;

    before = mmio_read32(0x00823834UL);
    ulogf(L"FTPNE %s === NB3 (A2): 0x00823834 before=0x%08x, "
          L"GFX_SPEED_SELECT(0x823830)=0x%08x ===\n", tag, before,
          mmio_read32(0x00823830UL));
    t = fx_now_us();
    after = ftp_booter_write(0x00823834UL, 0x00000004U, &polls);
    ulogf(L"FTPNF %s wrote 0x00000004 -> 0x%08x %s (polls=%d)\n", tag, after,
          (after == 0x00000004U) ? L"STUCK" : L"NOT STUCK", (INTN)polls);
    ulogf(L"FTPNF %s verdict: 0x823834 is %s\n", tag,
          (after == 0x00000004U)
              ? L"WRITABLE - a real control field, candidate for the real selector"
              : L"a readout - the 'stock 0x3' there is just a coincidence of value");
    if (after == 0x00000004U) {
        after = ftp_booter_write(0x00823834UL, before, &polls);
        ulogf(L"FTPNF %s restored 0x%08x -> 0x%08x %s\n", tag, before, after,
              (after == before) ? L"OK" : L"MISMATCH");
    }
    fx_mk_acc(t, L"ftp: NB3 selector neighbour probe");
}

/* ОДИН ботер-цикл: ровно тот, каким открываются маски рендера.
 * Отличие от масок одно: значение записи произвольное (у масок всегда
 * 0xFFFFFFFF), и вместо открытия маски проверяется произвольное значение.
 * Третий выстрел ботера в одном состоянии SEC2 не работает (v3.18,
 * usb-log-v318.txt), поэтому между вызовами обязателен FLR. */
static UINT32
ftp_booter_write(UINT32 addr, UINT32 want, INTN *polls)
{
    UINT32 saveBar, wLo, wHi, v;
    volatile UINT32 *pv = (volatile UINT32 *)(UINTN)(ftp_v67 + 0xf948);
    volatile UINT32 *pa = (volatile UINT32 *)(UINTN)(ftp_v67 + 0xf960);
    INTN   tries;

    saveBar = cfg_read32(0x10) & ~0xF;
    (VOID)do_flr();
    uefi_call_wrapper(BS->Stall, 1, 300000);
    cfg_write32(0x10, saveBar);
    enable_mem_decode();
    gBar0Base = saveBar;

    CopyMem((VOID *)(UINTN)ftp_v67, v67_payload_bin, V67_SIZE);
    __asm__ volatile("wbinvd" ::: "memory");
    (VOID)early_unlock_path(ftp_uc, ftp_fw, ftp_meta);

    wLo = mmio_read32(REG_PFB_MMU_WPR2_LO);
    wHi = mmio_read32(REG_PFB_MMU_WPR2_HI);
    *pv = want;
    *pa = addr;
    __asm__ volatile("wbinvd" ::: "memory");
    (VOID)booter_load_v67(ftp_meta, ftp_uc);
    mmio_write32(REG_PFB_MMU_WPR2_LO, wLo);
    mmio_write32(REG_PFB_MMU_WPR2_HI, wHi);

    v = mmio_read32(addr);
    for (tries = 0; v != want && tries < 400; tries++) {
        uefi_call_wrapper(BS->Stall, 1, 1000);
        v = mmio_read32(addr);
    }
    if (polls) *polls = tries;
    return v;
}

static void
fuse_table_probe(const CHAR16 *tag, UINT64 wprMetaPhys, UINT64 ucodePhys,
                 UINT64 fwsecPhys, UINT64 v67Phys)
{
    UINTN  i, polls;
    UINT32 before, after, disp0;
    UINT64 t;

    ftp_v67 = v67Phys; ftp_uc = ucodePhys;
    ftp_fw = fwsecPhys; ftp_meta = wprMetaPhys;

    ulogf(L"FTP   === FUSE_TABLE_PROBE start: %s ===\n", tag);
    ulogf(L"FTP   readback sanity: PLM=0x%08x SS0=0x%08x SS1=0x%08x\n",
          mmio_read32(REG_FEAT_OVR_PLM), mmio_read32(REG_FEAT_OVR_SM_SPD),
          mmio_read32(REG_FEAT_OVR_SM_SPD_1));
    ulogf(L"FTP   targets: disp=%08x A=%08x B=%08x C=%08x D=%08x E=%08x\n",
          mmio_read32(FTP_DISPLAY), mmio_read32(FTP_TGT_A),
          mmio_read32(FTP_TGT_B), mmio_read32(FTP_TGT_C),
          mmio_read32(FTP_TGT_D), mmio_read32(FTP_TGT_E));
    if (!v67Phys || !ucodePhys) {
        ulogf(L"FTP   *** no payload context (v67=%d uc=%d), phases 1-3 "
              L"skipped ***\n", v67Phys ? 1 : 0, ucodePhys ? 1 : 0);
        return;
    }

    /* ---- ФАЗА 0: только чтение. Идёт первой специально. ------------------ */
    t = fx_now_us();
    ftp_dump_page(tag);
#ifdef FUSE_NB
    /* NB0: страница физов 0x8238xx — её первый прогон не смотрел, а там
     * лежат и загадка A2, и вопрос A4. Тоже только чтение. */
    ftp_dump_fuse_page(tag);
#endif
    fx_mk_acc(t, L"ftp: phase0 read-only dump");

    /* ---- ФАЗА 1 (A3): OPTB, по одному адресу за цикл -------------------- */
    ulogf(L"FTP4  %s === PHASE 1 (A3): OPTB 0x%08x+%d, one booter cycle each "
          L"===\n", tag, (UINT32)FTP_OPTB_LO, (INTN)FTP_OPTB_N);
    t = fx_now_us();
    for (i = 0; i < FTP_OPTB_N; i++) {
        UINT32 a = FTP_OPTB_LO + (UINT32)i * 4;
        before = mmio_read32(a);
        ulogf(L"FTP5  %s OPTB[%d] 0x%08x before=0x%08x, writing 0xffffffff\n",
              tag, (INTN)i, a, before);
        if (before == 0xFFFFFFFFU) {
            ulogf(L"FTP6  %s OPTB[%d] 0x%08x already open, no cycle spent\n",
                  tag, (INTN)i, a);
            continue;
        }
        after = ftp_booter_write(a, 0xFFFFFFFFU, &polls);
        ulogf(L"FTP6  %s OPTB[%d] 0x%08x after=0x%08x %s (polls=%d)\n",
              tag, (INTN)i, a, after,
              (after == 0xFFFFFFFFU) ? L"OPEN" : L"LOCKED", (INTN)polls);
    }
    ulogf(L"FTP7  %s PHASE 1 verdict: %d of %d OPTB registers read 0xffffffff\n",
          tag,
          (INTN)ftp_count_open(FTP_OPTB_LO, FTP_OPTB_N), (INTN)FTP_OPTB_N);
    fx_mk_acc(t, L"ftp: phase1 OPTB booter cycles");
#ifdef FUSE_NB
    /* NB1: первый прогон дал «8 of 10» при десяти индивидуальных OPEN.
     * Выясняем, кто именно не удержался, и пробуем второй проход. */
    t = fx_now_us();
    ftp_optb_second_pass(tag);
    fx_mk_acc(t, L"ftp: NB1 OPTB second pass");
#endif

    /* ---- ФАЗА 2: контроль writability на безобидном поле ----------------- */
    ulogf(L"FTP8  %s === PHASE 2: writability control at 0x%08x "
          L"(NV_FUSE_STATUS_OPT_DISPLAY) ===\n", tag, (UINT32)FTP_DISPLAY);
    disp0 = mmio_read32(FTP_DISPLAY);
    t = fx_now_us();
    if (disp0 == 0x00000000U || disp0 == 0x00000001U) {
        UINT32 want = (disp0 == 0x00000000U) ? 0x00000001U : 0x00000000U;
        after = ftp_booter_write(FTP_DISPLAY, want, &polls);
        ulogf(L"FTP9  %s wrote 0x%08x -> 0x%08x %s (polls=%d)\n", tag, want,
              after, (after == want) ? L"STUCK" : L"NOT STUCK", (INTN)polls);
        ulogf(L"FTP9  %s verdict: page 0x820Cxx is %s\n", tag,
              (after == want) ? L"WRITABLE - phase 3 may proceed"
                              : L"read-only or still protected");
        if (after == want) {
            after = ftp_booter_write(FTP_DISPLAY, disp0, &polls);
            ulogf(L"FTP9  %s restored to 0x%08x -> 0x%08x %s\n", tag, disp0,
                  after, (after == disp0) ? L"OK" : L"MISMATCH");
        }
    } else {
        ulogf(L"FTP9  %s value 0x%08x is neither 0 nor 1, control skipped\n",
              tag, disp0);
    }
    fx_mk_acc(t, L"ftp: phase2 writability control");
#ifdef FUSE_NB
    /* NB2: исправление ошибки первого прогона. Контроль стоял на
     * 0x820C04 = NV_FUSE_STATUS_OPT_DISPLAY, а он документирован R-I4R,
     * то есть «NOT STUCK» из него ничего не следовало. Теперь контроль
     * на ЖИВОМ регистре той же страницы. */
    ftp_ctrl_live(tag);
#endif

    /* ---- ФАЗА 3 (A1): ОДНО возмущение "48"-регистра --------------------- */
    before = mmio_read32(FTP_TGT_A);
    ulogf(L"FTPA  %s === PHASE 3 (A1): perturb ONE 48-register 0x%08x -> "
          L"0x%08x, then restore ===\n", tag, (UINT32)FTP_TGT_A,
          (UINT32)FTP_PROBE_VAL);
    ulogf(L"FTPA  %s 0x%08x before=0x%08x (%d dec) bytes %02x %02x %02x %02x\n",
          tag, (UINT32)FTP_TGT_A, before, (INTN)before,
          (INTN)(before & 0xFF), (INTN)((before >> 8) & 0xFF),
          (INTN)((before >> 16) & 0xFF), (INTN)((before >> 24) & 0xFF));
    if (before != FTP_EXPECT48) {
        ulogf(L"FTPA  %s value is 0x%08x, not the expected 48 - perturbation "
              L"skipped, phase 0 dump is the result\n", tag, before);
    } else {
        t = fx_now_us();
        after = ftp_booter_write(FTP_TGT_A, FTP_PROBE_VAL, &polls);
        ulogf(L"FTPB  %s 0x%08x after=0x%08x %s (polls=%d)\n", tag,
              (UINT32)FTP_TGT_A, after,
              (after == FTP_PROBE_VAL) ? L"STUCK" : L"NOT STUCK", (INTN)polls);
        ulogf(L"FTPB  %s verdict: register is %s\n", tag,
              (after == FTP_PROBE_VAL)
                  ? L"WRITABLE - a value survives, so it is a control, not a readout"
                  : L"a readout or protected - writing 48 over 48 would prove nothing");
        if (after == FTP_PROBE_VAL) {
            after = ftp_booter_write(FTP_TGT_A, before, &polls);
            ulogf(L"FTPB  %s restored 0x%08x -> 0x%08x %s\n", tag, before,
                  after, (after == before) ? L"OK" : L"MISMATCH");
        }
        fx_mk_acc(t, L"ftp: phase3 single-register perturbation");
    }
    ulogf(L"FTPC  %s the other four, NOT written this run: B=%08x C=%08x "
          L"D=%08x E=%08x\n", tag, mmio_read32(FTP_TGT_B),
          mmio_read32(FTP_TGT_C), mmio_read32(FTP_TGT_D),
          mmio_read32(FTP_TGT_E));
#ifdef FUSE_NB
    /* NB3 (A2) — в конце, после всех записей фазы 3: к этому моменту
     * страница 0x8238xx уже вскрыта для чтения, а селектор GFX_SPEED_SELECT
     * ещё стоковый (блок стоит ДО блока селекторов). */
    ftp_nb_selector(tag);
#endif
    ulogf(L"FTP   === FUSE_TABLE_PROBE done: %s ===\n", tag);
}
#endif /* FUSE_TABLE_PROBE */

#ifdef XP3G_GATE_V67
/* ==== ЭКСПЕРИМЕНТ E-A: гейт XP3G привилегированным писателем V67 =============
 *
 * ВОПРОС, который закрывает этот блок — одним прогоном с флешки:
 *   откроет ли ПРИВИЛЕГИРОВАННЫЙ писатель V67 гейт 0x8E1B0 в точный
 *   0xFFFFFFFF, который с хоста не открывается НИ ОДНОЙ записью из 36?
 *
 * ПОЧЕМУ ЭТО НЕ ПОВТОРЕНИЕ §1q/§1r. Отрицательный результат там честный, но
 * он про ДРУГОГО писателя: §1q/§1r били mmio_write32 С ХОСТА, а маска и есть
 * защита от такой записи, поэтому «0 из 36» верно для хоста и ничего не
 * говорит о V67. §1r это прямо оговаривает: «у нас уже есть привилегированный
 * исполнитель (V67 открывает PLM), вопрос только в том, что именно он пишет».
 * Этот блок — ответ на «что именно он пишет», для одного адреса.
 *
 * ПРИМИТИВ УЖЕ ГОТОВ, НОВОГО КОДА В НЁМ НЕТ. V67 — параметризованный писатель:
 *   pv = payload+0xf948 -> значение,  pa = payload+0xf960 -> адрес
 * (так же устроены уже существующие ftp_booter_write и pcie_gen_unlock_debug,
 * второй пишет так же в PCIE_FUSE_OVERRIDE 0x823810). Здесь меняется только
 * адрес. Реверс блоба, которого ждал PORT-STATUS §1s, НЕ требуется: интерфейс
 * блоба проекту уже известен, см. строки 5553-5554.
 *
 * ПРО ЖИВУЮ ССЫЛКУ. Здесь НЕТ ни кика 0x8872C, ни TLS, ни ретрейна, ни записей
 * политики PCIe. Пишем ТОЛЬКО в регистр-маску (снимаем защиту с записи), ни
 * одного функционального бита. Линк не трогаем — ровно как объявлено заранее
 * в §1q перед шагом 1b.
 *
 * ФАЗЫ ПО ВОЗРАСТАНИЮ РИСКА. Правило проекта: фаза 0 только на чтение идёт
 * первой, чтобы даже жёсткое зависание в фазе 1 оставило дамп в логе.
 *
 *   Фаза 0  ТОЛЬКО ЧТЕНИЕ: гейт 0x8E1B0..BC и XP3G OVR/VAL 0 и 3. Ноль риска.
 *   Фаза 1  ЦЕЛЬ:    0x8E1B0 <- 0xFFFFFFFF привилегированно. Решающий выстрел.
 *   Фаза 2  КОНТРОЛЬ: 0x8E1B4 <- 0xFFFFFFFF, тем же кодом, свой FLR-цикл.
 *
 * ПОЧЕМУ КОНТРОЛЬ ОБЯЗАТЕЛ. 70HX-FINAL-SUMMARY §4: «показание принято за
 * доказательство, не будучи им» — три самые дорогие ошибки проекта. Отрицательный
 * результат фазы 1 сам по себе не значит ничего: он не отличает «гейт не
 * открывается привилегированно» от «механизм в этом прогоне не выстрелил».
 * 0x8E1B4 — сосед по тому же семейству 0x8E1B0..F0, с тем же стоковым
 * значением, и открывается тем же кодом. Разбор только такой пары:
 *
 *   контроль OPEN  + цель NOT OPEN -> гейт 0x8E1B0 особенный: НЕ открывается.
 *   контроль OPEN  + цель OPEN     -> гейт открыт, §1s пересмотреть, Gen2 жив.
 *   контроль NOT OPEN              -> результат фазы 1 НЕДЕЙСТВИТЕЛЕН, и вердикт
 *                                     обязан сказать это, а не закрывать Gen2.
 *
 * Ограничение ботера: третий выстрел в одном состоянии SEC2 не работает
 * (v3.18), поэтому между фазами 1 и 2 обязателен свой FLR-цикл — так же, как
 * в ftp_booter_write. Отсюда цена блока: два полных цикла, ~2,5 с прогона.
 *
 * Место вызова — сразу после цикла масок и ДО блока селекторов, потому что
 * ботер стреляет только пока SS0/SS1 нулевые (канарейка V67, строка G2RCC
 * выше). После блока селекторов предусловие уже нарушено.
 */
#define XG_GATE        0x0008e1b0U   /* гейт привилегий XP3G */
#define XG_CTRL        0x0008e1b4U   /* сосед по семейству: положительный контроль */
#define XG_OPEN        0xffffffffU
/* Маска XVE/PCIe-домена. Адрес референса iatethelogs (MASK_XVE), см.
 * KNOWN-ISSUES.md §51.4. Открывается БОТЕРОМ, не хост-MMIO: доказано
 * строкой ниже про откат в CF и таблицей g_rj16[] через ROP. */
#define XG_XVE_MASK    0x00088fe8U

/* Один привилегированный выстрел V67 — тот же цикл, что ftp_booter_write:
 * FLR -> restore BAR0 -> ботер#1 открывает PLM -> ботер#2 пишет пару pv/pa ->
 * restore WPR2 -> опрос readback. Ничего нового, кроме адреса. */
static UINT32
xg_v67_write(UINT64 v67Phys, UINT64 ucodePhys, UINT64 fwsecPhys,
             UINT64 wprMetaPhys, UINT32 addr, UINT32 want, INTN *polls)
{
    volatile UINT32 *pv = (volatile UINT32 *)(UINTN)(v67Phys + 0xf948);
    volatile UINT32 *pa = (volatile UINT32 *)(UINTN)(v67Phys + 0xf960);
    UINT32 saveBar, wLo, wHi, v;
    INTN   tries;

    saveBar = cfg_read32(0x10) & ~0xF;
    (VOID)do_flr();
    uefi_call_wrapper(BS->Stall, 1, 300000);
    cfg_write32(0x10, saveBar);
    enable_mem_decode();
    gBar0Base = saveBar;

    CopyMem((VOID *)(UINTN)v67Phys, v67_payload_bin, V67_SIZE);
    __asm__ volatile("wbinvd" ::: "memory");
    (VOID)early_unlock_path(ucodePhys, fwsecPhys, wprMetaPhys);

    /* Ботер портит WPR2 (42.10) — восстанавливаем ДО чтения результата, иначе
     * readback идёт по сломанному BAR0. Ровно как в ftp_booter_write. */
    wLo = mmio_read32(REG_PFB_MMU_WPR2_LO);
    wHi = mmio_read32(REG_PFB_MMU_WPR2_HI);
    *pv = want;
    *pa = addr;
    __asm__ volatile("wbinvd" ::: "memory");
    (VOID)booter_load_v67(wprMetaPhys, ucodePhys);
    mmio_write32(REG_PFB_MMU_WPR2_LO, wLo);
    mmio_write32(REG_PFB_MMU_WPR2_HI, wHi);

    v = mmio_read32(addr);
    for (tries = 0; v != want && tries < 400; tries++) {
        uefi_call_wrapper(BS->Stall, 1, 1000);
        v = mmio_read32(addr);
    }
    if (polls) *polls = tries;
    return v;
}

static void
xg_probe(const CHAR16 *tag, UINT64 wprMetaPhys, UINT64 ucodePhys,
         UINT64 fwsecPhys, UINT64 v67Phys)
{
    UINT32 before, tgt, later, ctrl;
    INTN   pT, pC;
    UINT64 t;

    t = fx_now_us();

    /* --- Фаза 0: ТОЛЬКО ЧТЕНИЕ. Идёт первой и всегда оставляет след. --- */
    before = mmio_read32(XG_GATE);
    ulogf(L"XGATE phase0: gate 0x%08x=0x%08x ctrl 0x%08x=0x%08x\n",
          XG_GATE, before, XG_CTRL, mmio_read32(XG_CTRL));
    ulogf(L"XGATE phase0: fam 0x%08x/0x%08x/0x%08x/0x%08x\n",
          mmio_read32(0x0008e1b8U), mmio_read32(0x0008e1bcU),
          mmio_read32(0x0008e1c0U), mmio_read32(0x0008e1c4U));
    ulogf(L"XGATE phase0: XP3G OVR0=0x%08x VAL0=0x%08x OVR3=0x%08x VAL3=0x%08x\n",
          mmio_read32(0x0008e110U), mmio_read32(0x0008e120U),
          mmio_read32(0x0008e11cU), mmio_read32(0x0008e12cU));
    Print(L"xgate: pre gate=0x%08x ctrl=0x%08x\n", before, mmio_read32(XG_CTRL));

    /* --- Фаза 1: ЦЕЛЬ, гейт 0x8E1B0. Решающий выстрел. --- */
    tgt = xg_v67_write(v67Phys, ucodePhys, fwsecPhys, wprMetaPhys,
                       XG_GATE, XG_OPEN, &pT);
    /* Повторное чтение через 0,5 с отделяет «не встало» от «встало и слетело». */
    uefi_call_wrapper(BS->Stall, 1, 500000);
    later = mmio_read32(XG_GATE);
    ulogf(L"XGATE phase1: target 0x%08x <- 0x%08x gave 0x%08x %s "
           "(polls=%d, recheck=0x%08x, before=0x%08x)\n",
          XG_GATE, XG_OPEN, tgt,
          (tgt == XG_OPEN) ? "OPEN" : "NOT OPEN", pT, later, before);
    Print(L"xgate: target 0x%08x -> 0x%08x %s polls=%d\n", XG_GATE, tgt,
          (tgt == XG_OPEN) ? "OPEN" : "NOT OPEN", pT);

    /* --- Фаза 2: КОНТРОЛЬ, 0x8E1B4, тот же код, свой FLR-цикл.
     * Без него отрицательный результат фазы 1 нельзя интерпретировать. --- */
    ctrl = xg_v67_write(v67Phys, ucodePhys, fwsecPhys, wprMetaPhys,
                        XG_CTRL, XG_OPEN, &pC);
    ulogf(L"XGATE phase2: control 0x%08x <- 0x%08x gave 0x%08x %s (polls=%d)\n",
          XG_CTRL, XG_OPEN, ctrl,
          (ctrl == XG_OPEN) ? "OPEN" : "NOT OPEN", pC);
    Print(L"xgate: control 0x%08x -> 0x%08x %s polls=%d\n", XG_CTRL, ctrl,
          (ctrl == XG_OPEN) ? "OPEN" : "NOT OPEN", pC);

    /* --- Вердикт. Три исхода, третий запрещает делать вывод. --- */
    if ((tgt == XG_OPEN) && (ctrl == XG_OPEN)) {
        ulogf(L"XGATE VERDICT: OPEN - gate opens privileged; "
               "XP3G_OVR0/VAL0 writable next; PORT-STATUS 1s needs rework\n");
        Print(L"xgate: VERDICT OPEN\n");
    } else if ((tgt != XG_OPEN) && (ctrl == XG_OPEN)) {
        ulogf(L"XGATE VERDICT: GATE-ONLY-LOCKED - mechanism works, gate does "
               "not open; XP3G policy writes stay dropped\n");
        Print(L"xgate: VERDICT GATE-ONLY-LOCKED\n");
    } else {
        ulogf(L"XGATE VERDICT: INCONCLUSIVE - control did not open either; "
               "phase1 result carries NO weight, do not close Gen2 on it\n");
        Print(L"xgate: VERDICT INCONCLUSIVE\n");
    }

    ulogf(L"XGATE === E-A done: %s ===\n", tag);
    fx_mk_acc(t, L"xgate: E-A xp3g gate via V67");
}
#endif /* XP3G_GATE_V67 */

#if defined(XP3G_XVE_BOOTER) && defined(XP3G_GATE_V67)
/* ==== ЭКСПЕРИМЕНТ E-G: маска 0x88FE8 ПРИВИЛЕГИРОВАННЫМ ВЫСТРЕЛОМ ========
 *
 * Определение XG_XVE_MASK и сама xg_v67_write() живут ВНУТРИ блока
 * XP3G_GATE_V67, поэтому E-G обязана требовать оба флага, а не один.
 *
 * ЗАЧЕМ, ПОСЛЕ ТОГО КАК E-F НЕ СРАБОТАЛ. E-F (xgate4) писала 0x88FE8
 * обычным mmio_write32 с ХОСТА и получила LOCKED на всех пяти адресах.
 * Тогда я записал, что домен 0x88xxx защищён сильнее гейта 0x8E1B0.
 * Это было верно только про ХОСТОВУЮ запись, и вывод из этого не следовал.
 *
 * ГДЕ ОШИБКА. Маску 0x88FE8 умеет открывать БОТЕР, а не хост. Прямо в этом
 * файле, src/unlock_v2.c:14384, написано: «маски переживают FLR, но гибнут при
 * тёплом/холодном ресете (доказано: 0x88fe8 откатился в CF после
 * ResetSystem-Warm)». «Откатился в CF» значит, что ДО этого был FFFFFFFF —
 * адрес в проекте открывался. Механизм там ботерный: пара pv/pa плюс
 * booter_load_v67 (строка 14452), то есть ROP через сам GPU, не хост-MMIO.
 *
 * Таким образом E-F проверял не тот путь доступа. Хост-MMIO к 0x8E1B0 после
 * E-A тоже не писался бы (гейт открывают БОТЕРОМ), и мы это знаем: E-B пишет
 * policy ХОСТОМ и встаёт только потому, что гейт уже открыт ботером.
 * Для 0x88FE8 открывающего гейта у нас нет — значит и хостовая запись была
 * обречена. Выстрел ботером — единственный путь, который ещё не пробован.
 *
 * ПОЧЕМУ ОГРАНИЧЕНИЕ «ДВА ВЫСТРЕЛА» НЕ МЕШАЕТ. «Третий выстрел в одном
 * состоянии SEC2 не работает» (v3.18) — про ОДНО состояние. xg_v67_write()
 * делает свой do_flr() в начале каждого выстрела (строка 6975), то есть
 * каждый выстрел получает свежий счётчик. Подтверждено на железе: xg_probe
 * делает два выстрела подряд (0x8E1B0, затем 0x8E1B4) и оба открываются.
 *
 * ГДЕ СТОИТ СТАДИЯ. МЕЖДУ E-A и E-B, и это невкусно. xg_v67_write() делает
 * FLR внутри. Политика E-B пишет обычные регистры, а не маски, — если бы E-G
 * шёл после неё, её результат зависел бы от того, пережил ли policy FLR.
 * Порядок E-A -> E-G -> E-B снимает вопрос: политика всегда заливается
 * последней, уже после всех FLR.
 *
 * ЧТО ПЕЧАТИТСЯ. Одна строка результата и вердикт из двух исходов, по той же
 * логике разбора, что у E-A: контрольного адреса здесь нет, но соседний домен
 * 0x8E1xx в этом же прогоне открыт ботером двумя выстрелами выше, поэтому
 * отрицательный результат считается содержательным, а не недействительным.
 *
 * ЕСЛИ ОТКРОЕТСЯ. Тогда E-F в xgate4 был отрицательным результатом неверного
 * пути доступа, а не свойством кремния, и вопрос «кто держит TLS=2 на GPU»
 * остаётся открытым: следующая проверка — снимет ли открытая маска отбрасывание
 * записи в шаге 1 E-C. Строка XCK step1 печатается в этом же прогоне.
 *
 * ЕСЛИ НЕ ОТКРОЕТСЯ. Это третий независимый способ, которым адрес не берётся
 * (рендер-таблица, хост-MMIO в E-F, ботер здесь), при том что тот же ботер,
 * тот же ROP и тот же FLR открывают 0x8E1B0 в ста метров строкой выше. Тогда
 * различие доменов 0x88xxx и 0x8E1xx на одном кремнии ИЗМЕРЕНО, а не
 * предположено, и следующий вопрос — какой переключатель между ними.
 */
static void
xg_xve_probe(const CHAR16 *tag, UINT64 wprMetaPhys, UINT64 ucodePhys,
             UINT64 fwsecPhys, UINT64 v67Phys)
{
    UINT32 before, got;
    INTN   pT;
    UINT64 t;

    t = fx_now_us();

    /* До: обязана быть видна как ровно закрытая, иначе результат без предмета. */
    before = mmio_read32(XG_XVE_MASK);
    ulogf(L"XGM  precondition: gate 0x%08x=0x%08x  XVE mask 0x%08x=0x%08x\n",
          XG_GATE, mmio_read32(XG_GATE), XG_XVE_MASK, before);

    /* Решающий выстрел. Тот же код, что открыл гейт, без единого изменения:
     * меняется только адрес. */
    got = xg_v67_write(v67Phys, ucodePhys, fwsecPhys, wprMetaPhys,
                       XG_XVE_MASK, XG_OPEN, &pT);

    ulogf(L"XGM  0x%08x before=0x%08x wrote 0x%08x gave 0x%08x %s "
           L"(polls=%d)\n", XG_XVE_MASK, before, XG_OPEN, got,
          (got == XG_OPEN) ? "OPEN" : "NOT OPEN", pT);
    Print(L"xgm: XVE 0x%08x 0x%08x -> 0x%08x %s polls=%d\n",
          XG_XVE_MASK, before, got,
          (got == XG_OPEN) ? "OPEN" : "NOT OPEN", pT);

    if (got == XG_OPEN) {
        ulogf(L"XGM  VERDICT: XVE-BOOTER-OPEN - the PCIe-domain mask opens "
               L"privilege, and E-F's host-MMIO failure was a wrong access path, "
               L"not a property of the silicon. Whether it unblocks TLS=2 is "
               L"decided by XCK step1, not here\n");
        Print(L"xgm: VERDICT XVE-BOOTER-OPEN\n");
    } else {
        ulogf(L"XGM  VERDICT: XVE-BOOTER-FAILED - the same booter that opened "
               L"0x%08x two shots above did NOT open the PCIe-domain mask. "
               L"Domains 0x88xxx and 0x8E1xx differ on this silicon, and that "
               L"is now measured rather than assumed\n", XG_GATE);
        Print(L"xgm: VERDICT XVE-BOOTER-FAILED\n");
    }

    ulogf(L"XGM  === E-G done: %s ===\n", tag);
    fx_mk_acc(t, L"xgm: E-G XVE mask 0x88fe8 via V67");
}
#endif /* XP3G_XVE_BOOTER && XP3G_GATE_V67 */

#ifdef XP3G_GATE_POLICY
/* ==== ЭКСПЕРИМЕНТ E-B: заливается ли policy set, когда гейт открыт ==========
 *
 * Продолжение E-A. Вопрос, который §1q назвал ДО всяких экспериментов и который
 * блокировал шаг 2: при закрытом гейте из семи полей политики вставало шесть,
 * и проваливалось ровно одно — XP3G_OVR0 (0x8E110). Прогон E-A 2026-09-09
 * показал, что гейт открывается привилегированно. Теперь проверяем, встаёт ли
 * оно с ХОСТА.
 *
 * ПОЧЕМУ ИМЕННО ХОСТОВЫМИ MMIO-ЗАПИСЯМИ, А НЕ ЧЕРЕЗ V67. Вопрос не «можно ли
 * записать это поле», а «снимает ли ОТКРЫТИЙ ГЕЙТ защиту с хостовой записи».
 * Если писать policy тоже через V67, тест получится тавтологией: привилегированный
 * писатель и так пишет куда угодно, и результат ничего не скажет о гейте.
 * Поэтому все семь полей — обычный mmio_write32 с хоста, как в §1q.
 *
 * ЗАЩИТА ОТ ТАВТОЛОГИИ (FINAL-SUMMARY §4, ошибка №1: «is_unlocked()=1 —
 * функция перечитывает регистры, в которые код только что записал. Тавтология»).
 * Поле, у которого целевое значение СОВПАДАЕТ с прочитанным «до», ничего не
 * доказывает: запись не меняет ничего и readback совпадёт по построению.
 * Такие поля помечаются NOOP и В СЧЁТ ПРОЙДЕННЫХ НЕ ИДУТ. Значимое поле то,
 * которое реально поменялось.
 *
 * Значения clr/set взяты из §1q и перепроверены арифметикой по замеренным
 * там «до»/«после» — сходятся байт в байт:
 *   0x8841C: 0x20360500, clr 0x5000 set 0x2800 -> 0x20362D00   (совпало)
 *   0x88610: 0x00001001, clr 0x1000 set 0x0001 -> 0x00000001   (совпало)
 *   0x8C2C0: 0x00802005, clr 0x0004 set 0x0000 -> 0x00802001   (совпало)
 *   0x8C040: MAX_RATE[19:18] = 2
 *   0x8C1C0: 0x00060000 -> 0x00040000
 *
 * ЖИВОЙ ЛИНК НЕ ТРОГАЕМ. Здесь НЕТ кика 0x8872C, НЕТ TLS, НЕТ ретрейна.
 * Пишем только регистры политики и только ЛИЧШИЙ раз, ничего не форсируя.
 * LnkSta читается и печатается как контроль того, что линок остался Gen1.
 */
typedef struct {
    UINT32   addr;
    UINT32   clrMask;
    UINT32   setBits;
    CHAR8    name[12];
} XG_POL;

static const XG_POL xg_pol[] = {
    { 0x0008e110U, 0xffffffffU, 0x00000001U, "XP3G_OVR0"  },
    { 0x0008e120U, 0xffffffffU, 0x00000000U, "XP3G_VAL0"  },
    { 0x0008c040U, 0x000c0000U, 0x00080000U, "LINK_CONFIG"},
    { 0x0008c1c0U, 0x00060000U, 0x00040000U, "PL_LINKRATE"},
    { 0x0008841cU, 0x00005000U, 0x00002800U, "PRIV_MISC1" },
    { 0x00088610U, 0x00001000U, 0x00000001U, "VSEC_HIER"  },
    { 0x0008c2c0U, 0x00000004U, 0x00000000U, "CYA_0"      },
};
#define XG_POL_N ((INTN)(sizeof(xg_pol) / sizeof(xg_pol[0])))

static void
xg_policy_probe(const CHAR16 *tag)
{
    UINT32 gate, st, changed, ok, i;
    UINT64 t;

    t = fx_now_us();

    /* Предусловие: гейт должен быть открыт. Если E-A не встал — E-B бессмыслен,
     * и это должно быть сказано в логе, а не промолчать. */
    gate = mmio_read32(0x0008e1b0U);
    ulogf(L"XGPOL precondition: XP3G gate 0x0008e1b0 = 0x%08x %s\n", gate,
          (gate == 0xffffffffU) ? "OPEN" : "NOT OPEN");
    if (gate != 0xffffffffU) {
        ulogf(L"XGPOL VERDICT: SKIPPED - gate is not open, policy result "
               "would carry no weight\n");
        Print(L"xpol: SKIPPED, gate not open\n");
        return;
    }

    /* LnkSta до: контроль того, что линок мы не трогаем. */
    st = mmio_read32(0x00088088U);
    ulogf(L"XGPOL link BEFORE: LNKSTA=0x%08x speed=%d width=%d\n", st,
          (INTN)((st >> 16) & 0xF), (INTN)((st >> 4) & 0x3F));

    changed = 0; ok = 0;
    for (i = 0; i < XG_POL_N; i++) {
        UINT32 cur = mmio_read32(xg_pol[i].addr);
        UINT32 want = (cur & ~xg_pol[i].clrMask) | xg_pol[i].setBits;
        UINT32 got;

        ulogf(L"XGPOL %s 0x%08x before=0x%08x want=0x%08x %s\n",
              xg_pol[i].name, xg_pol[i].addr, cur, want,
              (want == cur) ? "NOOP" : "CHANGE");
        if (want == cur) {
            /* Тавтология: запись ничего не меняет, доказательств не даёт. */
            Print(L"xpol: %s 0x%08x already 0x%08x - NOOP, not counted\n",
                  xg_pol[i].name, xg_pol[i].addr, cur);
            continue;
        }
        changed++;
        mmio_write32(xg_pol[i].addr, want);
        got = mmio_read32(xg_pol[i].addr);
        if (got == want) {
            ok++;
            ulogf(L"XGPOL %s 0x%08x wrote 0x%08x got 0x%08x STUCK\n",
                  xg_pol[i].name, xg_pol[i].addr, want, got);
            Print(L"xpol: %s 0x%08x -> 0x%08x OK\n", xg_pol[i].name,
                  xg_pol[i].addr, got);
        } else {
            ulogf(L"XGPOL %s 0x%08x wrote 0x%08x got 0x%08x DROPPED\n",
                  xg_pol[i].name, xg_pol[i].addr, want, got);
            Print(L"xpol: %s 0x%08x -> 0x%08x DROPPED\n", xg_pol[i].name,
                  xg_pol[i].addr, got);
        }
    }

    st = mmio_read32(0x00088088U);
    ulogf(L"XGPOL link AFTER : LNKSTA=0x%08x speed=%d width=%d\n", st,
          (INTN)((st >> 16) & 0xF), (INTN)((st >> 4) & 0x3F));
    ulogf(L"XGPOL summary: %d of %d changed fields stuck (%d NOOP not counted)\n",
          ok, changed, XG_POL_N - changed);

    if ((changed > 0) && (ok == changed)) {
        ulogf(L"XGPOL VERDICT: POLICY-OK - gate unlocks host writes; "
               "next step is the LTSSM kick, TLS and retrain, NOT done here\n");
        Print(L"xpol: VERDICT POLICY-OK\n");
    } else if (changed > 0) {
        ulogf(L"XGPOL VERDICT: POLICY-PARTIAL - %d of %d stuck; see DROPPED "
               "lines above\n", ok, changed);
        Print(L"xpol: VERDICT POLICY-PARTIAL %d/%d\n", ok, changed);
    } else {
        ulogf(L"XGPOL VERDICT: NO-CHANGE - every field already at target; "
               "nothing proven\n");
        Print(L"xpol: VERDICT NO-CHANGE\n");
    }

    ulogf(L"XGPOL === E-B done: %s ===\n", tag);
    fx_mk_acc(t, L"xpol: E-B policy set with gate open");
}
#endif /* XP3G_GATE_POLICY */
#if defined(XP3G_LINK_RETRAIN) && defined(XP3G_GATE_POLICY)
/* ==== ЭКСПЕРИМЕНТ E-C: кик LTSSM + TLS + ретрейн ==========================
 *
 * Блок требует ОБА флага: E-C перепроверяет policy set таблицей xg_pol[] и
 * XG_POL_N, объявленными в E-B, и повторно их использовать не должен.
 * Отдельный флаг, а не продолжение XP3G_GATE_POLICY, потому что xgate2
 * (E-A + E-B) проверен НА ЖЕЛЕЗЕ 2026-09-09, md5 9832745e50ee02cff08ec8d0c8cc5c45.
 * Если бы E-C жил внутри того же флага, имя xgate2 перестало бы давать тот
 * бинарь, который на флешке проверяли.
 *
 * Третий и последний шаг к Gen2. E-A открыл гейт, E-B показал, что policy set
 * заливается целиком. Осталось действие, которое ВПЕРВЫЕ трогает живой линк.
 *
 * ПОРЯДОК (из xrip, порядок значим):
 *   1. Проверить, что policy set действительно стоит (E-B это сделал, но это
 *      ДРУГИЙ запуск; здесь перепроверяем на ФАКТЕ перед тем, как дёргать линок).
 *   2. TLS = 2 (5 GT/s) через PCI config на GPU.
 *   3. TLS = 2 (5 GT/s) через PCI config на АПСТРИМ-БРИДЖЕ.
 *   4. Кик LTSSM BAR0 0x8872C = 6 - ПОСЛЕДНИМ, он и есть "adoption kick".
 *   5. Retrain Link: LNKCTL |= (1<<5) на мосте.
 *
 * ПОЧЕМУ TLS ЧЕРЕЗ PCI CONFIG, А НЕ ЧЕРЕЗ BAR0. 1p, ошибка 2: запись в
 * 0x880A8 (LC2) через BAR0 MMIO не липла и потеряла бит 0x00200000. xrip
 * ставит TLS через PCI config на обоих концах. Наш симптом этим и объяснялся.
 *
 * ЧЕГО ЗДЕСЬ НЕТ, СОЗНАТЕЛЬНО:
 *   - LINK_CAP 0x88084: xrip его не пишет, и у нас он live - speed-ниббл
 *     следует за фактическим линком, кремний клампит Gen3 (write 03 -> readback 02).
 *   - Link Disable и перезапуск устройства: на 40HX это отрывало GSP/RM.
 *     Здесь НЕ делаем, только нормальный ретрейн.
 *   - Повторных попыток. Один кик, один ретрейн. Если не поднялось - пишем
 *     RETRAIN-FAIL и выходим. Линк сам вернётся в Gen1 на POST.
 *
 * ЕСЛИ РЕТРЕЙН НЕ ПОДНЯЛ ЛИНОК, ЭТО НЕ ПРОВАЛ АНЛОКА. Линк фиксируется на
 * ближайшем к тренировке состоянии, Gen1 - это полностью рабочее состояние.
 *
 * ЕДИНСТВЕННЫЙ ЧЕСТНЫЙ КРИТЕРИЙ - ФИЗИЧЕСКАЯ ПОЛОСА:
 *   src/tools/pcie-bw.py -> > 5,5 GB/s (против нынешних 3,343, потолок Gen1 ~4,0).
 * pcie.link.gen.current в простое НЕ является критерием: это downshift (§1p 0.1).
 */

/* До и после: полный снимок состояния, чтобы отличить "не тронули" от
 * "тронули и не вышло". Печатается всегда, включая путь отказа. */
static void
xg_snap(const char *tag)
{
    UINT32 st = mmio_read32(0x00088088U);
    UINTN  gc = find_pcie_cap(gBus, gDev, gFn);
    ulogf(L"XCK %s LNKSTA-inner=0x%08x speed=%d width=%d\n", tag, st,
          (INTN)((st >> 16) & 0xF), (INTN)((st >> 4) & 0x3F));
    ulogf(L"XCK %s LINK_CAP=0x%08x LINK_CAP2=0x%08x LC2-inner=0x%08x\n", tag,
          mmio_read32(0x00088084U), mmio_read32(0x000880a4U),
          mmio_read32(0x000880a8U));
    if (gc) {
        UINT32 lk  = pci_cfg_rd_bdf(gBus, gDev, gFn, gc + 0x10);
        UINT32 lc2 = pci_cfg_rd_bdf(gBus, gDev, gFn, gc + 0x30);
        ulogf(L"XCK %s GPU   cap@0x%02lx LNKCTL=0x%04x speed=%u width=%u "
              L"LNKCTL2=0x%04x TLS=%u\n", tag, (INTN)gc,
              (INTN)(lk & 0xFFFF), (INTN)((lk >> 16) & 0xF),
              (INTN)((lk >> 20) & 0xF), (INTN)(lc2 & 0xFFFF),
              (INTN)(lc2 & 0xF));
    } else {
        ulogf(L"XCK %s GPU   pcie_cap NOT FOUND\n", tag);
    }
    {
        UINTN bb = 0, bd = 0, bf = 0;
        if (find_bridge_to(gBus, &bb, &bd, &bf)) {
            UINTN bc = find_pcie_cap(bb, bd, bf);
            if (bc) {
                UINT32 lk  = pci_cfg_rd_idx(gBrIdx, bb, bd, bf, bc + 0x10);
                UINT32 lc2 = pci_cfg_rd_idx(gBrIdx, bb, bd, bf, bc + 0x30);
                ulogf(L"XCK %s BRIDGE cap@0x%02lx LNKCTL=0x%04x speed=%u "
                      L"LNKCTL2=0x%04x TLS=%u\n", tag, (INTN)bc,
                      (INTN)(lk & 0xFFFF), (INTN)((lk >> 16) & 0xF),
                      (INTN)(lc2 & 0xFFFF), (INTN)(lc2 & 0xF));
            } else {
                ulogf(L"XCK %s BRIDGE pcie_cap NOT FOUND\n", tag);
            }
        } else {
            ulogf(L"XCK %s BRIDGE NOT FOUND - cannot retrain\n", tag);
        }
    }
}

#if defined(XP3G_LINK_DIAG)
/* ==== ДИАГНОСТИКА E-J: ОБА КОНЦА, ВСЕ ЧЕТЫРЕ ПОЛЯ LNKSTAT ================
 *
 * ЗАЧЕМ ЭТОТ БЛОК. Пять прогонов подряд мы смотрели на LNKSTA только у GPU
 * и только одним числом, подписанным в логе как «speed». Разбор показал, что
 * это число — НЕ текущая скорость:
 *
 *   LNKSTA-inner = 0x11010040
 *     CLS  (bits  3:0)  = 0   <- ФАКТИЧЕСКАЯ скорость, 2.5 GT/s
 *     NLW  (bits  9:4)  = 4   <- ширина x4
 *     MLS  (bits 15:10) = 0
 *     XLS  (bits 25:16) = 1   <- МАКСИМУМ, 5.0 GT/s
 *
 * Код печатал (st>>16)&0xF и подписывал это «speed» — то есть подписывал
 * МАКСИМУМ. Совпадение выглядит правдоподобно (1 = Gen2, а линок в Gen1),
 * и именно поэтому расхождение не заметили: подпись врала, но не выглядела
 * абсурдно. Фактическая скорость — CLS, и она 0.
 *
 * Вторая ошибка того же рода. Строки вида «GPU cap@0x78 LNKCTL=0x0040
 * speed=1 width=0» брали speed из битов 16+ LNKCTL — то есть ЗА ПРЕДЕЛАМИ
 * 16-битного регистра, где лежат Link Control 2 и Capability 2. Там всегда
 * нули, поэтому эти два поля не значили ничего.
 *
 * ЧТО ПЕЧАТАЕТСЯ. Для КАЖДОГО конца — LNKCAP (SLS, SLW), LNKSTA (CLS, NLW,
 * MLS, XLS) и оба LNKCTL. Мост читается через PCI config по bc+0x12, потому
 * что BAR0-зеркало есть только у GPU: до сих пор состояние моста мы видели
 * исключительно по TLS, а это одно поле из семи.
 *
 * ЗАЧЕМ ИМЕННО ЭТО СЕЙЧАС. TLS подтверждён на обоих концах, кик проходит,
 * ретрейн выполнен дважды — и скорость 1. Единственное, что осталось
 * непрочитанным, это потолок каждого конца. Если XLS GPU окажется 0,
 * устройство физически не тянет Gen2 и вопрос закрыт окончательно. Если
 * окажется 1 — оно может, и искать надо причину, по которой линок не
 * собирается.
 */
static void
xg_link_diag(const char *tag)
{
    UINTN  gc, bb = 0, bd = 0, bf = 0, bc;
    UINT32 cap, sta, ctl, ctl2;

    gc = find_pcie_cap(gBus, gDev, gFn);
    if (gc) {
        cap  = pci_cfg_rd_bdf(gBus, gDev, gFn, gc + 0x0C);
        sta  = pci_cfg_rd_bdf(gBus, gDev, gFn, gc + 0x12);
        ctl  = pci_cfg_rd_bdf(gBus, gDev, gFn, gc + 0x10);
        ctl2 = pci_cfg_rd_bdf(gBus, gDev, gFn, gc + 0x30);
#if defined(XP3G_LINK_K)
        ulogf(L"XCK DIAG %s GPU    cap@0x%02lx cfg-LNKSTA=0x%08x (0xFFFFFFFF "
              L"means this path does not answer)\n", tag, (INTN)gc, sta);
        /* Фактический источник - BAR0-зеркало LC_STATUS 0x88088. В прогоне
         * xgate8 config space отдавал по этому смещению 0xFFFFFFFF у ОБОИХ
         * концов, то есть LNKSTA оттуда недоступен; BAR0-зеркало при этом
         * отдаёт осмысленное 0x11010040. Печатаем оба, чтобы расхождение
         * источников было видно, а не спрятано за выбором одного. */
        sta = mmio_read32(0x00088088U);
        ulogf(L"XCK DIAG %s GPU    bar-LNKSTA=0x%08x CLS=%u NLW=%u MLS=%u XLS=%u "
              L"| LNKCAP=0x%08x SLS=%u SLW=%u | LNKCTL=0x%04x dis=%u retrain=%u "
              L"| LNKCTL2=0x%04x TLS=%u\n",
              tag, sta, (INTN)(sta & 0xF), (INTN)((sta >> 4) & 0x3F),
              (INTN)((sta >> 10) & 0x3F), (INTN)((sta >> 16) & 0x7),
              cap, (INTN)(cap & 0xF), (INTN)((cap >> 4) & 0x3F),
              (INTN)(ctl & 0xFFFF), (INTN)((ctl >> 4) & 1u),
              (INTN)((ctl >> 5) & 1u), (INTN)(ctl2 & 0xFFFF),
              (INTN)(ctl2 & 0xF));
#else
        /* Без XP3G_LINK_K текст не трогаем: xgate8 прогнан на железе именно
         * с прежней строкой, его отпечаток ad160343 обязан воспроизводиться. */
        ulogf(L"XCK DIAG %s GPU    cap@0x%02lx LNKCAP=0x%08x SLS=%u SLW=%u | "
              L"LNKSTA=0x%08x CLS=%u NLW=%u MLS=%u XLS=%u | LNKCTL=0x%04x "
              L"dis=%u retrain=%u | LNKCTL2=0x%04x TLS=%u\n",
              tag, (INTN)gc, cap, (INTN)(cap & 0xF),
              (INTN)((cap >> 4) & 0x3F), sta, (INTN)(sta & 0xF),
              (INTN)((sta >> 4) & 0x3F), (INTN)((sta >> 10) & 0x3F),
              (INTN)((sta >> 16) & 0xF), (INTN)(ctl & 0xFFFF),
              (INTN)((ctl >> 4) & 1u), (INTN)((ctl >> 5) & 1u),
              (INTN)(ctl2 & 0xFFFF), (INTN)(ctl2 & 0xF));
#endif
    } else {
        ulogf(L"XCK DIAG %s GPU    pcie_cap NOT FOUND\n", tag);
    }

    if (find_bridge_to(gBus, &bb, &bd, &bf) && (bc = find_pcie_cap(bb, bd, bf))) {
        cap  = pci_cfg_rd_idx(gBrIdx, bb, bd, bf, bc + 0x0C);
        sta  = pci_cfg_rd_idx(gBrIdx, bb, bd, bf, bc + 0x12);
        ctl  = pci_cfg_rd_idx(gBrIdx, bb, bd, bf, bc + 0x10);
        ctl2 = pci_cfg_rd_idx(gBrIdx, bb, bd, bf, bc + 0x30);
        ulogf(L"XCK DIAG %s BRIDGE cap@0x%02lx LNKCAP=0x%08x SLS=%u SLW=%u | "
              L"LNKSTA=0x%08x CLS=%u NLW=%u MLS=%u XLS=%u | LNKCTL=0x%04x "
              L"dis=%u retrain=%u | LNKCTL2=0x%04x TLS=%u\n",
              tag, (INTN)bc, cap, (INTN)(cap & 0xF),
              (INTN)((cap >> 4) & 0x3F), sta, (INTN)(sta & 0xF),
              (INTN)((sta >> 4) & 0x3F), (INTN)((sta >> 10) & 0x3F),
              (INTN)((sta >> 16) & 0xF), (INTN)(ctl & 0xFFFF),
              (INTN)((ctl >> 4) & 1u), (INTN)((ctl >> 5) & 1u),
              (INTN)(ctl2 & 0xFFFF), (INTN)(ctl2 & 0xF));
    } else {
        ulogf(L"XCK DIAG %s BRIDGE NOT FOUND\n", tag);
    }
}
#endif /* XP3G_LINK_DIAG */

#if defined(XP3G_WIN_SCAN)
/* ==== РАЗВЕДКА E-L: ЧТО ЕЩЁ ЕСТЬ В ОКНЕ XVE 0x88xxx =====================
 *
 * ЧИСТОЕ ЧТЕНИЕ. Ни одной записи по всему блоку - и это не осторожность, а
 * смысл этапа: мы не знаем, что лежит по адресам, и писать вслепую в
 * PCIe-контроллер значит рисковать состоянием линка вслепую.
 *
 * ПОЧЕМУ ИМЕННО ЭТО ОКНО. Стандартный путь управления линком через config
 * space на карте закрыт, это измерено:
 *     LNKCTL2 (cap+0x30) биты 0-3 (TLS)      -> ПРИНИМАЕТ
 *     LNKCTL  (cap+0x10) бит 4 (Disable Link) -> ОТВЕРГАЕТ
 *     LNKCTL  (cap+0x10) бит 5 (Retrain Link) -> ОТВЕРГАЕТ
 * причём одинаково при обоих порядках Disable (xgate8 и xgate9), то есть
 * дело не в порядке и не в синхронизации, а в самом регистре.
 *
 * ЧТО ИЗВЕСТНО ОБ ЭТОМ ОКНЕ. Референс GA102 (dev_nv_pcfg_xve_regmap.h) даёт
 * четыре адреса: LINK_CAP@0x84, LC_STATUS@0x88, LINK_CAP2@0xA4, LC2@0xA8.
 * Между 0x88 и 0xA4 - 28 БАЙТ, о которых ничего не известно. Там вполне
 * может быть зеркало LNKCTL, и тогда отвергнутый в config space бит окажется
 * записываемым через BAR0.
 *
 * ПОЧЕМУ ЭТО НЕ ПРОСТО ЛЮБОПЫТСТВО. Домен 0x88xxx открыт ботером (xgate5),
 * BAR0 отдаёт осмысленные значения (LNKSTA=0x11010040 читается), значит
 * территория доступна для чтения и потенциально для записи. Прежде чем что-то
 * писать, нужно увидеть, что там есть.
 *
 * КАК ЧИТАТЬ РЕЗУЛЬТАТ:
 *   значение 0x0040 где-либо в окне -> это зеркало LNKCTL (текущее значение
 *                                     GPU-LNKCTL как раз 0x0040), следующий
 *                                     шаг - запись бита туда;
 *   0x0001 рядом с 0x84              -> зеркало LNKCTL2;
 *   нули или 0xBADFxxxx               -> зеркал там нет, BAR0 как альтернатива
 *                                     закрыта.
 *
 * Печатаются ТОЛЬКО текущие значения, ничего не сравнивается с эталоном на
 * лету: сравнение делается человеком по этому же логу, и автоматическая
 * проверка тут была бы гаданием о том, что считать нормой.
 */
static void
xg_win_scan(const char *tag)
{
    UINT32 r[32];
    UINTN  i;

    /* Окно 0x88080..0x880FC = 32 слова. Считываем все подряд, прежде чем
     * печатать: так при отладке не нужно перезапускать ради хвоста. */
    for (i = 0; i < 32; i++)
        r[i] = mmio_read32(0x00088080U + i * 4);

    ulogf(L"XCK WIN %s scan 0x00088080..0x000880FC (read-only, 32 words)\n",
          tag);
    for (i = 0; i < 32; i++) {
        /* Помечаем четыре адреса, которые референс называет по имени, чтобы
         * в потоке шестнадцатеричных чисел они не терялись. */
        ulogf(L"XCK WIN %s +0x%02lx (0x%08lx) = 0x%08x%s\n", tag, (INTN)(i * 4),
              (INTN)(0x00088080U + i * 4), r[i],
              ((0x00088080U + i * 4) == 0x00088084U) ? L"  <- LINK_CAP" :
              ((0x00088080U + i * 4) == 0x00088088U) ? L"  <- LC_STATUS" :
              ((0x00088080U + i * 4) == 0x000880a4U) ? L"  <- LINK_CAP2" :
              ((0x00088080U + i * 4) == 0x000880a8U) ? L"  <- LC2" : L"");
    }

    /* Отдельной строкой - совпадения с текущим LNKCTL устройства (0x0040).
     * Это единственное, что мы ищем, и оно заслуживает отдельного взгляда. */
    {
        INTN hit = -1;
        for (i = 0; i < 32; i++)
            if (r[i] == 0x0040U) { hit = (INTN)(0x00088080U + i * 4); break; }
        if (hit >= 0) {
            ulogf(L"XCK WIN %s FINDING: value 0x0040 (current GPU LNKCTL) found "
                   L"at 0x%08lx - possible LNKCTL mirror\n", tag, (INTN)hit);
        } else {
            ulogf(L"XCK WIN %s no word equals 0x0040, so no obvious LNKCTL "
                   L"mirror in this window\n", tag);
        }
    }
}
#endif /* XP3G_WIN_SCAN */

static void
xg_link_probe(const CHAR16 *tag)
{
    UINT32 gate, st, kick, i, polOk;
    UINTN  gc, bb = 0, bd = 0, bf = 0, bc = 0;
    UINTN  polls;
    UINT64 t;
#if defined(XP3G_LINK_STIMULUS)
    /* Счётчик подтверждений TLS=2 на GPU. Считается ДВАЖДЫ: до кика LTSSM и
     * после него. Объявлен только под этим флагом, чтобы xgate5 и xgate6
     * собирались побайтово теми же, что проверены на железе. */
    UINT32 tlsSet;
#endif

    t = fx_now_us();

#if defined(XP3G_WIN_SCAN)
    /* РаЗВЕДКА ИДЁТ ПЕРВОЙ, ДО ВСЕХ ПРЕДУСЛОВИЙ. Это единственный блок,
     * который не требует ни открытого гейта, ни policy set, ни найденного
     * моста: он просто читает окно BAR0. Если поставить его позже, стадия
     * окажется заблокирована любым из ранних выходов, а её единственная
     * задача - увидеть содержимое окна, а не что-то изменить. */
    xg_win_scan("pre");
#endif

    /* --- Шаг 0: предусловие. Гейт и policy set обязаны стоять. Без них
     * дёргать линок бессмысленно и зачем рисковать. --- */
    gate = mmio_read32(0x0008e1b0U);
    if (gate != 0xffffffffU) {
        ulogf(L"XCK precondition FAIL: gate 0x0008e1b0=0x%08x not open - "
               "NOT touching the link\n", gate);
        Print(L"xck: SKIPPED, gate not open\n");
        return;
    }
    polOk = 0;
    for (i = 0; i < XG_POL_N; i++) {
        UINT32 cur  = mmio_read32(xg_pol[i].addr);
        UINT32 want = (cur & ~xg_pol[i].clrMask) | xg_pol[i].setBits;
        if (cur == want) polOk++;
    }
    if (polOk != XG_POL_N) {
        ulogf(L"XCK precondition FAIL: policy %d of %d at target - "
               "NOT touching the link\n", polOk, XG_POL_N);
        Print(L"xck: SKIPPED, policy %d/%d\n", polOk, XG_POL_N);
        return;
    }
    ulogf(L"XCK precondition OK: gate open, policy %d of %d at target\n",
          polOk, XG_POL_N);

    /* Мост ищём ОДИН раз: если его нет, ретрейн физически невозможен и
     * лезть в TLS GPU незачем. */
    if (!find_bridge_to(gBus, &bb, &bd, &bf)) {
        ulogf(L"XCK VERDICT: NO-BRIDGE - link NOT touched at all\n");
        Print(L"xck: VERDICT NO-BRIDGE\n");
        return;
    }
    bc = find_pcie_cap(bb, bd, bf);
    gc = find_pcie_cap(gBus, gDev, gFn);
    if (!bc || !gc) {
        ulogf(L"XCK VERDICT: NO-PCIE-CAP gpu=%u bridge=%u - link NOT touched\n",
              (UINTN)gc, (UINTN)bc);
        Print(L"xck: VERDICT NO-PCIE-CAP\n");
        return;
    }

    ulogf(L"XCK === BEFORE: the link is about to be touched for the first "
           L"time in this project ===\n");
    xg_snap("before");
#if defined(XP3G_LINK_DIAG)
    xg_link_diag("pre");
#endif

#if defined(XP3G_XVE_MASK)
    /* --- Шаг 0 (E-F): открыть XVE-маску PCIe-домена ДО ретрейна ----------
     *
     * ЗАЧЕМ. Референс iatethelogs (rejoin16-cycle.sh) открывает ровно две
     * маски: 0x823800 (FEAT PLM) и 0x88FE8 (XVE). Первую мы открываем
     * (рендер-стадия G2RMK), вторую НЕ открывали НИ РАЗУ ни в одной сборке.
     * Прогон 2026-10-10 (xgate3) поэтому мерил не тот рецепт: гейт 0x8E1B0
     * и policy set — из нашего списка, а XVE-маски из референсного в нём
     * не было. docs/70HX-XP3G-GATE-V67.md §4a.11.11.
     *
     * ГИПОТЕЗА, КОТОРУЮ ЭТО ПРОВЕРЯЕТ. Шаг 1 ниже пишет TLS=2 в LNKCTL2
     * (cap+0x30) на GPU и запись DROPPED — readback 0x0001, тогда как на
     * мосте тот же бит встал. Если XVE-маска держит запись в PCIe-домене,
     * после её открытия шаг 1 обязан перестать отбрасываться. Это
     * ПРОВЕРЯЕМО: строка шага 1 печатается в этом же прогоне.
     *
     * ПОРЯДОК. Маска открывается ДО шага 1, потому что её назначение —
     * снять защиту с записи в домен до того, как туда кто-то пишет. После
     * шага 1 открытие бессмысленно: отброшенную запись надо повторить.
     *
     * ЧТО ЗДЕСЬ НЕ ДЕЛАЕТСЯ. Не пишется 0x823800: рендер-стадия уже открыла
     * его раньше по коду, и повтор здесь ничего бы не изменил. Не делается
     * кик LTSSM и не трогается LINK_CAP — это шаги 3 и отдельная тема.
     */
    {
        UINT32 b4 = mmio_read32(0x00088fe8U);
        UINT32 g4;
        ulogf(L"XVM  precondition: gate=0x%08x XVE_D0(0x88fe8)=0x%08x\n",
              gate, b4);
        mmio_write32(0x00088fe8U, 0xffffffffU);
        /* Запись может быть синхронной, а может нет: у 0x823800 readback
         * читался с polls=0, но это не доказательство для этого адреса.
         * Опрос короткий, 400 мс — ровно как у рендер-масок. */
        g4 = mmio_read32(0x00088fe8U);
        for (i = 0; g4 != 0xffffffffU && i < 400; i++) {
            uefi_call_wrapper(BS->Stall, 1, 1000);
            g4 = mmio_read32(0x00088fe8U);
        }
        ulogf(L"XVM  0x00088fe8 before=0x%08x wrote 0xffffffff got 0x%08x %s "
               L"(polls=%d)\n", b4, g4,
              (g4 == 0xffffffffU) ? L"OPEN" : L"LOCKED", (INTN)i);
        Print(L"xvm: XVE 0x88fe8 0x%08x -> 0x%08x %s\n", b4, g4,
              (g4 == 0xffffffffU) ? L"OPEN" : L"LOCKED");

        /* Соседние маски того же домена (0x88FE8..0x88FF8 идут подряд,
         * KNOWN-ISSUES.md §51.7). Их открытие НЕ требуется для рецепта
         * референса, но показывает, открывается ли домой целиком или
         * по одному адресу. Одна попытка каждая, без повторов. */
        {
            static const UINT32 xvm_addr[4] = {
                0x00088fecU, 0x00088ff0U, 0x00088ff4U, 0x00088ff8U
            };
            UINT32 k;
            for (k = 0; k < 4; k++) {
                UINT32 b = mmio_read32(xvm_addr[k]);
                UINT32 g;
                if (b == 0xffffffffU) {
                    ulogf(L"XVM  0x%08x already 0xffffffff - NOOP\n",
                          xvm_addr[k]);
                    continue;
                }
                mmio_write32(xvm_addr[k], 0xffffffffU);
                g = mmio_read32(xvm_addr[k]);
                ulogf(L"XVM  0x%08x before=0x%08x wrote 0xffffffff got 0x%08x "
                       L"%s\n", xvm_addr[k], b, g,
                      (g == 0xffffffffU) ? L"OPEN" : L"LOCKED");
            }
        }

        if (g4 == 0xffffffffU) {
            ulogf(L"XVM  VERDICT: XVE-MASK-OPEN - the PCIe-domain write mask "
                   L"took; whether that unblocks TLS=2 on the GPU is decided by "
                   L"step1 below, not here\n");
            Print(L"xvm: VERDICT XVE-MASK-OPEN\n");
        } else {
            ulogf(L"XVM  VERDICT: XVE-MASK-LOCKED - 0x88fe8 did not open; the "
                   L"domain is protected by something the gate 0x8e1b0 does "
                   L"not cover. Step1 will still be DROPPED, and that is now "
                   L"measured rather than guessed\n");
            Print(L"xvm: VERDICT XVE-MASK-LOCKED\n");
        }
        ulogf(L"XVM  === E-F done: xve domain mask ===\n");
    }
#endif /* XP3G_XVE_MASK */

    /* --- Шаг 1: TLS = 2 (5 GT/s) на GPU, через PCI config. ---
     *
     * ЧТО ИСПРАВЛЕНО. До 2026-10-10 шаг был «записать и прочитать сразу».
     * Readback показывал 0x0001, и три прогона подряд это печаталось как
     * DROPPED. Прогон xgate5 доказал обратное: та же запись К ФИНАЛЬНОМУ
     * снимку давала LNKCTL2=0x0002 TLS=2 в config space и LC2-inner=0x00000002
     * в BAR0-зеркале. То есть запись НЕ отбрасывается, а применяется
     * асинхронно, и мгновенный readback ловил её до вступления в силу.
     *
     * ПОЧЕМУ ЭТО ЛОМАЛО ВСЁ. Шаг 4 (Retrain Link) выполнялся сразу после
     * шагов 1-3, то есть вероятнее всего ДО того, как TLS=2 вступил в силу.
     * Мы ретрейнили линок со старым значением скорости и получали Gen1 —
     * и считали, что запись не проходит. Теперь порядок другой: сначала
     * доказываем, что TLS встал, и только потом дёргаем линок.
     *
     * Опрос 40 x 100 мс = 4 с. Порядок величины взят у референса: там до
     * 13 попыток с паузой до 13 с, так что 4 с - скромно. Если TLS не встал
     * за это время, линк не трогаем: ретрейн без зафиксированной скорости
     * бессмыслен и просто тратит 10 с опроса.
     */
    {
        UINT32 lc2 = pci_cfg_rd_bdf(gBus, gDev, gFn, gc + 0x30);
        UINT32 set = (lc2 & 0xFFFF0000u) | ((lc2 & 0xFFFFu & ~0xFu) | 2u);
#if defined(XP3G_LINK_ORDER)
        UINT32 got, inst;
        UINTN  tp;
        pci_cfg_wr_bdf(gBus, gDev, gFn, gc + 0x30, set);
        got = pci_cfg_rd_bdf(gBus, gDev, gFn, gc + 0x30);
        ulogf(L"XCK step1 GPU LNKCTL2(cap+0x30) %04x -> %04x readback %04x "
              "TLS=%u (instant readback)\n", (INTN)(lc2 & 0xFFFF),
              (INTN)(set & 0xFFFF), (INTN)(got & 0xFFFF), (INTN)(got & 0xF));

        /* Ожидание фактического вступления в силу. */
        inst = got;
        for (tp = 0; ((got & 0xFu) != 2u) && tp < 40; tp++) {
            uefi_call_wrapper(BS->Stall, 1, 100000);
            got = pci_cfg_rd_bdf(gBus, gDev, gFn, gc + 0x30);
        }
#if defined(XP3G_LINK_STIMULUS)
        ulogf(L"XCK step1b GPU TLS %s after %d polls x 100ms (PRE-KICK, "
              "instant readback was TLS=%u)\n",
              ((got & 0xFu) == 2u) ? "SET" : "NOT-SET", (INTN)tp,
              (INTN)(inst & 0xF));
#else
        /* Текст строки НЕ трогаем без XP3G_LINK_STIMULUS: xgate6 прогнан на
         * железе с этой формулировкой, и его отпечаток 356b6b64 обязан
         * воспроизводиться. Пометка "PRE-KICK" имеет смысл только рядом с
         * точкой B, а она есть лишь в E-I. */
        ulogf(L"XCK step1b GPU TLS %s after %d polls x 100ms "
              "(instant readback was TLS=%u - ASYNCHRONOUS WRITE, this is what "
              "three earlier runs misread as DROPPED)\n",
              ((got & 0xFu) == 2u) ? "SET" : "NOT-SET", (INTN)tp,
              (INTN)(inst & 0xF));
#endif
        Print(L"xck: GPU TLS -> %u %s (%d polls)\n", (INTN)(got & 0xF),
              ((got & 0xFu) == 2u) ? "OK" : "NOT SET", (INTN)tp);

#if defined(XP3G_LINK_STIMULUS)
        /* РАННЕГО ВЫХОДА ЗДЕСЬ НЕТ, и это главное отличие от xgate6.
         *
         * xgate6 выходил с вердиктом TLS-NOT-SET после 4 с ожидания и на этом
         * останавливался. Прогон xgate5 при этом показывал TLS=2 - но там
         * между записью и чтением успевали пройти кик LTSSM И ретрейн. То
         * есть не установлено, чем именно применяется запись: временем или
         * побуждением контроллера. Выход по часам уничтожал ровно то
         * наблюдение, ради которого стадия существует.
         *
         * Теперь здесь только измерение точки A. Что с ней будет - решает
         * шаг 3b, а не таймер. */
        tlsSet = ((got & 0xFu) == 2u) ? 1u : 0u;
#else
        if ((got & 0xFu) != 2u) {
            ulogf(L"XCK VERDICT: TLS-NOT-SET on the GPU after %d polls - link "
                   "NOT touched, a retrain with no target speed would be "
                   "meaningless\n", (INTN)tp);
            Print(L"xck: VERDICT TLS-NOT-SET\n");
            return;
        }
#endif
#else
        /* Старый путь: записать и прочитать СРАЗУ. Именно он три прогона
         * подряд печатал DROPPED на запись, которая на самом деле вставала
         * асинхронно (доказано прогоном xgate5, см. §4a.11.13). Оставлен
         * нетронутым, чтобы xgate5 собирался побайтово тем же. */
        UINT32 got;
        pci_cfg_wr_bdf(gBus, gDev, gFn, gc + 0x30, set);
        got = pci_cfg_rd_bdf(gBus, gDev, gFn, gc + 0x30);
        ulogf(L"XCK step1 GPU LNKCTL2(cap+0x30) %04x -> %04x readback %04x "
              "TLS=%u %s\n", (INTN)(lc2 & 0xFFFF), (INTN)(set & 0xFFFF),
              (INTN)(got & 0xFFFF), (INTN)(got & 0xF),
              ((got & 0xFu) == 2u) ? "OK" : "NOT SET");
        Print(L"xck: GPU TLS -> %u %s\n", (INTN)(got & 0xF),
              ((got & 0xFu) == 2u) ? "OK" : "NOT SET");
#endif
    }

    /* --- Шаг 2: TLS = 2 на АПСТРИМ-БРИДЖЕ. Обязателен: ретрейн без него
     * не даст Gen2, потому что мост останется целиться в Gen1. Тот же опрос,
     * что и на шаге 1: до 2026-10-10 мост читался мгновенно и выглядел
     * синхронным, но это не было проверено, а расхождение с GPU было. --- */
    {
        UINT32 lc2 = pci_cfg_rd_idx(gBrIdx, bb, bd, bf, bc + 0x30);
        UINT32 set = (lc2 & 0xFFFF0000u) | ((lc2 & 0xFFFFu & ~0xFu) | 2u);
#if defined(XP3G_LINK_ORDER)
        UINT32 got;
        UINTN  tp;
        pci_cfg_wr_idx(gBrIdx, bb, bd, bf, bc + 0x30, set);
        got = pci_cfg_rd_idx(gBrIdx, bb, bd, bf, bc + 0x30);
        ulogf(L"XCK step2 BRIDGE LNKCTL2(cap+0x30) %04x -> %04x readback %04x "
              "TLS=%u (instant readback)\n", (INTN)(lc2 & 0xFFFF),
              (INTN)(set & 0xFFFF), (INTN)(got & 0xFFFF), (INTN)(got & 0xF));

        for (tp = 0; ((got & 0xFu) != 2u) && tp < 40; tp++) {
            uefi_call_wrapper(BS->Stall, 1, 100000);
            got = pci_cfg_rd_idx(gBrIdx, bb, bd, bf, bc + 0x30);
        }
#if defined(XP3G_LINK_STIMULUS)
        ulogf(L"XCK step2b BRIDGE TLS %s after %d polls x 100ms (PRE-KICK)\n",
              ((got & 0xFu) == 2u) ? "SET" : "NOT-SET", (INTN)tp);
#else
        /* См. комментарий у шага 1b: текст без STIMULUS не трогаем. */
        ulogf(L"XCK step2b BRIDGE TLS %s after %d polls x 100ms\n",
              ((got & 0xFu) == 2u) ? "SET" : "NOT-SET", (INTN)tp);
#endif
        Print(L"xck: BRIDGE TLS -> %u %s (%d polls)\n", (INTN)(got & 0xF),
              ((got & 0xFu) == 2u) ? "OK" : "NOT SET", (INTN)tp);

#if !defined(XP3G_LINK_STIMULUS)
        if ((got & 0xFu) != 2u) {
            ulogf(L"XCK VERDICT: TLS-NOT-SET on the bridge after %d polls - "
                   "link NOT touched\n", (INTN)tp);
            Print(L"xck: VERDICT TLS-NOT-SET bridge\n");
            return;
        }
#endif
#else
        /* Старый путь, см. шаг 1: оставлен нетронутым ради побайтовой
         * воспроизводимости xgate5. */
        UINT32 got;
        pci_cfg_wr_idx(gBrIdx, bb, bd, bf, bc + 0x30, set);
        got = pci_cfg_rd_idx(gBrIdx, bb, bd, bf, bc + 0x30);
        ulogf(L"XCK step2 BRIDGE LNKCTL2(cap+0x30) %04x -> %04x readback %04x "
              "TLS=%u %s\n", (INTN)(lc2 & 0xFFFF), (INTN)(set & 0xFFFF),
              (INTN)(got & 0xFFFF), (INTN)(got & 0xF),
              ((got & 0xFu) == 2u) ? "OK" : "NOT SET");
        Print(L"xck: BRIDGE TLS -> %u %s\n", (INTN)(got & 0xF),
              ((got & 0xFu) == 2u) ? "OK" : "NOT SET");
#endif
    }

    /* --- Шаг 3: кик LTSSM. При XP3G_LINK_ORDER идёт ПОСЛЕ подтверждения TLS
     * на обоих концах; иначе — на прежнем месте, как было. ---
     *
     * ЧТО ИЗМЕНЕНО ПО СУТИ (E-H). Раньше комментарий здесь говорил «ПОСЛЕДНИМ
     * из записей», и это было верно для той последовательности: шаги 1-2
     * считались выполненными сразу после мгновенного readback. С опросом
     * TLS кик приходит ПОСЛЕ того, как целевая скорость зафиксирована. Это
     * его правильное место: adoption говорит контроллеру «пересобери линок»,
     * и говорить это до установки цели бессмысленно.
     *
     * НАБЛЮДЕНИЕ ИЗ xgate5. Кик не вставал ни в одном прогоне (readback=
     * 0x00000000), пока домен 0x88xxx был закрыт. С открытой маской 0x88FE8
     * он встал: readback=0x00000006. То есть кик был исправен всегда, и
     * «кик не работает» было ещё одним следствием неверного пути доступа. */
    kick = mmio_read32(0x0008872cU);
    ulogf(L"XCK step3 LTSSM_OVR(0x8872c) before=0x%08x\n", kick);
    mmio_write32(0x0008872cU, 6u);
#if defined(XP3G_LINK_ORDER)
    ulogf(L"XCK step3 LTSSM_OVR wrote 6, readback=0x%08x %s\n",
          mmio_read32(0x0008872cU),
          (mmio_read32(0x0008872cU) == 6u) ? "STUCK" : "NOT STUCK");
#else
    ulogf(L"XCK step3 LTSSM_OVR wrote 6, readback=0x%08x\n",
          mmio_read32(0x0008872cU));
#endif
    Print(L"xck: LTSSM kick written\n");

    /* Даём LTSSM время перечитать кик, прежде чем ретрейнить. */
    uefi_call_wrapper(BS->Stall, 1, 100000);

#if defined(XP3G_LINK_STIMULUS)
    /* --- Шаг 3b (E-I): ТОЧКА B. Тот же опрос, что был точкой A, но ПОСЛЕ
     * кика LTSSM. Это и есть решающее измерение.
     *
     * ЧТО РАЗДЕЛЯЕТ ЭТОТ ШАГ. После xgate5 и xgate6 остались три равноправные
     * версии того, почему TLS=2 появляется в финальном снимке, но не сразу:
     *   (а) задержка больше 4 с - тогда TLS встал бы и в xgate6, где 4 с
     *       ожидания никуда не делись, а кика не было. Не встал.
     *   (б) запись применяет кик LTSSM - побуждение контроллера;
     *   (в) запись применяет ретрейн.
     * xgate6 отличался от xgate5 отсутствием И кика, И ретрейна, поэтому
     * сам по себе различения не дал. Этот шаг снимает кик из уравнения:
     * если здесь TLS встанет, а в точке A не стоял - побуждение это кик,
     * и никакого «просто подождать» не требуется.
     *
     * РАННЕГО ВЫХОДА ПО-прежнему НЕТ. Даже если и A, и B дали NOT-SET,
     * впереди ретрейн (версия в) и повторный кик (шаг 6), и останавливаться
     * здесь означало бы снова не довести замер до конца. */
    {
        UINT32 got2;
        UINTN  tp2;
        for (tp2 = 0; ((got2 = pci_cfg_rd_bdf(gBus, gDev, gFn, gc + 0x30),
                       (got2 & 0xFu)) != 2u) && tp2 < 40; tp2++) {
            uefi_call_wrapper(BS->Stall, 1, 100000);
        }
        ulogf(L"XCK step3b GPU TLS %s after %d polls x 100ms (POST-KICK) - "
               L"point A was %s\n",
              ((got2 & 0xFu) == 2u) ? "SET" : "NOT-SET", (INTN)tp2,
              tlsSet ? "SET" : "NOT-SET");
        Print(L"xck: GPU TLS post-kick -> %u %s (%d polls)\n",
              (INTN)(got2 & 0xF),
              ((got2 & 0xFu) == 2u) ? "OK" : "NOT SET", (INTN)tp2);

        if ((got2 & 0xFu) == 2u && !tlsSet) {
            ulogf(L"XCK FINDING: the LTSSM kick is what applies the TLS write - "
                   "point A was NOT-SET, point B is SET with no other event in "
                   "between. A plain write is not applied on its own; it needs "
                   "the kick as a stimulus\n");
            Print(L"xck: FINDING kick applies TLS write\n");
        } else if ((got2 & 0xFu) == 2u && tlsSet) {
            ulogf(L"XCK FINDING: the TLS write applied on its own - point A was "
                   "already SET, so the kick is not required for it\n");
        } else {
            ulogf(L"XCK FINDING: neither before nor after the kick did TLS "
                   "apply; the stimulus, if any, is the retrain\n");
        }
    }
#endif /* XP3G_LINK_STIMULUS */

    /* --- Шаг 4: Retrain Link на мосте. Единственный дёргающий момент. ---
     *
     * В XP3G_LINK_DISABLE сначала идёт полное Disable/Enable, и только затем
     * Retrain. Обоснование — в комментарии блока ниже. */
#if defined(XP3G_LINK_DISABLE)
    /* --- Шаг 4a (E-J): Disable Link -> пауза -> Enable -> пауза -> Retrain.
     *
     * ЧЕМ ЭТО ОТЛИЧАЕТСЯ ОТ RETRAIN. Retrain Link (бит 5) - это ПРОСЬБА
     * «перетренируйся в рамках текущей конфигурации»: контроллер остаётся в
     * Common Configuration и пересобирает линк, не выходя из него. Disable Link
     * (бит 4) - это выход из конфигурации с полным выключением линка и новым
     * входом. Это принципиально разные механизмы, и мы пробовали только первый.
     *
     * ПОЧЕМУ ИМЕННО СЕЙЧАС. TLS подтверждён на обоих концах (xgate7), кик
     * LTSSM применяет запись (тоже xgate7), ретрейн выполнен дважды - и
     * скорость 1. Значит «подождать дольше» и «сказать то же самое ещё раз»
     * уже исчерпаны. Осталась ровно одна не tried-механика: полное
     * пересобирание линка через Disable/Enable.
     *
     * ПОРЯДОК. Сначала мост, потом GPU: вниз по дереву. Между disable и
     * enable - 100 мс, чтобы линок реально погас; после enable - 500 мс, чтобы
     * он успел подняться в Gen1, и только потом Retrain, потому что бит
     * ставится на уже живой линок.
     *
     * ЧТО ПЕЧАТАЕТСЯ ПОСЛЕ КАЖДОЙ ЗАПИСИ. Не только «ок», а фактические
     * значения LNKCTL на обоих концах: если запись не встала (бывает при
     * закрытом домене), это видно сразу, а не через три шага.
     *
     * РИСК. Disable Link ненадолго уронит линк. Анлок от линка не зависит:
     * GFX_SPEED_SELECT и compute работают на Gen1, это измерено на всех
     * прогонах проекта. POST вернёт линк в сток в любом случае. */
    {
        UINT32 d, g;

#if defined(XP3G_LINK_K)
        /* ПОРЯДОК ИСПРАВЛЕН (E-K). Disable Link идёт ПО ДЕРЕВУ, от конца к
         * началу: сначала endpoint (GPU), потом корень (мост); включение —
         * в обратном порядке.
         *
         * В xgate8 было наоборот: Disable моста, Enable моста, и только потом
         * Disable GPU. В итоге Disable Link на GPU НЕ ВСТАЛ (0050 -> readback
         * 0040, бит отвергнут), тогда как на мосте встал. Объяснение простое:
         * к моменту попытки на GPU линок со стороны моста уже был включён
         * снова, то есть апстрим живой, и устройство не считает, что имеет
         * право выключить линок. Порядок не был случайной опечаткой - он
         * был выбран неявно, порядком вызовов, и никто его не проверял. */
        g = pci_cfg_rd_bdf(gBus, gDev, gFn, gc + 0x10);
        pci_cfg_wr_bdf(gBus, gDev, gFn, gc + 0x10, g | (1u << 4));
        ulogf(L"XCK step4a GPU    LNKCTL %04x -> %04x readback %04x "
               L"(Disable Link bit4, DOWNSTREAM FIRST)\n", (INTN)(g & 0xFFFF),
              (INTN)((g | (1u << 4)) & 0xFFFF),
              (INTN)(pci_cfg_rd_bdf(gBus, gDev, gFn, gc + 0x10) & 0xFFFF));
        uefi_call_wrapper(BS->Stall, 1, 100000);

        d = pci_cfg_rd_idx(gBrIdx, bb, bd, bf, bc + 0x10);
        pci_cfg_wr_idx(gBrIdx, bb, bd, bf, bc + 0x10, d | (1u << 4));
        ulogf(L"XCK step4a BRIDGE LNKCTL %04x -> %04x readback %04x "
               L"(Disable Link bit4)\n", (INTN)(d & 0xFFFF),
              (INTN)((d | (1u << 4)) & 0xFFFF),
              (INTN)(pci_cfg_rd_idx(gBrIdx, bb, bd, bf, bc + 0x10) & 0xFFFF));
        uefi_call_wrapper(BS->Stall, 1, 100000);

        d = pci_cfg_rd_idx(gBrIdx, bb, bd, bf, bc + 0x10);
        pci_cfg_wr_idx(gBrIdx, bb, bd, bf, bc + 0x10, d & ~(1u << 4));
        ulogf(L"XCK step4a BRIDGE LNKCTL %04x -> %04x readback %04x "
               L"(Enable Link, ROOT FIRST)\n", (INTN)(d & 0xFFFF),
              (INTN)((d & ~(1u << 4)) & 0xFFFF),
              (INTN)(pci_cfg_rd_idx(gBrIdx, bb, bd, bf, bc + 0x10) & 0xFFFF));
        uefi_call_wrapper(BS->Stall, 1, 500000);

        g = pci_cfg_rd_bdf(gBus, gDev, gFn, gc + 0x10);
        pci_cfg_wr_bdf(gBus, gDev, gFn, gc + 0x10, g & ~(1u << 4));
        ulogf(L"XCK step4a GPU    LNKCTL %04x -> %04x readback %04x "
               L"(Enable Link, DOWNSTREAM LAST)\n", (INTN)(g & 0xFFFF),
              (INTN)((g & ~(1u << 4)) & 0xFFFF),
              (INTN)(pci_cfg_rd_bdf(gBus, gDev, gFn, gc + 0x10) & 0xFFFF));
        uefi_call_wrapper(BS->Stall, 1, 500000);
#else
        /* Прежний порядок, оставлен как был: xgate8 прогнан на железе именно
         * с ним, и его отпечаток ad160343 обязан воспроизводиться. */
        d = pci_cfg_rd_idx(gBrIdx, bb, bd, bf, bc + 0x10);
        pci_cfg_wr_idx(gBrIdx, bb, bd, bf, bc + 0x10, d |  (1u << 4));
        ulogf(L"XCK step4a BRIDGE LNKCTL %04x -> %04x readback %04x "
               L"(Disable Link bit4)\n", (INTN)(d & 0xFFFF),
              (INTN)((d | (1u << 4)) & 0xFFFF),
              (INTN)(pci_cfg_rd_idx(gBrIdx, bb, bd, bf, bc + 0x10) & 0xFFFF));
        uefi_call_wrapper(BS->Stall, 1, 100000);

        d = pci_cfg_rd_idx(gBrIdx, bb, bd, bf, bc + 0x10);
        pci_cfg_wr_idx(gBrIdx, bb, bd, bf, bc + 0x10, d & ~(1u << 4));
        ulogf(L"XCK step4a BRIDGE LNKCTL %04x -> %04x readback %04x "
               L"(Enable Link)\n", (INTN)(d & 0xFFFF),
              (INTN)((d & ~(1u << 4)) & 0xFFFF),
              (INTN)(pci_cfg_rd_idx(gBrIdx, bb, bd, bf, bc + 0x10) & 0xFFFF));
        uefi_call_wrapper(BS->Stall, 1, 500000);

        g = pci_cfg_rd_bdf(gBus, gDev, gFn, gc + 0x10);
        pci_cfg_wr_bdf(gBus, gDev, gFn, gc + 0x10, g |  (1u << 4));
        ulogf(L"XCK step4a GPU    LNKCTL %04x -> %04x readback %04x "
               L"(Disable Link bit4)\n", (INTN)(g & 0xFFFF),
              (INTN)((g | (1u << 4)) & 0xFFFF),
              (INTN)(pci_cfg_rd_bdf(gBus, gDev, gFn, gc + 0x10) & 0xFFFF));
        uefi_call_wrapper(BS->Stall, 1, 100000);

        g = pci_cfg_rd_bdf(gBus, gDev, gFn, gc + 0x10);
        pci_cfg_wr_bdf(gBus, gDev, gFn, gc + 0x10, g & ~(1u << 4));
        ulogf(L"XCK step4a GPU    LNKCTL %04x -> %04x readback %04x "
               L"(Enable Link)\n", (INTN)(g & 0xFFFF),
              (INTN)((g & ~(1u << 4)) & 0xFFFF),
              (INTN)(pci_cfg_rd_bdf(gBus, gDev, gFn, gc + 0x10) & 0xFFFF));
        uefi_call_wrapper(BS->Stall, 1, 500000);
#endif /* XP3G_LINK_K */
#if defined(XP3G_LINK_DIAG)
        xg_link_diag("post-dis");
#endif
    }
#endif /* XP3G_LINK_DISABLE */

    {
        UINT32 lk;
#if defined(XP3G_LINK_K)
        /* РЕТРЕЙН С ОБОИХ КОНЦОВ (E-K). До сих пор Retrain Link ставился
         * ТОЛЬКО на мосте, ни на одном прогоне проекта - на GPU он не
         * ставился никогда. По PCIe это W1S-бит, и инициатором перехода
         * обычно выступает downstream-устройство; если инициатор только
         * upstream, GPU может не пойти на пересборку.
         *
         * Порядок: сначала GPU (инициатор), затем мост - чтобы к моменту
         * запроса от моста GPU уже был готов. */
        {
            UINT32 gs = pci_cfg_rd_bdf(gBus, gDev, gFn, gc + 0x10);
            pci_cfg_wr_bdf(gBus, gDev, gFn, gc + 0x10, gs | (1u << 5));
            ulogf(L"XCK step4 GPU    LNKCTL %04x -> %04x readback %04x "
                   L"(Retrain Link bit5, DOWNSTREAM INITIATOR)\n",
                  (INTN)(gs & 0xFFFF), (INTN)((gs | (1u << 5)) & 0xFFFF),
                  (INTN)(pci_cfg_rd_bdf(gBus, gDev, gFn, gc + 0x10) & 0xFFFF));
        }
        uefi_call_wrapper(BS->Stall, 1, 200000);
#endif
        lk  = pci_cfg_rd_idx(gBrIdx, bb, bd, bf, bc + 0x10);
        pci_cfg_wr_idx(gBrIdx, bb, bd, bf, bc + 0x10, lk | (1u << 5));
        ulogf(L"XCK step4 BRIDGE LNKCTL %04x -> %04x (Retrain Link bit5 set)\n",
              (INTN)(lk & 0xFFFF), (INTN)((lk | (1u << 5)) & 0xFFFF));
        Print(L"xck: Retrain Link issued\n");
    }

    /* --- Шаг 5: опрос. ОДИН цикл, никаких повторных попыток. --- */
    st = 0;
    for (polls = 0; polls < 40; polls++) {
        uefi_call_wrapper(BS->Stall, 1, 250000);
        st = mmio_read32(0x00088088U);
        if (((st >> 16) & 0xF) >= 2u) break;
    }
    ulogf(L"XCK step5 polled %d x 250ms, LNKSTA=0x%08x speed=%d width=%d\n",
          polls, st, (INTN)((st >> 16) & 0xF), (INTN)((st >> 4) & 0x3F));

#if defined(XP3G_LINK_ORDER)
    /* --- Шаг 6 (E-H): ВТОРОЙ ретрейн, только если первый не дал Gen2.
     *
     * ЗАЧЕМ. В прогоне xgate5 мы увидели, что TLS=2 вступает в силу
     * АСИНХРОННО: мгновенный readback давал 0x0001, финальный снимок —
     * 0x0002. Значит первый ретрейн вполне мог пройти ДО того, как целевая
     * скорость зафиксировалась, и поэтому видел только Gen1. Шаги 1b/2b
     * теперь ждут подтверждения, так что это окно сузилось, но не исчезло
     * полностью: подтверждение читается из config space, а решение
     * принимает LTSSM, и их моменты могут не совпасть.
     *
     * УСЛОВИЕ ПОВТОРА. Не «попробовать ещё раз на всякий случай», а строго
     * «первый дал speed<2 при ПОДТВЕРЖДЁННОМ TLS=2». Если TLS не встал, мы
     * вышли на шаге 1b/2b и сюда не дошли вовсе. Повтор печатается явно
     * (RETRY), чтобы по логу было видно, что попытка была вторая.
     *
     * ПРЕДЕЛ. Один повтор, не цикл. Референс делает до 13 попыток с
     * нарастающей паузой, но каждая у него идёт с ПОДТВЕРЖДЕНИЕМ результата;
     * слепой повтор без проверки читался бы как «стараемся», а не как замер.
     */
    if (((st >> 16) & 0xF) < 2u) {
        UINT32 lk2;
        ulogf(L"XCK step6 first retrain stayed at speed=%d with TLS=2 CONFIRMED "
               "- repeating once, because the target speed may have landed "
               "after the first kick\n", (INTN)((st >> 16) & 0xF));
        Print(L"xck: RETRY retrain (first attempt stayed at speed=%d)\n",
              (INTN)((st >> 16) & 0xF));

        /* Кик LTSSM повторно: ретраи без повторного adoption имеет смысл
         * только если контроллеру снова сказали «пересобери линок». */
        mmio_write32(0x0008872cU, 6u);
        ulogf(L"XCK step6 LTSSM_OVR wrote 6, readback=0x%08x\n",
              mmio_read32(0x0008872cU));
        uefi_call_wrapper(BS->Stall, 1, 500000);

        lk2 = pci_cfg_rd_idx(gBrIdx, bb, bd, bf, bc + 0x10);
        pci_cfg_wr_idx(gBrIdx, bb, bd, bf, bc + 0x10, lk2 | (1u << 5));
        ulogf(L"XCK step6 BRIDGE LNKCTL %04x -> %04x (RETRY, Retrain Link "
               "bit5 set)\n", (INTN)(lk2 & 0xFFFF),
              (INTN)((lk2 | (1u << 5)) & 0xFFFF));

        for (polls = 0; polls < 40; polls++) {
            uefi_call_wrapper(BS->Stall, 1, 250000);
            st = mmio_read32(0x00088088U);
            if (((st >> 16) & 0xF) >= 2u) break;
        }
        ulogf(L"XCK step6 polled %d x 250ms, LNKSTA=0x%08x speed=%d width=%d\n",
              polls, st, (INTN)((st >> 16) & 0xF), (INTN)((st >> 4) & 0x3F));
    } else {
        ulogf(L"XCK step6 skipped - first retrain already gave speed=%d\n",
              (INTN)((st >> 16) & 0xF));
    }
#endif /* XP3G_LINK_ORDER */

    ulogf(L"XCK === AFTER ===\n");
    xg_snap("after");
#if defined(XP3G_LINK_DIAG)
    xg_link_diag("post");
#endif

    /* Вердикт. Скорость ниже и ширина ниже - это НЕ провал анлока: линок
     * зафиксировался на ближайшем к тренировке состоянии, и Gen1 рабоч.
     *
     * ФОРМУЛИРОВКА ПРИ ОТКАЗЕ ИЗМЕНЕНА. До 2026-10-10 здесь стояло «no further
     * attempts are made» — но это было написано для прогона, где TLS не
     * вставал вовсе. Теперь TLS подтверждён ДО ретрейна, и «повторов нет»
     * было бы уже неправдой: один повтор выполнен. */
    if (((st >> 16) & 0xF) >= 2u) {
        ulogf(L"XCK VERDICT: RETRAIN-OK - negotiated speed=%d; measure the "
               "bandwidth with src/tools/pcie-bw.py, LNKSTA alone is not the "
               "criterion\n", (INTN)((st >> 16) & 0xF));
        Print(L"xck: VERDICT RETRAIN-OK speed=%d\n", (INTN)((st >> 16) & 0xF));
    } else {
#if defined(XP3G_LINK_ORDER)
        ulogf(L"XCK VERDICT: RETRAIN-FAIL - stayed at speed=%d WITH TLS=2 "
               "CONFIRMED on both ends. This is NOT an unlock failure: Gen1 is "
               "fully working. One repeat was performed; further attempts are "
               "not made, POST returns the link to stock anyway\n",
              (INTN)((st >> 16) & 0xF));
        Print(L"xck: VERDICT RETRAIN-FAIL speed=%d (TLS=2 confirmed)\n",
              (INTN)((st >> 16) & 0xF));
#else
        /* Прежняя формулировка «no further attempts are made» была верна для
         * прогона без подтверждения TLS. Здесь она сохранена как есть: под
         * XP3G_LINK_ORDER повтор действительно делается, и об этом сказано
         * выше строкой step6. */
        ulogf(L"XCK VERDICT: RETRAIN-FAIL - stayed at speed=%d. This is NOT "
               "an unlock failure: Gen1 is fully working. No further attempts "
               "are made; POST returns the link to stock anyway\n",
              (INTN)((st >> 16) & 0xF));
        Print(L"xck: VERDICT RETRAIN-FAIL speed=%d\n",
              (INTN)((st >> 16) & 0xF));
#endif
    }

    ulogf(L"XCK === E-C done: %s ===\n", tag);
    fx_mk_acc(t, L"xck: E-C LTSSM kick + TLS + retrain");
}
#endif /* XP3G_LINK_RETRAIN && XP3G_GATE_POLICY */

#ifdef XP3G_CAP_DIAG
/* ==== ЭКСПЕРИМЕНТ E-D: ГДЕ ЛОМАЕТСЯ ОБХОД PCIe CAPABILITY ==================
 *
 * Симптом. Ни в одном прогоне проекта обход capability не нашёл ничего - НИ НА
 * GPU, НИ НА МОСТЕ:
 *
 *   usb-log-1008-235743  GEN2C not-found 4/4, успешных cap@0x : 0
 *   usb-log-pre-xgate    GEN2C not-found 4/4, успешных cap@0x : 0
 *   usb-log-xgate        GEN2C not-found 4/4, успешных cap@0x : 0
 *   usb-log-xg2          GEN2C not-found 4/4, успешных cap@0x : 0
 *   usb-log-xg3          XCK VERDICT: NO-PCIE-CAP gpu=0 bridge=0
 *
 * Из-за этого E-C вышел по страховке, НЕ тронув линок. Причина отказа Gen2
 * сейчас ровно одна: find_pcie_cap() возвращает 0.
 *
 * ЧТО УЖЕ ИЗВЕСТНО. Чтение конфигурации РАБОТАЕТ: лог показывает
 * "PCI: #0 = 10de:0000248A bus=2 dev=0 fn=0 (root bridge #0)" - это
 * pci_cfg_rd_bdf(). Значит вопрос не в доступе к конфигу, а в САМОМ ОБХОДЕ.
 *
 * ГИПОТЕЗЫ, ВСЕ ПРОВЕРЯЮТСЯ ОТДЕЛЬНО:
 *   (A) чтение 0x04 отдаёт 0xFFFFFFFF -> выход сразу;
 *   (B) CapPtr = 0 или < 0x40 -> цикл не начинается;
 *   (C) Capability ID != 0x10 (у GA104 может быть иной);
 *   (D) цепочка обрывается на next = 0 раньше 0x10;
 *   (E) 0x10 есть, но не там, где смотрим;
 *   (F) обход идёт через gRb, а ответ лежит через другой RB.
 *
 * (F) САМАЯ ВЕРОЯТНАЯ: find_bridge_to() берёт мост через ЛЮБОЙ из gRbAll[] и
 * запоминает gBrIdx, а pci_cfg_rd_bdf() читает только через gRb (первый).
 * Для bus=2 это может разойтись.
 *
 * ЧИСТО ЧТЕНИЕ. Ни одной записи, ни в BAR0, ни в конфиг. Линок не трогаем.
 */
static void
xcap_dump_hdr(const char *name, UINTN bus, UINTN dev, UINTN fn, INTN rb)
{
    UINT32 id, r04, st;
    UINTN  cap;

    id = r04 = 0; st = 0;
    if (rb >= 0) {
        UINT64 A = ((UINT64)bus << 20) | ((UINT64)dev << 15) |
                   ((UINT64)fn << 12);
        UINT32 v;
        uefi_call_wrapper(gRbAll[rb]->Pci.Read, 5, gRbAll[rb],
            EfiPciIoWidthUint32, A | 0x00, 1, &v); id = v;
        uefi_call_wrapper(gRbAll[rb]->Pci.Read, 5, gRbAll[rb],
            EfiPciIoWidthUint32, A | 0x04, 1, &v); r04 = v;
        uefi_call_wrapper(gRbAll[rb]->Pci.Read, 5, gRbAll[rb],
            EfiPciIoWidthUint32, A | 0x0C, 1, &v); st = v;
    } else {
        id = pci_cfg_rd_bdf(bus, dev, fn, 0x00);
        r04 = pci_cfg_rd_bdf(bus, dev, fn, 0x04);
        st = pci_cfg_rd_bdf(bus, dev, fn, 0x0C);
    }
    cap = (r04 >> 24) & 0xFFu;
    ulogf(L"XCAP raw %s id=0x%08x 0x04=0x%08x CapPtr=0x%02x "
           L"capLo=0x%02x status=0x%08x\n", name, id, r04, (INTN)cap,
          (INTN)(r04 & 0xFF), st);
    Print(L"xcap: %s id=0x%08x 0x04=0x%08x CapPtr=0x%02x\n",
          name, id, r04, (INTN)cap);
}

/* Обход цепочки с ЧЕТЫРЬМЯ разными источниками чтения и стартовой точкой,
 * так видно: ломается доступ, извлечение или сама цепочка. */
static UINTN
xcap_walk(const char *name, INTN rb, UINTN bus, UINTN dev, UINTN fn,
          UINTN start, int from40, UINTN *psteps, UINTN *plast)
{
    UINTN pos = start, guard;
    UINT32 cdw;
    UINTN  off, id, next;

    *psteps = 0; *plast = 0;
    for (guard = 0; guard < 48; guard++) {
        UINT64 A = ((UINT64)bus << 20) | ((UINT64)dev << 15) |
                   ((UINT64)fn << 12);

        if (!from40 && pos < 0x40) {
            ulogf(L"XCAP walk %s stop: pos=0x%02x < 0x40 after %d steps\n",
                  name, (INTN)pos, (INTN)guard);
            return 0;
        }
        if (rb >= 0) {
            UINT32 v;
            uefi_call_wrapper(gRbAll[rb]->Pci.Read, 5, gRbAll[rb],
                EfiPciIoWidthUint32, A | (pos & ~3u), 1, &v); cdw = v;
        } else {
            cdw = pci_cfg_rd_bdf(bus, dev, fn, pos & ~3u);
        }
        off = pos & 3u;
        id   = (cdw >> (off * 8)) & 0xFFu;
        next = (cdw >> (off * 8 + 8)) & 0xFFu;
        (*psteps)++;
        *plast = id;
        if (id == 0x10) {
            ulogf(L"XCAP walk %s HIT pos=0x%02x id=0x10 after %d steps\n",
                  name, (INTN)pos, (INTN)guard);
            return pos;
        }
        ulogf(L"XCAP walk %s step %d pos=0x%02x id=0x%02x next=0x%02x\n",
              name, (INTN)guard, (INTN)pos, (INTN)id, (INTN)next);
        if (next == 0 || next == 0xFF) {
            ulogf(L"XCAP walk %s chain ends after %d steps, no id=0x10\n",
                  name, (INTN)guard);
            return 0;
        }
        pos = next;
    }
    ulogf(L"XCAP walk %s exhausted 48 steps\n", name);
    return 0;
}

static void
xg_cap_diag(const CHAR16 *tag)
{
    UINTN  bb = 0, bd = 0, bf = 0, steps, last, hits, capStart;
    INTN   gpuRb = -1;
    UINTN  i;
    UINT64 t;

    t = fx_now_us();
    ulogf(L"XCAP === E-D start: capability chain walk, READ ONLY ===\n");
    ulogf(L"XCAP env: gRbAllN=%u gBrIdx=%d GPU bus=%u dev=%u fn=%u\n",
          (UINTN)gRbAllN, (INTN)gBrIdx, gBus, gDev, gFn);

    /* --- GPU --- */
    xcap_dump_hdr("GPU/gRb", gBus, gDev, gFn, -1);
    for (i = 0; i < gRbAllN; i++) {
        UINT64 A = ((UINT64)gBus << 20) | ((UINT64)gDev << 15) |
                   ((UINT64)gFn << 12);
        UINT32 v;
        uefi_call_wrapper(gRbAll[i]->Pci.Read, 5, gRbAll[i],
            EfiPciIoWidthUint32, A | 0x00, 1, &v);
        if (v != 0xFFFFFFFFU && v != 0) {
            if (gpuRb < 0) gpuRb = (INTN)i;
            ulogf(L"XCAP raw GPU/rb%u answers 0x%08x\n", (UINTN)i, v);
        } else {
            ulogf(L"XCAP raw GPU/rb%u DEAD 0x%08x\n", (UINTN)i, v);
        }
    }

    capStart = (pci_cfg_rd_bdf(gBus, gDev, gFn, 0x04) >> 24) & 0xFFu;
    hits = xcap_walk("GPU/capptr", -1, gBus, gDev, gFn, capStart, 0,
                     &steps, &last);
    ulogf(L"XCAP RESULT GPU/capptr -> %u (steps=%u lastid=0x%02x)\n",
          hits, steps, last);

    hits = xcap_walk("GPU/from40", -1, gBus, gDev, gFn, 0x40, 1,
                     &steps, &last);
    ulogf(L"XCAP RESULT GPU/from40 -> %u (steps=%u lastid=0x%02x)\n",
          hits, steps, last);

    if (gpuRb >= 0) {
        xcap_dump_hdr("GPU/goodRB", gBus, gDev, gFn, gpuRb);
        hits = xcap_walk("GPU/goodRB-capptr", gpuRb, gBus, gDev, gFn,
                         capStart, 0, &steps, &last);
        ulogf(L"XCAP RESULT GPU/goodRB-capptr -> %u (steps=%u lastid=0x%02x)\n",
              hits, steps, last);
        hits = xcap_walk("GPU/goodRB-from40", gpuRb, gBus, gDev, gFn, 0x40, 1,
                         &steps, &last);
        ulogf(L"XCAP RESULT GPU/goodRB-from40 -> %u (steps=%u lastid=0x%02x)\n",
              hits, steps, last);
    } else {
        ulogf(L"XCAP RESULT GPU: no RB answers the GPU BDF at all\n");
    }

    /* --- Мост --- */
    if (find_bridge_to(gBus, &bb, &bd, &bf)) {
        ulogf(L"XCAP bridge found dev=%u fn=%u gBrIdx=%d\n", bd, bf,
              (INTN)gBrIdx);
        xcap_dump_hdr("BRIDGE/gRb", bb, bd, bf, -1);
        xcap_dump_hdr("BRIDGE/gBrIdx", bb, bd, bf, gBrIdx);

        capStart = (pci_cfg_rd_bdf(bb, bd, bf, 0x04) >> 24) & 0xFFu;
        hits = xcap_walk("BRIDGE/gBr-capptr", -1, bb, bd, bf, capStart, 0,
                         &steps, &last);
        ulogf(L"XCAP RESULT BRIDGE/gBr-capptr -> %u (steps=%u lastid=0x%02x)\n",
              hits, steps, last);

        hits = xcap_walk("BRIDGE/gBr-from40", -1, bb, bd, bf, 0x40, 1,
                         &steps, &last);
        ulogf(L"XCAP RESULT BRIDGE/gBr-from40 -> %u (steps=%u lastid=0x%02x)\n",
              hits, steps, last);

        if (gBrIdx >= 0) {
            hits = xcap_walk("BRIDGE/idx-capptr", gBrIdx, bb, bd, bf,
                             capStart, 0, &steps, &last);
            ulogf(L"XCAP RESULT BRIDGE/idx-capptr -> %u "
                  L"(steps=%u lastid=0x%02x)\n", hits, steps, last);
            hits = xcap_walk("BRIDGE/idx-from40", gBrIdx, bb, bd, bf, 0x40, 1,
                             &steps, &last);
            ulogf(L"XCAP RESULT BRIDGE/idx-from40 -> %u "
                  L"(steps=%u lastid=0x%02x)\n", hits, steps, last);
        }
    } else {
        ulogf(L"XCAP RESULT: NO-BRIDGE\n");
    }

    ulogf(L"XCAP === E-D done: %s ===\n", tag);
    fx_mk_acc(t, L"xcap: E-D capability chain diagnostic");
}
#endif /* XP3G_CAP_DIAG */

#if defined(XP3G_TLS_BAR0) && defined(XP3G_GATE_POLICY)
/* ==== ЭКСПЕРИМЕНТ E-E: ПРИМЕТ ЛИ BAR0-ЗЕРКАЛО TLS ПРИ ОТКРЫТОМ ГЕЙТЕ ======
 *
 * Проблема, которую поставил E-D. На GPU цепочки PCIe capabilities НЕТ:
 *
 *   XCAP raw GPU/gBr id=0x248A10DE 0x04=0x00100006 CapPtr=0x00 capLo=0x06
 *   XCAP RESULT GPU/capptr -> 0 (steps=0)
 *
 * Байт 0x07 = 0x00, то есть CapPtr обнулён и обход не начинается. Обход с 0x40
 * читает на GPU мусор - id=0xDE это BAR4, а не capability:
 *
 *   XCAP walk GPU/from40 step 0 pos=0x40 id=0xDE next=0x10
 *
 * На МОСТЕ capability есть, но указатель на неё тоже обнулён:
 *
 *   XCAP raw BRIDGE  id=0xA1678086 0x04=0x00100007 CapPtr=0x00 capLo=0x07
 *   XCAP RESULT BRIDGE/gBr-from40 -> 64 (steps=1 lastid=0x10)   <- HIT на 0x40
 *
 * Итог E-D: мост читается и TLS на нём поставить можно; на GPU через PCI config
 * поставить НЕЧЕГО, capability-структуры нет.
 *
 * ЧТО ПРОВЕРЯЕМ. Link Control 2 существует в BAR0 как зеркало того же регистра:
 *   BAR0 0x880A8  = LC2 (LINK_CTRL_2), мы его читаем в дампах;
 *   PCI config cap+0x30 = тот же регистр на другой стороне.
 * Проблема была в том, что ЗАПИСЬ в 0x880A8 отбрасывалась (1p ошибка 2). Но
 * те записи шли ПРИ ЗАКРЫТОМ гейте. Гейт с тех пор открыт (E-A), и это ровно
 * то, что здесь проверяется: изменилось ли поведение.
 *
 * ЧТО ВАЖНО НЕ СДЕЛАТЬ. LINK_CAP 0x88084 НЕ пишем ни в коем случае: он
 * скорость-ибловый и живой - следует за фактическим линком, кремний клампит
 * Gen3 (REGISTERS.md, замер "write 03 -> readback 02"). TLS - другое поле.
 *
 * ЛИНК НЕ ТРОГАЕМ. Ни кика, ни ретрейна, ни LnkSta-записей. Только запись
 * TLS-полей с readback и чтение LnkSta как контроль. Даже если TLS встанет,
 * ретрейн в этом блоке НЕ делается - это отдельное решение E-C.
 *
 * ЗАЩИТА ОТ ТАВТОЛОГИИ, как в E-B: поле, у которого цель совпала с «до»,
 * помечается NOOP и в счёт пройденных не идёт.
 *
 * ОТКАТ БЕЗОПАСЕН. Запись в зеркало TLS, даже если она встанет, не меняет
 * negotiated speed: линок переходит на новую скорость только по ретрейну.
 * POST вернёт регистр в сток в любом случае.
 */
typedef struct {
    UINT32 addr;
    UINT32 clrMask;
    UINT32 setBits;
    CHAR8  name[12];
} XT_TLS;

static const XT_TLS xt_tls[] = {
    /* LC2: Target Link Speed в младшем ниббле. */
    { 0x000880a8U, 0x0000000fU, 0x00000002U, "LC2_TLS"    },
    /* Контрольные: те же поля политики, что и в E-B, но в BAR0-виде.
     * Если хотя бы одно из них не встанет - значит проблема не в TLS, а в
     * доступе к BAR0-зеркалам вообще, и вывод E-E будет другой. */
    { 0x0008c040U, 0x000c0000U, 0x00080000U, "LINK_CONFIG"},
    { 0x0008c1c0U, 0x00060000U, 0x00040000U, "PL_LINKRATE"},
};
#define XT_TLS_N ((INTN)(sizeof(xt_tls) / sizeof(xt_tls[0])))

static void
xg_tls_bar0(const CHAR16 *tag)
{
    UINT32 gate, st, stAfter, changed, ok, i;
    UINT64 t;

    t = fx_now_us();

    gate = mmio_read32(0x0008e1b0U);
    if (gate != 0xffffffffU) {
        ulogf(L"XTL precondition FAIL: gate 0x0008e1b0=0x%08x not open\n", gate);
        Print(L"xtl: SKIPPED, gate not open\n");
        return;
    }
    ulogf(L"XTL precondition OK: gate open - testing whether the BAR0 mirror "
           L"now accepts a write, which it did not while the gate was shut\n");

    st = mmio_read32(0x00088088U);
    ulogf(L"XTL link BEFORE: LNKSTA=0x%08x speed=%d width=%d\n", st,
          (INTN)((st >> 16) & 0xF), (INTN)((st >> 4) & 0x3F));

    changed = 0; ok = 0;
    for (i = 0; i < XT_TLS_N; i++) {
        UINT32 cur  = mmio_read32(xt_tls[i].addr);
        UINT32 want = (cur & ~xt_tls[i].clrMask) | xt_tls[i].setBits;
        UINT32 got;

        ulogf(L"XTL %s 0x%08x before=0x%08x want=0x%08x %s\n",
              xt_tls[i].name, xt_tls[i].addr, cur, want,
              (want == cur) ? "NOOP" : "CHANGE");
        if (want == cur) {
            Print(L"xtl: %s 0x%08x already 0x%08x - NOOP, not counted\n",
                  xt_tls[i].name, xt_tls[i].addr, cur);
            continue;
        }
        changed++;
        mmio_write32(xt_tls[i].addr, want);
        got = mmio_read32(xt_tls[i].addr);
        if (got == want) {
            ok++;
            ulogf(L"XTL %s 0x%08x wrote 0x%08x got 0x%08x STUCK\n",
                  xt_tls[i].name, xt_tls[i].addr, want, got);
            Print(L"xtl: %s 0x%08x -> 0x%08x OK\n", xt_tls[i].name,
                  xt_tls[i].addr, got);
        } else {
            ulogf(L"XTL %s 0x%08x wrote 0x%08x got 0x%08x DROPPED\n",
                  xt_tls[i].name, xt_tls[i].addr, want, got);
            Print(L"xtl: %s 0x%08x -> 0x%08x DROPPED\n", xt_tls[i].name,
                  xt_tls[i].addr, got);
        }
    }

    stAfter = mmio_read32(0x00088088U);
    ulogf(L"XTL link AFTER : LNKSTA=0x%08x speed=%d width=%d\n", stAfter,
          (INTN)((stAfter >> 16) & 0xF), (INTN)((stAfter >> 4) & 0x3F));
    ulogf(L"XTL summary: %d of %d changed fields stuck (%d NOOP not counted)\n",
          ok, changed, XT_TLS_N - changed);

    if ((changed > 0) && (ok == changed)) {
        ulogf(L"XTL VERDICT: MIRROR-OK - BAR0 TLS mirror accepts writes now "
               "that the gate is open; E-C can be retried. NOT retrained here, "
               "link speed is unchanged on purpose\n");
        Print(L"xtl: VERDICT MIRROR-OK\n");
    } else if (changed > 0) {
        ulogf(L"XTL VERDICT: MIRROR-BLOCKED - %d of %d stuck; the gate was not "
               "the reason the BAR0 mirror refused writes\n", ok, changed);
        Print(L"xtl: VERDICT MIRROR-BLOCKED %d/%d\n", ok, changed);
    } else {
        ulogf(L"XTL VERDICT: NO-CHANGE - every field already at target; "
               "nothing proven\n");
        Print(L"xtl: VERDICT NO-CHANGE\n");
    }

    ulogf(L"XTL === E-E done: %s ===\n", tag);
    fx_mk_acc(t, L"xtl: E-E TLS via BAR0 mirror, gate open");
}
#endif /* XP3G_TLS_BAR0 && XP3G_GATE_POLICY */

#ifdef PJTAG_SCAN
/* ==== ЭКСПЕРИМЕНТ E-F: ПОИСК PJTAG / ПРИВИЛЕГИРОВАННЫХ ГЕЙТОВ. ТОЛЬКО ЧТЕНИЕ
 *
 * ЗАЧЕМ, ПОСЛЕ ТОГО КАК ЗАКРЫТ Gen2. Граница, которая его убила: на GPU нет
 * цепочки PCIe capabilities (CapPtr обнулён, E-D), а BAR0-зеркало LC2
 * (0x880A8) заблокировано не тем гейтом, что мы открыли (E-E). Каждый
 * оставшийся вопрос упирается в "регистр недоступен", а не в "значение
 * неизвестно" - значит снимать надо потолок доступа, а не искать значения.
 *
 * ГДЕ ВЗЯТО. amoghmunikote/cmpunlocker (CMP 170HX) перечисляет
 * "JTAG (Host2Jtag register access): Working" и в common/constants.yaml даёт
 *   pjtag_plm     { addr: 0x0000c840, value: 0xffffffff }
 *   pjtag_sec_plm { addr: 0x0000c848, value: 0xffffffff }
 *
 * ГЛАВНЫЙ РИСК, И ОН ПРИЧИНА, ПОЧЕМУ БЛОК ТОЛЬКО ЧИТАЕТ. 170HX - это GA100
 * (HBM2e, 7 нм, как A100). У нас GA104. Это РАЗНЫЕ внутренние карты, и
 * priv-домены между GA100 и GA10x переставлялись: тот же 0x8E1xx у нас не
 * совпадает с GA100. Переносить 0xC840 слепо нельзя - это было бы правкой без
 * измерения, ровно то, за что в проекте платили трижды.
 *
 * ПОЭТОМУ ИЩЕМ НЕ АДРЕС, А КЛАСС. Замаскированный регистр в этом проекте
 * выглядит предсказуемо: PLM-поля читаются как 0xFFFFFF8F / 0xFFFFFFCF, а
 * открытые - как точный 0xFFFFFFFF. Значит кандидат находится признаком, а не
 * адресом из чужого репозитория.
 *
 * ЧТО ДЕЛАЕМ. Три дампа, все только чтение:
 *   1. Окно вокруг предполагаемого PJTAG: 0xC800..0xC8FF. Есть ли оно на GA104
 *      вообще, и замаскировано ли оно тем же 0xFFFFFFxx.
 *   2. Скан двух priv-окон (0x820000..0x821FFF и 0x8E0000..0x8E0FFF) на ВСЕ
 *      значения вида 0xFFFFFFxx - это и есть карта запертых гейтов.
 *   3. Скан младших окон BAR0 (0xC0000..0xC0FFF) тем же признаком.
 *
 * ЧТО НЕ ДЕЛАЕМ. Ни одной записи. Ни в один регистр, включая предполагаемый
 * PJTAG: пока кандидат не найден признаком, трогать нечего.
 *
 * ПРИЁМКА:
 *   XPJT win 0x000c800..0x000c8ff  nonff=.. mask8f=.. maskcf=.. zeros=..
 *   XPJT cands: 0x........ = 0x........ (name)
 *   XPJT === E-F done ===
 */
#define PJT_WIN_LO    0x0000c800UL
#define PJT_WIN_HI    0x0000c8ffUL
#define PJT_SCAN_LO   0x000c0000UL
#define PJT_SCAN_HI   0x000c0fffUL
#define PJT_PRIV_LO   0x00820000UL
#define PJT_PRIV_HI   0x00821fffUL
#define PJT_XP3G_LO   0x008e0000UL
#define PJT_XP3G_HI   0x008e0fffUL
/* Лог кольцевой и переполняется, поэтому печатаем счётчики всегда, а сами
 * кандидаты - с жёстким потолком, как CHIPLOG_MAX в chip_size_scan(). */
#define PJT_LOG_MAX   160

static void
pjt_log_cand(UINT32 addr, UINT32 v, INTN *printed)
{
    if (*printed < PJT_LOG_MAX) {
        ulogf(L"XPJT cand 0x%08x = 0x%08x\n", addr, v);
        Print(L"xpjt: cand 0x%08x = 0x%08x\n", addr, v);
        (*printed)++;
    }
}

static void
xg_pjtag_scan(const CHAR16 *tag)
{
    UINT32 a, v;
    INTN   nonff, m8f, mcf, zeros, printed = 0;
    UINT64 t;

    t = fx_now_us();
    ulogf(L"XPJT === E-F start: PJTAG / privileged gate hunt, READ ONLY ===\n");
    ulogf(L"XPJT reference values from amoghmunikote/cmpunlocker (GA100!): "
          L"pjtag_plm=0x0000c840 pjtag_sec_plm=0x0000c848\n");
    ulogf(L"XPJT caveat: 170HX is GA100, ours is GA104; priv domains differ "
          L"between the two, so the addresses above are a HINT, not a target\n");

    /* --- 1. Окно вокруг предполагаемого PJTAG --- */
    nonff = m8f = mcf = zeros = 0;
    for (a = PJT_WIN_LO; a <= PJT_WIN_HI; a += 4) {
        v = mmio_read32(a);
        if (v == 0xFFFFFFFFU) nonff++;
        else if (v == 0)          zeros++;
        else if ((v & 0xFFFFFF00U) == 0xFFFFFF00U) {
            /* КЛАСС ЗАКРЫТЫХ ГЕЙТОВ. Печатаем каждый - их десятки, и они и есть
             * содержание окна. Потолок защищает кольцевой лог. */
            if (v == 0xFFFFFF8FU) m8f++;
            else                  mcf++;
            pjt_log_cand(a, v, &printed);
        }
    }
    ulogf(L"XPJT win 0x%08x..0x%08x: nonff=%d mask8f=%d maskcf=%d zeros=%d\n",
          PJT_WIN_LO, PJT_WIN_HI, nonff, m8f, mcf, zeros);
    Print(L"xpjt: win C800: nonff=%d mask8f=%d maskcf=%d zeros=%d\n",
          nonff, m8f, mcf, zeros);

    /* --- 2. Младшее окно BAR0: там может быть сам PJTAG --- */
    nonff = m8f = mcf = zeros = 0;
    for (a = PJT_SCAN_LO; a <= PJT_SCAN_HI; a += 4) {
        v = mmio_read32(a);
        if (v == 0xFFFFFFFFU) nonff++;
        else if (v == 0)          zeros++;
        else if ((v & 0xFFFFFF00U) == 0xFFFFFF00U) {
            if (v == 0xFFFFFF8FU) m8f++;
            else                  mcf++;
            pjt_log_cand(a, v, &printed);
        }
    }
    ulogf(L"XPJT scan 0x%08x..0x%08x: nonff=%d mask8f=%d maskcf=%d zeros=%d\n",
          PJT_SCAN_LO, PJT_SCAN_HI, nonff, m8f, mcf, zeros);

    /* --- 3. priv-окно 0x82xxxx: эталонная карта гейтов проекта --- */
    nonff = m8f = mcf = zeros = 0;
    for (a = PJT_PRIV_LO; a <= PJT_PRIV_HI; a += 4) {
        v = mmio_read32(a);
        if (v == 0xFFFFFFFFU) nonff++;
        else if (v == 0)          zeros++;
        else if ((v & 0xFFFFFF00U) == 0xFFFFFF00U) {
            if (v == 0xFFFFFF8FU) m8f++;
            else                  mcf++;
            pjt_log_cand(a, v, &printed);
        }
    }
    ulogf(L"XPJT priv 0x%08x..0x%08x: nonff=%d mask8f=%d maskcf=%d zeros=%d\n",
          PJT_PRIV_LO, PJT_PRIV_HI, nonff, m8f, mcf, zeros);

    /* --- 4. XP3G-окно: где уже есть открытый гейт, для сравнения --- */
    nonff = m8f = mcf = zeros = 0;
    for (a = PJT_XP3G_LO; a <= PJT_XP3G_HI; a += 4) {
        v = mmio_read32(a);
        if (v == 0xFFFFFFFFU) nonff++;
        else if (v == 0)          zeros++;
        else if ((v & 0xFFFFFF00U) == 0xFFFFFF00U) {
            if (v == 0xFFFFFF8FU) m8f++;
            else                  mcf++;
            pjt_log_cand(a, v, &printed);
        }
    }
    ulogf(L"XPJT xp3g 0x%08x..0x%08x: nonff=%d mask8f=%d maskcf=%d zeros=%d\n",
          PJT_XP3G_LO, PJT_XP3G_HI, nonff, m8f, mcf, zeros);

    ulogf(L"XPJT printed %d candidates (cap %d)\n", printed, PJT_LOG_MAX);
    ulogf(L"XPJT === E-F done: %s ===\n", tag);
    fx_mk_acc(t, L"xpjt: E-F PJTAG / gate hunt, read only");
}
#endif /* PJTAG_SCAN */

#ifdef FCFF_SCAN
/* ==== ЭКСПЕРИМЕНТ E-G: ЧТО ЗАЩИЩАЮТ ЧЕТЫРЕ РЕГИСТРА 0xFFFFFFFC ============
 *
 * НАХОДКА. E-F (docs/70HX-XP3G-GATE-V67.md §4a.9) нашёл в priv-окне класс
 * значений, которого в прежних выборках проекта не было: 0xFFFFFFFC, то есть
 * заперты биты 0 и 1. Раньше встречались только 0xFFFFFF8F и 0xFFFFFFCF.
 *
 *   XPJT priv 0x00820000..0x00821FFF: nonff=7 mask8f=6 maskcf=4 zeros=448
 *   0x008200D0=0xFFFFFF8F  0x008200D4=0xFFFFFFFC
 *   0x008200D8=0xFFFFFF8F  0x008200DC=0xFFFFFF8F
 *   0x008200E0=0xFFFFFF8F  0x008200E4=0xFFFFFF8F
 *   0x008200E8=0xFFFFFFFC  0x008200EC=0xFFFFFFFC
 *   0x008200F0=0xFFFFFFFC  0x008200F4=0xFFFFFF8F
 *
 * ПОЧЕМУ ИМЕННО ЭТО ИНТЕРЕСНО. Тот же блок 0x8200D0..0x8200F4 проект
 * исключает из всех обходов, и на то есть причина в коде: "записи в этой зоне
 * стабильно валят гостя в ресет на итерациях [29-31] (3 прогона подряд)". То
 * есть про НИХ известно только одно - что их нельзя трогать. ЧТО ОНИ ЗАЩИЩАЮТ,
 * не знает никто, и ни одного прогона, который бы об этом спрашивал, не было.
 *
 * ЧТО ПРОВЕРЯЕМ, ТОЛЬКО ЧТЕНИЕ. Разбираем битовые маски каждого из десяти:
 *   - снимаем маску, сравниваем с соседями того же класса;
 *   - выясняем, чем отличаются 0xFFFFFFFC от 0xFFFFFF8F в пределах одного
 *     блока (какой бит замерен как "защищённый");
 *   - смотрим, есть ли рядом уже ОТКРЫТЫЕ регистры (точный 0xFFFFFFFF) - это
 *     покажет границу между защищённым и нет.
 *
 * ГИПОТЕЗА, КОТОРУЮ ЭТО МОЖЕТ ОПРОВЕРГНУТЬ. "0xFFFFFFFC = 4 гейта, которые
 * можно открыть и которые дадут доступ". Возможно и наоборот: возможно, 0xFC -
 * это НЕ маска, а другое состояние (статусное поле), и открывать там нечего.
 * Именно поэтому сначала ЧТЕНИЕ: отличить "маска" от "статус" можно по чтению,
 * а стоимость ошибки при записи здесь известна - ресет гостя.
 *
 * ЗАЧЕМ ЭТО НУЖНО, ЕСЛИ Gen2 УЖЕ ЗАКРЫТ. Закрыт потому, что НЕЧЕМ открыть
 * LC2. Эти десять - единственные оставшиеся запертые регистры, которые вообще
 * нашлись на карте. Если они ведут к домену, где лежит что-то ещё закрытое,
 * это новая точка входа. Если нет - вопрос закрывается замером, а не
 * рассуждением.
 *
 * НИ ОДНОЙ ЗАПИСИ. Даже если регистры окажутся масками: причину валить гостя
 * в ресет никто не выяснял, и повторять прогоны 29-31 вслепую нельзя.
 */
static void
xg_fcff_scan(const CHAR16 *tag)
{
    UINT32 a, v, opened, fcff, m8f, mcf;
    UINTN  i;
    UINT64 t;
    static const struct { UINT32 base; UINT32 n; } blk[] = {
        { 0x008200d0UL, 10 },   /* OPTB: тот самый блок, который исключён */
    };

    t = fx_now_us();
    ulogf(L"XFCC === E-G start: what do the four 0xFFFFFFFC gates protect? "
           L"READ ONLY ===\n");
    ulogf(L"XFCC context: this block is excluded from every sweep in the project "
           L"because writes there crash the guest (runs 29-31, three in a row)\n");
    ulogf(L"XFCC known: classes seen before were 0xFFFFFF8F and 0xFFFFFFCF only\n");

    for (i = 0; i < 1; i++) {
        UINT32 base = blk[i].base;
        ulogf(L"XFCC block 0x%08x n=%u\n", base, blk[i].n);

        for (a = base; a < base + blk[i].n * 4; a += 4) {
            v = mmio_read32(a);
            ulogf(L"XFCC reg 0x%08x = 0x%08x\n", a, v);
        }

        /* Граница блока: что непосредственно ДО и ПОСЛЕ. Если края открыты,
         * блок виден как осмысленная группа, а не как случайный набор. */
        ulogf(L"XFCC edge before: 0x%08x=0x%08x 0x%08x=0x%08x\n",
              base - 8, mmio_read32(base - 8), base - 4,
              mmio_read32(base - 4));
        ulogf(L"XFCC edge after : 0x%08x=0x%08x 0x%08x=0x%08x\n",
              base + blk[i].n * 4, mmio_read32(base + blk[i].n * 4),
              base + blk[i].n * 4 + 4,
              mmio_read32(base + blk[i].n * 4 + 4));
    }

    /* Счётчики по расширенному окну: сколько вообще какого класса и где. */
    opened = fcff = m8f = mcf = 0;
    for (a = 0x00820000UL; a <= 0x00821000UL; a += 4) {
        v = mmio_read32(a);
        if (v == 0xFFFFFFFFU) { opened++; }
        else if ((v & 0xFFFFFF00U) == 0xFFFFFF00U) {
            if (v == 0xFFFFFFFCU) fcff++;
            else if (v == 0xFFFFFF8FU) m8f++;
            else if (v == 0xFFFFFFCFU) mcf++;
            else ulogf(L"XFCC odd class 0x%08x = 0x%08x\n", a, v);
        }
    }
    ulogf(L"XFCC census 0x00820000..0x00821000: opened=%u fcff=%u mask8f=%u "
          L"maskcf=%u\n", opened, fcff, m8f, mcf);

    /* Тот же счётчик на XP3G-окне, где гейт УЖЕ открыт: сравнение покажет,
     * чем открытый класс отличается от закрытого по соседству. */
    opened = fcff = m8f = mcf = 0;
    for (a = 0x008e1b00UL; a <= 0x008e1c00UL; a += 4) {
        v = mmio_read32(a);
        if (v == 0xFFFFFFFFU) { opened++; }
        else if ((v & 0xFFFFFF00U) == 0xFFFFFF00U) {
            if (v == 0xFFFFFFFCU) fcff++;
            else if (v == 0xFFFFFF8FU) m8f++;
            else if (v == 0xFFFFFFCFU) mcf++;
            else ulogf(L"XFCC odd class (xp3g) 0x%08x = 0x%08x\n", a, v);
        }
    }
    ulogf(L"XFCC census 0x008e1b00..0x008e1c00: opened=%u fcff=%u mask8f=%u "
          L"maskcf=%u\n", opened, fcff, m8f, mcf);

    ulogf(L"XFCC === E-G done: %s ===\n", tag);
    fx_mk_acc(t, L"xfcc: E-G what the 0xFFFFFFFC gates protect");
}
#endif /* FCFF_SCAN */
#endif /* RENDER_MASKS */


static BOOLEAN
fwsec_boot_gsp_sig(UINT64 fwsecPhys, const UINT8 *sig, UINTN sigIdx)
{
    UINT64 fx_ph;   /* метка времени для учёта по фазам */
    UINTN i;
    UINT32 data;
    UINTN fwsecImemSec = g_fwsecImemSec;
    UINT8 *dmem = (UINT8*)(UINTN)(fwsecPhys + FWSEC_DATA_OFF);
    /* v3.20: ЭТОТ fx_ph_begin() ТОЖЕ БЫЛ ЛИШНИМ.
     *
     * Он открывал внешнюю фазу функции, которую не закрывал никто: ни
     * fx_ph_end, ни fx_ph_end_in. Внутренние фазы ('fwsec: reset+STARTCPU'
     * и диагностические) открывались и закрывались своими парами, но
     * счётчик глубины от этого внешнего begin оставался сдвинутым
     * навсегда - на все последующие вызовы функции.
     *
     * Функция зовётся 9 раз за прогон, то есть перекос накапливался до
     * девяти. Этого достаточно, чтобы пометить вложенными ВСЕ фазы,
     * которые считаются после неё.
     *
     * Наблюдалось в прогоне v3.19: все 15 фаз (inside), SUM top-level = 0.
     * Это вторая из двух незакрытых фаз; первая была в
     * render_open_gfx_masks (см. комментарий там).
     *
     * Начинать внешнюю фазу здесь не нужно: имя функции уже известно
     * вызывающему коду, который и меряет 'render: early_unlock_path'
     * вокруг всего вызова. Двойной счёт тут был бы тем же, что и в v3.17,
     * когда ручная метка соврала именно на внешней фазе.
     *
     * v3.21: ВМЕСТО УДАЛЕНИЯ ЗДЕСЬ СТАВИТСЯ ШТАМП, И ЭТО ИСПРАВЛЕНИЕ БАГА,
     * КОТОРЫЙ Я ВНЁС В ЭТАПЕ 5. Удалив begin, я оставил fx_ph
     * неинициализированным, и первая внутренняя фаза функции считалась от
     * мусора на стеке. Плохо выглядящего числа не было - было неправильное,
     * а это хуже. Штамп ставится до первого действия функции. */
    fx_ph = fx_now_us();

    Print(L"\n--- v2.28: FWSEC HS-boot на GSP (0x110000) ---\n");

    /* 1. kflcnReset(GSP): ENGINE reset → BCR=FALCON → RM=PMC_BOOT_0 */
    Print(L"fwsec: kflcnReset(GSP)...\n");
    falcon_wait_reset_ready(L"rr: fwsec kflcnReset GSP", GSP_HWCFG2, GSP_CPUCTL);
    mmio_write32(GSP_ENGINE, 0x1);
    for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
    mmio_write32(GSP_ENGINE, 0x0);
    for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
    falcon_wait_scrub_done(GSP_DMACTL, GSP_HWCFG2, L"gsp-reset");
    uefi_call_wrapper(BS->Stall, 1, 50000);
    mmio_write32(GSP_BCR, 0x1);                 /* CORE_SELECT=FALCON */
    for (i = 0; i < 16; i++) mmio_read32(GSP_BCR);
    mmio_write32(GSP_RM, mmio_read32(0x00100000));  /* chipId0 = PMC_BOOT_0 */
    Print(L"fwsec: GSP после reset: cpuctl=0x%x bcr=0x%x engine=0x%x\n",
          mmio_read32(GSP_CPUCTL), mmio_read32(GSP_BCR), mmio_read32(GSP_ENGINE));
    if ((mmio_read32(GSP_CPUCTL) & 0xBADF0000) == 0xBADF0000) {
        Print(L"fwsec: GSP залочен (0xBADF) — прерываю\n");
        return FALSE;
    }

    /* 2. Патчинг DMEM: сигнатура @0x5A4 + интерфейс FRTS (init_cmd + cmd)
     *
     * ПЕРЕЗАЛИВАЕМ ОБРАЗ ПРЯМО ЗДЕСЬ. Раньше он копировался один раз в
     * efi_main, а между этим местом и повторными попытками буфер успевал
     * оказываться пустым — в логе это видно как bufIMEM0=0x00000001 при
     * blobIMEM0=0xEC547D23. Лишние 59904 байта копирования ничего не
     * стоят, зато образ гарантированно актуален в момент DMA. */
    CopyMem((VOID *)(UINTN)fwsecPhys, fwsec_ga104_bin, FWSEC_SIZE);
    {
        UINT32 ca = crc32_upd(0xFFFFFFFFU, fwsec_ga104_bin, FWSEC_SIZE);
        UINT32 cb = crc32_upd(0xFFFFFFFFU, (const UINT8 *)(UINTN)fwsecPhys,
                              FWSEC_SIZE);
        ulogf(L"FWSEC   image reflashed: CRC32 blob=0x%08x buffer=0x%08x %s\n",
              ca, cb, ca == cb ? L"OK" : L"MISMATCH");
    }

    Print(L"fwsec: патчинг DMEM (sig[%d]@0x5a4, iface@0x1c, FRTS cmd)...\n",
          (INTN)sigIdx);
    CopyMem(dmem + FWSEC_SIG_DMEM_ADDR, sig, FWSEC_SIG_SIZE);
    ulogf(L"FWSEC   sig=%d sig0=%08x%08x... (patched into DMEM@0x5a4)\n",
          (INTN)sigIdx, sig[0] | (sig[1] << 8), sig[2] | (sig[3] << 8));
    {
        /* DMEM_MAPPER_V3: signature@0, version(u16)@4, size(u16)@6,
         * cmd_in_buffer_offset@8, ..., init_cmd@44 (с u16-паддингом!) */
        UINT32 *mapper = (UINT32*)(dmem + 0x560);
        UINT32 cmdInOff = mapper[2];                /* cmd_in_buffer_offset */
        UINT32 *c = (UINT32*)(dmem + cmdInOff);     /* cmd_in буфер @0x7C0 */

        c[0] = 1; c[1] = 24;                        /* readVbiosDesc ver,size */
        c[2] = 0; c[3] = 0;                         /* gfwImageOffset lo,hi */
        c[4] = 0; c[5] = 2;                         /* gfwImageSize, flags=2 */
        c[6] = 1; c[7] = 20;                        /* frtsRegionDesc ver,size */
        c[8] = (UINT32)(FWSEC_FRTS_OFFSET >> 12);   /* frtsRegionOffset4K */
        c[9] = 0x100;                               /* 1MB в 4K-блоках */
        c[10] = 2;                                  /* frtsRegionMediaType=FB */
        mapper[11] = FWSEC_CMD_FRTS;                /* init_cmd @0x58C */
        Print(L"fwsec: mapper init_cmd=0x%x cmd_in_off=0x%x (размер буфера 0x%x)\n",
              mapper[11], cmdInOff, mapper[3]);
    }

    /* 3. kflcnDisableCtxReq (FBIF_CTL ALLOW_PHYS_NO_CTX + DMACTL=0) +
     *    TRANSCFG(0): TARGET=COHERENT_SYSMEM(1) | MEM_TYPE=PHYSICAL(1<<2) */
    data = mmio_read32(GSP_FBIF_CTL);
    data |= (1 << 7);
    mmio_write32(GSP_FBIF_CTL, data);
    mmio_write32(GSP_DMACTL, 0);
    data = mmio_read32(GSP_FBIF_TRANSCFG0);
    data = (data & ~0x7) | 0x5;
    mmio_write32(GSP_FBIF_TRANSCFG0, data);
    Print(L"fwsec: fbifctl=0x%x dmactl=0x%x transcfg0=0x%x dmatrfcmd=0x%x\n",
          mmio_read32(GSP_FBIF_CTL), mmio_read32(GSP_DMACTL),
          mmio_read32(GSP_FBIF_TRANSCFG0), mmio_read32(GSP_DMATRFCMD));

    /* диагностика DMATRF (как v2.21 для SEC2): write+readback */
    mmio_write32(GSP_DMATRFBASE, 0xDEADBEEF);
    Print(L"fwsec: DMATRFBASE write-test = 0x%08x (DEADBEEF = доступен)\n",
          mmio_read32(GSP_DMATRFBASE));
    mmio_write32(GSP_DMATRFBASE, 0);

    /* 4. Загрузка образа в IMEM/DMEM — ровно как в драйвере.
     *
     * РАЗБОР ПРИЧИНЫ (2026-09-28). Эталон — kgspExecuteHsFalcon_GA102
     * (kernel_gsp_falcon_ga102.c:213-272), это единственная реализация
     * FWSEC для GA10x, и на 90HX анлок с ней работает. Разбор desc V3 из
     * GA104.rom (@0x4A408) даёт ровно те поля, которые драйвер и читает:
     *
     *     PKCDataOffset=0x5A4  IMEMPhysBase=0  IMEMLoadSize=0xE200
     *     IMEMVirtBase=0  DMEMPhysBase=0  DMEMLoadSize=0x800
     *     EngineIdMask=0x0400  UcodeId=0x09  SignatureCount=3
     *
     * и dmemVa = FLCN_DMEM_VA_INVALID, то есть SET_DMTAG не ставится.
     * Наши FWSEC_ENGID_MASK/FWSEC_UCORE_ID совпали с desc - здесь всё
     * было правильно.
     *
     * А вот команда DMA была собрана неверно. Поля DMATRFCMD
     * (dev_falcon_v4.h):
     *
     *     SEC = 3:2    IMEM = 4:4    WRITE = 5:5
     *     SIZE = 10:8  CTXDMA = 14:12
     *
     * Стояло:
     *     0 | (6 << 8) | (0 << 12) | (fwsecImemSec << 4) | (1 << 2)
     *
     * То есть переменная, названная «secure», попадала в бит 4 - а это
     * IMEM, а не SEC. При fwsecImemSec=0 в лог уходило:
     *
     *     DMA   imem_sec_bit=0 cmd=0x00000604
     *
     * 0x604 = IMEM:0, SEC:1 - то есть DMA писала в DMEM, а не в IMEM.
     * Код FWSEC в IMEM не попадал НИКОГДА. Отсюда сразу всё наблюдаемое:
     *
     *     imem_ns=0x00000000 MISMATCH   - в IMEM пусто
     *     CMDIN buffer UNCHANGED        - по BOOTVEC=0 нечего выполнять
     *     dbg=0, cpuctl=0x10 (HALTED)   - старт из пустого IMEM
     *     FRTS_ERR_CODE=0               - код не запускался
     *
     * Драйвер (строки 222-247) делает ровно:
     *     IMEM: SIZE=256B, CTXDMA=0, IMEM=1, SEC=1  -> 0x614
     *     DMEM: SIZE=256B, CTXDMA=0, IMEM=0, SEC=0  -> 0x600
     *
     * То есть у DMEM в драйвере SEC=0, а у нас был 1. Ниже - ровно эти
     * значения, без вариантов, флаг fwsecImemSec больше не используется. */
    {
        /* IMEM=1 ВСЕГДА - это и была исправленная ошибка. А SEC теперь
         * берётся из fwsecImemSec, чтобы перебор попыток был осмысленным
         * (см. secOrder в вызывающем коде). */
        const UINT32 DMA_CMD_IMEM = (6u << 8)                    /* SIZE=256B */
                                 | (0u << 12)                   /* CTXDMA=0  */
                                 | (1u << 4)                    /* IMEM=1    */
                                 | ((fwsecImemSec ? 1u : 0u) << 2);
        const UINT32 DMA_CMD_DMEM = (6u << 8)                    /* SIZE=256B */
                                 | (0u << 12)                   /* CTXDMA=0  */
                                 | (0u << 4)                    /* IMEM=0    */
                                 | (0u << 2);                   /* SEC=0     */

        ulogf(L"DMA2  cmd IMEM=0x%08x (IMEM=1 SEC=%d SIZE=256B)  "
              L"cmd DMEM=0x%08x (IMEM=0 SEC=0 SIZE=256B)  "
              L"was=0x%08x (IMEM=0 - the bug)\n",
              DMA_CMD_IMEM, (INTN) fwsecImemSec, DMA_CMD_DMEM,
              (UINT32)((6u << 8) | (0u << 4) | (1u << 2)));

        /* IMEM: dest = IMEMPhysBase = 0, src = образ, размер = IMEMLoadSize */
        gsp_dma_transfer(0, 0, fwsecPhys, FWSEC_CODE_SIZE, DMA_CMD_IMEM);
        /* DMEM: dest = DMEMPhysBase = 0, src = образ + dataOffset, где
         * dataOffset = imemSize (kernel_gsp_fwsec.c:919) = 0xE200. */
        gsp_dma_transfer(0, 0, fwsecPhys + FWSEC_DATA_OFF, FWSEC_DMEM_SIZE,
                         DMA_CMD_DMEM);
        ulogf(L"DMA2  done  imem 0x%x<-phys+0x0  dmem 0x%x<-phys+0x%x\n",
              (UINT32)0, (UINT32)0, (UINT32)FWSEC_DATA_OFF);

        /* Проверка: код действительно в IMEM? Раньше такой проверки не
         * было - и пустой IMEM был неотличим от «DMA не работает». */
        {
            UINT32 stat = falcon_imem_verify(fwsecPhys, FWSEC_CODE_SIZE);
            ulogf(L"IVER   empty=%d matched=%d occupied=%d  %s\n",
                  stat & 0xFF, (stat >> 8) & 0xFF, (stat >> 16) & 0xFF,
                  (stat & 0xFF) ? L"*** IMEM STILL EMPTY - dma did not land ***"
                                : L"*** IMEM OCCUPIED - the IMEM bit fix works ***");
        }
    }

    /* 4b. Верификация: куда лёг код/данные (порты GSP IMEMC/DMEMC)
     *
     * В лог пишем ОБЯЗАТЕЛЬНО: если чтение через порт GSP не совпадёт с
     * тем, что мы записали, значит DMA не сработала и BROM стартует с
     * мусором — тогда 0x780009 не имеет отношения ни к подписи, ни к
     * окружению, а просто к тому, что кода в IMEM нет. Проверено на
     * 70HX: все три подписи (включая нулевую) дают один и тот же
     * 0x780009, то есть падение происходит ДО проверки подписи. */
    {
        UINT32 want0 = *(UINT32*)(UINTN)fwsecPhys;
        UINT32 got_ns, got_sec, got_sec100, got_sig, got_cmd, got_hdr;
        UINT32 *d0 = (UINT32*)(UINTN)(fwsecPhys + FWSEC_DATA_OFF);

        /* Диагностика буфера. Предыдущие логи показывали want=0x00000001,
         * тогда как в блобе IMEM[0]=0xEC547D23 и DMEM[0]=0x00100001, и
         * совпадение было подозрительно одинаковым в двух разных местах.
         * Здесь читаем из константы и из буфера ЯВНО и по отдельности, плюс
         * сам адрес: так за один заход станет ясно, врёт форматтер, не
         * скопировался образ или адрес не тот. */
        ulogf(L"BUF   phys=0x%llx blobIMEM0=0x%08x bufIMEM0=0x%08x "
              L"blobDMEM0=0x%08x bufDMEM0=0x%08x\n",
              fwsecPhys,
              *(UINT32*)(UINTN)fwsec_ga104_bin,
              *(UINT32*)(UINTN)fwsecPhys,
              *(UINT32*)(UINTN)(fwsec_ga104_bin + FWSEC_DATA_OFF),
              *(UINT32*)(UINTN)(fwsecPhys + FWSEC_DATA_OFF));
        ulogf(L"BUF   blobE204=0x%08x bufE204=0x%08x "
              L"blobE5A4=0x%08x bufE5A4=0x%08x\n",
              *(UINT32*)(UINTN)(fwsec_ga104_bin + FWSEC_DATA_OFF + 4),
              *(UINT32*)(UINTN)(fwsecPhys + FWSEC_DATA_OFF + 4),
              *(UINT32*)(UINTN)(fwsec_ga104_bin + FWSEC_DATA_OFF + 0x5A4),
              *(UINT32*)(UINTN)(fwsecPhys + FWSEC_DATA_OFF + 0x5A4));

        mmio_write32(GSP_BASE + 0x180, 0);          /* IMEMC0: addr 0, non-secure */
        got_ns = mmio_read32(GSP_BASE + 0x184);
        mmio_write32(GSP_BASE + 0x180, (1 << 28));  /* IMEMC0: addr 0, SECURE */
        got_sec = mmio_read32(GSP_BASE + 0x184);
        mmio_write32(GSP_BASE + 0x180, 0x100 | (1 << 28));
        got_sec100 = mmio_read32(GSP_BASE + 0x184);

        Print(L"fwsec: GSP IMEM[0x00]=0x%08x (образ: 0x%08x)\n", got_ns, want0);
        Print(L"fwsec: GSP IMEM_S[0x00]=0x%08x (secure view)\n", got_sec);
        Print(L"fwsec: GSP IMEM_S[0x100]=0x%08x\n", got_sec100);

        mmio_write32(GSP_BASE + 0x1C0, FWSEC_SIG_DMEM_ADDR);
        got_sig = mmio_read32(GSP_BASE + 0x1C4);
        Print(L"fwsec: GSP DMEM[0x5a4]=0x%08x (ожидаю 0x%08x — sig[%d])\n",
              got_sig, *(UINT32*)(UINTN)sig, (INTN)sigIdx);
        mmio_write32(GSP_BASE + 0x1C0, 0x7C0);
        got_cmd = mmio_read32(GSP_BASE + 0x1C4);
        Print(L"fwsec: GSP DMEM[0x7c0]=0x%08x (ожидаю 0x00000001 — FRTS readVbiosDesc.ver)\n",
              got_cmd);
        mmio_write32(GSP_BASE + 0x1C0, 0x000);
        got_hdr = mmio_read32(GSP_BASE + 0x1C4);

        ulogf(L"DMA   imem_ns=0x%08x want=0x%08x %s\n", got_ns, want0,
              got_ns == want0 ? L"OK" : L"MISMATCH");
        ulogf(L"DMA   imem_sec=0x%08x %s\n", got_sec,
              got_sec == want0 ? L"OK" : L"MISMATCH");
        ulogf(L"DMA   imem_sec_0x100=0x%08x\n", got_sec100);
        ulogf(L"DMA   dmem_hdr=0x%08x want=0x%08x %s\n", got_hdr, d0[0],
              got_hdr == d0[0] ? L"OK" : L"MISMATCH");
        ulogf(L"DMA   dmem_sig=0x%08x want=0x%08x %s\n", got_sig,
              *(UINT32*)(UINTN)sig, got_sig == *(UINT32*)(UINTN)sig ? L"OK" : L"MISMATCH");
        ulogf(L"DMA   dmem_cmd=0x%08x want=0x00000001 %s\n", got_cmd,
              got_cmd == 1 ? L"OK" : L"MISMATCH");
        ulogf(L"DMA   dmatrfcmd=0x%08x dmatrfbase=0x%08x\n",
              mmio_read32(GSP_DMATRFCMD), mmio_read32(GSP_DMATRFBASE));
    }

    /* v2.40: диагностика порта GSP УБРАНА (v2.37: SEC=0 DMA на IMEM[0x8000]
     * ПЕРЕЗАПИСАЛ часть предзагруженного FWSEC-кода (0..0xE200) — FWSEC
     * перестал исполняться! В GSP IMEM до 0xE400 ничего не писать.) */

    /* v2.42: скан GSP IMEM — что предзагрузил VBIOS за пределами FWSEC
     * (0xE200)? Если там BL/booter-код — можно запустить через BROM params.
     * Читаем оба представления по сетке. */
    {
        static const UINT32 scan_offs[] = {
            0x000, 0x100, 0x1000, 0x4000, 0x8000, 0xC000, 0xE000, 0xE200,
            0xE400, 0xF000, 0x10000, 0x11000, 0x12000, 0x14000, 0x16000,
            0x18000, 0x1A000, 0x1C000, 0x20000, 0x24000, 0x28000, 0x30000,
            0x40000, 0x60000, 0x80000
        };
        UINTN s;
        Print(L"fwsec: GSP IMEM-скан (v2.42):\n");
        for (s = 0; s < sizeof(scan_offs)/sizeof(scan_offs[0]); s++) {
            UINT32 a = scan_offs[s];
            UINT32 vn, vs;
            mmio_write32(GSP_BASE + 0x180, a);
            vn = mmio_read32(GSP_BASE + 0x184);
            mmio_write32(GSP_BASE + 0x180, a | (1 << 28));
            vs = mmio_read32(GSP_BASE + 0x184);
            Print(L"fwsec:   IMEM[0x%05x]=0x%08x IMEM_S=0x%08x%s\n",
                  a, vn, vs,
                  (vn != 0xDEAD5EC1 && vs != 0xDEAD5EC1 && vn != 0) ? L" <<<" : L"");
        }
    }

    /* 5. BROM params (PKC RSA3K) — GSP FALCON2 @0x111000 */
    mmio_write32(GSP_BROM_PARAADDR0, FWSEC_SIG_DMEM_ADDR);
    mmio_write32(GSP_BROM_ENGIDMASK, FWSEC_ENGID_MASK);
    mmio_write32(GSP_BROM_CURR_UCODE_ID, FWSEC_UCORE_ID);
    mmio_write32(GSP_MOD_SEL, 0x1);                    /* RSA3K */
    Print(L"fwsec: BROM: paraaddr=0x%x engmask=0x%x ucodeid=%d modsel=0x1\n",
          FWSEC_SIG_DMEM_ADDR, FWSEC_ENGID_MASK, FWSEC_UCORE_ID);

    /* 6. BOOTVEC = imemVa + STARTCPU.
     *
     * Драйвер (kernel_gsp_falcon_ga102.c:278) пишет не 0, а
     * pUcode->imemVa = IMEMVirtBase из desc. В GA104.rom это 0, так что
     * значение совпадает - но ставить надо именно imemVa, потому что dest
     * DMA равен imemPa, и они обязаны быть согласованы. */
    mmio_write32(GSP_BOOTVEC, 0 /* = FWSEC_IMEM_VIRT_BASE = IMEMVirtBase */);
    __asm__ volatile("wbinvd" ::: "memory");
    mmio_write32(GSP_CPUCTL, NV_PFALCON_FALCON_CPUCTL_STARTCPU_TRUE);
    Print(L"fwsec: STARTCPU (GSP), жду WPR2 до 5с...\n");

    /* параметры запуска и состояние DMA — в лог: по ним видно, что именно
     * BROM получил (и не получил) перед стартом */
    ulogf(L"BROM  paraaddr=0x%x engmask=0x%x ucodeid=%d modsel=0x1 "
          "bootvec=0x0 imemLoad=0x%x dmemLoad=0x%x\n",
          FWSEC_SIG_DMEM_ADDR, FWSEC_ENGID_MASK, FWSEC_UCORE_ID,
          (UINTN)FWSEC_DATA_OFF, (UINTN)FWSEC_DMEM_SIZE);
    ulogf(L"BROM  readback para=0x%08x engmask=0x%08x ucodeid=0x%08x "
          "modsel=0x%08x bootvec=0x%08x\n",
          mmio_read32(GSP_BROM_PARAADDR0), mmio_read32(GSP_BROM_ENGIDMASK),
          mmio_read32(GSP_BROM_CURR_UCODE_ID), mmio_read32(GSP_MOD_SEL),
          mmio_read32(GSP_BOOTVEC));
    ulogf(L"BROM  cpuctl=0x%08x (STARTCPU) dmatrfcmd=0x%08x dmatrfbase=0x%08x "
          "fbifctl=0x%08x dmactl=0x%08x\n",
          mmio_read32(GSP_CPUCTL), mmio_read32(GSP_DMATRFCMD),
          mmio_read32(GSP_DMATRFBASE), mmio_read32(GSP_FBIF_CTL),
          mmio_read32(GSP_DMACTL));

    /* 7. Поллинг WPR2 (FRTS ставит lo=frtsOffset, hi=frtsOffset+0xE00)
     *
     * ВАЖНО (2026-09-28): вердикт пишется В ЛОГ на каждом витке опроса, а
     * не только в конце 5-секундного ожидания. Раньше единственная
     * запись была глубоко внутри Print(), и если после STARTCPU код уходил
     * в следующую стадию (BOOTER) раньше, чем отрабатывал опрос, в логе
     * не оставалось НИ ОДНОЙ строки о результате FWSEC. Так выглядел
     * прогон imemfilled: лог чистый, а вердикта нет - невозможно было
     * понять, выполнялся FWSEC или нет.
     *
     * Печатаем сразу после старта и далее раз в секунду. */
    for (i = 0; i < 5000; i++) {
        UINT32 lo = mmio_read32(REG_PFB_MMU_WPR2_LO);
        UINT32 hi = mmio_read32(REG_PFB_MMU_WPR2_HI);
        if (i == 0)
            ulogf(L"WAIT   t=0ms wpr2=0x%08x/0x%08x cpuctl=0x%08x dbg=0x%08x "
                  L"expect=0x%08x/0x%08x\n",
                  lo, hi, mmio_read32(GSP_CPUCTL),
                  mmio_read32(GSP_BASE + 0x94), TARGET_WPR2_LO, TARGET_WPR2_HI);
        else if ((i % 1000) == 0)
            ulogf(L"WAIT   t=%dms wpr2=0x%08x/0x%08x cpuctl=0x%08x dbg=0x%08x\n",
                  (INTN) i, lo, hi, mmio_read32(GSP_CPUCTL),
                  mmio_read32(GSP_BASE + 0x94));
        if ((lo & 0xFFFFFFF0) == (TARGET_WPR2_LO & 0xFFFFFFF0) &&
            (hi & 0xFFFFFFF0) == (TARGET_WPR2_HI & 0xFFFFFFF0)) {
            ulogf(L"WAIT   *** WPR2 ESTABLISHED lo=0x%08x hi=0x%08x after %d ms ***\n",
                  lo, hi, (INTN) i);
            Print(L"fwsec: *** WPR2 УСТАНОВЛЕН lo=0x%08x hi=0x%08x после %d ms ***\n",
                  lo, hi, i);

            /* --- v3n: ПОДТВЕРЖДЕНИЕ НА ПУТИ УСПЕХА (2026-09-28) --------
             *
             * Раньше все проверки состояния FWSEC жили в ветке ПРОВАЛА
             * (CMDIN / DMAP / PLMM / SCR). На успехе их не было вовсе, и
             * первый же успешный прогон вышел с единственным доказательством
             * «WPR2 стал равен ожидаемому» - без FRTS_ERR_CODE, без
             * privLevelMask, без следа от того, что вообще делал маппер.
             *
             * Три проверки, которые драйвер делает после FWSEC
             * (kernel_gsp_frts_tu102.c:489-525), повторяем здесь явно:
             *   1) FRTS_ERR_CODE == NONE
             *   2) wpr2HiVal != 0
             *   3) wpr2LoVal == frtsOffset >> 8
             *
             * Плюс privLevelMask: без его нуля значение WPR2 может быть
             * прикрытым, и «успех» окажется ложным.
             * И CMDIN: если буфер команды изменён - маппер команду выполнил. */
            {
                UINT32 scr, plm, cinOff, cin0, plmHi, dmHdr;
                scr = mmio_read32(NV_PBUS_VBIOS_SCRATCH + FWSECLIC_SCRATCH_FRTSE * 4);
                plm = mmio_read32(REG_PFB_MMU_WPR2_PLM);
                plmHi = mmio_read32(REG_PFB_MMU_WPR2_PLM + 4);
                /* v3n: 0x568 бралось как смещение cmd_in_buffer_offset, но
                 * поле лежит в DMAP по +0x08, то есть 0x560+8 = 0x568 - и
                 * это верно. Ошибка была в интерпретации прочитанного:
                 * в первом прогоне OKCHK напечатал
                 *     cmdIn[0]=0xDEAD5EC2 at dmem+0xDEAD5EC2
                 * то есть подставил ЗНАЧЕНИЕ ПРОЧИТАННОГО СЛОВА в поле
                 * смещения, а не наоборот. Теперь печатаем оба числа
                 * раздельно и сверяем с ожидаемым 0x7C0, плюс читаем
                 * dmem[0] - если и он 0xDEAD5EC2, то это отказ порта
                 * DMEMC/DMEMD, а не содержимое буфера команды. */
                mmio_write32(GSP_BASE + 0x1C0, 0x560);
                dmHdr  = mmio_read32(GSP_BASE + 0x1C4);   /* DMAP magic */
                mmio_write32(GSP_BASE + 0x1C0, 0x568);
                cinOff = mmio_read32(GSP_BASE + 0x1C4);   /* cmd_in_buffer_offset */
                mmio_write32(GSP_BASE + 0x1C0, 0x000);
                cin0   = mmio_read32(GSP_BASE + 0x1C4);   /* dmem[0] = header */

                ulogf(L"OKCHK  frtsErrCode=0x%08x (want 0x00000000) %s\n", scr,
                      ((scr >> 16) & 0xFFFF) == 0 ? L"NONE" : L"NON-ZERO");
                ulogf(L"OKCHK  wpr2Hi=0x%08x (driver needs != 0) %s\n", hi,
                      hi ? L"OK" : L"FAIL");
                ulogf(L"OKCHK  wpr2Lo=0x%08x expected=0x%08x %s\n", lo,
                      TARGET_WPR2_LO, lo == TARGET_WPR2_LO ? L"OK" : L"FAIL");
                ulogf(L"OKCHK  privLevelMask=0x%08x/0x%08x %s\n", plm, plmHi,
                      (plm == 0 && plmHi == 0)
                          ? L"OPEN - wpr2 read is trustworthy"
                          : L"*** STILL MASKED - see FBP mask note ***");
                ulogf(L"OKCHK  dmem[0]=0x%08x dmem[0x560]=0x%08x (DMAP) %s\n",
                      cin0, dmHdr,
                      (dmHdr == 0x50414D44U) ? L"intact"
                                             : L"*** DMAP damaged/refused ***");
                ulogf(L"OKCHK  cmdInBufferOffset(dmem[0x568])=0x%08x (want 0x7C0) %s\n",
                      cinOff, cinOff == 0x7C0 ? L"OK" : L"UNEXPECTED");
                ulogf(L"OKCHK  dbg=0x%08x cpuctl=0x%08x (dbg not checked by driver)\n",
                      mmio_read32(GSP_BASE + 0x94), mmio_read32(GSP_CPUCTL));
                ulogf(L"OKCHK  NOTE: if dmem[0]=0xDEAD5EC2 the DMEM read port "
                      L"itself is refused; dmem values above are not data.\n");
            }

            /* v2.43: ПЕРЕБОР команд FWSEC (0x10..0x1F) — ищем команду записи
             * регистров (PLM!). Для каждой: патч init_cmd + re-DMA + STARTCPU
             * + 200мс poll → сравниваем PLM/privmask/WPR2 до/после. */
            /* v3.16: конец фазы reset+STARTCPU, дальше идут диагностические
             * эксперименты (помечены как вложенные — в верхний итог не входят).
             *
             * v3.21: ЗДЕСЬ БЫЛ МОЙ БАГ, ВНЕСЁННЫЙ В ЭТАПЕ 5.
             *
             * В v3.20 я снёс fx_ph_begin() в начале fwsec_boot_gsp_sig,
             * потому что он не закрывался и копил перекос. Снёс правильно по
             * сути, но НЕ поставил замену: fx_ph здесь не инициализирован
             * никогда - ни в декларации, ни выше по функции. То есть в
             * 'fwsec: reset+STARTCPU' попадало значение из мусора на стеке.
             *
             * Чем это опасно именно здесь, а не где угодно: функция зовётся
             * 9 раз, и при мусорной метке фаза могла получить правдоподобное
             * число. То есть плохо выглядящего значения не было - было
             * неправильное. Заметить это по логу было нечем.
             *
             * Ставлю явный штамп в начале функции. Он честный: отсчёт
             * ведётся от входа в fwsec_boot_gsp_sig, то есть ровно то, что
             * интересует. */
            fx_mk_acc(fx_ph, L"fwsec: reset+STARTCPU");
            fx_ph = fx_now_us();
/* ==== v2.43 + v2.45: ДИАГНОСТИЧЕСКИЕ ЭКСПЕРИМЕНТЫ =================
             *
             * Что здесь стоит. Оба блока — чистая диагностика, и оба
             * лежат ВНУТРИ ветки «WPR2 ESTABLISHED», то есть выполняются
             * на УЖЕ УСПЕШНОМ пути, после того как разблокировка уже
             * состоялась. Они отвечают на два вопроса, ответы на которые
             * зафиксированы в комментариях и в PLAN-SPEED.md (часть II, ретроспектива v3.16):
             *   v2.43 — какая команда FWSEC пишет регистры (PLM);
             *   v2.45 — работает ли SEC=1 DMA на GSP (не работает; вместо
             *            нашего кода исполняется предзагруженный VBIOS).
             * Ни один из них не влияет на то, открылись маски или нет.
             *
             * Сколько это стоило. Фазовый учёт прогона 2026-10-02 дал:
             *     fwsec: v2.43 cmd scan   6,11 с  x24
             *     fwsec: v2.45 SEC=1 discr 17,57 с x24
             *     итого 23,7 с из 113 с прогона, то есть 21 % времени
             *     на диагностику, которая повторяет один и тот же опыт
             *     24 раза подряд. Ответ не меняется от повтора: он
             *     зависит от железа, а не от номера маски.
             *
             * ЧТО СДЕЛАНО. Эксперименты выполняются на ПЕРВОМ успешном
             * вызове, дальше пропускаются, а в лог пишется строка со
             * счётчиком — так же, как устроен fx_repeat_gate. Данные
             * эксперимента не теряются: первый прогон по-прежнему даёт
             * полный перебор 0x10..0x1F и полную дискриминацию, то есть
             * ровно те данные, ради которых блоки существуют.
             *
             * ПОЧЕМУ ЭТО НЕ «ПРОСТО УДАЛИТЬ». Ответ на вопрос «работает ли
             * SEC=1 на GSP» однажды может стать «да» — например, после
             * другой правки. Если бы блок был удалён, мы бы об этом не
             * узнали, потому что узнавать было бы нечем. Один прогон с
             * полными данными — это ровно то, ради чего оставлять.
             *
             * Вернуть прежнее поведение (полный эксперимент на каждом
             * вызове): FX_DIAG_EVERY = 1.
             */
            fx_ph = fx_now_us();   /* v2.43 + v2.45, обе под воротами */
            /* v3.33, ЭТАП 16: за fx_diagV245, по умолчанию 0 - снимает 705 мс.
             *
             * Комментарий выше говорит, что оба блока лежат ВНУТРИ ветки
             * «WPR2 ESTABLISHED», то есть выполняются на уже успешном пути,
             * после того как разблокировка состоялась, и ни один из них не
             * влияет на то, открылись маски или нет. Это ровно то свойство,
             * ради которого блок можно вынести из рабочего прогона.
             *
             * Измеренная цена в v3.30 - 705 мс из 18 084 (3,9%). Старый
             * fx_diag_gate() отдавал первый вызов из каждых 24, и в v3.30 он
             * сработал. Платить 3,9% прогона за диагностику, которую мы уже
             * забрали, незачем.
             *
             * Чтобы включить обратно для нового эксперимента: fx_diagV245 = 1
             * в объявлении рядом с fx_rmDirect/fx_rmNeedBooter. */
            if (fx_diagV245 && fx_diag_gate())
            {
            {   /* блок v2.43 в собственной области */
                UINT8 *dmem2 = (UINT8*)(UINTN)(fwsecPhys + FWSEC_DATA_OFF);
                UINT32 cmd;
                Print(L"fwsec: v2.43 перебор команд 0x10..0x1F:\n");
                Print(L"fwsec: v2.43 перебор команд 0x10..0x1F:\n");
                for (cmd = 0x10; cmd <= 0x1F; cmd++) {
                    UINT32 *mapper2 = (UINT32*)(dmem2 + 0x560);
                    UINT32 cmdInOff2 = mapper2[2];
                    UINT32 *c2 = (UINT32*)(dmem2 + cmdInOff2);
                    UINT32 plm0, priv0, wpr0;
                    UINT32 plmA, privA, wprA;

                    c2[0] = 1; c2[1] = 24;             /* readVbiosDesc */
                    c2[2] = 0; c2[3] = 0;
                    c2[4] = 0; c2[5] = 2;
                    mapper2[11] = cmd;
                    gsp_dma_transfer(0, 0, fwsecPhys + FWSEC_DATA_OFF,
                                     FWSEC_DMEM_SIZE,
                                     0 | (6 << 8) | (0 << 12));
                    plm0 = mmio_read32(REG_FEAT_OVR_PLM);
                    priv0 = mmio_read32(0x00118128);
                    wpr0 = mmio_read32(REG_PFB_MMU_WPR2_LO);
                    mmio_write32(GSP_BOOTVEC, 0);
                    __asm__ volatile("wbinvd" ::: "memory");
                    mmio_write32(GSP_CPUCTL,
                                 NV_PFALCON_FALCON_CPUCTL_STARTCPU_TRUE);
    /* v3.16: было слепое Stall(200000) на КАЖДУЮ из 16 команд, а
     * fwsec_boot_gsp_sig зовётся 24 раза -> 16 x 200 мс x 24 = 77 с.
     * Теперь ждём HALT с тем же потолком 200 мс.
     *
     * ИМЕННО ЗДЕСЬ в первой версии v3.16 всё сломалось. Примитив из
     * шага 3 тут применим, потому что дальше ЧИТАЕТСЯ результат работы
     * (PLM/priv/WPR2 до и после). Но порядок обязателен: сначала
     * защёлка старта (CPUCTL == STARTCPU), потом завершение. Запись
     * CPUCTL posted, и ожидание одного лишь «CPUCTL != STARTCPU»
     * выходит через 0-2 мкс вместо 200 мс — это и уронило
     * разблокировку на 2026-10-02 (WPR2 8 раз вместо 24, dbg=0x007E0009,
     * маски 5 из 25 вместо 24). */
    fx_wait_falcon_halt(GSP_CPUCTL, 200000, L"v2.43 cmd scan");
                    plmA = mmio_read32(REG_FEAT_OVR_PLM);
                    privA = mmio_read32(0x00118128);
                    wprA = mmio_read32(REG_PFB_MMU_WPR2_LO);
                    Print(L"fwsec:   cmd=0x%02x: PLM=0x%08x priv=0x%08x "
                          L"wpr2lo=0x%08x gsp=0x%x dbg=0x%x%s\n",
                          cmd, plmA, privA, wprA,
                          mmio_read32(GSP_CPUCTL),
                          mmio_read32(GSP_BASE + 0x94),
                          (plmA != plm0 || privA != priv0 || wprA != wpr0)
                              ? L" <<< ИЗМЕНЕНИЕ" : L"");
                    if (plmA == VAL_PLM_OPEN) {
                        Print(L"fwsec:   *** cmd=0x%02x ОТКРЫЛ PLM! ***\n", cmd);
                        break;
                    }
                }
                wpr2_probe(L"after-0x10..0x1F-scan");
            }

            /* v2.45: ДИСКРИМИНАЦИЯ SEC=1 на GSP — загружаем МОДИФИЦИРОВАННЫЙ
             * FWSEC (frtsOffset=0x10000000 вместо профильного) + sig[2] +
             * BROM params. Если SEC=1 DMA работает — BROM выполнит НАШ код →
             * WPR2 станет lo=0x00100000. Если нет — предзагруженный код
             * выполнится со стандартным offset → WPR2 останется прежним. */
            {
                UINT8 *buf = (UINT8*)(UINTN)fwsecPhys;   /* переиспользуем */
                UINT32 *mapper2 = (UINT32*)(buf + FWSEC_DATA_OFF + 0x560);
                UINT32 cmdInOff2 = mapper2[2];
                UINT32 *c2 = (UINT32*)(buf + cmdInOff2);
                UINTN p;

                CopyMem(buf, fwsec_ga104_bin, FWSEC_SIZE);
                CopyMem(buf + FWSEC_DATA_OFF + FWSEC_SIG_DMEM_ADDR,
                        fwsec_ga104_sig, FWSEC_SIG_SIZE);
                c2[0] = 1; c2[1] = 24;
                c2[2] = 0; c2[3] = 0;
                c2[4] = 0; c2[5] = 2;
                c2[6] = 1; c2[7] = 20;
                c2[8] = 0x10000;                       /* frtsOffset 0x10000000>>12 */
                c2[9] = 0x100;
                c2[10] = 2;
                mapper2[11] = 0x15;

                Print(L"fwsec: v2.45 модиф. FWSEC (frts=0x10000000)...\n");
                gsp_dma_transfer(0, 0, fwsecPhys, FWSEC_CODE_SIZE,
                                 0 | (6 << 8) | (0 << 12) | (1 << 4) | (1 << 2));
                gsp_dma_transfer(0, 0, fwsecPhys + FWSEC_DATA_OFF,
                                 FWSEC_DMEM_SIZE,
                                 0 | (6 << 8) | (0 << 12));
                mmio_write32(GSP_BROM_PARAADDR0, FWSEC_SIG_DMEM_ADDR);
                mmio_write32(GSP_BROM_ENGIDMASK, FWSEC_ENGID_MASK);
                mmio_write32(GSP_BROM_CURR_UCODE_ID, FWSEC_UCORE_ID);
                mmio_write32(GSP_MOD_SEL, 0x1);
                mmio_write32(GSP_BOOTVEC, 0);
                __asm__ volatile("wbinvd" ::: "memory");
                mmio_write32(GSP_CPUCTL,
                             NV_PFALCON_FALCON_CPUCTL_STARTCPU_TRUE);
                Print(L"fwsec:   жду WPR2 (модиф. код → lo=0x100000):\n");
for (p = 0; p < 2000; p++) {
                UINT32 lo = mmio_read32(REG_PFB_MMU_WPR2_LO);
                UINT32 hi = mmio_read32(REG_PFB_MMU_WPR2_HI);
                if ((lo & 0xFFFFFFF0) == 0x00100000) {
                    Print(L"fwsec:   *** WPR2=0x%08x%08x — НАШ модиф. код "
                          L"выполнился (SEC=1 на GSP РАБОТАЕТ!) ***\n",
                          hi, lo);
                    ulogf(L"V245   *** WPR2=0x%08x%08x — наш код выполнился, "
                          L"SEC=1 на GSP РАБОТАЕТ, на %d-й итерации ***\n",
                          hi, lo, (INTN)p);
                    break;
                }
                /* v3.16: ранний выход по закрытому вопросу.
                 *
                 * Полные первые 500 итераций (500 мс) — это БОЛЬШЕ, чем
                 * прежние первые 200 мс, то есть ответ не берётся раньше,
                 * чем раньше. Дальше выход по двум условиям, каждое из
                 * которых закрывает вопрос:
                 *   • WPR2 == 0x00100000 — код выполнился, ответ «да»
                 *     (обрабатывается выше);
                 *   • Falcon дошёл до HALT и WPR2 за это время не изменился
                 *     — код отработал и ответ «нет», дальше меняться нечему.
                 *
                 * Если HALT по какой-то причине не наступит, цикл всё равно
                 * завершится по 2000 итерациям, как и раньше. Потолок по
                 * времени НЕ ставится сознательно: Stall(1000) уже даёт
                 * границу, а лишний потолок означал бы второе, ни о чём не
                 * говорящее ограничение.
                 */
                if (p >= 500) {
                    UINT32 cc = mmio_read32(GSP_CPUCTL);
                    if (cc != NV_PFALCON_FALCON_CPUCTL_STARTCPU_TRUE &&
                        mmio_read32(REG_PFB_MMU_WPR2_LO) == lo) {
                        Print(L"fwsec:   v2.45: Falcon в HALT (cpuctl=0x%08x) "
                              L"и WPR2 не изменился — наш код не выполнился "
                              L"(SEC=1 на GSP не проходит), ждать дальше "
                              L"нечего, выход на %d-й итерации\n", (INTN)cc,
                              (INTN)p);
                        ulogf(L"V245   Falcon в HALT (cpuctl=0x%08x) и WPR2 "
                              L"не изменился — SEC=1 на GSP НЕ проходит, "
                              L"выход на итерации %d из 2000\n",
                              (INTN)cc, (INTN)p);
                        break;
                    }
                }
                if ((p % 200) == 0)
                    Print(L"fwsec:   t=%dms wpr2lo=0x%08x wpr2hi=0x%08x "
                          L"gsp=0x%x dbg=0x%x\n",
                          p, lo, hi, mmio_read32(GSP_CPUCTL),
                          mmio_read32(GSP_BASE + 0x94));
                uefi_call_wrapper(BS->Stall, 1, 1000);
            }
            ulogf(L"V245   итог: p=%d итераций, wpr2lo=0x%08x\n", (INTN)p,
                  mmio_read32(REG_PFB_MMU_WPR2_LO));
            Print(L"fwsec:   итог: wpr2lo=0x%08x hi=0x%08x "
                  L"(ожидаем 0x%08X = предзагруженный код, SEC=1 не работает; "
                  L"0x100000 = НАШ код!)\n",
                  mmio_read32(REG_PFB_MMU_WPR2_LO),
                  mmio_read32(REG_PFB_MMU_WPR2_HI),
                  TARGET_WPR2_LO);
            fx_mk_acc(fx_ph, L"fwsec: v2.43+v2.45 diagnostics");
            }   /* конец if (fx_diag_gate()) — блоки v2.43 + v2.45 */
            }
            /* v3n: здесь функция возвращает TRUE («успех»), НЕ проверяя, что
             * сделали с WPR2 перебор команд 0x10..0x1F и модифицированный
             * FWSEC выше. Оба блока перезапускают FWSEC через STARTCPU, то
             * есть FWSEC исполняется заново и может перещёлкивать WPR2.
             * Замер: OKCHK печатал 0x01F7E000, а в блоке селекторов было
             * 0x01EAD000 — и между этими точками больше ничего не пишет
             * WPR2, кроме этих блоков. */
            wpr2_probe(L"before-return-TRUE");
            return TRUE;
        }
        if ((i % 200) == 0)
            Print(L"fwsec:   t=%dms wpr2lo=0x%08x wpr2hi=0x%08x gspcpuctl=0x%x dbg=0x%x scratch0e=0x%x\n",
                  i, lo, hi, mmio_read32(GSP_CPUCTL),
                  mmio_read32(GSP_BASE + 0x94), mmio_read32(0x001438));
        uefi_call_wrapper(BS->Stall, 1, 1000);
    }
    Print(L"fwsec: WPR2 НЕ установлен: lo=0x%08x hi=0x%08x gspcpuctl=0x%x dbg=0x%x scratch0e=0x%x\n",
          mmio_read32(REG_PFB_MMU_WPR2_LO), mmio_read32(REG_PFB_MMU_WPR2_HI),
          mmio_read32(GSP_CPUCTL), mmio_read32(GSP_BASE + 0x94),
          mmio_read32(0x001438));
    ulogf(L"FWSEC ours FAIL wpr2=0x%08x/0x%08x cpuctl=0x%08x dbg=0x%08x "
         "scratch0e=0x%08x imem_ours=0x%08x\n",
         mmio_read32(REG_PFB_MMU_WPR2_LO), mmio_read32(REG_PFB_MMU_WPR2_HI),
         mmio_read32(GSP_CPUCTL), mmio_read32(GSP_BASE + 0x94),
         mmio_read32(0x001438),
         g_fwsecPhys ? *(UINT32*)(UINTN)g_fwsecPhys : 0);

    /* --- v3n: ЧТО ИМЕННО FWSEC СДЕЛАЛ (2026-09-28) -----------------------
     *
     * До этого прогона ответ был неоднозначен: dbg=0 и scratch0e=0
     * (FRTS_ERR_CODE=0, то есть FWSEC СЧИТАЕТ, что отработал нормально),
     * при этом WPR2 побайтово не менялся НИ РАЗУ — ни при frts=0x1FFE00000,
     * ни при 0x1F7E00000. Два объяснения неразличимы по имеющимся данным:
     *
     *   (а) FWSEC исполнился, но записал результат не туда, куда мы смотрим;
     *   (б) FWSEC вообще не исполнился, а dbg=0 — это его состояние ПОСЛЕ
     *       старта без выполнения команды.
     *
     * Различить можно по состоянию DMEM, и раньше это было невозможно:
     * дамп ниже обрезается на 110 словах (смещение 0x1C4), а интересующее
     * лежит дальше — DMAP на 0x560 и буфер команды на 0x7C0. То есть самый
     * важный свидетель просто никогда не печатался.
     *
     * Печатаем (все значения читаются тем же окном 0x1101C0/0x1101C4,
     * которое уже подтверждено рабочим на dmem[0x5A4] и dmem[0x7C0]):
     *   DMAP   — не тронут ли init_cmd? не сбросил ли FWSEC структуру;
     *   cmd_in — ПРОЧИТАЛ ли FWSEC буфер (это главный признак: непустой
     *           readVbiosDesc.version после прогона = команда не исполнена);
     *   cmd_out— куда FWSEC пишет результат (драйвер его не читает);
     *   scratch— полный веер NV_PBUS_VBIOS_SCRATCH 0x0C..0x17;
     *   plmmask— чем на самом деле прикрыты регистры WPR2. */
    {
        UINT32 sig, versz, cinOff, cinSize, coutOff, coutSize;
        UINT32 initCmd, feat, mask0, mask1;
        UINT32 c0, c1, c6, c8, c10, out0, out1;
        UINT32 lo2, hi2, plm;
        UINTN  s;

        mmio_write32(GSP_BASE + 0x1C0, 0x560);
        sig    = mmio_read32(GSP_BASE + 0x1C4);
        mmio_write32(GSP_BASE + 0x1C0, 0x564);
        versz  = mmio_read32(GSP_BASE + 0x1C4);
        mmio_write32(GSP_BASE + 0x1C0, 0x568);
        cinOff = mmio_read32(GSP_BASE + 0x1C4);
        mmio_write32(GSP_BASE + 0x1C0, 0x56C);
        cinSize= mmio_read32(GSP_BASE + 0x1C4);
        mmio_write32(GSP_BASE + 0x1C0, 0x570);
        coutOff= mmio_read32(GSP_BASE + 0x1C4);
        mmio_write32(GSP_BASE + 0x1C0, 0x574);
        coutSize= mmio_read32(GSP_BASE + 0x1C4);
        mmio_write32(GSP_BASE + 0x1C0, 0x580);
        feat   = mmio_read32(GSP_BASE + 0x1C4);
        mmio_write32(GSP_BASE + 0x1C0, 0x58C);
        initCmd= mmio_read32(GSP_BASE + 0x1C4);
        mmio_write32(GSP_BASE + 0x1C0, 0x590);
        mask0  = mmio_read32(GSP_BASE + 0x1C4);
        mmio_write32(GSP_BASE + 0x1C0, 0x594);
        mask1  = mmio_read32(GSP_BASE + 0x1C4);

        ulogf(L"DMAP   sig=0x%08x versz=0x%08x cmdIn=0x%x/0x%x "
             L"cmdOut=0x%x/0x%x feat=0x%08x initCmd=0x%08x mask=0x%08x/0x%08x\n",
             sig, versz, cinOff, cinSize, coutOff, coutSize,
             feat, initCmd, mask0, mask1);
        ulogf(L"DMAP   %s\n",
             (sig == 0x50414D44U) ? L"struct intact (still 'DMAP')"
                                  : L"*** structure CORRUPTED - fwsec reset it");

        /* Буфер команды: c[0]=readVbiosDesc.version, c[6]=frtsRegionDesc
         * .version, c[8]=frtsRegionOffset4K. Если FWSEC исполнил команду,
         * буфер должен быть изменён или обнулён. */
        mmio_write32(GSP_BASE + 0x1C0, cinOff);      c0  = mmio_read32(GSP_BASE + 0x1C4);
        mmio_write32(GSP_BASE + 0x1C0, cinOff + 4);  c1  = mmio_read32(GSP_BASE + 0x1C4);
        mmio_write32(GSP_BASE + 0x1C0, cinOff + 24); c6  = mmio_read32(GSP_BASE + 0x1C4);
        mmio_write32(GSP_BASE + 0x1C0, cinOff + 32); c8  = mmio_read32(GSP_BASE + 0x1C4);
        mmio_write32(GSP_BASE + 0x1C0, cinOff + 40); c10 = mmio_read32(GSP_BASE + 0x1C4);
        ulogf(L"CMDIN  off=0x%x  readVbiosDesc(ver,size)=0x%08x/0x%08x  "
             L"frtsDesc(ver)=0x%08x  offset4K=0x%08x  mediaType=0x%08x\n",
             cinOff, c0, c1, c6, c8, c10);
        ulogf(L"CMDIN  %s\n",
             (c0 == 0)
               ? L"buffer ZEROED -> fwsec CONSUMED the command"
               : L"*** buffer UNCHANGED -> fwsec did NOT execute the command");

        if (coutOff && coutSize && (coutOff + coutSize) <= FWSEC_DMEM_SIZE) {
            mmio_write32(GSP_BASE + 0x1C0, coutOff);
            out0 = mmio_read32(GSP_BASE + 0x1C4);
            mmio_write32(GSP_BASE + 0x1C0, coutOff + 4);
            out1 = mmio_read32(GSP_BASE + 0x1C4);
            ulogf(L"CMDOUT off=0x%x size=0x%x  [0]=0x%08x [4]=0x%08x %s\n",
                  coutOff, coutSize, out0, out1,
                  (out0 || out1) ? L"(fwsec wrote something here)"
                                 : L"(empty)");
        } else {
            ulogf(L"CMDOUT unusable off=0x%x size=0x%x\n", coutOff, coutSize);
        }

        /* NV_PBUS_VBIOS_SCRATCH(i) = 0x1400 + i*4. Драйвер читает 0x0E
         * (FRTS_ERR_CODE 31:16) и 0x15 (SB_ERR_CODE 15:0). Печатаем веер,
         * потому что FWSEC мог писать и в соседние. */
        for (s = 0x0C; s <= 0x17; s++) {
            UINT32 v = mmio_read32(NV_PBUS_VBIOS_SCRATCH + s * 4);
            if (v == 0) continue;
            ulogf(L"SCR    [0x%02x] = 0x%08x\n", (INTN) s, v);
        }

        /* Чем прикрыты регистры WPR2: если маска непустая, то чтение
         * отдаёт запись-по-умолчанию, а не то, что записал FWSEC. */
        lo2  = mmio_read32(REG_PFB_MMU_WPR2_LO);
        hi2  = mmio_read32(REG_PFB_MMU_WPR2_HI);
        plm  = mmio_read32(REG_PFB_MMU_WPR2_PLM);
        ulogf(L"PLMM   wpr2_lo=0x%08x wpr2_hi=0x%08x privLevelMask=0x%08x "
             L"expect_lo=0x%08x\n",
             lo2, hi2, plm, TARGET_WPR2_LO);
        ulogf(L"PLMM   %s\n",
             (lo2 == TARGET_WPR2_LO) ? L"*** wpr2_lo == expected - FRTS SUCCEEDED ***"
             : (plm != 0)         ? L"wpr2 reads are priv-masked - value unreliable"
                                   : L"wpr2_lo is a plain read, genuinely not set");
    }

    /* v3n: ДАМП DMEM ПОСЛЕ ПРОГОНА. dbg=0x00000000 означает, что FWSEC не
     * сообщил об ошибке, но WPR2 не защёлкнулся. Значит вопрос не «падает
     * ли он», а «где именно остановился». Печатаем все НЕнулевые слова
     * DMEM: там видно, что он успел записать (статус, счётчики, ответ на
     * FRTS-команду) и что осталось нетронутым. */
    {
        UINT32 off, shown = 0;
        ulogf(L"FWSEC   DMEM dump after run (all non-zero):\n");
        for (off = 0; off < FWSEC_DMEM_SIZE; off += 4) {
            UINT32 v;
            mmio_write32(GSP_BASE + 0x1C0, off);   /* тот же порт, что и в проверке dmem_* */
            v = mmio_read32(GSP_BASE + 0x1C4);
            if (v == 0) continue;
            if (shown >= 110) {                  /* лог не должен упираться в 1 МБ */
                if (shown == 110)
                    ulogf(L"FWSEC   ... (dump truncated at 110 lines)\n");
                shown++;
                continue;
            }
            ulogf(L"FWSEC   dmem[0x%03x]=0x%08x\n", off, v);
            shown++;
        }
        ulogf(L"FWSEC   end of DMEM dump (non-empty words: %d)\n", (INTN)shown);
    }

    /* Проба доступа к кадровому буферу уехала на fb_access_probe(): там
     * есть контроли и она гоняется на чистом GSP до основного флоу, а не
     * на грязном состоянии после этого прогона. */
    return FALSE;
}

/* ==== THE EXPLOIT PRIMITIVE: SEC2 booter load with V67 signature ====
 * Full driver-equivalent sequence: pre-reset-wait -> ENGINE reset ->
 * scrub wait -> switch core to Falcon (BCR) -> FBIF/DMA setup -> DMA
 * IMEM(SEC=1)+DMEM -> PKC/BROM params (RSA3K) -> BOOTVEC/mailboxes
 * (WPR meta phys addr, <4GB copy!) -> STARTCPU. Returns EFI_SUCCESS the
 * moment PLM reads back open; on failure dumps DMEM/IMEM and the
 * RISC-V trace ring (last executed PCs) to serial. */
/* v2.64: WPR meta копия ниже 4ГБ (единая для ВСЕХ mailbox-сайтов).
 * Ботер/LibosBootArgs читают mailbox0 как 32-битный адрес; meta на >4ГБ
 * даёт мусор (exit 0x91). Копия СВЕЖАЯ при каждом вызове (контент мог
 * обновиться между стадиями). */
static UINT64 cmp90_metaLowPhys = 0;
static UINT64
cmp90_meta_low(UINT64 wprMetaPhys)
{
    if (cmp90_metaLowPhys == 0) {
        if (EFI_ERROR(alloc_below_4g(1, &cmp90_metaLowPhys))) {
            Print(L"meta-low: alloc FAIL — использую оригинал\n");
            return wprMetaPhys;
        }
    }
    CopyMem((VOID*)(UINTN)cmp90_metaLowPhys,
            (VOID*)(UINTN)wprMetaPhys, WPR_META_SIZE);
    __asm__ volatile("wbinvd" ::: "memory");
    {
        /* v2.64: верификация контента — magic + heap + sig + flags */
        UINT64 *m = (UINT64*)(UINTN)cmp90_metaLowPhys;
        /* поля: [9]=sigAddr [10]=sigSize [15]=heapOff [16]=heapSize
         * [17]=gspFwOffset [19]=frtsOff [20]=frtsSize; flags @байт 0xB4 */
        /* v3.52: подробная строка - ОДИН раз, при первой удачной проверке.
         * Сама проверка выполняется на КАЖДОМ вызове (функция зовётся 16 раз
         * за прогон), но 32 одинаковые строки ничего не добавляли и раздували
         * дамп кольца. При любой неудаче строка печатается ВСЕГДА: молчание
         * здесь опаснее повтора. */
        if ((m[0] == 0xDC3AAE21371A60B3ULL) && !g_metaLowPrinted) {
            g_metaLowPrinted = TRUE;
            Print(L"meta-low @0x%lx: magic ok=1 sig@0x%llx sz=0x%llx "
                  L"heapOff=0x%llx heapSz=0x%llx fwOff=0x%llx flags=0x%x\n",
                  cmp90_metaLowPhys, m[9], m[10], m[15], m[16], m[17],
                  *(UINT32*)((UINT8*)cmp90_metaLowPhys + 0xB4));
        } else if (m[0] != 0xDC3AAE21371A60B3ULL) {
            Print(L"meta-low @0x%lx: *** MAGIC BAD *** got 0x%016llx "
                  L"want 0xDC3AAE21371A60B3\n",
                  cmp90_metaLowPhys, m[0]);
        }
        /* v3.51: верхняя граница окна, которое поставит GSP. Раньше в логе не
         * было НИ ОДНОЙ строки о том, каким должно быть WPR2_LO, и именно
         * поэтому чтение 0x01EAD000 вместо 0x01F7E000 шесть дней выглядело
         * аномалией, а не следствием нашей же формулы.
         *
         * v3.52: отсюда строка УБРАНА и печатается в build_wpr_meta(), где
         * значение вычисляется. Здесь функция зовётся 16 раз за прогон. */
    }
    return cmp90_metaLowPhys;
}

/* ==================== v2.69: поллинг mbox0 ВО ВРЕМЯ исполнения ботера =====
 * Пост-halt скраб (v2.67) уничтожает IMEM/DMEM, а промежуточные коды mbox0
 * перезаписываются финальным 0x91 ещё ДО halt. Единственное окно — опрос
 * регистров в реальном времени: история изменений пишется в RAM хоста
 * (скраб туда не достаёт) с PTIMER-таймштампами. */
typedef struct {
    UINT32 t_lo, t_hi;              /* PTIMER (нс) в момент изменения */
    UINT32 cpuctl, irqstat, dbg;
    UINT32 mbox0, mbox1;
    /* v2.72: расширенный срез состояния во время исполнения ботера */
    UINT32 wpr2lo, dmatrfcmd, gspmbox0;
    UINT32 dFF4c, dFF50, d10;       /* DMEM: canary 0xff4c/0xff50 (sec) + [0x10] ns */
} CMP90_MBOX_ENT;
#define CMP90_MBOX_HIST_MAX 4096

static UINT64 cmp90_ptimer64(void)
{
    /* чтение TIME_1 защёлкивает TIME_0 — порядок как в драйвере NV.
     * v3n: читаем ДВАЖДЫ до совпадения. Одиночное чтение во время FLR-циклов
     * gen2 давало мусор (t=16658495639518мс) — TIME_0 обновляется между
     * двумя чтениями. Повтор с проверкой стабильности это лечит. */
    UINT32 hi, lo, hi2, lo2;
    hi  = mmio_read32(NV_PTIMER_TIME_1);
    lo  = mmio_read32(NV_PTIMER_TIME_0);
    hi2 = mmio_read32(NV_PTIMER_TIME_1);
    lo2 = mmio_read32(NV_PTIMER_TIME_0);
    if (hi != hi2) return ((UINT64)hi2 << 32) | lo2;   /* сдвиг разряда — берём второе */
    if (lo != lo2) {
        /* TIME_0 переполнился между чтениями — перечитаем один раз */
        hi = mmio_read32(NV_PTIMER_TIME_1);
        lo = mmio_read32(NV_PTIMER_TIME_0);
    }
    return ((UINT64)hi << 32) | lo;
}

/* v3n: ЗАМЕРЫ ВРЕМЕНИ.
 *
 * Лог не содержал меток времени, поэтому 13 минут работы приходилось
 * раскладывать по коду вручную. PTIMER — свободно идущие GPU-часы (нс),
 * читаются через уже проверенный порт. Печатаем миллисекунды от старта
 * приложения: так за один заход видно, какая фаза съедает время. */
static UINT64 g_t0 = 0;      /* NV_PTIMER на старте отсчёта (нужен BAR0) */
static UINT64 g_t0tsc = 0;   /* TSC на старте отсчёта (работает всегда)  */
static BOOLEAN g_t0set = FALSE;

/* ---- Часы на TSC: работают с первой инструкции efi_main ---------------
 *
 * ЗАЧЕМ. NV_PTIMER (cmp90_ptimer64) — это MMIO, он читается только после
 * enable_mem_decode(). Старый log_t0() стоял ПОСЛЕ отображения BAR0, то
 * есть 382 строки efi_main шли вообще без хронометража.
 *
 * Нашёл это сравнение с секундомером: прогон занимает 2 мин 05 с, а
 * счётчик показывает 108 с. Разница ~17 с — не POST и не UEFI, а работа
 * до начала отсчёта.
 *
 * RDTSC для этого подходит: он не требует отображения BAR0 и на x86-64
 * гарантирован (IA32_TSC). Калибровка против BS->Stall(1000) занимает
 * 1 мс — на фоне 120 с это несущественно.
 */
/* Включить часы и начать отсчёт. Вызывается ПЕРВЫМ делом в efi_main. */
static void
log_clock_start(void)
{
    UINT64 a, b;
    if (g_t0set) return;              /* уже запущены */
    a = fx_rdtsc();
    uefi_call_wrapper(BS->Stall, 1, 1000);
    b = fx_rdtsc();
    fx_tscPerUs = (b - a) / 1000ULL;
    if (fx_tscPerUs == 0) fx_tscPerUs = 1;
    fx_mark = fx_rdtsc();
    g_t0tsc = fx_mark;
    g_t0set = TRUE;
    ulogf(L"TIME  t=0ms - start of count (tsc=%lld ticks/us; NBPTIMER not "
          L"readable yet, BAR0 not mapped)\n", (INT64)fx_tscPerUs);
}

/* Прежний нуль по NV_PTIMER. Оставлен: он не сбрасывает TSC-отсчёт, а
 * только дописывает в лог второе, независимое подтверждение времени. */
static void
log_t0(void)
{
    g_t0 = cmp90_ptimer64();
    ulogf(L"TIME  ptimer zero = %lldns (TSC count already running since "
          L"efi_main entry)\n", (INT64)g_t0);
}

static void
log_ms(const CHAR16 *tag)
{
    /* v3.17: после каждой метки буфер СБРАСЫВАЕТСЯ на флешку. Метки
     * времени - это ровно те строки, по которым определяется, где
     * прогон остановился, поэтому терять их нельзя даже при зависании.
     * Сброс идёт один раз на ~20 меток за прогон и на общий объём лога
     * почти не влияет. */
    if (g_t0tsc) {
        UINT64 ms = fx_now_us() / 1000ULL;
        ulogf(L"TIME  t=%lldms  %s\n", (INT64)ms, tag);
        log_flush_sector(TRUE);
        return;
    }
    if (g_t0 == 0) return;
    {
        UINT64 ms = (cmp90_ptimer64() - g_t0) / 1000000ULL;
        ulogf(L"TIME  t=%lldms  %s\n", (INT64)ms, tag);
        log_flush_sector(TRUE);
    }
}

/* v2.69b: проба здоровья SEC2 — липнут ли записи в блок регистров.
 * Canary пишется в безвредные MAILBOX0/DMATRFBASE, читается обратно,
 * восстанавливается. Наблюдение v2.69: к моменту ботера записи НЕ липнут
 * (mbox0=0x91 пережил наш write 0x7FB38000), ботер не исполнялся вовсе.
 * HWCFG2=0 на GA102 SEC2 — НОРМА (так и в живом unlocked-свипе). */
static void sec2_health(const CHAR16 *tag)
{
    UINT32 m0old = mmio_read32(SEC2_MAILBOX0);
    UINT32 dbold = mmio_read32(SEC2_DMATRFBASE);
    UINT32 m0wr, dbwr;

    mmio_write32(SEC2_MAILBOX0, 0xA5A5C3C3);
    m0wr = mmio_read32(SEC2_MAILBOX0);
    mmio_write32(SEC2_DMATRFBASE, 0xDEADBEEF);
    dbwr = mmio_read32(SEC2_DMATRFBASE);
    mmio_write32(SEC2_MAILBOX0, m0old);
    mmio_write32(SEC2_DMATRFBASE, dbold);
    Print(L"[health %s] hwcfg2=0x%08x cpu=0x%08x irq=0x%08x "
          L"mbox0 0x%08x->wr=0x%08x dmabase 0x%08x->wr=0x%08x "
          L"| gsp cpu=0x%08x mbox0=0x%08x\n",
          tag, mmio_read32(0x84001C), mmio_read32(SEC2_CPUCTL),
          mmio_read32(SEC2_IRQSTAT), m0old, m0wr, dbold, dbwr,
          mmio_read32(GSP_CPUCTL), mmio_read32(GSP_MAILBOX0));
}

static EFI_STATUS
booter_load_v67(UINT64 wprMetaPhys, UINT64 ucodePhys)
{
    UINT64 fx_ph;
    UINT32 data;
    UINTN i;

    sec2_health(L"7-booter-entry");
    fx_ph = fx_now_us();

    /* v2.63: WPR meta копируется НИЖЕ 4ГБ — ботер читает mailbox0 как
     * 32-битный адрес; meta на >4ГБ даёт ему мусор (exit 0x91). Контент
     * (фиксированная раскладка heap/flags) сохраняется при копировании. */
    wprMetaPhys = cmp90_meta_low(wprMetaPhys);

    /* kflcnReset (SEC2) — обязателен перед загрузкой ucode (kgspExecuteBooterLoad):
     * ENGINE._RESET=TRUE → чтения → _FALSE → чтения.
     * ПОТОМ kflcnSwitchToFalcon: BCR CORE_SELECT=FALCON — снимает priv lockdown.
     * (v2.12: CPUCTL 0xBADF5620 → 0x10 сразу после записи BCR=1; НО если BCR
     * писать ДО ENGINE reset — reset сбрасывает BCR обратно в RISC-V+BRFETCH
     * (0x110) и lockdown возвращается. Порядок драйвера: reset → BCR!) */
    /* v2.34: kflcnPreResetWait — ждать HWCFG2 RESET_READY (bit31), как драйвер */
    for (i = 0; i < 100000; i++) {
        data = mmio_read32(0x84001C);   /* SEC2 HWCFG2 */
        if (data & 0x80000000) break;
        if (i == 99999)
            Print(L"booter: ВНИМАНИЕ RESET_READY не пришёл (HWCFG2=0x%08x)\n", data);
    }
    Print(L"booter: SEC2 HWCFG2=0x%08x (RESET_READY=bit31)\n", data);

    Print(L"booter: SEC2 reset (ENGINE 0x8403C0)...\n");
    falcon_wait_reset_ready(L"rr: booter SEC2 reset", SEC2_HWCFG2, SEC2_CPUCTL);
    mmio_write32(SEC2_ENGINE, 0x1);
    for (i = 0; i < 16; i++) mmio_read32(SEC2_ENGINE);
    mmio_write32(SEC2_ENGINE, 0x0);
    for (i = 0; i < 16; i++) mmio_read32(SEC2_ENGINE);
    falcon_wait_scrub_done(SEC2_DMACTL, SEC2_HWCFG2, L"sec2-reset");
    uefi_call_wrapper(BS->Stall, 1, 50000);   /* дать ресету дойти до конца */

    /* v2.41: kflcnSwitchToFalcon — ТРЕЙС драйвера: BCR_CTRL=0x0 (НЕ 0x1!).
     * VALID ставит HW. (Трейс 2026-08-21: 0x841668 = 0x00000000.) */
    mmio_write32(SEC2_BCR_CTRL, 0x0);
    for (i = 0; i < 16; i++) mmio_read32(SEC2_BCR_CTRL);
    uefi_call_wrapper(BS->Stall, 1, 10000);

    data = mmio_read32(SEC2_CPUCTL);
    Print(L"booter: CPUCTL после BCR=0 = 0x%08x (0xBADF = lockdown не снят)\n", data);
    if ((data & 0xBADF0000) == 0xBADF0000) {
        /* запасной вариант: BCR=0x1 (как в v2.12 — тоже снимал lockdown) */
        Print(L"booter: пробую BCR=0x1...\n");
        mmio_write32(SEC2_BCR_CTRL, 0x1);
        uefi_call_wrapper(BS->Stall, 1, 10000);
        data = mmio_read32(SEC2_CPUCTL);
        Print(L"booter: CPUCTL после BCR=1 = 0x%08x\n", data);
        if ((data & 0xBADF0000) == 0xBADF0000) {
            Print(L"booter: SEC2 lockdown НЕ снят — прерываю booter load\n");
            /* v3.18: каждый ранний выход закрывает открытую фазу.
             * Счётчик глубины живёт балансом begin/end, и незакрытая фаза
             * оставляет его сдвинутым навсегда: каждая следующая фаза
             * после такого места была бы помечена вложенной и исчезла бы
             * из верхнего итога. Здесь это сделано явно, потому что
             * автоматика в C для этого не существует. */
            fx_mk_acc(fx_ph, L"booter: reset+scrub (early exit)");
            return EFI_DEVICE_ERROR;
        }
    }

    /* ждать завершение скраббинга (DMACTL теперь читается) */
    for (i = 0; i < 100000; i++) {
        data = mmio_read32(SEC2_DMACTL);
        if ((data & 0xBADF0000) != 0xBADF0000) {
            if (!(data & 0x6)) break;   /* DMEM/IMEM scrubbing done */
        }
    }
    Print(L"booter: reset ok (dmactl=0x%x)\n", mmio_read32(SEC2_DMACTL));
    sec2_health(L"8-booter-post-reset");
    /* v3.18: фаза переименована и раздроблена.
     *
     * ИЗМЕРЕНО (v3.17): booter_load_v67 стоит 1196 мс на вызов, при этом
     * САМ ботер исполняется за 49 мкс (BOOTER iters=5 in 0.049ms). То
     * есть 99,996 % времени - подготовка вокруг него, и до этого прогона
     * она была одной строкой без разбивки. Ниже она поделена на части,
     * каждая со своим счётчиком:
     *   reset+scrub   - сброс движка и ожидание скраба IMEM/DMEM
     *   wpr2+setup    - запись WPR2 и программирование FBIF/DMATRFCMD
     *   dma           - перенос образа ботера в IMEM/DMEM
     *   start+wait    - STARTCPU и ожидание, пока код отработает
     *
     * Вложенность теперь определяется счётчиком fx_phDepth, а не
     * ручной меткой: см. комментарий у fx_ph_begin(). Прежний
     * fx_ph_end_in здесь стоял как раз потому, что вызов вложен - и это
     * работало, пока ручная метка не соврала в трёх других местах.
     */
    fx_mk_acc(fx_ph, L"booter: reset+scrub");
    fx_ph = fx_now_us();

    Print(L"booter: WPR2 до записи: lo=0x%08x hi=0x%08x\n",
          mmio_read32(REG_PFB_MMU_WPR2_LO), mmio_read32(REG_PFB_MMU_WPR2_HI));
    mmio_write32(REG_PFB_MMU_WPR2_LO, TARGET_WPR2_LO);
    mmio_write32(REG_PFB_MMU_WPR2_HI, TARGET_WPR2_HI);
    uefi_call_wrapper(BS->Stall, 1, 10000);
    fx_mk_acc(fx_ph, L"booter: wpr2+setup");
    fx_ph = fx_now_us();
    Print(L"booter: WPR2 после записи: lo=0x%08x hi=0x%08x (расчёт 0x%08X/0x%08X; не изменились = заблокировано)\n",
          mmio_read32(REG_PFB_MMU_WPR2_LO), mmio_read32(REG_PFB_MMU_WPR2_HI),
          TARGET_WPR2_LO, TARGET_WPR2_HI);

    /* kflcnDisableCtxReq: FBIF_CTL ALLOW_PHYS_NO_CTX + DMACTL=0 */
    data = mmio_read32(SEC2_FBIF_CTL);
    data |= (1 << 7);
    mmio_write32(SEC2_FBIF_CTL, data);
    data = mmio_read32(SEC2_FBIF_CTL);
    if ((data & 0xBADF0000) == 0xBADF0000)
        Print(L"booter: ВНИМАНИЕ FBIF_CTL всё ещё залочен (0x%08x)\n", data);
    mmio_write32(SEC2_DMACTL, 0);

    /* v2.41: RM = chipId0 — из ТРЕЙСА драйвера: 0xb72000a1 (НЕ PMC_BOOT_0!).
     * kflcnReset_TU102: kflcnRegWrite(RM, pGpu->chipId0). */
    mmio_write32(SEC2_RM, 0xb72000a1);
    Print(L"booter: RM записан = 0xb72000a1 (chipId0 из трейса драйвера)\n");

    /* TRANSCFG(0): TARGET=COHERENT_SYSMEM(1) | MEM_TYPE=PHYSICAL(1<<2)
     * (нужен и для внутреннего DMA booter'а при чтении WPR meta) */
    data = mmio_read32(SEC2_FBIF_TRANSCFG0);
    data = (data & ~0x7) | 0x5;
    mmio_write32(SEC2_FBIF_TRANSCFG0, data);

    /* v2.21: ТЕСТ доступности DMATRF (запись+readback). v2.17: DMA «не
     * передал» (IMEM=DEAD5EC1 через НЕ-secure порт) — но SEC=1 передача
     * могла писать в SECURE IMEM (невидимый не-secure чтению), а блобы тогда
     * были мусором (до --redefine-sym). Теперь блобы настоящие. */
    Print(L"booter: DMATRFBASE до = 0x%08x\n", mmio_read32(SEC2_DMATRFBASE));
    mmio_write32(SEC2_DMATRFBASE, 0xDEADBEEF);
    Print(L"booter: DMATRFBASE после = 0x%08x (DEADBEEF = пишется; 0xBADF = залочен)\n",
          mmio_read32(SEC2_DMATRFBASE));

    /* v2.71b: GROUND TRUTH размеры (V2-49, живой драйвер): IMEM 0x8900 из
     * src+0x100 (SEC=1), DMEM 0x6200 из src+0x8A00 (SEC=0); сигнатура
     * image[0x8A10] САМА ложится на DMEM[0x10]=hsSigDmemAddr — порт-патч
     * подписи не нужен. Порт-загрузка IMEM ОТМЕНЕНА экспериментом v2.71:
     * записи IMEMC0 bit28 НЕ липнут (readback=scrub), BROM не увидел хедера
     * (мгновенный halt, dbg=0x0). А DMA-вариант v251[3] давал маркер
     * HS-старта 0x8C00FF — хедер БЫЛ прочитан, т.е. DMA доставляет. */
    Print(L"booter: DMA IMEM SEC=1 (dest=0, src+0x100, 0x8900 байт)...\n");
    falcon_dma_transfer(0, 0x100, ucodePhys, 0x8900,
                        0 | (6 << 8) | (0 << 12) | (1 << 4) | (1 << 2));
    Print(L"booter: DMA DMEM SEC=0 (dest=0, src+0x8A00, 0x6200 байт)...\n");
    falcon_dma_transfer(0, 0, ucodePhys + 0x8A00, 0x6200,
                        0 | (6 << 8) | (0 << 12));
    mmio_write32(SEC2_DMEMC0, 0x10);
    Print(L"booter: DMEM[0x10]=0x%08x (ожидаю sig SIG_PROD[0] 0x%08x)\n",
          mmio_read32(SEC2_DMEMD0),
          *(UINT32*)((UINTN)ucodePhys + 0x8A10));
    fx_mk_acc(fx_ph, L"booter: dma image");
    fx_ph = fx_now_us();

    /* PKC (RSA3K) параметры */
    mmio_write32(SEC2_BROM_PARAADDR0, BOOTER_HS_SIG_DMEM_ADDR);
    mmio_write32(SEC2_BROM_ENGIDMASK, BOOTER_ENGINE_ID_MASK);
    mmio_write32(SEC2_BROM_CURR_UCODE_ID, BOOTER_UCODE_ID);
    data = mmio_read32(SEC2_MOD_SEL);
    data = (data & ~0xFF) | 0x1;   /* RSA3K */
    mmio_write32(SEC2_MOD_SEL, data);

    /* BOOTVEC=0x100 (из ТРЕЙСА драйвера!) + mailboxes (WPR meta phys) + start */
    mmio_write32(SEC2_BOOTVEC, 0x100);
    mmio_write32(SEC2_MAILBOX0, (UINT32)(cmp90_meta_low(wprMetaPhys) & 0xFFFFFFFF));
    mmio_write32(SEC2_MAILBOX1, (UINT32)((cmp90_meta_low(wprMetaPhys) >> 32) & 0xFFFFFFFF));

    /* копируем booter ucode в кэш-безопасную область: DMA из sysmem идёт напрямую,
     * поэтому flush кэша перед стартом обязателен */
    __asm__ volatile("wbinvd" ::: "memory");

    /* v2.82: ВКЛЮЧАЕМ RISC-V ТРАССИРОВКУ до старта (dev_riscv_pri.h):
     * TRACECTL(+0x400): MMODE_ENABLE(bit23) + MODE=FULL(25:24=0) +
     * дефолтные пороги HIGH_THSHD=0xFF/LOW_THSHD=0x00.
     * После halt кольцо RDIDX/WTIDX(+404/+408) отдаст последние PC! */
    mmio_write32(NV_FALCON2_SEC_BASE + 0x400, 0x10B0FF00);

    /* старт CPU */
    mmio_write32(SEC2_CPUCTL, NV_PFALCON_FALCON_CPUCTL_STARTCPU_TRUE);

    Print(L"booter: CPU started, v2.72 deep-poll...\n");

    /* v2.72: расширенный поллинг ВО ВРЕМЯ исполнения ботера. Быстрый набор
     * (mbox0/IRQSTAT/CPUCTL/DEBUGINFO) — каждую итерацию; медленный срез
     * (WPR2, DMATRFCMD, GSP mbox0, DMEM canary 0xff4c/0xff50 ns|sec,
     * DMEM[0x10] ns) — каждую 32-ю итерацию. Запись в историю: любое
     * изменение ИЛИ каждые 256 итераций (временные ряды). */
    {
        CMP90_MBOX_ENT *hist = NULL;
        UINTN hist_n = 0;
        UINT64 t0 = cmp90_ptimer64();
        UINT32 pm0 = mmio_read32(SEC2_MAILBOX0);
        UINT32 pir = mmio_read32(SEC2_IRQSTAT);
        UINT32 pcu = mmio_read32(SEC2_CPUCTL);
        UINT32 pdg = mmio_read32(SEC2_DEBUGINFO);
        UINT32 pw2 = mmio_read32(REG_PFB_MMU_WPR2_LO);
        UINT32 pdm = mmio_read32(SEC2_DMATRFCMD);
        UINT32 pgm = mmio_read32(GSP_MAILBOX0);
        UINT32 pd4n, pd4s, pd5n, pd5s, pd10;
        BOOLEAN plmOpen = FALSE, halted = FALSE;
        UINT64 elapsed;
        UINTN j, it = 0, lastRec = 0;

        uefi_call_wrapper(BS->AllocatePool, 3, EfiBootServicesData,
                          CMP90_MBOX_HIST_MAX * sizeof(CMP90_MBOX_ENT),
                          (VOID **)&hist);

#define CMP90_DREAD(addr, sec) ({ \
    mmio_write32(SEC2_DMEMC0, (addr) | ((sec) ? (1u << 28) : 0)); \
    mmio_read32(SEC2_DMEMD0); })
        pd4n = CMP90_DREAD(0xFF4C, 0); pd4s = CMP90_DREAD(0xFF4C, 1);
        pd5n = CMP90_DREAD(0xFF50, 0); pd5s = CMP90_DREAD(0xFF50, 1);
        pd10 = CMP90_DREAD(0x10, 0);

        Print(L"booter: baseline m0=0x%08x irq=0x%x cpu=0x%x dbg=0x%x "
              L"w2=0x%08x dma=0x%08x gsp=0x%08x d[ff4c]=%08x/%08x "
              L"d[ff50]=%08x/%08x d[10]=%08x\n",
              pm0, pir, pcu, pdg, pw2, pdm, pgm, pd4n, pd4s, pd5n, pd5s, pd10);

        /* v2.77: трассировка исполнения через RISC-V wtidx (FALCON2+0x408):
         * индекс растёт, пока ботер исполняется; замирание = точка смерти.
         * MMIO-чит ~0.65мс, поэтому поллим только wtidx; mbox0/halt — реже.
         * После остановки — обход кольца назад даёт последние PC! */
        {
            UINT32 lastWt = mmio_read32(NV_FALCON2_SEC_BASE + 0x408);
            UINTN stable = 0;
            for (it = 0; it < 200000; it++) {
                UINT32 wt = mmio_read32(NV_FALCON2_SEC_BASE + 0x408);
                if (wt != lastWt) {
                    if (hist && hist_n < CMP90_MBOX_HIST_MAX &&
                        (it - lastRec) >= 24) {
                        UINT64 t = cmp90_ptimer64();
                        hist[hist_n].t_lo = (UINT32)t;
                        hist[hist_n].t_hi = (UINT32)(t >> 32);
                        hist[hist_n].cpuctl = mmio_read32(SEC2_CPUCTL);
                        hist[hist_n].irqstat = mmio_read32(SEC2_IRQSTAT);
                        hist[hist_n].dbg = mmio_read32(SEC2_DEBUGINFO);
                        hist[hist_n].mbox0 = mmio_read32(SEC2_MAILBOX0);
                        hist[hist_n].mbox1 = mmio_read32(SEC2_MAILBOX1);
                        hist[hist_n].wpr2lo = pw2;
                        hist[hist_n].dmatrfcmd = pdm;
                        hist[hist_n].gspmbox0 = pgm;
                        hist[hist_n].dFF4c = wt;      /* wtidx в момент среза */
                        hist[hist_n].dFF50 = pd5s;
                        hist[hist_n].d10 = pd10;
                        hist_n++;
                        lastRec = it;
                    }
                    lastWt = wt; stable = 0;
                } else {
                    stable++;
                    if (stable >= 6) break;   /* исполнение замерло */
                }
                if ((it & 7) == 7) {
                    UINT32 irx = mmio_read32(SEC2_IRQSTAT);
                    if (irx & 0x10) { pir = irx; halted = TRUE; break; }
                    if ((it & 31) == 31 &&
                        mmio_read32(REG_FEAT_OVR_PLM) == VAL_PLM_OPEN) {
                        plmOpen = TRUE; break;
                    }
                }
            }
        }
        /* фаза B: редкий опрос до 5с (halt/PLM/mbox) */
        for (;;) {
            UINT32 ir = mmio_read32(SEC2_IRQSTAT);
            UINT32 m0;
            if (ir & 0x10) { pir = ir; halted = TRUE; break; }
            m0 = mmio_read32(SEC2_MAILBOX0);
            if (m0 != pm0) {
                if (hist && hist_n < CMP90_MBOX_HIST_MAX) {
                    UINT64 t = cmp90_ptimer64();
                    hist[hist_n].t_lo = (UINT32)t;
                    hist[hist_n].t_hi = (UINT32)(t >> 32);
                    hist[hist_n].mbox0 = m0;
                    hist[hist_n].irqstat = ir;
                    hist[hist_n].dbg = mmio_read32(SEC2_DEBUGINFO);
                    hist[hist_n].cpuctl = mmio_read32(SEC2_CPUCTL);
                    hist[hist_n].mbox1 = mmio_read32(SEC2_MAILBOX1);
                    hist[hist_n].wpr2lo = pw2;
                    hist[hist_n].dmatrfcmd = pdm;
                    hist[hist_n].gspmbox0 = pgm;
                    hist[hist_n].dFF4c = pd4s;
                    hist[hist_n].dFF50 = pd5s;
                    hist[hist_n].d10 = pd10;
                    hist_n++;
                }
                pm0 = m0;
            }
            if (mmio_read32(REG_FEAT_OVR_PLM) == VAL_PLM_OPEN) {
                plmOpen = TRUE; break;
            }
            elapsed = cmp90_ptimer64() - t0;
            if (elapsed > 5000000000ULL) break;
            uefi_call_wrapper(BS->Stall, 1, 1000);
        }
#undef CMP90_DREAD

        elapsed = cmp90_ptimer64() - t0;
        Print(L"booter: hist %u записей за %u.%03u мс, iters=%u (%s)\n",
              (UINT32)hist_n,
              (UINT32)(elapsed / 1000000ULL),
              (UINT32)((elapsed / 1000ULL) % 1000ULL),
              (UINT32)it,
              plmOpen ? L"PLM OPEN" : halted ? L"HALT" : L"таймаут 5с");
        /* v3n: то же в лог — именно этот поллинг (до 200000 итераций по
         * ~0.65мс) подозреваем в съедании большей части 13 минут */
        ulogf(L"BOOTER iters=%u in %u.%03ums %s\n",
              (INTN)it,
              (INTN)(elapsed / 1000000ULL),
              (INTN)((elapsed / 1000ULL) % 1000ULL),
              plmOpen ? L"PLM-OPEN" : halted ? L"HALT" : L"timeout-5s");
        for (j = 0; j < hist_n; j++) {
            UINT64 tj = ((UINT64)hist[j].t_hi << 32) | hist[j].t_lo;
            UINT64 d = tj - t0;
            if (hist_n > 240 && j == 120) {
                Print(L"  ... пропущено %u записей ...\n", (UINT32)(hist_n - 240));
                j = hist_n - 121;   /* после j++ продолжим с n-120 */
            }
            Print(L"  hist[%03u] +%u.%03uмс cpu=0x%08x irq=0x%08x dbg=0x%08x "
                  L"m0=0x%08x w2=0x%08x dma=0x%08x gsp=0x%08x "
                  L"d[ff4c]=%08x d[ff50]=%08x d[10]=%08x\n",
                  (UINT32)j,
                  (UINT32)(d / 1000000ULL), (UINT32)((d / 1000ULL) % 1000ULL),
                  hist[j].cpuctl, hist[j].irqstat, hist[j].dbg,
                  hist[j].mbox0, hist[j].wpr2lo, hist[j].dmatrfcmd,
                  hist[j].gspmbox0, hist[j].dFF4c, hist[j].dFF50,
                  hist[j].d10);
        }
        Print(L"booter: финал: cpu=0x%x irq=0x%x dbg=0x%x m0=0x%08x m1=0x%08x\n",
              mmio_read32(SEC2_CPUCTL), mmio_read32(SEC2_IRQSTAT),
              mmio_read32(SEC2_DEBUGINFO),
              mmio_read32(SEC2_MAILBOX0), mmio_read32(SEC2_MAILBOX1));

        if (plmOpen) {
            Print(L"booter: PLM OPEN (cpu_ctl=0x%x irq=0x%x mbox0=0x%x)\n",
                  mmio_read32(SEC2_CPUCTL), mmio_read32(SEC2_IRQSTAT),
                  mmio_read32(SEC2_MAILBOX0));
            /* v3.18: закрытие фазы перед выходом - см. объяснение в
             * раннем выходе выше. */
            fx_mk_acc(fx_ph, L"booter: start+wait");
            if (hist) uefi_call_wrapper(BS->FreePool, 1, hist);
            return EFI_SUCCESS;
        }
        if (hist) uefi_call_wrapper(BS->FreePool, 1, hist);
    }

    /* v2.67: ДМП DMEM ботера после halt — его рабочее состояние!
     * 0x00-0x1F: сигнатура (hsSigDmemAddr=0x10); дальше — переменные. */
    Print(L"booter: === DMEM DUMP (0x000-0x1FF, ns|sec) ===\n");
    {
        UINTN a;
        for (a = 0; a < 0x200; a += 4) {
            UINT32 vn, vs;
            mmio_write32(SEC2_DMEMC0, a);
            vn = mmio_read32(SEC2_DMEMD0);
            mmio_write32(SEC2_DMEMC0, a | (1 << 28));
            vs = mmio_read32(SEC2_DMEMD0);
            Print(L"booter: dmem %04x: %08x %08x\n", a, vn, vs);
        }
    }
    /* v2.67: IMEM первые 0x100 байт — доставился ли код? (шифртекст или скраб) */
    Print(L"booter: === IMEM DUMP (0x000-0x0FF, ns|sec) ===\n");
    {
        UINTN a;
        for (a = 0; a < 0x100; a += 4) {
            UINT32 vn, vs;
            mmio_write32(SEC2_IMEMC0, a);
            vn = mmio_read32(SEC2_IMEMD0);
            mmio_write32(SEC2_IMEMC0, a | (1 << 28));
            vs = mmio_read32(SEC2_IMEMD0);
            Print(L"booter: imem %04x: %08x %08x\n", a, vn, vs);
        }
    }

    /* v2.16: дамп RISC-V trace — где остановился booter (диагностика) */
    {
        UINTN t;
        UINT32 rdidx, wtidx;
        /* v3.19: ЗДЕСЬ СТОЯЛО ВТОРОЕ ЗАКРЫТИЕ ТОЙ ЖЕ ФАЗЫ.
         * Первое - 'booter: start+wait' - уже закрыло её выше по выходу
         * plmOpen. Второе закрытие уводило счётчик глубины fx_phDepth в
         * минус, и после этого КАЖДАЯ следующая фаза получала dep>0, то
         * есть становилась вложенной. Итог прогона v3.18:
         *     все 16 фаз помечены (inside), SUM top-level = 0
         *     CHECK 0 us (phases vs elapsed 65264689 us: unaccounted 100%)
         * То есть таблица фаз перестала означать что-либо, и я не заметил
         * этого, потому что не сверил её с реально прошедшим временем.
         * Именно ради такой сверки в v3.18 и добавлена строка CHECK.
         *
         * Дамп IMEM и RISC-V-trace - это диагностика на пути отказа,
         * отдельной фазой они не являются. Закрытия здесь не нужно. */

        Print(L"booter: riscv: cpuctl=0x%x tracectl=0x%x rdidx=0x%x wtidx=0x%x bcr=0x%x\n",
              mmio_read32(NV_FALCON2_SEC_BASE + 0x388),
              mmio_read32(NV_FALCON2_SEC_BASE + 0x400),
              mmio_read32(NV_FALCON2_SEC_BASE + 0x404),
              mmio_read32(NV_FALCON2_SEC_BASE + 0x408),
              mmio_read32(NV_FALCON2_SEC_BASE + 0x668));
        rdidx = mmio_read32(NV_FALCON2_SEC_BASE + 0x404) & 0xFF;
        wtidx = mmio_read32(NV_FALCON2_SEC_BASE + 0x408) & 0xFF;
        Print(L"booter: trace rdidx=%d wtidx=%d (0xBADF = riscv блок залочен)\n",
              rdidx, wtidx);
        for (t = 0; t < 16; t++) {
            UINT32 idx = (wtidx + 0x100 - t) & 0xFF;
            UINT32 pcLo, pcHi;
            mmio_write32(NV_FALCON2_SEC_BASE + 0x404, idx);
            pcLo = mmio_read32(NV_FALCON2_SEC_BASE + 0x40C);
            pcHi = mmio_read32(NV_FALCON2_SEC_BASE + 0x410);
            Print(L"booter: trace[-%d] pc=0x%x%08x\n", t, pcHi, pcLo);
        }
    }
    return EFI_TIMEOUT;
    /* v3.18: здесь стояло `fx_ph_end(fx_ph, L"booter_load_v67: run+trace")`
     * ПОСЛЕ return - то есть МЁРТВЫЙ КОД. Компилятор его выбрасывал, и
     * фаза run+trace не закрывалась НИКОГДА. В таблице прогона v3.17 её
     * действительно нет, при том что имя на неё ссылалось.
     *
     * Почему это было опасно, а не просто неаккуратно: счётчик глубины
     * вложенности живёт балансом begin/end, и незакрытая фаза оставляет
     * его сдвинутым. Каждая последующая фаза после такого места
     * считалась бы вложенной и исчезла бы из верхнего итога. Закрытие
     * фазы перенесено выше, к месту, где функция реально доходит до
     * конца этого блока. */
}

/* ==== EARLY PATH — run the booter FIRST, on a fresh SEC2 (MAIN PATH) ====
 * Measured behaviour: only the FIRST booter start after POST actually
 * executes — afterwards the SEC2 register block wedges (writes stop
 * sticking, engine reset does NOT heal) and every later attempt runs a
 * corpse. Release order is therefore: BL(GSP) -> FWSEC(GSP) sets WPR2
 * -> ResetIntoRiscv + LibosBootArgs -> booter_load_v67 immediately.
 * Диагностика v2.69b (canary-пробы [health]): ПЕРВЫЙ же старт ботера на SEC2
 * (v251 шаг [3]) исполняется (dbg 0x8C00FF→0xDA550000), пишет mbox0=0x91 —
 * и КЛИНИТ блок регистров SEC2: записи больше не липнут, engine reset НЕ
 * лечит. Все последующие попытки (включая главный booter_load_v67) исполняли
 * «труп» и читали чужой 0x91. Новый порядок: BL(GSP) → FWSEC(GSP) → WPR2 →
 * ResetIntoRiscv+libos args → booter_load_v67 на ЖИВОМ SEC2 (поллинг v2.69). */
static EFI_STATUS
early_unlock_path(UINT64 ucodePhys, UINT64 fwsecPhys, UINT64 wprMetaPhys)
{
    UINT64 fx_ph;   /* метка времени для учёта по фазам */
    UINTN i;

    Print(L"\n=== v2.70: ранний путь — ботер ПЕРВЫЙ на свежем SEC2 ===\n");

    /* --- [E1] BL (ucodeId=1) на GSP — открывает secure-путь (урок v2.62b).
     *        Дословная копия стадии [1/3] v2.46 (эмпирически рабочая). --- */
    Print(L"[E1] GSP BL ucodeId=1 (IMEM 0x4000/DMEM 0x2400)...\n");
    fx_ph = fx_now_us();
    mmio_write32(0x110080, 0x0);          /* из трейса (IRQMSET=0) */
    falcon_wait_reset_ready(L"rr: [E1] BL reset-ready", GSP_HWCFG2, GSP_CPUCTL);
    mmio_write32(GSP_ENGINE, 0x1);
    for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
    mmio_write32(GSP_ENGINE, 0x0);
    for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
    falcon_wait_scrub_done(GSP_DMACTL, GSP_HWCFG2, L"gsp-reset");
    /* v3.35, ЭТАП 18: Stall(50000) -> Stall(10000). ЭТО ПЕРВАЯ ИЗ ТРЁХ пауз
     * по 50 мс внутри early_unlock_path (строки 6665, 6730, 6821). Все три
     * СЛЕПЫЕ - ни условия, ни опроса, просто ожидание. x8 итераций цикла
     * масок = 1 200 мс, то есть 7% прогона, и они НИКОГДА НЕ бисектировались.
     *
     * ПОЧЕМУ РЕЗКИЙ ПРЫЖОК 50 -> 10, А НЕ ДЕЛЕНИЕ ПОПОЛАМ. Правило проекта:
     * сначала измерить концы интервала, потом делить пополам. Здесь КОНЦОВ НЕТ
     * - ни один прогон не показал, что эти 50 мс нужны. Нижней границы не
     * существует, интервала нет, делить нечего. Значит первый зонд должен быть
     * информативным, а не аккуратным.
     *
     *   8 итераций x 40 мс = 320 мс
     *   17 417 - 320 = 17 097 мс   (ожидаем ~17,1 с)
     *
     * РИСК РЕАЛЕН, и это не страховка, а факт. Эта пауза лежит в той же
     * последовательности [E1]/[E3], где 150 мс QUIESCE в v3.32 сломали рендер
     * (1 из 8). Поэтому РОВНО ОДНА правка за прогон, а не три сразу: если
     * рендер сломается, виновата будет ровно эта строка.
     *
     * Только три исхода, все полезны:
     *   PASS ~17,1 с -> порог <=10 мс, следующим прогоном срезать 6730 и 6821
     *   FAIL          -> граница в (10; 50], дальше делить и останавливаться
     *   неожиданно     -> это новая информация, а не повод для догадок
     */
    uefi_call_wrapper(BS->Stall, 1, 10000);
    mmio_write32(GSP_BCR, 0x0);
    for (i = 0; i < 16; i++) mmio_read32(GSP_BCR);
    mmio_write32(GSP_RM, 0xb72000a1);
    mmio_write32(GSP_DMACTL, 0x0);
    gsp_dma_transfer(0, 0x100, ucodePhys, 0x4000,
                     0 | (6 << 8) | (0 << 12) | (1 << 4) | (1 << 2));
    gsp_dma_transfer(0, 0, ucodePhys + 0x4100, 0x2400,
                     0 | (6 << 8) | (0 << 12));
    {
        /* сигнатура для DMEM[0x1F10]: src[0x4100+0x1F10=0x6010] ← sig(0x8A10) */
        UINT8 *img = (UINT8*)(UINTN)ucodePhys;
        CopyMem(img + 0x6010, img + 0x8A10, 0x180);
    }
    mmio_write32(GSP_BROM_PARAADDR0, 0x1F10);
    mmio_write32(GSP_BROM_ENGIDMASK, 0x400);
    mmio_write32(GSP_BROM_CURR_UCODE_ID, 1);
    mmio_write32(GSP_MOD_SEL, 0x1);
    mmio_write32(GSP_MAILBOX0, 0xFE);     /* из трейса: 0x110040 = 0xfe */
    mmio_write32(GSP_BOOTVEC, 0x100);
    __asm__ volatile("wbinvd" ::: "memory");
    mmio_write32(GSP_CPUCTL, 2);          /* STARTCPU */
    mmio_write32(GSP_BCR, 0x111);         /* RISCV+BRFETCH после старта */
    /* v3.16: было слепое Stall(1000000). Зовётся 24 раза за прогон = 24 с
     * чистого расхода. Теперь ждём события; бюджет 1 с сохранён как
     * потолок, фактическое время печатается в лог. */
    fx_settle_after_startcpu(L"[E1]");
    Print(L"[E1] после BL: cpuctl=0x%x dbg=0x%x mbox0=0x%x bcr=0x%x\n",
          mmio_read32(GSP_CPUCTL), mmio_read32(GSP_BASE + 0x94),
          mmio_read32(GSP_MAILBOX0), mmio_read32(GSP_BCR));
    wpr2_probe(L"E1-after-BL");
    fx_mk_acc(fx_ph, L"[E1] BL load+settle");
    fx_ph = fx_now_us();

    /* --- [E2] FWSEC на GSP → WPR2 (fwsec_boot_gsp сам ресетит GSP) --- */
    Print(L"[E2] FWSEC на GSP (WPR2)...\n");
    CopyMem((VOID*)(UINTN)fwsecPhys, fwsec_ga104_bin, FWSEC_SIZE);
    wpr2_probe(L"E2-pre-fwsec");
    sec2_window_dump(L"E2-pre-fwsec");
    if (!fwsec_boot_gsp_sig(fwsecPhys, fwsec_ga104_prod_sig2, 2)) {
        Print(L"[E2] WPR2 не встал — ранний путь не удался\n");
        return EFI_DEVICE_ERROR;
    }
    wpr2_probe(L"E2-post-fwsec");
    sec2_window_dump(L"E2-post-fwsec");
    fx_mk_acc(fx_ph, L"[E2] fwsec_boot_gsp_sig");
    fx_ph = fx_now_us();

    /* --- [E3] ResetIntoRiscv + LibosBootArgs.
     * v2.80: ТОЧНАЯ реплика kflcnResetIntoRiscv_GA102: PreResetWait →
     * ResetHw → WaitForResetToFinish (HWCFG2 bit31 — у GSP он РАБОТАЕТ,
     * в отличие от SEC2!) → ProgramBcr(RISCV|VALID|BRFETCH=0x111).
     * Раньше пропускали Wait → GSP оставался ЗАЛОЧЕННЫМ (BADF5620 на пробе
     * E4), а на живой карте SNAP-B даёт gsp cpuctl=0x10 на входе ботера! */
    Print(L"[E3] ResetIntoRiscv(GSP) + libos args...\n");
    falcon_wait_reset_ready(L"rr: [E3] ResetIntoRiscv ready", GSP_HWCFG2, GSP_CPUCTL);
    mmio_write32(GSP_ENGINE, 0x1);
    for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
    mmio_write32(GSP_ENGINE, 0x0);
    for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
    for (i = 0; i < 100000; i++) {
        if (mmio_read32(GSP_HWCFG2) & 0x80000000) break;
        if (i == 99999)
            Print(L"[E3] ВНИМАНИЕ: GSP RESET_READY не пришёл\n");
    }
    /* v3.36, ЭТАП 19: Stall(50000) -> Stall(10000). ВТОРАЯ ИЗ ТРЁХ слепых пауз
     * по 50 мс внутри early_unlock_path (строки 6689 [E1], 6754 [E3], 6845).
     *
     * ПЕРЕНОС ИЗМЕРЕННОГО ПОРОГА, А НЕ ДОГАДКА. На идентичном месте того же
     * блока (строка 6689, [E1]) в v3.35 доказано: 50 мс не нужны, хватает
     * 10 мс, рендер 8 из 8. Это тот же блок, та же стадия, то же окружение.
     * Механика та же - слепая пауза, ни условия, ни опроса.
     *
     *   9 вызовов x 40 мс = 360 мс
     *   17 040 - 360 = 16 680 мс   (ожидаем ~16,7 с)
     *
     * ЧТО ОСТАЁТСЯ ПОСЛЕ ЭТОГО. Одна пауза 50 мс, строка 6845, ~320 мс. Она
     * единственная из трёх, чей порог ещё не проверен.
     *
     * ЧТО ЕСЛИ СЛОМАЕТСЯ. Значит [E3] чувствительнее [E1], и порог лежит в
     * (10; 50]. Делить и останавливаться - не угадывать. Строка 6845 в этом
     * случае трогать нельзя, потому что тогда непонятно будет, что виновато.
     */
    uefi_call_wrapper(BS->Stall, 1, 10000);
    mmio_write32(GSP_BCR, 0x111);
    for (i = 0; i < 16; i++) mmio_read32(GSP_BCR);
    Print(L"[E3] GSP BCR=0x%x hwcfg2=0x%08x cpu=0x%08x\n",
          mmio_read32(GSP_BCR), mmio_read32(GSP_HWCFG2),
          mmio_read32(GSP_CPUCTL));
    mmio_write32(GSP_MAILBOX0, (UINT32)cmp90_meta_low(wprMetaPhys));
    mmio_write32(GSP_MAILBOX1, (UINT32)(cmp90_meta_low(wprMetaPhys) >> 32));
    wpr2_probe(L"E3-after-ResetIntoRiscv");
    fx_mk_acc(fx_ph, L"[E3] ResetIntoRiscv");

    sec2_health(L"E4-pre-booter");

    /* --- [E5] БОТЕР — ПЕРВАЯ попытка на СВЕЖЕМ SEC2.
     *        Свежая копия образа (патч 0x6010 от BL-шага затирался бы
     *        в DMEM-окне ботера 0x5000..0x9D00). --- */
    CopyMem((VOID*)(UINTN)ucodePhys, booter_ucode_prod, BOOTER_UCODE_SIZE);
    {
        /* v3n: ботер — последний кандидат на смену WPR2: он исполняет V67,
         * а тот по устройству делает произвольные привилегированные записи
         * в регистры. Замер снимает вопрос одним прогоном. */
        EFI_STATUS bst;
        UINT32 wLo, wHi;

        /* v3n: СОХРАНЕНИЕ И ВОССТАНОВЛЕНИЕ
         * WPR2 ВОКРУГ V67 (2026-09-29).
         *
         * Замер доказал: исполнение V67 портит WPR2_LO
         *     E5-до-ботера      WPR2=0x01F7E000/0x01F7EE00
         *     E5-после-ботера   WPR2=0x01EAD000/0x01F7EE00
         *
         * И это НЕ неизбежное свойство
         * эксплойта, а известная особенность,
         * которую работающая реализация
         * bendy2 обходит явно (патч
         * 0001-58015903-cmp90hx-direct-compute.patch):
         *
         *     wpr2Lo = GPU_REG_RD32(pGpu, 0x001fa824U);
         *     wpr2Hi = GPU_REG_RD32(pGpu, 0x001fa828U);
         *     for (attempt = 0; attempt < 2; attempt++) {
         *         GPU_REG_WR32(pGpu, 0x001fa824U, wpr2Lo);   // перед V67
         *         GPU_REG_WR32(pGpu, 0x001fa828U, wpr2Hi);
         *         ...ExecuteBooterLoad...                     // V67
         *     }
         *     GPU_REG_WR32(pGpu, 0x001fa824U, wpr2Lo);       // после V67
         *     GPU_REG_WR32(pGpu, 0x001fa828U, wpr2Hi);
         *     // и только потом — селекторы SS1, SS0
         *
         * Эталон пишет WPR2 обратно ДО
         * записи селекторов. У нас этого
         * не было — и это была самая вероятная
         * причина отказа, ПОКА её не проверили.
         *
         * ВОТ ЧТО ИЗМЕРЕНО (2026-09-29), и оно опровергает ту догадку:
         *   * наша запись WPR2 обратно НЕ ЛИПНЕТ — после неё всё равно
         *     остаётся 0x01EAD000 (строка E5-после-восстановления);
         *   * в Windows значение WPR2 не переживает ВООБЩЕ: RWEverything
         *     даёт 0x1FFFFE00/0x00000000, то есть ровно постовское,
         *     какое было в EFI до любой нашей работы. Ни правильное, ни
         *     испорченное до ОС не доходит.
         * Поэтому «драйвер в Windows проверяет WPR2 и получает
         * испорченное значение» — НЕВЕРНО. Драйвер видит постовское
         * значение независимо от того, что делал EFI, и проверка
         * frtsErrCode / wpr2Hi != 0 / wpr2Lo == expected в Windows не
         * может нас отклонить.
         *
         * Следствия, которые стоит помнить:
         *   - строки `OKCHK wpr2Lo == expected OK` НЕ являются
         *     доказательством ничего: они описывают состояние, которого к
         *     моменту загрузки Windows не существует;
         *   - WPR2 — это защита кадрового буфера, а анлок это SS0/SS1.
         *     Разные подсистемы; добиваться липкости восстановления смысла
         *     нет, измерять всё равно нечего.
         *
         * Порядок «сначала вернуть WPR2, потом SS1/SS0» оставлен как в
         * эталоне — он безвреден и соответствует bendy2.
         *
         * Отличие от эталона, которое стоит держать в виду: bendy2
         * выполняет ботер ДВАЖДЫ, записывая WPR2 перед каждым прогоном;
         * у нас ботер один и запись одна, после. Расхождение не
         * блокирующее — путь работает, — но оно означает, что поведение
         * ботера при повторе мы не воспроизводили.
        wLo = mmio_read32(REG_PFB_MMU_WPR2_LO);
        wHi = mmio_read32(REG_PFB_MMU_WPR2_HI);
        wpr2_probe(L"E5-до-ботера");
        bst = booter_load_v67(wprMetaPhys, ucodePhys);
        wpr2_probe(L"E5-после-ботера");

        /* восстановление того, что было до V67 */
        mmio_write32(REG_PFB_MMU_WPR2_LO, wLo);
        mmio_write32(REG_PFB_MMU_WPR2_HI, wHi);
        /* v3.37, ЭТАП 20: Stall(50000) -> Stall(10000). ТРЕТЬЯ И ПОСЛЕДНЯЯ из
         * трёх слепых пауз по 50 мс внутри early_unlock_path. Две оставшиеся
         * срезаны и обе дали РОВНО 40,0 мс на вызов при 100% успеха:
         *     6689 [E1]  v3.35 PASS, 17 040 мс, промах 57 мс
         *     6772 [E3]  v3.36 PASS, 16 679 мс, промах  1 мс
         * Это перенос доказанного порога с двух идентичных мест того же блока,
         * а не ставка.
         *
         *   9 вызовов x 40 мс = 360 мс
         *   16 679 - 360 = 16 319 мс   (ожидаем ~16,3 с)
         *
         * ЧТО ПОСЛЕ ЭТОГО. Три паузы закрыты, рычаг исчерпан. Остаётся
         * QUIESCE 250 -> 200 мс (~500 мс, шанс ~50%, порог в (150; 250]) -
         * единственная оставшаяся ставка, и она настоящий gamble, а не
         * перенос. Оценка потолка архитектуры ~15,5 с; после этой правки
         * останется до него ~1,2 с.
         */
        uefi_call_wrapper(BS->Stall, 1, 10000);
        wpr2_probe(L"E5-after-restore");
        /* v3.51: ПОДПИСЬ 'DID NOT HOLD' УБРАНА, ВМЕСТО НЕЁ - ЧТО ИМЕННО
         * ПРОИЗОШЛО.
         *
         * Здесь пишется обратно НЕ целевое значение, а то, что прочитано
         * строкой выше (wLo), - то есть save/restore до загрузки V67. Проверка
         * сравнивала чтение с записанным и рапортовала '*** DID NOT HOLD ***'.
         *
         * На прогоне 1004-171751 вышло: 'lo 0x00000000->0x01F7E000'. То есть
         * мы записали 0x00000000, а прочитали 0x01F7E000 - и это РОВНО
         * TARGET_WPR2_LO. Факт проверки верен: записанное не удержалось. Но
         * подпись читается как поломка, тогда как вернулось именно то
         * значение, которого мы добивались: ботер или GSP переустановили
         * правильное окно.
         *
         * Это тот же класс, что и WPR2 UNEXPECTED: факт верный, вывод подписан
         * не тот. Здесь сообщение вводило в заблуждение буквально на каждом
         * прогоне, и оно ничего не сообщало о том, чего мы ждали.
         *
         * Теперь печатаются все три величины - записали, прочитали, ожидали -
         * и вывод говорит, ЧТО ПРОИЗОШЛО, а не просто «не удержалось». */
        {
            UINT32 rLo = mmio_read32(REG_PFB_MMU_WPR2_LO);
            UINT32 rHi = mmio_read32(REG_PFB_MMU_WPR2_HI);
            if (rLo == wLo && rHi == wHi) {
                ulogf(L"FLRX   WPR2 after V67: wrote 0x%08x/0x%08x, read back "
                      L"the same - value held\n", wLo, wHi);
            } else if (rLo == (UINT32)TARGET_WPR2_LO &&
                       rHi == (UINT32)TARGET_WPR2_HI) {
                ulogf(L"FLRX   WPR2 after V67: wrote 0x%08x/0x%08x, read back "
                      L"0x%08x/0x%08x = TARGET - booter/GSP re-established the "
                      L"FRTS window, our value did not hold and we do not need "
                      L"it to\n", wLo, wHi, rLo, rHi);
            } else {
                ulogf(L"FLRX   WPR2 after V67: wrote 0x%08x/0x%08x, read back "
                      L"0x%08x/0x%08x (target 0x%08x/0x%08x) - neither what we "
                      L"wrote nor what we wanted; window no longer contains "
                      L"FRTS\n", wLo, wHi, rLo, rHi,
                      (UINT32)TARGET_WPR2_LO, (UINT32)TARGET_WPR2_HI);
            }
        }

        return bst;
    }
}

/* ==== FALLBACK A: full replay of the kernel driver's 3-stage init ====
 * [1] GSP booter load (ucodeId=1, sizes from live trace) -> [2] MODIFIED
 * FWSEC (frts=0x10000000) as a discriminator (our code ran => WPR2 lands
 * at 0x100000 instead of 0x27FE000) -> [3] probes + SEC2 booter load
 * with correct sizes, DMA vs ports, plus a GSP-direct attempt.
 * Legacy fallback ladder member — early_unlock_path() supersedes it.
 * Идея пользователя: «вывалить на GPU то, что шлёт патченный драйвер».
 * Из полного трейса (V2-41) драйвер 610.43.03 при инициализации делает ТРИ
 * загрузки в строгом порядке:
 *   1) GSP ucodeId=1 (booter): BCR=0, RM=chipId0(0xb72000a1), DMACTL=0,
 *      IMEM 0x4000 SEC=1 (источник src+0x100 — пропуск заголовка образа!),
 *      DMEM 0x2400 SEC=0 (источник src+0x4100), PARAADDR0=0x1F10,
 *      ENGIDMASK=0x400, UCODE_ID=1, MOD_SEL=1, MAILBOX0=0xFE,
 *      BOOTVEC=0x100, STARTCPU=2, ПОСЛЕ старта BCR=0x111 (RISCV).
 *   2) GSP FWSEC ucodeId=9: BCR=0, RM, IMEM 0xE200 SEC=1, DMEM 0x800 SEC=0,
 *      PARAADDR0=0x5A4, ENGIDMASK=0x400, MOD_SEL=1, BOOTVEC=0, STARTCPU=2.
 *   3) SEC2 booter ucodeId=3: BCR=0, RM, IMEM 0x4F00 SEC=1, DMEM 0x4D00
 *      SEC=0 (источник +0x5000), PARAADDR0=0x10, ENGIDMASK=1, MOD_SEL=1,
 *      BOOTVEC=0x100, STARTCPU=2.
 * ГИПОТЕЗА v2.46: загрузка #1 (GSP booter) — недостающий ключ: в v2.28-45
 * мы грузили FWSEC БЕЗ неё, и SEC=1 DMA «не работал». После #1 грузим
 * МОДИФИЦИРОВАННЫЙ FWSEC (frts=0x10000000) — дискриминация:
 *   WPR2=0x100000 → НАШ код выполнился → SEC=1 на GSP РАБОТАЕТ после booter!
 *   WPR2=0x27FE000 → снова предзагруженный VBIOS-код → SEC=1 закрыт.
 * Возвращает TRUE при успехе (PLM открыт ИЛИ наш код выполнился). */
static BOOLEAN
driver_replay_v246(UINT64 booterPhys, UINT64 fwsecPhys, UINT64 ucodePhys,
                   UINT64 wprMetaPhys)
{
    UINTN i;
    UINT32 data;
    BOOLEAN ourCode = FALSE;
    BOOLEAN plmOpen = FALSE;

    Print(L"\n=== v2.46: ПОЛНЫЙ РЕПЛЕЙ ПОСЛЕДОВАТЕЛЬНОСТИ ДРАЙВЕРА ===\n");
    Print(L"исходное: PLM=0x%08x SS0=0x%08x SS1=0x%08x GFW=0x%08x WPR2lo=0x%08x\n",
          mmio_read32(REG_FEAT_OVR_PLM), mmio_read32(REG_FEAT_OVR_SM_SPD),
          mmio_read32(REG_FEAT_OVR_SM_SPD_1), mmio_read32(REG_GFW_BOOT_OK),
          mmio_read32(REG_PFB_MMU_WPR2_LO));

    /* ---------- Стадия 1: GSP booter load (ucodeId=1) ---------- */
    Print(L"[1/3] GSP booter load ucodeId=1 (из трейса 538.881)\n");
    mmio_write32(0x110080, 0x0);          /* из трейса (IRQMSET=0) */
    falcon_wait_reset_ready(L"rr: [1/3] booter load ready", GSP_HWCFG2, GSP_CPUCTL);
    mmio_write32(GSP_ENGINE, 0x1);
    for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
    mmio_write32(GSP_ENGINE, 0x0);
    for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
    falcon_wait_scrub_done(GSP_DMACTL, GSP_HWCFG2, L"gsp-reset");
    uefi_call_wrapper(BS->Stall, 1, 50000);

    mmio_write32(GSP_BCR, 0x0);
    for (i = 0; i < 16; i++) mmio_read32(GSP_BCR);
    mmio_write32(GSP_RM, 0xb72000a1);
    mmio_write32(GSP_DMACTL, 0x0);

    Print(L"[1] DMA IMEM SEC=1 0x4000 б (src+0x100 — заголовок пропущен)...\n");
    gsp_dma_transfer(0, 0x100, booterPhys, 0x4000,
                     0 | (6 << 8) | (0 << 12) | (1 << 4) | (1 << 2));
    Print(L"[1] DMA DMEM SEC=0 0x2400 б (src+0x4100)...\n");
    gsp_dma_transfer(0, 0, booterPhys + 0x4100, 0x2400,
                     0 | (6 << 8) | (0 << 12));

    /* сигнатура booter'а: DMEM[0x1F10] (paraaddr) ← sig_dbg из образа.
     * DMEM грузится из src+0x4100 → DMEM[0x1F10] = src[0x4100+0x1F10=0x6010] */
    {
        UINT8 *img = (UINT8*)(UINTN)booterPhys;
        Print(L"[1] патч src[0x6010] ← sig_dbg (0x180 б) для DMEM[0x1F10]...\n");
        CopyMem(img + 0x6010, img + 0x8A10, 0x180);
    }

    mmio_write32(GSP_BROM_PARAADDR0, 0x1F10);
    mmio_write32(GSP_BROM_ENGIDMASK, 0x400);
    mmio_write32(GSP_BROM_CURR_UCODE_ID, 1);
    mmio_write32(GSP_MOD_SEL, 0x1);
    mmio_write32(GSP_MAILBOX0, 0xFE);     /* из трейса: 0x110040 = 0xfe */
    mmio_write32(GSP_BOOTVEC, 0x100);
    __asm__ volatile("wbinvd" ::: "memory");
    mmio_write32(GSP_CPUCTL, 2);          /* STARTCPU */
    mmio_write32(GSP_BCR, 0x111);         /* RISCV+BRFETCH после старта (трейс!) */
    /* v3.16: см. fx_settle_after_startcpu — было слепое Stall(1000000). */
    fx_settle_after_startcpu(L"[1]");
    Print(L"[1] после booter: cpuctl=0x%x dbg=0x%x mbox0=0x%x bcr=0x%x "
          L"GFW=0x%x WPR2lo=0x%x PLM=0x%x\n",
          mmio_read32(GSP_CPUCTL), mmio_read32(GSP_BASE + 0x94),
          mmio_read32(GSP_MAILBOX0), mmio_read32(GSP_BCR),
          mmio_read32(REG_GFW_BOOT_OK), mmio_read32(REG_PFB_MMU_WPR2_LO),
          mmio_read32(REG_FEAT_OVR_PLM));
    dump_regs(L"[1-booter]");

    /* ---------- Стадия 2: FWSEC МОДИФИЦИРОВАННЫЙ (frts=0x10000000) ---------- */
    Print(L"\n[2/3] GSP FWSEC load ucodeId=9 (МОДИФ. frts=0x10000000, дискриминация)\n");
    {
        UINT8 *buf = (UINT8*)(UINTN)fwsecPhys;
        UINT32 *mapper2 = (UINT32*)(buf + FWSEC_DATA_OFF + 0x560);
        UINT32 cmdInOff2 = mapper2[2];
        UINT32 *c2 = (UINT32*)(buf + cmdInOff2);

        CopyMem(buf, fwsec_ga104_bin, FWSEC_SIZE);
        CopyMem(buf + FWSEC_DATA_OFF + FWSEC_SIG_DMEM_ADDR,
                fwsec_ga104_sig, FWSEC_SIG_SIZE);
        c2[0] = 1; c2[1] = 24;            /* readVbiosDesc ver,size */
        c2[2] = 0; c2[3] = 0;
        c2[4] = 0; c2[5] = 2;
        c2[6] = 1; c2[7] = 20;            /* frtsRegionDesc ver,size */
        c2[8] = 0x10000;                  /* frtsOffset 0x10000000 >> 12 */
        c2[9] = 0x100;
        c2[10] = 2;
        mapper2[11] = FWSEC_CMD_FRTS;
        Print(L"[2] mapper init_cmd=0x%x cmd_in_off=0x%x frts4k=0x%x\n",
              mapper2[11], cmdInOff2, c2[8]);
    }

    /* как драйвер (трейс 539.410): BCR=0, RM, DMACTL=0 + 0x110080/0x110004/0x1103e8 */
    mmio_write32(GSP_BCR, 0x0);
    for (i = 0; i < 16; i++) mmio_read32(GSP_BCR);
    mmio_write32(GSP_RM, 0xb72000a1);
    mmio_write32(GSP_DMACTL, 0x0);
    mmio_write32(0x110080, 0x0);
    mmio_write32(0x110004, 0x40);
    mmio_write32(0x1103E8, 0x1);

    Print(L"[2] DMA IMEM SEC=1 0xE200 б...\n");
    gsp_dma_transfer(0, 0, fwsecPhys, FWSEC_CODE_SIZE,
                     0 | (6 << 8) | (0 << 12) | (1 << 4) | (1 << 2));
    Print(L"[2] DMA DMEM SEC=0 0x800 б...\n");
    gsp_dma_transfer(0, 0, fwsecPhys + FWSEC_DATA_OFF, FWSEC_DMEM_SIZE,
                     0 | (6 << 8) | (0 << 12));

    mmio_write32(GSP_BROM_PARAADDR0, FWSEC_SIG_DMEM_ADDR);
    mmio_write32(GSP_BROM_ENGIDMASK, FWSEC_ENGID_MASK);
    mmio_write32(GSP_BROM_CURR_UCODE_ID, FWSEC_UCORE_ID);
    mmio_write32(GSP_MOD_SEL, 0x1);
    mmio_write32(GSP_BOOTVEC, 0);
    __asm__ volatile("wbinvd" ::: "memory");
    mmio_write32(GSP_CPUCTL, 2);

    Print(L"[2] жду WPR2 (наш код → lo=0x100000; предзагруженный → 0x27FE000):\n");
    for (i = 0; i < 2000; i++) {
        UINT32 lo = mmio_read32(REG_PFB_MMU_WPR2_LO);
        UINT32 hi = mmio_read32(REG_PFB_MMU_WPR2_HI);
        if ((lo & 0xFFFFFFF0) == 0x00100000) {
            Print(L"[2] *** WPR2=0x%08x%08x — НАШ модиф. код выполнился! "
                  L"SEC=1 на GSP РАБОТАЕТ после booter! ***\n", hi, lo);
            ourCode = TRUE;
            break;
        }
        if ((i % 200) == 0)
            Print(L"[2] t=%dms wpr2lo=0x%08x wpr2hi=0x%08x gsp=0x%x dbg=0x%x\n",
                  i, lo, hi, mmio_read32(GSP_CPUCTL), mmio_read32(GSP_BASE + 0x94));
        uefi_call_wrapper(BS->Stall, 1, 1000);
    }
    Print(L"[2] итог: wpr2lo=0x%08x hi=0x%08x (%s)\n",
          mmio_read32(REG_PFB_MMU_WPR2_LO), mmio_read32(REG_PFB_MMU_WPR2_HI),
          ourCode ? L"НАШ КОД!" : L"предзагруженный код — SEC=1 всё ещё закрыт");
    dump_regs(L"[2-fwsec]");

    /* ---------- Стадия 3a (v2.48): ЗОНД ДОСТАВКИ DMA в IMEM SEC2 ----------
     * Вопрос: доставляет ли SEC2 IMEM DMA контент? Порты IMEM[0]=DEAD5EC1 —
     * не видно. Зонд: SEC=0 DMA маркер в IMEM[0x8000], SEC=1 DMA маркер в
     * IMEM[0x8400], читаем оба через порты (ns + secure bit28).
     *   SEC=0 лег, SEC=1 нет → SEC=1 на SEC2 scrub (канал закрыт) — H1.
     *   оба легли → 0x780009 от BROM-предусловия (не от пустого IMEM) — H2. */
    Print(L"\n[3a] ЗОНД доставки DMA в SEC2 IMEM (v2.48)...\n");
    {
        UINT32 marker0 = 0x11111111, marker1 = 0x22222222;
        UINT32 vns, vsec;

        /* SEC2 reset + BCR=0 */
        mmio_write32(SEC2_ENGINE, 0x1);
        for (i = 0; i < 16; i++) mmio_read32(SEC2_ENGINE);
        mmio_write32(SEC2_ENGINE, 0x0);
        for (i = 0; i < 16; i++) mmio_read32(SEC2_ENGINE);
        uefi_call_wrapper(BS->Stall, 1, 50000);
        mmio_write32(SEC2_BCR_CTRL, 0x0);
        for (i = 0; i < 16; i++) mmio_read32(SEC2_BCR_CTRL);
        uefi_call_wrapper(BS->Stall, 1, 10000);

        /* маркер-буфер: 0x100 байт = 64 × 0x11111111 */
        {
            UINT64 probePhys = 0;
            UINT32 *pbuf;

            if (!EFI_ERROR(alloc_below_4g(1, &probePhys))) {
                pbuf = (UINT32*)(UINTN)probePhys;
                for (i = 0; i < 0x100 / 4; i++) pbuf[i] = marker0;
                mmio_write32(SEC2_DMATRFBASE, (UINT32)(probePhys >> 8));
                mmio_write32(SEC2_DMATRFBASE1, 0);
                /* SEC=0 DMA → IMEM[0x8000] */
                mmio_write32(SEC2_DMATRFMOFFS, 0x8000);
                mmio_write32(SEC2_DMATRFFBOFFS, 0);
                mmio_write32(SEC2_DMATRFCMD, 0 | (6 << 8) | (1 << 4));
                falcon_dma_wait_idle();
                mmio_write32(SEC2_IMEMC0, 0x8000);
                vns = mmio_read32(SEC2_IMEMD0);
                mmio_write32(SEC2_IMEMC0, 0x8000 | (1 << 28));
                vsec = mmio_read32(SEC2_IMEMD0);
                Print(L"[3a] SEC=0 → IMEM[0x8000]: ns=0x%08x sec=0x%08x "
                      L"(ожидаю 0x11111111; DEAD5EC1 = scrub)\n", vns, vsec);

                for (i = 0; i < 0x100 / 4; i++) pbuf[i] = marker1;
                mmio_write32(SEC2_DMATRFBASE, (UINT32)(probePhys >> 8));
                mmio_write32(SEC2_DMATRFBASE1, 0);
                /* SEC=1 DMA → IMEM[0x8400] */
                mmio_write32(SEC2_DMATRFMOFFS, 0x8400);
                mmio_write32(SEC2_DMATRFFBOFFS, 0);
                mmio_write32(SEC2_DMATRFCMD, 0 | (6 << 8) | (1 << 4) | (1 << 2));
                falcon_dma_wait_idle();
                mmio_write32(SEC2_IMEMC0, 0x8400);
                vns = mmio_read32(SEC2_IMEMD0);
                mmio_write32(SEC2_IMEMC0, 0x8400 | (1 << 28));
                vsec = mmio_read32(SEC2_IMEMD0);
                Print(L"[3a] SEC=1 → IMEM[0x8400]: ns=0x%08x sec=0x%08x "
                      L"(ожидаю 0x22222222; DEAD5EC1 = scrub)\n", vns, vsec);
            } else {
                Print(L"[3a] alloc probe: %r\n", probePhys);
            }
        }
    }

    /* ---------- Стадия 3b (v2.49): SEC2 booter load — ПРАВИЛЬНЫЕ размеры ----
     * Ground truth (2026-08-21, живой драйвер, CMP90_BLDUMP_HS + трейс):
     *   imemSize=0x8900, imemVa=0x100 (FBOFFS стартует 0x100), dataOffset=0x8A00,
     *   dmemSize=0x6200, hsSigDmemAddr=0x10, ucodeId=3, engmask=1, BOOTVEC=0x100.
     * Размеры 0x4F00/0x5000/0x4D00 (v2.41) — ИЛЛЮЗИЯ обрезанного/rate-limited
     * трейса! При правильном dataOffset=0x8A00 сигнатура image[0x8A10]
     * естественно ложится на DMEM[0x10] (paraaddr) — патч не нужен.
     * WPR meta: sysmemAddrOfSignature = V67 (0xFA00) — canary-баг в booter'е
     * при обработке сигнатуры запустит ROP-цепочку → PLM OPEN.
     * Доставка IMEM: A) DMA SEC=1 (как драйвер), B) порты IMEMC (v2.18). */
    Print(L"\n[3b/3] SEC2 booter load ucodeId=3 — ПРАВИЛЬНЫЕ размеры "
          L"(0x8900/0x8A00/0x6200, V67-сигнатура)\n");
    /* свежая копия образа (стадия 1 патчила src[0x6010] внутри data-региона) */
    CopyMem((VOID*)(UINTN)ucodePhys, booter_ucode_prod, BOOTER_UCODE_SIZE);

    {
        UINTN p;
        BOOLEAN portLoad;

        for (portLoad = FALSE; ; portLoad = TRUE) {
            Print(L"[3b] вариант %s (%s IMEM)...\n",
                  portLoad ? L"B: порты" : L"A: DMA",
                  portLoad ? L"IMEMC/IMEMD, SECURE bit28" : L"DMA SEC=1");

            /* WPR2 нормализуем (booter валидирует раскладку) */
            mmio_write32(REG_PFB_MMU_WPR2_LO, TARGET_WPR2_LO);
            mmio_write32(REG_PFB_MMU_WPR2_HI, TARGET_WPR2_HI);
            uefi_call_wrapper(BS->Stall, 1, 10000);

            /* SEC2 reset + BCR=0 (kflcnReset как драйвер) */
            mmio_write32(SEC2_ENGINE, 0x1);
            for (i = 0; i < 16; i++) mmio_read32(SEC2_ENGINE);
            mmio_write32(SEC2_ENGINE, 0x0);
            for (i = 0; i < 16; i++) mmio_read32(SEC2_ENGINE);
            uefi_call_wrapper(BS->Stall, 1, 50000);
            mmio_write32(SEC2_BCR_CTRL, 0x0);
            for (i = 0; i < 16; i++) mmio_read32(SEC2_BCR_CTRL);
            uefi_call_wrapper(BS->Stall, 1, 10000);

            data = mmio_read32(SEC2_FBIF_CTL);
            data |= (1 << 7);
            mmio_write32(SEC2_FBIF_CTL, data);
            mmio_write32(SEC2_DMACTL, 0);
            mmio_write32(SEC2_RM, 0xb72000a1);
            data = mmio_read32(SEC2_FBIF_TRANSCFG0);
            data = (data & ~0x7) | 0x5;
            mmio_write32(SEC2_FBIF_TRANSCFG0, data);

            if (!portLoad) {
                /* A: DMA — IMEM 0x8900 SEC=1 (src+0x100), DMEM 0x6200 SEC=0
                 * (src+0x8A00 — сигнатура ложится на DMEM[0x10] сама!) */
                Print(L"[3b-A] DMA IMEM SEC=1 (0x8900 б, src+0x100)...\n");
                falcon_dma_transfer(0, 0x100, ucodePhys, 0x8900,
                                    0 | (6 << 8) | (0 << 12) | (1 << 4) | (1 << 2));
                Print(L"[3b-A] DMA DMEM SEC=0 (0x6200 б, src+0x8A00)...\n");
                falcon_dma_transfer(0, 0, ucodePhys + 0x8A00, 0x6200,
                                    0 | (6 << 8) | (0 << 12));
            } else {
                /* B: порты — IMEM image[0x100..0x89FF] → IMEM[0..0x88FF]
                 * (SECURE bit28), DMEM image[0x8A00..0xEBFF] → DMEM[0..0x61FF] */
                const UINT8 *img = (const UINT8*)(UINTN)ucodePhys;
                Print(L"[3b-B] порты IMEM (SECURE, 0x8900 б)...\n");
                mmio_write32(SEC2_IMEMC0, (1 << 28) | (1 << 24));  /* SECURE|AINCW */
                for (i = 0; i < 0x8900 / 4; i++)
                    mmio_write32(SEC2_IMEMD0,
                        *(UINT32*)(img + 0x100 + i * 4));
                Print(L"[3b-B] порты DMEM (0x6200 б)...\n");
                mmio_write32(SEC2_DMEMC0, (1 << 24));              /* AINCW */
                for (i = 0; i < 0x6200 / 4; i++)
                    mmio_write32(SEC2_DMEMD0,
                        *(UINT32*)(img + 0x8A00 + i * 4));
            }

            /* верификация */
            mmio_write32(SEC2_IMEMC0, (1 << 28));
            data = mmio_read32(SEC2_IMEMD0);
            mmio_write32(SEC2_IMEMC0, (1 << 28) | 0x100);
            Print(L"[3b] IMEM_S[0]=0x%08x IMEM_S[0x100]=0x%08x "
                  L"(ожидаю %08x — код)\n", data, mmio_read32(SEC2_IMEMD0),
                  *(UINT32*)((UINTN)ucodePhys + 0x100));
            mmio_write32(SEC2_DMEMC0, 0x10);
            Print(L"[3b] DMEM[0x10]=0x%08x (ожидаю a9d43de4 — sig!)\n",
                  mmio_read32(SEC2_DMEMD0));

            mmio_write32(SEC2_BROM_PARAADDR0, BOOTER_HS_SIG_DMEM_ADDR);
            mmio_write32(SEC2_BROM_ENGIDMASK, BOOTER_ENGINE_ID_MASK);
            mmio_write32(SEC2_BROM_CURR_UCODE_ID, BOOTER_UCODE_ID);
            data = mmio_read32(SEC2_MOD_SEL);
            data = (data & ~0xFF) | 0x1;          /* RSA3K */
            mmio_write32(SEC2_MOD_SEL, data);
            mmio_write32(SEC2_BOOTVEC, 0x100);
            mmio_write32(SEC2_MAILBOX0, (UINT32)(cmp90_meta_low(wprMetaPhys) & 0xFFFFFFFF));
            mmio_write32(SEC2_MAILBOX1, (UINT32)((cmp90_meta_low(wprMetaPhys) >> 32) & 0xFFFFFFFF));
            __asm__ volatile("wbinvd" ::: "memory");
            mmio_write32(SEC2_CPUCTL, NV_PFALCON_FALCON_CPUCTL_STARTCPU_TRUE);

            Print(L"[3b] CPU started, polling PLM до 5с (V67-цепочка)...\n");
            for (p = 0; p < 5000; p++) {
                if (mmio_read32(REG_FEAT_OVR_PLM) == VAL_PLM_OPEN) {
                    Print(L"[3b-%s] *** PLM OPEN после %d ms! ***\n",
                          portLoad ? L"B" : L"A", p);
                    plmOpen = TRUE;
                    break;
                }
                if ((p % 1000) == 0)
                    Print(L"[3b-%s] t=%dms PLM=0x%08x cpu=0x%x dbg=0x%x mbox0=0x%x\n",
                          portLoad ? L"B" : L"A", p, mmio_read32(REG_FEAT_OVR_PLM),
                          mmio_read32(SEC2_CPUCTL), mmio_read32(SEC2_DEBUGINFO),
                          mmio_read32(SEC2_MAILBOX0));
                uefi_call_wrapper(BS->Stall, 1, 1000);
            }
            Print(L"[3b-%s] итог: PLM=0x%08x cpu=0x%x irq=0x%x dbg=0x%x mbox0=0x%x\n",
                  portLoad ? L"B" : L"A", mmio_read32(REG_FEAT_OVR_PLM),
                  mmio_read32(SEC2_CPUCTL), mmio_read32(SEC2_IRQSTAT),
                  mmio_read32(SEC2_DEBUGINFO), mmio_read32(SEC2_MAILBOX0));
            if (plmOpen || portLoad)
                break;   /* оба варианта проверены */
        }
    }
    dump_regs(L"[3b-sec2]");

    /* ---------- Стадия 3c (v2.50): GSP-DIRECT booter load (SEC2 ucode на GSP)
     * SEC2 IMEM с хоста НЕ пишется (v2.48/2.49: DMA scrub, порты DEAD5EC1) —
     * а GSP IMEM пишется (v2.46: SEC=1 доставляет!). Грузим SEC2 booter
     * (правильные размеры 0x8900/0x8A00/0x6200!) в GSP IMEM/DMEM, BROM params
     * GSP (ucodeId=3, engmask=0x400), mailboxes=WPR meta (V67-сигнатура!).
     * Если GSP BROM верифицирует sig_dbg (DMEM[0x10]) и запустит booter —
     * booter обработает V67-сигнатуру → canary-баг → ROP → PLM OPEN! */
    Print(L"\n[3c] GSP-DIRECT booter load (SEC2 ucode на GSP, V67)...\n");
    {
        UINTN p;
        UINT32 ucodeIdTry;

        for (ucodeIdTry = 3; ucodeIdTry <= 9; ucodeIdTry += 6) {
            /* свежая копия образа */
            CopyMem((VOID*)(UINTN)ucodePhys, booter_ucode_prod, BOOTER_UCODE_SIZE);

            Print(L"[3c] ucodeId=%d engmask=0x400 (GSP)...\n", ucodeIdTry);

            /* GSP ENGINE reset (как kflcnReset) */
            mmio_write32(GSP_ENGINE, 0x1);
            for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
            mmio_write32(GSP_ENGINE, 0x0);
            for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
            uefi_call_wrapper(BS->Stall, 1, 50000);
            mmio_write32(GSP_BCR, 0x0);
            for (i = 0; i < 16; i++) mmio_read32(GSP_BCR);
            uefi_call_wrapper(BS->Stall, 1, 10000);

            /* WPR2 нормализуем */
            mmio_write32(REG_PFB_MMU_WPR2_LO, TARGET_WPR2_LO);
            mmio_write32(REG_PFB_MMU_WPR2_HI, TARGET_WPR2_HI);
            uefi_call_wrapper(BS->Stall, 1, 10000);

            data = mmio_read32(GSP_FBIF_CTL);
            data |= (1 << 7);
            mmio_write32(GSP_FBIF_CTL, data);
            mmio_write32(GSP_DMACTL, 0);
            mmio_write32(GSP_RM, 0xb72000a1);
            data = mmio_read32(GSP_FBIF_TRANSCFG0);
            data = (data & ~0x7) | 0x5;
            mmio_write32(GSP_FBIF_TRANSCFG0, data);

            Print(L"[3c] DMA IMEM SEC=1 (0x8900 б, src+0x100) в GSP IMEM...\n");
            gsp_dma_transfer(0, 0x100, ucodePhys, 0x8900,
                             0 | (6 << 8) | (0 << 12) | (1 << 4) | (1 << 2));
            Print(L"[3c] DMA DMEM SEC=0 (0x6200 б, src+0x8A00) в GSP DMEM...\n");
            gsp_dma_transfer(0, 0, ucodePhys + 0x8A00, 0x6200,
                             0 | (6 << 8) | (0 << 12));

            /* верификация */
            mmio_write32(GSP_BASE + 0x1C0, 0x10);
            Print(L"[3c] GSP DMEM[0x10]=0x%08x (ожидаю a9d43de4 — sig)\n",
                  mmio_read32(GSP_BASE + 0x1C4));
            mmio_write32(GSP_BASE + 0x180, (1 << 28));
            Print(L"[3c] GSP IMEM_S[0]=0x%08x (ожидаю 29f1b35e — код)\n",
                  mmio_read32(GSP_BASE + 0x184));

            mmio_write32(GSP_BROM_PARAADDR0, 0x10);
            mmio_write32(GSP_BROM_ENGIDMASK, 0x400);
            mmio_write32(GSP_BROM_CURR_UCODE_ID, ucodeIdTry);
            mmio_write32(GSP_MOD_SEL, 0x1);              /* RSA3K */
            mmio_write32(GSP_BOOTVEC, 0x100);
            mmio_write32(GSP_MAILBOX0, (UINT32)(wprMetaPhys & 0xFFFFFFFF));
            mmio_write32(GSP_MAILBOX1, (UINT32)((wprMetaPhys >> 32) & 0xFFFFFFFF));
            __asm__ volatile("wbinvd" ::: "memory");
            mmio_write32(GSP_CPUCTL, NV_PFALCON_FALCON_CPUCTL_STARTCPU_TRUE);

            Print(L"[3c] STARTCPU (GSP), polling PLM до 5с (V67-цепочка)...\n");
            for (p = 0; p < 5000; p++) {
                if (mmio_read32(REG_FEAT_OVR_PLM) == VAL_PLM_OPEN) {
                    Print(L"[3c] *** PLM OPEN после %d ms! ***\n", p);
                    plmOpen = TRUE;
                    break;
                }
                if ((p % 1000) == 0)
                    Print(L"[3c] t=%dms PLM=0x%08x gsp=0x%x dbg=0x%x mbox0=0x%x\n",
                          p, mmio_read32(REG_FEAT_OVR_PLM),
                          mmio_read32(GSP_CPUCTL), mmio_read32(GSP_BASE + 0x94),
                          mmio_read32(GSP_MAILBOX0));
                uefi_call_wrapper(BS->Stall, 1, 1000);
            }
            Print(L"[3c] итог: PLM=0x%08x gsp=0x%x dbg=0x%x bcr=0x%x mbox0=0x%x\n",
                  mmio_read32(REG_FEAT_OVR_PLM), mmio_read32(GSP_CPUCTL),
                  mmio_read32(GSP_BASE + 0x94), mmio_read32(GSP_BCR),
                  mmio_read32(GSP_MAILBOX0));
            if (plmOpen || ucodeIdTry == 9)
                break;   /* оба ucodeId проверены */
        }
    }
    dump_regs(L"[3c-gsp-direct]");

    /* ---------- Финальные проверки ---------- */
    if (plmOpen || ourCode) {
        Print(L"v2.46: *** реплей дал результат — записываю SS0/SS1 ***\n");
        mmio_write32(REG_FEAT_OVR_SM_SPD_1, VAL_SS1_UNLOCKED);
        mmio_write32(REG_FEAT_OVR_SM_SPD, VAL_SS0_UNLOCKED);
        uefi_call_wrapper(BS->Stall, 1, 100000);
        dump_regs(L"[v2.46-unlock]");
    } else {
        Print(L"v2.46: результата нет. Пробую прямую запись SS0/SS1 "
              L"(rejoin15-style)...\n");
        mmio_write32(REG_FEAT_OVR_SM_SPD_1, VAL_SS1_UNLOCKED);
        mmio_write32(REG_FEAT_OVR_SM_SPD, VAL_SS0_UNLOCKED);
        uefi_call_wrapper(BS->Stall, 1, 100000);
        dump_regs(L"[v2.46-direct]");
    }
    return plmOpen || ourCode || is_unlocked();
}

/* ==== FALLBACK B: FWSEC re-load (FRTS then SB command) -> booter ====
 * Hypothesis: SEC2 IMEM DMA needs the HS state established by FWSEC's
 * SB command. Reloads our FWSEC blob onto GSP (GSP key, sig[2]),
 * FRTS (WPR2) -> SB (privmask) -> SEC2 booter load with correct sizes
 * + V67 signature; stage [4] also tries the VBIOS-preloaded SEC2 ucode
 * (ucodeId=10, appid 0x49 DBG / 0x89 PROD). Legacy ladder member.
 * Гипотеза: SEC2 IMEM DMA требует HS-состояния, которое задаёт SB-команда
 * FWSEC (v2.40: после SB halt SEC2 меняется 0x780009 → dbg=0x0). Драйвер
 * ПЕРЕЗАГРУЖАЕТ FWSEC на GSP (наша копия того же блоба — GSP-ключ! sig[2]
 * PROD) — если GSP BROM примет наш копию, FRTS+SB отработают и SEC2 откроется.
 * Порядок (как драйвер): FWSEC re-load (FRTS→WPR2, затем SB) → SEC2 booter
 * load (ПРАВИЛЬНЫЕ размеры 0x8900/0x8A00/0x6200, V67-сигнатура в meta).
 * БЕЗ разрушительной стадии 1 (не убиваем предзагруженный код заранее). */
static BOOLEAN
driver_replay_v251(UINT64 fwsecPhys, UINT64 ucodePhys, UINT64 wprMetaPhys)
{
    UINTN i;
    UINT32 data;
    BOOLEAN fwsecOk = FALSE;
    BOOLEAN sbChanged = FALSE;
    BOOLEAN plmOpen = FALSE;

    Print(L"\n=== v2.51: FWSEC re-load + SB → SEC2 booter (V67) ===\n");
    Print(L"исходное: PLM=0x%08x SS0=0x%08x WPR2lo=0x%08x privmask=0x%08x\n",
          mmio_read32(REG_FEAT_OVR_PLM), mmio_read32(REG_FEAT_OVR_SM_SPD),
          mmio_read32(REG_PFB_MMU_WPR2_LO), mmio_read32(0x00118128));

    /* ---------- 1. FWSEC FRTS (ПОЛНАЯ последовательность v2.28-34!)
     * v2.51-1b показал: БЕЗ IMEM DMA STARTCPU не исполняет код (gsp halted
     * dbg=0x0). В v2.28-34 WPR2 ставился за 9мс — там был IMEM SEC=1 DMA
     * (0xE200) + DMEM (FRTS) + BROM + STARTCPU. Воспроизводим точно:
     * IMEM DMA доставляет (v2.46) — BROM принимает FWSEC (GSP-ключ + sig[2]). */
    Print(L"[1] FWSEC FRTS (полная v2.28-34: IMEM+DMEM+FRTS)...\n");
    {
        UINT8 *buf = (UINT8*)(UINTN)fwsecPhys;
        UINT32 *mapper2 = (UINT32*)(buf + FWSEC_DATA_OFF + 0x560);
        UINT32 cmdInOff2 = mapper2[2];
        UINT32 *c2 = (UINT32*)(buf + cmdInOff2);

        CopyMem(buf, fwsec_ga104_bin, FWSEC_SIZE);
        CopyMem(buf + FWSEC_DATA_OFF + FWSEC_SIG_DMEM_ADDR,
                fwsec_ga104_sig, FWSEC_SIG_SIZE);
        c2[0] = 1; c2[1] = 24;
        c2[2] = 0; c2[3] = 0;
        c2[4] = 0; c2[5] = 2;
        c2[6] = 1; c2[7] = 20;
        c2[8] = FWSEC_FRTS_OFFSET >> 12;      /* 0x27FE000 */
        c2[9] = 0x100;
        c2[10] = 2;
        mapper2[11] = FWSEC_CMD_FRTS;
    }

    /* GSP ENGINE reset (убить GFW, предзагруженный FWSEC переживает reset) */
    falcon_wait_reset_ready(L"rr: gsp engine reset GFW kill", GSP_HWCFG2, GSP_CPUCTL);
    mmio_write32(GSP_ENGINE, 0x1);
    for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
    mmio_write32(GSP_ENGINE, 0x0);
    for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
    falcon_wait_scrub_done(GSP_DMACTL, GSP_HWCFG2, L"gsp-reset");
    /* v3.38, ЭТАП 21: Stall(50000) -> Stall(10000). ПЕРВЫЙ срез ВНЕ
     * early_unlock_path. До этого срезались только три паузы внутри неё
     * (6689, 6772, 6880) - все дали ровно 40,0 мс на вызов при 100% успеха.
     *
     * ЧТО ЭТО ЗА САЙТ. Связка 'falcon_wait_scrub_done -> Stall(50000)' -
     * идиома проекта, а не единичный случай: сайтов 12, из них 8 несут 50 мс.
     * Этот стоит сразу ПОСЛЕ doomed-ожидания
     * falcon_wait_reset_ready("rr: gsp engine reset GFW kill"), которое
     * никогда не срабатывает и всегда съедает 260 мс.
     *
     * ЧИСЛО ВЫЗОВОВ ИЗМЕРЕНО, НЕ УГАДАНО. Атрибуция получена из самого лога,
     * без нового прогона: повторяющиеся теги SCRUB разделяются по следующей
     * за ними строке.
     *     gsp-reset -> DMAQ             x9  (это 6689, уже срезанная)
     *     gsp-reset -> FWSEC reflashed  x9  (этот)
     *     sec2-reset -> TIME            x8  (это 7490, следующий)
     * Сходится с общими счётчиками: gsp-reset 9+9+1 = 19, sec2-reset 8+1 = 9.
     *
     *   9 вызовов x 40 мс = 360 мс
     *   16 021 - 360 = 15 661 мс   (ожидаем ~15,7 с)
     *
     * ВОЗМОЖНЫЙ БОНУС, НЕ ОБЕЩАН. В v3.37 срез третьей паузы дал 658 мс вместо
     * 360: исчезло одно неуспешное ожидание GFW kill (вызовов стало 2 -> 1).
     * Здесь та же связка, поэтому бонус возможен, но стабильность по одному
     * прогону неизвестна, и закладывать его в прогноз нельзя.
     *
     * ОДНА ПРАВКА ЗА ПРОГОН. Рядом стоит такой же сайт 7490 (~320 мс), но
     * срезать оба сразу нельзя: если рендер сломается, причина станет
     * неоднозначной.
     */
    uefi_call_wrapper(BS->Stall, 1, 10000);
    mmio_write32(GSP_BCR, 0x1);                 /* CORE_SELECT=FALCON (v2.28-34!) */
    for (i = 0; i < 16; i++) mmio_read32(GSP_BCR);
    mmio_write32(GSP_RM, mmio_read32(0x00100000));  /* PMC_BOOT_0 (v2.28-34!) */
    uefi_call_wrapper(BS->Stall, 1, 10000);

    data = mmio_read32(GSP_FBIF_CTL);
    data |= (1 << 7);
    mmio_write32(GSP_FBIF_CTL, data);
    mmio_write32(GSP_DMACTL, 0);
    data = mmio_read32(GSP_FBIF_TRANSCFG0);
    data = (data & ~0x7) | 0x5;
    mmio_write32(GSP_FBIF_TRANSCFG0, data);

    Print(L"[1] DMA IMEM SEC=1 (0xE200 б)...\n");
    gsp_dma_transfer(0, 0, fwsecPhys, FWSEC_CODE_SIZE,
                     0 | (6 << 8) | (0 << 12) | (1 << 4) | (1 << 2));
    Print(L"[1] DMA DMEM SEC=0 (0x800 б, FRTS cmd)...\n");
    gsp_dma_transfer(0, 0, fwsecPhys + FWSEC_DATA_OFF, FWSEC_DMEM_SIZE,
                     0 | (6 << 8) | (0 << 12));

    mmio_write32(GSP_BROM_PARAADDR0, FWSEC_SIG_DMEM_ADDR);
    mmio_write32(GSP_BROM_ENGIDMASK, FWSEC_ENGID_MASK);
    mmio_write32(GSP_BROM_CURR_UCODE_ID, FWSEC_UCORE_ID);
    mmio_write32(GSP_MOD_SEL, 0x1);              /* RSA3K */
    mmio_write32(GSP_BOOTVEC, 0);
    __asm__ volatile("wbinvd" ::: "memory");
    mmio_write32(GSP_CPUCTL, NV_PFALCON_FALCON_CPUCTL_STARTCPU_TRUE);

    Print(L"[1] жду WPR2 до 5с (предзагруженный FWSEC + наш FRTS → 0x%08X):\n",
          TARGET_WPR2_LO);
    for (i = 0; i < 5000; i++) {
        UINT32 lo = mmio_read32(REG_PFB_MMU_WPR2_LO);
        UINT32 hi = mmio_read32(REG_PFB_MMU_WPR2_HI);
        if ((lo & 0xFFFFFFF0) == (TARGET_WPR2_LO & 0xFFFFFFF0) &&
            (hi & 0xFFFFFFF0) == (TARGET_WPR2_HI & 0xFFFFFFF0)) {
            Print(L"[1] *** WPR2 УСТАНОВЛЕН lo=0x%08x hi=0x%08x после %d ms "
                  L"— предзагруженный FWSEC выполнил наш FRTS! ***\n",
                  lo, hi, i);
            fwsecOk = TRUE;
            break;
        }
        if ((i % 1000) == 0)
            Print(L"[1] t=%dms wpr2lo=0x%08x gsp=0x%x dbg=0x%x\n",
                  i, lo, mmio_read32(GSP_CPUCTL), mmio_read32(GSP_BASE + 0x94));
        uefi_call_wrapper(BS->Stall, 1, 1000);
    }
    Print(L"[1] итог: WPR2=%s (lo=0x%08x hi=0x%08x)\n",
          fwsecOk ? L"УСТАНОВЛЕН" : L"НЕ установлен",
          mmio_read32(REG_PFB_MMU_WPR2_LO), mmio_read32(REG_PFB_MMU_WPR2_HI));
    dump_regs(L"[1-fwsec]");

    /* ---------- 2. SB-команда (0x19) через FWSEC ---------- */
    {
        UINT8 *buf = (UINT8*)(UINTN)fwsecPhys;
        UINT32 *mapper2 = (UINT32*)(buf + FWSEC_DATA_OFF + 0x560);
        UINT32 priv0 = mmio_read32(0x00118128);
        UINT32 privA;

        mapper2[11] = 0x19;                    /* SB */
        gsp_dma_transfer(0, 0, fwsecPhys + FWSEC_DATA_OFF,
                         FWSEC_DMEM_SIZE, 0 | (6 << 8) | (0 << 12));
        mmio_write32(GSP_BOOTVEC, 0);
        __asm__ volatile("wbinvd" ::: "memory");
        mmio_write32(GSP_CPUCTL, NV_PFALCON_FALCON_CPUCTL_STARTCPU_TRUE);
        uefi_call_wrapper(BS->Stall, 1, 500000);
        privA = mmio_read32(0x00118128);
        sbChanged = (privA != priv0);
        Print(L"[2] SB (0x19): privmask 0x%08x → 0x%08x%s\n",
              priv0, privA, sbChanged ? L" <<< ИЗМЕНЕНИЕ (SB сработал!)" : L"");
        dump_regs(L"[2-sb]");
    }

    /* ---------- 3. SEC2 booter load (правильные размеры + V67) ---------- */
    Print(L"[3] SEC2 booter load ucodeId=3 (0x8900/0x8A00/0x6200, V67)...\n");
    CopyMem((VOID*)(UINTN)ucodePhys, booter_ucode_prod, BOOTER_UCODE_SIZE);

    mmio_write32(REG_PFB_MMU_WPR2_LO, TARGET_WPR2_LO);
    mmio_write32(REG_PFB_MMU_WPR2_HI, TARGET_WPR2_HI);
    uefi_call_wrapper(BS->Stall, 1, 10000);

    falcon_wait_reset_ready(L"rr: post-WPR2 sec2 ready", SEC2_HWCFG2, SEC2_CPUCTL);
    mmio_write32(SEC2_ENGINE, 0x1);
    for (i = 0; i < 16; i++) mmio_read32(SEC2_ENGINE);
    mmio_write32(SEC2_ENGINE, 0x0);
    for (i = 0; i < 16; i++) mmio_read32(SEC2_ENGINE);
    falcon_wait_scrub_done(SEC2_DMACTL, SEC2_HWCFG2, L"sec2-reset");
    /* v3.39, ЭТАП 22: Stall(50000) -> Stall(10000). ВТОРОЙ горячий сайт идиомы
     * 'falcon_wait_scrub_done -> Stall(50000)', после первого (строка 7403,
     * срезан в v3.38). Стоит сразу ПОСЛЕ doomed-ожидания
     * falcon_wait_reset_ready("rr: post-WPR2 sec2 ready") - второго из двух,
     * что никогда не срабатывают.
     *
     * ЧИСЛО ВЫЗОВОВ ИЗМЕРЕНО, НЕ УГАДАНО: 8, получено из лога разбором узоров
     * 'SCRUB-тег -> следующая строка'. 'sec2-reset -> TIME' x8, и это
     * единственный такой узор. Сходится: sec2-reset 8 + 1 = 9.
     *
     * ОДНОЗНАЧНОСТЬ САЙТА ПРОВЕРЕНА. 'sec2-reset' встречается в коде трижды:
     * строки 6243, 7520 и 7738. На прошлом этапе я попал не в тот сайт, потому
     * что два из них имеют ИДЕНТИЧНЫЙ текст falcon_wait_scrub_done(SEC2_DMACTL,
     * SEC2_HWCFG2, L"sec2-reset") и следующий Stall(50000). Здесь условие
     * добавлено - сайт рядом с 'post-WPR2 sec2 ready'.
     *
     *   8 вызовов x 40 мс = 320 мс
     *   15 303 - 320 = 14 983 мс
     *
     * ЧЕСТНО ПРО ПРОГНОЗ. Два последних прогона дали результат ЛУЧШЕ расчёта на
     * 298 и 358 мс, причём второй раз отклонение затронуло секцию
     * 'render: FLR settle', которую я не менял, и механизм я объяснить не могу.
     * Эту положительную поправку в прогноз НЕ ЗАКЛАДЫВАЮ: реалистично
     * ожидаю 14,6-15,0 с, называю отдельно, но считаю честной цифрой 14 983.
     *
     * Если это последний срезаемый сайт и всё сложится, дальше останется
     * QUIESCE 250 -> 200 мс (~500 мс, шанс ~50%, порог в (150 мс; 250 мс]) -
     * единственный остающийся gamble, а не перенос доказанного порога.
     */
    uefi_call_wrapper(BS->Stall, 1, 10000);
    mmio_write32(SEC2_BCR_CTRL, 0x0);
    for (i = 0; i < 16; i++) mmio_read32(SEC2_BCR_CTRL);
    uefi_call_wrapper(BS->Stall, 1, 10000);

    data = mmio_read32(SEC2_FBIF_CTL);
    data |= (1 << 7);
    mmio_write32(SEC2_FBIF_CTL, data);
    mmio_write32(SEC2_DMACTL, 0);
    mmio_write32(SEC2_RM, 0xb72000a1);
    data = mmio_read32(SEC2_FBIF_TRANSCFG0);
    data = (data & ~0x7) | 0x5;
    mmio_write32(SEC2_FBIF_TRANSCFG0, data);

    Print(L"[3] DMA IMEM SEC=1 (0x8900 б, src+0x100)...\n");
    falcon_dma_transfer(0, 0x100, ucodePhys, 0x8900,
                        0 | (6 << 8) | (0 << 12) | (1 << 4) | (1 << 2));
    Print(L"[3] DMA DMEM SEC=0 (0x6200 б, src+0x8A00)...\n");
    falcon_dma_transfer(0, 0, ucodePhys + 0x8A00, 0x6200,
                        0 | (6 << 8) | (0 << 12));

    mmio_write32(SEC2_DMEMC0, 0x10);
    Print(L"[3] DMEM[0x10]=0x%08x (ожидаю a9d43de4 — sig)\n",
          mmio_read32(SEC2_DMEMD0));

    mmio_write32(SEC2_BROM_PARAADDR0, BOOTER_HS_SIG_DMEM_ADDR);
    mmio_write32(SEC2_BROM_ENGIDMASK, BOOTER_ENGINE_ID_MASK);
    mmio_write32(SEC2_BROM_CURR_UCODE_ID, BOOTER_UCODE_ID);
    data = mmio_read32(SEC2_MOD_SEL);
    data = (data & ~0xFF) | 0x1;          /* RSA3K */
    mmio_write32(SEC2_MOD_SEL, data);
    mmio_write32(SEC2_BOOTVEC, 0x100);
    mmio_write32(SEC2_MAILBOX0, (UINT32)(cmp90_meta_low(wprMetaPhys) & 0xFFFFFFFF));
    mmio_write32(SEC2_MAILBOX1, (UINT32)((cmp90_meta_low(wprMetaPhys) >> 32) & 0xFFFFFFFF));
    __asm__ volatile("wbinvd" ::: "memory");
    mmio_write32(SEC2_CPUCTL, NV_PFALCON_FALCON_CPUCTL_STARTCPU_TRUE);

    Print(L"[3] STARTCPU (SEC2), polling PLM до 5с (V67-цепочка)...\n");
    for (i = 0; i < 5000; i++) {
        if (mmio_read32(REG_FEAT_OVR_PLM) == VAL_PLM_OPEN) {
            Print(L"[3] *** PLM OPEN после %d ms! ***\n", i);
            plmOpen = TRUE;
            break;
        }
        if ((i % 1000) == 0)
            Print(L"[3] t=%dms PLM=0x%08x cpu=0x%x dbg=0x%x mbox0=0x%x\n",
                  i, mmio_read32(REG_FEAT_OVR_PLM), mmio_read32(SEC2_CPUCTL),
                  mmio_read32(SEC2_DEBUGINFO), mmio_read32(SEC2_MAILBOX0));
        uefi_call_wrapper(BS->Stall, 1, 1000);
    }
    Print(L"[3] итог: PLM=0x%08x cpu=0x%x irq=0x%x dbg=0x%x mbox0=0x%x\n",
          mmio_read32(REG_FEAT_OVR_PLM), mmio_read32(SEC2_CPUCTL),
          mmio_read32(SEC2_IRQSTAT), mmio_read32(SEC2_DEBUGINFO),
          mmio_read32(SEC2_MAILBOX0));
    dump_regs(L"[3-sec2-v251]");

    /* ---------- 4 (v2.54): SEC2 ПРЕДЗАГРУЖЕННЫЙ ucode (ucodeId=10!) ----------
     * В VBIOS есть SEC2 ucode (appid 0x49 DBG / 0x89 PROD): ucodeId=10,
     * engmask=1, imemLoad=0x4400, dmemLoad=0x8F4, pkc=0x6DC, iface=0x10.
     * VBIOS грузит его в SEC2 при POST (v2.38 «нет предзагрузки» — порты
     * врут!). BROM сверяет сигнатуру с РЕАЛЬНЫМ IMEM — у нас (ucodeId=3,
     * sig_dbg) сигнатура не совпадала → 0x780009! Теперь: ucodeId=10 +
     * сигнатура VBIOS на DMEM[0x6DC] — BROM проверит и ЗАПУСТИТ
     * предзагруженный код → он обработает WPR meta (V67-сигнатура!) →
     * canary-баг → ROP → PLM! IMEM DMA НЕ нужен (код уже там!). */
    Print(L"\n[4] SEC2 предзагруженный ucode (ucodeId=10, sig из VBIOS)...\n");
    {
        UINTN p;
        UINT32 appidTry = 0x89;
        UINT32 appidDone = 0;

        while (1) {
            const UINT8 *sec2img = (appidTry == 0x89)
                ? sec2_ucode_vbios_89 : sec2_ucode_vbios_49;
            const UINTN sec2size = (appidTry == 0x89)
                ? sec2_ucode_vbios_89_size : sec2_ucode_vbios_49_size;

            Print(L"[4] appid=0x%02x (ucodeId=10, 0x4400/0x8F4, pkc=0x6DC)...\n",
                  appidTry);
            CopyMem((VOID*)(UINTN)ucodePhys, sec2img, sec2size);

            /* SEC2 reset + BCR=0 + FBIF + DMACTL + RM */
            mmio_write32(SEC2_ENGINE, 0x1);
            for (i = 0; i < 16; i++) mmio_read32(SEC2_ENGINE);
            mmio_write32(SEC2_ENGINE, 0x0);
            for (i = 0; i < 16; i++) mmio_read32(SEC2_ENGINE);
            uefi_call_wrapper(BS->Stall, 1, 50000);
            mmio_write32(SEC2_BCR_CTRL, 0x0);
            for (i = 0; i < 16; i++) mmio_read32(SEC2_BCR_CTRL);
            uefi_call_wrapper(BS->Stall, 1, 10000);

            data = mmio_read32(SEC2_FBIF_CTL);
            data |= (1 << 7);
            mmio_write32(SEC2_FBIF_CTL, data);
            mmio_write32(SEC2_DMACTL, 0);
            mmio_write32(SEC2_RM, 0xb72000a1);
            data = mmio_read32(SEC2_FBIF_TRANSCFG0);
            data = (data & ~0x7) | 0x5;
            mmio_write32(SEC2_FBIF_TRANSCFG0, data);

            /* DMEM: данные из образа (imemLoad=0x4400, 0x8F4 б) — сигнатура
             * патчена на DMEM[0x6DC] */
            Print(L"[4] DMA DMEM SEC=0 (0x8F4 б, src+0x4400)...\n");
            falcon_dma_transfer(0, 0, ucodePhys + 0x4400, 0x8F4,
                                0 | (6 << 8) | (0 << 12));
            mmio_write32(SEC2_DMEMC0, 0x6DC);
            Print(L"[4] DMEM[0x6DC]=0x%08x (ожидаю sig[2][0]: %08x)\n",
                  mmio_read32(SEC2_DMEMD0),
                  *(UINT32*)((UINTN)sec2img + 0x4400 + 0x6DC));
            /* v2.55: дамп DMEM[0x600..0x700] в NS и SECURE-представлениях */
            {
                UINTN di;
                Print(L"[4] DMEM dump (NS  |  SEC):\n");
                for (di = 0x600; di < 0x700; di += 0x40) {
                    UINT32 vn0, vs0;
                    mmio_write32(SEC2_DMEMC0, di);
                    vn0 = mmio_read32(SEC2_DMEMD0);
                    mmio_write32(SEC2_DMEMC0, di | (1 << 28));
                    vs0 = mmio_read32(SEC2_DMEMD0);
                    Print(L"[4]   %04x: ns=0x%08x sec=0x%08x\n", di, vn0, vs0);
                }
            }

            mmio_write32(SEC2_BROM_PARAADDR0, 0x6DC);
            mmio_write32(SEC2_BROM_ENGIDMASK, 1);
            mmio_write32(SEC2_BROM_CURR_UCODE_ID, 10);
            data = mmio_read32(SEC2_MOD_SEL);
            data = (data & ~0xFF) | 0x1;          /* RSA3K */
            mmio_write32(SEC2_MOD_SEL, data);
            mmio_write32(SEC2_BOOTVEC, 0);        /* imemVa=0 */
            mmio_write32(SEC2_MAILBOX0, (UINT32)(cmp90_meta_low(wprMetaPhys) & 0xFFFFFFFF));
            mmio_write32(SEC2_MAILBOX1, (UINT32)((cmp90_meta_low(wprMetaPhys) >> 32) & 0xFFFFFFFF));
            __asm__ volatile("wbinvd" ::: "memory");
            mmio_write32(SEC2_CPUCTL, NV_PFALCON_FALCON_CPUCTL_STARTCPU_TRUE);

            /* v2.56: BCR=RISCV после STARTCPU (как GSP booter load у драйвера) */
            mmio_write32(SEC2_BCR_CTRL, 0x111);
            for (i = 0; i < 16; i++) mmio_read32(SEC2_BCR_CTRL);
            Print(L"[4] BCR после STARTCPU+0x111 = 0x%x (0x111 = RISCV!)\n",
                  mmio_read32(SEC2_BCR_CTRL));

            Print(L"[4] STARTCPU (SEC2), polling PLM до 5с (V67-цепочка)...\n");
            for (p = 0; p < 5000; p++) {
                UINT32 trIdx = mmio_read32(NV_PSEC_BASE + 0x148);
                UINT32 trPc = mmio_read32(NV_PSEC_BASE + 0x14C);
                if (mmio_read32(REG_FEAT_OVR_PLM) == VAL_PLM_OPEN) {
                    Print(L"[4] *** PLM OPEN после %d ms! ***\n", p);
                    plmOpen = TRUE;
                    break;
                }
                                if ((p % 1000) == 0)
                    Print(L"[4] t=%dms PLM=0x%08x cpu=0x%x dbg=0x%x bcr=0x%x "
                          L"traceIdx=0x%x tracePc=0x%x mbox0=0x%x\n",
                          p, mmio_read32(REG_FEAT_OVR_PLM),
                          mmio_read32(SEC2_CPUCTL), mmio_read32(SEC2_DEBUGINFO),
                          mmio_read32(SEC2_BCR_CTRL), trIdx, trPc,
                          mmio_read32(SEC2_MAILBOX0));
                uefi_call_wrapper(BS->Stall, 1, 1000);
            }
            Print(L"[4] итог: PLM=0x%08x cpu=0x%x irq=0x%x dbg=0x%x mbox0=0x%x\n",
                  mmio_read32(REG_FEAT_OVR_PLM), mmio_read32(SEC2_CPUCTL),
                  mmio_read32(SEC2_IRQSTAT), mmio_read32(SEC2_DEBUGINFO),
                  mmio_read32(SEC2_MAILBOX0));
            dump_regs(L"[4-sec2-v254]");

            if (plmOpen || appidDone)
                break;   /* оба appid проверены */
            appidDone = appidTry;
            appidTry = (appidTry == 0x89) ? 0x49 : 0x89;
        }
    }

    return fwsecOk || sbChanged || plmOpen || is_unlocked();
}

/* ==== Dev experiment: drive the VBIOS-preloaded SEC2 ucode directly ====
 * Preloaded ucode (ucodeId=10) is FWSEC-family: DMAP v3 mapper at
 * DMEM[0x698], init_cmd@0x6C4, cmd_in@0x23D0, sig@0x6DC (accepted by
 * BROM). Pokes FRTS(0x15)/SB(0x19) commands via port writes and watches
 * WPR2/privmask. Skipped by default (cmp90_skipMapper=1) — not part of
 * the real driver flow.
 * SEC2-ucode (ucodeId=10, предзагружен VBIOS при POST) = FWSEC-семья:
 * mapper "DMAP" v3 @DMEM[0x698] (init_cmd@+44=0x6C4, cmd_in@0x23D0,
 * cmd_out@0x2410), sig@DMEM[0x6DC] (fuse-выбор, предзагружен — BROM его
 * принимает: стадия 4 дала dbg=0x0 вместо 0x780009!). Стадия 4 НЕ ставила
 * команду → ucode ждал (cpu=0x10 halt). Драйвер для FWSEC патчит
 * init_cmd=0x15 (FRTS)/0x19 (SB) в DMEM-образ ДО DMA — но SEC2
 * DMEM[0x600..0x700] secure-защищён, NS-DMA туда НЕ пишет (v2.54).
 * ПРОВЕРЯЕМ: (a) читаем живой mapper (NS+SEC), (b) пишем cmd_in @0x23D0
 * (не-secure!) портами, (c) пробуем ПОРТОВУЮ запись init_cmd @0x6C4
 * (никогда не тестировалась!), (d) STARTCPU ucodeId=10 → FRTS ставит WPR2,
 * SB открывает privmask (0x118128). Потом booter load (PROD sig!) → V67. */
static BOOLEAN
sec2_ucode_mapper_cmd(UINT64 wprMetaPhys)
{
    UINTN i, p;
    UINT32 data;
    BOOLEAN wpr2set = FALSE;
    BOOLEAN sbChanged = FALSE;

    /* FRTS cmd (44Б): readVbiosDesc{ver=1,size=24,gfwOff=0,gfwSize=0,flags=2}
     * + frtsRegionDesc{ver=1,size=20,offset4K=0x27fe00,size=0x100,media=2} */
    static const UINT32 frtsCmd[11] = {
        1, 24, 0, 0, 0, 2,
        1, 20, 0x27fe00, 0x100, 2
    };
    /* SB cmd (24Б): readVbiosDesc{ver=1,size=24,gfwOff=0,gfwSize=0,flags=2} */
    static const UINT32 sbCmd[6] = { 1, 24, 0, 0, 0, 2 };

    Print(L"\n=== v2.57: SEC2 ucode mapper init_cmd (FRTS/SB) ===\n");

    /* ---------- подготовка SEC2 (reset + unlock, как стадия 4) ---------- */
    falcon_wait_reset_ready(L"rr: sec2 ucode mapper ready", SEC2_HWCFG2, SEC2_CPUCTL);
    mmio_write32(SEC2_ENGINE, 0x1);
    for (i = 0; i < 16; i++) mmio_read32(SEC2_ENGINE);
    mmio_write32(SEC2_ENGINE, 0x0);
    for (i = 0; i < 16; i++) mmio_read32(SEC2_ENGINE);
    falcon_wait_scrub_done(SEC2_DMACTL, SEC2_HWCFG2, L"sec2-reset");
    uefi_call_wrapper(BS->Stall, 1, 50000);
    mmio_write32(SEC2_BCR_CTRL, 0x0);
    for (i = 0; i < 16; i++) mmio_read32(SEC2_BCR_CTRL);
    uefi_call_wrapper(BS->Stall, 1, 10000);

    data = mmio_read32(SEC2_FBIF_CTL);
    data |= (1 << 7);
    mmio_write32(SEC2_FBIF_CTL, data);
    mmio_write32(SEC2_DMACTL, 0);
    mmio_write32(SEC2_RM, 0xb72000a1);
    data = mmio_read32(SEC2_FBIF_TRANSCFG0);
    data = (data & ~0x7) | 0x5;
    mmio_write32(SEC2_FBIF_TRANSCFG0, data);

    /* ---------- 1. дамп живого mapper (DMEM 0x680..0x710, NS | SEC) ---------- */
    Print(L"[5] mapper region (DMEM 0x680..0x710) NS | SEC:\n");
    for (i = 0x680; i < 0x710; i += 4) {
        UINT32 vn, vs;
        mmio_write32(SEC2_DMEMC0, i);
        vn = mmio_read32(SEC2_DMEMD0);
        mmio_write32(SEC2_DMEMC0, i | (1 << 28));
        vs = mmio_read32(SEC2_DMEMD0);
        Print(L"[5]   %04x: ns=0x%08x sec=0x%08x\n", i, vn, vs);
    }

    /* ---------- 2. cmd_in буфер @0x23D0 (не-secure!) ← FRTS cmd ---------- */
    Print(L"[5] cmd_in @0x23D0 <- FRTS cmd (44Б, явная адресация)...\n");
    for (i = 0; i < 11; i++) {
        mmio_write32(SEC2_DMEMC0, 0x23D0 + i * 4);
        mmio_write32(SEC2_DMEMD0, frtsCmd[i]);
    }
    Print(L"[5]   cmd_in[0..5]: ");
    for (i = 0; i < 6; i++) {
        mmio_write32(SEC2_DMEMC0, 0x23D0 + i * 4);
        Print(L"%08x ", mmio_read32(SEC2_DMEMD0));
    }
    Print(L"\n");

    /* ---------- 3. порт-запись init_cmd @0x6C4 (secure-зона!?) ---------- */
    Print(L"[5] port-write init_cmd DMEM[0x6C4] <- 0x15 (FRTS)...\n");
    mmio_write32(SEC2_DMEMC0, 0x6C4);
    mmio_write32(SEC2_DMEMD0, 0x15);
    mmio_write32(SEC2_DMEMC0, 0x6C4);
    Print(L"[5]   ns =0x%08x", mmio_read32(SEC2_DMEMD0));
    mmio_write32(SEC2_DMEMC0, 0x6C4 | (1 << 28));
    Print(L" sec=0x%08x (0x15 = порт пишет secure-зону!)\n", mmio_read32(SEC2_DMEMD0));

    /* ---------- 4. BROM params + STARTCPU (ucodeId=10, как стадия 4) ----- */
    mmio_write32(SEC2_BROM_PARAADDR0, 0x6DC);
    mmio_write32(SEC2_BROM_ENGIDMASK, 1);
    mmio_write32(SEC2_BROM_CURR_UCODE_ID, 10);
    data = mmio_read32(SEC2_MOD_SEL);
    data = (data & ~0xFF) | 0x1;               /* RSA3K */
    mmio_write32(SEC2_MOD_SEL, data);
    mmio_write32(SEC2_BOOTVEC, 0);
    mmio_write32(SEC2_MAILBOX0, (UINT32)(cmp90_meta_low(wprMetaPhys) & 0xFFFFFFFF));
    mmio_write32(SEC2_MAILBOX1, (UINT32)((cmp90_meta_low(wprMetaPhys) >> 32) & 0xFFFFFFFF));
    __asm__ volatile("wbinvd" ::: "memory");
    mmio_write32(SEC2_CPUCTL, NV_PFALCON_FALCON_CPUCTL_STARTCPU_TRUE);

    Print(L"[5] STARTCPU (ucodeId=10), polling WPR2 до 5с (FRTS)...\n");
    for (p = 0; p < 5000; p++) {
        UINT32 lo = mmio_read32(REG_PFB_MMU_WPR2_LO);
        UINT32 hi = mmio_read32(REG_PFB_MMU_WPR2_HI);
        if ((lo & 0xFFFFFFF0) == (TARGET_WPR2_LO & 0xFFFFFFF0) &&
            (hi & 0xFFFFFFF0) == (TARGET_WPR2_HI & 0xFFFFFFF0)) {
            Print(L"[5] *** WPR2 УСТАНОВЛЕН lo=0x%08x hi=0x%08x после %d ms — "
                  L"SEC2 ucode выполнил FRTS! ***\n", lo, hi, p);
            wpr2set = TRUE;
            break;
        }
        if ((p % 1000) == 0)
            Print(L"[5] t=%dms wpr2lo=0x%08x cpu=0x%x dbg=0x%x bcr=0x%x\n",
                  p, lo, mmio_read32(SEC2_CPUCTL), mmio_read32(SEC2_DEBUGINFO),
                  mmio_read32(SEC2_BCR_CTRL));
        uefi_call_wrapper(BS->Stall, 1, 1000);
    }
    Print(L"[5] FRTS итог: WPR2=%s lo=0x%08x hi=0x%08x cpu=0x%x dbg=0x%x\n",
          wpr2set ? L"УСТАНОВЛЕН" : L"НЕТ",
          mmio_read32(REG_PFB_MMU_WPR2_LO), mmio_read32(REG_PFB_MMU_WPR2_HI),
          mmio_read32(SEC2_CPUCTL), mmio_read32(SEC2_DEBUGINFO));
    /* cmd_out @0x2410 — ucode пишет сюда результат команды (диагностика) */
    Print(L"[5] cmd_out @0x2410: ");
    for (i = 0; i < 4; i++) {
        mmio_write32(SEC2_DMEMC0, 0x2410 + i * 4);
        Print(L"%08x ", mmio_read32(SEC2_DMEMD0));
    }
    Print(L"\n");
    dump_regs(L"[5-frts]");

    /* ---------- 5. SB (init_cmd=0x19 + cmd @0x23D0) ---------- */
    Print(L"[5] SB: init_cmd=0x19 @0x6C4, cmd 24Б @0x23D0...\n");
    /* cmd_in <- SB cmd (readVbiosDesc) */
    for (i = 0; i < 6; i++) {
        mmio_write32(SEC2_DMEMC0, 0x23D0 + i * 4);
        mmio_write32(SEC2_DMEMD0, sbCmd[i]);
    }
    mmio_write32(SEC2_DMEMC0, 0x6C4);
    mmio_write32(SEC2_DMEMD0, 0x19);
    mmio_write32(SEC2_BOOTVEC, 0);
    __asm__ volatile("wbinvd" ::: "memory");
    mmio_write32(SEC2_CPUCTL, NV_PFALCON_FALCON_CPUCTL_STARTCPU_TRUE);

    {
        UINT32 priv0 = mmio_read32(0x00118128);
        UINT32 privA;
        uefi_call_wrapper(BS->Stall, 1, 500000);
        privA = mmio_read32(0x00118128);
        sbChanged = (privA != priv0);
        Print(L"[5] SB (0x19): privmask 0x%08x -> 0x%08x%s\n",
              priv0, privA, sbChanged ? L" <<< ИЗМЕНЕНИЕ (SB сработал!)" : L"");
    }
    dump_regs(L"[5-sb]");

    Print(L"[5] итог: WPR2=%s SB=%s PLM=0x%08x\n",
          wpr2set ? L"OK" : L"нет", sbChanged ? L"OK" : L"нет",
          mmio_read32(REG_FEAT_OVR_PLM));

    return wpr2set || sbChanged || is_unlocked();
}

/* ==== Register monitor: key-register snapshots + block sweeps ====
 * Вывод доступен напрямую (serial → файл) — регулярно читаем ВСЕ ключевые
 * регистры: слепок + свипы блоков на каждой фазе, поллинг каждые 500мс. */
static void
dump_key_regs(const CHAR16 *tag)
{
    Print(L"\n--- REGS [%s] ---\n", tag);
    Print(L"PLM=0x%08x SS0=0x%08x SS1=0x%08x GFW=0x%08x WPR2lo=0x%08x WPR2hi=0x%08x\n",
        mmio_read32(REG_FEAT_OVR_PLM), mmio_read32(REG_FEAT_OVR_SM_SPD),
        mmio_read32(REG_FEAT_OVR_SM_SPD_1), mmio_read32(REG_GFW_BOOT_OK),
        mmio_read32(REG_PFB_MMU_WPR2_LO), mmio_read32(REG_PFB_MMU_WPR2_HI));
    Print(L"SEC2: cpuctl=0x%08x irq=0x%08x dbg=0x%08x dmactl=0x%08x dmatrfcmd=0x%08x engine=0x%08x bcr=0x%08x\n",
        mmio_read32(SEC2_CPUCTL), mmio_read32(SEC2_IRQSTAT),
        mmio_read32(SEC2_DEBUGINFO), mmio_read32(SEC2_DMACTL),
        mmio_read32(SEC2_DMATRFCMD), mmio_read32(SEC2_ENGINE),
        mmio_read32(SEC2_BCR_CTRL));
    Print(L"RV:   cpuctl=0x%08x tracectl=0x%08x rdidx=0x%08x wtidx=0x%08x\n",
        mmio_read32(NV_FALCON2_SEC_BASE + 0x388),
        mmio_read32(NV_FALCON2_SEC_BASE + 0x400),
        mmio_read32(NV_FALCON2_SEC_BASE + 0x404),
        mmio_read32(NV_FALCON2_SEC_BASE + 0x408));
    Print(L"GSP:  cpuctl=0x%08x engine=0x%08x mbox0=0x%08x mbox1=0x%08x\n",
        mmio_read32(GSP_BASE + 0x100), mmio_read32(GSP_ENGINE),
        mmio_read32(GSP_MAILBOX0), mmio_read32(GSP_MAILBOX1));
    Print(L"PTIMER=0x%08x PMC_BOOT0=0x%08x FBsz=0x%08x\n",
        mmio_read32(NV_PTIMER_TIME_0), mmio_read32(0x00100000),
        mmio_read32(0x00100440));
}

static void
sweep_regs(const CHAR16 *name, UINTN base, UINTN count)
{
    UINTN r;
    Print(L"SWEEP %s (0x%06x, %d regs):\n", name, (UINTN)base, (INTN)count);
    for (r = 0; r < count; r++) {
        UINT32 v = mmio_read32(base + r * 4);
        if (v != 0)
            Print(L"  0x%06x = 0x%08x\n", (UINTN)(base + r * 4), v);
    }
}

static void
sweep_all(const CHAR16 *tag)
{
    Print(L"\n######## SWEEPS [%s] ########\n", tag);
    sweep_regs(L"FEAT_OVR", 0x00823800, 12);
    sweep_regs(L"SEC2", 0x00840000, 256);
    sweep_regs(L"SEC2_FBIF", 0x00840600, 16);
    sweep_regs(L"FALCON2", 0x00841000, 192);
    sweep_regs(L"GSP", 0x00110000, 64);
    sweep_regs(L"GSP_MBOX", 0x00110800, 8);
    sweep_regs(L"PFB_WPR", 0x001FA800, 8);
    sweep_regs(L"GFW", 0x00118200, 16);
    sweep_regs(L"PTIMER", 0x00009400, 8);
}

/* ==== Preload probe: read GSP/SEC2 IMEM+DMEM (NS|SEC views) FIRST ====
 * Must run before ANY engine reset or DMA. Shows whether the VBIOS
 * preload (FWSEC in GSP secure IMEM, SEC2 ucode) is still alive:
 * Читаем GSP/SEC2 IMEM+DMEM (NS и SEC-виды) ПЕРВЫМИ действиями приложения —
 * до engine-reset'ов и DMA. Ответ: живёт ли предзагрузка VBIOS (FWSEC в GSP
 * secure IMEM, SEC2 ucode) внутри QEMU/vfio, или vfio/FLR её убил. */
#define GSP_IMEMC0   (GSP_BASE + 0x180)
#define GSP_IMEMD0   (GSP_BASE + 0x184)
#define GSP_DMEMC0   (GSP_BASE + 0x1C0)
#define GSP_DMEMD0   (GSP_BASE + 0x1C4)
static void
probe_preload(void)
{
    UINTN i;
    Print(L"\n=== v2.57-4: ЗОНД ПРЕДЗАГРУЗКИ (IMEM/DMEM GSP+SEC2, NS|SEC) ===\n");
    Print(L"[pre] GSP IMEM[0x00..0x2F]:\n");
    for (i = 0; i < 0x30; i += 4) {
        UINT32 vn, vs;
        mmio_write32(GSP_IMEMC0, i);
        vn = mmio_read32(GSP_IMEMD0);
        mmio_write32(GSP_IMEMC0, i | (1 << 28));
        vs = mmio_read32(GSP_IMEMD0);
        Print(L"[pre]   gsp-imem %04x: ns=0x%08x sec=0x%08x\n", i, vn, vs);
    }
    Print(L"[pre] GSP DMEM[0x00..0x2F]:\n");
    for (i = 0; i < 0x30; i += 4) {
        UINT32 vn, vs;
        mmio_write32(GSP_DMEMC0, i);
        vn = mmio_read32(GSP_DMEMD0);
        mmio_write32(GSP_DMEMC0, i | (1 << 28));
        vs = mmio_read32(GSP_DMEMD0);
        Print(L"[pre]   gsp-dmem %04x: ns=0x%08x sec=0x%08x\n", i, vn, vs);
    }
    Print(L"[pre] SEC2 IMEM[0x00..0x2F]:\n");
    for (i = 0; i < 0x30; i += 4) {
        UINT32 vn, vs;
        mmio_write32(SEC2_IMEMC0, i);
        vn = mmio_read32(SEC2_IMEMD0);
        mmio_write32(SEC2_IMEMC0, i | (1 << 28));
        vs = mmio_read32(SEC2_IMEMD0);
        Print(L"[pre]   sec2-imem %04x: ns=0x%08x sec=0x%08x\n", i, vn, vs);
    }
    Print(L"[pre] SEC2 DMEM[0x00..0x2F]:\n");
    for (i = 0; i < 0x30; i += 4) {
        UINT32 vn, vs;
        mmio_write32(SEC2_DMEMC0, i);
        vn = mmio_read32(SEC2_DMEMD0);
        mmio_write32(SEC2_DMEMC0, i | (1 << 28));
        vs = mmio_read32(SEC2_DMEMD0);
        Print(L"[pre]   sec2-dmem %04x: ns=0x%08x sec=0x%08x\n", i, vn, vs);
    }
    Print(L"[pre] GSP BCR=0x%x SEC2 BCR=0x%x (CORE_SELECT: 0=FALCON 1=RISCV)\n",
          mmio_read32(GSP_BASE + 0x668), mmio_read32(SEC2_BCR_CTRL));
}

/* ==== Shortcut probe: do plain host MMIO writes stick? ====
 * If PLM accepts 0xFFFFFFFF written directly from the host side, the
 * whole booter path is unnecessary (unlock = 3 writes). On a locked
 * card the writes bounce back as RO patterns — costs nothing, saves
 * the full sequence on warm re-runs:
 * НЕ ТЕСТИРОВАЛОСЬ: прилипают ли записи PLM/SS0/SS1 с хоста (BAR0 MMIO)
 * напрямую, без GSP/booter (V67-цепочки). Если PLM=0xFFFFFFFF прилипает —
 * весь BROM/FWSEC/WPR2 путь не нужен: анлок = 3 записи.
 * Порядок: open (0xFFFFFFFF) → если прилипло, SS0/SS1 → полный анлок.
 * Если нет — диагностические значения (0x0, 0xFFFFFFFE, 0x11111111) при
 * закрытом PLM — ничего не теряем. */
static BOOLEAN
direct_write_probe(void)
{
    UINT32 v;

    Print(L"\n--- v2.26: ПРЯМАЯ запись FEAT_OVR (host probe) ---\n");
    mmio_write32(REG_FEAT_OVR_PLM, VAL_PLM_OPEN);
    v = mmio_read32(REG_FEAT_OVR_PLM);
    Print(L"probe: PLM=0x%08x после записи 0xFFFFFFFF (0xFFFFFF8F = запись игнор)\n", v);

    mmio_write32(REG_FEAT_OVR_SM_SPD, VAL_SS0_UNLOCKED);
    mmio_write32(REG_FEAT_OVR_SM_SPD_1, VAL_SS1_UNLOCKED);
    Print(L"probe: SS0=0x%08x SS1=0x%08x после записи 0x88888888/0x8\n",
          mmio_read32(REG_FEAT_OVR_SM_SPD), mmio_read32(REG_FEAT_OVR_SM_SPD_1));

    if (is_unlocked()) {
        Print(L"probe: *** ПРЯМЫЕ ЗАПИСИ РАБОТАЮТ — GPU открыт без booter ***\n");
        return TRUE;
    }

    Print(L"probe: диагностика (регистр закрыт?):\n");
    mmio_write32(REG_FEAT_OVR_PLM, 0x00000000);
    Print(L"probe:   PLM=0x%08x после 0x0 (закрыть)\n", mmio_read32(REG_FEAT_OVR_PLM));
    mmio_write32(REG_FEAT_OVR_PLM, 0xFFFFFFFE);
    Print(L"probe:   PLM=0x%08x после 0xFFFFFFFE (bit0 flip)\n", mmio_read32(REG_FEAT_OVR_PLM));
    mmio_write32(REG_FEAT_OVR_SM_SPD, 0x11111111);
    Print(L"probe:   SS0=0x%08x после 0x11111111\n", mmio_read32(REG_FEAT_OVR_SM_SPD));
    mmio_write32(REG_FEAT_OVR_SM_SPD_1, 0x00000000);
    Print(L"probe:   SS1=0x%08x после 0x0\n", mmio_read32(REG_FEAT_OVR_SM_SPD_1));
    return FALSE;
}

/* ==== Dev experiment: start the RISC-V core directly, bypassing BROM ====
 * Writes BCR CORE_SELECT=RISCV itself and starts the CPU without BROM
 * verification (no FWSEC/WPR2/signature), placing own_code_67 at several
 * IMEM addresses. Historically never opened PLM alone; diagnostic value.
 * v2.11-v2.24: BROM-хендофф (BOOTVEC+STARTCPU → BROM сам переключает ядро
 * в RISC-V). BROM отказывается (dbg=0x0, bcr=FALCON) — не из-за RM (v2.24),
 * не из-за контента IMEM (v2.23). НОВАЯ гипотеза: пишем BCR CORE_SELECT=
 * RISCV САМИ и стартуем ядро напрямую, минуя BROM-верификацию (без FWSEC/
 * WPR2/сигнатуры). Наш CSB-код разложен по IMEM (0/0x100/0x1000/0x2000/
 * 0x4000/0x8000). Старт: cpuctl SEC2 (0x840100) и/или cpuctl RISC-V (0x841388).
 * Наблюдаем каждые 500мс: PLM/SS0/SS1 + trace (0x841404/40C/410). */
static BOOLEAN
riscv_direct_start(void)
{
    UINTN a;
    BOOLEAN opened = FALSE;

    /* (bcr, bootvec, cpu: 0=SEC2 0x840100, 1=RV 0x841388) */
    static const UINT32 try_bcr[] = { 0x111, 0x110, 0x111, 0x110 };
    static const UINT32 try_vec[] = { 0x100, 0x000, 0x100, 0x000 };
    static const UINT32 try_cpu[] = {    0,    0,    1,    1 };

    Print(L"\n--- v2.25: ПРЯМОЙ запуск RISC-V (обход BROM) ---\n");
    for (a = 0; a < 4; a++) {
        UINT32 cpuAddr = try_cpu[a] ? (NV_FALCON2_SEC_BASE + 0x388) : SEC2_CPUCTL;
        UINTN  p;
        UINT32 bcrNow;

        mmio_write32(SEC2_BCR_CTRL, try_bcr[a]);
        {
            UINTN j;
            for (j = 0; j < 16; j++) mmio_read32(SEC2_BCR_CTRL);
        }
        bcrNow = mmio_read32(SEC2_BCR_CTRL);
        mmio_write32(SEC2_BOOTVEC, try_vec[a]);
        mmio_write32(cpuAddr, NV_PFALCON_FALCON_CPUCTL_STARTCPU_TRUE);
        Print(L"riscv: попытка %d: BCR=0x%x (читается 0x%x) BOOTVEC=0x%x cpu=0x%x STARTCPU\n",
              (INTN)a + 1, try_bcr[a], bcrNow, try_vec[a], cpuAddr);

        for (p = 0; p < 4; p++) {   /* 4 × 500мс = 2с */
            uefi_call_wrapper(BS->Stall, 1, 500000);
            dump_key_regs(L"riscv-poll");
            if (mmio_read32(REG_FEAT_OVR_PLM) == VAL_PLM_OPEN) break;
        }
        if (mmio_read32(REG_FEAT_OVR_PLM) == VAL_PLM_OPEN) { opened = TRUE; break; }
    }
    return opened;
}

/* ==== Legacy: GSP-mailbox booter-load command path ====
 * Driver protocol: mailboxes 0x110040/44 = phys(WPR meta), command port
 * 0x110804 (0x554 init, 0x57c booter load; 0x65 = OK, 0x55 = busy).
 * Superseded by direct falcon loading; retained for diagnostics.
 * Протокол Windows-драйвера (booter_load 0xb74240):
 *   GSP mailboxes 0x110040/0x110044 = phys(WPR meta) — аргумент команды
 *   PGSP_MAILBOX 0x110804 = команда (0x554 init, 0x57c booter load)
 *   статусы в 0x110804: 0x65 = OK, 0x55 = busy
 * GSP-блок доступен с хоста (v2.10: реальные значения, не 0xBADF),
 * в отличие от SEC2 (залочен PLM). */
static EFI_STATUS
gsp_mailbox_booter_load(UINT64 wprMetaPhys)
{
    UINTN i;
    UINT32 st = 0;

    Print(L"gspmail: WPR meta @0x%lx\n", wprMetaPhys);
    mmio_write32(0x110040, (UINT32)(wprMetaPhys & 0xFFFFFFFF));
    mmio_write32(0x110044, (UINT32)(wprMetaPhys >> 32));

    /* 0x554 — init */
    Print(L"gspmail: cmd 0x554 (init)...\n");
    mmio_write32(0x110804, 0x554);
    for (i = 0; i < 5000; i++) {
        st = mmio_read32(0x110804);
        if (st == 0x65 || st == 0x55) break;
        uefi_call_wrapper(BS->Stall, 1, 1000);
    }
    Print(L"gspmail: init -> status 0x%08x через %d ms (mbox0=0x%x mbox1=0x%x)\n",
          st, i, mmio_read32(0x110040), mmio_read32(0x110044));
    if (st != 0x65 && st != 0x55)
        Print(L"gspmail: ВНИМАНИЕ — статус init не 0x65/0x55\n");

    /* 0x57c — booter load (V67-сигнатура в WPR meta) */
    Print(L"gspmail: cmd 0x57c (booter load, V67)...\n");
    mmio_write32(0x110804, 0x57c);
    for (i = 0; i < 5000; i++) {
        st = mmio_read32(0x110804);
        if (st == 0x65 || st == 0x55) break;
        if (mmio_read32(REG_FEAT_OVR_PLM) == VAL_PLM_OPEN) break;
        uefi_call_wrapper(BS->Stall, 1, 1000);
    }
    Print(L"gspmail: load -> status 0x%08x через %d ms (mbox0=0x%x mbox1=0x%x PLM=0x%x)\n",
          st, i, mmio_read32(0x110040), mmio_read32(0x110044),
          mmio_read32(REG_FEAT_OVR_PLM));

    if (mmio_read32(REG_FEAT_OVR_PLM) == VAL_PLM_OPEN)
        return EFI_SUCCESS;
    return EFI_TIMEOUT;
}

/* ==== PCIe Function Level Reset ====
 * Walks the capability list, sets Device Control bit 15. FLR is the ONLY
 * reset that clears a latched WPR2 (direct writes bounce even with PLM
 * open); the unlocked masks/selectors survive it. */
static EFI_STATUS
do_flr(void)
{
    UINT32 capPtr = cfg_read32(0x34) & 0xFF;
    while (capPtr && capPtr < 0x100) {
        UINT32 hdr = cfg_read32(capPtr);
        if ((hdr & 0xFF) == 0x10) {           /* PCIe Express capability */
            UINT16 devctl;                    /* Device Control = cap+0x08 */
            devctl = (UINT16)cfg_read32(capPtr + 0x08);
            cfg_write32(capPtr + 0x08, devctl | (1 << 15));  /* Initiate FLR */
            /* v3.30, ЭТАП 13r: ПАУЗА 200 мс ВОЗВРАЩЕНА, ЗОНД СОХРАНЁН КАК ИЗМЕРЕНИЕ.
             *
             * v3.29 заменил эту слепую паузу опросом готовности и сломал
             * рендер: 0 из 8 масок. Разбор в out/BUILDS.md.
             *
             * ЗОНД ОСТАВЛЕН, и вот почему. Он показал:
             *     FLRW  post-FLR ready in 8us (id=0x10DE raw=0x248A10DE)  x9/9
             * То есть конфигурационное пространство отвечает через 8-9 мкс,
             * значением 0x248A10DE (NVIDIA / GA104), и оно НЕ МЕНЯЕТСЯ.
             * Признак живости здесь бесполезен: он истинн в момент t=0 и
             * никогда не становится ложным.
             *
             * ПРАВИЛЬНЫЙ ВЫВОД, КОТОРЫЙ ТЕПЕРЬ ЗАПИСАН: ждать после FLR надо
             * не ответа конфигурации, а того, что ФУНКЦИЯ ВЕРНУЛАСЬ
             * ФУНКЦИОНАЛЬНО - то есть что BAR0 принимает перезапись. Это
             * предмет этапа 14, и измерять это надо отдельно.
             *
             * Стоимость оставленного зонда: 8-9 мкс на вызов, 9 вызовов =
             * 81 мкс на прогон. Он не влияет на поведение и навсегда
             * фиксирует в логе, что повторять попытку v3.29 бессмысленно. */
            {
                UINT64 t0 = fx_now_us();
                UINT32 raw = cfg_read32(0x00);
                fx_flrCalls++;
                fx_flrFast++;            /* liveness: всегда истинна сразу */
                fx_flrLastRaw = raw;
                fx_flrLastId  = raw & 0xFFFFU;
                fx_flrUs += fx_now_us() - t0;
                ulogf(L"FLRW  config answers in %lldus (id=0x%04x raw=0x%08x)"
                      L" - LIVENESS ONLY, not readiness\n",
                      (INT64)(fx_now_us() - t0), fx_flrLastId, raw);
            }
            /* СЛЕПАЯ ПАУЗА ВОЗВРАЩЕНА (v3.29 её убрал и сломал рендер).
             * Несущая: без неё функция не успевает вернуться, BAR0 не
             * встаёт, FWSEC не грузится, маски не открываются. */
            uefi_call_wrapper(BS->Stall, 1, 200000);
            Print(L"FLR: issued (pcie cap @0x%x)\n", capPtr);
            return EFI_SUCCESS;
        }
        capPtr = (hdr >> 8) & 0xFF;
    }
    Print(L"FLR: PCIe capability не найден\n");
    return EFI_NOT_FOUND;
}

/* ==== PCIe gen unlock experiments (flag PCIE_GEN_EXPERIMENT) ====
 * Method verified on CMP 170HX/GA100 (cmp170hx-gen2): phase 1 publishes
 * capabilities GPU-side (XVE window, BAR0 base 0x88000), phase 2
 * retrains the link. Offsets cross-checked against upstream regmap
 * dev_nv_pcfg_xve_regmap.h. Retrain happens naturally when the link
 * comes back, so this runs strictly BEFORE any FLR; no MMIO after.
 * Stand finding: a LIVE GSP guards link regs and discards writes —
 * on real HW phase3 runs pre-OS, before any GSP exists.
 * Метод верифицирован на CMP 170HX/GA100 (luannanxian/cmp170hx-gen2,
 * upstream amoghmunikote/cmpunlocker ветка Gen2): фаза 1 — публикация
 * capability на GPU-стороне, фаза 2 — ретрейн. У них каждая запись шла
 * через перезапуск SEC2-ботера (у RM нет priv); у нас PLM уже открыт —
 * пишем напрямую в XVE-окно BAR0. Смещения сверены с официальной regmap:
 * open-gpu-kernel-modules ampere/ga102/dev_nv_pcfg_xve_regmap.h
 * (XVE-окно GA102 = база 0x88000; LINK_CAP@0x84, LC_STATUS@0x88 speed[19:16]
 * width[9:4], CAP2@0xA4, LC2@0xA8 target[3:0], PRIV_MISC_1@0x41C,
 * VSEC@0x60C/0x610, XVE_D0/D4/D8@0xFE8/EC/F0).
 * Ретрейн происходит сам при восстановлении линка после FLR — поэтому
 * стадия строго ДО FLR (BAR живой), пост-FLR MMIO не трогаем (уроки v2.87). */
#ifdef PCIE_GEN_EXPERIMENT
#ifndef PCIE_GEN_TARGET
#define PCIE_GEN_TARGET 3   /* 2=Gen2, 3=Gen3, 4=Gen4 — лестница тестов */
#endif

#define XVE_LINK_CAP         0x00088084u
#define XVE_LINK_CTRL_STATUS 0x00088088u
#define XVE_LINK_CAP2        0x000880a4u
#define XVE_LINK_CTRL_2      0x000880a8u
#define XVE_PRIV_MISC_1      0x0008841cu
#define XVE_VSEC_DEVICE      0x0008860cu
#define XVE_VSEC_HIERARCHY   0x00088610u
#define XVE_LTSSM_OVR        0x0008872cu
#define XVE_D0               0x00088fe8u
#define XVE_D4               0x00088fecu
#define XVE_D8               0x00088ff0u

/* v2.93: priv-домены PCIe-блока. FEAT_OVR — РОДНОЕ семейство наших
 * PLM(0x823804)/SS0(0x82381C)/SS1(0x823820); у GA100 в этой же странице
 * сидит FEAT_OVR_ECC_PLM=0x00823800. OPT_* — fuse-shadow регистры
 * с битами поддерживаемых gen (имена из патча 0007 GA100).
 * XP3G — приватный домен PCIe IP (смещения GA100, регион валиден на
 * GA102 по regmap 0x8E000-0x8EFFC). */
#define PCIE_FEAT_OVR_ECC    0x00823800u
#define PCIE_OPT_MAGIC       0x00820520u
#define PCIE_OPT_GEN23       0x0082057cu
#define PCIE_OPT_GEN3        0x00820580u
/* v2.95: OPTB — priv-домен страницы 0x82xxxx (у GA100: 10 регов D0..F4=FF) */
#define PCIE_OPTB_BASE       0x008200d0u
#define PCIE_OPTB_COUNT      10u
/* v2.96: регистры из рабочего CMP90-патча (GA102, device 0x20B0):
 * FUSE_OVERRIDE — снятие fuse-лока PCIe gen (та же FEAT_OVR-страница,
 * что PLM/SS0/SS1!), LINK_CONTROL/LINK_SPEED — PL-блок как у GA100 */
#define PCIE_FUSE_OVERRIDE   0x00823810u
#define PCIE_LINK_CONTROL    0x0008c000u
#define PCIE_LINK_SPEED_CFG  0x0008c040u
#define PCIE_XP3G_PLM0       0x0008e1b0u
#define PCIE_XP3G_OVR0       0x0008e110u
#define PCIE_XP3G_VAL0       0x0008e120u
#define PCIE_XP3G_OVR3       0x0008e11cu
#define PCIE_XP3G_VAL3       0x0008e12cu

static int pcie_gen_fails;

static void
pcie_gen_status(const CHAR16 *tag)
{
    UINT32 st = mmio_read32(XVE_LINK_CTRL_STATUS);
    Print(L"pcie-gen %s: LNKSTA=0x%08x speed=%d width=%d CAP=0x%08x CAP2=0x%08x LC2=0x%08x\n",
          tag, st, (st >> 16) & 0xF, (st >> 4) & 0x3F,
          mmio_read32(XVE_LINK_CAP), mmio_read32(XVE_LINK_CAP2),
          mmio_read32(XVE_LINK_CTRL_2));
}

static void
pcie_gen_wr_verify(UINTN off, UINT32 want, const CHAR16 *name)
{
    UINT32 rd;
    mmio_write32(off, want);
    rd = mmio_read32(off);
    if (rd != want) {
        pcie_gen_fails++;
        Print(L"pcie-gen: FAIL %s(0x%06x): want=0x%08x got=0x%08x\n",
              name, off, want, rd);
    } else {
        Print(L"pcie-gen: ok %s=0x%08x\n", name, rd);
    }
}

static void
pcie_gen_unlock_debug(UINT64 wprMetaPhys, UINT64 ucodePhys, UINT64 v67Phys)
{
    UINT32 v;
    EFI_STATUS st;

    Print(L"\n=== pcie-gen: разблокировка PCIe Gen%d (v2.97 booter-write) ===\n",
          PCIE_GEN_TARGET);
    pcie_gen_fails = 0;
    pcie_gen_status(L"pre ");

    /* Шаг 0 (v2.97): снятие fuse-лока ЧЕРЕЗ БОТЕР (falcon priv, как
     * kgspCmp90RefillPayload у драйвера): патчим {value@0xf948,
     * addr@0xf960} в копии V67-payload в ОЗУ и гоним второй прогон ботера.
     * booter_load_v67 сам делает полный ресет SEC2 на входе. */
    if (v67Phys && ucodePhys) {
        volatile UINT32 *pv = (volatile UINT32 *)(UINTN)(v67Phys + 0xf948);
        volatile UINT32 *pa = (volatile UINT32 *)(UINTN)(v67Phys + 0xf960);
        Print(L"pcie-gen: v97: payload value@0xf948=0x%08x addr@0xf960=0x%08x\n",
              *pv, *pa);
        *pv = 0x00000000u;
        *pa = PCIE_FUSE_OVERRIDE;
        Print(L"pcie-gen: booter#2 (PCIE_FUSE=0)...\n");
        st = booter_load_v67(wprMetaPhys, ucodePhys);
        Print(L"pcie-gen: booter#2: %r, FUSE_OVR=0x%08x (want 0)\n",
              st, mmio_read32(PCIE_FUSE_OVERRIDE));
    } else {
        Print(L"pcie-gen: v97: нет payload-контекста — booter-запись пропущена\n");
    }

    /* v2.93: дамп fuse-shadow страницы FEAT_OVR/OPT (родня PLM/SS0/SS1).
     * OPT_MAGIC должен показать сигнатуру, если OPT-space живёт тут же. */
    Print(L"pcie-gen: FEAT_OVR[0x823800..04]=0x%08x/0x%08x  SS0=0x%08x SS1=0x%08x\n",
          mmio_read32(PCIE_FEAT_OVR_ECC), mmio_read32(REG_FEAT_OVR_PLM),
          mmio_read32(REG_FEAT_OVR_SM_SPD), mmio_read32(REG_FEAT_OVR_SM_SPD_1));
    Print(L"pcie-gen: OPT_MAGIC(0x820520)=0x%08x GEN23(0x82057c)=0x%08x GEN3(0x820580)=0x%08x\n",
          mmio_read32(PCIE_OPT_MAGIC), mmio_read32(PCIE_OPT_GEN23),
          mmio_read32(PCIE_OPT_GEN3));

    /* Шаг 1 (v2.95): OPTB priv-домен страницы 0x82xxxx — как у GA100,
     * 10 регистров 0x8200D0..F4 = FF. Открывает OPT/fuse-shadow записи. */
    {
        UINTN i;
        for (i = 0; i < PCIE_OPTB_COUNT; i++)
            pcie_gen_wr_verify(PCIE_OPTB_BASE + i * 4, 0xFFFFFFFFu, L"OPTB");
    }
    /* Шаг 1b: FEAT_OVR ECC-страница + XP3G PCIe IP (v2.93, ретрай) */
    pcie_gen_wr_verify(PCIE_FEAT_OVR_ECC, 0xFFFFFFFFu, L"FEAT_OVR_ECC");
    {
        int i;
        for (i = 0; i < 4; i++)
            pcie_gen_wr_verify(PCIE_XP3G_PLM0 + i * 4, 0xFFFFFFFFu, L"XP3G_PLM");
    }
    /* XP3G overrides как у GA100: OVR0=1/VAL0=0, OVR3=4/VAL3=0x00200000 */
    pcie_gen_wr_verify(PCIE_XP3G_VAL0, 0x00000000u, L"XP3G_VAL0");
    pcie_gen_wr_verify(PCIE_XP3G_OVR0, 0x00000001u, L"XP3G_OVR0");
    pcie_gen_wr_verify(PCIE_XP3G_VAL3, 0x00200000u, L"XP3G_VAL3");
    pcie_gen_wr_verify(PCIE_XP3G_OVR3, 0x00000004u, L"XP3G_OVR3");

    /* Шаг 2 (v2.95): OPT-биты gen — GA100 клал GEN23=0; пробуем и GEN3=0.
     * Это fuse-shadow — та же семья, что SS0/SS1, может принять запись. */
    pcie_gen_wr_verify(PCIE_OPT_GEN23, 0x00000000u, L"OPT_GEN23");
    pcie_gen_wr_verify(PCIE_OPT_GEN3, 0x00000000u, L"OPT_GEN3");

    /* Шаг 2: priv-домены XVE (как у GA100: XVE_D0/D4/D8 = FF) — повторно,
     * уже после открытия доменов шага 1 */
    mmio_write32(XVE_D0, 0xFFFFFFFFu);
    mmio_write32(XVE_D4, 0xFFFFFFFFu);
    mmio_write32(XVE_D8, 0xFFFFFFFFu);
    Print(L"pcie-gen: XVE_D0/D4/D8 = 0x%x/0x%x/0x%x\n",
          mmio_read32(XVE_D0), mmio_read32(XVE_D4), mmio_read32(XVE_D8));

    /* PRIV_MISC_1: set bits(11|13), clear bits(12|14) — семантика GA100 */
    v = mmio_read32(XVE_PRIV_MISC_1);
    pcie_gen_wr_verify(XVE_PRIV_MISC_1,
                       (v | (1u << 11) | (1u << 13)) & ~((1u << 12) | (1u << 14)),
                       L"PRIV_MISC_1");

    /* VSEC_HIERARCHY: clear bit12, set bit0 */
    v = mmio_read32(XVE_VSEC_HIERARCHY);
    pcie_gen_wr_verify(XVE_VSEC_HIERARCHY, (v & ~(1u << 12)) | 1u,
                       L"VSEC_HIERARCHY");

    /* VSEC_DEVICE: set bit0 */
    v = mmio_read32(XVE_VSEC_DEVICE);
    pcie_gen_wr_verify(XVE_VSEC_DEVICE, v | 1u, L"VSEC_DEVICE");

    /* LINK_CAP: MAX_LINK_SPEED[3:0] = target */
    v = mmio_read32(XVE_LINK_CAP);
    pcie_gen_wr_verify(XVE_LINK_CAP, (v & ~0xFu) | PCIE_GEN_TARGET, L"LINK_CAP");

    /* LINK_CAP2: как GA100 0x2→0x6 (set bits 1|2) */
    v = mmio_read32(XVE_LINK_CAP2);
    pcie_gen_wr_verify(XVE_LINK_CAP2, v | 0x6u, L"LINK_CAP2");

    /* LINK_CTRL_2: TARGET_LINK_SPEED = target + биты [19:16]=F как у GA100 */
    v = mmio_read32(XVE_LINK_CTRL_2);
    pcie_gen_wr_verify(XVE_LINK_CTRL_2,
                       (v & ~0xFu) | PCIE_GEN_TARGET | 0x000F0000u,
                       L"LINK_CTRL_2");

    /* Шаг 2b (v2.96): ГЛАВНАЯ ПРОБА — регистры из рабочего CMP90-патча.
     * FUSE_OVERRIDE=0 снимает fuse-лок gen; LINK_CONTROL=target выбирает
     * скорость. Оба пишутся хостом ПОСЛЕ открытия PLM (у нас он открыт). */
    pcie_gen_wr_verify(PCIE_FUSE_OVERRIDE, 0x00000000u, L"PCIE_FUSE_OVR");
    pcie_gen_wr_verify(PCIE_LINK_CONTROL, (UINT32)PCIE_GEN_TARGET,
                       L"LINK_CONTROL");
    Print(L"pcie-gen: LINK_SPEED_CFG(0x8c040)=0x%08x\n",
          mmio_read32(PCIE_LINK_SPEED_CFG));

    /* Шаг 3 (v2.95): фолбэк — запись Link Cap через ХОСТОВОЕ конфиг-
     * пространство. XVE-зеркало шарит смещения с cfg (Link Cap = pcie_cap
     * +0x0C); вдруг cfg-запись хоста обслуживается минуя MMIO-гейт. */
    {
        UINT32 capPtr = cfg_read32(0x34) & 0xFF, lnkcapOff = 0, cur;
        while (capPtr && capPtr < 0x100) {
            UINT32 hdr = cfg_read32(capPtr);
            if ((hdr & 0xFF) == 0x10) { lnkcapOff = capPtr + 0x0C; break; }
            capPtr = (hdr >> 8) & 0xFF;
        }
        if (lnkcapOff) {
            cur = cfg_read32(lnkcapOff);
            Print(L"pcie-gen: host-cfg LNKCAP(0x%02x)=0x%08x\n", lnkcapOff, cur);
            cfg_write32(lnkcapOff, (cur & ~0xFu) | PCIE_GEN_TARGET);
            Print(L"pcie-gen: host-cfg LNKCAP post=0x%08x (want max_speed=%d)\n",
                  cfg_read32(lnkcapOff), PCIE_GEN_TARGET);
        } else {
            Print(L"pcie-gen: host-cfg: PCIe capability не найден\n");
        }
    }

    Print(L"pcie-gen: LTSSM_OVR(0x8872c)=0x%08x (только чтение)\n",
          mmio_read32(XVE_LTSSM_OVR));

    pcie_gen_status(L"post");
    Print(L"pcie-gen: готово, fail=%d (ретрейн — при восстановлении линка после FLR)\n",
          pcie_gen_fails);
}
#endif /* PCIE_GEN_EXPERIMENT */

/* ==== gsp_ga10x.bin loader via SimpleFileSystem (LEGACY helper) ====
 * The main flow reads the firmware with raw BlockIo instead — SFS
 * operations hang on some AMI firmwares (see preload_bootmgfw). */
static EFI_STATUS
read_fwimage(EFI_HANDLE DeviceHandle, UINT8 **pOut, UINTN *pSize)
{
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FS = NULL;
    EFI_FILE_PROTOCOL *Root = NULL, *File = NULL;
    EFI_STATUS Status;
    UINT8 *Buf = NULL;
    UINTN BufSize = 0;
    static EFI_GUID FsGuid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
    static EFI_GUID FileInfoGuid = EFI_FILE_INFO_ID;

    Status = uefi_call_wrapper(BS->HandleProtocol, 3, DeviceHandle,
                               &FsGuid, (VOID**)&FS);
    if (EFI_ERROR(Status)) { Print(L"fw: no FS: %r\n", Status); return Status; }

    Status = FS->OpenVolume(FS, &Root);
    if (EFI_ERROR(Status)) { Print(L"fw: OpenVolume: %r\n", Status); return Status; }

    Status = Root->Open(Root, &File, L"\\gsp_ga10x.bin", EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(Status)) { Print(L"fw: \\gsp_ga10x.bin: %r\n", Status); return Status; }

    /* размер файла */
    {
        EFI_FILE_INFO *Info = NULL;
        UINTN InfoSize = sizeof(EFI_FILE_INFO) + 256;
        Info = AllocatePool(InfoSize);
        if (!Info) return EFI_OUT_OF_RESOURCES;
        Status = File->GetInfo(File, &FileInfoGuid, &InfoSize, Info);
        if (EFI_ERROR(Status)) { FreePool(Info); return Status; }
        BufSize = Info->FileSize;
        FreePool(Info);
    }
    if (BufSize == 0 || BufSize > 0x6000000ULL) {  /* до 96MB */
        Print(L"fw: подозрительный размер %d\n", BufSize);
        return EFI_LOAD_ERROR;
    }

    Buf = AllocatePool(BufSize);
    if (!Buf) { Print(L"fw: no mem\n"); return EFI_OUT_OF_RESOURCES; }

    /* Читаем чанками по 2МБ (некоторые прошивки режут Read до малого размера;
     * 84МБ одним вызовом может висеть). Прогресс каждые 16МБ. */
    {
        UINTN total = 0;
        UINTN chunk = 0x200000;   /* 2MB */
        while (total < BufSize) {
            UINTN rd = (BufSize - total < chunk) ? (BufSize - total) : chunk;
            Status = File->Read(File, &rd, Buf + total);
            if (EFI_ERROR(Status)) {
                Print(L"fw: read err @%d: %r\n", total, Status);
                return EFI_LOAD_ERROR;
            }
            if (rd == 0) {
                Print(L"fw: EOF до конца файла (%d/%d)\n", total, BufSize);
                return EFI_LOAD_ERROR;
            }
            total += rd;
            if ((total & 0xFFFFFF) == 0 || total >= BufSize)
                Print(L"fw: ... %d / %d МБ\n", (total >> 20), (BufSize >> 20));
        }
    }
    File->Close(File);
    *pOut = Buf;
    *pSize = BufSize;
    Print(L"fw: прочитано %d байт gsp_ga10x.bin\n", BufSize);
    return EFI_SUCCESS;
}

/* ==== radix3 page-table builder (generic form) ====
 * NOTE: efi_main() builds the table inline following the exact driver
 * layout (root + L1 + nL2 pages + data); this generic variant is kept
 * for reference/experiments only. */
static UINT64
build_radix3(UINT8 *Buf, UINT64 physBase, const UINT8 *Data, UINT64 size)
{
    /* 4 уровня; размер данных страницами */
    UINT64 n3 = (size + RADIX_PAGE_SIZE - 1) >> RADIX_PAGE_LOG2;
    UINT64 n2 = (n3 - 1) / RADIX_ENTRIES + 1;
    UINT64 n1 = (n2 - 1) / RADIX_ENTRIES + 1;
    UINT64 off1 = (1ULL) << RADIX_PAGE_LOG2;                 /* L1 PDEs (L0=1 страница) */
    UINT64 off2 = (1ULL + n1) << RADIX_PAGE_LOG2;            /* L2 PTEs */
    UINT64 off3 = (1ULL + n1 + n2) << RADIX_PAGE_LOG2;       /* данные */
    UINT64 i;

    if (n1 != 1) { Print(L"radix3: n1=%d (ожидалось 1)\n", n1); return 0; }

    /* L0 PDE → страница L1 */
    *(UINT64*)(Buf + 0) = physBase + off1;
    /* L1 PDEs → страницы L2 */
    for (i = 0; i < n2; i++)
        *(UINT64*)(Buf + off1 + i*8) = physBase + off2 + i * RADIX_PAGE_SIZE;
    /* L2 PTEs → страницы данных */
    for (i = 0; i < n3; i++)
        *(UINT64*)(Buf + off2 + i*8) = physBase + off3 + i * RADIX_PAGE_SIZE;
    /* данные */
    CopyMem(Buf + off3, Data, size);

    Print(L"radix3: n3=%d n2=%d off3=0x%x total=0x%x\n", n3, n2, off3,
          off3 + (n3 << RADIX_PAGE_LOG2));
    return off3 + (n3 << RADIX_PAGE_LOG2);
}

/* ==== Locate a section inside the GSP firmware ELF ====
 * gsp_ga10x.bin is an ELF wrapper: the WPR meta must point at the .fwimage
 * payload, sizeOfRadix3Elf must be EXACTLY that section's size, and the
 * stock-signature test copies .fwsignature_ga10x out of it. The old code
 * hardcoded 0x40 / 0x5053000 / 0x505E02E, all of which silently break with a
 * different driver package — and choosing the right GSP image is exactly what
 * changes with the target die, so read it out of the file instead.
 * Returns FALSE if the buffer is not an ELF64 or lacks the section. */
static BOOLEAN
gsp_elf_section(const UINT8 *elf, UINTN avail, const char *want,
                UINT64 *outOff, UINT64 *outSize)
{
    const UINT8 *shstr, *shstrEnd;
    UINT64 shoff, shnum, shstrndx, i;

    if (avail < 0x40 || elf[0] != 0x7F || elf[1] != 'E' ||
        elf[2] != 'L' || elf[3] != 'F') return FALSE;
    if (elf[4] != 2) return FALSE;                 /* ELFCLASS64 only */

    shoff    = *(const UINT64 *)(elf + 0x28);
    shnum    = *(const UINT16 *)(elf + 0x3C);
    shstrndx = *(const UINT16 *)(elf + 0x3E);
    if (*(const UINT16 *)(elf + 0x3A) != 0x40) return FALSE;  /* shEntSize */
    if (!shoff || !shnum || shnum > 256 || shstrndx >= shnum) return FALSE;
    if (shoff + (UINT64)shnum * 0x40 > avail) return FALSE;

    {
        const UINT8 *sh = elf + shoff + (UINT64)shstrndx * 0x40;
        UINT64 so = *(const UINT64 *)(sh + 0x18);
        UINT64 ss = *(const UINT64 *)(sh + 0x20);
        if (so + ss > avail || ss == 0) return FALSE;
        shstr    = elf + so;
        shstrEnd = shstr + ss;
    }

    for (i = 0; i < shnum; i++) {
        const UINT8 *sh = elf + shoff + i * 0x40;
        const UINT8 *nm;
        UINT64 nameOff = *(const UINT32 *)(sh + 0x00);
        UINT64 shOff   = *(const UINT64 *)(sh + 0x18);
        UINT64 shSize  = *(const UINT64 *)(sh + 0x20);

        if (shstr + nameOff >= shstrEnd) continue;
        nm = shstr + nameOff;
        /* strlen + NUL; `want` is a short compile-time literal */
        {
            UINTN wl = 0;
            while (want[wl]) wl++;
            if (CompareMem(nm, want, wl + 1) != 0) continue;
        }
        if (shOff + shSize > avail) continue;       /* buffer too small */
        *outOff = shOff; *outSize = shSize;
        return TRUE;
    }
    return FALSE;
}

/* ==== WPR meta construction — exact driver geometry ====
 * Formulas replicated from kgspPopulateWprMeta_TU102 (610.43.03).
 * fbSize proof: a working unlock's dmesg shows frts_offset=0x27fe00000,
 * back-solving to fbSize=0x280000000 (10 GB) with 1 MB PRAMIN and 1 MB
 * FRTS. An earlier fbSize 16x smaller gave garbage layout and the
 * booter bailed before touching the signature (halt 0x780009). Heap
 * size must be EXACTLY 0x7F00000 per live-driver dump — recomputing it
 * after alignment inflated the value and broke the layout (exit 0x91).=
 * Формулы из kgspPopulateWprMeta_TU102 (610.43.03).
 * ДОКАЗАТЕЛЬСТВО fbSize: dmesg рабочего анлока frts_offset=0x27fe00000 →
 * gspFwWprEnd=frtsOffset+frtsSize=0x27FF00000, vgaWorkspaceOffset+PRAMIN:
 * fbSize = 0x280000000 (10GB), PRAMIN = 1MB, frtsSize = 1MB (GA102).
 * Старый fbSize=0x28000000 (640MB!) был в 16 раз меньше — раскладка мусорная,
 * booter валился (v2.13: halt с DEBUGINFO=0x780009 до обработки сигнатуры).
 *
 * ПОРТ НА 70HX: fbSize берётся из профиля карты (TARGET_FB_SIZE), 8 ГБ →
 * frtsOffset=0x1FFE00000. Размер heap 0x7F00000 НЕ зависит от FB: в
 * _kgspCalculateFwHeapSize это нижний кламп (min 88 МБ / max 280 МБ), а
 * расчёт для 8 и 10 ГБ даёт одно и то же ~57 МБ, поэтому значение
 * остаётся 0x7F00000 и для GA104. */
/* v2.78: 1 = СТОКОВЫЙ тест (настоящая подпись .fwsignature_ga10x из fw-контейнера,
 * sizeOfSignature=0x1000); 0 = V67-эксплойт (0xFA00). Один прогон = одна переменная. */
static UINTN cmp90_stockSig = 0;
/* v2.79: 1 = пропускать mapper-стадию [5] (ucodeId=10 на SEC2 — НЕТ в реальном
 * флоу драйвера; её abort-прогоны могут оставлять остатки в BROM-блоке) */
static UINTN cmp90_skipMapper = 1;
/* v2.81: бисекция abort-точки. 1 = портить magic в meta (если exit-код
 * изменится с 0x2 — ботер ДОХОДИТ до чтения meta и 0x2 возникает позже) */
static UINTN cmp90_corruptMeta = 0;

static void
build_wpr_meta(GspFwWprMeta *m, UINT64 elfPhys, UINT64 elfSize,
               UINT64 sigPhys, UINT64 fbSize, UINT64 blPhys, UINT64 blSize)
{
    UINT64 wprEnd;
    const UINT64 MB = 0x100000ULL;

/* ==== РУЧКА: fbSize в GspFwWprMeta (эксперимент E1, 2026-10-06) ==========
 *
 * ЗАЧЕМ. §8.9/§9.4 проекта называют GspFwWprMeta единственной точкой
 * управления, которая по времени РАНЬШЕ BAR0 и при этом в нашей власти, и
 * добавляют, что положительный контроль над ней НЕ делался:
 *
 *   «Утверждение "метаданные WPR управляют тем, что видит драйвер" введено
 *    ВЫВОДОМ, а не измерением на нашей карте... Положительный контроль
 *    (намеренно занизить fbSize и убедиться, что totalGlobalMem следует за
 *    ним) не делался»
 *
 * Пакет xrip на 50HX именно так и делает «20 ГБ геометрию» — через это
 * поле. Значит проверка обязательная: если fbSize управляет тем, что видит
 * драйвер, то поле живое и рычаг не мёртв; если нет — закрываем весь класс
 * гипотез «управлять чипом до BAR0».
 *
 * КАК. 0 (по умолчанию) = вести себя как сейчас, брать TARGET_FB_SIZE.
 * Ненулевое значение = подставить его вместо TARGET_FB_SIZE ДО всех
 * вычислений раскладки (важно: vgaWorkspaceOffset и wprEnd считаются от
 * параметра fbSize, а не от m->fbSize, поэтому подмена идёт в параметр).
 *
 * ОЖИДАЕМОЕ. 4 ГБ (0x100000000) -> в Windows cudaGetDeviceProperties
 * должен отдать totalGlobalMem ~= 4 ГиБ вместо 8. Если отдаст 8 ГиБ -
 * поле не управляет отчётом и рычаг закрыт.
 *
 * ПОСЛЕДСТВИЯ ДЛЯ ОТКАТА. При WPR_META_FB_SIZE=0 компилятор вырезает
 * ветку целиком, машинный код совпадает с текущим, md5 откатного бинаря
 * не меняется. */
#ifndef WPR_META_FB_SIZE
# define WPR_META_FB_SIZE 0
#endif
#if WPR_META_FB_SIZE != 0 && (WPR_META_FB_SIZE % 0x20000ULL) != 0
# error "WPR_META_FB_SIZE должен быть кратен 128KB (alignment WPR)"
#endif
    if (WPR_META_FB_SIZE != 0)
        fbSize = WPR_META_FB_SIZE;

/* ==== РУЧКА: байт flags в GspFwWprMeta (эксперимент E2, 2026-10-06) =========
 *
 * ЗАЧЕМ. v3.17 закрыл поле «подняли все незанятые биты маской 0xFE, ничего
 * не изменилось». Но у этого отрицательного результата есть дыра: у нас нет
 * положительного контроля над САМИМ полем. Если бит 0 (GSP_FW_FLAGS_CLOCK_BOOST)
 * вообще не влияет на часы, то и остальные семь не могут - но это утверждение
 * никто не проверял, а из него следует «поле мертво».
 *
 * ОБРАТНЫЙ ТЕСТ (это и есть E2). Часы - единственное, что мы умеем надёжно
 * измерить на нашей карте без бенчмарка игры: nvidia-smi --query-gpu=
 * clocks.sm под нагрузкой, потолок 1545 МГц.
 *
 *   WPR_META_FLAGS=0x0  -> бит CLOCK_BOOST снят.
 *   Если часы под нагрузкой ПАДАЮТ (например, до 1395 или ниже), поле живое и
 *   вопрос «можно ли им управлять» остаётся открытым: остальные биты имеют
 *   смысл.
 *   Если часы НЕ изменились - поле не влияет ни на что, и класс гипотез
 *   «управлять чипом через WprFwMeta» закрыт целиком.
 *
 * Это дешевле и честнее, чем снова поднимать 0xFE: сначала надо доказать,
 * что инструмент вообще что-то делает.
 *
 * При значении по умолчанию (0x1) машинный код идентичен текущему. */
#ifndef WPR_META_FLAGS
# define WPR_META_FLAGS 0x1
#endif

    SetMem(m, sizeof(*m), 0);
    m->magic    = GSP_FW_WPR_META_MAGIC;
    m->revision = GSP_FW_WPR_META_REVISION;

    m->sysmemAddrOfRadix3Elf = elfPhys;
    m->sizeOfRadix3Elf       = elfSize;

    m->sysmemAddrOfSignature = sigPhys;
    m->sizeOfSignature = cmp90_stockSig ? 0x1000ULL : (UINT64)V67_SIZE;

    /* --- BL (GspRmBoot): сигнатура (V67) верифицируется ПРИ загрузке BL! ---
     * Оффсеты ПОДТВЕРЖДЕНЫ живым драйвером (2026-08-21, WPR meta дамп):
     * bootloaderCodeOffset=0x1800, bootloaderDataOffset=0x800,
     * bootloaderManifestOffset=0x0. (Правка v2.47 на 0x1000 была неверна —
     * декод desc дал сдвиг; живой дамп — истина.) */
    m->sysmemAddrOfBootloader = blPhys;
    m->sizeOfBootloader       = blSize;
    m->bootloaderCodeOffset   = 0x1800;
    m->bootloaderDataOffset   = 0x800;
    m->bootloaderManifestOffset = 0x0;

    /* --- FB layout (kgspPopulateWprMeta_TU102) --- */
    m->fbSize = fbSize;

    /* CMP mining cards: нет display-fuse → vgaWorkspaceOffset = fbSize - PRAMIN(1MB) */
    m->vgaWorkspaceOffset = fbSize - TARGET_PRAMIN;
    m->vgaWorkspaceSize   = fbSize - m->vgaWorkspaceOffset;   /* 1MB */

    /* End of WPR region, 128KB aligned.
     *
     * ВАЖНО (2026-09-28): эта геометрия ОБЯЗАНА брать значения из
     * TARGET PROFILE, а не считать их здесь заново. Раньше здесь стояло
     *     wprEnd = m->vgaWorkspaceOffset & ~0x1FFFF;
     * то есть маржа не вычиталась, и после того как в профиль добавили
     * TARGET_WPR_END_MARGIN, значения РАСХОДИЛИСЬ:
     *
     *     META  frtsOffset=0x1FFE00000  <- отсюда (старая формула)
     *     GEOM  frts=0x1F7E00000        <- из профиля (с маржой)
     *
     * То есть профиль изменился, а то, что реально уходит в FWSEC-команду
     * и в booter, — нет. Второй источник правды для одной и той же
     * величины = гарантированный рассинхрон. Теперь единственный источник
     * — TARGET PROFILE.
     *
     * Драйвер (kernel_gsp_tu102.c:817) считает так же:
     *     gspFwWprEnd = ALIGN_DOWN(vbiosReservedOffset - margin, 128K)
     * см. docs/70HX-DRIVER-ANALYSIS.md §5. */
    wprEnd = (m->vgaWorkspaceOffset - TARGET_WPR_END_MARGIN) & ~0x1FFFFULL;
    m->gspFwWprEnd = wprEnd;

    /* FRTS: 1MB на GA10x (kgspGetFrtsSize). FWSEC-шаг не выполняем, но регион
     * заявляем в meta — booter валидирует раскладку по этим полям */
    m->frtsSize   = TARGET_FRTS_SIZE;
    m->frtsOffset = m->gspFwWprEnd - m->frtsSize;

    m->bootBinOffset = (m->frtsOffset - blSize) & ~0xFFFULL;  /* ALIGN_DOWN(4K) */

    /* Start of ELF (radix3), 64KB align */
    m->gspFwOffset = (m->bootBinOffset - elfSize) & ~0xFFFFULL;

    /* v2.63: ТОЧНЫЕ формулы kgspPopulateWprMeta_TU102 (дамп живого драйвера:
     * heap 0x272e00000-0x27acfffff size 0x7f00000, wprStart 0x272d00000,
     * nonWpr 0x272c00000/0x100000, flags=CLOCK_BOOST|0x1). Раньше heap был
     * 1MB вместо 127MB → ботер отбраковывал meta → exit 0x91!
     * v2.73: heapSize = РОВНО 0x7f00000 (живой дамп), БЕЗ перечета после
     * выравнивания offset — у драйвера между heap-end (0x27ad00000) и
     * gspFwOffset (0x27ada0000) гэп 0xA0000; наш перечет раздувал heap до
     * 0x7fa0000 и ломал раскладку.
     * Порт на 8 ГБ: значение НЕ пересчитываем — _kgspCalculateFwHeapSize
     * (_kgspCalculateFwHeapSize_IMPL, 610.x) даёт ~57 МБ и для 8 ГБ, и для
     * 10 ГБ, и оба раза упирается в нижний кламп 0x7F00000. */
    m->gspFwHeapSize   = 0x7F00000ULL;   /* нижний кламп kgspGetFwHeapSize (GA10x) */
    m->gspFwHeapOffset = (m->gspFwOffset - m->gspFwHeapSize) & ~(MB - 1);
    m->gspFwWprStart   = m->gspFwHeapOffset - MB;     /* wprMetaSize = 1MB */
    /* v3.51: запоминаем, что GSP поставит в WPR2_LO из этого поля. Иначе
     * единственное место в коде, где записано ожидаемое значение окна GSP, -
     * это лог, и сравнивать с ним нечем. */
    g_expGspWprLo      = (UINT32)(m->gspFwWprStart >> 8);
    /* v3.52: строка с ожидаемым окном печатается ЗДЕСЬ, а не в
     * cmp90_meta_low(). В v3.51 она была там, а cmp90_meta_low() вызывается
     * 16 раз за прогон (по два на загрузку - mailbox0 и mailbox1), и строка
     * вышла 32 раза, попутно раздув дамп кольца, потому что печать шла через
     * Print. Здесь значение вычисляется один раз, здесь же и печатается,
     * вплотную к формуле.
     *
     * Через ulogf, а не Print: это единственное объяснение, почему WPR2_LO не
     * равен FRTS>>8, и оно обязано попасть в файловый лог надёжно, а не в
     * расходуемое кольцо. */
    if (!g_metaGeomPrinted) {
        g_metaGeomPrinted = TRUE;
        ulogf(L"META   GSP window: wprStart=0x%llx = heapOff-1MB -> "
              L"WPR2_LO=0x%08x (поставит GSP); FRTS window lo=0x%08x "
              L"hi=0x%08x (ставим мы); окно GSP содержит окно FRTS\n",
              m->gspFwWprStart, (UINT32)g_expGspWprLo,
              (UINT32)TARGET_WPR2_LO, (UINT32)TARGET_WPR2_HI);
    }
    m->nonWprHeapSize  = MB;
    m->nonWprHeapOffset = m->gspFwWprStart - MB;
    m->gspFwRsvdStart  = m->nonWprHeapOffset;

    m->bootCount = 0;
    m->verified  = 0;
    m->pmuReservedSize = 0;
    m->gspFwHeapVfPartitionCount = 0;
    m->flags = WPR_META_FLAGS;         /* GSP_FW_FLAGS_CLOCK_BOOST */
/* v3.17: ПРОБА БЫЛА И СНЯТА - отрицательный результат.
 *
 * Поднимали все незанятые биты разом маской 0xFE. Записалось flags=0xFF,
 * анлок не пострадал, Windows загрузилась - и НИ ОДНО свойство не
 * изменилось: multiProcessorCount 30 -> 30, l2CacheSize 2 MB -> 2 MB,
 * шина, частоты, объём памяти - всё то же. Поле закрыто целиком.
 *
 * Ветка с логом должна быть пустой, а не содержать ulogf: любая строка
 * попадает в бинарь и ломает откат. Откат уже ломался дважды при
 * НЕИЗМЕННОМ размере файла, и единственным признаком была сверка md5. */
m->flags = m->flags;   /* оставляем как задано выше: только CLOCK_BOOST */
}

#define WINDOWS_BOOT_PATH L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi"

/* ==== SFS-free bootmgfw preload — own FAT32 parser over BlockIo ====
 * This platform (X570 GAMING X, AMI F37d) HANGS on SimpleFileSystem
 * calls from loaded applications — hangs occurred on plain file reads
 * unrelated to the unlock. BlockIo ReadBlocks is stable (84 MB fw
 * reads OK). Solution: read bootmgfw.efi into RAM BEFORE the unlock
 * with our own FAT32 parser (MBR/GPT -> ESP -> path with LFN), keep
 * the ESP DevicePath, later LoadImage(SourceBuffer). Zero SFS calls
 * remain anywhere in the hot path.
 * Это железо (X570 GAMING X, AMI F37d) виснет на SimpleFileSystem-операциях
 * из загруженных приложений — история проекта (ранние версии висли на чтении
 * файла НЕЗАВИСИМО от анлока). BlockIo ReadBlocks стабилен (84МБ fw-read ОК).
 *
 * Решение: ЕЩЁ ДО разблокировки читаем bootmgfw.efi своим FAT32-парсером
 * поверх BlockIo (GPT→ESP→каталоги с LFN), держим в ОЗУ. После анлока:
 * LoadImage(DevicePath=<реальный ESP>, SourceBuffer=<ОЗУ>) + StartImage.
 * В нашем коде не остаётся НИ ОДНОЙ SimpleFileSystem-операции. */

static UINT8 *g_bmBuf = NULL;
static UINTN g_bmSize = 0;
static EFI_DEVICE_PATH *g_bmDp = NULL;

static EFI_GUID cmp90BioGuid = EFI_BLOCK_IO_PROTOCOL_GUID;
static UINT8 cmp90EspGuid[16] = { 0x28,0x73,0x2A,0xC1, 0x1F,0xF8, 0xD2,0x11,
                                  0xBA,0x4B, 0x00,0xA0,0xC9,0x3E,0xC9,0x3B };

/* аллокатор-обёртка (gnu-efi AllocatePool имеет другую арность) */
static VOID *cmp90_alloc(UINTN size)
{
    VOID *p = NULL;
    if (!size) return NULL;
    if (EFI_ERROR(uefi_call_wrapper(BS->AllocatePool, 3, EfiBootServicesData,
                                    size, &p)))
        return NULL;
    return p;
}

static void cmp90_free(VOID *p)
{
    if (p) uefi_call_wrapper(BS->FreePool, 1, p);
}

/* ==== ЛОГ НА ФЛЕШКУ (сырые секторы, без файловой системы) ====
 * Реализация ниже, у блока cmp90_bio_read; здесь только прототипы,
 * потому что точки вызова (FWSEC-стадии) идут раньше по файлу. */
static void ulogf(const CHAR16 *fmt, ...);
static void log_flush_sector(BOOLEAN force);
/* Всё, что раньше уходило только в Print() на экран, теперь ещё и
 * пишется на флешку СЫРЫМИ СЕКТОРАМИ через BlockIo.
 *
 * Почему не файл: SimpleFileSystem на этой плате вешает прошивку
 * (OpenVolume виснет — многократно замечено в комментариях ниже), а
 * NVRAM-вызовы тем более. BlockIo ReadBlocks/WriteBlocks работают
 * стабильно (84 МБ firmware читается), значит и запись безопасна.
 *
 * Почему так безопасно: мы пишем в область, которую FAT32 не
 * использует (2 ГБ от начала флешки, а занято ~85 МБ под файлы).
 * Таблица разделов, FAT и каталоги не трогаются — для файловой
 * системы это просто свободные кластеры. Загрузка к этому моменту
 * уже завершена (efi-приложение живёт в ОЗУ), так что запись на
 * флешку, с которой мы запустились, не мешает.
 *
 * Читается обратно out\read-log.ps1 (или Get-Content вручную).
 *
 * Механика записи и чтения лога целиком описана в docs/LOGGING.md: формат
 * области на диске, отбор флешки (log_stick_ok), секторный буфер, контракт
 * синхронности с out/read-log.ps1 и диагностика отказов. Процедура снятия
 * лога — docs/FLASH-AND-LOG.md.
 * ================================================================== */
/* Адрес области лога. ДЕСЯТИЧНОЕ ЧИСЛО, а не hex: в hex здесь легко
 * ошибиться (0x3E8000 = 4 096 000, а не 4 000 000) и тогда читающий
 * скрипт смотрит в другое место и не находит лог. Значение обязано
 * совпадать с $LBA в out/read-log.ps1 — это проверяет
 * opencode/lba_sync.py в сборочном харнессе. */
#define LOG_LBA      4000000ULL   /* ≈ 1,9 ГБ от начала */
#define LOG_SECTORS  2048          /* 1 МБ = 2048 секторов на весь лог */
#define LOG_HDR      "CMPUNLOG v1 "

static EFI_BLOCK_IO_PROTOCOL *g_logBio = NULL;
/* v3.17: ЗАПИСЬ ПАКЕТАМИ ПО 8 СЕКТОРОВ.
 *
 * Раньше одна строка лога = один WriteBlocks на 512 байт, и это стоило
 * целое состояние: за прогон пишется около 3200 строк.
 *
 * Почему пакет безопасен: WriteBlocks по BlockIo на 4096 байт - обычная
 * операция, а лог и так пишется сырыми секторами без файловой системы.
 * Наблюдаемая картина не меняется: хвост по-прежнему добивается нулями
 * до границы сектора, и парсер обрывается там же.
 *
 * ЧТО ТЕРЯЕТСЯ, и почему это приемлемо: при аварийном зависании без
 * штатного сброса можно потерять до 7 последних секторов (3,5 КБ). Все
 * важные строки идут через log_ms(), а он сбрасывает буфер принудительно.
 */
#define LOG_BATCH_SECS  8
#define LOG_BATCH_BYTES (LOG_BATCH_SECS * 512)
static UINT8   g_logBuf[LOG_BATCH_BYTES];
static UINT32  g_logSec  = 1;     /* 0-й сектор — заголовок */
static UINTN   g_logFill = 0;
static BOOLEAN g_logOn   = FALSE;

/* записать накопленный сектор; при переполнении — переход к следующему,
 * при конце области — молча начинаем сначала (лог круговой) */
static void
log_flush_sector(BOOLEAN force)
{
    if (!g_logOn || g_logBio == NULL) return;
    if (g_logFill == 0 && !force) return;

    /* v3.18: ВЫБРАСЫВАНИЕ ХВОСТА БУФЕРА - исправленный дефект.
     *
     * В v3.17 здесь стояло:
     *     nsec = (g_logFill + 511) / 512;
     *     if (nsec > LOG_BATCH_SECS) nsec = LOG_BATCH_SECS;   <- кламп
     *     ... write nsec ...
     *     g_logFill = 0;                                      <- хвост выброшен
     *
     * Кламп был задуман как ограничение размера одной записи, но он не
     * ограничивал, а УНИЧТОЖАЛ: если в буфере оказывалось больше
     * LOG_BATCH_SECS секторов, писались первые восемь, а остальное
     * молча исчезало.
     *
     * Обнаружено на прогоне v3.17 (usb-log-v317.txt): финальная
     * выгрузка консольного кольца - около 130 секторов - попала под
     * кламп, и в лог не попало НИЧЕГО из неё, включая заголовок PRN.
     * Разблокировке это не повредило (маркеры END уже стояли в буфере
     * небольшого размера), но отладочный текст пропал целиком.
     *
     * Именно тот класс молчаливого отказа, из-за которого этот проект
     * уже один раз потерял рабочий бинарь. Поэтому здесь теперь цикл,
     * а не кламп, и рядом стоит счётчик - по правилу «пропуск не молчит,
     * а считается».
     */
    while (g_logFill > 0) {
        EFI_STATUS st;
        UINTN nsec = (g_logFill + 511) / 512;
        if (nsec == 0) nsec = 1;
        if (nsec > LOG_BATCH_SECS) nsec = LOG_BATCH_SECS;
        while (g_logFill < nsec * 512) g_logBuf[g_logFill++] = 0;
        st = uefi_call_wrapper(g_logBio->WriteBlocks, 5, g_logBio,
                               g_logBio->Media->MediaId,
                               LOG_LBA + g_logSec, nsec * 512, g_logBuf);
        if (EFI_ERROR(st)) {
            /* v3.48: ОТКАЗ ЗАПИСИ ОБЪЯВЛЯЕТСЯ НА КОНСОЛИ.
             *
             * Раньше единственное сообщение об отказе уходило через ulogf, то
             * есть в g_logBuf - буфер, СБРОС КОТОРОГО ТОЛЬКО ЧТО ПРОВАЛИЛСЯ, - а
             * следом g_logOn = FALSE, после чего сбрасывать его больше некому.
             * Сообщение, объясняющее тишину, было конструктивно
             * недоставляемым: оно не «не нашлось», оно не могло дойти. На
             * экране единственным следом отказа был бы голословный дефект
             * прошивки - ровно то, в что v3.19 и поверил.
             *
             * Консоль от флешки не зависит, поэтому сообщение идёт туда.
             * Печатается только при ПЕРВОМ отказе (гвард g_logFlushFails == 0),
             * то есть на норме экран не меняется и лишних 17 мс не платится.
             *
             * ============ v3.50: ОТКАЗОВ НИ ОДНОГО НЕ БЫЛО ============
             *
             * Комментарий предыдущей ревизии утверждал, что «на прогоне
             * 1004-163842 отказ WriteBlocks случается ПОСЛЕ маркера END». Это
             * БЫЛО НЕВЕРНО, и опровергнуто прямым чтением флешки:
             *     PRND  AFTER  ring dump: entered=1 filled=25836 logOn=1
             *             sectors_written=199 flush_fails=0
             * То есть отказов не было ни разу, выгрузка кольца отработала, и
             * лог был жив до конца прогона.
             *
             * Настоящая причина отсутствия PRN в логах с v3.17 была в ЧИТАЛКЕ:
             * read-log.ps1 обрезал текст по маркеру 'END ---- end of log ----',
             * а выгрузка кольца пишется ПОСЛЕ этого маркера. Данные были на
             * флешке все это время - их удалял скрипт на стороне ПК.
             *
             * Почему это стоило шести дней и двух регрессий: отчёт о причине
             * не мог появиться, потому что лог, в котором он записан,
             * обрезался раньше него. Отсутствие данных выглядело как
             * отсутствие события. Неверный вывод - «WriteBlocks отказал» - был
             * не случайной ошибкой, а единственным объяснением, которое
             * согласовывалось с наблюдаемым. */
            if (g_logFlushFails == 0) {
                CHAR16 m[224];
                UnicodeSPrint(m, sizeof(m),
                              L"LOG WRITE FAILED at LBA %d (log sec %d), "
                              L"%d sectors queued - logging OFF, rest lost\r\n",
                              (INTN)(LOG_LBA + (UINT64)g_logSec),
                              (INTN)g_logSec, (INTN)nsec);
                fx_console_raw(m);
                /* В файл - тоже, но это уже вторая попытка: при отказе записи
                 * она может не сработать, и тогда останется только экран. */
                ulogf(L"LOG    write FAILED at LBA %d (log sec=%d) "
                      L"queued=%d sectors of %d - logging disabled\r\n",
                      (INTN)(LOG_LBA + (UINT64)g_logSec), (INTN)g_logSec,
                      (INTN)nsec, (INTN)LOG_BATCH_SECS);
            }
            g_logFlushFails++;
            g_logOn = FALSE;
            return;
        }
        g_logSectors += nsec;
        g_logFill = 0;
        g_logSec += (UINT32)nsec;
        if (g_logSec >= LOG_SECTORS) g_logSec = 1;
        /* Указатель двигается на границе ПАКЕТА, а не пакета по 8 секторов:
         * при полном пакете это то же самое, а при коротком хвосте
         * указатель не сбивается с шага. */
        if ((g_logSec & 31) == 0) log_store_ptr(g_logBio, g_logSec);
    }
}

/* записать один байт в накопитель сектора */
static void
log_putc(CHAR8 c)
{
    if (!g_logOn || g_logBio == NULL) return;
    if (g_logFill >= LOG_BATCH_BYTES) log_flush_sector(FALSE);
    if (!g_logOn) return;
    g_logBuf[g_logFill++] = c;
}

static void
log_write(const CHAR8 *s)
{
    while (*s) log_putc(*s++);
}

/* v3.47: выгрузка накопленного ДО кольца вывода в файловый лог.
 *
 * Вызывается сразу после успешного выделения кольца, то есть когда лог на
 * флешке уже есть и работает. Пишем через log_write - тот же путь, что и
 * все работающие строки лога (ulogf в итоге тоже приходит в log_putc).
 *
 * Правило перевода в ASCII то же, что у ulogf и у fx_pr_dump: непечатные
 * и не-ASCII символы, включая кириллицу, становятся '?'. Это делает файл
 * лога пригодным для поиска, ценой читаемости русских слов - но русские
 * слова в логе и так не несут смысла, которого нет в английских.
 *
 * Пропуск не молчит: если буфер переполнился и часть строк отброшена,
 * это печатается числом, а не остаётся неизвестным. */
static VOID
fx_pr_pre_flush(void)
{
    UINTN i;

    if (g_prPreFlushed) return;
    g_prPreFlushed = TRUE;      /* даже если писать некуда - второй раз не пробуем */

    if (!g_logOn) {
        /* Лога нет - сохраняем хотя бы это сведение, иначе потеря и этого
         * факта останется незамеченной. */
        ulogf(L"PRE   console pre-ring buffer DISCARDED: log was off, "
              L"%d chars lost\r\n", (INTN)g_prPreLen);
        return;
    }
    if (g_prPreLen == 0) return;

    log_write("\nPRE ==== console output before the ring existed "
              "(banner + log_init device path walk) ====\n");
    for (i = 0; i < g_prPreLen; i++) {
        CHAR16 c = g_prPre[i];
        log_putc((c == L'\n' || c == L'\r') ? '\n'
                 : ((c < 0x20 || c > 0x7E) ? '?' : (CHAR8)c));
    }
    log_write("\nPRE ==== end pre-ring output ====\n");
    /* Счётчик потерь - сразу сюда, а не в fx_io_report: тот вызывается
     * сильно позже, и если между этой точкой и ним что-то пойдёт не так,
     * число потерь потеряется вместе с причиной. */
    ulogf(L"PRE   pre-ring buffer: %d chars, capacity %d, DROPPED %d\r\n",
          (INTN)g_prPreLen, (INTN)FX_PR_PRE_CHARS, (INTN)g_prPreDropped);
}

/* Проверка, что образ действительно лежит по адресу, который мы отдаём DMA.
 * Адрес используется и как VA (CopyMem), и как PA (DMA GSP); если VA != PA,
 * CPU пишет в чужую страницу, а DMA читает пустую. На 70HX так и было:
 *     blobIMEM0=0xEC547D23  bufIMEM0=0x00000001  phys=0x113025000
 * Сверяем слова константы с тем, что физически лежит по адресу. */
static void
log_buf_check(const CHAR16 *tag, const UINT8 *src, UINT64 addr, UINTN size)
{
    UINT32 s0, b0, s1, b1;
    if (!g_logOn || addr == 0 || src == NULL || size < 8) return;
    s0 = *(const UINT32*)(const void *)src;
    b0 = *(const UINT32*)(UINTN)addr;
    s1 = *(const UINT32*)(const void *)(src + 4);
    b1 = *(const UINT32*)(UINTN)(addr + 4);
    ulogf(L"BUF   %s addr=0x%llx size=0x%llx src0=0x%08x buf0=0x%08x "
          L"src4=0x%08x buf4=0x%08x %s\n",
          tag, addr, size, s0, b0, s1, b1,
          (s0 == b0 && s1 == b1) ? L"OK" : L"MISMATCH");
}

/* v3n: РЕШАЮЩАЯ самопроверка буфера. До сих пор не было ясно, куда именно
 * не ложится образ: адрес не тот, память не пишется, или копируется не
 * оттуда. Поэтому проверяем буфер в три независимых шага и печатаем
 * контрольные суммы (CRC32) всего образа:
 *   1) память живая?   пишем 5 меченых слов, читаем обратно
 *   2) суммы совпали?   CRC32(блоб) против CRC32(буфер) по всему размеру
 *   3) где именно порча? печатаем 8 равномерно разнесённых 32-битных слов
 * Одно слово CRC32 одинаково и для всего образа, и для его половины —
 * поэтому суммы печатаем двумя: CRC32(0..size) и CRC32(size/2..size). */
static UINT32 crc32_upd(UINT32 crc, const UINT8 *p, UINTN n)
{
    UINTN i;
    int k;
    for (i = 0; i < n; i++) {
        crc ^= p[i];
        for (k = 0; k < 8; k++)
            crc = (crc >> 1) ^ (0xEDB88320U & (UINT32)(-(INT32)(crc & 1)));
    }
    return crc;
}

static void
log_mem_selftest(const CHAR16 *tag, const UINT8 *src, UINT64 addr, UINTN size)
{
    static const UINT32 mag[5] = { 0xA5A5A5A5U, 0x5A5A5A5AU, 0xC3C3C3C3U,
                                   0x96969696U, 0x0F0F0F0FU };
    UINT64 mo[5];
    UINT32 rb[5], cs, cb, ch, chb;
    int i, bad = 0;

    if (!g_logOn || addr == 0 || src == NULL || size < 0x2000) return;

    mo[0] = 0; mo[1] = 0x1000; mo[2] = size / 2; mo[3] = size - 0x1000; mo[4] = 0;

    /* 1) память живая: 5 слов по 4КБ */
    for (i = 0; i < 5; i++)
        *(volatile UINT32 *)(UINTN)(addr + mo[i]) = mag[i];
    for (i = 0; i < 5; i++) {
        rb[i] = *(volatile UINT32 *)(UINTN)(addr + mo[i]);
        if (rb[i] != mag[i]) bad++;
    }
    ulogf(L"MEM   %s addr=0x%llx W/R %s (bad %d)\n", tag, addr,
          bad ? L"DEAD" : L"ok", (INTN)bad);

    /* 2) копируем образ и сверяем CRC32 целиком и со второй половины */
    CopyMem((VOID *)(UINTN)addr, src, size);
    cs = crc32_upd(0xFFFFFFFFU, src, size);
    cb = crc32_upd(0xFFFFFFFFU, (const UINT8 *)(UINTN)addr, size);
    ch  = crc32_upd(0xFFFFFFFFU, src + size / 2, size / 2);
    chb = crc32_upd(0xFFFFFFFFU, (const UINT8 *)(UINTN)(addr + size / 2), size / 2);
    ulogf(L"MEM   %s CRC32 blob=0x%08x buffer=0x%08x %s | tail blob=0x%08x "
          L"buffer=0x%08x %s\n", tag, cs, cb, cs == cb ? L"OK" : L"MISMATCH",
          ch, chb, ch == chb ? L"OK" : L"MISMATCH");

    /* 3) где именно расходится — 8 слов через весь образ */
    ulogf(L"MEM   %s words:", tag);
    for (i = 0; i < 8; i++) {
        UINTN off = (size / 8) * (UINTN)i;
        UINT32 a = *(const UINT32 *)(const void *)(src + off);
        UINT32 b = *(UINT32 *)(UINTN)(addr + off);
        ulogf(L" 0x%04llx:%08x/%08x", (UINT64)off, a, b);
    }
    ulogf(L"\n");
}

/* единственная точка записи в лог.
 *
 * ФОРМАТИРОВАНИЕ. Раньше здесь стоял AsciiVSPrint, и он оказался НЕ
 * пригоден для чисел: в логе значения выходили неверные (want=0x00000001
 * вместо 0xEC547D23, хотя Print() на экране печатает те же числа
 * правильно). Плюс его %s читает ШИРОКИЕ строки и печатает только младшие
 * байты, останавливаясь на первом 0x0000, — из-за чего «OK» превращалось
 * в «O», а «MISMATCH» в «MSAC».
 *
 * Поэтому форматируем ТЕМ ЖЕ кодом, что и Print() на экране
 * (UnicodeVSPrint), а потом переводим результат в ASCII. Сектор лога
 * обязан быть ASCII: читающий скрипт декодирует через
 * [Text.Encoding]::ASCII, и байты >= 0x80 стали бы '?'. */
static void
ulogf(const CHAR16 *fmt, ...)
{
    CHAR16 wbuf[400];
    va_list ap;
    UINTN i;
    /* v3.17: замер САМОГО ulogf, включая запись секторов. Это точный
     * счётчик: ulogf - наша функция, замер охватывает ровно её работу. */
    UINT64 u0 = fx_now_us();
    if (!g_logOn) return;
    g_ulogCalls++;
    va_start(ap, fmt);
    /* ВАЖНО: вторым аргументом UnicodeVSPrint ждёт размер В БАЙТАХ, а не
     * число символов. Проверено на gnu-efi 4.0.0: функция начинается с
     *     shr $1,%rsi ; sub $0x1,%rsi
     * то есть сама переводит байты в символы как BufferSize/2 - 1.
     *
     * Раньше здесь стояло sizeof(wbuf)/sizeof(wbuf[0]) = 400, и функция
     * считала 400/2 - 1 = 199 символов. Любая строка лога длиннее 199
     * молча обрывалась. Наблюдалось так (2026-09-29):
     *     META ... bootBin=0x1F7DFA000 bootCounGEOM  margin=0x8000000 (128 MB)
     * — 199 символов, без перевода строки, следующая строка приклеена.
     *
     * Именно поэтому оборванная строка выглядела как «сломанный формат»:
     * ложный след вели к правке не того. Формат был ни при чём — предел
     * наступил раньше, чем разбиралисьSpecifier'ы.
     *
     * Строки MEM длиннее 199 в том же логе целые: они собираются
     * несколькими вызовами ulogf (заголовок + цикл), и предел действует
     * на КАЖДЫЙ вызов по отдельности. */
    UnicodeVSPrint(wbuf, sizeof(wbuf), fmt, ap);
    va_end(ap);
    for (i = 0; wbuf[i] && i < 400; i++) {
        CHAR16 c = wbuf[i];
        log_putc((c == L'\t' || c == L'\n' || c == L'\r') ? (CHAR8)c
             : ((c < 0x20 || c > 0x7E) ? '?' : (CHAR8)c));
    }
    if (u0) g_ulogUs += fx_now_us() - u0;
}

/* ==== ЭКРАННЫЙ БАННЕР ВЕРДИКТА (v3.45) ====
 *
 * Рамка на 70 символов. Ширина подобрана под самую длинную строку блока:
 * '  SS0/SS1 = 0x........ / 0x........    GFX_SPEED_SELECT = 0x........'
 * ровно 68 символов, и 70 помещаются в стандартные 80 колонок UEFI-консоли.
 *
 * Экран и лог получают ОДИН И ТОТ ЖЕ текст. Это не украшение: экран
 * исчезает, если машина зависнет, и тогда единственным источником остаётся
 * лог. Два независимо написанных текста рано или поздно разойдутся, и
 * человек увидит «разблокировано» там, где графика не поднялась.
 *
 * VRCFMT 1 — маркер формата, а не данные. Он нужен проверяющему скрипту,
 * чтобы отличить «лог старой сборки, где вердикта ещё не было» от «новой
 * сборки, где баннер почему-то не напечатался». Без него проверка вердикта
 * падала бы на всех исторических логах, то есть её отключили бы, и она
 * перестала бы что-либо проверять. */
static void
unlock_verdict_banner(void)
{
    UINT32 ss0 = g_snapSs0, ss1 = g_snapSs1, gfx = g_snapGfx;
    const CHAR16 *v = unlock_verdict_text(ss0, ss1, gfx);

    /* v3.46: Print() ЗДЕСЬ БОЛЬШЕ НЕ ПЕЧАТАЕТСЯ - и это не отступление от
     * плана, а его уточнение.
     *
     * #define Print(...) fx_print(...) перенаправляет ВЕСЬ вывод в кольцо
     * 64 КБ в ОЗУ. В консоль из него попадает только пульс раз в 512 вызовов
     * и финальный дамп последних 12 строк (fx_pr_console_dump). Причина
     * видна в замере: 17,0 мс на вызов, то есть 726 прямых вызовов стоили
     * бы 12,3 с. Баннер, напечатанный через Print, попадал в кольцо и
     * конкурировал за 12 строк финального дамма - а должен был быть тем, что
     * человек видит наверняка.
     *
     * Хуже: кольцо вообще не выгружается в файловый лог. fx_pr_dump() должен
     * писать заголовок 'PRN ==== console ring ====', и его нет ни в одном
     * прогоне начиная с v3.17 (дефект, зафиксированный в v3.19). То есть
     * копия вердикта в кольце была бы потеряна целиком.
     *
     * Поэтому: экран - через fx_console_raw (см. unlock_verdict_print_screen),
     * файл - здесь, через ulogf, который до флешки доходит по построению. */
    ulogf(L"VRCFMT 1\n");
    ulogf(L"VRC  %s : %s\n", TARGET_NAME, v);
    ulogf(L"VRC  SS0/SS1 = 0x%08x / 0x%08x    GFX_SPEED_SELECT = 0x%08x\n",
          ss0, ss1, gfx);
}

/* Рамка вердикта НА НАСТОЯЩУЮ КОНСОЛЬ, мимо кольца.
 *
 * Единственный вывод, за недетерминированность которого платить заданно.
 * Цена: 5 строк x 17,0 мс = 85 мс - сопоставимо с целым последним рычагом
 * по 100 мс, который снимали. Это осознанный размен: видимость вердикта
 * важнее 85 мс, потому что без него человек при сбое смотрит на «last 12
 * lines» и не видит ничего.
 *
 * ВЫЗЫВАЕТСЯ ПОСЛЕ fx_pr_console_dump() - иначе дамп последних строк
 * напечатался бы поверх и вытолкнул рамку вверх, то есть ровно то, ради
 * чего всё затевалось. */
static void
unlock_verdict_print_screen(void)
{
    UINT32 ss0 = g_snapSs0, ss1 = g_snapSs1, gfx = g_snapGfx;
    const CHAR16 *v = unlock_verdict_text(ss0, ss1, gfx);
    CHAR16 b[512];

    UnicodeSPrint(b, sizeof(b), L"\n" VERDICT_RULE L"\n");
    fx_console_raw(b);
    UnicodeSPrint(b, sizeof(b), L"  %s : %s\n", TARGET_NAME, v);
    fx_console_raw(b);
    UnicodeSPrint(b, sizeof(b),
                  L"  SS0/SS1 = 0x%08x / 0x%08x    GFX_SPEED_SELECT = 0x%08x\n",
                  ss0, ss1, gfx);
    fx_console_raw(b);
    UnicodeSPrint(b, sizeof(b),
                  L"  log: out\\pull-log.ps1    full log on stick LBA %d..%d\n",
                  (INTN)LOG_LBA, (INTN)(LOG_LBA + LOG_SECTORS - 1));
    fx_console_raw(b);
    UnicodeSPrint(b, sizeof(b), L"" VERDICT_RULE L"\n");
    fx_console_raw(b);
}

/* Есть ли на томе наш собственный загрузчик EFI/BOOT/BOOTX64.EFI?
 *
 * Отбор флешки по геометрии («первый MBR с разделом 0xEF и FAT32»)
 * НЕНАДЁЖЕН: на машине с несколькими USB-устройствами прошивка отдаёт
 * BlockIo и для них, и приложение писало лог не на ту флешку — на
 * устройство с разделом с LBA 0xB00 вместо 0x800.
 *
 * Единственный однозначный признак нужной флешки — сам загрузчик на
 * ней. Ищем его своим же FAT32-обходом поверх BlockIo (без SFS, который
 * на этой плате вешает прошивку). Свойства тома проверяем по-настоящему,
 * а не «похоже на FAT32». */

/* ВНИМАНИЕ: вариант с обходом каталога (проверка «есть ли на томе
 * EFI/BOOT/BOOTX64.EFI» через cmp90_fat_dir_find) УДАЛЁН. На реальном
 * железе он вешал загрузку: приложение зависало сразу после печати
 * сведений об устройстве. Обход каталога FAT32 на загрузочной флешке
 * трогает область данных тома (смещение ~16 МБ) — на этой плате такие
 * обращения к USB не проверены, а SimpleFileSystem здесь уже вешает
 * прошивку (см. KNOWN-ISSUES, п. 8). Никаких лишних обращений к диску
 * в логировании быть не должно: DevicePath даёт ответ бесплатно. */

/* Длина device path без ПОСЛЕДНЕГО узла (последний — узел файла
 * \EFI\BOOT\BOOTX64.EFI). Родительский путь заканчивается на узле
 * носителя, и по нему LocateDevicePath находит BlockIo диска. */
static UINTN
log_parent_path_size(EFI_DEVICE_PATH *path)
{
    UINT8 *base = (UINT8 *)path;
    UINTN off = 0, prev = 0;
    if (!path) return 0;
    while (!IsDevicePathEndType((EFI_DEVICE_PATH *)(base + off))) {
        EFI_DEVICE_PATH *n = (EFI_DEVICE_PATH *)(base + off);
        prev = off;
        off  += 4 + ((UINTN)n->Length[0] | ((UINTN)n->Length[1] << 8));
        if (off > 4096) return 0;      /* защита от мусора в пути */
    }
    return prev;
}

/* Найти флешку и начать лог.
 *
 * ТРИ попытки, каждая дешевле и безопаснее предыдущей; порядок — от
 * самого надёжного к запасному, и каждая печатает свой результат.
 *
 * Чего здесь НЕТ и не должно быть (проверено на железе):
 *   - обхода каталогов FAT32: он ВЕШАЕТ загрузку на этой плате;
 *   - LocateDevicePath по разобранному вручную DevicePath: путь от
 *     DeviceHandle на этой прошивке не распарсился (log_parent_path_size
 *     вернул 0), а логика была единственным способом найти флешку;
 *   - вызовов SimpleFileSystem: они вешают прошивку (п. 8 KNOWN-ISSUES).
 *
 * Рабочий критерий — геометрия, которую задаёт out/make-usb-stick.ps1:
 * MBR, единственный раздел типа 0xEF с LBA 2048, FAT32 (FilSysType по
 * 0x52), и размер >= 4 ГБ. Именно этот разрез отличает нашу флешку от
 * второго USB-устройства, которое прошивка тоже отдаёт в BlockIo (у него
 * раздел начинается с 0xB00). Плюс контрольная запись с чтением
 * обратно: устройство обязано быть реально доступным на запись. */

/* Печать узлов device path — чистая диагностика, никакого I/O. */
static void
log_dump_devpath(const CHAR16 *tag, EFI_DEVICE_PATH *path)
{
    UINT8 *p = (UINT8 *)path;
    UINTN off = 0, shown = 0;
    if (!path) { Print(L"[log] %s: путь=NULL\n", tag); return; }
    Print(L"[log] %s:\n", tag);
    for (;;) {
        UINT8 t, s;
        UINTN ln;
        if (off > 2048 || shown >= 12) break;
        t  = p[off];
        s  = p[off + 1];
        ln = (UINTN)p[off + 2] | ((UINTN)p[off + 3] << 8);
        if (t == END_DEVICE_PATH_TYPE) {
            Print(L"[log]   узел END (тип 0x%02x подтип 0x%02x)\n", t, s);
            break;
        }
        if (ln < 4) {      /* мусор в пути — дальше идти нельзя */
            Print(L"[log]   узел %d: тип 0x%02x подтип 0x%02x длина %d "
                  L"<<< МУСОР, останавливаюсь\n", (INTN)shown, t, s, (INTN)ln);
            break;
        }
        Print(L"[log]   узел %d: тип 0x%02x подтип 0x%02x длина %d\n",
              (INTN)shown, t, s, (INTN)ln);
        off += ln;
        shown++;
    }
    Print(L"[log]   всего байт разобрано: %d\n", (INTN)off);
}

/* Проверить устройство как нашу флешку. Только два чтения по 512 байт —
 * ровно столько же, сколько делает fw-read, который на этой плате
 * работает. Никаких обходов томов. */
static BOOLEAN
log_stick_ok(EFI_BLOCK_IO_PROTOCOL *bio, UINT32 *outPartLba,
             const CHAR16 **why)
{
    static UINT8 mbr[512], bpb[512];
    UINT32 lba, tot;
    UINTN part;

    if (bio == NULL || bio->Media == NULL) { *why = L"нет BlockIo/Media"; return FALSE; }
    if (bio->Media->BlockSize != 512)   { *why = L"blocksize != 512"; return FALSE; }
    if (bio->Media->LastBlock < LOG_LBA + LOG_SECTORS) {
        *why = L"меньше 4 ГБ"; return FALSE;
    }
    if (EFI_ERROR(uefi_call_wrapper(bio->ReadBlocks, 5, bio,
                                    bio->Media->MediaId, 0, 512, mbr))) {
        *why = L"не читается LBA 0"; return FALSE;
    }
    if (mbr[510] != 0x55 || mbr[511] != 0xAA) { *why = L"нет MBR 55AA (GPT?)"; return FALSE; }
    /* ровно один раздел типа 0xEF, начинающийся с LBA 2048: этот разрез
     * и отличает нашу флешку от прочих USB-устройств */
    lba = 0;
    for (part = 0; part < 4; part++) {
        UINT8 *e = mbr + 446 + 16 * part;
        if (e[4] != 0xEF) continue;
        if (lba != 0) { *why = L"больше одного FAT32-раздела"; return FALSE; }
        lba = (UINT32)e[8] | ((UINT32)e[9] << 8) |
              ((UINT32)e[10] << 16) | ((UINT32)e[11] << 24);
    }
    if (lba == 0)   { *why = L"нет раздела 0xEF"; return FALSE; }
    if (lba != 2048) {
        *why = L"раздел не с LBA 2048"; return FALSE;
    }
    if (EFI_ERROR(uefi_call_wrapper(bio->ReadBlocks, 5, bio,
                                    bio->Media->MediaId, lba, 512, bpb))) {
        *why = L"не читается загрузочный сектор раздела"; return FALSE;
    }
    if (bpb[510] != 0x55 || bpb[511] != 0xAA) { *why = L"у раздела нет 55AA"; return FALSE; }
    /* FilSysType по 0x52. По 0x54 читается хвост поля ("T32   3?") —
     * с такой ошибкой флешка молча отбраковывалась. */
    if (CompareMem(bpb + 0x52, "FAT32   ", 8) != 0) { *why = L"не FAT32"; return FALSE; }
    tot = (UINT32)bpb[32] | ((UINT32)bpb[33] << 8) |
          ((UINT32)bpb[34] << 16) | ((UINT32)bpb[35] << 24);
    if (tot == 0) { *why = L"нулевой размер тома"; return FALSE; }
    if (outPartLba) *outPartLba = lba;
    return TRUE;
}

/* v3n: ГДЕ ПРОДОЛЖАТЬ ЛОГ.
 *
 * Задача: не затирать лог предыдущего прогона. Первый вариант — прочитать
 * всю область (1 МБ) и найти первый нулевой сектор — ПОВЕСИЛ ПРОШИВКУ на
 * загрузке: кандидат #0 напечатался, и на этом всё встало. Крупные чтения
 * с этой флешки эта AMI-прошивка не тянет (тот же эффект раньше давало
 * чтение 84-МБ образа).
 *
 * Рабочий вариант: хранить указатель «с какого сектора писать» в секторе 0
 * области. Это ОДИН блок 512 байт — ровно тот размер, который уже proven
 * рабочим для записи лога. Никаких больших операций.
 *   сектор 0: "CMPN" + 4 байта next (little-endian) + нули.
 * Лог пишется в сектора 1..LOG_SECTORS-1, то есть физически в пределах
 * отведённых 2048 секторов; ничего за их пределами не трогаем. */
#define LOG_PTR_MAGIC "CMPN"

static void
log_store_ptr(EFI_BLOCK_IO_PROTOCOL *bio, UINT32 next)
{
    UINT8 buf[512];
    SetMem(buf, 512, 0);
    CopyMem(buf, LOG_PTR_MAGIC, 4);
    buf[4] = (UINT8)(next & 0xFF);
    buf[5] = (UINT8)((next >> 8) & 0xFF);
    buf[6] = (UINT8)((next >> 16) & 0xFF);
    buf[7] = (UINT8)((next >> 24) & 0xFF);
    uefi_call_wrapper(bio->WriteBlocks, 5, bio, bio->Media->MediaId,
                      LOG_LBA, 512, buf);
}

static UINT32
log_load_ptr(EFI_BLOCK_IO_PROTOCOL *bio)
{
    UINT8 buf[512];
    UINT32 next;
    EFI_STATUS st = uefi_call_wrapper(bio->ReadBlocks, 3, bio,
                                      LOG_LBA, 512, buf);
    if (EFI_ERROR(st)) return 1;
    if (CompareMem(buf, LOG_PTR_MAGIC, 4) != 0) return 1;   /* первый запуск: с 1 */
    next = (UINT32)buf[4] | ((UINT32)buf[5] << 8) |
           ((UINT32)buf[6] << 16) | ((UINT32)buf[7] << 24);
    if (next < 1 || next >= LOG_SECTORS) return 1;
    return next;
}

/* v3n: ОДНОРАЗОВАЯ очистка области лога.
 *
 * Хостовая запись на диск заблокирована (Windows даёт Access Denied, пока
 * том смонтирован), поэтому чистим из приложения. Пишем нули блоками по
 * 64 сектора — 32 записи на всю область, быстро. После очистки указатель
 * сбрасывается, и следующий прогон начинается с сектора 1 на чистом листе.
 *
 * ВАЖНО (2026-09-28): очистка теперь БЕЗУСЛОВНАЯ, каждый прогон.
 *
 * Раньше за очисткой стоял одноразовый флаг g_logClear, и лог накапливался
 * («прогон продолжает с сектора N (логи не затираются)»). На флешке лежала
 * конкатенация всех прошлых прогонов, а новый перезаписывал только начало.
 *
 * Чем это кончилось: в логе оказались строки
 *     DMA   imem_sec_bit=0 cmd=0x00000604
 * которых в записанном EFI физически нет (проверено поиском по бинарю) —
 * это хвост прогона ПРЕДЫДУЩЕЙ сборки. Метки времени шли назад
 * (t=33368 -> t=29756). Из-за этого вывод «после правки бита IMEM три
 * ретрая всё ещё идут по старому коду» был ложным: ретраи шли по новому
 * коду, а строки просто принадлежали прошлому прогону.
 *
 * Итог: без изоляции прогонов нельзя делать выводы «что изменилось после
 * правки» — а именно такие выводы и нужны. Стоимость очистки — 1 МБ
 * записи на флешку, это ничто по сравнению с загрузкой UEFI. */
static BOOLEAN g_logClear = TRUE;   /* очищать область лога на каждом прогоне */

static void
log_clear_area(EFI_BLOCK_IO_PROTOCOL *bio)
{
    static UINT8 buf[64 * 512];
    UINT32 sec;
    SetMem(buf, sizeof(buf), 0);
    for (sec = 1; sec < LOG_SECTORS; sec += 64) {
        UINTN n = LOG_SECTORS - sec;
        if (n > 64) n = 64;
        uefi_call_wrapper(bio->WriteBlocks, 5, bio, bio->Media->MediaId,
                          LOG_LBA + sec, (UINTN)n * 512, buf);
    }
    /* указатель тоже сбрасываем — иначе останется старый номер */
    log_store_ptr(bio, 1);
    ulogf(L"LOG   area cleared, next run starts at sector 1\n");
}

/* Заголовок лога + контрольная запись.
 *
 * v3n: `how` — ШИРОКАЯ строка (CHAR16*), не CHAR8*. Раньше здесь стояло
 * `const CHAR8 *how`, и "geometry" уходило в %s UnicodeVSPrint, который
 * читает %s как CHAR16*. Узкие байты 'g','e' читались как символ 0x6567 —
 * вне диапазона 0x20..0x7E, и ulogf() превращал его в '?'. В логе от
 * 2026-09-29 это выглядело так:
 *     stick ... sec=1 by=????????T????
 * где '????????' — это «geometry», прочитанная по два байта как wide, а
 * дальше — хвост мусора, потому что обход не остановился на границе
 * литерала. Та же беда описана в комментарии выше про AsciiVSPrint, но при
 * переходе на UnicodeVSPrint её повторили: узкая строка в %s недопустима
 * в обоих. Правило: в %s для ulogf()/Print() передавать ТОЛЬКО L"...". */
static void
log_start(EFI_BLOCK_IO_PROTOCOL *bio, UINT32 lba, const CHAR16 *how)
{
    UINT32 startSec = log_load_ptr(bio);

    if (g_logClear) {
        g_logClear = FALSE;
        log_clear_area(bio);
        startSec = 1;
    }

    g_logBio  = bio;
    g_logSec  = startSec;
    g_logFill = 0;
    g_logOn   = TRUE;
    /* указатель двигаем сразу: если прогон упадёт/зависнет, следующий
     * начнётся с текущего места, а не поверх него */
    log_store_ptr(bio, startSec);
    Print(L"[log] флешка = %ld МБ, lastLBA=0x%llx, раздел с LBA 0x%x, "
          L"лог с LBA 0x%llx\n",
          (INTN)((bio->Media->LastBlock * bio->Media->BlockSize) >> 20),
          bio->Media->LastBlock, lba, LOG_LBA);
    Print(L"[log] прогон продолжает с сектора %d (логи не затираются)\n",
          (INTN)startSec);
    Print(L"[log] способ отбора: %s\n", how);
    log_write(LOG_HDR);
    ulogf(L"profile=%s pci=10de:%04x fb=0x%llx frts=0x%llx wpr2=0x%08x/0x%08x\n",
         TARGET_NAME, (INTN)TARGET_PCI_DEV, TARGET_FB_SIZE,
         TARGET_FRTS_OFFSET, TARGET_WPR2_LO, TARGET_WPR2_HI);
    ulogf(L"stick  lastLba=0x%llx partLba=0x%x logLba=0x%llx sec=%d by=%s\n",
         bio->Media->LastBlock, lba, LOG_LBA, (INTN)startSec, how);
    log_write("\n");
    log_flush_sector(TRUE);
    if (!g_logOn)
        Print(L"[log] ВНИМАНИЕ: контрольная запись НЕ прошла — лог недоступен\n");
}

static void
log_init(EFI_HANDLE ImageHandle)
{
    EFI_LOADED_IMAGE_PROTOCOL *li = NULL;
    EFI_DEVICE_PATH_PROTOCOL *fdp = NULL;
    EFI_HANDLE *hs = NULL;
    UINTN n = 0, i;
    EFI_STATUS st;

    /* --- попытка 1: устройство загрузки через DevicePath (диагностика) --- */
    st = uefi_call_wrapper(BS->HandleProtocol, 3, ImageHandle,
                           &gEfiLoadedImageProtocolGuid, &li);
    if (!EFI_ERROR(st) && li != NULL) {
        log_dump_devpath(L"device path образа", (EFI_DEVICE_PATH *)li->FilePath);
        st = uefi_call_wrapper(BS->HandleProtocol, 3, li->DeviceHandle,
                               &gEfiDevicePathProtocolGuid, &fdp);
        if (!EFI_ERROR(st) && fdp != NULL)
            log_dump_devpath(L"device path DeviceHandle", (EFI_DEVICE_PATH *)fdp);
        else
            Print(L"[log] DeviceHandle: нет DevicePath (%r)\n", st);
    } else {
        Print(L"[log] нет EFI_LOADED_IMAGE_PROTOCOL (%r)\n", st);
    }

    /* --- попытка 2: перебор BlockIo по геометрии флешки --- */
    st = uefi_call_wrapper(BS->LocateHandleBuffer, 5, ByProtocol,
                           &gEfiBlockIoProtocolGuid, NULL, &n, &hs);
    if (EFI_ERROR(st) || n == 0) {
        Print(L"[log] BlockIo-устройств нет (%r) — лог только на экран\n", st);
        return;
    }
    for (i = 0; i < n; i++) {
        EFI_BLOCK_IO_PROTOCOL *bio = NULL;
        UINT32 lba = 0;
        const CHAR16 *why = NULL;
        if (EFI_ERROR(uefi_call_wrapper(BS->HandleProtocol, 3, hs[i],
                                         &gEfiBlockIoProtocolGuid, &bio)))
            continue;
        if (bio != NULL && bio->Media != NULL)
            Print(L"[log] кандидат #%d: %ld МБ, lastLBA=0x%llx\n", (INTN)i,
                  (INTN)((bio->Media->LastBlock * bio->Media->BlockSize) >> 20),
                  bio->Media->LastBlock);
        if (!log_stick_ok(bio, &lba, &why)) {
            Print(L"[log] кандидат #%d отброшен: %s\n", (INTN)i, why);
            continue;
        }
        log_start(bio, lba, L"geometry");
        if (g_logOn) return;
    }
    Print(L"[log] флешка не найдена среди %d устройств — лог только на экран\n",
          (INTN)n);
}

/* чтение байтового диапазона внутри раздела через BlockIo */
static EFI_STATUS
cmp90_bio_read(EFI_BLOCK_IO_PROTOCOL *bio, UINT64 lbaPartStart,
               UINT64 byteOff, UINTN size, VOID *dest)
{
    STATIC UINT8 bounce[4096];
    UINT32 bs = bio->Media->BlockSize;
    UINT64 off = byteOff;
    UINT8 *dst = (UINT8 *)dest;

    if (bs == 0 || bs > sizeof(bounce)) return EFI_INVALID_PARAMETER;
    while (size) {
        UINT64 lba = lbaPartStart + off / bs;
        UINTN inBlk = (UINTN)(off % bs);
        UINTN chunk = bs - inBlk;
        EFI_STATUS st;
        if (chunk > size) chunk = size;
        st = uefi_call_wrapper(bio->ReadBlocks, 5, bio, bio->Media->MediaId,
                               lba, bs, bounce);
        if (EFI_ERROR(st)) return st;
        CopyMem(dst, bounce + inBlk, chunk);
        dst += chunk; off += chunk; size -= chunk;
    }
    return EFI_SUCCESS;
}

static BOOLEAN cmp90_eqi(const CHAR16 *a, const CHAR16 *b)
{
    while (*a && *b) {
        CHAR16 ca = *a, cb = *b;
        if (ca >= L'a' && ca <= L'z') ca -= 0x20;
        if (cb >= L'a' && cb <= L'z') cb -= 0x20;
        if (ca != cb) return FALSE;
        a++; b++;
    }
    return *a == *b;
}

/* следующая FAT32-запись таблицы FAT */
static EFI_STATUS
cmp90_fat_next(EFI_BLOCK_IO_PROTOCOL *bio, UINT64 lbaPartStart,
               const UINT8 *bpb, UINT32 clus, UINT32 *next)
{
    UINT32 bps = bpb[11] | (bpb[12] << 8);
    UINT32 rsvd = bpb[14] | (bpb[15] << 8);
    UINT32 fatOff = rsvd * bps + clus * 4;
    UINT32 v = 0;
    EFI_STATUS st = cmp90_bio_read(bio, lbaPartStart, fatOff, 4, &v);
    if (!EFI_ERROR(st)) *next = v & 0x0FFFFFFFu;
    return st;
}

/* поиск компонента пути в каталоге FAT32 (с поддержкой LFN).
 * dirClus — первый кластер каталога; имя сравнивается без регистра. */
static EFI_STATUS
cmp90_fat_dir_find(EFI_BLOCK_IO_PROTOCOL *bio, UINT64 lbaPartStart,
                   const UINT8 *bpb, UINT32 dirClus,
                   const CHAR16 *name, UINT32 *outClus, UINT64 *outSize)
{
    UINT32 bps = bpb[11] | (bpb[12] << 8);
    UINT32 spc = bpb[13];
    UINT32 rsvd = bpb[14] | (bpb[15] << 8);
    UINT32 nfats = bpb[16];
    UINT32 fatsz = bpb[36] | (bpb[37]<<8) | (bpb[38]<<16) | (bpb[39]<<24);
    UINT32 dataOff = (rsvd + nfats * fatsz) * bps;
    UINT32 clus = dirClus;
    UINTN guard;

    for (guard = 0; guard < 65536 && clus >= 2 && clus < 0x0FFFFFF8; guard++) {
        UINTN csz = spc * bps;
        UINT64 cOff = dataOff + (UINT64)(clus - 2) * spc * bps;
        UINT8 *buf = cmp90_alloc(csz);
        UINTN e;
        EFI_STATUS st;
        if (!buf) return EFI_OUT_OF_RESOURCES;
        st = cmp90_bio_read(bio, lbaPartStart, cOff, csz, buf);
        if (EFI_ERROR(st)) { cmp90_free(buf); return st; }

        {
            CHAR16 lfn[260]; BOOLEAN haveLfn = FALSE;
            for (e = 0; e + 32 <= csz; e += 32) {
                UINT8 *ent = buf + e;
                UINT8 attr = ent[11];
                if (ent[0] == 0x00) { cmp90_free(buf); return EFI_NOT_FOUND; }
                if (ent[0] == 0xE5) { haveLfn = FALSE; continue; }
                if (attr == 0x0F) {
                    /* LFN-фрагмент: seq N хранит символы (N-1)*13 .. N*13-1.
                     * Физический порядок N|0x40, N-1, ..., 1 — раскладка
                     * base=(seq-1)*13 корректна при любом порядке прихода.
                     * После имени в чанке идёт 0x0000, дальше 0xFFFF —
                     * cmp90_eqi остановится на терминанте внутри. */
                    UINTN seq = ent[0] & 0x1F;
                    UINTN base, ci;
                    if (seq == 0 || seq > 20) { haveLfn = FALSE; continue; }
                    base = (seq - 1) * 13;
                    for (ci = 0; ci < 13; ci++) {
                        UINTN src;
                        UINT16 ch;
                        if (ci < 5) src = 1 + ci * 2;
                        else if (ci < 11) src = 14 + (ci - 5) * 2;
                        else src = 28 + (ci - 11) * 2;
                        ch = ent[src] | (ent[src + 1] << 8);
                        if (base + ci < 259) lfn[base + ci] = ch;
                    }
                    haveLfn = TRUE;
                    continue;
                }
                /* обычная запись каталога */
                {
                    BOOLEAN match = FALSE;
                    if (haveLfn && cmp90_eqi(lfn, name)) match = TRUE;
                    if (!match && !(attr & 0x08)) {   /* 0x08 = метка тома */
                        CHAR16 sfn[13]; UINTN si, sj = 0;
                        for (si = 0; si < 8; si++) {
                            UINT8 c = ent[si];
                            if (c == ' ') break;
                            sfn[sj++] = (CHAR16)c;
                        }
                        if (ent[8] != ' ') {
                            sfn[sj++] = L'.';
                            for (si = 8; si < 11; si++) {
                                UINT8 c = ent[si];
                                if (c == ' ') break;
                                sfn[sj++] = (CHAR16)c;
                            }
                        }
                        sfn[sj] = 0;
                        if (cmp90_eqi(sfn, name)) match = TRUE;
                    }
                    haveLfn = FALSE;
                    if (!match) continue;   /* v2.91: БЕЗ FreePool (был use-after-free) */
                    *outClus = (UINT32)(ent[26] | (ent[27] << 8)) |
                               ((UINT32)(ent[20] | (ent[21] << 8)) << 16);
                    *outSize = ent[28] | (ent[29]<<8) | (ent[30]<<16) |
                               ((UINT64)ent[31] << 24);
                    cmp90_free(buf);
                    return EFI_SUCCESS;
                }
            }
        }
        cmp90_free(buf);
        {
            EFI_STATUS st = cmp90_fat_next(bio, lbaPartStart, bpb, clus, &clus);
            if (EFI_ERROR(st)) return st;
        }
    }
    return EFI_NOT_FOUND;
}

/* чтение файла целиком по кластерной цепочке */
static EFI_STATUS
cmp90_fat_read_file(EFI_BLOCK_IO_PROTOCOL *bio, UINT64 lbaPartStart,
                    const UINT8 *bpb, UINT32 firstClus, UINT64 size,
                    UINT8 *dest)
{
    UINT32 bps = bpb[11] | (bpb[12] << 8);
    UINT32 spc = bpb[13];
    UINT32 rsvd = bpb[14] | (bpb[15] << 8);
    UINT32 nfats = bpb[16];
    UINT32 fatsz = bpb[36] | (bpb[37]<<8) | (bpb[38]<<16) | (bpb[39]<<24);
    UINT32 dataOff = (rsvd + nfats * fatsz) * bps;
    UINT32 clus = firstClus;
    UINT64 done = 0;
    UINTN guard;

    for (guard = 0; guard < 4000000 && done < size && clus >= 2 &&
                    clus < 0x0FFFFFF8; guard++) {
        UINT64 cOff = dataOff + (UINT64)(clus - 2) * spc * bps;
        UINTN take = spc * bps;
        if ((UINT64)take > size - done) take = (UINTN)(size - done);
        {
            EFI_STATUS st = cmp90_bio_read(bio, lbaPartStart,
                                           cOff, take, dest + done);
            if (EFI_ERROR(st)) return st;
        }
        done += take;
        {
            EFI_STATUS st = cmp90_fat_next(bio, lbaPartStart, bpb, clus, &clus);
            if (EFI_ERROR(st)) return st;
        }
    }
    return (done == size) ? EFI_SUCCESS : EFI_END_OF_FILE;
}

/* чтение bootmgfw.efi с тома: свой BPB → спуск по пути → кластерная цепочка */
static EFI_STATUS
cmp90_fat_load_bootmgfw(EFI_BLOCK_IO_PROTOCOL *bio, UINT64 lbaPartStart,
                        UINT8 **fileBuf, UINTN *fileSize)
{
    STATIC UINT8 bpb[512];
    UINT32 bps = 0, spc = 0, rsvd = 0, nfats = 0, fatsz = 0, rootClus = 0;
    static const CHAR16 *comps[4] = {
        L"EFI", L"Microsoft", L"Boot", L"bootmgfw.efi"
    };
    UINT32 cur = 0;
    UINT64 sz = 0;
    UINTN ci;
    UINT8 *buf = NULL;
    EFI_STATUS st;

    st = cmp90_bio_read(bio, lbaPartStart, 0, 512, bpb);
    if (EFI_ERROR(st)) return st;
    if (bpb[510] != 0x55 || bpb[511] != 0xAA) return EFI_UNSUPPORTED;

    bps   = bpb[11] | (bpb[12] << 8);
    spc   = bpb[13];
    rsvd  = bpb[14] | (bpb[15] << 8);
    nfats = bpb[16];
    fatsz = bpb[36] | (bpb[37]<<8) | (bpb[38]<<16) | (bpb[39]<<24);
    rootClus = bpb[44] | (bpb[45]<<8) | (bpb[46]<<16) | (bpb[47]<<24);

    if (bps < 512 || bps > 4096 || (bps & (bps-1)) ||
        spc == 0 || spc > 128 || nfats == 0 || nfats > 4 ||
        fatsz == 0 || rootClus < 2)
        return EFI_UNSUPPORTED;

    cur = rootClus;
    for (ci = 0; ci < 4; ci++) {
        Print(L"[preload] ищу \"%s\"...\n", comps[ci]);
        st = cmp90_fat_dir_find(bio, lbaPartStart, bpb, cur,
                                comps[ci], &cur, &sz);
        if (EFI_ERROR(st)) {
            Print(L"[preload] не найдено (%r)\n", st);
            return st;
        }
        if (ci < 3 && sz != 0) return EFI_NOT_FOUND; /* ждали каталог */
    }
    if (sz == 0 || sz > 0x02000000ull) return EFI_BAD_BUFFER_SIZE;

    buf = cmp90_alloc((UINTN)sz);
    if (!buf) return EFI_OUT_OF_RESOURCES;
    st = cmp90_fat_read_file(bio, lbaPartStart, bpb, cur, sz, buf);
    if (EFI_ERROR(st)) { cmp90_free(buf); return st; }

    /* PE-санити: 'MZ' и e_lfanew → 'PE\0\0' */
    if (!(buf[0] == 'M' && buf[1] == 'Z')) { cmp90_free(buf); return EFI_LOAD_ERROR; }

    *fileBuf = buf;
    *fileSize = (UINTN)sz;
    return EFI_SUCCESS;
}

/* обход всех BlockIo-дисков: GPT → ESP → загрузить bootmgfw в ОЗУ.
 * DevicePath запоминаем от ДИСКА с найденным ESP (для LoadImage). */
static void preload_bootmgfw(void)
{
    EFI_HANDLE *H = NULL;
    UINTN n = 0, k;
    EFI_STATUS st;

    Print(L"[preload v2.89] BlockIo перечисление (SFS не используем!)...\n");
    st = uefi_call_wrapper(BS->LocateHandleBuffer, 5, ByProtocol,
                           &cmp90BioGuid, NULL, &n, &H);
    if (EFI_ERROR(st)) { Print(L"[preload] LocateHandleBuffer: %r\n", st); return; }
    Print(L"[preload] блочных устройств: %d\n", n);

    for (k = 0; k < n && !g_bmBuf; k++) {
        EFI_BLOCK_IO_PROTOCOL *bio = NULL;
        BOOLEAN isPart;

        if (uefi_call_wrapper(BS->HandleProtocol, 3, H[k], &cmp90BioGuid,
                              (VOID **)&bio) || !bio || !bio->Media)
            continue;
        isPart = bio->Media->LogicalPartition;
        /* v3n: «%llu» НЕ работает в этом Print (тот же дефект, что и в строке
         * META выше) — печатаем 64-битное значение как «0x%llx». */
        Print(L"[preload] хендл %d: bs=%d last=0x%llx removable=%d logical=%d\n",
              k, bio->Media->BlockSize,
              (UINT64)bio->Media->LastBlock,
              bio->Media->RemovableMedia, isPart);

        /* v2.90: пробуем КАЖДЫЙ хендл как FAT-том напрямую (партиционные
         * хендлы маппятся с LBA0 своего раздела!). Это покрывает MBR-диски,
         * GPT-ESP без парсинга таблиц и superfloppy. */
        {
            UINT8 *fb = NULL; UINTN fsz = 0;
            EFI_STATUS stf = cmp90_fat_load_bootmgfw(bio, 0, &fb, &fsz);
            if (!EFI_ERROR(stf)) {
                g_bmBuf = fb; g_bmSize = fsz;
                g_bmDp = FileDevicePath(H[k], WINDOWS_BOOT_PATH);
                Print(L"[preload] ✓ bootmgfw.efi %d байт в ОЗУ (хендл %d, direct)\n",
                      fsz, k);
                break;
            }
            if (stf != EFI_UNSUPPORTED && stf != EFI_NOT_FOUND)
                Print(L"[preload] хендл %d FAT: %r\n", k, stf);
        }

        /* для ЦЕЛЫХ дисков дополнительно — GPT: ESP-разделы внутри */
        if (!isPart) {
            STATIC UINT8 hdr[512];
            UINT64 partEntLba, espLba = 0;
            UINT32 num, esz;

            if (EFI_ERROR(cmp90_bio_read(bio, 0, 512, 512, hdr)) ||
                CompareMem(hdr, "EFI PART", 8) != 0)
                continue;   /* не GPT (или protective-MBR) — direct уже пробован */
            CopyMem(&partEntLba, hdr + 72, 8);
            CopyMem(&num,  hdr + 80, 4);
            CopyMem(&esz,  hdr + 84, 4);
            if (num == 0 || num > 128 || esz < 128 || esz > 1024) continue;

            {
                STATIC UINT8 ents[128 * 1024];
                UINTN cnt, j;
                UINT64 rdBytes = (UINT64)num * esz;
                if (rdBytes > sizeof(ents)) rdBytes = sizeof(ents);
                st = cmp90_bio_read(bio, 0, partEntLba * 512, (UINTN)rdBytes, ents);
                if (EFI_ERROR(st)) { Print(L"[preload] GPT entries: %r\n", st); continue; }
                cnt = (UINTN)(rdBytes / esz);
                for (j = 0; j < cnt && !espLba; j++) {
                    UINT8 *e = ents + j * esz;
                    UINT64 first;
                    if (CompareMem(e, cmp90EspGuid, 16) != 0) continue;
                    CopyMem(&first, e + 32, 8);
                    if (first) espLba = first;
                }
            }
            if (!espLba) { Print(L"[preload] ESP не найден в GPT\n"); continue; }
            Print(L"[preload] ESP @LBA 0x%llx — читаю bootmgfw...\n",
                  (UINT64) espLba);

            {
                UINT8 *fb = NULL; UINTN fsz = 0;
                st = cmp90_fat_load_bootmgfw(bio, espLba, &fb, &fsz);
                if (EFI_ERROR(st)) { Print(L"[preload] bootmgfw: %r\n", st); continue; }
                g_bmBuf = fb; g_bmSize = fsz;
                g_bmDp = FileDevicePath(H[k], WINDOWS_BOOT_PATH);
                Print(L"[preload] ✓ bootmgfw.efi %d байт в ОЗУ (GPT ESP@0x%llx)\n",
                      fsz, (UINT64) espLba);
            }
        }
    }
    if (H) FreePool(H);
}

static EFI_STATUS chainload_windows(EFI_HANDLE ImageHandle);

/* финальный старт: из ОЗУ (SourceBuffer), DevicePath = реальный ESP */
static EFI_STATUS chainload_preloaded(EFI_HANDLE ImageHandle)
{
    EFI_HANDLE h = NULL;
    EFI_STATUS st;

    /* ===== v2.99m: лестница загрузки ОС БЕЗ единого ресета =====
     * Тёплый ресет = POST = VBIOS переинициализирует GPU и анлок гибнет
     * (подтверждено юзером на реальном HW 2026-08-23). Лестница:
     *   1) StartImage bootmgfw из ОЗУ (preload до анлока)
     *   2) любая ошибка -> SFS-цепочка с ESP
     *      (\EFI\Microsoft\Boot\bootmgfw.efi через SimpleFileSystem)
     *   3) и снова мимо -> BootNext->Windows + возврат из приложения:
     *      BDS продолжит boot-order и загрузит Windows БЕЗ POST,
     *      анлок сохраняется. */

    if (!g_bmBuf || !g_bmSize || !g_bmDp)
        Print(L"chainload-pre: preload пуст\n");
    else {
        Print(L"chainload-pre: LoadImage из ОЗУ (%d байт)...\n", g_bmSize);
        st = uefi_call_wrapper(BS->LoadImage, 6, FALSE, ImageHandle,
                               g_bmDp, g_bmBuf, g_bmSize, &h);
        if (EFI_ERROR(st)) {
            Print(L"chainload-pre: LoadImage: %r\n", st);
        } else {
            Print(L"chainload-pre: StartImage Windows Boot Manager...\n");
            st = uefi_call_wrapper(BS->StartImage, 3, h, NULL, NULL);
            Print(L"chainload-pre: StartImage вернул: %r\n", st);
            if (!EFI_ERROR(st))
                return EFI_SUCCESS;
        }
    }

    Print(L"chainload-pre: fallback на SFS-путь\n");
    st = chainload_windows(ImageHandle);
    if (!EFI_ERROR(st))
        return EFI_SUCCESS;

    /* последняя ступень: возврат в прошивку. НИКАКОГО ResetSystem и
     * НИКАКОГО BootNext (NVRAM-записи на этой плате вешают систему). */
    Print(L"chainload-pre: возврат в прошивку (без POST)\n");
    return EFI_NOT_FOUND;
}


#define WINDOWS_BOOT_PATH L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi"

static EFI_STATUS
chainload_windows(EFI_HANDLE ImageHandle)
{
    EFI_STATUS Status;
    EFI_LOADED_IMAGE *LoadedImage = NULL;
    EFI_DEVICE_PATH *Dp = NULL;
    EFI_HANDLE WinHandle = NULL;
    static EFI_GUID FsGuid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;

    /* 1) сначала — с устройства, откуда загружен наш .efi */
    Status = uefi_call_wrapper(BS->HandleProtocol, 3,
        ImageHandle, &LoadedImageProtocol, (VOID**)&LoadedImage);
    if (!EFI_ERROR(Status) && LoadedImage->DeviceHandle) {
        Dp = FileDevicePath(LoadedImage->DeviceHandle, WINDOWS_BOOT_PATH);
        if (Dp) {
            Status = uefi_call_wrapper(BS->LoadImage, 6,
                FALSE, ImageHandle, Dp, NULL, 0, &WinHandle);
            if (!EFI_ERROR(Status)) {
                Print(L"chainload: bootmgfw.efi с текущего устройства\n");
                goto start;
            }
        }
    }

    /* 2) поиск bootmgfw.efi на ВСЕХ файловых системах (Windows ESP = sda1) */
    {
        EFI_HANDLE *Handles = NULL;
        UINTN n = 0, i;

        Print(L"chainload: перечисляю SimpleFileSystem-хендлы...\n");
        Status = uefi_call_wrapper(BS->LocateHandleBuffer, 5,
            ByProtocol, &FsGuid, NULL, &n, &Handles);
        if (!EFI_ERROR(Status)) {
            Print(L"chainload: найдено FS-хендлов: %d\n", n);
            for (i = 0; i < n; i++) {
                EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FS = NULL;
                EFI_FILE_PROTOCOL *Root = NULL, *File = NULL;
                Print(L"chainload: FS#%d OpenVolume...\n", i);
                Status = uefi_call_wrapper(BS->HandleProtocol, 3,
                    Handles[i], &FsGuid, (VOID**)&FS);
                if (EFI_ERROR(Status)) { Print(L"  HandleProtocol: %r\n", Status); continue; }
                Status = FS->OpenVolume(FS, &Root);
                if (EFI_ERROR(Status)) { Print(L"  OpenVolume: %r\n", Status); continue; }
                Print(L"  том открыт, ищу bootmgfw...\n");
                Status = Root->Open(Root, &File,
                    (CHAR16*)WINDOWS_BOOT_PATH, EFI_FILE_MODE_READ, 0);
                if (!EFI_ERROR(Status)) {
                    UINT64 fsize = 0;
                    EFI_FILE_INFO *fi = NULL; UINTN fisz = 0;
                    { /* размер для лога (буфер под INFO) */
                        EFI_GUID fiGuid = EFI_FILE_INFO_ID;
                        CHAR8 buf[256];
                        fisz = sizeof(buf);
                        if (!EFI_ERROR(File->GetInfo(File, &fiGuid, &fisz, buf)))
                            fi = (EFI_FILE_INFO *)buf;
                    }
                    fsize = fi ? fi->FileSize : 0;
                    File->Close(File);
                    Print(L"  НАЙДЕН bootmgfw (%lu байт), LoadImage...\n", fsize);
                    Dp = FileDevicePath(Handles[i], (CHAR16*)WINDOWS_BOOT_PATH);
                    if (Dp) {
                        Status = uefi_call_wrapper(BS->LoadImage, 6,
                            FALSE, ImageHandle, Dp, NULL, 0, &WinHandle);
                        if (!EFI_ERROR(Status)) {
                            Print(L"chainload: bootmgfw.efi загружен с FS #%d\n", i);
                            goto start;
                        }
                        Print(L"  LoadImage: %r\n", Status);
                    }
                }
            }
            if (Handles) FreePool(Handles);
        } else {
            Print(L"chainload: LocateHandleBuffer: %r\n", Status);
        }
    }

    Print(L"chainload: bootmgfw.efi НЕ найден\n");
    return EFI_NOT_FOUND;

start:
    Print(L"chainload: старт Windows Boot Manager...\n");
    Status = uefi_call_wrapper(BS->StartImage, 3, WinHandle, NULL, NULL);
    Print(L"chainload: StartImage вернул: %r\n", Status);
    return Status;
}

/* Scan config space of ALL root bridges looking for the target card
 * (default CMP 70HX / GA104 / 10de:248a; see the TARGET PROFILE block).
 * Multi-card builds use find_all_cmp90hx() instead. */
static EFI_STATUS
find_cmp90hx(void)
{
    EFI_STATUS Status;
    EFI_HANDLE *RbHandles = NULL;
    UINTN RbCount = 0;
    UINTN i;

    Status = uefi_call_wrapper(BS->LocateHandleBuffer, 5,
        ByProtocol, &gEfiPciRootBridgeIoProtocolGuid, NULL, &RbCount, &RbHandles);
    if (EFI_ERROR(Status)) {
        Print(L"PCI: root bridges not found: %r\n", Status);
        return Status;
    }
    Print(L"PCI: %d root bridge(s)\n", (INTN)RbCount);

    for (i = 0; i < RbCount; i++) {
        Status = uefi_call_wrapper(BS->HandleProtocol, 3,
            RbHandles[i], &gEfiPciRootBridgeIoProtocolGuid, (VOID**)&gRb);
        if (EFI_ERROR(Status)) continue;

        /* Полный скан bus 0-255 (Configuration() в этой gnu-efi нет).
         * Быстрый отбор: dev0 fn0 на каждой шине. */
        UINTN Bus, Dev, Fn;
        for (Bus = 0; Bus <= 255; Bus++) {
            UINT32 Id = 0;
            UINT64 A0 = ((UINT64)Bus << 20);  /* dev0 fn0 reg0 */
            Status = uefi_call_wrapper(gRb->Pci.Read, 5, gRb,
                EfiPciIoWidthUint32, A0, 1, &Id);
            if (EFI_ERROR(Status) || Id == 0xFFFFFFFF) continue;

            for (Dev = 0; Dev < 32; Dev++) {
                UINTN MaxFn = 1;
                UINT32 Hdr = 0;
                UINT64 AD = ((UINT64)Bus << 20) | ((UINT64)Dev << 15);
                Status = uefi_call_wrapper(gRb->Pci.Read, 5, gRb,
                    EfiPciIoWidthUint32, AD, 1, &Id);
                if (EFI_ERROR(Status) || Id == 0xFFFFFFFF) continue;
                /* multifunction? */
                Status = uefi_call_wrapper(gRb->Pci.Read, 5, gRb,
                    EfiPciIoWidthUint32, AD | 0x0C, 1, &Hdr);
                if (!EFI_ERROR(Status) && (Hdr & 0x80)) MaxFn = 8;

                for (Fn = 0; Fn < MaxFn; Fn++) {
                    UINT64 AF = AD | ((UINT64)Fn << 12);
                    Status = uefi_call_wrapper(gRb->Pci.Read, 5, gRb,
                        EfiPciIoWidthUint32, AF, 1, &Id);
                    if (EFI_ERROR(Status) || Id == 0xFFFFFFFF) continue;
                    if (is_target_gpu(Id)) {
                        gBus = Bus; gDev = Dev; gFn = Fn;
                        Print(L"PCI: цель найдена: 10de:%04X = %s "
                              L"(bus=%d dev=%d fn=%d), FB=0x%llX, "
                              L"FRTS=0x%llX (0x%llX pg), "
                              L"WPR2=0x%08X/0x%08X\n",
                              (INTN)((Id >> 16) & 0xFFFF), TARGET_NAME,
                              (INTN)Bus, (INTN)Dev, (INTN)Fn,
                              TARGET_FB_SIZE, TARGET_FRTS_OFFSET,
                              TARGET_FRTS_OFFSET_PG,
                              TARGET_WPR2_LO, TARGET_WPR2_HI);
                        ulogf(L"FIND  target 10de:%04x bus=%d dev=%d fn=%d "
                             "fb=0x%llx frts=0x%llx wpr2=0x%08x/0x%08x\n",
                             (INTN)((Id >> 16) & 0xFFFF), (INTN)Bus, (INTN)Dev,
                             (INTN)Fn, TARGET_FB_SIZE, TARGET_FRTS_OFFSET,
                             TARGET_WPR2_LO, TARGET_WPR2_HI);
                        FreePool(RbHandles);
                        return EFI_SUCCESS;
                    } else if ((Id & 0xFFFF) == TARGET_PCI_VENDOR) {
                        Print(L"PCI: вижу 10de:%04X, но это не %s (bus=%d dev=%d fn=%d)\n",
                              (INTN)((Id >> 16) & 0xFFFF), TARGET_NAME,
                              (INTN)Bus, (INTN)Dev, (INTN)Fn);
                        /* в лог пишем ВСЕ карты NVIDIA — так проверяется,
                         * что приложение выбрало именно CMP, а не GeForce */
                        ulogf(L"FIND  other 10de:%04x bus=%d dev=%d fn=%d\n",
                             (INTN)((Id >> 16) & 0xFFFF), (INTN)Bus,
                             (INTN)Dev, (INTN)Fn);
                    }
                }
            }
        }
    }

    FreePool(RbHandles);
    Print(L"PCI: цель (%s, 10de:%04X) НЕ найдена (scanned %d bridges).\n",
          TARGET_NAME, (INTN)TARGET_PCI_DEV, (INTN)RbCount);
    Print(L"      Если карта точно в этой машине — посмотрите строки "
          L"'PCI: вижу 10de:xxxx' выше: скорее всего у вашей карты другой "
          L"Device ID. Тогда поправьте TARGET_PCI_DEV (и FB, если она не 8 ГБ) "
          L"в блоке TARGET PROFILE и пересоберите.\n");
    return EFI_NOT_FOUND;
}

/* ==== Application entry point — release flow map (v3.03) ====
 * banner -> locate card(s) -> gen2 fire-mode decision (NVRAM counter
 * CMP90G2; quick-check whether masks are already open) -> BAR0 + MEM_EN ->
 * preload bootmgfw into RAM (skipped on intermediate fire iterations) ->
 * preload probe / sweeps / diag -> shortcut if ALREADY unlocked -> shortcut
 * if direct MMIO probe sticks -> seed GPU time -> allocate payloads
 * (v67/booter/BL/fwsec above 4GB; <4GB copies of meta+v67 for 32-bit
 * readers) -> read ~84MB firmware via raw BlockIo -> build radix3 table +
 * WPR meta -> kill GFW -> verify SEC2 unlocked -> [mapper skipped] ->
 * EARLY PATH (BL->FWSEC->WPR2->booter#1) opens PLM; fallbacks if not:
 * v251 -> v246 -> fwsec retries x3 -> plain booter -> riscv-direct ->
 * then EITHER the gen2/fire multipass table (when armed) OR the plain
 * finish: SS0/SS1 -> kill SEC2 spinner -> final FLR -> return to firmware
 * (BDS boots Windows with NO POST; the unlock survives).
 * Every failure path also returns to firmware — release never resets. */
EFI_STATUS EFIAPI
efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    EFI_STATUS Status;
    UINT64 wprMetaPhys = 0, ucodePhys = 0, v67Phys = 0, radixPhys = 0, blPhys = 0;
    UINT64 fwsecPhys = 0, fwBase = 0;
    UINTN radixSize = 0, fwimageSizeUsed = 0;
    GspFwWprMeta *wprMeta = NULL;
    UINTN i;
    BOOLEAN directOk = FALSE;
    BOOLEAN earlyOk = FALSE;

    InitializeLib(ImageHandle, SystemTable);
    /* Banner: always print the exact card profile, so a mixed-up build is
     * obvious on screen before anything is touched. */
    Print(L"\n=== NVIDIA %s Unlock — PCI 10de:%04X, FB 0x%llX (%d МБ) ===\n",
          TARGET_NAME, (INTN)TARGET_PCI_DEV, TARGET_FB_SIZE,
          (INTN)(TARGET_FB_SIZE >> 20));
    log_init(ImageHandle);
    /* v3.16: часы включаются ЗДЕСЬ, а не позже.
     *
     * Раньше отсчёт начинался на log_t0() — уже после enable_mem_decode(),
     * то есть 382 строки шли без хронометража. Секундомер показывал
     * 2 мин 05 с при 108 с в счётчике, и разница была не «POST», а
     * именно этим участком. Подробности: PLAN-SPEED.md (часть II, ретроспектива v3.16),
     * раздел «17 секунд, которых нет в счётчике». */
    log_clock_start();   /* лог на флешку: сырые секторы, без ФС */
    /* v3.17: кольцо консоли + разовая проба цены вывода.
     *
     * Проба идёт ДО баннера и до любой работы с GPU: это единственное
     * место, где её можно сделать, не потратив время на уже начатое
     * состояние. Она печатает 20 служебных строк на настоящую консоль и
     * меряет их - это и есть измерение цены одного вызова.
     * Если выделение кольца не удалось, Print продолжает идти прямо в
     * консоль (см. fx_print), то есть поведение становится как было. */
    {
        VOID *ring = NULL;
        uefi_call_wrapper(BS->AllocatePool, 3, EfiBootServicesData,
                          FX_PR_RING_CHARS * sizeof(CHAR16), &ring);
        if (ring) {
            g_prRing = (CHAR16 *)ring;
            g_prCap  = FX_PR_RING_CHARS;
            fx_console_cost_probe();
            /* v3.47: всё, что напечатано до кольца (баннер профиля и весь
             * разбор device path из log_init), уходит в файл. Раньше эти
             * строки были ТОЛЬКО на экране: кольца ещё не было, а в лог они
             * не попадали. Теперь экран начинается чисто, а диагностика
             * выбора флешки не пропадает. */
            fx_pr_pre_flush();
        } else {
            g_prNoRing = TRUE;   /* fx_print вернётся к прямому выводу */
            Print(L"[io] console ring allocation FAILED - "
                  L"console output stays direct (no speedup)\n");
        }
    }
/* v3.47: БАННЕР ВЕРСИИ УБРАН.
 *
 * Здесь стояло '=== v3.04 FULL-NOGEN2 (render table, no pcie-gen2) ==='.
 * На момент v3.47 сборка - это v3.47, список масок рендера - две, а не
 * «render table», так что надпись была просто неверной. Хуже: она уходила
 * в кольцо, а кольцо не выгружается в файловый лог начиная с v3.17
 * (fx_pr_dump() не пишет заголовок PRN ни в одном прогоне), то есть ложь
 * оставалась только на экране и без единого следа.
 *
 * Версию сообщать незачем: имя карты и вердикт теперь печатаются напрямую на
 * консоль, а версия видна в баннере build.sh и в тегах git.
 *
 * Удалён весь блок версионных баннеров, а не только строка FULL-NOGEN2.
 * Оставшиеся варианты были столь же неверны - 'v3.04 compute-only',
 * 'v3.02 FULL', 'v3.04-nogen2 (render table)', 'v2.101' - и ни один не
 * соответствовал сборке, в которой все они печатались. Плюс все они уходят
 * в кольцо, а кольцо не выгружается в файловый лог начиная с v3.17, то есть
 * на экране не появлялось НИ ОДНОГО из них, а в логе их не было.
 *
 * Осталась строка профиля ниже - она верна и что-то сообщает. */
    Print(L"=== FRTS=0x%llX (0x%llX pages)  WPR2=0x%08X/0x%08X  FWSEC=%s ===\n",
          TARGET_FRTS_OFFSET, TARGET_FRTS_OFFSET_PG,
          TARGET_WPR2_LO, TARGET_WPR2_HI, FWSEC_BLOB_NAME);

#ifdef MULTI_CARD
    {
        BOOLEAN have = FALSE;
        find_all_cmp90hx();
        /* зонд КАЖДОЙ найденной функции ДО выбора карты: на машине с
         * одной физической картой перечисление иногда даёт две функции
         * (фантом от прежних манипуляций), и работать надо с настоящей */
        mc_probe_all();
        g_mcIndex = mc_var_get(L"CMP90IDX", &have);
        if (!have || g_mcIndex >= g_mcCount) {
            if (have) mc_vars_clear();   /* устаревший индекс (карт стало меньше) */
            g_mcIndex = 0;
        }
        g_mcAdvance = (g_mcCount > 0) && (g_mcIndex + 1 < g_mcCount);
    /* v3n: метка в лог. Без неё нельзя отличить «карт одна, BootNext
     * не писался» от «карт две, BootNext писался и устроил POST». */
    ulogf(L"MC     g_mcIndex=%d g_mcCount=%d g_mcAdvance=%d "
          L"SINGLE_CARD_ONLY=%d SKIP_FLR=%d\n",
          (INTN)g_mcIndex, (INTN)g_mcCount, (INTN)g_mcAdvance,
          (INTN)SINGLE_CARD_ONLY, (INTN)SKIP_FLR);
        Print(L"MULTI-CARD: найдено %d карт(ы), итерация %d, advance=%d\n",
              (INTN)g_mcCount, (INTN)g_mcIndex + 1, g_mcAdvance ? 1 : 0);
        if (g_mcAdvance)
            mc_var_set(L"CMP90CNT", (UINT32)g_mcCount);
        /* v3.04: холодный бут (POST перелокал ВСЕ карты) — если idx>0,
         * цикл продолжился бы «с середины»: карта 0 осталась бы залоченной
         * (в v3.03 fire-путь не сдвигал idx, и индекс застревал на 1).
         * Тёплая итерация: карта 0 ещё разлочен (PLM/SS переживают возврат
         * в прошивку без POST) — idx сохраняем. */
        if (g_mcIndex > 0) {
            EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *sRb = gRb;
            UINTN sBus = gBus, sDev = gDev, sFn = gFn;
            BOOLEAN c0open = FALSE;

            mc_pick(0);
            gBar0Base = cfg_read32(0x10) & ~0xF;
            enable_mem_decode();
            c0open = is_unlocked();
            gRb = sRb; gBus = sBus; gDev = sDev; gFn = sFn;

            if (!c0open) {
                Print(L"multi-card: карта 0 залочена (холодный бут) — "
                      L"цикл перезапускается с карты 0\n");
                g_mcIndex = 0;
                g_mcAdvance = (g_mcCount > 0);
                mc_var_set(L"CMP90IDX", 0);
            }
        }
        if (!mc_pick(g_mcIndex)) {
            Print(L"ERROR: %s не найдена\n", TARGET_NAME);
            Status = EFI_NOT_FOUND;
            goto done;
        }
        Status = EFI_SUCCESS;
    }
#else
    Status = find_cmp90hx();
    if (EFI_ERROR(Status)) {
        Print(L"ERROR: %s не найдена: %r\n", TARGET_NAME, Status);
        goto done;
    }
#endif

#ifdef PCIE_GEN2_REJOIN
    /* v2.99: активен, если в NVRAM есть счётчик gen2-циклов (пишется после
     * первого успешного анлока). Каждый прогон = одна запись из таблицы.
     * FLR на входе = разделение прогонов (как reload модуля у rejoin16);
     * после FLR восстанавливаем BAR0/command сами. */
    {
        BOOLEAN have2 = FALSE;
        UINTN gi = mc_var_get(L"CMP90G2", &have2);
        /* v3n: РАЗБЛОКИРОВКА СОСТОЯНИЯ (2026-09-28). Прогон stages показал:
         *
         *   STG  gen2: no branch taken (have2=1 success=0 direct=0 early=1)
         *   STG  reached 'chainload'
         *   STG  is_unlocked()=0 (SS0=0x05173106 SS1=0x00000007)
         *
         * То есть earlyOk=1 (анлок по раннему пути ПРОШЁЛ, WPR2 защёлкнут),
         * но блок записи селекторов НЕ выполнился, и SS0/SS1 остались
         * ровно такими, какими были до прогона.
         *
         * Причина — старый счётчик CMP90G2 в NVRAM (остался от прежней
         * работы с 90HX). Из-за него have2=TRUE и gi<=41, то есть
         * g_gen2Fire=TRUE. Дальше:
         *
         *   стр. ~7515: if (g_gen2Fire && have2 && g_gen2Enable)  -> FALSE
         *               (свип выключен рубильником)  -> тело вырезано
         *   стр. ~7910: else if (!have2 && ...)                  -> FALSE
         *               (have2=1)                  -> не берётся
         *   стр. ~7897: if ((успех) && !g_gen2Fire)             -> FALSE
         *               (!g_gen2Fire == 0)         -> СЕЛЕКТОРЫ ПРОПУЩЕНЫ
         *
         * Взаимная блокировка: счётчик означает «свип в процессе», свип
         * выключен, а из-за счётчика не выполняется обычный путь, который
         * и должен записать SS0/SS1. Ничего не происходит, кроме FWSEC.
         *
         * Исправление: не входить в fire-режим, пока свип выключен. Счётчик
         * существует только чтобы управлять свипом; если свип не может
         * идти, счётчик - бессмысленное состояние, и он не должен подавлять
         * обычный путь. Это также снимает необходимость вручную чистить
         * NVRAM. */
        if (!g_gen2Enable && have2)
            ulogf(L"G2NVR  CMP90G2=%d present, but sweep disabled -> fire mode "
                  L"NOT enabling, the normal selector path will run\n",
                  (INTN) gi);
        if (g_gen2Enable && have2 && gi <= RJ16_N && g_mcCount > 0) {
            UINT32 saveBar;
            g_gen2Fire = TRUE;
            Print(L"gen2: fire-режим (счётчик %d/%d)\n",
                  (INTN)gi, (INTN)RJ16_N);
            saveBar = cfg_read32(0x10) & ~0xF;
            do_flr();
            uefi_call_wrapper(BS->Stall, 1, 300000);
            cfg_write32(0x10, saveBar);
            enable_mem_decode();
            gBar0Base = saveBar;
            Print(L"gen2: BAR0 восстановлен = 0x%08x\n", gBar0Base);
            /* v2.99h: быстрый путь — маски переживают перезапуск стенда
             * (гибнут только при повторном POST/VBIOS). Если все
             * обязательные маски уже FF — таблицу не гоняем. Обязательные =
             * все, кроме OPTB-блока и трёх «упрямых» регистров, чей
             * readback не показывает FF даже при проставленной записи. */
            {
                INTN k;
                BOOLEAN allOpen = TRUE;
                for (k = 0; k < RJ16_N && allOpen; k++) {
                    UINT32 a = g_rj16[k].addr;
                    /* v2.100a: 0x88084 исключён — его speed-ниббл следует за
                     * ФАКТИЧЕСКИМ линком (в госте Gen1 -> читается ...D01),
                     * строгое сравнение там невозможно в принципе */
                    if ((a >= 0x008200d0U && a <= 0x008200f4U) ||
                        a == 0x00088084U)
                        continue;                       /* OPTB / LINK_CAP */
                    /* v2.100: критерий — ТОЛЬКО точный 0xFFFFFFFF. Скипы
                     * «readback-упрямцев» и приём FFFFFF8F/7F за открытое
                     * УБРАНЫ: на хосте эти семейства дали точный FF вторым
                     * проходом (rejoin16-apply round 2); без точного FF
                     * запись GFX_SPEED_SELECT и XP3G-фичи молча не работают. */
                    if (mmio_read32(a) != g_rj16[k].val) {
                        Print(L"gen2: quick-check: 0x%08x не точный FF (%08x) — "
                              L"полная таблица\n", a, mmio_read32(a));
                        allOpen = FALSE;
                    }
                }
                if (allOpen) {
                    g_gen2Quick = TRUE;
                    Print(L"gen2: все обязательные маски уже открыты — "
                          L"сразу Gen2-конфиг\n");
                }
            }
        } else if (have2 && gi > RJ16_N) {
            /* счётчик больше таблицы = аномалия; чистим и работаем как без него */
            mc_var_set(L"CMP90G2", 0);
        }
    }
#endif

    gBar0Base = cfg_read32(0x10) & ~0xF;
    Print(L"BAR0 = 0x%08x\n", gBar0Base);
    enable_mem_decode();
    dump_regs(L"[POST]");
    /* v2.57-4: зонд предзагрузки — ПЕРВЫМ (до любых сбросов/DMA!) */
    /* v2.89: ПРЕДЗАГРУЗКА bootmgfw в ОЗУ ДО разблокировки (SFS не трогаем) */
#ifdef MULTI_CARD
    /* v2.99n: в gen2-режиме preload НЕ нужен вовсе — ОС грузится через
     * BootNext без POST, а не chainload'ом из ОЗУ */
    {
        BOOLEAN skipPreload = g_mcAdvance;
#ifdef PCIE_GEN2_REJOIN
        skipPreload |= g_gen2Fire;
#endif
        if (!skipPreload) {
            preload_bootmgfw();
        } else if (g_mcAdvance) {
            Print(L"multi-card: preload пропущен (не последняя карта)\n");
        } else {
            Print(L"gen2: preload пропущен (OS via BootNext)\n");
        }
    }
#else
    preload_bootmgfw();
#endif

    log_ms(L"after preload_bootmgfw");
    probe_preload();
    log_ms(L"after probe_preload");
#ifdef PCIE_GEN2_REJOIN
    if (!g_gen2Fire)   /* v2.99b: fire-итерациям не нужен гигантский свип */
#endif
        {
        UINT64 ph0 = fx_now_us();
        /* v3.17: свип регистровых блоков убран из релизной сборки.
         *
         * ИЗМЕРЕНО: этот один вызов стоил 11,86 с из 3 мин 40 с
         * (t=1659ms -> t=13516ms в usb-log-2026-10-02-V316-WAKE-218s.txt).
         * Он состоит ИЗ ОДНИХ ЧТЕНИЙ: sweep_regs() делает mmio_read32 на
         * 580 регистрах и печатает ненулевые в консоль. В GPU не пишется
         * ни одного байта, состояние карты не меняется НИКАК.
         *
         * Почему так дорого при 580 чтениях MMIO: печать. Измеренная цена
         * вывода в консоль - см. fx_console_cost_report() в финале лога.
         *
         * Флаг по умолчанию 0 - требование BUILDING 6.0: любая проверка
         * должна быть за флагом, который по умолчанию равен 0. Ветка #else
         * содержит одну строку лога: пропуск не молчит, а считается.
         * Возврат: -DFX_DIAG_SWEEPS=1 в build.sh. */
#if FX_DIAG_SWEEPS
        sweep_all(L"POST");
        ulogf(L"TIME   sweep_all(POST) took %lldus\n", (INT64)(fx_now_us()-ph0));
#else
        (VOID)ph0;
        ulogf(L"SWEEP  sweep_all(POST) SKIPPED: FX_DIAG_SWEEPS=0 "
              L"(read-only diagnostic, measured 11.86s)\n");
#endif
    }
    log_ms(L"after sweep_all(POST)");

    /* v2.10: ДИАГНОСТИКА (SEC2 + GSP, только чтения, с паузами) + АНЛОК */
    diag_regs(SystemTable);

    /* v2.36: [POST] IMEM-содержимое ДО любых сбросов — проверка предзагрузки
     * кода VBIOS (гипотеза: GSP FWSEC выполнился из secure IMEM, оставленного
     * VBIOS при POST; SEC=1 DMA не работает нигде). */
    mmio_write32(SEC2_IMEMC0, 0);
    Print(L"diag: [POST] SEC2 IMEM[0]=0x%08x (ns)\n", mmio_read32(SEC2_IMEMD0));
    mmio_write32(SEC2_IMEMC0, (1 << 28));
    Print(L"diag: [POST] SEC2 IMEM_S[0]=0x%08x (secure)\n", mmio_read32(SEC2_IMEMD0));
    mmio_write32(SEC2_IMEMC0, 0x100 | (1 << 28));
    Print(L"diag: [POST] SEC2 IMEM_S[0x100]=0x%08x\n", mmio_read32(SEC2_IMEMD0));
    mmio_write32(GSP_BASE + 0x180, 0);
    Print(L"diag: [POST] GSP IMEM[0]=0x%08x (ns)\n", mmio_read32(GSP_BASE + 0x184));
    mmio_write32(GSP_BASE + 0x180, (1 << 28));
    Print(L"diag: [POST] GSP IMEM_S[0]=0x%08x (secure)\n", mmio_read32(GSP_BASE + 0x184));
    mmio_write32(GSP_BASE + 0x180, 0x100 | (1 << 28));
    Print(L"diag: [POST] GSP IMEM_S[0x100]=0x%08x\n", mmio_read32(GSP_BASE + 0x184));
    mmio_write32(SEC2_DMEMC0, 0x10);
    Print(L"diag: [POST] SEC2 DMEM[0x10]=0x%08x\n", mmio_read32(SEC2_DMEMD0));

#ifdef PCIE_GEN2_REJOIN
    if (is_unlocked() && !g_gen2Fire) {
#else
    if (is_unlocked()) {
#endif
        /* v2.28: карта уже открыта (анлок пережил vfio/rmmod) — но FWSEC/WPR2
         * не зависит от PLM: прогоняем диагностику (WPR2 установится), затем выход */
        Print(L"GPU уже разблокирован — v2.89: chainload из ОЗУ...\n");
#ifdef PCIE_GEN_EXPERIMENT
        /* v2.97: PLM открыт, но ботер-контекста нет (короткий путь) —
         * booter-запись пропустится, останутся прямые пробы */
        pcie_gen_unlock_debug(0, 0, 0);
#endif
#ifdef PCIE_GEN2_REJOIN
        {
            BOOLEAN hv2 = FALSE;
            mc_var_get(L"CMP90G2", &hv2);
            if (!hv2) {
                mc_var_set(L"CMP90G2", 0);
                Print(L"gen2: счётчик засеян (0) из короткого пути\n");
            }
        }
#endif
#ifdef MULTI_CARD
        if (g_mcAdvance) {
            Print(L"multi-card: карта %d уже разлочена -> следующая\n",
                  (INTN)g_mcIndex + 1);
            /* v3n: тот же запрет, что и в основном финале — см. SINGLE_CARD_ONLY.
             * Этот путь («карта уже разлочена») тоже писал BootNext на флешку,
             * то есть устраивал POST и стирал то, ради чего карта и
             * разблокировалась. */
            ulogf(L"MC     already-unlocked path: BootNext=self SKIPPED "
                  L"(SINGLE_CARD_ONLY=%d)\n", (INTN)SINGLE_CARD_ONLY);
#if !SINGLE_CARD_ONLY
            mc_var_set(L"CMP90IDX", (UINT32)(g_mcIndex + 1));
            mc_set_bootnext_self(ImageHandle);
#endif
            goto done;
        }
        mc_vars_clear();   /* последняя карта — грузим Windows */
#endif
        /* v2.99n: на этой плате SFS/StartImage ненадёжны (No mapping,
         * OpenVolume-висняк). Выход: возврат в прошивку — BDS грузит
         * Windows по BootOrder БЕЗ POST, анлок живёт */
        Print(L"v3.0: возврат в прошивку — Windows по BootOrder без POST\n");
        goto done;
        /* v2.62: буфер ВЫШЕ 4ГБ (как у драйвера 0x110BB0000) — единственное
     * оставшееся различие с эталонным трейсом HS-загрузки */
    Status = alloc_fwsec_buffer((FWSEC_SIZE + 0xFFF) >> 12, &fwsecPhys);
        if (EFI_ERROR(Status)) { Print(L"alloc fwsec: %r\n", Status); goto chainload; }
        Print(L"alloc fwsec @0x%lx (0x%lx bytes)\n", fwsecPhys, FWSEC_SIZE);
        CopyMem((VOID*)(UINTN)fwsecPhys, fwsec_ga104_bin, FWSEC_SIZE);
        gsp_engine_reset();
        fwsec_boot_gsp_sig(fwsecPhys, fwsec_ga104_prod_sig2, 2);

        /* v2.41 diag: SEC2 DMA с ПРАВИЛЬНЫМИ размерами (0x4F00/0x5000/0x4D00
         * из трейса драйвера) — проверка: ломал ли размер 0x8900 SEC=1? */
        {
            UINT64 ucodePhys2 = 0;
            UINT32 vv;
            Print(L"diag: SEC2 DMA 0x4F00 (правильный размер)...\n");
            Status = alloc_below_4g((0xEC00 + 0xFFF) >> 12, &ucodePhys2);
            if (EFI_ERROR(Status)) {
                Print(L"diag: alloc ucode: %r\n", Status);
            } else {
                CopyMem((VOID*)(UINTN)ucodePhys2, booter_ucode_dbg, 0xEC00);
                /* SEC2 reset */
                mmio_write32(SEC2_ENGINE, 0x1);
                for (i = 0; i < 16; i++) mmio_read32(SEC2_ENGINE);
                mmio_write32(SEC2_ENGINE, 0x0);
                for (i = 0; i < 16; i++) mmio_read32(SEC2_ENGINE);
                uefi_call_wrapper(BS->Stall, 1, 50000);
                mmio_write32(SEC2_BCR_CTRL, 0x0);
                for (i = 0; i < 16; i++) mmio_read32(SEC2_BCR_CTRL);
                mmio_write32(SEC2_RM, 0xb72000a1);
                Print(L"diag: CPUCTL после reset = 0x%x\n", mmio_read32(SEC2_CPUCTL));
                falcon_dma_transfer(0, 0, ucodePhys2, 0x4F00,
                                    0 | (6 << 8) | (0 << 12) | (1 << 4) | (1 << 2));
                mmio_write32(SEC2_IMEMC0, 0);
                vv = mmio_read32(SEC2_IMEMD0);
                mmio_write32(SEC2_IMEMC0, (1 << 28));
                Print(L"diag: IMEM[0]=0x%08x (ns) IMEM_S[0]=0x%08x (secure; "
                      L"ожидаю 0x%08x — код)\n", vv, mmio_read32(SEC2_IMEMD0),
                      *(UINT32*)(UINTN)ucodePhys2);
                mmio_write32(SEC2_BROM_PARAADDR0, 0x10);
                mmio_write32(SEC2_BROM_ENGIDMASK, 1);
                mmio_write32(SEC2_BROM_CURR_UCODE_ID, 3);
                mmio_write32(SEC2_BOOTVEC, 0x100);
                mmio_write32(SEC2_CPUCTL, 0x2);
                uefi_call_wrapper(BS->Stall, 1, 500000);
                Print(L"diag: после STARTCPU: dbg=0x%x cpuctl=0x%x\n",
                      mmio_read32(SEC2_DEBUGINFO), mmio_read32(SEC2_CPUCTL));
            }
        }
        goto chainload;
    }

    /* v2.26: ПРЯМАЯ запись FEAT_OVR (host probe) — если прилипает, booter не нужен.
     * v2.99b: в gen2 fire-режиме НЕ используем: PLM остаётся открыт с прошлого
     * прогона (переживает FLR), probe «успешен» и уводит путь мимо ботера,
     * а XVE/XP3G/OPTB без ботера всё равно не пишутся. */
    if (
#ifdef PCIE_GEN2_REJOIN
        !g_gen2Fire &&
#endif
        direct_write_probe()) {
        Print(L"probe: GPU разблокирован ПРЯМЫМИ записями — пропуск booter-пути\n");
        directOk = TRUE;
    }

    if (!directOk) {
    /* GFW_BOOT_OK: регистр 0x118234, прогресс в младшем байте (0xFF = COMPLETED);
     * старшие биты — доп. флаги (наблюдалось 0x3FF = 0x300|0xFF — GPU готов). */
    if ((mmio_read32(REG_GFW_BOOT_OK) & 0xFF) != 0xFF) {
        Print(L"GFW не готов (0x%08x), жду...\n", mmio_read32(REG_GFW_BOOT_OK));
        /* v3.16: хронометраж и запись В ЛОГ.
         *
         * Раньше обе ветки печатались через Print, то есть только на
         * экран, и в кольцевой лог на флешке их не попадало. Из-за этого
         * по логу было невозможно сказать, отработал ли цикл полностью.
         *
         * По построению цикл стоит до 200 x 50 мс = 10 СЕКУНД. Это
         * главный подозреваемый на те 17 с, которых не было в счётчике.
         * Теперь фактическое время печатается и в лог, и на экран. */
        {
            UINT64 gt0 = fx_now_us();
            for (i = 0; i < 200; i++) {
                uefi_call_wrapper(BS->Stall, 1, 50000);
                if ((mmio_read32(REG_GFW_BOOT_OK) & 0xFF) == 0xFF) break;
            }
            ulogf(L"GFWT   GFW wait: %lldus over %d iterations of 50ms, "
                  L"reg=0x%08x %s\n",
                  (INT64)(fx_now_us() - gt0), (INTN)(i + 1),
                  mmio_read32(REG_GFW_BOOT_OK),
                  ((mmio_read32(REG_GFW_BOOT_OK) & 0xFF) == 0xFF)
                      ? L"OK" : L"TIMEOUT - continuing blind");
        }
        if ((mmio_read32(REG_GFW_BOOT_OK) & 0xFF) != 0xFF)
            Print(L"GFW таймаут — продолжаю вслепую\n");
        else
            Print(L"GFW OK после ожидания (0x%08x)\n", mmio_read32(REG_GFW_BOOT_OK));
    } else {
        ulogf(L"GFWT   GFW already ready, no wait (0x%08x)\n",
              mmio_read32(REG_GFW_BOOT_OK));
        Print(L"GFW OK (0x%08x)\n", mmio_read32(REG_GFW_BOOT_OK));
    }

    set_gpu_time();
    log_ms(L"after set_gpu_time (incl. GFW wait)");

    /* v3n: дополнительный нуль по NV_PTIMER. Основной отсчёт уже идёт
     * с начала efi_main по TSC, поэтому этот вызов его НЕ сбрасывает. */
    log_t0();

    /* --- Выделение памяти (ниже 4ГБ — для DMA) --- */
    Status = alloc_fwsec_buffer((V67_SIZE + 0xFFF) >> 12, &v67Phys);
    if (EFI_ERROR(Status)) { Print(L"alloc v67: %r\n", Status); goto done; }
    Print(L"alloc v67  @0x%lx\n", v67Phys);
    { UINT64 tq = fx_now_us(); log_mem_selftest(L"v67", v67_payload_bin, v67Phys, V67_SIZE); fx_mk_acc(tq, L"pro: alloc+selftest v67"); }
#ifdef PCIE_GEN2_REJOIN
    /* v2.99c: ЗДЕСЬ НЕ ПАТЧИМ! Тёплый ресет закрывает PLM (доказано
     * итерацией 3: XVE-запись при закрытом PLM = mbox 0x15, регистр
     * 0x4ABCF вместо FF). Итерация стала двухфазной: ботер#1 идёт с
     * ОРИГИНАЛЬНЫМ payload (открывает PLM как в обычном анлоке),
     * ботер#2 с патченной парой пишется уже при открытом PLM
     * (см. gen2-блок после раннего пути; booter_load_v67 сам ресетит SEC2,
     * механика второго прогона проверена в v2.97). */
    if (g_gen2Fire)
        Print(L"gen2: ботер#1 с оригинальным payload (фаза открытия PLM)\n");
#endif

    Status = alloc_fwsec_buffer((BOOTER_UCODE_SIZE + 0xFFF) >> 12, &ucodePhys);
    if (EFI_ERROR(Status)) { Print(L"alloc ucode: %r\n", Status); goto done; }
    Print(L"alloc ucode @0x%lx\n", ucodePhys);
    { UINT64 tq = fx_now_us(); log_mem_selftest(L"ucode", booter_ucode_prod, ucodePhys, BOOTER_UCODE_SIZE); fx_mk_acc(tq, L"pro: alloc+selftest ucode"); }

    /* --- BL (GspRmBoot): сигнатура V67 верифицируется при загрузке BL --- */
    Status = alloc_fwsec_buffer((GSP_RM_BOOT_SIZE + 0xFFF) >> 12, &blPhys);
    if (EFI_ERROR(Status)) { Print(L"alloc bl: %r\n", Status); goto done; }
    Print(L"alloc bl    @0x%lx\n", blPhys);
    { UINT64 tq = fx_now_us(); log_mem_selftest(L"gsp_rm_boot", gsp_rm_boot_dbg, blPhys, GSP_RM_BOOT_SIZE); fx_mk_acc(tq, L"pro: alloc+selftest gsp_rm_boot"); }

    /* --- v2.28: FWSEC ucode (из VBIOS) — для FRTS/WPR2 на GSP ---
     *
     * БУФЕР НИЖЕ 4ГБ (а не >4ГБ, как в v2.62). Причина установлена по
     * логу: адрес используется и как VA (CopyMem), и как PA (DMA GSP).
     * Выше 4ГБ прошивка не отображает память тождественно, поэтому образ
     * физически не попадал в буфер, и FWSEC стартовал с мусором:
     *     blobIMEM0=0xEC547D23  bufIMEM0=0x00000001  phys=0x113025000
     * Ниже 4ГБ VA==PA, и это ровно то, что работало на 90HX до v2.62.
     * FWSEC читает только DMA GSP (не ботер с GPU), ограничения «не
     * читать sysmem ниже 4ГБ» на него не распространяется. */
    Status = alloc_below_4g((FWSEC_SIZE + 0xFFF) >> 12, &fwsecPhys);
    if (EFI_ERROR(Status)) {
        Print(L"alloc fwsec ниже 4ГБ: %r, фолбэк выше 4ГБ\n", Status);
        Status = alloc_fwsec_buffer((FWSEC_SIZE + 0xFFF) >> 12, &fwsecPhys);
        if (EFI_ERROR(Status)) { Print(L"alloc fwsec: %r\n", Status); goto done; }
    }
    Print(L"alloc fwsec @0x%lx (0x%lx bytes) %s\n", fwsecPhys, FWSEC_SIZE,
          fwsecPhys < 0x100000000ULL ? L"ниже 4ГБ, VA==PA" : L"ВЫШЕ 4ГБ (VA!=PA!)");
    CopyMem((VOID*)(UINTN)fwsecPhys, fwsec_ga104_bin, FWSEC_SIZE);
    { UINT64 tq = fx_now_us(); log_mem_selftest(L"fwsec", fwsec_ga104_bin, fwsecPhys, FWSEC_SIZE); fx_mk_acc(tq, L"pro: alloc+copy+selftest fwsec"); }
    g_fwsecPhys = fwsecPhys;

    /* v3.42: LBA файла gsp_ga10x.bin в разделе FAT. 0 = читать нечего, чтение
 * выключено. См. большой комментарий у вызова ReadBlocks ниже: LBA 0 — это
 * загрузочный сектор, а не файл. */
#define GSP_FW_LBA 0

/* --- ЭКСПЕРИМЕНТ v2.4: БЕЗ чтения gsp_ga10x.bin ---
     * USB-чтение 84МБ через EFI-файловый протокол ЖЁСТКО фризит прошивку
     * (AMI 2012). Гипотеза: V67-переполнение происходит при обработке
     * СИГНАТУРЫ (64КБ пейлоад), а не образа → реальный .fwimage не нужен.
     * Фиктивный образ: 1МБ нулей в radix3. Если PLM откроется — образ не нужен. */
    /* --- v2.68: ЧИТАЕМ РЕАЛЬНЫЙ gsp_ga10x.bin с блочного устройства --- */
    {
        EFI_GUID bioGuid = EFI_BLOCK_IO_PROTOCOL_GUID;
        UINTN HandleCount = 0, h;
        EFI_HANDLE *Handles = NULL;
        /* v2.78b: читаем С ЛИШНИМ хвостом — секции .fwsignature_* лежат в
         * файле ПОСЛЕ .fwimage (0x5053040..); плюс таблица секций ELF в самом
         * конце (~0x505f3d8). Окно 0x5060000 покрывает файл 610.43.03
         * (0x505f898) целиком; оффсеты внутри вытаскиваются из ELF. */
        UINT64 fwSize = GSP_FW_READ_WINDOW;
        UINT64 elfOff = 0, elfLen = 0;
        BOOLEAN fwLoaded = FALSE;

        /* v3.41, этап 24: ГРАНИЦЫ ДЫРЫ В 3,1 С. В логе между
         * 'pro: alloc+copy+selftest fwsec' (t=367) и 'pro: radtab SetMem'
         * (t=3488) не было НИ ОДНОЙ строки - 3 121 мс без attribution. Здесь
         * единственный тяжёлый блок кода, и он печатает только через Print(),
         * а Print в лог на флешке не попадает вообще (проверено: баннер,
         * alloc_high:, alloc fwsec, fw-read: отсутствуют при 142 строках
         * TIME). 84,4 МБ / 3,121 с = 27 МБ/с - практический потолок USB 2.0.
         * Три марки разрезают дыру на аллокацию / поиск устройства / чтение. */
        log_ms(L"fw-read: before alloc");
        ulogf(L"FWRD  window=0x%llx bytes\n", fwSize);
        Status = alloc_fwsec_buffer((fwSize + 0xFFF) >> 12, &radixPhys);
        if (EFI_ERROR(Status)) { Print(L"alloc fw: %r\n", Status); goto done; }
        fwBase = radixPhys;
        log_ms(L"fw-read: alloc done");

        Status = uefi_call_wrapper(BS->LocateHandleBuffer, 5,
                                   ByProtocol, &bioGuid, NULL, &HandleCount, &Handles);
        log_ms(L"fw-read: handles located");
        ulogf(L"FWRD  BlockIo handles=%d\n", (INTN)HandleCount);
        if (!EFI_ERROR(Status) && Handles) {
            for (h = 0; h < HandleCount && !fwLoaded; h++) {
                EFI_BLOCK_IO *bio = NULL;
                Status = uefi_call_wrapper(BS->HandleProtocol, 3,
                                           Handles[h], &bioGuid, (VOID**)&bio);
                if (EFI_ERROR(Status) || !bio || !bio->Media || !bio->Media->MediaPresent)
                    continue;
                UINT64 devSz = (UINT64)(bio->Media->LastBlock + 1) * bio->Media->BlockSize;
                Print(L"fw-read: BlkIo[%d] blk=%d last=%lx dev=0x%lx\n",
                      h, bio->Media->BlockSize, bio->Media->LastBlock, devSz);
                if (devSz < fwSize) continue;
                /* v3.42: ЧТЕНИЕ ОТКЛЮЧЕНО — ОНО НИКОГДА НЕ ЧИТАЛО ФАЙЛ.
                 *
                 * Замер v3.41 (out/usb-log-1004-120314.txt, 8 471 мс):
                 *     t=370ms   fw-read: handles located   (7 устройств BlockIo)
                 *     t=3498ms  fw-read: done              <- 3 128 мс
                 *     FWRD  loaded=0 off=0x0 sz=0x5053000
                 *
                 * loaded=0 — ELF не распознан. И sz=0x5053000 — это ровно
                 * константа DummySize из ветки ниже, то есть отработал
                 * fallback на нули.
                 *
                 * ПОЧЕМУ НЕ ЧИТАЛОСЬ. Вызов ниже читает с LBA 0 УСТРОЙСТВА:
                 * это загрузочный сектор FAT/MBR. Файл gsp_ga10x.bin лежит
                 * ВНУТРИ файловой системы, а не в начале устройства, поэтому
                 * вызов физически не может вернуть файл — он возвращает
                 * мусор, который проверка ELF-магии честно отвергает. Комментарий
                 * выше про «FAT boot sector тоже ненулевой» описывал защиту от
                 * МБР, но не тот факт, что читать там нечего.
                 *
                 * ПОЧЕМУ УБРАТЬ БЕЗОПАСНО. При fwLoaded==FALSE буфер в любом
                 * случае заканчивается SetMem(...,0) — ровно те же нули.
                 * Итоговое состояние памяти побайтово то же, минус ~3,1 с и
                 * минус 84 МБ чтения с USB на каждой загрузке. Это не гипотеза
                 * «нужен ли образ»: данные УЖЕ выбрасывались, каждый прогон.
                 *
                 * ЕСЛИ НАСТОЯЩИЙ ОБРАЗ ДЕЙСТВИТЕЛЬНО НУЖЕН: сначала найти
                 * LBA файла в FAT (SFS LocateHandleBuffer либо свой разбор
                 * каталога) и читать оттуда. До этого GSP_FW_LBA обязан
                 * быть 0, иначе вернётся MBR. */
#if GSP_FW_LBA
                Status = uefi_call_wrapper(bio->ReadBlocks, 5,
                                           bio, bio->Media->MediaId,
                                           GSP_FW_LBA, fwSize, (VOID*)(UINTN)radixPhys);
                if (!EFI_ERROR(Status)) {
                    UINT32 *p = (UINT32*)(UINTN)radixPhys;
                    UINT32 nz = 0;
                    for (UINTN z = 0; z < 64; z++) { if (p[z] != 0) nz++; }
                    /* Not just "non-zero": it has to be the ELF we expect.
                     * A FAT boot sector or an MBR is also non-zero, and
                     * accepting one would make the meta point the booter at
                     * garbage. Check the ELF magic and that .fwimage is
                     * actually inside the window we just read. */
                    if (nz > 8 &&
                        gsp_elf_section((const UINT8 *)(UINTN)radixPhys, fwSize,
                                        ".fwimage", &elfOff, &elfLen) && elfLen) {
                        fwLoaded = TRUE;
                        Print(L"fw-read: OK! %08x %08x %08x %08x "
                              L"(.fwimage off=0x%llx size=0x%llx)\n",
                              p[0], p[1], p[2], p[3], elfOff, elfLen);
                    } else {
                        Print(L"fw-read: не gsp ELF (.fwimage нет) — пропуск\n");
                    }
                }
#else
                (VOID)devSz;
                ulogf(L"FWRD  READ SKIPPED (GSP_FW_LBA=0): чтение шло с LBA 0 "
                      L"устройства, то есть из FAT/MBR, а не из gsp_ga10x.bin. "
                      L"Проверка ELF отвергала этот мусор и fallback всё равно "
                      L"заполнял буфер нулями. Снято ~3.1 с и 84 МБ USB-чтения "
                      L"за прогон.\n");
#endif
            }
            uefi_call_wrapper(BS->FreePool, 1, Handles);
        }

        if (fwLoaded) {
            /* meta указывает на данные .fwimage, sizeOfRadix3Elf = РОВНО её
             * размер (v2.78b: было 0x5052FC0 вместо 0x5053000 — расхождение
             * ломало раскладку). Офсет/размер уже проверены как ELF-валидные
             * в fw-read: OK, дублировать не нужно. */
            radixPhys += elfOff;
            fwimageSizeUsed = elfLen;
            Print(L"fw-read: РЕАЛЬНЫЙ firmware загружен! radix@0x%lx "
                  L"off=0x%llx sz=0x%llx\n",
                  radixPhys, elfOff, fwimageSizeUsed);
        } else {
            /* Штатный путь: .fwimage не нужен — V67-переполнение срабатывает
             * на обработке подписи, поэтому dummy-заглушка достаточна (v2.4).
             * Размер = .fwimage из пакета 610.43.03, он же booterCodeOffset
             * не трогает — нужен лишь как правдоподобный объём. */
            Print(L"fw-read: реальный GSP ELF не найден — dummy fallback "
                  L"(zeros, 0x5053000)\n");
            {
                UINTN DummySize = 0x5053000;
                Status = alloc_fwsec_buffer((DummySize + 0xFFF) >> 12, &radixPhys);
                if (EFI_ERROR(Status)) { Print(L"alloc dummy: %r\n", Status); goto done; }
                SetMem((VOID *)(UINTN)radixPhys, DummySize, 0x00);
                fwBase = radixPhys;
                fwimageSizeUsed = DummySize;
            }
        }
        log_ms(L"fw-read: done");
        ulogf(L"FWRD  loaded=%d off=0x%llx sz=0x%llx\n",
              (INTN)fwLoaded, elfOff, fwimageSizeUsed);
    }

    /* --- WPR meta --- */
    /* v2.86: СТРОИМ НАСТОЯЩУЮ radix-3 таблицу (реплика kgspCreateRadix3_IMPL).
     * Живой драйвер кладёт в sysmemAddrOfRadix3Elf НЕ сырой образ, а
     * page-table: корень(+0) -> L1(+0x1000) -> L2(+0x2000, 41 шт) ->
     * данные(+0x2B000). PTE = чистый физадрес 4K-страницы.
     * Наш сырой ELF ботер парсил как таблицу -> мусорные PTE -> exit 0x2! */
    {
        UINT64 radTabPhys = 0;
        UINT64 nData = (fwimageSizeUsed + 0xFFF) >> 12;      /* 0x5053 */
        UINT64 nL2   = ((nData - 1) >> 9) + 1;               /* 41     */
        UINT64 ptSize  = (2 + nL2) << 12;                    /* корень+L1+L2 */
        UINT64 dataOff = ptSize;
        UINT64 allocSz = dataOff + fwimageSizeUsed;
        Status = alloc_fwsec_buffer((allocSz + 0xFFF) >> 12, &radTabPhys);
        if (!EFI_ERROR(Status)) {
            UINT8 *rb = (UINT8 *)(UINTN)radTabPhys;
            UINT64 i;
            /* v3.21 (этап 7): три независимых замера вместо одного участка на 3,2 с.
             * Подозрение - CopyMem на 81 МБ из апертуры radixPhys: если
             * источник в MMIO, копирование идёт по PCIe побайтно. Проверяется
             * замером, а не догадкой: если CopyMem окажется 3 с, вердикт
             * изменится, и если окажется 10 мс - значит время в другом. */
            { UINT64 tq = fx_now_us(); SetMem(rb, ptSize, 0); fx_mk_acc(tq, L"pro: radtab SetMem"); }
            { UINT64 tq = fx_now_us(); CopyMem(rb + dataOff, (VOID *)(UINTN)radixPhys, fwimageSizeUsed); fx_mk_acc(tq, L"pro: radtab CopyMem 81MB"); }
            /* та же проверка VA/PA: таблица страниц адресуется DMA-устройством */
            { UINT64 tq = fx_now_us();
              log_buf_check(L"radtab", (const UINT8 *)(UINTN)radixPhys,
                          radTabPhys + dataOff, fwimageSizeUsed);
              fx_mk_acc(tq, L"pro: radtab buf_check"); }
            for (i = 0; i < nData; i++)
                *(UINT64 *)(rb + 0x2000 + i * 8) =
                    radTabPhys + dataOff + (i << 12);
            for (i = 0; i < nL2; i++)
                *(UINT64 *)(rb + 0x1000 + i * 8) =
                    radTabPhys + 0x2000 + (i << 12);
            *(UINT64 *)rb = radTabPhys + 0x1000;
            __asm__ volatile("wbinvd" ::: "memory");
            Print(L"v2.86: radix-таблица @0x%lx: L2=%llu стр, данные@+%lx (%lx байт)\n",
                  radTabPhys, nL2, (UINT64)dataOff, fwimageSizeUsed);
            radixPhys = radTabPhys;   /* meta теперь указывает на ТАБЛИЦУ */
        } else {
            Print(L"v2.86: alloc radix-table: %r — остаёмся на сыром образе\n", Status);
        }
    }
    Status = alloc_fwsec_buffer((WPR_META_SIZE + 0xFFF) >> 12, &wprMetaPhys);
    if (EFI_ERROR(Status)) { Print(L"alloc meta: %r\n", Status); goto done; }
    Print(L"alloc meta  @0x%lx\n", wprMetaPhys);
    wprMeta = (GspFwWprMeta*)(UINTN)wprMetaPhys;
    /* v2.104: явные маркеры вокруг участка, где v2.103 зависал. Печать идёт
     * ДО любых вызовов выделения — если следующая строка не появилась,
     * зависание находится точно здесь. */
    Print(L"step: meta выделен, прошу страниц ниже 4ГБ (%d шт)...\n",
          (INTN)((V67_SIZE + 0xFFF) >> 12));
    /* fbSize: регистр 0x100440 отдаёт 0xBADF-паттерн (PLM-лок) — берём из
     * профиля карты. 70HX/GA104 8 ГБ → 0x200000000; 90HX/GA102 10 ГБ →
     * 0x280000000 (доказано: frts_offset 0x27fe00000 в dmesg рабочего анлока).
     * Значение критично: неверный fbSize даёт мусорную раскладку WPR, и
     * booter валится (halt 0x780009) ДО обработки подписи. */
        /* v2.66: V67-сигнатура дублируется НИЖЕ 4ГБ — ботер может читать
     * sysmemAddrOfSignature 32-битным путём; >4ГБ адрес = мусор для него */
    {
        UINT64 v67LowPhys = 0;
        if (!EFI_ERROR(alloc_below_4g((V67_SIZE + 0xFFF) >> 12, &v67LowPhys))) {
            CopyMem((VOID*)(UINTN)v67LowPhys, (VOID*)(UINTN)v67Phys, V67_SIZE);
            __asm__ volatile("wbinvd" ::: "memory");
            Print(L"v67-low копия @0x%lx (оригинал 0x%lx)\n", v67LowPhys, v67Phys);
            v67Phys = v67LowPhys;   /* meta указывает на <4ГБ копию */
        }
    }
    if (cmp90_stockSig) {
        /* v2.78: настоящая подпись BL — секция .fwsignature_ga10x из fw-ELF.
         * Копируем её в выровненный v67-буфер (Booter DMA требует
         * выравнивание 256). Оффсет берём из ELF: жёсткое 0x505E02E было
         * верно только для того gsp_ga10x.bin, где .fwimage начинался с 0x40
         * (в .fwsignature_га10x лежит на 0x505e06e, в буфере — минус 0x40). */
        UINT64 sigOff = 0, sigLen = 0;
        if (fwBase && gsp_elf_section((const UINT8 *)(UINTN)fwBase,
                                      GSP_FW_READ_WINDOW,
                                      ".fwsignature_ga10x", &sigOff, &sigLen) &&
            sigLen >= 0x1000) {
            CopyMem((VOID *)(UINTN)v67Phys, (VOID *)(UINTN)(fwBase + sigOff),
                    0x1000);
            __asm__ volatile("wbinvd" ::: "memory");
            {
                const UINT32 *s = (const UINT32 *)(UINTN)v67Phys;
                Print(L"v2.78: stock sig @0x%lx (ELF 0x%llx) head=%08x %08x %08x\n",
                      v67Phys, sigOff, s[0], s[1], s[2]);
            }
        } else {
            Print(L"v2.78: .fwsignature_ga10x не найдена — стоковый тест "
                  L"пропущен\n");
        }
    }
    build_wpr_meta(wprMeta, radixPhys, fwimageSizeUsed, v67Phys, TARGET_FB_SIZE,
                   blPhys, GSP_RM_BOOT_SIZE);
    Print(L"step: meta собрана (fb=0x%llX, frts=0x%llX, WPR2=0x%08X/0x%08X)\n",
          wprMeta->fbSize, wprMeta->frtsOffset,
          TARGET_WPR2_LO, TARGET_WPR2_HI);
    if (cmp90_corruptMeta) {
        /* v2.85: бисекция указателей. BL->0x300 дал 0x2, SIG->0x300 дал 0x2.
         * Теперь RADIX3 addr (поле 2): если снова 0x2 — НИ ОДИН указатель
         * не разыменовывается до abort => чистый environment-check. */
        wprMeta->sysmemAddrOfRadix3Elf = 0x300;
        Print(L"v2.85: RADIX ADDR ПОРЧЕН -> 0x%lx\n", wprMeta->sysmemAddrOfRadix3Elf);
    }
    {
        /* v2.84: полный дамп meta (248 байт) для побайтового сравнения с живым */
        UINT8 *mb = (UINT8 *)(UINTN)wprMetaPhys;
        UINTN r, c;
        Print(L"step: дамп meta...\n");
        for (r = 0; r < 248; r += 32) {
            Print(L"m[%02x]:", r);
            for (c = 0; c < 32; c++)
                Print(L"%02x", mb[r + c]);
            Print(L"\n");
        }
    }
    {
        UINT32 fbsz = mmio_read32(0x00100440);
        Print(L"fb size reg 0x440 = 0x%08x (0xBADF = залочен → берём из профиля: 0x%llX)\n",
              fbsz, TARGET_FB_SIZE);
        ulogf(L"FBIOS fbreg_0x440=0x%08x profile_fb=0x%llx %s\n", fbsz,
             TARGET_FB_SIZE, (fbsz == 0xBADF0000U || fbsz == 0) ? L"LOCKED" : L"READABLE");
    }
    __asm__ volatile("wbinvd" ::: "memory");
    Print(L"meta@0x%lx radix@0x%lx ucode@0x%lx v67@0x%lx fb=0x%lx\n",
          wprMetaPhys, radixPhys, ucodePhys, v67Phys, wprMeta->fbSize);
    /* v3n: здесь стояло «bootCount=%llu», и строка выглядела оборванной.
     * ПРИЧИНА ОКАЗАЛАСЬ НЕ В ФОРМАТЕ: ulogf передавал в UnicodeVSPrint
     * размер в символах вместо БАЙТ, и функция резала вывод на 199-м
     * символе (см. ulogf). Формат был ни при чём — предел наступал раньше,
     * чем разбирались спецификаторы. Именно поэтому оборванная строка так
     * убедительно выглядела как «сломанный %llu».
     *
     * Проверить утверждение «%llu не поддержан» НЕ УДАЛОСЬ: стенд для
     * проверки форматов (линковка print.o из gnu-efi в хостовую программу)
     * не пошёл из-за несовместимости ABI на границе. Утверждение НЕ
     * ДОКАЗАНО, опираться на него нельзя.
     *
     * Печатаем как 0x%llx — заодно ради единообразия: остальные поля этой
     * строки тоже hex. Проверенно рабочие форматы: %d с приведением к
     * INTN, %x/%llx, %u, %03u, %lld (см. KNOWN-ISSUES §42/43). */
    ulogf(L"META  meta@0x%llx radix@0x%llx ucode@0x%llx v67@0x%llx "
         "fbSize=0x%llx frtsOffset=0x%llx frtsSize=0x%llx wprEnd=0x%llx "
         "vgaWS=0x%llx bootBin=0x%llx bootCount=0x%llx\n",
         wprMetaPhys, radixPhys, ucodePhys, v67Phys, wprMeta->fbSize,
         wprMeta->frtsOffset, wprMeta->frtsSize, wprMeta->gspFwWprEnd,
         wprMeta->vgaWorkspaceOffset, wprMeta->bootBinOffset,
         (UINT64) wprMeta->bootCount);
    /* v3n: печатаем ВСЮ геометрию профиля, включая маржу. Именно её
     * подбираем перебором, и по этому логу видно, какая сборка на флешке —
     * иначе при переборе непонятно, откуда взялось значение. */
    ulogf(L"GEOM  margin=0x%llx (%d MB)  wprEnd=0x%llx  frts=0x%llx  "
         "frtsPG=0x%llx  expectWPR2=0x%08x/0x%08x\n",
         (UINT64) TARGET_WPR_END_MARGIN,
         (INTN)(TARGET_WPR_END_MARGIN >> 20),
         (UINT64) TARGET_WPR_END, (UINT64) TARGET_FRTS_OFFSET,
         (UINT64) TARGET_FRTS_OFFSET_PG,
         TARGET_WPR2_LO, TARGET_WPR2_HI);
    /* Сверка профиля со структурой, которая реально уходит в FWSEC и
     * booter. Прогон 2026-09-28 показал, что рассинхрон возможен и молчалив:
     * GEOM печатал frts=0x1F7E00000, а META — 0x1FFE00000, потому что
     * build_wpr_meta() считала геометрию сама. Теперь такой разрыв
     * печатается явно. */
    if (wprMeta->frtsOffset != TARGET_FRTS_OFFSET ||
        wprMeta->gspFwWprEnd != TARGET_WPR_END)
        ulogf(L"GEOM  *** MISMATCH: meta frts=0x%llx wprEnd=0x%llx  vs "
              L"profile frts=0x%llx wprEnd=0x%llx - BUILD BUG, fix "
              L"build_wpr_meta()\n",
              wprMeta->frtsOffset, wprMeta->gspFwWprEnd,
              (UINT64) TARGET_FRTS_OFFSET, (UINT64) TARGET_WPR_END);
    else
        ulogf(L"GEOM  profile and wpr meta agree\n");
    ulogf(L"PRE   WPR2=0x%08x/0x%08x PLM=0x%08x SS0=0x%08x SS1=0x%08x GFW=0x%08x\n",
         mmio_read32(REG_PFB_MMU_WPR2_LO), mmio_read32(REG_PFB_MMU_WPR2_HI),
         mmio_read32(0x00823804U), mmio_read32(REG_FEAT_OVR_SM_SPD),
         mmio_read32(REG_FEAT_OVR_SM_SPD_1), mmio_read32(0x00020f70U));

    /* --- ШАГ 1: доступен ли кадровый буфер через GSP-DMA? ---------------
     * Идёт ДО убийства GFW и до основного флоу, на чистом GSP: так результат
     * не зависит от того, что нагадили предыдущие стадии. Сама проба
     * ресетит GSP, поэтому порядок «сначала проба, потом GFW» безопасен —
     * и gsp_engine_reset() ниже всё равно приводит GSP в нужное состояние.
     * Ничего, кроме какого-нибудь мусора в неприкрытом FRTS-регионе, эта
     * проба испортить не может: WPR2 здесь ещё не защёлкнут. */
    log_ms(L"framebuffer access probe");
    /* v3.18: проба доступа к кадровому буферу убрана из релизной сборки.
     *
     * ИЗМЕРЕНО на прогоне v3.17 (usb-log-v317.txt):
     *     t=354ms  ->  t=3566ms "framebuffer access probe"   3212 мс
     *     t=3566ms ->  t=4752ms "FB probe done"               1186 мс
     * Итого 4,40 с из 57,3 с, то есть 7,7 % времени ПРОГОНА.
     *
     * Почему это чистая диагностика, а не часть анлока: функция ТОЛЬКО
     * ЧИТАЕТ - fbp_read() это DMA силами GSP в DMEM-окно, и всё, что она
     * печатает, является наблюдением. Её собственный вывод в прогоне
     * v3.17 гласит:
     *     ctrlA=PASS frtsRead=zero write=sent roundTrip=FAIL
     *     conclusion=frts-NOT-reachable-via-dma
     * То есть она честно сообщает об ОТРИЦАТЕЛЬНОМ результате и ничего не
     * меняет. Проба сбрашивает GSP ради чистоты замера, но
     * gsp_engine_reset() ниже всё равно приводит GSP в нужное состояние,
     * то есть её побочный эффект компенсируется следующей же стадией.
     *
     * Флаг по умолчанию 0 - BUILDING 6.0. Пропуск печатается строкой:
     * он обязан быть виден, иначе исчезновение пробы выглядело бы как
     * «проба перестала существовать». Возврат: -DFX_DIAG_FBPROBE=1.
     */
#if FX_DIAG_FBPROBE
    fb_access_probe(fwsecPhys);
#else
    ulogf(L"FBP    SKIPPED: FX_DIAG_FBPROBE=0 (read-only diagnostic, "
          L"measured 4.40s)\n");
#endif
    log_ms(L"FB probe done");

    /* --- v2.12: убить GFW (как драйвер: kflcnReset(GSP) перед booter load) ---
     * Живой GFW из POST держит SEC2 залоченным. GSP ENGINE (0x1103C0)
     * доступен из EFI (v2.10: читался 0x0). */
    /* v3.17: разметка окна 10,64 с, которое раньше НЕ БЫЛО размечено.
     * Измерено по маркерам времени прогона 2026-10-02:
     *     t=19969ms "FB probe done"  ->  t=30607ms "before early path"
     * Между ними: gsp_engine_reset + Stall(200000), проверка разлочки
     * SEC2, второй sweep_all (теперь убран) и sec2_ucode_mapper_cmd.
     *
     * Без этих меток окно выглядело одним куском, и оптимизировать в нём
     * было нечего. Внутри mapper есть два Stall(500000) - это секунда,
     * и до сих пор она была гипотезой, а не измерением. */
    {
        UINT64 mrk = fx_now_us();
        log_ms(L"before gsp_engine_reset (kill GFW)");
        gsp_engine_reset();
        /* v3.18: слепая пауза 200 мс заменена ожиданием СОБЫТИЯ.
         *
         * ИЗМЕРЕНО (v3.17): вся фаза «gsp_engine_reset + 200ms settle» стоит
         * 200 697 мкс, из которых ровно 200 000 - это Stall, то есть 99,6 %
         * фазы не ждёт ничего. Замер: fx_ph_end печатает фактическое время,
         * поэтому в следующем прогоне видно, сработало ли ожидание.
         *
         * ЧТО ЖДЁМ: после сброса движка GSP Falcon скрабит IMEM/DMEM
         * паттерном DEAD5EC*. До окончания скраба DMA соревнуется со
         * скраббером и затирается - это ровно тот класс отказа, из-за
         * которого falcon_wait_scrub_done() ЗАПРЕЩЕНО заканчивать раньше
         * времени (см. предупреждение в его комментарии).
         *
         * ПОЧЕМУ ЭТО НЕ ТО ЖЕ, ЧТО ТАМ. Здесь скраб не проверяется - он
         * просто переживается, потому что следом идёт полная перезагрузка
         * GSP движком и своя последовательность с собственным ожиданием
         * скраба. То есть это «дать железу отдохнуть», а не «ждать готовности
         * к DMA». Разница принципиальная, и поэтому ожидание события здесь
         * уместно, а в falcon_wait_scrub_done - нет.
         *
         * Потолок 200 мс СОХРАНЁН: если скраб не завершится, ждём ровно
         * столько же, сколько раньше. Быстрее - только когда событие уже
         * наступило, то есть когда ждать нечего. */
        (VOID)falcon_wait_scrub_done(GSP_DMACTL, GSP_HWCFG2, L"gsp-post-reset");
        fx_mk_acc(mrk, L"gsp_engine_reset + scrub wait");
    }

    /* --- v2.12: проверка разлочки SEC2 после смерти GFW --- */
    {
        UINT32 cpuctl = mmio_read32(SEC2_CPUCTL);
        UINT32 dmatrf = mmio_read32(SEC2_DMATRFCMD);
        UINT32 fbictl = mmio_read32(SEC2_FBIF_CTL);
        UINT32 bcr    = mmio_read32(SEC2_BCR_CTRL);
        Print(L"sec2: после убийства GFW: CPUCTL=0x%08x DMATRFCMD=0x%08x FBIF_CTL=0x%08x BCR=0x%08x\n",
              cpuctl, dmatrf, fbictl, bcr);
        if (((cpuctl & 0xBADF0000) == 0xBADF0000) ||
            ((dmatrf & 0xBADF0000) == 0xBADF0000)) {
            /* priv lockdown не снят — пробую BCR CORE_SELECT=FALCON
             * (kflcnSwitchToFalcon: "Switch the core to FALCON. Releases priv lockdown.") */
            Print(L"sec2: залочен — пишу BCR CORE_SELECT=FALCON (0x841668 = 0x1)...\n");
            mmio_write32(SEC2_BCR_CTRL, 0x1);  /* VALID=1, CORE_SELECT=FALCON(0), BRFETCH=0 */
            for (i = 0; i < 16; i++) mmio_read32(SEC2_BCR_CTRL);
            uefi_call_wrapper(BS->Stall, 1, 10000);
            cpuctl = mmio_read32(SEC2_CPUCTL);
            Print(L"sec2: CPUCTL после BCR = 0x%08x\n", cpuctl);
        }
        if ((cpuctl & 0xBADF0000) == 0xBADF0000) {
            Print(L"sec2: ВСЁ ЕЩЁ ЗАЛОЧЕН (0xBADF) — SEC2-путь недоступен, останов.\n");
            goto done;
        }
        Print(L"sec2: РАЗЛОЧЕН! (CPUCTL=0x%08x) — запускаю SEC2 booter load (механизм Linux-драйвера)\n", cpuctl);
    }
    /* v3.17: тот же read-only свип, что и POST. Стоимость не измерена
     * отдельно (здесь маркеров времени нет), но тот же код и тот же
     * приём: печать ненулевых регистров. Убран вместе с POST-свипом.
     * Комментарий 21bb387 «sweep_all ran twice, costing 11.9 s» относился
     * именно к этим двум вызовам. */
#if FX_DIAG_SWEEPS
    sweep_all(L"SEC2-unlocked");
#else
    ulogf(L"SWEEP  sweep_all(SEC2-unlocked) SKIPPED: FX_DIAG_SWEEPS=0\n");
#endif

    /* v2.57: SEC2 ucode mapper init_cmd (FRTS/SB) — ПЕРВЫМ (до v2.51!):
     * предзагруженный VBIOS-ucode (ucodeId=10) живёт в SEC2 DMEM только до
     * первых инженерных операций (v2.51/stage-4 убивают secure-зону —
     * DEAD5EC2). Mapper@DMEM[0x698], init_cmd@0x6C4, cmd_in@0x23D0.
     * FRTS→WPR2, SB→privmask. На свежем POST secure-зона цела. */
    sec2_health(L"1-post-unlock");
    if (!cmp90_skipMapper) {
        UINT64 mrk = fx_now_us();
        if (sec2_ucode_mapper_cmd(wprMetaPhys)) {
            Print(L"v2.57: *** SEC2 ucode команда сработала (WPR2/SB) ***\n");
        }
        /* v3.17: mapper-стадия в окне 10,64 с шла без единой метки. Здесь
         * появляется её фактическая стоимость - два Stall(500000) внутри
         * видны отдельной строкой фазового учёта. */
        fx_mk_acc(mrk, L"sec2 ucode mapper cmd");
    } else {
        Print(L"v2.79: mapper-стадия пропущена (приближение к флоу драйвера)\n");
    }
    sec2_health(L"2-post-mapper");

    /* === v2.70: РАННИЙ ПРЯМОЙ ПУТЬ — ботер ПЕРВЫЙ на свежем SEC2 ===
     * v2.69b: первый же старт ботера на SEC2 (v251[3]) клинит блок регистров
     * (записи не липнут, reset не лечит) — все последующие попытки исполняли
     * труп. Теперь BL(GSP)→FWSEC(GSP)→WPR2→libos→booter_load_v67 на живом. */
    earlyOk = FALSE;
    log_ms(L"before early path (allocs done)");
    {
        EFI_STATUS earlySt = early_unlock_path(ucodePhys, fwsecPhys, wprMetaPhys);
        sec2_health(L"9-post-early");
        /* v3n: граница после раннего пути (он зовёт booter_load_v67).
         * Нужна, чтобы отделить вклад FWSEC-перебора от вклада ботера:
         * оба печатают через Print/ulogf по-разному, но WPR2 трогать могут
         * оба. */
        wpr2_probe(L"after-early-path");
        sec2_window_dump(L"after-early-path");
        if (earlySt == EFI_SUCCESS) {
            Print(L"v2.70: *** ранний путь: PLM открыт ***\n");
            earlyOk = TRUE;
        }
    }
    log_ms(L"early path finished");
    fx_gapT0 = fx_now_us();      /* v3.21: старт замера разрыва, см. fx_gapT0 */

    if (!earlyOk) {
    /* --- v2.28/32: FWSEC на GSP (FRTS/WPR2) + kflcnResetIntoRiscv + LibosBootArgs
     * Драйвер: kflcnReset(GSP) → kgspExecuteFwsec(FRTS) → kflcnResetIntoRiscv(GSP) →
     * kgspProgramLibosBootArgsAddr(GSP) → BooterLoad(SEC2). Без FWSEC SEC2 BROM
     * не стартует (dbg=0x0); после WPR2 добавлены шаги ResetIntoRiscv (BCR=RISCV)
     * и LibosBootArgs (mailbox), т.к. booter load всё ещё dbg=0x0 (v2.31). */
    /* v2.51: FWSEC re-load + SB → SEC2 booter (V67) — ПЕРВЫЙ тест на свежем
     * POST. Если наш FWSEC выполнится (WPR2) — SEC=1+BROM на GSP работают;
     * SB откроет SEC2; booter load с правильными размерами запустит V67. */
    {
        BOOLEAN v251ok = driver_replay_v251(fwsecPhys, ucodePhys, wprMetaPhys);
        sec2_health(L"3-post-v251");
        if (v251ok) {
            Print(L"v2.51: *** результат получен — разблокирую ***\n");
            Status = EFI_SUCCESS;
        } else {
            log_ms(L"v2.51 no result");
            Print(L"v2.51: без результата — пробую v2.46 полный реплей\n");
    /* v2.46: ПОЛНЫЙ РЕПЛЕЙ последовательности драйвера (3 стадии) — замена
     * v2.45 flow. Если реплей дал результат (наш код выполнился / PLM открыт) —
     * пишем SS0/SS1, FLR, chainload. Иначе — fallback на v2.45 flow. */
    {
        BOOLEAN replayOk = driver_replay_v246(ucodePhys, fwsecPhys,
                                              ucodePhys, wprMetaPhys);
        sec2_health(L"4-post-v246");
        if (replayOk) {
            Print(L"v2.46: *** ПОЛНЫЙ РЕПЛЕЙ УСПЕШЕН — разблокирую ***\n");
            Status = EFI_SUCCESS;
        } else {
            /* v2.62: ретрай-луп FWSEC с паузами — гипотеза асинхронного
             * процесса GPU (скраб/GFW-хвост), мешающего первому прогону */
            BOOLEAN fwOk = FALSE;
            UINTN attempt;

            /* v2.105 (порт 70HX): СНАЧАЛА пробуем штатный FWSEC, который
             * карта загрузила сама. Наш образ не запустится — к нему в
             * репозитории пришита подпись от GA102 (см. fwsec_preloaded_gsp).
             * Подписанный силами самой карты код с её же FRTS-параметрами —
             * единственный вариант, который не требует от нас знать
             * frtsOffset и не требует валидной подписи. */
            Print(L"\nv2.105: ПРОБА ШТАТНОГО FWSEC (без нашей подписи)...\n");
            log_ms(L"before stock FWSEC");
            if (fwsec_preloaded_gsp()) {
                fwOk = TRUE;
                Print(L"v2.105: *** ШТАТНЫЙ FWSEC СРАБОТАЛ — WPR2 поднят ***\n");
            } else {
                Print(L"v2.105: штатный FWSEC не поднял WPR2, пробую свой образ\n");
            }

            /* v2.106: перебор трёх подписей FWSEC из VBIOS карты.
             * Проверено на дампе GA104.rom: sigCount=3, третья запись (sig[2])
             * — та, что лежит в репозитории, и верна для 90HX. Подпись НЕ
             * вычисляется по образу (у GA102 и GA104 она байт-в-байт равна
             * при разных образах) — это версии под разные fuse-ревизии, так
             * что ревизия 70HX вполне может требовать sig[1].
             *
             * Порядок: 2 (рабочая на 90HX), 1 (единственная другая настоящая),
             * 0 — ВСЕ НУЛИ, заглушка неподписанного слота. Её пробуем
             * последней как КОНТРОЛЬНЫЙ ОПЫТ: если WPR2 встанет и с нулевой
             * подписью, значит BROM подпись не проверяет вовсе и 0x780009
             * вызван чем-то другим. */
            {
                /* v2.107: перебор 2x2 — подпись {sig2, sig1, sig0} x
                 * {IMEM SEC=1, IMEM SEC=0}. Подпись: SIG[2] рабочая на
                 * 90HX, остальные — из VBIOS самой карты. Режим SEC: на
                 * 70HX защищённый IMEM отдаёт 0xDEAD5EC1 (осознанный отказ
                 * GSP), а основания грузить через SEC=1 больше нет —
                 * после POST IMEM пуст (imem_card=0x00000000), затирать
                 * нечего. Порядок: сначала проверенная комбинация
                 * sig2+SEC1, затем то, что правдоподобно для 70HX. */
                /* Подписи 1 и 0: sig[0] — это 384 байта НУЛЕЙ (см.
                 * docs/70HX-VBIOS-ANALYSIS.md §4), то есть заведомо
                 * бесполезна. Оставляем все три на случай, если
                 * пересчёт из другого VBIOS даст иной набор. */
                static const UINT8 *sigs[3] = {
                    fwsec_ga104_prod_sig2, fwsec_ga104_prod_sig1,
                    fwsec_ga104_prod_sig0
                };
                static const UINTN sigOrder[3] = { 2, 1, 0 };
                /* v3n: решающий сдвиг 2026-09-28.
                 *
                 * Раньше здесь стояло secOrder = {0,0,0} с обоснованием
                 * «secure-DMA забивает DMEM значением 0xDEAD5EC2». Это
                 * заключение было построено на НЕВЕРНОЙ команде DMA: бит
                 * IMEM=1 ставился в позицию SEC, поэтому «secure-DMA» на
                 * самом деле писал в DMEM, а не в IMEM. Сейчас:
                 *
                 *   IMEM: cmd=0x614 (IMEM=1, SEC=1) - как в драйвере
                 *   DMEM: cmd=0x600 (IMEM=0, SEC=0) - как в драйвере
                 *
                 * и IMEM после DMA читается как 0xDEAD5EC1 во всех 9 точках,
                 * то есть он ЗАНЯТ (код загрузился), а не пуст. Старый
                 * вывод «на 70HX secure-путь не проходит» доказанным
                 * образом не состоялся.
                 *
                 * Итог: перебор SEC теперь осмыслен. Идём 1=secure (как в
                 * драйвере), 0=non-secure, 0=non-secure — на случай, если
                 * на этой карте secure-IMEM всё же недоступен для записи.
                 */
                static const UINTN secOrder[3] = { 1, 0, 0 };
                for (attempt = 1; attempt <= 3 && !fwOk; attempt++) {
                    UINTN s = sigOrder[attempt - 1];
                    UINTN sec = secOrder[attempt - 1];
                    Print(L"v2.107: FWSEC попытка %d/3 — sig[%d] + IMEM SEC=%d "
                          L"(пауза 3с)...\n", attempt, (INTN)s, (INTN)sec);
                    ulogf(L"FWSEC try=%d sigIndex=%d imemSec=%d\n",
                          attempt, s, sec);
                    uefi_call_wrapper(BS->Stall, 1, 3000000);
                    CopyMem((VOID*)(UINTN)fwsecPhys, fwsec_ga104_bin, FWSEC_SIZE);
                    fwsec_set_imem_sec(sec);
                    if (fwsec_boot_gsp_sig(fwsecPhys, sigs[attempt - 1], s)) {
                        fwOk = TRUE;
                        Print(L"v2.107: *** FWSEC СРАБОТАЛ: sig[%d] SEC=%d ***\n",
                              (INTN)s, (INTN)sec);
                        ulogf(L"FWSEC OK with sig[%d] imemSec=%d\n", s, sec);
                    } else {
                        Print(L"v2.107: sig[%d] SEC=%d — WPR2 не встал\n",
                              (INTN)s, (INTN)sec);
                    }
                    sec2_health(L"5-fwsec-retry");
                }
            }
            log_ms(L"FWSEC attempts finished");
            if (fwOk) {
        Print(L"fwsec: OK — WPR2 установлен. kflcnResetIntoRiscv(GSP)...\n");
        mmio_write32(GSP_ENGINE, 0x1);
        for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
        mmio_write32(GSP_ENGINE, 0x0);
        for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
        uefi_call_wrapper(BS->Stall, 1, 50000);
        mmio_write32(GSP_BCR, 0x111);            /* VALID|CORE_SELECT=RISCV|BRFETCH */
        for (i = 0; i < 16; i++) mmio_read32(GSP_BCR);
        Print(L"fwsec: GSP BCR после ResetIntoRiscv = 0x%x (0x111 = RISCV)\n",
              mmio_read32(GSP_BCR));
        mmio_write32(GSP_MAILBOX0, (UINT32)cmp90_meta_low(wprMetaPhys));   /* LibosBootArgs */
        mmio_write32(GSP_MAILBOX1, (UINT32)(cmp90_meta_low(wprMetaPhys) >> 32));
        Print(L"fwsec: GSP mbox0=0x%08x mbox1=0x%08x (libos args = WPR meta)\n",
              mmio_read32(GSP_MAILBOX0), mmio_read32(GSP_MAILBOX1));
        Print(L"fwsec: запускаю SEC2 booter load\n");
    } else {
        Print(L"fwsec: НЕ отработал — SEC2 booter load без WPR2 (как v2.24)\n");
    }

    /* --- SEC2 booter load (V67) — тот же механизм, что в Linux (rejoin15) --- */
    sec2_health(L"6-pre-booter");
    Status = booter_load_v67(wprMetaPhys, ucodePhys);

    /* v2.25: если BROM-путь не сработал — прямой запуск RISC-V (обход BROM) */
    if (Status != EFI_SUCCESS && riscv_direct_start()) {
        Print(L"riscv: *** ПРЯМОЙ запуск RISC-V открыл PLM ***\n");
        Status = EFI_SUCCESS;
    }
        }   /* конец else (fallback v2.45) */
    }   /* конец replay-блока v2.46 */
        }   /* конец else v2.51 */
    }   /* конец блока v2.51 */
    }   /* !directOk */
    }   /* !earlyOk (v2.70) */

#ifdef PCIE_GEN2_REJOIN
    /* v2.99: gen2-цикл — verify + advance (или финальный конфиг) */
    {
        BOOLEAN have2 = FALSE;
        UINTN gi = mc_var_get(L"CMP90G2", &have2);
        /* v3n: g_gen2Enable — рубильник. По умолчанию выключен: замер показал,
         * что свип съедает ~10.8 мин из 13 и не доходит до FF. Включается
         * осознанно, когда WPR2 защёлкивается и понадобится полный PLM. */
        ulogf(L"GEN2  switch: fire=%d have2=%d enable=%d -> %s\n",
              (INTN)g_gen2Fire, (INTN)have2, (INTN)g_gen2Enable,
              (g_gen2Fire && have2 && g_gen2Enable) ? L"SWEEP RUNNING"
                                                    : L"sweep SKIPPED");

        /* v3n: МЕТКИ ПО ПУТИ (2026-09-28).
         *
         * Наблюдение: прогоны sec1/okchk ОБРЫВАЮТСЯ ровно на этой строке -
         * после неё в логе нет ни 'SS0', ни 'END', ни 'возврат в прошивку'.
         * То есть до финального блока селекторов (стр. ~7899) управление
         * не доходит, и непонятно где именно.
         *
         * Причина непонятна ещё и потому, что огромная часть кода ниже
         * печатает ТОЛЬКО через Print() (на экран), а в лог идёт ulogf().
         * Если обрыв происходит после Print(), в логе его не видно, и
         * вывод 'ничего не выполнилось' неверен - просто нечего писать.
         *
         * Поэтому: метки до и после каждой стадии, именно в лог. Тогда
         * обрыв локализуется точно, без догадок. */
        ulogf(L"STG   enter gen2 block fire=%d have2=%d enable=%d\n",
              (INTN)g_gen2Fire, (INTN)have2, (INTN)g_gen2Enable);

        if (g_gen2Fire && have2 && g_gen2Enable) {
            ulogf(L"STG   gen2 sweep START\n");

            /* v2.99f: каждая пара = ПОЛНЫЙ FLR-миницикл внутри EFI,
             * 1:1 как «module reload» у rejoin16:
             *   FLR → ранний путь (BL→FWSEC→WPR2→RISCV→ботер#1 со stock-
             *   payload, открывает PLM заново — он ПЕРЕЖИВАЕТ FLR) →
             *   ботер#2 с патченной парой → поллинг readback.
             * Эмпирика стенда: за один бут-цикл стреляют ровно 2 исполнения
             * ботера (#1 stock + #2 crafted); третье и далее — никогда,
             * FWSEC-рефилл между ними не помогает (v2.99e).
             * Маски переживают FLR, но гибнут при тёплом/холодном ресете
             * (доказано: 0x88fe8 откатился в CF после ResetSystem-Warm) —
             * поэтому после любого сбоя таблица перепроходится с начала.
             * v2.99h: при g_gen2Quick цикл не выполняется (маски уже
             * открыты) — сразу свип и Gen2-конфиг ниже. */
            INTN i, pass;
            BOOLEAN done = FALSE;
            Print(L"gen2: ботер#1 открыл PLM=0x%08x\n",
                  mmio_read32(0x00823804U));
            /* v2.100: МУЛЬТИПРОХОД. На хосте семейства с RO-нулями
             * (0xFFFFFFCF/8F) дали точный FF только на ВТОРОМ проходе,
             * после открытия соседних PLM. Один проход = один полный обход
             * таблицы с FLR-минициклами; перед выстрелом — pre-check:
             * уже точный FF => миницикл не нужен. До 3 проходов. */
            for (pass = 0; pass < 3 && !g_gen2Quick && !done; pass++) {
                Print(L"gen2: === ПРОХОД %d/3 ===\n", (INTN)pass + 1);
                ulogf(L"GEN2  pass %d/3 started\n", (INTN)pass + 1);
                for (i = 1; i < RJ16_N; i++) {
                    volatile UINT32 *pv =
                        (volatile UINT32 *)(UINTN)(v67Phys + 0xf948);
                    volatile UINT32 *pa =
                        (volatile UINT32 *)(UINTN)(v67Phys + 0xf960);
                    UINT32 rd, saveBar;
                    UINTN tries;
                    /* v2.99g: SKIP OPTB-блока (0x8200d0..f4). У rejoin16 прямо
                     * написано: «Gen2 provably works with OPTB locked». У нас
                     * записи в этой зоне стабильно валят гостя в ресет на
                     * итерациях [29-31] (3 прогона подряд, QEMU exit=0).
                     * v2.100a: SKIP и 0x88084 LINK_CAP — speed-ниббл живой,
                     * следует за фактическим линком, записью не фиксируется. */
                    if ((g_rj16[i].addr >= 0x008200d0U && g_rj16[i].addr <= 0x008200f4U) ||
                        g_rj16[i].addr == 0x00088084U) {
                        Print(L"gen2[%d/%d] SKIP 0x%08x\n",
                              (INTN)i + 1, (INTN)RJ16_N, g_rj16[i].addr);
                        continue;
                    }
                    /* v2.100: уже точный FF — миницикл не тратим */
                    if (mmio_read32(g_rj16[i].addr) == g_rj16[i].val)
                        continue;
                    ulogf(L"GEN2  pass%d [%d] 0x%08x <- 0x%08x (now 0x%08x)\n",
                          (INTN)pass + 1, (INTN)i + 1, g_rj16[i].addr,
                          g_rj16[i].val, mmio_read32(g_rj16[i].addr));
                    Print(L"gen2[%d/%d] 0x%08x <- 0x%08x\n",
                          (INTN)i + 1, (INTN)RJ16_N,
                          g_rj16[i].addr, g_rj16[i].val);
                    /* --- FLR-разделение: маски переживают, счётчик выстрелов
                     *      сбрасывается; BAR0 восстанавливаем сами --- */
                    saveBar = cfg_read32(0x10) & ~0xF;
                    do_flr();
                    uefi_call_wrapper(BS->Stall, 1, 300000);
                    cfg_write32(0x10, saveBar);
                    enable_mem_decode();
                    gBar0Base = saveBar;
                    /* --- ранний путь: ботер#1 со stock-payload (PLM) ---
                     *
                     * v3n: РАНЬШЕ early_unlock_path() звался на КАЖДОЙ записи
                     * таблицы, где маска ещё не FF. Это 3 прохода × 41 запись
                     * = до 120 полных FWSEC-загрузок, каждая с паузами по
                     * секунде, — минуты работы и сотни строк лога, при том что
                     * FWSEC от запуска не зависит: образ уже залит и лежит в
                     * IMEM (imem_ours=0xEC547D23). Запускаем ОДИН раз: FWSEC
                     * нужен, чтобы открыть secure-путь, а не чтобы повторять
                     * его 120 раз подряд. */
                    if (!g_fwsecOnce) {
                        g_fwsecOnce = TRUE;
                        CopyMem((VOID*)(UINTN)v67Phys, v67_payload_bin, V67_SIZE);
                        early_unlock_path(ucodePhys, fwsecPhys, wprMetaPhys);
                    }
                    /* --- ботер#2 с нашей парой (второй разрешённый выстрел) --- */
                    *pv = g_rj16[i].val;
                    *pa = g_rj16[i].addr;
                    booter_load_v67(wprMetaPhys, ucodePhys);
                    /* запись асинхронная: у референса ~147-1000 polls×1мс */
                    rd = mmio_read32(g_rj16[i].addr);
                    for (tries = 0; rd != g_rj16[i].val && tries < 1000; tries++) {
                        uefi_call_wrapper(BS->Stall, 1, 1000);
                        rd = mmio_read32(g_rj16[i].addr);
                    }
                    if (rd == g_rj16[i].val)
                        continue;
                    /* v2.99g: НЕ ПРЕРЫВАЕМСЯ — недостrel попадёт в свип и
                     * будет перепроверен следующим проходом (v2.100). */
                    Print(L"gen2[%d]: readback 0x%08x != FF — продолжаю "
                          L"(перепроверка в свипе)\n", (INTN)i + 1, rd);
                }
                /* --- v2.100: свип прохода — критерий ТОЛЬКО точный FF --- */
                done = TRUE;
                for (i = 0; i < RJ16_N; i++) {
                    UINT32 a = g_rj16[i].addr, cur;
                    /* v2.100a: OPTB не обязателен; 0x88084 живой (см. выше) */
                    if ((a >= 0x008200d0U && a <= 0x008200f4U) ||
                        a == 0x00088084U)
                        continue;
                    cur = mmio_read32(a);
                    if (cur != g_rj16[i].val) {
                        Print(L"gen2: свип п%d [%d] 0x%08x = 0x%08x — НЕ точный\n",
                              (INTN)pass + 1, (INTN)i + 1, a, cur);
                        ulogf(L"GEN2  sweep pass%d [%d] 0x%08x = 0x%08x - NOT exact\n",
                              (INTN)pass + 1, (INTN)i + 1, a, cur);
                        done = FALSE;
                    }
                }
                ulogf(L"GEN2  pass %d finished - masks %s\n", (INTN)pass + 1,
                      done ? L"ALL EXACT FF" : L"not all exact (another pass)");
                {
                    /* v3n: замер времени проходa — без него 13 минут не
                     * разложить по фазам */
                    static const CHAR16 *ptag[3] = { L"gen2 pass 1 finished",
                                                     L"gen2 pass 2 finished",
                                                     L"gen2 pass 3 finished" };
                    if (pass < 3) log_ms(ptag[pass]);
                }
            }
            mc_var_set(L"CMP90G2", (UINT32)RJ16_N);
            Print(L"gen2: таблица пройдена — состояние масок перед конфигом:\n");
            {
                INTN k;
                for (k = 0; k < RJ16_N; k++)
                    Print(L"gen2: [%d] 0x%08x = 0x%08x\n", (INTN)k,
                          g_rj16[k].addr, mmio_read32(g_rj16[k].addr));
                ulogf(L"GEN2  summary of 41 entries (to log, not to read on screen):\n");
                for (k = 0; k < RJ16_N; k++)
                    ulogf(L"GEN2  [%d] 0x%08x = 0x%08x%s\n", (INTN)k,
                          g_rj16[k].addr, mmio_read32(g_rj16[k].addr),
                          (mmio_read32(g_rj16[k].addr) == g_rj16[k].val)
                              ? L"  exact" : L"  NOT exact");
            }
            Print(L"gen2: применяю конфиг\n");
#ifndef FULL_NOGEN2
            {   /* xrip-рецепт: порядок важен, PL_LINK_RATE НЕ трогаем! */
                UINT32 v2;
                v2 = mmio_read32(0x0008841cU);   /* PRIV_MISC_1 */
                mmio_write32(0x0008841cU,
                    (v2 | (1u<<11)|(1u<<13)) & ~((1u<<12)|(1u<<14)));
                mmio_write32(0x0008c2c0U,          /* CYA_0: bit2=0 */
                             mmio_read32(0x0008c2c0U) & ~(1u<<2));
                mmio_write32(0x0008e120U, 0x00000000u);   /* XP3G VAL0 */
                mmio_write32(0x0008e110U, 0x00000001u);   /* XP3G OVR0 */
                mmio_write32(0x0008e12cU, 0x00200000u);   /* XP3G VAL3 */
                mmio_write32(0x0008e11cU, 0x00000004u);   /* XP3G OVR3 */
                v2 = mmio_read32(0x0008c040U);             /* LINK_CONFIG_0 */
                /* v2.99o: MAX_RATE=2 (Gen3 клампится кремнием, v2.99k) */
                mmio_write32(0x0008c040U, (v2 & ~0x000C0000U) | (2u<<18));
                /* v2.99o: LTSSM kick УБРАН! На реальном HW он бьёт по линку
                 * в момент, когда консоль идёт через эту же карту — экран
                 * «замерзает» (ложный висяк). Тренинг сделает драйвер
                 * Windows при инициализации: LINK_CAP=Gen2 уже стоит. */
                v2 = mmio_read32(0x000880a8U);             /* LC2 TLS=Gen2 */
                mmio_write32(0x000880a8U, (v2 & ~0xFu) | 2u);
            }
#endif /* !FULL_NOGEN2 */
                {   /* v2.100: GFX_SPEED_SELECT=4 + верификация readback.
                     * Бин 0x4 открывает следующий gfx-бин (на хосте это
                     * дало 214.7 -> 4236.7 fps в vkrenderbench). Запись
                     * липнет только при открытом PLM 0x823b04 — поэтому
                     * проверяем и повторяем, иначе «3D не ускоряется». */
                    INTN t;
                    UINT32 gv;
                    mmio_write32(0x00823830U, GFX_SPEED_SEL_VALUE);
                    uefi_call_wrapper(BS->Stall, 1, 50000);
                    gv = mmio_read32(0x00823830U);
                    for (t = 0; gv != 0x00000004u && t < 5; t++) {
                        Print(L"gen2: GFX_SEL readback 0x%08x != 4 — повтор\n",
                              gv);
                        uefi_call_wrapper(BS->Stall, 1, 50000);
                        mmio_write32(0x00823830U, GFX_SPEED_SEL_VALUE);
                        uefi_call_wrapper(BS->Stall, 1, 50000);
                        gv = mmio_read32(0x00823830U);
                    }
                    Print(L"gen2: GFX_SPEED_SELECT %s\n",
                          gv == 0x00000004u
                              ? L"OK = 0x4 (3D-бин открыт)"
                              : L"НЕ ВСТАЛ — маска 0x823b04 не точный FF?");
                }
                /* ===== v2.101: SS0/SS1 — compute-селекторы напрямую =====
                 * Ванильный драйвер ОС не восстанавливает их (это был
                 * stockflow-патч). Прямые записи при открытом PLM
                 * 0x823804 липнут и применяются живой системой без
                 * ресета (хост, 2026-08-24: bench2 18.27 TFLOP/s FP32).
                 * Порядок: до phase3, как GFX_SEL выше. */
                {
                    INTN t;
                    UINT32 sv;
                    mmio_write32(REG_FEAT_OVR_SM_SPD, 0x88888888u);
                    uefi_call_wrapper(BS->Stall, 1, 50000);
                    sv = mmio_read32(REG_FEAT_OVR_SM_SPD);
                    for (t = 0; sv != 0x88888888u && t < 5; t++) {
                        Print(L"gen2: SS0 readback 0x%08x — повтор\n", sv);
                        uefi_call_wrapper(BS->Stall, 1, 50000);
                        mmio_write32(REG_FEAT_OVR_SM_SPD, 0x88888888u);
                        uefi_call_wrapper(BS->Stall, 1, 50000);
                        sv = mmio_read32(REG_FEAT_OVR_SM_SPD);
                    }
                    mmio_write32(REG_FEAT_OVR_SM_SPD_1, 0x00000008u);
                    uefi_call_wrapper(BS->Stall, 1, 50000);
                    sv = mmio_read32(REG_FEAT_OVR_SM_SPD_1);
                    for (t = 0; sv != 0x00000008u && t < 5; t++) {
                        Print(L"gen2: SS1 readback 0x%08x — повтор\n", sv);
                        uefi_call_wrapper(BS->Stall, 1, 50000);
                        mmio_write32(REG_FEAT_OVR_SM_SPD_1, 0x00000008u);
                        uefi_call_wrapper(BS->Stall, 1, 50000);
                        sv = mmio_read32(REG_FEAT_OVR_SM_SPD_1);
                    }
                    Print(L"gen2: SS0=%08x SS1=%08x %s\n",
                          mmio_read32(REG_FEAT_OVR_SM_SPD),
                          mmio_read32(REG_FEAT_OVR_SM_SPD_1),
                          (mmio_read32(REG_FEAT_OVR_SM_SPD) == 0x88888888u &&
                           mmio_read32(REG_FEAT_OVR_SM_SPD_1) == 0x8u)
                              ? L"OK (compute-бин открыт)"
                              : L"НЕ ВСТАЛИ");
                }
#ifndef FULL_NOGEN2
                /* ===== v2.100: phase3 — ОЕ СТОРОНЫ ЛИНКА (рецепт хоста) =====
                 * Доказано на хосте: TLS=5GT/s в LNKCTL2 ОБОИХ концов +
                 * Retrain Link на бридже -> линк 5 GT/s, и драйвер ОС при
                 * инициализации САМ удерживает/возвращает Gen2. Два бага
                 * v2.99k исправлены: (1) LNKCTL2 = cap+0x30, а НЕ cap+0x2C
                 * (= LNKCAP2, read-only — записи игнорировались!);
                 * (2) TLS = 2 (5 GT/s), а НЕ 3 — Gen3 клампится кремнием.
                 * Бридж ищется через ВСЕ root bridges (v2.99l-баг). */
                {
                    UINTN bb = 0, bd = 0, bf = 0;
                    UINTN gc = find_pcie_cap(gBus, gDev, gFn);
                    if (gc) {
                        UINT32 lc2 = pci_cfg_rd_bdf(gBus, gDev, gFn, gc + 0x30);
                        lc2 = (lc2 & ~0xFu) | 2u;      /* TLS = 5 GT/s */
                        pci_cfg_wr_bdf(gBus, gDev, gFn, gc + 0x30, lc2);
                        Print(L"gen2: GPU LNKCTL2(cap+30) <- %04x (TLS=5GT/s)\n",
                              (INTN)(lc2 & 0xFFFF));
                    }
                    if (find_bridge_to(gBus, &bb, &bd, &bf)) {
                        UINTN bc = find_pcie_cap(bb, bd, bf);
                        Print(L"gen2: апстрим-бридж %02lx:%02lx.%lx "
                              L"pcie_cap@%02lx (RB %d)\n",
                              (INT64)bb, (INT64)bd, (INT64)bf, (INT64)bc,
                              (INTN)gBrIdx);
                        if (bc) {
                            UINT32 lc2 = pci_cfg_rd_idx(gBrIdx, bb, bd, bf,
                                                        bc + 0x30);
                            UINT32 lc;
                            lc2 = (lc2 & ~0xFu) | 2u;  /* v2.100: TLS=5GT/s */
                            pci_cfg_wr_idx(gBrIdx, bb, bd, bf, bc + 0x30, lc2);
                            lc = pci_cfg_rd_idx(gBrIdx, bb, bd, bf, bc + 0x10);
                            pci_cfg_wr_idx(gBrIdx, bb, bd, bf, bc + 0x10,
                                           lc | (1u << 5));/* Retrain Link */
                            Print(L"gen2: бридж LNKCTL2=%04x TLS=5GT/s + RL "
                                  L"— тренинг запущен\n", (INTN)(lc2 & 0xFFFF));
                        }
                    } else {
                        /* v2.99j: на стенде QEMU GPU висит на root complex
                         БЕЗ апстрим-бриджа (гость его не видит) — это НЕ
                         ошибка; на реальном HW бридж будет найден и
                         настроен здесь же. */
                        Print(L"gen2: upstream bridge not found (OK on "
                              L"q35 stand)\n");
                    }
                    uefi_call_wrapper(BS->Stall, 1, 3000000);
                    /* ===== v2.99l: retrain-check БЕЗ FLR =====
                     * FLR стирал внутренний скоростной конфиг (MAX_RATE/
                     * TLS) сразу после записи — хостовый setpci-ретрейн
                     * опаздывал, линк возвращался на Gen1. Теперь конфиг
                     * живёт; фактический ретрейн делает хост через бридж
                     * (host-retrain-trigger.sh) или phase3 на реальном HW. */
                    {
                        UINTN k;
                        UINT32 spd = 0;
                        for (k = 0; k < 20; k++) {
                            uefi_call_wrapper(BS->Stall, 1, 100000);
                            spd = (mmio_read32(0x00088088U) >> 16) & 0xF;
                            Print(L"gen2: retrain-check %d00ms speed=%d\n",
                                  (INTN)k + 1, (INTN)spd);
                            if (spd >= 2) break;   /* Gen2 ИЛИ Gen3 */
                        }
                        Print(L"gen2: %s\n",
                              spd == 3 ? L"*** GEN3! 8 GT/s PODTVERZHDEN ***"
                              : spd == 2 ? L"*** GEN2 PODTVERZHDEN (speed=2) ***"
                                       : L"link speed unchanged in-guest "
                                         L"(host will retrain)");
                    }
                    /* итоговое состояние LNKSTA обеих сторон:
                     * dword@cap+0x10 = LNKCTL | LNKSTA<<16,
                     * speed = LNKSTA[3:0], width = LNKSTA[9:4] */
                    if (find_bridge_to(gBus, &bb, &bd, &bf)) {
                        UINTN bc = find_pcie_cap(bb, bd, bf);
                        if (bc) {
                            UINT32 ls = pci_cfg_rd_idx(gBrIdx, bb, bd, bf,
                                                       bc + 0x10);
                            Print(L"gen2: бридж LNKSTA speed=%d width=%d\n",
                                  (INTN)((ls >> 16) & 0xF),
                                  (INTN)((ls >> 20) & 0xF));
                        }
                    }
                    if (gc) {
                        UINT32 ls = pci_cfg_rd_bdf(gBus, gDev, gFn, gc + 0x10);
                        Print(L"gen2: GPU   LNKSTA speed=%d width=%d\n",
                              (INTN)((ls >> 16) & 0xF),
                              (INTN)((ls >> 20) & 0xF));
                    }
                }
#endif /* !FULL_NOGEN2 */
#ifndef FULL_NOGEN2
                /* v2.99l: счётчик НЕ чистим (dev) — каждый следующий бут
                 * снова идёт по fire+quick пути без прогона A. Для релиза
                 * очистку вернуть. */
#ifdef RELEASE_BUILD
                uefi_call_wrapper(RT->SetVariable, 6, L"CMP90G2", &mcGuid,
                                  0, 0, NULL);
#endif
                Print(L"gen2: Gen2-конфиг применён\n");
                /* v2.99n: НИКАКОГО SFS/chainload из EFI — OpenVolume виснет
                 * на этой прошивке (стенд + реальный HW), а preload пуст
                 * (bootmgfw живёт на системном ESP, не на USB).
                 * Вместо этого: BootNext -> Windows + возврат в прошивку.
                 * BDS грузит Windows БЕЗ POST: анлок, маски и Gen2-конфиг
                 * сохраняются; драйвер при инициализации сам тренирует
                 * линк до 5GT/s (наш LINK_CAP уже анонсирует Gen2,
                 * TLS бриджа по умолчанию = max). */
                uefi_call_wrapper(BS->Stall, 1, 2000000);
                /* v2.99o: BootNext-запись убрана — NVRAM-операции
                 * (GetVariable/SetVariable) в этом месте вешают систему
                 * при нашем состоянии GPU (caps lock мёртв у юзера).
                 * Возврат в прошивку: BDS продолжит BootOrder и загрузит
                 * Windows БЕЗ POST — анлок, маски и Gen2-конфиг живы;
                 * драйвер при инициализации тренирует линк до 5GT/s. */
                Print(L"gen2: возврат в прошивку — Windows по BootOrder "
                      L"без POST (анлок и Gen2 сохранятся)\n");
#else
                /* ===== v3.03 FIX Code 43 (DIAG-2026-08-25) =====
                 * Хвостовой cleanup КАК В ОБЫЧНОМ ПУТИ v3.01 (проверен на
                 * этой машине): fire-путь оставлял GSP с защёлкнутым WPR2
                 * последнего мини-цикла и ЖИВЫМ SEC2-ROP-спиннером — GSP-RM
                 * виндового драйвера падал при старте (frts_err=0xbe класс,
                 * bugcheck 0x1B0/C000009A). Сначала глушим спиннер, затем
                 * финальный FLR — единственный сброс защёлкнутого WPR2.
                 * Маски/селекторы FLR переживают (доказано). После FLR MMIO
                 * не трогаем — функция мертва до конца загрузки ОС. */
                Print(L"gen2: cleanup — глушу SEC2-спиннер...\n");
                mmio_write32(SEC2_ENGINE, 0x1);
                { INTN k; for (k = 0; k < 16; k++) mmio_read32(SEC2_ENGINE); }
                mmio_write32(SEC2_ENGINE, 0x0);
                { INTN k; for (k = 0; k < 16; k++) mmio_read32(SEC2_ENGINE); }
                uefi_call_wrapper(BS->Stall, 1, 200000);
                Print(L"gen2: финальный FLR (сброс защёлкнутого WPR2)...\n");
                do_flr();
                uefi_call_wrapper(BS->Stall, 1, 300000);
                Print(L"v3.03: возврат в прошивку — Windows по BootOrder "
                      L"без POST (маски/GFX/SS сохранятся)\n");
#endif
#ifdef MULTI_CARD
                /* v3.04: fire-путь теперь сдвигает multi-card индекс так же,
                 * как обычный путь. В v3.03 advance был только в обычном
                 * пути — после fire-карты idx застревал: остальные карты не
                 * обрабатывались, а после следующего POST карта 0 уже не
                 * анлокалась. NVRAM-записи в том же состоянии (после
                 * финального FLR), что и в обычном пути. */
                if (g_mcAdvance) {
                    Print(L"multi-card: карта %d разлочена (fire) -> BootNext "
                          L"на себя (без ребута)\n", (INTN)g_mcIndex + 1);
                    /* v3n: тот же запрет — см. SINGLE_CARD_ONLY */
                    ulogf(L"MC     fire path: BootNext=self SKIPPED "
                          L"(SINGLE_CARD_ONLY=%d)\n", (INTN)SINGLE_CARD_ONLY);
#if !SINGLE_CARD_ONLY
                    mc_var_set(L"CMP90IDX", (UINT32)(g_mcIndex + 1));
                    mc_set_bootnext_self(ImageHandle);
#endif
                    goto done;   /* возврат в прошивку: BootOrder -> Windows */
                }
                mc_vars_clear();   /* последняя карта — BootOrder (Windows) */
#endif
                ulogf(L"STG   gen2 block done, goto done\n");
                goto done;
        } else if (!have2 && (Status == EFI_SUCCESS || directOk || earlyOk)) {
            mc_var_set(L"CMP90G2", 0);   /* первый успешный анлок — старт циклов */
            Print(L"gen2: счётчик инициализирован (следующий бут = цикл 1)\n");
            ulogf(L"STG   gen2 counter initialised, falling through\n");
        } else {
            /* v3n: этот случай в прогонах sec1/okchk как раз и молчал -
             * fire=1 и have2=1, enable=0 -> ни первая ветка, ни вторая.
             * Теперь это видно в логе явно. */
            ulogf(L"STG   gen2: no branch taken (have2=%d success=%d "
                  L"direct=%d early=%d) - falling through\n",
                  (INTN)have2, (INTN)Status, (INTN)directOk, (INTN)earlyOk);
        }
    }
#endif

#ifdef RENDER_MASKS
    /* Маски-предусловия GFX_SPEED_SELECT. Ставим ДО блока селекторов:
     * референс делает именно так (маски -> GFX_SEL -> SS0/SS1), и GFX_SEL
     * липнет только при открытых масках. Не трогаем g_gen2Fire, поэтому
     * селекторы продолжат выполняться, и не трогаем обычный хвост с
     * фиксом Code 43. Гоняем только если анлок сам прошёл. */
    if (Status == EFI_SUCCESS || directOk || earlyOk) {
        /* v3.21: замыкание замера разрыва. 3031 мс из прогона v321 приходятся
         * на участок между этой точкой и 'early path finished'; если метка
         * покажет ~3031 мс, виновник найден, если сильно меньше - время
         * в render_open_gfx_masks, и там уже стоит 'render: preamble'. */
        fx_mk_acc(fx_gapT0, L"pro: early-path to render entry");
        render_open_gfx_masks(L"render-masks",
                              wprMetaPhys, ucodePhys, fwsecPhys, v67Phys);
#ifdef FUSE_TABLE_PROBE
        /* A1 + A3, docs/POWER-SEARCH-LIST.md. Стоит РЯДОМ с циклом масок и
         * до блока селекторов по одной причине: ботер стреляет только пока
         * SS0/SS1 нулевые (канарейка V67, строка G2RCC выше). После блока
         * селекторов предусловие уже нарушено, и все циклы ботера в этом
         * месте были бы холостыми. */
        fuse_table_probe(L"ftp", wprMetaPhys, ucodePhys, fwsecPhys, v67Phys);
#endif
#ifdef XP3G_GATE_V67
        /* ЭКСПЕРИМЕНТ E-A. Место то же, что у FUSE_TABLE_PROBE и по той же
         * причине: ботер стреляет только пока SS0/SS1 нулевые, то есть до
         * блока селекторов. Блок не трогает линк и не пишет ни одного
         * функционального бита — только снятие защиты с записи. */
        xg_probe(L"xg", wprMetaPhys, ucodePhys, fwsecPhys, v67Phys);
#endif
#if defined(XP3G_XVE_BOOTER) && defined(XP3G_GATE_V67)
        /* ЭКСПЕРИМЕНТ E-G. МЕЖДУ E-A и E-B — порядок обязателен, а не
         * косметика. xg_v67_write() делает FLR внутри себя. E-B ниже пишет
         * policy обычными регистрами (не масками), и если бы E-G шёл после
         * E-B, результат E-B зависел бы от того, пережил ли policy этот FLR.
         * Здесь политика заливается последней, уже после всех FLR.
         *
         * Само место то же, что у E-A: до блока селекторов, пока SS0/SS1
         * нулевые — ботер больше нигде не стреляет. Линк не трогает. */
        xg_xve_probe(L"xgm", wprMetaPhys, ucodePhys, fwsecPhys, v67Phys);
#endif
#ifdef XP3G_GATE_POLICY
        /* ЭКСПЕРИМЕНТ E-B. Идёт сразу за E-A и тем же местом — до блока
         * селекторов, пока SS0/SS1 нулевые. Ни кика, ни TLS, ни ретрейна. */
        xg_policy_probe(L"xpol");
#endif
#ifdef XP3G_LINK_RETRAIN
        /* ЭКСПЕРИМЕНТ E-C. Впервые трогает ЖИВОЙ ЛИНОК: кик LTSSM, TLS на
         * обоих концах через PCI config и ретрейн. Одна попытка, без
         * повторов; при отказе печатается RETRAIN-FAIL и всё. */
        xg_link_probe(L"xck");
#endif
#ifdef XP3G_CAP_DIAG
        /* ЭКСПЕРИМЕНТ E-D. ТОЛЬКО ЧТЕНИЕ PCI config: обход capability chain на
         * GPU и мосте, четырьмя способами каждый. Ни одной записи, линок не
         * трогаем. Разбирает причину NO-PCIE-CAP, из-за которой E-C вышел по
         * страховке. */
        xg_cap_diag(L"xcap");
#endif
#ifdef XP3G_TLS_BAR0
        /* ЭКСПЕРИМЕНТ E-E. Только запись TLS-полей через BAR0-зеркало при
         * ОТКРЫТОМ гейте, с readback. Ни кика, ни ретрейна, ни записей в
         * LINK_CAP: скорость линка этим блоком не меняется. Требует E-B. */
        xg_tls_bar0(L"xtl");
#endif
#ifdef PJTAG_SCAN
        /* ЭКСПЕРИМЕНТ E-F. ТОЛЬКО ЧТЕНИЕ: поиск класса запертых гейтов
         * 0xFFFFFFxx по BAR0, вокруг адреса PJTAG из чужого проекта и по
         * priv-окнам. Ни одной записи. Снимает потолок доступа после того, как
         * Gen2 упёрся в "регистр недоступен". */
        xg_pjtag_scan(L"xpjt");
#endif
#ifdef FCFF_SCAN
        /* ЭКСПЕРИМЕНТ E-G. ТОЛЬКО ЧТЕНИЕ: что защищают четыре регистра
         * 0xFFFFFFFC, впервые увиденные в E-F. Блок OPTB известен тем, что
         * записи в него валят гостя в ресет - поэтому сначала чтение. */
        xg_fcff_scan(L"xfcc");
#endif
    } else {
        ulogf(L"G2RMS  render masks SKIPPED: unlock did not pass "
              L"(success=%d direct=%d early=%d)\n",
              (INTN)Status, (INTN)directOk, (INTN)earlyOk);
    }
#endif

#ifdef PCIE_GEN2_REJOIN
    if ((Status == EFI_SUCCESS || directOk || earlyOk) && !g_gen2Fire) {
#else
    if (Status == EFI_SUCCESS || directOk || earlyOk) {
#endif
        /* --- Селекторы --- */
        /* v3.41, этап 24: ВТОРАЯ ДЫРА, 1 091 мс. Между 'render masks: sweep
         * finished' и 'final: before return to firmware' не было ни одной
         * метки. Подозреваемые здесь по размеру: блок дампов FUSE/GEN2M/
         * GEN2R/CHIP (~116 MMIO-чтений, то есть единицы мс) и - главное -
         * log_flush_sector(TRUE) в хвосте, принудительный сброс буфера на
         * флешку. Отметка входит в блок, дальше см. хвост перед 'final:'. */
        log_ms(L"post: selector block entered");
        ulogf(L"STG   reached selector block success=%d direct=%d early=%d "
              L"gen2Fire=%d\n",
              (INTN)Status, (INTN)directOk, (INTN)earlyOk,
              GEN2_FIRE_STATE());
#ifdef FUSE_ORACLE
        /* Снимок ДО записи селекторов. Сама запись не добавляется: SS0/SS1 и
         * GFX_SPEED_SELECT и так пишутся штатным путём, мы только запоминаем
         * состояние страницы и потом сравниваем. */
        ftp_snap_take(L"pre-sel");
#endif

        /* v3n: СНИМОК БЛОКА FUSE ДО записи селекторов.
         *
         * Урок из §3j: is_unlocked() — тавтология, она перечитывает то, что
         * только что записала. Здесь измеряем НЕ ЭХО, а ЭФФЕКТ: в этом же
         * диапазоне 0x008238xx лежит документированный регистр
         *     NV_FUSE_FEATURE_READOUT = 0x00823814   (R--4R, только чтение)
         * Если запись селекторов включает признаки, то FeatureReadout
         * обязан измениться. Если он не изменился — значения не те.
         *
         * Снимаем окно 0x00823800..0x0082382F до и после и печатаем diff.
         * Безопасность: только чтение, ничего не пишем. */
        /* Широкое окно блока fuse. Задача — НЕ угадывать значения, а
         * собрать структуру: 0x008238xx в драйвере не описан почти никак
         * (только 0x823814 = FEATURE_READOUT, и то лишь с полем
         * ECC_DRAM бит 16). Поэтому печатаем всё окно до и после записи
         * и diff — по нему видно и раскладку, и побочные эффекты.
         * Только чтение. */
#define FUSE_WIN_LO   0x00823780UL
#define FUSE_WIN_N    48
        static UINT32 freg[FUSE_WIN_N];
        UINT32 fbefore[FUSE_WIN_N], fafter[FUSE_WIN_N];
        UINTN k, fchanged = 0;
        for (k = 0; k < FUSE_WIN_N; k++) freg[k] = FUSE_WIN_LO + k * 4;

        for (k = 0; k < FUSE_WIN_N; k++) fbefore[k] = mmio_read32(freg[k]);
        for (k = 0; k < FUSE_WIN_N; k++)
            ulogf(L"FUSE   before 0x%08x = 0x%08x%s\n", freg[k], fbefore[k],
                  (freg[k] == 0x00823814UL)
                      ? L"  <- NV_FUSE_FEATURE_READOUT (only ECC_DRAM doc'd)"
                  : (freg[k] == 0x0082381CUL) ? L"  <- SS0 (we write here)"
                  : (freg[k] == 0x00823820UL) ? L"  <- SS1 (we write here)"
                                               : L"");

        /* v3n: PLM тоже открываем здесь. Раньше он считался уже открытым
         * (BOOTER давал PLM-OPEN), но после secure-загрузки FWSEC
         * привилегии могли смениться, и запись в селекторы без открытого
         * PLM молча не липнет. Поэтому читаем-пишем с проверкой. */
        {
            UINT32 plmNow = mmio_read32(REG_FEAT_OVR_PLM);
            if (plmNow != VAL_PLM_OPEN) {
                mmio_write32(REG_FEAT_OVR_PLM, VAL_PLM_OPEN);
                uefi_call_wrapper(BS->Stall, 1, 50000);
            }
            ulogf(L"STG   PLM 0x%08x -> 0x%08x readback 0x%08x %s\n",
                  plmNow, (UINT32) VAL_PLM_OPEN, mmio_read32(REG_FEAT_OVR_PLM),
                  (mmio_read32(REG_FEAT_OVR_PLM) == VAL_PLM_OPEN)
                      ? L"OPEN" : L"*** DID NOT STICK ***");
        }
        /* v3n: СЛЕЖКА ЗА ПОБОЧНЫМИ РЕГИСТРАМИ (2026-09-29).
         *
         * Наблюдение: WPR2_LO меняется между OKCHK и PREFLR, но код эти
         * два момента разделяет большим куском работы, поэтому виноват
         * не назван:
         *     OKCHK  wpr2Lo=0x01F7E000   OK
         *     PREFLR WPR2=0x01EAD000/0x01F7EE00
         * Заодно поехал GFW: 0xBADF5040 -> 0xBADF1100.
         *
         * Что делает этот блок: читает «неинтересные» регистры ДО и ПОСЛЕ
         * двух записей селекторов, вплотную. Тогда следующий прогон
         * отвечает на вопрос не «где-то в этом окне испортилось», а
         * «эти ли две записи это сделали».
         *
         * Это измерение, а не исправление: ничего не пишет, только читает.
         * Побочный эффект заведомо есть — запись в 0x0082381C/0x00823820
         * обнуляет соседний 0x00823818 (это видно в FUSE-diff). Вопрос
         * в том, дотянется ли он до WPR2 по адресу 0x001FA824, который
         * в другое подпространство. */
        ulogf(L"WATCH  before WPR2=0x%08x/0x%08x GFW=0x%08x dbg=0x%08x "
              L"cpuctl=0x%08x scratch0e=0x%08x privMask=0x%08x/0x%08x "
              L"fuse18=0x%08x fuse0C=0x%08x\n",
              mmio_read32(REG_PFB_MMU_WPR2_LO), mmio_read32(REG_PFB_MMU_WPR2_HI),
              mmio_read32(REG_GFW_BOOT_OK), mmio_read32(GSP_BASE + 0x94),
              mmio_read32(GSP_CPUCTL),
              mmio_read32(NV_PBUS_VBIOS_SCRATCH + FWSECLIC_SCRATCH_FRTSE * 4),
              mmio_read32(REG_PFB_MMU_WPR2_PLM), mmio_read32(REG_PFB_MMU_WPR2_PLM + 4),
              mmio_read32(0x00823818UL), mmio_read32(0x0082380CUL));

        mmio_write32(REG_FEAT_OVR_SM_SPD_1, VAL_SS1_UNLOCKED);
        mmio_write32(REG_FEAT_OVR_SM_SPD, VAL_SS0_UNLOCKED);
        uefi_call_wrapper(BS->Stall, 1, 100000);

        /* та же слежка сразу после — единственное место, где видно,
         * что именно эти две записи сделали с WPR2/GFW */
        ulogf(L"WATCH  after  WPR2=0x%08x/0x%08x GFW=0x%08x dbg=0x%08x "
              L"cpuctl=0x%08x scratch0e=0x%08x privMask=0x%08x/0x%08x "
              L"fuse18=0x%08x fuse0C=0x%08x\n",
              mmio_read32(REG_PFB_MMU_WPR2_LO), mmio_read32(REG_PFB_MMU_WPR2_HI),
              mmio_read32(REG_GFW_BOOT_OK), mmio_read32(GSP_BASE + 0x94),
              mmio_read32(GSP_CPUCTL),
              mmio_read32(NV_PBUS_VBIOS_SCRATCH + FWSECLIC_SCRATCH_FRTSE * 4),
              mmio_read32(REG_PFB_MMU_WPR2_PLM), mmio_read32(REG_PFB_MMU_WPR2_PLM + 4),
              mmio_read32(0x00823818UL), mmio_read32(0x0082380CUL));

        /* ---------------------------------------------------------------
         * v3n: ЭКСПЕРИМЕНТ — SM_ISSUE_RATE_MOD (2026-09-29)
         *
         * Основание. Замер вычислительной производительности показал, что
         * анлок по SS0/SS1 НЕ действует: 233.89 t/s = заблокированная база
         * (~230), при том что в Windows наши значения селекторов стоят
         * (чтение RWEverything, расхождений ноль). Значит ограничитель
         * вычислительной скорости на 70HX — не только (или не) эти поля.
         *
         * Внешний ориентир, которого раньше не было. Отчёт bendy2 по
         * анализу BAR0 пяти карт (90HX против RTX 3090/3080Ti) содержит
         * прямую строку про ВЫЧИСЛИТЕЛЬНЫЙ домен:
         *
         *     SM_ISSUE_RATE_MOD @0x504204:  90HX=0x7  3090=0x5
         *     «SM-планировщик, троттлинг, вычислительный домен, НЕ графика»
         *
         * То есть у заблокированной карты 0x7, у полностью разлоченной
         * потребительской карты 0x5. В отличие от fuse-OTP это обычный
         * MMIO-регистр домена SM.
         *
         * ОСТОРОЖНО, ЧЕСТНО О ГРАНИЦАХ ВЫВОДА:
         *   - сравнение 90HX/3090 выполнено на GA102, у нас GA104. Диэны
         *     разные, перенос 0x5 на 70HX — гипотеза, а не факт;
         *   - назначение битов 0x504204 нигде не документировано, кроме этой
         *     строки отчёта;
         *   - поэтому пишем ровно наблюдавшееся у рабочей карты значение и
         *     НЕ трогаем соседние регистры.
         *
         * Критерий успеха — ВНЕ этого кода: llama-bench. 233 t/s значит
         * «не сработало», тысячи — «сработало». Показаний в самом логе для
         * этого недостаточно (см. FINAL-SUMMARY §4).
         * --------------------------------------------------------------- */
        ulogf(L"IRM    before 0x504200=0x%08x 0x504204=0x%08x "
              L"0x504208=0x%08x 0x50420C=0x%08x\n",
              mmio_read32(0x00504200UL), mmio_read32(0x00504204UL),
              mmio_read32(0x00504208UL), mmio_read32(0x0050420CUL));
        if (PROBE_ISSUE_RATE_MOD) {
            mmio_write32(REG_SM_ISSUE_RATE_MOD, ISSUE_RATE_MOD_UNLOCKED);
            uefi_call_wrapper(BS->Stall, 1, 100000);
            ulogf(L"IRM    write 0x%08x = 0x%08x -> readback 0x%08x %s\n",
                  REG_SM_ISSUE_RATE_MOD, ISSUE_RATE_MOD_UNLOCKED,
                  mmio_read32(REG_SM_ISSUE_RATE_MOD),
                  (mmio_read32(REG_SM_ISSUE_RATE_MOD) == ISSUE_RATE_MOD_UNLOCKED)
                      ? L"STUCK" : L"NOT STUCK (RO or another context)");
        }
        ulogf(L"IRM    after  0x504200=0x%08x 0x504204=0x%08x "
              L"0x504208=0x%08x 0x50420C=0x%08x\n",
              mmio_read32(0x00504200UL), mmio_read32(0x00504204UL),
              mmio_read32(0x00504208UL), mmio_read32(0x0050420CUL));

        {
            UINT32 ss0 = mmio_read32(REG_FEAT_OVR_SM_SPD);
            UINT32 ss1 = mmio_read32(REG_FEAT_OVR_SM_SPD_1);
            ulogf(L"STG   selectors: want SS0=0x%08x SS1=0x%08x | got "
                  L"SS0=0x%08x SS1=0x%08x %s\n",
                  (UINT32) VAL_SS0_UNLOCKED, (UINT32) VAL_SS1_UNLOCKED,
                  ss0, ss1,
                  (ss0 == VAL_SS0_UNLOCKED && ss1 == VAL_SS1_UNLOCKED)
                      ? L"written OK" : L"*** DID NOT STICK ***");
            ulogf(L"STG   is_selectors_written()=%d  (THIS IS A TAUTOLOGY: "
                  L"it re-reads what was just written; does not prove unlock)\n",
                  (INTN) is_unlocked());

            /* Тот же блок fuse ПОСЛЕ записи — ищем реальный эффект. */
            for (k = 0; k < FUSE_WIN_N; k++) fafter[k] = mmio_read32(freg[k]);
            for (k = 0; k < FUSE_WIN_N; k++) {
                if (fafter[k] == fbefore[k]) continue;
                fchanged++;
                ulogf(L"FUSE   CHANGED 0x%08x: 0x%08x -> 0x%08x "
                      L"(xor 0x%08x)%s\n",
                      freg[k], fbefore[k], fafter[k],
                      fbefore[k] ^ fafter[k],
                      (freg[k] == 0x00823814UL)
                          ? L"  <- FEATURE_READOUT MOVED"
                      : ((freg[k] != 0x0082381CUL && freg[k] != 0x00823820UL)
                             ? L"  <- UNREQUESTED SIDE EFFECT" : L""));
            }
            ulogf(L"FUSE   %d of %d changed; FEATURE_READOUT=0x%08x->0x%08x %s\n",
                  (INTN) fchanged, (INTN) FUSE_WIN_N,
                  fbefore[(0x00823814UL - FUSE_WIN_LO) / 4],
                  fafter[(0x00823814UL - FUSE_WIN_LO) / 4],
                  (fbefore[(0x00823814UL - FUSE_WIN_LO) / 4] ==
                   fafter[(0x00823814UL - FUSE_WIN_LO) / 4])
                      ? L"UNCHANGED (but the field is documented only as "
                        L"ECC_DRAM bit 16 - that is NOT a sign of unlock)"
                      : L"moved");

        /* --- ГИПОТЕЗА B: пробуем 0x0082380C как настоящий селектор ------- */
#if PROBE_FUSE_NEIGHBOUR
        {
            UINT32 was  = mmio_read32(REG_FUSE_SEL_CAND);
            UINT32 was2 = mmio_read32(REG_FUSE_ROUTINE);
            ulogf(L"PROBE  0x%08x = 0x%08x (selector candidate), "
                  L"0x%08x = 0x%08x\n",
                  REG_FUSE_SEL_CAND, was, REG_FUSE_ROUTINE, was2);
            ulogf(L"PROBE  %s -> writing 0x88888888 (fill in high byte)\n",
                  (was == 0x88888888UL) ? L"already 0x88888888, nothing to write"
                                         : L"WRITING");
            if (was != 0x88888888UL) {
                mmio_write32(REG_FUSE_SEL_CAND, 0x88888888UL);
                uefi_call_wrapper(BS->Stall, 1, 100000);
            }
            ulogf(L"PROBE  readback 0x%08x = 0x%08x %s | 0x%08x = 0x%08x%s\n",
                  REG_FUSE_SEL_CAND, mmio_read32(REG_FUSE_SEL_CAND),
                  (mmio_read32(REG_FUSE_SEL_CAND) == 0x88888888UL)
                      ? L"STUCK" : L"NOT STUCK (probably just reporting)",
                  REG_FUSE_ROUTINE, mmio_read32(REG_FUSE_ROUTINE),
                  (mmio_read32(REG_FUSE_ROUTINE) == was2)
                      ? L" (unchanged)" : L" *** CHANGED ***");
        }
#endif
        }
        /* v3.43, этап 24: 588 мс этого блока НЕ РАЗЛОЖЕНЫ. Две паузы доказаны:
         * 100 мс после записи SS0/SS1 и 100 мс после пробной записи в
         * 0x0082380C. Остальные три не срабатывают (PLM уже открыт,
         * PROBE_ISSUE_RATE_MOD=0, строки PLMZ в логе нет). Итого 200 мс из
         * 588, остальные ~389 мс unexplained. Три марки ниже режут блок. */
        log_ms(L"sel: FUSE+selectors+PROBE done");
        dump_regs(L"[unlock]");
        snapshot_state();   /* до FLR — потом MMIO уже мёртв */
        /* v3n: вторая половина A/B по Gen2. Ставим ЗДЕСЬ — после селекторов,
         * но до глушения SEC2 и до FLR, потому что после FLR функция мертва
         * и MMIO не читается (см. комментарий выше про «v2.88: БЕЗ FLR»).
         * Только чтение: ни одной записи, ни в GPU, ни в конфиг PCIe. */
        gen2_readonly_dump(L"after-unlock");
#if CHIP_SIZE_SCAN
        /* v3.15: ищем, где хранится размер кристалла. Только чтение. */
        chip_size_scan(L"after-unlock");
#endif
#if SM_ACF
        /* Определяем геометрию per-SM массива из содержимого BAR0:
         * ни адрес, ни шаг не заданы заранее. Две предыдущие попытки
         * предполагали геометрию (шаг 0x80 из документации 50HX для
         * TU102) и обе выдали артефакты, см. описание блока. Ставится
         * рядом с chip_size_scan, то есть до всех записей селектора. */
        sm_autocorr(L"after-unlock");
#endif
#ifdef GEN2_LINK_TRY
/* v3.43, этап 24: граница перед собственно записью GFX_SPEED_SELECT. */
        log_ms(L"sel: dump_regs+snapshot+gen2+chip done");
        /* v3.07 ШАГ 1: GFX_SPEED_SELECT = 4, рендер-селектор. Ставим ЗДЕСЬ —
         * после снимка состояния и блока селекторов, до do_flr() ниже: после
         * FLR функция мертва и readback невозможен. Линком не управляем, маски
         * не трогаем, NVRAM не пишем. */
#if PROBE_PRIV_LEVEL_MASK
        /* v3.15: обнуляем privLevelMask. Наш комментарий в okchk_check()
         * утверждает, что без нуля WPR2 может быть прикрыт и «успех» ложен.
         * Стоим здесь: разблокировка уже отработала и проверена, до
         * GFX_SPEED_SELECT ещё не дошли. */
        {
            UINT32 p0 = mmio_read32(REG_PFB_MMU_WPR2_PLM);
            UINT32 p1 = mmio_read32(REG_PFB_MMU_WPR2_PLM + 4);
            UINT32 l0, l1;
            mmio_write32(REG_PFB_MMU_WPR2_PLM, 0);
            mmio_write32(REG_PFB_MMU_WPR2_PLM + 4, 0);
            uefi_call_wrapper(BS->Stall, 1, 100000);
            ulogf(L"PLMZ  before 0x%08x/0x%08x -> write 0 -> after 0x%08x/0x%08x %s\n",
                  p0, p1,
                  mmio_read32(REG_PFB_MMU_WPR2_PLM),
                  mmio_read32(REG_PFB_MMU_WPR2_PLM + 4),
                  ((mmio_read32(REG_PFB_MMU_WPR2_PLM) == 0) &&
                   (mmio_read32(REG_PFB_MMU_WPR2_PLM + 4) == 0))
                      ? L"STUCK" : L"NOT STUCK (RO)");
            l0 = mmio_read32(REG_PFB_MMU_WPR2_LO);
            l1 = mmio_read32(REG_PFB_MMU_WPR2_HI);
            ulogf(L"PLMZ  wpr2Lo=0x%08x (want 0x%08x) %s | wpr2Hi=0x%08x %s\n",
                  l0, TARGET_WPR2_LO, (l0 == TARGET_WPR2_LO) ? L"OK" : L"CHANGED",
                  l1, (l1 == TARGET_WPR2_HI) ? L"OK" : L"CHANGED");
            ulogf(L"PLMZ  SS0=0x%08x SS1=0x%08x (must not drop: 0x%08x/0x%08x)\n",
                  mmio_read32(REG_FEAT_OVR_SM_SPD),
                  mmio_read32(REG_FEAT_OVR_SM_SPD_1),
                  VAL_SS0_UNLOCKED, VAL_SS1_UNLOCKED);
        }
#endif
        gen2_gfx_try(L"step1-GFX_SEL");
#ifdef FUSE_ORACLE
        /* Тот же снимок ПОСЛЕ записи селектора. Сравнение даёт ответ на
         * вопрос A2 без единой новой записи: если 0x823834 повторит
         * значение селектора, то это его отчётчик, и мы получаем oracle
         * для проверки любой записи без запуска игры. */
        ftp_snap_diff(L"post-sel");
#endif
        /* v3.43, этап 24: замыкает разрез блока селекторов. */
        log_ms(L"sel: GFX_SPEED_SELECT write done");
#endif

        /* v2.88: БЕЗ FLR! На реальном железе (X570 F37d) FLR обнуляет BARs/
         * command → функция «умирает» → виснет обход устройств/консоль.
         * Вместо него, пока PLM открыт:
         *   1) глушим SEC2 (ROP-спиннер продолжает писать PLM);
         *   2) WPR2 → POST-дефолт 0x1FFFFE00/0 (драйверу нужен чистый WPR2,
         *      иначе его FWSEC/FRTS падает frts_err=0xbe — проверено);
         * Селекторы в fuse-shadow — переживают всё это без FLR. */
        Print(L"cleanup: глушу SEC2-спиннер...\n");
        mmio_write32(SEC2_ENGINE, 0x1);
        { UINTN k; for (k = 0; k < 16; k++) mmio_read32(SEC2_ENGINE); }
        mmio_write32(SEC2_ENGINE, 0x0);
        { UINTN k; for (k = 0; k < 16; k++) mmio_read32(SEC2_ENGINE); }
        uefi_call_wrapper(BS->Stall, 1, 200000);   /* скраб после ресета */
        dump_regs(L"[cleanup]");

#ifdef PCIE_GEN_EXPERIMENT
        /* v2.97: PCIe gen unlock — строго ДО FLR (BAR живой, PLM открыт);
         * передаём контекст ботера для booter-опосредованной записи */
        pcie_gen_unlock_debug(wprMetaPhys, ucodePhys, v67Phys);
#endif

#ifdef ENDGAME_WARMRESET
        /* ПЛАН B: BootNext → тёплый ресет. Если POST сохраняет fuse-shadow
         * селекторы — Windows поднимется разлоченной, весь chainload не нужен. */
        if (set_bootnext_windows()) {
            Print(L"v2.90-WR: тёплый ресет через 3с (BootNext→Windows)...\n");
            uefi_call_wrapper(BS->Stall, 1, 3000000);
            uefi_call_wrapper(RT->ResetSystem, 4, EfiResetWarm, EFI_SUCCESS, 0, NULL);
        }
        Print(L"v2.90-WR: BootNext не удался — fallback на chainload\n");
#endif

        /* v2.90: FLR ВОЗВРАЩАЕТСЯ — он единственный способ сбросить
         * защёлкнутый WPR2 (записи не липнут даже при открытом PLM, проверено
         * на реальном железе), а драйверу нужен чистый WPR2 иначе FWSEC/FRTS
         * падает frts_err=0xbe. Селекторы переживают FLR (доказано 2 раза).
         * СРАЗУ после FLR — StartImage из ОЗУ, БЕЗ печатей и чтений MMIO
         * (функция «мертва» до конца загрузки; консоль на второй ГПУ). */
        /* v3n: ПОЛНЫЙ СНИМОК ДО FLR. После FLR функция «мертва», и все
         * показания после него недоступны. Значит всё, что хотим узнать,
         * снимаем здесь — тогда результат эксперимента не зависит от того,
         * доживёт ли приложение до маркера END. */
        ulogf(L"PREFLR PLM=0x%08x SS0=0x%08x SS1=0x%08x WPR2=0x%08x/0x%08x "
              L"GFW=0x%08x dbg=0x%08x cpuctl=0x%08x scratch0e=0x%08x\n",
              mmio_read32(REG_FEAT_OVR_PLM),
              mmio_read32(REG_FEAT_OVR_SM_SPD),
              mmio_read32(REG_FEAT_OVR_SM_SPD_1),
              mmio_read32(REG_PFB_MMU_WPR2_LO),
              mmio_read32(REG_PFB_MMU_WPR2_HI),
              mmio_read32(0x0000B100U),
              mmio_read32(GSP_BASE + 0x94), mmio_read32(GSP_CPUCTL),
              mmio_read32(NV_PBUS_VBIOS_SCRATCH + FWSECLIC_SCRATCH_FRTSE * 4));
        ulogf(L"PREFLR want SS0=0x%08x SS1=0x%08x -> %s\n",
              (UINT32) VAL_SS0_UNLOCKED, (UINT32) VAL_SS1_UNLOCKED,
              (mmio_read32(REG_FEAT_OVR_SM_SPD) == VAL_SS0_UNLOCKED &&
               mmio_read32(REG_FEAT_OVR_SM_SPD_1) == VAL_SS1_UNLOCKED)
                  ? L"written OK" : L"MISMATCH");
        /* v3.41, этап 24: разрезаем хвост прогона. До этих меток участок от
         * 'render masks: sweep finished' до 'final: before return to firmware'
         * стоил 1 091 мс и не был атрибутирован ничем. */
        log_ms(L"post: PREFLR snapshot done, before FLR");

#if SKIP_FLR
        /* Эксперимент: FLR пропускаем, чтобы проверить, переживают ли
         * селекторы сброс. Всё, что было до сброса, уже записано в лог
         * строками выше. */
        ulogf(L"FLRX   *** SKIP_FLR=%d - do_flr() SKIPPED ***\n", (INTN) SKIP_FLR);
        uefi_call_wrapper(BS->Stall, 1, 500000);
#else
        Print(L"FLR (сброс защёлкнутого WPR2)...\n");
        do_flr();
        uefi_call_wrapper(BS->Stall, 1, 300000);   /* PCIe: 100мс + запас */
        g_postFlr = TRUE;
        /* После FLR MMIO не читаем принципиально — только запись в лог. */
        ulogf(L"FLRX   do_flr() done, no further MMIO reads\n");
        log_ms(L"post: FLR + 300ms settle done");
#endif

#ifdef MULTI_CARD
        if (g_mcAdvance) {
            Print(L"multi-card: карта %d разлочена -> BootNext на себя (без ребута)\n",
                  (INTN)g_mcIndex + 1);
            ulogf(L"MC     g_mcIndex=%d g_mcCount=%d g_mcAdvance=1 -> "
                  L"BootNext=self SKIPPED (SINGLE_CARD_ONLY=%d): reboot "
                  L"from USB = POST = fuse-shadow erase\n",
                  (INTN)g_mcIndex, (INTN)g_mcCount, (INTN)SINGLE_CARD_ONLY);
#if !SINGLE_CARD_ONLY
            mc_var_set(L"CMP90IDX", (UINT32)(g_mcIndex + 1));
            ulogf(L"MC     mc_set_bootnext_self() = %d (0 = BootNext write "
                  L"failed, so there will be no reboot)\n",
                  (INTN) mc_set_bootnext_self(ImageHandle));
#else
            mc_var_set(L"CMP90IDX", 0);   /* счётчик сбрасываем, чтобы не крутить */
#endif
            goto done;   /* возврат в прошивку: BootOrder -> Windows без POST */
        }
        mc_vars_clear();   /* последняя карта — дальше как обычно chainload */
#endif

        /* v2.99n: Chainload Windows из ОЗУ заменён на BootNext -> Windows:
         * SFS/StartImage ненадёжны на этой плате (No mapping, OpenVolume
         * висняк). Возврат в прошивку: BDS грузит Windows БЕЗ POST,
         * анлок и Gen2-конфиг сохраняются */
        /* v2.99n/o: SFS/StartImage/BootNext ненадёжны на этой плате
         * (No mapping, OpenVolume-висняк, NVRAM-висяк). Возврат в
         * прошивку: BDS грузит Windows по BootOrder БЕЗ POST */
        Print(L"v3.0: возврат в прошивку — Windows по BootOrder без POST\n");
        log_ms(L"final: return to firmware");
        goto done;
    }

chainload:
    /* v3n: метка. Существенно, что путь сюда ВОЗМОЖЕН даже при успешном
     * анлоке: условие селекторов содержит !g_gen2Fire, а при fire=1
     * (счётчик CMP90G2 в NVRAM) оно ложно. То есть в fire-режиме блок
     * записи SS0/SS1 не выполняется вовсе — и это не должно выглядеть
     * как «анлок сломался». Различить позволяет именно эта метка. */
    ulogf(L"STG   reached 'chainload' (selector block skipped if "
          L"g_gen2Fire=1)\n");
    dump_regs(L"[pre-Windows]");
    if (!g_snapOk) snapshot_state();   /* ветка неуспеха — MMIO ещё живы */
    ulogf(L"STG   is_unlocked()=%d (SS0=0x%08x SS1=0x%08x)\n",
          (INTN) is_unlocked(), mmio_read32(REG_FEAT_OVR_SM_SPD),
          mmio_read32(REG_FEAT_OVR_SM_SPD_1));
    /* v3.45: УДАЛЕНЫ ДВЕ СТРОКИ ВЕРДИКТА, БЫВШИЕ ЗДЕСЬ.
     *
     *     if (is_unlocked())
     *         Print(L"*** NVIDIA %s РАЗБЛОКИРОВАН ***\n", TARGET_NAME);
     *     else
     *         Print(L"*** ВНИМАНИЕ: GPU НЕ разблокирован ... ***\n", ...);
     *
     * Они стояли ДО метки done:, а все четыре пути релизной сборки делают
     * goto done и перепрыгивают их. То есть на экране не появлялось НИЧЕГО:
     * подтверждено логами, где есть 'STG reached ''done'' label' и нет
     * 'reached ''chainload'''. Мёртвый код в релизной сборке - хуже его
     * отсутствия, потому что создаёт видимость работающей проверки.
     *
     * Вторая причина удалить, а не починить: обе строки судили только по
     * SS0/SS1, то есть о графике не говорили ничего. Новый баннер стоит
     * ПОСЛЕ done:, печатается на всех путях и различает compute и render. */

done:
    /* v3n: метка входа в done — иначе 'лог оборвался' и 'приложение
     * не дописало' неразличимы: обе означают одно и то же (ничего не
     * записано), но причины разные. */
    ulogf(L"STG   reached 'done' label\n");
    /* v3n: после FLR функция «мертва» — MMIO читать нельзя. Именно этим,
     * по всей видимости, объясняется отсутствие маркера END в прогонах
     * sec1/okchk/stages: snapshot_state() в этой точке висела на мёртвом
     * устройстве. Теперь состояние просто переиспользуем. */
    if (!g_snapOk && !g_postFlr) snapshot_state();
    else if (g_postFlr)
        ulogf(L"STG   post-FLR: MMIO unavailable, summary takes a snapshot "
              L"from the moment up to FLR\n");
    {
        Print(L"\n================ ИТОГ ================\n");
        Print(L" profile      %s  10de:%04x  bus=%d dev=%d fn=%d\n",
              TARGET_NAME, (INTN)TARGET_PCI_DEV, (INTN)gBus, (INTN)gDev, (INTN)gFn);
        Print(L" PLM          0x%08x\n", g_snapPlm);
        /* v3.47: строка SS0/SS1 из этого блока УДАЛЕНА.
         *
         * Её печатал и дамп в кольцо (здесь), и баннер вердикта в файл
         * (строки VRC). Одно и то же число в двух местах - а при правке
         * одного из них они разойдутся, и человек увидит «разблокировано»
         * там, где графика не поднялась. Именно это уже случилось в
         * прогоне 1004-135604, где вердикт врал из-за устаревшего
         * значения; проверка 2b в verify-log.ps1 теперь это ловит.
         *
         * Оставляем там, где переживает: в логе. В кольцо эти строки всё
         * равно не попадают - fx_pr_dump не даёт ни байта с v3.17, а
         * RELEASE_BUILD на консоль кольцо не выгружает вовсе. */
        Print(L" WPR2         0x%08x/0x%08x  (ожидалось 0x%08x/0x%08x)\n",
              g_snapWLo, g_snapWHi, TARGET_WPR2_LO, TARGET_WPR2_HI);
        Print(L" dbg(0x94)    0x%08x   scratch0e 0x%08x   cpuctl 0x%08x\n",
              g_snapDbg, g_snapSc0, g_snapCpu);
        /* v3.45: строка ВЕРДИКТ убрана из дампа. Она судила только по SS0/SS1,
         * то есть молчала о графике, а рядом теперь стоит баннер, который
         * различает все четыре состояния. Дублировать вывод в двух местах
         * опасно: при правке одного они разойдутся, и человек увидит
         * «разблокировано» там, где графика не поднялась. Вместо неё -
         * значение селектора, на котором вердикт и построен. */
        Print(L" GFX_SPEED_SEL 0x%08x\n", g_snapGfx);
        Print(L" лог          флешка, LBA %d..%d  ->  out\\read-log.ps1\n",
              (INTN)LOG_LBA, (INTN)(LOG_LBA + LOG_SECTORS - 1));
        Print(L"=======================================\n");
        /* v3.45: БАННЕР ПОСЛЕ ДАМПА И ДО СБРОСА БУФЕРА. Порядок выбран по двум
         * причинам, и обе существенные.
         *
         * 1) На экране это последнее, что человек видит перед возвратом в
         *    прошивку: дамп длинный, а вердикт в его середине не читается.
         * 2) До log_ms(...final), который сбрасывает буфер принудительно.
         *    После него строки VRC остались бы в буфере и на флешку не
         *    попали бы, а лог читают как эталон. */
        unlock_verdict_banner();
        /* v3.41, этап 24:log_flush_sector(TRUE) — принудительный сброс буфера
         * на флешку. Главный подозреваемый в остатке хвоста после FLR. */
        log_ms(L"post: before log_flush_sector(TRUE)");
        log_flush_sector(TRUE);
        log_ms(L"post: after log_flush_sector(TRUE)");
        /* Финальный дамп окна SEC2: это последнее состояние перед уходом
         * в прошивку, то есть ровно то, что доживает до Windows. Именно
         * его и надо сравнивать между прогонами с флешкой и без. */
        sec2_window_dump(L"END-final");
    /* v3.16: сводка по ожиданиям DMA-очередей. Печатается всегда, даже
     * если таймаутов не было — иначе отсутствие строки нельзя отличить
     * от «сводка не дошла». Стоимость самих ожиданий видна в строках
     * DMAQ/DMAQ2 (cost=N reads/...us). */
    ulogf(L"TIME   DMA queue: full timeouts=%d idle timeouts=%d\n",
          (INTN)g_dmaFullTo, (INTN)g_dmaIdleTo);
    log_ms(L"final: before return to firmware");
    log_ms(L"final: before return to firmware");
    fx_mk_report();
    /* v3.17: ИТОГ ПО ВЫВОДУ - то, ради чего всё затевалось.
     *
     * Печатается ДО выгрузки кольца и ДО маркеров END: если прогон
     * оборвётся раньше, цифры останутся в логе, потому что log_ms выше
     * уже сбросил буфер принудительно.
     *
     * est_if_unbuffered - сколько миллисекунд заняли бы те же вызовы
     * консоли, если бы они печатались напрямую. Это переводит спор
     * «сколько стоит вывод» из прикидки в измерение. */
    fx_io_report();
    /* Пропуск диагностических экспериментов обязан быть виден, иначе
     * «оптимизация» выглядит бы как «эксперимента перестал существовать».
     * Печатаются и число выполненных, и число пропущенных прогонов. */
    if (fx_diagCalls > fx_diagDone)
        ulogf(L"TIME   diag experiments: ran=%d skipped=%d (every %d) - the "
              L"skipped runs repeated an answer that does not depend on the "
              L"mask; full data is in the runs that did execute\n",
              (INTN)fx_diagDone, (INTN)(fx_diagCalls - fx_diagDone),
              (INTN)FX_DIAG_EVERY);
    else
        ulogf(L"TIME   diag experiments: ran=%d skipped=0\n", (INTN)fx_diagDone);
        ulogf(L"END   ss0=0x%08x ss1=0x%08x PLM=0x%08x WPR2=0x%08x/0x%08x "
             "dbg=0x%08x cpuctl=0x%08x scratch0e=0x%08x\n",
             g_snapSs0, g_snapSs1, g_snapPlm, g_snapWLo, g_snapWHi,
             g_snapDbg, g_snapCpu, g_snapSc0);
        ulogf(L"END   ---- end of log ----\n");   /* ASCII: см. log_write() */
        /* v3n: ФИНАЛЬНЫЙ СБРОС. Без него обе строки END остаются в буфере.
         *
         * Как выяснилось 2026-09-29: log_flush_sector(TRUE) выше (строка
         * перед блоком END) сбрасывает буфер с «STG reached done» и
         * «STG post-FLR», и на этом запись на флешке заканчивается. Две
         * строки END уходят в свежий, уже не сброшенный буфер, а дальше
         * Print -> Stall -> return, и приложение возвращается в прошивку
         * с ~230 байтами лога в ОЗУ.
         *
         * Наблюдалось ровно так, лог обрывался чистым переводом строки:
         *     ... STG   reached 'done' label
         *         STG   post-FLR: MMIO недоступен, ...
         *         <дальше на флешке пусто, маркера END нет>
         *
         * Именно поэтому лог ВСЕГДА обрывался на границе сброса, и
         * «лог оборвался» и «приложение не дописало» было неразличимо —
         * оба варианта давали один и тот же вид. Маркер END появится только
         * после этого фикса; до него во всех прогонах (sec1, okchk, stages,
         * verify-fixes, after-fix) его не было, и это НЕ было признаком
         * зависания. */
        /* v3.17: перед последним сбросом выгружается кольцо консоли.
         * Порядок именно такой: выгрузка идёт ПЕРЕД строками END, чтобы
         * маркер конца остался последней строкой лога - по нему и судят,
         * что приложение дописало всё, а не зависло на середине. */
        /* v3.20: ВЫЗОВ ОБОРАЧЁН В МЕТКУ ВРЕМЕНИ.
         *
         * Кольцо не пишется на флешку в трёх прогонах подряд
         * (v3.17, v3.18, v3.19), и до сих пор непонятно ПОЧЕМУ: то ли
         * функция не вызывается, то ли вызывается, но её вывод теряется,
         * то ли она отрабатывает и пишет, а парсер это не показывает.
         * Три разные причины дают одинаковую картину в логе, а лечатся
         * совершенно по-разному.
         *
         * Ставить здесь log_ms() нельзя: он сам вызывает ulogf и сбрасывает
         * буфер, то есть изменил бы измеряемое состояние. Поэтому замер
         * идёт в фазовый счётчик, который здесь не мешает.
         *
         * ============ v3.48: БЛОК ПЕРЕЕХАЛ В КОНЕЦ efi_main ============
         *
         * Он стоял ЗДЕСЬ, между маркерами END и выводом вердикта, и этим
         * порядком сам был причиной потери: выгрузка кольца - единственная
         * крупная запись в приложении (~26 КБ, около 50 секторов), и если
         * отказ WriteBlocks когда-нибудь придётся на неё, то logOn станет
         * FALSE и унесёт с собой всё, что записано после, - включая
         * счётчик SCREEN FINAL.
         *
         * ============ v3.50: ОТКАЗА НЕ БЫЛО, ПЕРЕНОС НЕ ПОНАДОБИЛСЯ =======
         *
         * Комментарий предыдущей ревизии утверждал: «на прогоне 1004-163842
         * отказ и случился именно здесь». Это НЕВЕРНО. Отказов не было ни
         * разу - на прогоне 1004-171751 прямо с флешки читается
         *     PRND  AFTER  ring dump: entered=1 filled=25836 logOn=1
         *             sectors_written=199 flush_fails=0
         * а обрезало данные НЕ приложение, а читалка: read-log.ps1 резал
         * текст по маркеру 'END ---- end of log ----', а дамп кольца пишется
         * ПОСЛЕ этого маркера. Данные лежали на флешке всё это время.
         *
         * Перенос оставлен: для исправления сегодняшнего дефекта он не
         * требовался, но он бесплатно делает правильную вещь - важное
         * отправляется на флешку до того, как может отказать крупная запись.
         * Страховка без побочных эффектов не удаляется, когда необходимость
         * в ней не подтвердилась.
         *
         * Диагностика вокруг вызова не переехала: она нужна именно там, где
         * выгрузка выполняется. */
    }
    /* Маркеры END - на флешку ДО всего, что может упасть. */
    log_flush_sector(TRUE);

    /* v3.17: всё, что накоплено в кольце, показываем на настоящей
     * консоли - пользователь видит финальный отчёт, а не молчание. */
    fx_pr_console_dump();
    Print(L"\nКонец.\n");
    /* v3.46: ВЕРДИКТ - ПОСЛЕ ДАМПА, МИМО КОЛЬЦА.
     *
     * Print внутри unlock_verdict_print_screen() идёт прямо на консоль через
     * fx_console_raw, потому что вся остальная печать буферизуется в кольцо
     * ради скорости (17,0 мс на вызов). Если бы баннер печатался обычным
     * Print, он попал бы в кольцо и вытеснился бы из «последних 12 строк» -
     * то есть ровно то, ради чего его делали.
     *
     * Порядок именно такой: после fx_pr_console_dump() и после «Конец.», иначе
     * рамку вытеснил бы финальный дамп. */
    unlock_verdict_print_screen();
    /* v3.48: ИТОГОВЫЙ СЧЁТ ЭКРАНА - ПОСЛЕ РАМКИ, А НЕ ДО НЕЁ.
     *
     * На прогоне 1004-161157 отчёт показал «SCREEN raw console lines=2», и
     * это была не ошибка прошивки, а ошибка самого измерения: fx_io_report()
     * вызывается выше по потоку, чем unlock_verdict_print_screen(), то есть
     * счётчик снимался за пять прямых вызовов до того, как они произошли.
     * Проверка 2c ругалась на неполное число, и ругалась правильно.
     *
     * Порядок важен и потому, что счётчик единственный: прямой вывод в консоль
     * не оставляет следа нигде, и по логу нельзя доказать, что рамка дошла до
     * экрана. Значит число обязано сниматься в последний момент, когда рамка
     * уже напечатана.
     *
     * Сброса здесь не нужно: log_flush_sector(FALSE) в конце efi_main идёт
     * после этой точки и уносит строку на флешку. */
    ulogf(L"TIME  SCREEN raw console lines=%d FINAL "
          L"(2 верхние + рамка из 5 = 7) logOn=%d flush_fails=%d\r\n",
          (INTN)g_rawCalls, (INTN)g_logOn, (INTN)g_logFlushFails);
    /* v3.48: ЭТОТ СБРОС - ГРАНИЦА «ВАЖНОЕ» И «РАСХОДУЕМОЕ».
     *
     * Всё, что записано до этой точки, теперь на флешке и не зависит от того,
     * выживет ли следующая запись. Дальше идёт только выгрузка кольца - около
     * 40 КБ, около десяти сбросов, единственная крупная запись в приложении.
     * Именно на ней отказ WriteBlocks и случался (прогон 1004-163842), и
     * именно из-за её позиции она забирала с собой всё, что за ней стояло,
     * - включая счётчик экранных строк, который до v3.48 и не печатался вовсе
     * по противоположной причине: счётчик снимался раньше рамки.
     *
     * Теперь два независимых механизма наблюдения не могут погасить друг
     * друга: счётчик экрана гарантированно переживает выгрузку кольца. */
    log_flush_sector(TRUE);

    /* v3.48: ВЫГРУЗКА КОЛЬЦА - ПОСЛЕДНЯЯ ЗАПИСЬ ПРИЛОЖЕНИЯ.
     *
     * Всё, что человеку нужно от лога, уже на флешке. Это расходуемый
     *diagnостический материал: 719 строк, которые полезны только для разбора,
     * и которые не должны иметь права унести с собой счётчики.
     *
     * Два маркера вокруг вызова остаются: они и есть измерение. Читаются
     * однозначно:
     *   нет BEFORE              -> код сюда не дошёл;
     *   есть BEFORE, нет AFTER  -> запись сломалась внутри выгрузки;
     *   оба есть, нет PRN       -> fx_pr_dump вышел раньше, не написав причину
     *                             (тогда отсутствует и строка NOT DUMPED);
     *   оба есть, PRN есть      -> выгрузка идёт и пишет.
     *
     * Если BEFORE есть, а AFTER нет - это и есть отказ записи, и теперь он
     * дополнительно объявлен на экране строкой 'LOG WRITE FAILED', которую
     * видно независимо от флешки. */
    {
        UINT64 pm = fx_now_us();
        ulogf(L"PRND  BEFORE ring dump: entered=%d calls=%d filled=%d "
              L"logOn=%d sec=%d\r\n",
              (INTN)g_prDumpCalls, (INTN)g_prCalls, (INTN)g_prFilled,
              (INTN)g_logOn, (INTN)g_logSec);
        fx_pr_dump();
        ulogf(L"PRND  AFTER  ring dump: entered=%d filled=%d logOn=%d "
              L"sectors_written=%d flush_fails=%d\r\n",
              (INTN)g_prDumpCalls, (INTN)g_prFilled, (INTN)g_logOn,
              (INTN)g_logSectors, (INTN)g_logFlushFails);
        fx_mk_acc(pm, L"console ring dump to log");
    }
    log_flush_sector(TRUE);
#if !defined(EFI_AUTOTEST) && !defined(RELEASE_BUILD)
    WaitForSingleEvent(SystemTable->ConIn->WaitForKey, 0);
#endif
#ifdef RELEASE_BUILD
    /* релиз: НИКАКИХ перезагрузок — POST сбросит анлок!
     * Возврат в прошивку: если анлок успел примениться, состояние
     * сохраняется; firmware продолжит boot-порядок (Windows). */
    /* v3.48: БЫЛО 'Print(L"v3.01: возврат в прошивку без перезагрузки ... ")'.
     *
     * Две ошибки в одной строке. Первая - версия: в сборке v3.48 надпись
     * 'v3.01' была просто неверной, и она относилась к тому же классу, что и
     * удалённые баннеры v3.04/v3.02/v2.101: текст о версии, который никогда
     * не обновляли и который не с чем сверяться.
     *
     * Вторая - Print вместо ulogf. Print уходит в кольцо, а кольцо это
     * расходуемый материал (v3.48: выгрузка кольца идёт последней записью,
     * чтобы отказ на ней не забрал с собой важное). Смысл поведения - то,
     * что приложение возвращается в прошивку БЕЗ перезагрузки, потому что
     * анлок волатилен, - deserves быть в логе, а не в буфере, который
     * разрешено потерять.
     *
     * Версия убрана целиком: её показывает баннер build.sh и теги git, и
     * дублировать её в логе незачем - расходиться она будет только в одну
     * сторону, как и разошлись все предыдущие. */
    ulogf(L"RET   returning to firmware WITHOUT reboot: the unlock is "
          L"volatile, so no reset may be issued here\r\n");
    /* v3.19: было Stall(2000000) - две секунды чистого ожидания, и обе были
     * ВНЕ счётчика, то есть невидимы. Смысл паузы: дать человеку прочитать
     * финальные строки на экране до того, как управление уйдёт в BDS и
     * экран переключится. Экран остаётся видимым и при возврате в
     * прошивку - BDS продолжает грузить Windows, а не стирает кадр.
     *
     * 500 мс достаточно: последние строки к этому моменту уже напечатаны
     * ( fx_pr_console_dump() стоит выше), и пауза нужна только чтобы глаз
     * успел, а не чтобы что-то дописалось.
     *
     * Экономия 1,5 с. Это последнее, что вообще можно убрать без риска:
     * дальше начинается работа прошивки и ОС, которая не наша. */
    uefi_call_wrapper(BS->Stall, 1, 500000);
#endif
    /* v3n: страховка. Всё, что напечатано после сброса выше, обязано
     * попасть на флешку ДО возврата в прошивку: после return управление
     * уходит BDS, и дописать уже нечем. Без этой строки любой вывод,
     * добавленный после блока END, молча пропадал бы — именно так и
     * пропадал маркер конца. С force=FALSE: если буфер пуст, ничего не
     * пишется, и мы не оставляем лишний нулевой сектор на флешке. */
    log_flush_sector(FALSE);
    return EFI_SUCCESS;
}

