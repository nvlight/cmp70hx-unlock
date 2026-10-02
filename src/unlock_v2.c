/*
 * unlock_v2.c — NVIDIA CMP 70HX (GA104) full unlock — UEFI application
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
 *                        alt device ID at TARGET_PCI_DEV_ALT1 remains a known
 *                        latent hazard (see KNOWN-ISSUES).
 *   PCIE_GEN2_REJOIN     include render-mask table + fire machinery.
 *                        WITHOUT IT THE RENDER PHASE IS NOT EVEN COMPILED
 *                        (that is how v3.01 shipped compute-only by mistake)
 *   FULL_NOGEN2          v3.03: keep render table, drop the PCIe-gen2 link
 *                        domain, add tail cleanup (SEC2 kill + final FLR);
 *                        fixes the Code 43 of v3.02-full
 *   EFI_AUTOTEST         QEMU test-stand behaviour: auto-advance, extra dumps
 *   PCIE_GEN_EXPERIMENT  dev-only Gen2/Gen3 register experiments
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
static UINTN   g_ulogCalls = 0;
static UINT64  g_ulogUs    = 0;
static UINTN   g_logSectors = 0;
/* v3.19: сколько раз реально дошло до выгрузки кольца, и сколько секторов
 * при этом записано. Без этого выгрузка неотличима от «функция не вызвана».
 * См. комментарий у fx_pr_dump. */
static UINTN   g_prDumpCalls = 0;
static UINTN   g_prDumpSecBefore = 0;
/* v3.18: сколько раз запись на флешку сорвалась. Ноль в норме. */
static UINTN   g_logFlushFails = 0;

static VOID fx_print(CHAR16 *fmt, ...);
static BOOLEAN g_logOn;        /* лог на флешку; определён ниже */
static UINT32  g_logSec;       /* текущий сектор записи; определён ниже */
static UINTN   g_logFill;      /* заполнение буфера секторов; определён ниже */
static VOID fx_console_raw(CHAR16 *s);
static VOID fx_pr_dump(void);
static VOID fx_pr_console_dump(void);
static VOID fx_io_report(void);
static VOID fx_console_cost_probe(void);
#define Print(...) fx_print(__VA_ARGS__)

/* Настоящий вызов в консоль мимо буфера. Используется и пробой, и пульсом. */
static VOID
fx_console_raw(CHAR16 *s)
{
    fx_print_real(s);
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

    if (!g_prRing) {            /* кольцо ещё не выделено - прямо в консоль */
        fx_console_raw(tmp);
        return;
    }
    g_prCalls++;
    for (i = 0; tmp[i] && i < 512; i++) {
        if (g_prHead >= g_prCap) g_prHead = 0;      /* кольцо: затираем старое */
        g_prRing[g_prHead++] = tmp[i];
        if (g_prFilled < g_prCap) g_prFilled++;
    }
    /* Пульс на настоящей консоли: пользователь должен видеть, что идёт
     * процесс. Одна строка на 512 вызовов - при 3000 вызовах это 6 строк. */
    if ((g_prCalls % FX_PR_BEAT_EVERY) == 0) {
        CHAR16 beat[128];
        UnicodeSPrint(beat, sizeof(beat),
                      L"  ... console %d calls buffered\r\n", g_prCalls);
        fx_console_raw(beat);
    }
}

/* Разовая проба цены одного вывода в консоль. Делается на НАСТОЯЩЕЙ
 * консоли, иначе она измеряла бы цену собственной буферизации. */
static VOID
fx_console_cost_probe(void)
{
    UINT64 t0, t1;
    UINTN i;
    if (!g_prRing || !fx_now_us()) return;   /* часы не откалиброваны - пропуск */
    t0 = fx_now_us();
    for (i = 0; i < 20; i++)
        fx_console_raw(L"[probe] console cost measurement, dummy line\r\n");
    t1 = fx_now_us();
    if (t1 > t0) g_prUsPerCall = (UINTN)((t1 - t0) / 20);
}

/* Итог по выводу. Печатается ПОСЛЕ ulogf-счётчиков снятых, иначе строка
 * сама себя учтёт. */
static VOID
fx_io_report(void)
{
    UINTN uc = g_ulogCalls;
    UINT64 uu = g_ulogUs;
    UINTN ls = g_logSectors;
    UINT64 est = g_prUsPerCall ? (UINT64)g_prCalls * g_prUsPerCall : 0;

    ulogf(L"TIME  I/O: Print n=%d measured=%dus/call "
          L"est_if_unbuffered=%lldms | ulogf n=%d cost=%lldus sectors=%d\n",
          g_prCalls, g_prUsPerCall, (INT64)(est / 1000ULL),
          uc, (INT64)uu, ls);
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
    g_prDumpCalls++;

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
 * либо печатаем итог, либо не печатаем ничего.
 */
#define FX_SCREEN_LINES 12      /* строк на экране; 12 x 16,8 мс = 0,2 с */

static VOID
fx_pr_console_dump(void)
{
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
 * читаем. По умолчанию 1 — эксперимент. */
#ifndef PROBE_FUSE_NEIGHBOUR
#define PROBE_FUSE_NEIGHBOUR 1
#endif
#define REG_FUSE_SEL_CAND     0x0082380CUL   /* кандидат: сейчас 0x00888888 */
#define REG_FUSE_ROUTINE      0x00823810UL   /* сопровождающий, 0x002AAAAA */
static BOOLEAN g_postFlr = FALSE;   /* после do_flr() MMIO не читать */

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
    /* v2.99i FIX: CapPtr — байт 0x07 (старший байт dword@0x04);
     * раньше брали >>8 (байт 0x05) и всегда промахивались */
    pos = (pci_cfg_rd_bdf(bus, dev, fn, 0x04) >> 24) & 0xFF;
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
    g_snapOk  = TRUE;
}

static BOOLEAN
is_unlocked(void)
{
    return (mmio_read32(REG_FEAT_OVR_SM_SPD) == VAL_SS0_UNLOCKED &&
            mmio_read32(REG_FEAT_OVR_SM_SPD_1) == VAL_SS1_UNLOCKED);
}

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
#define FX_RQ_BUDGET_US  250000  /* v3.28, ЭТАП 12 ШАГ 2: бюджет ожидания покоя.
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
         * RJ16_N = 38, а i идёт с шагом 4, так что на последней итерации
         * i+1 в границах, а i+2 и i+3 — уже за массивом. Без зажима это
         * чтение за пределами таблицы (GCC на это ругается правильно). */
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
    for (t = 0; t < 5; t++) {
        mmio_write32(0x00823830U, 0x00000004U);
        uefi_call_wrapper(BS->Stall, 1, 50000);
        v = mmio_read32(0x00823830U);
        if (v == 0x00000004U) { okA = 1; break; }
        ulogf(L"G2GFX  %s order A attempt %d: readback 0x%08x != 4, retry\n",
              tag, (INTN)t + 1, v);
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
            mmio_write32(0x00823830U, 0x00000004U);
            uefi_call_wrapper(BS->Stall, 1, 50000);
            v = mmio_read32(0x00823830U);
            if (v == 0x00000004U) { okB = 1; break; }
            ulogf(L"G2GFX  %s order B attempt %d: readback 0x%08x != 4, retry\n",
                  tag, (INTN)t + 1, v);
            uefi_call_wrapper(BS->Stall, 1, 50000);
        }
        ulogf(L"G2GFX  %s ORDER B (GFX before SS): GFX_SPEED_SELECT=0x%08x %s\n",
              tag, v, okB ? L"SET" : L"NOT SET");
    }

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
    mmio_write32(0x00823830U, 0x00000004U);
    uefi_call_wrapper(BS->Stall, 1, 100000);
    v     = mmio_read32(0x00823830U);
    feat1 = mmio_read32(0x00823814U);
     ulogf(L"G2SUM  %s GFX_SPEED_SELECT=0x4 (kartina: 0x2=9fps, 0x4=50fps/135W, "
          L"0x5=26fps, 0x7=9fps - lestnicy net, 0x4 edinstvennyi rabochii): "
          L"readback 0x%08x %s; "
          L"FEAT_READOUT_0=0x%08x bit8=%u; DMAQ full=%d idle=%d; "
          L"SS0=0x%08x SS1=0x%08x\n",
          tag, v, (v == 0x00000004U) ? L"OK" : L"*** DID NOT HOLD ***",
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
    /* ОКНО XVE — «дверь» GFX_SPEED_SELECT. Это написано в нашем же коде
     * (unlock_v2.c:1760): «окно XVE (0x88xxx, «дверь» GFX_SPEED_SELECT)».
     * Независимо то же называют референс (docs/REGISTERS.md: 0x88FE8 =
     * «XVE mask», в таблице Render/движки) и iatethelogs (открывает 0x88FE8).
     *
     * Первый прогон (v3.08) целился в 0x823B04 по комментарию v2.100
     * («липнет только при открытом PLM 0x823b04») и в 0x823800. Итог:
     *   0x00823800 -> 0xFFFFFFFF ОТКРЫТА (polls=0)   механизм рабочий
     *   0x00823B04 -> 0xFFFFFF8F   3 попытки по 1000 polls, не сдвинулась
     * То есть v2.100-комментарий про 0x823B04 — единственный источник этого
     * требования, и на 70HX он не подтвердился. А 0x823800, который
     * референс называет вполне достаточным («без него GFX_SEL не пишется»),
     * открылся — и GFX_SPEED_SELECT всё равно не встал. Значит дверь
     * другая, и наш собственный комментарий называет её прямо.
     *
     * Плюс 0x823800 (PLM стр. 0x8238xx) и 0x823B04 — оба в g_rj16, первый
     * в прошлом прогоне открылся, второй не подтвердился, но стоит копейки.
     *
     * v3.10 (текущий состав): первые 6 адресов открылись с polls=0, и
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
     * НИЖЕ — список 8 адресов. Расширять его можно только с новым замером
     * «fps/ватты изменились», иначе он вернёт ровно эти 121 секунду. */
    static const UINT32 tgt[] = {
        /* окно XVE */
        0x00088FE8U, 0x00088FECU, 0x00088FF0U, 0x00088FF4U, 0x00088FF8U,
        0x00088AB4U,
        /* PLM 0x8238xx и маска рендера — обе открылись в v3.10, и на них
         * держится GFX_SPEED_SELECT = 0x4 */
        0x00823800U, 0x00823B04U };
/* БЫЛО 25 адресов. Первые 8 — рабочие, они выше. Остальные 17 НЕ пишутся
 * и НЕ нужны, потому что единственная их функция — разрешить запись в
 * 0x8e1xx (PCIe Gen2), а он выключен:
 *     0x0008E1B0U, 0x0008E1B4U, 0x0008E1B8U, 0x0008E1BCU, 0x0008E1C0U,
 *     0x0008E1C4U, 0x0008E1C8U, 0x0008E1CCU, 0x0008E1D0U, 0x0008E1D4U,
 *     0x0008E1D8U, 0x0008E1DCU, 0x0008E1E0U, 0x0008E1E4U, 0x0008E1E8U,
 *     0x0008E1ECU, 0x0008E1F0U
 * Замер их открытия: 24 из 25, polls=0 — механика работает. Их эффект:
 * ноль fps и ноль ватт (PORT-STATUS §1u). Если Gen2 когда-нибудь будет
 * включён обратно, эти 17 адресов надо вернуть ПЕРВЫМИ. */
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
    ulogf(L"G2RMK  %s === opening XVE window (GFX_SPEED_SELECT door): "
          L"full FLR path per mask (fast path was removed in v3.19) ===\n",
          tag);
    for (k = 0; k < NTGT; k++)
        ulogf(L"G2RMK  %s BEFORE  0x%08x = 0x%08x\n", tag, tgt[k],
              mmio_read32(tgt[k]));
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
            uefi_call_wrapper(BS->Stall, 1, 300000);
            cfg_write32(0x10, saveBar);
            enable_mem_decode();
            gBar0Base = saveBar;
            fx_mk_acc(fx_ph, L"render: FLR + 300ms settle");
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
    ulogf(L"G2RMS  %s TOTAL: XVE window open %d of %d | 0x823800=0x%08x | "
          L"0x823B04=0x%08x | WPR2=0x%08x/0x%08x %s | GFX-gate %s\n", tag,
          (INTN)done, (INTN)NTGT, v, mmio_read32(0x00823B04U),
          mmio_read32(REG_PFB_MMU_WPR2_LO),
          mmio_read32(REG_PFB_MMU_WPR2_HI),
          (mmio_read32(REG_PFB_MMU_WPR2_LO) == TARGET_WPR2_LO &&
           mmio_read32(REG_PFB_MMU_WPR2_HI) == TARGET_WPR2_HI)
              ? L"expected" : L"*** UNEXPECTED ***",
          (done > 0) ? L"open, GFX_SPEED_SELECT can engage"
                     : L"closed, GFX_SPEED_SELECT will not engage");
    log_ms(L"render masks: sweep finished");
#undef NTGT
}
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
             * зафиксированы в комментариях и в docs/SPEED-REFACTOR.md:
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
            if (fx_diag_gate())
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
        Print(L"meta-low @0x%lx: magic ok=%d sig@0x%llx sz=0x%llx "
              L"heapOff=0x%llx heapSz=0x%llx fwOff=0x%llx flags=0x%x\n",
              cmp90_metaLowPhys,
              (m[0] == 0xDC3AAE21371A60B3ULL),
              m[9], m[10], m[15], m[16], m[17],
              *(UINT32*)((UINT8*)cmp90_metaLowPhys + 0xB4));
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
    uefi_call_wrapper(BS->Stall, 1, 50000);
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
    uefi_call_wrapper(BS->Stall, 1, 50000);
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
        uefi_call_wrapper(BS->Stall, 1, 50000);
        wpr2_probe(L"E5-after-restore");
        ulogf(L"FLRX   WPR2 restored after V67: "
              L"lo 0x%08x->0x%08x hi 0x%08x->0x%08x %s\n",
              wLo, mmio_read32(REG_PFB_MMU_WPR2_LO),
              wHi, mmio_read32(REG_PFB_MMU_WPR2_HI),
              (mmio_read32(REG_PFB_MMU_WPR2_LO) == wLo &&
               mmio_read32(REG_PFB_MMU_WPR2_HI) == wHi)
                  ? L"OK" : L"*** DID NOT HOLD ***");

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
    uefi_call_wrapper(BS->Stall, 1, 50000);
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
            uefi_call_wrapper(BS->Stall, 1, 200000);  /* 200ms */
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
    m->nonWprHeapSize  = MB;
    m->nonWprHeapOffset = m->gspFwWprStart - MB;
    m->gspFwRsvdStart  = m->nonWprHeapOffset;

    m->bootCount = 0;
    m->verified  = 0;
    m->pmuReservedSize = 0;
    m->gspFwHeapVfPartitionCount = 0;
    m->flags = 0x1;                    /* GSP_FW_FLAGS_CLOCK_BOOST */
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
            /* Запись не идёт - не мешаем анлоку, но ЧИСЛО ПОТЕРЯННЫХ
             * секторов обязано попасть в лог, пока он ещё пишется. */
            if (g_logFlushFails == 0)
                ulogf(L"LOG    write FAILED at sec=%d fill=%d/512 - "
                      L"logging disabled, %d bytes lost\r\n",
                      (INTN)g_logSec, (INTN)(g_logFill / 512), (INTN)g_logFill);
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
     * именно этим участком. Подробности: docs/SPEED-REFACTOR.md,
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
        } else {
            Print(L"[io] console ring allocation FAILED - "
                  L"console output stays direct (no speedup)\n");
        }
    }
#ifdef RELEASE_BUILD
#ifdef PCIE_GEN2_REJOIN
# ifdef FULL_NOGEN2
    Print(L"=== v3.04 FULL-NOGEN2 (render table, no pcie-gen2) ===\n");
# else
    Print(L"=== v3.02 FULL (render table + gen2) ===\n");
# endif
#else
    Print(L"=== v3.04 compute-only (multi-card) ===\n");
#endif
#elif defined(EFI_AUTOTEST)
# ifdef FULL_NOGEN2
    Print(L"=== v3.04-nogen2 (render table) [AUTOTEST] ===\n");
# else
    Print(L"=== v2.101 (multipass + GFX/SS verify) [AUTOTEST] ===\n");
# endif
#else
    Print(L"=== v2.101 (multipass + GFX/SS verify) ===\n");
#endif
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

        Status = alloc_fwsec_buffer((fwSize + 0xFFF) >> 12, &radixPhys);
        if (EFI_ERROR(Status)) { Print(L"alloc fw: %r\n", Status); goto done; }
        fwBase = radixPhys;

        Status = uefi_call_wrapper(BS->LocateHandleBuffer, 5,
                                   ByProtocol, &bioGuid, NULL, &HandleCount, &Handles);
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
                Status = uefi_call_wrapper(bio->ReadBlocks, 5,
                                           bio, bio->Media->MediaId,
                                           0, fwSize, (VOID*)(UINTN)radixPhys);
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
     * Комментарий 4d635d8 «sweep_all ran twice, costing 11.9 s» относился
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
                    mmio_write32(0x00823830U, 0x00000004u);
                    uefi_call_wrapper(BS->Stall, 1, 50000);
                    gv = mmio_read32(0x00823830U);
                    for (t = 0; gv != 0x00000004u && t < 5; t++) {
                        Print(L"gen2: GFX_SEL readback 0x%08x != 4 — повтор\n",
                              gv);
                        uefi_call_wrapper(BS->Stall, 1, 50000);
                        mmio_write32(0x00823830U, 0x00000004u);
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
        ulogf(L"STG   reached selector block success=%d direct=%d early=%d "
              L"gen2Fire=%d\n",
              (INTN)Status, (INTN)directOk, (INTN)earlyOk,
              GEN2_FIRE_STATE());

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
#ifdef GEN2_LINK_TRY
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
    if (is_unlocked())
        Print(L"*** NVIDIA %s РАЗБЛОКИРОВАН ***\n", TARGET_NAME);
    else
        Print(L"*** ВНИМАНИЕ: GPU НЕ разблокирован (SS0=0x%08x SS1=0x%08x) ***\n",
              mmio_read32(REG_FEAT_OVR_SM_SPD), mmio_read32(REG_FEAT_OVR_SM_SPD_1));

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
        Print(L" SS0/SS1      0x%08x / 0x%08x\n", g_snapSs0, g_snapSs1);
        Print(L" WPR2         0x%08x/0x%08x  (ожидалось 0x%08x/0x%08x)\n",
              g_snapWLo, g_snapWHi, TARGET_WPR2_LO, TARGET_WPR2_HI);
        Print(L" dbg(0x94)    0x%08x   scratch0e 0x%08x   cpuctl 0x%08x\n",
              g_snapDbg, g_snapSc0, g_snapCpu);
        Print(L" ВЕРДИКТ      %s\n",
              (g_snapSs0 == VAL_SS0_UNLOCKED && g_snapSs1 == VAL_SS1_UNLOCKED)
                  ? L"РАЗБЛОКИРОВАН" : L"НЕ РАЗБЛОКИРОВАН");
        Print(L" лог          флешка, LBA %d..%d  ->  out\\read-log.ps1\n",
              (INTN)LOG_LBA, (INTN)(LOG_LBA + LOG_SECTORS - 1));
        Print(L"=======================================\n");
        log_flush_sector(TRUE);
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
         * Следующий прогон даст число. Если оно нулевое - вызова не было
         * (и надо искать, кто перескакивает этот блок). Если ненулевое, а
         * строки PRN в логе по-прежнему нет - вывод теряется ПОСЛЕ
         * записи, и виноват log_flush_sector. */
        {
            UINT64 pm = fx_now_us();
            fx_pr_dump();
            fx_mk_acc(pm, L"console ring dump to log");
        }
        log_flush_sector(TRUE);
    }

    /* v3.17: всё, что накоплено в кольце, показываем на настоящей
     * консоли - пользователь видит финальный отчёт, а не молчание. */
    fx_pr_console_dump();
    Print(L"\nКонец.\n");
#if !defined(EFI_AUTOTEST) && !defined(RELEASE_BUILD)
    WaitForSingleEvent(SystemTable->ConIn->WaitForKey, 0);
#endif
#ifdef RELEASE_BUILD
    /* релиз: НИКАКИХ перезагрузок — POST сбросит анлок!
     * Возврат в прошивку: если анлок успел примениться, состояние
     * сохраняется; firmware продолжит boot-порядок (Windows). */
    Print(L"v3.01: возврат в прошивку без перезагрузки (анлок волатилен)\n");
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
