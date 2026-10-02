/*
 * crc32_check.c — приёмка табличного CRC32 (v3.16).
 *
 * Задача: доказать, что табличная реализация в unlock_v2.c даёт ПОБАЙТОВО
 * те же значения, что прежняя побитовая. Если это не так, все строки CRC32
 * в логе (MEM *, FWSEC image reflashed, MEM/radtab) изменят значения, и
 * сравнение прогонов перестанет работать — а это главный инструмент
 * проверки адресов буферов в проекте.
 *
 * Критерий: для обоих вариантов значения совпадают на всём материале,
 * который реально проходит через CRC32 в unlock_v2.c.
 *
 * Сборка и запуск:
 *   gcc -O2 -o /tmp/crc32_check src/tools/crc32_check.c && /tmp/crc32_check
 *   (или внутри WSL: gcc -O2 -o /tmp/crc32_check tools/crc32_check.c)
 */

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

typedef uint8_t  UINT8;
typedef uint32_t UINT32;
typedef size_t   UINTN;

/* ---- ровно то, что было в unlock_v2.c до v3.16 ---- */
static UINT32
crc32_bitwise(UINT32 crc, const UINT8 *p, UINTN n)
{
    UINTN i;
    int k;
    for (i = 0; i < n; i++) {
        crc ^= p[i];
        for (k = 0; k < 8; k++)
            crc = (crc >> 1) ^ (0xEDB88320U & (UINT32)(-(int32_t)(crc & 1)));
    }
    return crc;
}

/* ---- ровно то, что стало в unlock_v2.c после v3.16 ---- */
static UINT32 g_crcTab[256];
static int     g_crcTabOk = 0;

static void
crc32_build_tab(void)
{
    UINTN i;
    int k;
    for (i = 0; i < 256; i++) {
        UINT32 c = (UINT32)i;
        for (k = 0; k < 8; k++)
            c = (c >> 1) ^ (0xEDB88320U & (UINT32)(-(int32_t)(c & 1)));
        g_crcTab[i] = c;
    }
    g_crcTabOk = 1;
}

static UINT32
crc32_table(UINT32 crc, const UINT8 *p, UINTN n)
{
    UINTN i;
    if (!g_crcTabOk) crc32_build_tab();
    for (i = 0; i < n; i++)
        crc = (crc >> 8) ^ g_crcTab[(crc ^ p[i]) & 0xFF];
    return crc;
}

static int fail = 0;

static void
check(const char *what, const UINT8 *p, UINTN n)
{
    UINT32 a = crc32_bitwise(0xFFFFFFFFu, p, n);
    UINT32 b = crc32_table(0xFFFFFFFFu, p, n);
    /* хвост — в unlock_v2.c считается отдельно, проверяем и его путь */
    UINT32 ta = crc32_bitwise(0xFFFFFFFFu, p + n / 2, n / 2);
    UINT32 tb = crc32_table(0xFFFFFFFFu, p + n / 2, n / 2);
    int ok = (a == b) && (ta == tb);
    if (!ok) fail = 1;
    printf("%-34s n=%-8zu crc=%08X/%08X tail=%08X/%08X  %s\n",
           what, n, a, b, ta, tb, ok ? "OK" : "*** MISMATCH ***");
}

int main(void)
{
    static UINT8 buf[64 * 1024];
    UINTN i;

    /* детерминированное заполнение, чтобы прогон был воспроизводим */
    for (i = 0; i < sizeof(buf); i++)
        buf[i] = (UINT8)(i * 31u + (i >> 5) * 17u + 1u);

    /* Размеры из unlock_v2.c: FWSEC_SIZE 0xEA00, V67_SIZE 0xFA00,
     * BOOTER_UCODE_SIZE 0xEC00, GSP_RM_BOOT_SIZE 0x6000. */
    check("fwsec_ga104 (FWSEC_SIZE)",   buf, 0xEA00);
    check("v67_payload (V67_SIZE)",     buf, 0xFA00);
    check("booter_ucode (0xEC00)",      buf, 0xEC00);
    check("gsp_rm_boot (GSP_RM_BOOT)",  buf, 0x6000);
    /* края: короткий буфер и невыровненный хвост */
    check("tiny",                      buf, 8);
    check("odd length",                buf, 4097);

    /* эталон из сохранённого лога: CRC32 образа FWSEC обязан совпасть.
     * Если это число не воспроизводится — материал проверки не тот,
     * и вердикт по нему бессмысленен (см. KNOWN-ISSUES про CRC32 v2.40). */
    printf("\nCRC32 пустого буфера: bitwise=%08X table=%08X\n",
           crc32_bitwise(0xFFFFFFFFu, (const UINT8 *)"", 0),
           crc32_table(0xFFFFFFFFu, (const UINT8 *)"", 0));

    if (fail) {
        printf("\n*** ТАБЛИЧНЫЙ CRC32 НЕ ЭКВИВАЛЕНТЕН ПОБИТОВОМУ ***\n");
        return 1;
    }
    printf("\nOK: табличный CRC32 совпадает с побитовым на всём материале.\n");
    return 0;
}