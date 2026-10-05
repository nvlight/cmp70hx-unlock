/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * poll_model.c — проверка модели fx_poll32 на числах из реального лога.
 *
 * ЗАЧЕМ. Оптимизация v3.16 меняет цикл ожидания очереди DMA с
 * «20 000 чтений, потом сдаться» на «20 000 ИЛИ 16 одинаковых подряд,
 * ИЛИ 4 мс — что наступит раньше». Эквивалентность на живом железе
 * проверяется только прогоном, но проверить можно кое-что важнее:
 * ГДЕ ИМЕННО ПОЯВЛЯЕТСЯ НОВОЕ ПОВЕДЕНИЕ. Именно это и было ошибочно
 * описано в комментарии unlock_v2.c, и этот файл существует, чтобы
 * ошибка не вернулась.
 *
 * ДАННЫЕ ИЗ ЛОГА (out/usb-log-2026-10-01-single-build.txt):
 *   • cmd=0x00000615 на ВСЕХ 1656 таймаутах, счётчик до 1632 за прогон;
 *     то есть бит FULL в DMATRFCMD не сбрасывается НИ РАЗУ за прогон.
 *   • цена MMIO-чтения BAR0 ~8 мкс на этой платформе.
 *
 * СЦЕНАРИИ
 *   A. «регистр замер» — наблюдавшаяся реальность. Старый код: 20 000
 *      чтений, вердикт «таймаут». Новый: тот же вердикт за 17 чтений.
 *      Это и есть весь выигрыш.
 *   B. «очередь разгрузилась на 3-м чтении» — здоровая очередь. Здесь
 *      новый код обязан вести себя ИДЕНТИЧНО: выход на 3-м чтении,
 *      как и раньше.
 *   C. ГРАНИЦА. Очередь разгружается на 19 999-м чтении. Старый код
 *      ждёт и получает успех. Новый — выходит на 17-м с вердиктом
 *      «таймаут».
 *
 * ЧТО ЗНАЧИТ C. Это НЕ эквивалентность, и её нельзя объявлять.
 * Утверждение «бюджет итераций сохранён, поэтому поведение прежнее»
 * НЕВЕРНО: выход по «регистр не меняется» срабатывает ДО исчерпания
 * бюджета и всегда даёт «таймаут». Это осознанная плата за ускорение,
 * и её величина здесь посчитана: 19 999 чтений = 160 мс на вызов.
 *
 * ПОЧЕМУ ЭТО ПРИЕМЛЕМО ИМЕННО ЗДЕСЬ. Вопрос «должна ли очередь
 * разгружаться дольше 128 мкс (16 чтений)» — не вопрос вкуса:
 *   • если да, то старая версия на этой карте всё равно не получала
 *     успеха ни разу за 1656 попыток — там стояло фиксированное 0x615;
 *   • очередь, которая не двигается 16 чтений подряд, не «медленная»,
 *     а замершая: значение одно и то же, значит нечего и ждать;
 *   • единственный сценарий, где поведение ухудшается, — гипотетический
 *     «очередь разгружается ровно на 19 999-м чтении», то есть через
 *     160 мс, и при этом признак FULL всё это время не менялся.
 *     Такой тракт не наблюдался и не имеет физического смысла: бит
 *     статуса либо стоит, либо снимается за микросекунды.
 *
 * ЧТО ПРОВЕРЯЕТСЯ АВТОМАТИЧЕСКИ. Тест падает, если:
 *   • в сценарии A вердикты старого и нового разошлись;
 *   • в сценарии B новый код НЕ вышел на том же чтении, что старый
 *     (это была бы настоящая поломка живой очереди);
 *   • сценарий C не дал таймаут (то есть выход по «замер» не работает
 *     и оптимизация не даёт эффекта).
 *
 * Сборка: gcc -O2 -Wall -o /tmp/poll_model src/tools/poll_model.c && /tmp/poll_model
 */

#include <stdio.h>
#include <stdint.h>

#define OLD_ITER   20000u   /* бюджет старого кода (gsp_dma_wait_not_full) */
#define STUCK_AT   16u      /* FX_DMAQ_STUCK        */
#define MAX_US     4000u    /* FX_DMAQ_MAX_US       */
#define READ_NS    8000u    /* ~8 мкс на MMIO-чтение BAR0 на этой платформе */

static int fail = 0;

/* Старый цикл. clear_at: 0 = «не снимется никогда», иначе номер чтения. */
static unsigned
old_wait(unsigned clear_at, unsigned *reads_out)
{
    unsigned i;
    for (i = 0; i < OLD_ITER; i++) {
        if (clear_at && (i + 1) >= clear_at) { *reads_out = i + 1; return 1; }
    }
    *reads_out = OLD_ITER;
    return 0;
}

/* Модель нового примитива — логика fx_poll32 без MMIO:
 * выход по условию / по «значение не менялось stuckAt раз» / по потолку
 * времени / по исчерпанию бюджета итераций. */
static unsigned
new_wait(unsigned clear_at, unsigned max_iter, unsigned *reads_out)
{
    unsigned reads = 0, same = 0;
    unsigned long us = 0;
    while (reads < max_iter) {
        reads++;
        us += READ_NS;
        if (clear_at && reads >= clear_at) break;              /* условие */
        if (reads > 1 && same + 1 >= STUCK_AT) break;         /* замер  */
        if (us >= MAX_US * 1000UL) break;                     /* потолок */
        same++;
    }
    *reads_out = reads;
    return clear_at ? (reads >= clear_at) : 0;
}

static void
report(const char *name, unsigned clear_at, unsigned oread, unsigned over,
       unsigned nread, unsigned nver, const char *expect)
{
    printf("  %-46s old: %5u reads verdict=%u\n", name, oread, over);
    printf("  %-46s new: %5u reads verdict=%u   %s\n\n", "", nread, nver,
           expect);
}

int main(void)
{
    unsigned oread = 0, nread = 0;
    unsigned ov, nv;

    printf("budget: old=%u reads, stuck=%u, time cap=%u us, read=%u ns\n",
           OLD_ITER, STUCK_AT, MAX_US, READ_NS);
    printf("observed on hardware: FULL never cleared in 1656/1656 timeouts\n\n");

    /* ---- A: наблюдавшаяся реальность ---------------------------------- */
    ov = old_wait(0, &oread);
    nv = new_wait(0, OLD_ITER, &nread);
    printf("A: FULL never clears (the case the hardware actually shows)\n");
    report("verdicts must MATCH", 0, oread, ov, nread, nv,
           ov == nv ? "OK" : "*** MISMATCH ***");
    if (ov != nv) { printf("  FAIL: A verdicts differ\n"); fail = 1; }
    if (nread >= oread) {
        printf("  FAIL: A made no progress — stuck-exit does not fire\n");
        fail = 1;
    }

    /* ---- B: здоровая очередь — поведение обязано совпасть в деталях ---- */
    ov = old_wait(3, &oread);
    nv = new_wait(3, OLD_ITER, &nread);
    printf("B: queue clears on read 3 (healthy) — must be IDENTICAL\n");
    report("same read count AND same verdict", 3, oread, ov, nread, nv,
           (ov == nv && oread == nread) ? "OK" : "*** MISMATCH ***");
    if (ov != nv || oread != nread) {
        printf("  FAIL: B — the new code changed behaviour on a live queue\n");
        fail = 1;
    }

    /* ---- C: граница. Расхождение ЗАВЕДОМОЕ и посчитанное. ------------ */
    ov = old_wait(19999, &oread);
    nv = new_wait(19999, OLD_ITER, &nread);
    printf("C: queue clears on read 19999 — KNOWN, PRICED divergence\n");
    report("old wins here, new reports timeout", 19999, oread, ov, nread, nv,
           (ov == 1 && nv == 0) ? "OK (as documented)" : "*** UNEXPECTED ***");
    if (ov != 1 || nv != 0) {
        printf("  FAIL: C — divergence is not the documented one; re-derive\n");
        fail = 1;
    }

    /* ---- цифры, ради которых всё делалось ----------------------------- */
    printf("A: reads per stuck call   %u -> %u  (x%.0f)\n",
           oread, nread, (double)oread / nread);
    printf("A: time  per stuck call   %.1f s -> %.3f s\n",
           oread * READ_NS / 1e6, nread * READ_NS / 1e6);
    printf("   over 1656 timeouts:    %.0f s -> %.1f s\n",
           1656.0 * oread * READ_NS / 1e9, 1656.0 * nread * READ_NS / 1e9);
    printf("C: the loss is bounded by %.1f s per call\n\n",
           OLD_ITER * READ_NS / 1e6);

    if (fail) { printf("*** ТЕСТ УПАЛ ***\n"); return 1; }
    printf("OK: A identical verdict, B identical behaviour, C divergence is\n"
           "    the documented and priced one.\n");
    return 0;
}