# SPDX-License-Identifier: GPL-2.0-only
"""Поиск device ID карты в GSP-образе.

Зачем. Референс (WildFlash1st, docs/DIAG-REPORT-2026-08-25-CODE43.md, §D)
пишет, что PGRAPH отключён «прошивкой GSP-RM», и указывает конкретное
место: *whitelist device-ID @ firmware 0xe037b0 не содержит 0x220D*.

То есть проверяемое утверждение: в образе GSP есть таблица допустимых
device ID, и наш 10de:248A в неё не входит. Это объясняло бы всё, что мы
наблюдаем: маски открыты, GFX_SPEED_SELECT=4 стоит, GFW загружен, а
FEAT_READOUT_0 bit8 = 0 и рендер частичный.

Что делаем. Ищем в образе все известные device ID NVIDIA в виде 32-битного
слова (младшие 16 бит = device ID, старшие = vendor 0x10DE) и в виде
16-битного device ID. Смотрим, какие ID встречаются рядом друг с другом —
если соседние строки содержат ID разных SKU, это и есть whitelist.

Осторожно с интерпретацией: 0x10DE и 0x248A — очень частые байты, поэтому
совпадения сами по себе ничего не доказывают. Поэтому дальше печатается
КОНТЕКСТ вокруг каждой находки: соседние 32-битные слова. Настоящий
whitelist виден как таблица, где ID идут подряд.
"""
import io
import struct
import sys

# Известные device ID NVIDIA (младшие 16 бит)
KNOWN = {
    0x1E04: "CMP 90HX? нет - TU102 CMP 50HX (этот ID у 50HX)",
    0x1E09: "CMP 50HX",
    0x220D: "CMP 90HX (GA102) - наш референс, НЕТ в whitelist по §D",
    0x248A: "CMP 70HX (GA104) - НАША КАРТА",
    0x2408: "RTX 3070 Ti (GA104, тот же д dies, что и 70HX)",
    0x1B06: "RTX 3080 (GA102)",
    0x1B04: "RTX 3070 (GA104)",
    0x2204: "RTX 3090 (GA102)",
    0x220E: "RTX 3080 Ti (GA102)",
    0x2504: "RTX 4090 (AD102)",
    0x2684: "RTX 4090 (AD102, другой)",
    0x2685: "RTX 4080 SUPER (AD103)",
    0x27B8: "RTX 5080 (GB202)",
}

WANT = [0x1E09, 0x220D, 0x248A, 0x2408, 0x1B06, 0x1B04, 0x2204, 0x220E,
        0x2504, 0x2684, 0x2685, 0x27B8]


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else r"X:\gsp_ga10x.bin"
    ctx_words = 8
    data = io.open(path, "rb").read()
    print("образ: %s" % path)
    print("размер: %d байт (%.1f МБ)" % (len(data), len(data) / 1048576.0))
    print("")

    # ---- 32-битный вид: 0x10DE0000 | dev  --------------------------------
    print("=" * 78)
    print("32-битные слова вида 0x10DExxxx (vendor=10DE, device=xxxx)")
    print("=" * 78)
    total32 = 0
    for dev in WANT:
        pat = struct.pack("<I", 0x10DE0000 | dev)
        offs, i = [], 0
        while True:
            i = data.find(pat, i)
            if i < 0:
                break
            offs.append(i)
            i += 1
        total32 += len(offs)
        tag = KNOWN.get(dev, "")
        print("0x%04X %-46s найдено: %d" % (dev, tag, len(offs)))
        for o in offs[:6]:
            lo = max(0, o - 16)
            words = struct.unpack_from("<8I", data, lo)
            ctx = " ".join("%08X" % w for w in words)
            mark = " <-- наш" if dev == 0x248A else ""
            print("     @0x%08X  ctx: %s%s" % (o, ctx, mark))
        if len(offs) > 6:
            print("     ... ещё %d" % (len(offs) - 6))
    print("")
    print("всего 32-битных совпадений: %d" % total32)

    # ---- кластеры: соседние ID в пределах окна ---------------------------
    print("")
    print("=" * 78)
    print("КЛАСТЕРЫ: области, где несколько РАЗНЫХ известных ID идут рядом")
    print("=" * 78)
    print("(признак whitelist: таблица, где device ID соседствуют)")
    print("")
    hits = []
    for dev in WANT:
        pat = struct.pack("<I", 0x10DE0000 | dev)
        i = 0
        while True:
            i = data.find(pat, i)
            if i < 0:
                break
            hits.append((i, dev))
            i += 1
    hits.sort()
    clusters, cur = [], [hits[0]] if hits else []
    for prev, nxt in zip(hits, hits[1:]):
        if nxt[0] - prev[0] <= 64:
            cur.append(nxt)
        else:
            if len(set(d for _, d in cur)) >= 3:
                clusters.append(cur)
            cur = [nxt]
    if len(set(d for _, d in cur)) >= 3:
        clusters.append(cur)

    if not clusters:
        print("кластеров из >=3 разных известных ID не найдено.")
        print("Это означает одно из двух:")
        print("  а) whitelist хранится не как 0x10DExxxx, а в другой форме;")
        print("  б) whitelist устроен как разреженный список (ID, флаг, ID, флаг),")
        print("     и соседние ID не обязаны стоять рядом.")
    for c in clusters[:20]:
        lo, hi = c[0][0], c[-1][0]
        devs = sorted(set(d for _, d in c))
        print("окно 0x%08X..0x%08X, %d находок, %d разных ID:"
              % (lo, hi, len(c), len(devs)))
        for d in devs:
            print("    0x%04X  %s" % (d, KNOWN.get(d, "")))
        lo2 = max(0, lo - 8)
        words = struct.unpack_from("<%dI" % ((hi - lo2) // 4 + 2), data, lo2)
        print("    сырые слова: %s"
              % " ".join("%08X" % w for w in words[:40]))
        print("")

    # ---- итого ----------------------------------------------------------
    print("=" * 78)
    print("ИТОГ")
    print("=" * 78)
    have = [d for d in WANT if struct.pack("<I", 0x10DE0000 | d) in data]
    missing = [d for d in WANT if struct.pack("<I", 0x10DE0000 | d) not in data]
    print("присутствуют как 0x10DExxxx: %s"
          % ", ".join("0x%04X(%s)" % (d, KNOWN.get(d, "?")[:14]) for d in have))
    print("отсутствуют:                   %s"
          % ", ".join("0x%04X(%s)" % (d, KNOWN.get(d, "?")[:14]) for d in missing))
    print("")
    if 0x248A in missing:
        print("0x248A (наша карта) ОТСУТСТВУЕТ в образе как 0x10DE248A.")
        print("Это согласуется с §D референса и объясняет FEAT_READOUT_0 bit8=0:")
        print("прошивка не знает нашу карту, поэтому PGRAPH не поднимает.")
        print("Следующий шаг - найти whitelist и понять его формат.")


if __name__ == "__main__":
    main()
