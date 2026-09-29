"""Как вообще лежат device ID в GSP-образе.

Контекст. Гипотеза «PGRAPH отключён whitelist'ом device ID в GSP» пришла из
референса (§D: *whitelist device-ID @ firmware 0xe037b0 не содержит 0x220D*).
Проверка на нашем образе gsp_ga10x.bin дала НОЛЬ вхождений 0x10DExxxx для
двенадцати известных ID — включая те, что заведомо работают (RTX 3070 Ti,
RTX 4090). Значит либо формат хранения другой, либо гипотеза неверна.

Этот скрипт ищет ID во всех разумных представлениях и показывает реальные
находки, чтобы вывод делать по фактам, а не по догадке:

  1. 32-битное слово 0x10DExxxx        - vendor+device в одном dword
  2. 16-битное значение 0x248A         - device ID без vendor
  3. 16-битное значение 0x10DE         - vendor отдельно
  4. байтовые пары, разделённые мусором - если ID зашит невыровненно
  5. ASCII-строки "248A" / "10DE248A" - если таблица текстовая

Важно про интерпретацию. Находка 16-битного 0x248A в 80 МБ НИЧЕГО не
доказывает: это два байта, они встречаются тысячи раз. Поэтому для каждой
находки печатается окружение, и вывод делается по картине, а не по счёту.
"""
import io
import re
import struct
import sys

IDS = {
    0x248A: "CMP 70HX (наша)",
    0x220D: "CMP 90HX",
    0x1E09: "CMP 50HX",
    0x2408: "RTX 3070 Ti",
    0x1B06: "RTX 3080",
    0x1B04: "RTX 3070",
    0x2204: "RTX 3090",
    0x220E: "RTX 3080 Ti",
    0x2504: "RTX 4090",
    0x2684: "RTX 4090 (AD102)",
    0x2685: "RTX 4080 SUPER",
    0x27B8: "RTX 5080",
}
VENDOR = 0x10DE


def ctx32(data, off, before=6, after=10):
    lo = max(0, off - before * 4)
    hi = min(len(data), off + after * 4)
    n = (hi - lo) // 4
    words = struct.unpack_from("<%dI" % n, data, lo)
    out, hit = [], off // 4
    for i, w in enumerate(words):
        mark = "<<" if (lo // 4 + i) == hit else "  "
        out.append("%08X%s" % (w, mark))
    return " ".join(out)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else r"X:\gsp_ga10x.bin"
    data = io.open(path, "rb").read()
    print("образ : %s" % path)
    print("размер: %d байт (%.1f МБ)" % (len(data), len(data) / 1048576.0))
    print("")

    # ---------- 1. 32-бит 0x10DExxxx ------------------------------------
    print("=" * 78)
    print("1) 32-битное слово 0x10DExxxx")
    print("=" * 78)
    tot = 0
    for dev, name in IDS.items():
        pat = struct.pack("<I", VENDOR << 16 | dev)
        n = data.count(pat)
        tot += n
        print("  0x%04X %-22s : %d" % (dev, name, n))
    print("  ИТОГО: %d" % tot)
    print("")

    # ---------- 2. 16-бит device ID --------------------------------------
    print("=" * 78)
    print("2) 16-битное значение device ID (выравнено и невыровнено)")
    print("=" * 78)
    for dev, name in IDS.items():
        pat = struct.pack("<H", dev)
        n = data.count(pat)
        n_al = 0
        o = 0
        while True:
            o = data.find(pat, o)
            if o < 0:
                break
            if o % 4 == 0:
                n_al += 1
            o += 1
        print("  0x%04X %-22s всего %7d, из них по 4-байтному выравниванию %6d"
              % (dev, name, n, n_al))
    print("")
    print("  ВНИМАНИЕ: счётчики сами по себе ничего не значат — два байта в")
    print("  80 МБ встречаются тысячи раз. Смотрим картину ниже.")
    print("")

    # ---------- 3. vendor отдельно ---------------------------------------
    print("=" * 78)
    print("3) vendor 0x10DE отдельно (16 и 32 бита)")
    print("=" * 78)
    print("  0x10DE как 16-бит : %d" % data.count(struct.pack("<H", VENDOR)))
    print("  0x000010DE как dword: %d" % data.count(struct.pack("<I", VENDOR)))
    print("  ASCII '10DE'      : %d" % len(re.findall(rb"10DE", data)))
    print("")

    # ---------- 4. ASCII-строки ------------------------------------------
    print("=" * 78)
    print("4) ASCII-следы device ID")
    print("=" * 78)
    for dev, name in IDS.items():
        hx = ("%04X" % dev).lower()
        hU = ("%04X" % dev)
        c1 = len(re.findall(hx.encode(), data))
        c2 = len(re.findall(hU.encode(), data))
        c3 = len(re.findall(("10DE" + hx).lower().encode(), data))
        if c1 or c2 or c3:
            print("  0x%04X %-22s '%s'=%d '%s'=%d '10DE%s'=%d"
                  % (dev, name, hx, c1, hU, c2, hx, c3))
    print("  (пусто = ни одного ASCII-следа)")
    print("")

    # ---------- 5. наш ID в контексте, выравненные ----------------------
    print("=" * 78)
    print("5) 0x248A по 4-байтному выравниванию: окружения")
    print("=" * 78)
    pat = struct.pack("<H", 0x248A)
    shown, o, cnt = 0, 0, 0
    while shown < 12:
        o = data.find(pat, o)
        if o < 0:
            break
        if o % 4 == 0:
            cnt += 1
            print("  @0x%08X  %s" % (o, ctx32(data, o)))
            shown += 1
        o += 1
    print("  всего выравненных: %d, показано %d" % (cnt, shown))
    print("")

    # ---------- 6. вывод -------------------------------------------------
    print("=" * 78)
    print("ВЫВОД")
    print("=" * 78)
    d32 = sum(data.count(struct.pack("<I", VENDOR << 16 | d)) for d in IDS)
    if d32 == 0:
        print("Ни одного 32-битного 0x10DExxxx из списка. При том что в списке")
        print("есть ID заведомо работающих карт (3070 Ti, 4090), гипотеза")
        print("'whitelist как массив 0x10DExxxx' в этом образе НЕ подтверждается.")
        print("")
        print("Возможные объяснения, по убыванию правдоподобия:")
        print("  а) ID сравниваются по маске или хешу, а не как полное слово;")
        print("  б) whitelist лежит в другом образе (например, в vbios/фузе),")
        print("     а не в gsp_ga10x.bin;")
        print("  в) отключение PGRAPH привязано к FEAT/привилегиям, а не к ID;")
        print("  г) референс описывал 90HX, у нас другой путь блокировки.")
        print("")
        print("Что это значит практически: патчить образ GSP по ID пока нечего —")
        print("нет ни одного места, где можно было бы заменить 0x248A на что-то.")
    else:
        print("Есть %d вхождений — нужен разбор кластеров." % d32)


if __name__ == "__main__":
    main()
