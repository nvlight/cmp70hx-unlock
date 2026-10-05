# SPDX-License-Identifier: GPL-2.0-only
"""Поиск по комментариям и строкам реверсеров внутри .i64 (IDA IDB64).

Зачем. База IDA оказалась гораздо богаче, чем просто код: внутри 381 475
ascii-строк есть комментарии реверсеров — уже с разбором RM-контролов.
Это самый быстрый способ понять, ЧТО именно ломает PGRAPH, вместо того
чтобы гадать по регистрам.

Что ищем, по убыванию приоритета:
  * whitelist / device id / device-id  - механизм, на который ссылался
    референс как на причину отключения PGRAPH;
  * pgraph / pg_ / graphics enable     - что включает графику;
  * feat_ovr / feat_ovr_plm / featoverride - наш же путь;
  * 0xe037b0                            - конкретный адрес из §D референса.

Формат: печатаем строки целиком (с контекстом), помечая те, где есть
адрес или ключевое слово. Строки у IDA часто длинные — это нормально,
именно в них ценность.
"""
import io
import re
import sys

GROUPS = [
    ("WHITELIST / device id", re.compile(
        r"(?i)(white.?list|device.?id|devid|deviceid|0x10de|0x248a|0x220d|0x1e09)")),
    ("PGRAPH / graphics enable", re.compile(
        r"(?i)(pgraph|pg_|graphics.?enable|enable.?graphics|graphics.?off|"
        r"render.?enable|gr_?enable)")),
    ("FEAT / PLM (наш путь)", re.compile(
        r"(?i)(feat_?ovr|featoverride|feat.?readout|0x823804|0x823830|"
        r"0x823800|0x823b04|0x8e1b)")),
    ("АДРЕС 0xe037b0 из §D", re.compile(
        r"(?i)(0xe037b0|e037b0)")),
    ("GFX / GFX_SPEED", re.compile(
        r"(?i)(gfx.?speed|gfxselect|gfx_select|0x823830)")),
    ("XVE", re.compile(r"(?i)(xve)")),
]

ASCII = re.compile(rb"[ -~]{12,}")


def main():
    path = sys.argv[1]
    data = io.open(path, "rb").read()
    print("файл: %s (%.1f МБ)" % (path, len(data) / 1048576.0))
    print("")

    strs = [(m.start(), m.group().decode("ascii", "replace"))
            for m in ASCII.finditer(data)]
    print("ascii-строк >=12 симв.: %d" % len(strs))
    print("")

    for title, rx in GROUPS:
        print("=" * 78)
        print(title)
        print("=" * 78)
        hits = [(off, s) for off, s in strs if rx.search(s)]
        print("найдено: %d" % len(hits))
        seen = set()
        shown = 0
        for off, s in hits:
            key = s[:120]
            if key in seen:
                continue
            seen.add(key)
            print("  @0x%08X" % off)
            # печатаем строку, переносы — на 100 символов с отступом
            w = 100
            for i in range(0, min(len(s), 600), w):
                print("      %s" % s[i:i + w])
            if len(s) > 600:
                print("      ... (строка %d симв.)" % len(s))
            shown += 1
            if shown >= 15:
                print("  ... ещё %d уникальных" % (len(seen) - shown))
                break
        print("")


if __name__ == "__main__":
    main()
