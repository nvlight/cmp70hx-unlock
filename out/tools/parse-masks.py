# SPDX-License-Identifier: GPL-2.0-only
"""Разбор строк G2RMK из лога EFI: какие маски открылись, какие нет.

Нужен потому, что сам лог по устройству ASCII: log_putc() заменяет
всё вне 0x20..0x7E на '?', поэтому русский текст в нём необратим. Фильтровать
строки по словам («ОТКРЫТА», «заперта») бессмысленно — остаются одни '?'.
Разбирать надо по значениям, которые в логе сохранились.
"""
import io
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else r"out\usb-log-e1fam.txt"

# «0x00088FE8 ????? 0xFFFFFFFF ??????? (polls=0)» — берём адрес и результат
pat = re.compile(r"0x([0-9A-Fa-f]{8})\s+\?+\s+0x([0-9A-Fa-f]{8})")
# «ДО  0x00088FE8 = 0xFFFFFFCF» — исходное значение
pat_before = re.compile(r"0x([0-9A-Fa-f]{8})\s*=\s*0x([0-9A-Fa-f]{8})")

lines = io.open(path, encoding="utf-8", errors="replace").read().split("\n")

before, after = {}, {}
for ln in lines:
    if "G2RMK" not in ln:
        continue
    m = pat.search(ln)
    if m:
        after[m.group(1).upper()] = m.group(2).upper()
    m2 = pat_before.search(ln)
    if m2:
        before[m2.group(1).upper()] = m2.group(2).upper()

rows = []
for a in sorted(set(before) | set(after)):
    b = before.get(a, "-")
    c = after.get(a, "-")
    rows.append((a, b, c))

print("%-12s %-12s %-12s" % ("адрес", "ДО", "ПОСЛЕ"))
print("-" * 40)
locked = []
for a, b, c in rows:
    mark = ""
    if c == "FFFFFFFF":
        mark = "ОТКРЫТА"
    elif c != "-":
        mark = "ЗАПЕРТА"
        locked.append(a)
    print("0x%s  0x%s  0x%s  %s" % (a, b, c, mark))

print()
print("всего адресов: %d | открыто: %d | заперто: %d"
      % (len(rows), len(rows) - len(locked), len(locked)))
if locked:
    print("заперты: " + ", ".join("0x" + x for x in locked))
    for a in locked:
        if before.get(a):
            x = int(before[a], 16)
            print("   0x%s было 0x%s -> XOR с FF = 0x%08X, заперты биты %s"
                  % (a, before[a], x ^ 0xFFFFFFFF,
                     [b for b in range(32) if x ^ 0xFFFFFFFF & (1 << b)]))
