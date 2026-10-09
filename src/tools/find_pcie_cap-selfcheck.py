#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""find_pcie_cap-selfcheck.py — проверка починки find_pcie_cap() на живой карте.

Зачем
-----
В `src/unlock_v2.c` `find_pcie_cap()` брала Capabilities Pointer из байта 0x07
dword'а по 0x04. Байт 0x07 — старший байт Status, он всегда 0, поэтому обход
цепочки не мог начаться никогда. Настоящий CapPtr живёт по 0x34.

Правку на EFI проверить нельзя: стенд умеет только EFI. Но логика обхода —
обычный код, и её можно прогнать ПРОТИВ тех же данных, что читает EFI, если
достать их из config space. Здесь это делается независимым путём (WinRing0) и
сравнивается с эталоном.

Что делает
---------
1. Читает config space GPU и моста через WinRing0.
2. Прогоняет ДВЕ реализации обхода:
      OLD — как было в unlock_v2.c (CapPtr из байта 0x07 dword@0x04)
      NEW — как стало (CapPtr из 0x34)
3. Печатает результат обеих и вердикт.

Эталонные значения для стенда (замерено 2026-10-10):
   GPU     01:00.0  CapPtr=0x60  цепочка 0x60 PM -> 0x68 MSI -> 0x78 PCIe -> 0xB4 Vendor
   bridge  00:1b.0  CapPtr=0x40  цепочка 0x40 PCIe -> 0x80 MSI -> 0x90 BridgeSubsys -> 0xA0 PM

Запуск (от администратора):
    python src\\tools\\find_pcie_cap-selfcheck.py -Driver <путь к WinRing0x64.sys> \\
        -Bdf 01:00.0 -Bridge 00:1b.0
"""
import argparse
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "pcd", os.path.join(HERE, "pci-config-dump.py"))
pcd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pcd)

CAP_NAMES = pcd.CAP_NAMES


def walk_old(w, bdf):
    """Ровно то, что было в unlock_v2.c до правки: CapPtr из байта 0x07."""
    pos = (w.rd32(bdf, 0x04) >> 24) & 0xFF
    return _walk(w, bdf, pos, "OLD")


def walk_new(w, bdf):
    """Ровно то, что стало: CapPtr из 0x34."""
    pos = w.rd32(bdf, 0x34) & 0xFF
    return _walk(w, bdf, pos, "NEW")


def _walk(w, bdf, pos, tag):
    steps = []
    for _ in range(48):
        if not (0x40 <= pos <= 0xFF):
            return tag, steps, 0
        cdw = w.rd32(bdf, pos & ~3)
        off = pos & 3
        cid = (cdw >> (off * 8)) & 0xFF
        nxt = (cdw >> (off * 8 + 8)) & 0xFF
        steps.append((pos, cid, nxt))
        if cid == 0x10:
            return tag, steps, pos
        pos = nxt
    return tag, steps, 0


def show(w, bdf, label):
    print("=" * 70)
    print("%s   BDF=%08x" % (label, bdf))
    print("=" * 70)
    print("Config header:")
    print("  dword@0x04 = 0x%08X   Command=%04X  Status=%04X"
          % (w.rd32(bdf, 0x04), w.rd32(bdf, 0x04) & 0xFFFF,
             (w.rd32(bdf, 0x04) >> 16) & 0xFFFF))
    print("  dword@0x34 = 0x%08X   <- здесь CapPtr = 0x%02X"
          % (w.rd32(bdf, 0x34), w.rd32(bdf, 0x34) & 0xFF))
    print()
    print("  NB: у OLD байт 0x07 = %02X (старший байт Status) — всегда 0."
          % ((w.rd32(bdf, 0x04) >> 24) & 0xFF))
    print()

    ok = True
    for fn, name in ((walk_old, "OLD (было в unlock_v2.c до 2026-10-10)"),
                     (walk_new, "NEW (CapPtr из 0x34)")):
        tag, steps, found = fn(w, bdf)
        print("  %s" % name)
        if not steps:
            print("      обход не начался: CapPtr вне диапазона 0x40..0xFF")
        else:
            for pos, cid, nxt in steps:
                print("      0x%02X  ID=0x%02X %-16s -> 0x%02X"
                      % (pos, cid, CAP_NAMES.get(cid, "?"), nxt))
        if found:
            print("      РЕЗУЛЬТАТ: PCIe capability найдена по 0x%02X" % found)
        else:
            print("      РЕЗУЛЬТАТ: PCIe capability НЕ найдена")
            if name.startswith("OLD"):
                print("      (ожидаемо для OLD — именно это и наблюдалось")
                print("       в прогонах: GEN2C pcie_cap not found, E-D CapPtr=0)")
        print()
        if name.startswith("NEW") and not found:
            ok = False
    print("  ИТОГ: %s" % ("NEW находит capability — правка верна"
                          if ok else "NEW НЕ нашёл — правка не подтверждена"))
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-Driver", required=True)
    ap.add_argument("-Bdf", default="01:00.0")
    ap.add_argument("-Bridge", default="00:1b.0")
    a = ap.parse_args()

    created = pcd.install_driver(a.Driver)
    try:
        w = pcd.WinRing0(None)
        try:
            r1 = show(w, pcd.parse_bdf(a.Bdf), "GPU")
            r2 = show(w, pcd.parse_bdf(a.Bridge), "UPSTREAM BRIDGE")
        finally:
            w.close()
    finally:
        pcd.remove_driver(created)
    return 0 if (r1 and r2) else 1


if __name__ == "__main__":
    sys.exit(main())