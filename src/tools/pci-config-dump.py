#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""pci-config-dump.py — чтение PCI config space карты через WinRing0.

Зачем
-----
Единственный способ узнать, что карта рекламирует, из Windows: прочитать
конфигурационное пространство напрямую. Ни NVML, ни nvidia-smi, ни
DEVPKEY_PciDevice_* этого не дают — DEVPKEY заполнены константой (замерено,
см. docs/70HX-XP3G-GATE-V67.md §4a.11.7), а NVML отдаёт агрегаты без
capability.

Про ABI: метод взят не с нуля, а из работающей реализации xrip/cmp50hx-unlock
(efi-unlock-windows/tools/50hxcore/regs.go), где тот же доступ применяется для
Gen2. Там и WinRing0, и код устройства `\\.\WinRing0_1_2_0`.

Что делает
---------
1. Читает dword по 0x00 (идентификация), 0x04 (Command|Status) и **0x34
   (Capabilities Pointer)**.
2. Обходит цепочку capabilities до 32 шагов, печатает ID и Next.
3. Находит PCIe Capability (ID 0x10) и печатает link-регистры:
       +0x0C LNKCAP   — Max Link Speed [3:0] (жёсткая проводка)
       +0x10 LNKCTL   — Retrain Link = бит 5
       +0x12 LNKSTA   — Current Link Speed [3:0], Width [9:4]
       +0x2C LNKCAP2  — read-only
       +0x30 LNKCTL2  — Target Link Speed [3:0]

Только чтение. Драйвер ставится как служба и после чтения удаляется, если не
был установлен ранее.

Запуск (от администратора, PowerShell):

    python src\\tools\\pci-config-dump.py `
        -Driver "C:\\path\\to\\WinRing0x64.sys" `
        -Bdf 01:00.0

WinRing0 должен быть WHQL-подписанной сборки (официальный релиз); иначе
Windows не загрузит его без тестового режима.
"""
import argparse
import ctypes
import struct
import subprocess
import sys

# WinRing0: CTL(fn,acc) = (40000<<16)|(acc<<14)|(fn<<2)
IOCTL_READ_PCI = (40000 << 16) | (1 << 14) | (0x851 << 2)
GENERIC_RW = 0xC0000000
OPEN_EXISTING = 3

SERVICE_NAME = "WinRing0_1_2_0"
DEVICE_PATH = "\\\\.\\" + SERVICE_NAME

SPEEDS = {0: "2.5GT/s (Gen1)", 1: "2.5GT/s (Gen1)", 2: "5GT/s (Gen2)",
          3: "8GT/s (Gen3)", 4: "16GT/s (Gen4)", 5: "32GT/s", 6: "64GT/s"}

CAP_NAMES = {
    0x01: "PM", 0x02: "AGP", 0x03: "VPD", 0x04: "SlotID", 0x05: "MSI",
    0x06: "Chipset", 0x07: "PCI-X", 0x08: "HyperTransport", 0x09: "Vendor",
    0x0A: "Debug", 0x0B: "CCRC", 0x0C: "HotPlug", 0x0D: "Bridge Subsys",
    0x0E: "AGP3", 0x0F: "Device Serial", 0x10: "PCIe", 0x11: "MSI-X",
    0x12: "SATA", 0x13: "AF", 0x14: "EA",
}


def speed_str(v):
    return SPEEDS.get(v & 0xF, "?%x" % (v & 0xF))


class WinRing0:
    def __init__(self, path):
        self.k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.h = self.k32.CreateFileW(DEVICE_PATH, GENERIC_RW, 0, None,
                                     OPEN_EXISTING, 0x80, None)
        if self.h == ctypes.c_void_p(-1).value or self.h is None:
            raise OSError("CreateFileW(%s) failed: winerr=%d — драйвер не "
                          "загружен или нет прав" % (DEVICE_PATH,
                                                    ctypes.get_last_error()))

    def rd32(self, bdf, reg):
        buf_in = struct.pack("<II", bdf, reg)
        buf_out = ctypes.create_string_buffer(4)
        got = ctypes.c_ulong(0)
        ok = self.k32.DeviceIoControl(self.h, IOCTL_READ_PCI,
                                      buf_in, len(buf_in),
                                      buf_out, 4,
                                      ctypes.byref(got), None)
        if not ok:
            raise OSError("DeviceIoControl(reg=0x%02x) failed: winerr=%d"
                          % (reg, ctypes.get_last_error()))
        return struct.unpack("<I", buf_out.raw)[0]

    def close(self):
        if self.h:
            self.k32.CloseHandle(self.h)


def sc(*args):
    return subprocess.run(("sc",) + args, capture_output=True, text=True)


def service_exists():
    r = sc("query", SERVICE_NAME)
    return "FAILED 1060" not in (r.stdout + r.stderr)


def install_driver(driver):
    if service_exists():
        print("[drv] служба %s уже есть — оставляем как есть" % SERVICE_NAME)
        return False
    r = sc("create", SERVICE_NAME, "type=", "kernel", "start=", "demand",
           "binPath=", driver)
    if r.returncode != 0:
        print("[drv] sc create не удался:\n" + r.stdout + r.stderr)
        return False
    r = sc("start", SERVICE_NAME)
    print("[drv] %s: %s" % (SERVICE_NAME, (r.stdout + r.stderr).strip()))
    return True


def remove_driver(created):
    if not created:
        return
    sc("stop", SERVICE_NAME)
    r = sc("delete", SERVICE_NAME)
    print("[drv] служба удалена: %s" % (r.stdout + r.stderr).strip())


def parse_bdf(text):
    bd, fn = text.split(".")
    bus, dev = (int(x, 16) for x in bd.split(":"))
    return (bus << 8) | (dev << 3) | int(fn, 16)


def dump(w, bdf, label):
    print("=" * 66)
    print("%s   BDF=%08x" % (label, bdf))
    print("=" * 66)

    ident = w.rd32(bdf, 0x00)
    vendor, device = ident & 0xFFFF, (ident >> 16) & 0xFFFF
    print("id      : vendor=%04X device=%04X" % (vendor, device))

    cmd_sta = w.rd32(bdf, 0x04)
    cmd, sta = cmd_sta & 0xFFFF, (cmd_sta >> 16) & 0xFFFF
    print("0x04    : raw=%08X  Command=%04X  Status=%04X" % (cmd_sta, cmd, sta))
    print("          Status[4] Capabilities List = %s"
          % ("ЕСТЬ" if sta & 0x10 else "НЕТ"))

    cap_raw = w.rd32(bdf, 0x34)
    cap = cap_raw & 0xFF
    print("0x34    : raw=%08X  CapPtr=0x%02X   <- правильный адрес CapPtr"
          % (cap_raw, cap))
    print()
    print("          ВНИМАНИЕ: наш find_pcie_cap() в src/unlock_v2.c читает")
    print("          CapPtr из байта 0x07 (старший байт dword@0x04), а не из")
    print("          0x34. Байт 0x07 — старший байт Status, он всегда 0,")
    print("          поэтому обход цепочки не мог начаться никогда.")
    print()

    if cap == 0:
        print("chain   : CapPtr == 0 -> цепочки нет")
        return

    print("--- цепочка capabilities ---")
    cur, seen, pcie = cap, set(), None
    for step in range(32):
        if cur < 0x40:
            print("  шаг %-2d: ptr=0x%02X — вне области, конец" % (step, cur))
            break
        if cur in seen:
            print("  шаг %-2d: ptr=0x%02X — зацикливание" % (step, cur))
            break
        seen.add(cur)
        dw = w.rd32(bdf, cur & ~3)
        off = cur & 3
        cid = (dw >> (off * 8)) & 0xFF
        nxt = (dw >> (off * 8 + 8)) & 0xFF
        nm = CAP_NAMES.get(cid, "?")
        mark = "   <== PCI Express" if cid == 0x10 else ""
        print("  шаг %-2d: ptr=0x%02X  ID=0x%02X %-16s Next=0x%02X%s"
              % (step, cur, cid, nm, nxt, mark))
        if cid == 0x10:
            pcie = cur
        if nxt == 0:
            break
        cur = nxt

    if pcie is None:
        print()
        print("PCIe capability (ID 0x10) в цепочке НЕТ")
        return

    print()
    print("--- link-регистры, база capability = 0x%02X ---" % pcie)

    lnkcap = w.rd32(bdf, pcie + 0x0C)
    maxgen = lnkcap & 0xF
    maxwid = (lnkcap >> 4) & 0x3F
    print("+0x0C LNKCAP   = 0x%08X" % lnkcap)
    print("       Max Link Speed [3:0] = %d (%s)  <-- ЖЁСТКАЯ ПРОВОДКА"
          % (maxgen, speed_str(maxgen)))
    print("       Max Link Width  [9:4] = %d" % maxwid)

    lnkctl = w.rd32(bdf, pcie + 0x10)
    print("+0x10 LNKCTL   = 0x%08X   (Retrain Link bit5 = %d)"
          % (lnkctl, (lnkctl >> 5) & 1))

    lnksta = w.rd32(bdf, pcie + 0x12)
    curgen = lnksta & 0xF
    curwid = (lnksta >> 4) & 0x3F
    print("+0x12 LNKSTA   = 0x%08X" % lnksta)
    print("       Current Link Speed [3:0] = %d (%s)"
          % (curgen, speed_str(curgen)))
    print("       Negotiated Width  [9:4]  = %d" % curwid)

    lnkcap2 = w.rd32(bdf, pcie + 0x2C)
    print("+0x2C LNKCAP2  = 0x%08X   (read-only)" % lnkcap2)

    lnkctl2 = w.rd32(bdf, pcie + 0x30)
    print("+0x30 LNKCTL2  = 0x%08X   Target Link Speed [3:0] = %d"
          % (lnkctl2, lnkctl2 & 0xF))
    print()
    print("ВЕРДИКТ: кремний рекламирует максимум %s." % speed_str(maxgen))
    if maxgen < 2:
        print("         Со стороны устройства Gen2 невозможен: LNKCAP[3:0] —")
        print("         поле HwInit, в софте не меняется.")
    else:
        print("         Потолок не кремниевый — Gen2 достижим, вопрос только")
        print("         в маршруте и в TLS/retrain.")


def safe_rd32(w, bdf, reg, default=0xFFFFFFFF):
    """WinRing0 отказывает на отсутствующих устройствах — это норма, не сбой."""
    try:
        return w.rd32(bdf, reg)
    except OSError:
        return default


def find_upstream(w, target_bus):
    """Ищет на шине 0 мост (class 0604), у которого Secondary Bus == target."""
    for dev in range(32):
        for fn in range(8):
            bdf = (0 << 8) | (dev << 3) | fn
            ident = safe_rd32(w, bdf, 0x00)
            if ident == 0xFFFFFFFF or not (ident & 0xFFFF):
                continue
            cls = (safe_rd32(w, bdf, 0x08) >> 24) & 0xFF
            sub = (safe_rd32(w, bdf, 0x08) >> 16) & 0xFF
            if cls != 0x06 or sub != 0x04:
                continue
            hdr = safe_rd32(w, bdf, 0x0C) & 0xFF
            if hdr not in (0x00, 0x01):
                continue
            # 0x18 = Primary, 0x19 = Secondary, 0x1A = Subordinate
            hdr18 = safe_rd32(w, bdf, 0x18)
            sec = (hdr18 >> 8) & 0xFF
            if sec == target_bus:
                return bdf
    return None


def main():
    ap = argparse.ArgumentParser(description="PCI config dump через WinRing0")
    ap.add_argument("-Driver", required=True, help="путь к WinRing0x64.sys")
    ap.add_argument("-Bdf", default="01:00.0", help="BDF устройства")
    ap.add_argument("-AlsoBridge", default="", help="BDF апстрим-моста")
    ap.add_argument("-FindUpstream", action="store_true",
                    help="найти и вывести апстрим-мост автоматически")
    ap.add_argument("-Keep", action="store_true",
                    help="не удалять службу после чтения")
    a = ap.parse_args()

    created = install_driver(a.Driver)
    try:
        w = WinRing0(a.Driver)
        try:
            dump(w, parse_bdf(a.Bdf), "GPU")
            up = parse_bdf(a.AlsoBridge) if a.AlsoBridge else None
            if a.FindUpstream:
                found = find_upstream(w, parse_bdf(a.Bdf) >> 8)
                if found is None:
                    print()
                    print("UPSTREAM: мост с Secondary Bus == %02X не найден"
                          % (parse_bdf(a.Bdf) >> 8))
                else:
                    up = found
            if up is not None:
                print()
                dump(w, up, "UPSTREAM BRIDGE")
        finally:
            w.close()
    finally:
        if not a.Keep:
            remove_driver(created)
    return 0


if __name__ == "__main__":
    sys.exit(main())