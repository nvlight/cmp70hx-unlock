#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""bar0-read.py — чтение BAR0 карты из работающей Windows через ThrottleStop.

Зачем
-----
`docs/REGISTERS.md:49` фиксирует: запись в `LC2 TLS` через BAR0 под живым GSP
отбрасывается — писать можно только до загрузки ОС. Значит из Windows BAR0
недоступен для ПРАВОК. Но прочитать его можно, и это нужно: расхождение между
`config LNKCAP = 0x00453D01` (nibble 1 = Gen1) и BAR0-зеркалом
`0x88084 = 0x00453D02` (nibble 2 = Gen2) решается чтением, а не записью.

Кто это умеет
-------------
Драйвер `ThrottleStop.sys` (TechPowerUp, подпись WHQL — Status: Valid,
проверено 2026-10-10) даёт канал произвольной физической памяти:
    чтение  ioctl 0x80006498, in = <u64 physAddr>, out <= 8 байт
    запись  ioctl 0x8000649C, in = <u64 physAddr><data>
Устройство: `\\\\.\\ThrottleStop`

ABI взят НЕ с нуля: из `efi-unlock-windows/tools/50hxcore/tsdrv.go`
(xrip/cmp50hx-unlock), где тот же драйвер используется для Gen2. Там же
отмечено, что модуль «wraps read only — no writes», и по соображениям
безопасности здесь сделано так же: см. класс ниже.

Почему класс `ThrottleStop` ничего не пишет
------------------------------------------
Обёртка `Bar0` содержит только `read32`. Записи нет НЕ из осторожности
инструмента, а потому что проект по Gen2 пока не решил, кто управляет
фактической скоростью линка (см. §4a.11.8). Писать в BAR0 карты до решения
этого вопроса — значит гадать, какой из двух регистров вообще имеет смысл
трогать.

Базовый адрес берётся из BAR0 в PCI config space (offset 0x10), читается
WinRing0 — так же, как в `pci-config-dump.py`.

Запуск (от администратора):

    python src\\tools\\bar0-read.py -Driver <ThrottleStop.sys> -Bdf 01:00.0
"""
import argparse
import ctypes
import struct
import sys

GENERIC_RW = 0xC0000000
OPEN_EXISTING = 3

IOCTL_TS_READ = 0x80006498

SVC_TS = "ThrottleStop"
DEV_TS = "\\\\.\\" + SVC_TS

# Что смотрим. Адреса — BAR0-смещения из docs/REGISTERS.md и unlock_v2.c.
WATCH = [
    (0x00088084, "LINK_CAP", "Gen2-зеркало; nibble[3:0] = скорость"),
    (0x000880A8, "LC2 TLS", "зеркало LNKCTL2; под живым GSP запись отбрасывается"),
    (0x00088088, "LNKSTA mirror", "[31:16] = LNKSTA: [3:0] скорость, [9:4] ширина"),
    (0x0008872C, "LTSSM_OVR", "кик LTSSM, xrip пишет 6"),
    (0x0008C040, "LINK_CONFIG_0", "MAX_RATE[19:18]"),
    (0x0008C1C0, "PL_LINK_RATE", "xrip: 0x00040000"),
    (0x0008C2C0, "CYA_0", "bit2"),
    (0x0008841C, "PRIV_MISC_1", "Gen2_EN биты 11,13"),
    (0x00088610, "VSEC_HIERARCHY", "бит 12"),
    (0x0008E110, "XP3G_OVR0", "1"),
    (0x0008E120, "XP3G_VAL0", "0"),
    (0x0008E1B0, "XP3G PLM gate", "0xFFFFFFFF = открыт"),
    (0x00823800, "PLM FEAT", "маска рендера"),
    (0x00823804, "PLM SS page", "открывается первым"),
    (0x0082381C, "SS0", "главный compute-селектор"),
    (0x00823820, "SS1", "пара к SS0"),
    (0x00823B04, "PLM gfx", "маска рендера"),
    (0x00823B30, "GFX_SPEED_SELECT", "главный рычаг рендера"),
    (0x0008E1DC, "XVE_D*", "статусное семейство"),
]


def _sc(*args):
    import subprocess
    return subprocess.run(("sc",) + args, capture_output=True, text=True)


def svc_exists(name):
    r = _sc("query", name)
    return "FAILED 1060" not in (r.stdout + r.stderr)


def install_service(driver, name=SVC_TS):
    if svc_exists(name):
        print("[drv] служба %s уже есть — оставляем" % name)
        return False
    r = _sc("create", name, "type=", "kernel", "start=", "demand",
            "binPath=", driver)
    if r.returncode != 0:
        print("[drv] sc create не удался:\n" + r.stdout + r.stderr)
        return False
    r = _sc("start", name)
    print("[drv] %s: %s" % (name, (r.stdout + r.stderr).strip().splitlines()[0]))
    return True


def remove_service(created, name=SVC_TS):
    if not created:
        return
    _sc("stop", name)
    _sc("delete", name)
    print("[drv] служба %s удалена" % name)


class ThrottleStop:
    """Только чтение физической памяти. Метода записи нет намеренно."""

    def __init__(self):
        self.k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.h = self.k32.CreateFileW(DEV_TS, GENERIC_RW, 0, None,
                                     OPEN_EXISTING, 0x80, None)
        if self.h == ctypes.c_void_p(-1).value or self.h is None:
            raise OSError("CreateFileW(%s): winerr=%d — драйвер не загружен "
                          "или нет прав" % (DEV_TS, ctypes.get_last_error()))

    def read32(self, phys):
        ib = struct.pack("<Q", phys)
        ob = ctypes.create_string_buffer(4)
        got = ctypes.c_ulong(0)
        ok = self.k32.DeviceIoControl(self.h, IOCTL_TS_READ,
                                      ib, len(ib), ob, 4,
                                      ctypes.byref(got), None)
        if not ok:
            raise OSError("ioctl READ phys=0x%x: winerr=%d"
                          % (phys, ctypes.get_last_error()))
        return struct.unpack("<I", ob.raw)[0]

    def close(self):
        if self.h:
            self.k32.CloseHandle(self.h)


def read_bar0_base(bdf, ts):
    """BAR0 base from config space, via WinRing0 (see pci-config-dump.py).

    The WinRing0 service is installed here and removed again afterwards:
    whoever creates a service must also remove it. The driver path is taken
    from the folder that holds ThrottleStop.sys.
    """
    import importlib.util
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    spec = importlib.util.spec_from_file_location(
        "pcd", os.path.join(here, "pci-config-dump.py"))
    pcd = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pcd)

    winring0 = os.path.join(os.path.dirname(ts.driver_path), "WinRing0x64.sys")
    if not os.path.isfile(winring0):
        raise SystemExit("no WinRing0x64.sys next to ThrottleStop.sys: %s"
                         % winring0)

    created = pcd.install_driver(winring0)
    try:
        w = pcd.WinRing0(None)
        try:
            raw = w.rd32(bdf, 0x10)
        finally:
            w.close()
    finally:
        pcd.remove_driver(created)

    if raw == 0xFFFFFFFF:
        raise SystemExit("BAR0 is not mapped (command 0 / no driver bound)")
    return raw & 0xFFFFFFF0

def main():
    ap = argparse.ArgumentParser(description="чтение BAR0 через ThrottleStop")
    ap.add_argument("-Driver", required=True, help="путь к ThrottleStop.sys")
    ap.add_argument("-Bdf", default="01:00.0")
    ap.add_argument("-Only", default="", help="читать один адрес, напр. 0x88084")
    a = ap.parse_args()

    def bdf(s):
        bd, fn = s.split(".")
        bus, dev = (int(x, 16) for x in bd.split(":"))
        return (bus << 8) | (dev << 3) | int(fn, 16)

    b = bdf(a.Bdf)

    created = install_service(a.Driver)
    ts = ThrottleStop()
    ts.driver_path = a.Driver
    try:
        base = read_bar0_base(b, ts)
        print()
        print("=" * 68)
        print("BAR0 @ %s   физический базис = 0x%08X"
              % (a.Bdf, base))
        print("=" * 68)
        print()

        if a.Only:
            rows = [(int(a.Only, 0), "запрошено", "")]
        else:
            rows = WATCH

        for off, name, note in rows:
            try:
                v = ts.read32(base + off)
            except OSError as e:
                print("0x%08X  %-16s ОШИБКА: %s" % (off, name, e))
                continue
            print("0x%08X  %-16s = 0x%08X   %s" % (off, name, v, note))

        print()
        print("ЗАПИСЬ НЕ РЕАЛИЗОВАНА. См. докстринг: сначала нужно решить,")
        print("кто управляет скоростью — config LNKCAP (nibble 1) или BAR0")
        print("0x88084 (nibble 2). Пока не решено, писать некуда осмысленно.")
    finally:
        ts.close()
        remove_service(created)
    return 0


if __name__ == "__main__":
    sys.exit(main())