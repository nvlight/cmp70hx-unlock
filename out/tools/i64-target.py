"""Прицельный разбор вокруг двух находок из базы IDA.

Находки из i64-mine.py:
  * aRmdevidcheckig              - функция проверки device ID
  * GrEnableGfxpControlBuffer... - функция включения графики (Gfxp)
  * pGraphicsFeatureState        - состояние графики

Плюс комментарий реверсера про RMPcieLinkSpeed, где перечислены НАШИ адреса
(0x880a8, 0x8841c, 0x8c040, 0x8c1c0, 0x8c2c0) - это независимое
подтверждение, что наш Gen2-рецепт взят из этой прошивки, а не выдуман.

Скрипт печатает ВСЕ строки базы, содержащие эти имена, плюс соседние по
смещению (в IDB имена функций лежат рядом с их комментариями).
"""
import io
import re
import sys

KEYS = [
    "devidcheck", "devid", "dev_id", "deviceid",
    "GrEnableGfxp", "GfxpControl", "pGraphicsFeatureState",
    "RMPcieLinkSpeed", "GraphicsManager", "EnableGfx",
]

ASCII = re.compile(rb"[ -~]{8,}")


def main():
    path = sys.argv[1]
    data = io.open(path, "rb").read()

    strs = [(m.start(), m.group().decode("ascii", "replace"))
            for m in ASCII.finditer(data)]
    # индекс по смещению для окрестностей
    offs = [o for o, _ in strs]

    def window(center, radius=4000):
        out = []
        for o, s in strs:
            if abs(o - center) <= radius:
                out.append((o, s))
        return out

    for key in KEYS:
        hits = [(o, s) for o, s in strs if key.lower() in s.lower()]
        print("=" * 78)
        print("КЛЮЧ: %s   (вхождений: %d)" % (key, len(hits)))
        print("=" * 78)
        if not hits:
            print("  нет")
            print("")
            continue
        for o, s in hits[:4]:
            print("  @0x%08X" % o)
            w = 96
            for i in range(0, min(len(s), 900), w):
                print("      %s" % s[i:i + w])
            if len(s) > 900:
                print("      ... (всего %d симв.)" % len(s))
            # соседи по базе
            near = window(o, 1200)
            if len(near) > 1:
                print("      --- соседи по смещению (±1200) ---")
                for no, ns in near[:8]:
                    if abs(no - o) < 4:
                        continue
                    t = ns[:150]
                    print("      @0x%08X %s" % (no, t))
            print("")
        print("")


if __name__ == "__main__":
    main()
