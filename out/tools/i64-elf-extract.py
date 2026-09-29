"""Что можно вытащить из .i64 без IDA.

Контекст. Скачали gsp_tu10x_610.43.03.elf.i64 (217 774 732 байта, LFS-хеш
совпал). Формат — IDB64, проприетарный и сжатый, открыть его без IDA нельзя.
Но внутри базы IDA лежит ИСХОДНЫЙ файл, который анализировали: ELF-образ
GSP-прошивки TU102 (50HX). Если найти его границы, получим настоящий
firmware-image и сможем искать в нём структуры так же, как в нашем
gsp_ga10x.bin.

Что делаем:
  1. ищем магию \x7fELF — начало исходного ELF;
  2. читаем заголовок ELF: тип, машина, точка входа, число программных
     заголовков и их смещения (это даёт размер исходника);
  3. ищем читаемые строки (имена функций/секций IDA иногда хранятся plainly);
  4. ищем device ID в найденном ELF тем же методом, что и в нашем образе.

Зачем 4: если в TU102-прошивке есть таблица device ID, а в GA10x-прошивке
(наш образ) её нет — это укажет, где именно искать в GA10x, и как её
должно выглядеть. Если её нет и там, гипотеза whitelist'а закрывается
окончательно.
"""
import io
import re
import struct
import sys

ELF_MAGIC = b"\x7fELF"
IDB_MAGIC = b"IDA2"


def find_all(data, pat, limit=64):
    out, i = [], 0
    while len(out) < limit:
        i = data.find(pat, i)
        if i < 0:
            break
        out.append(i)
        i += 1
    return out


def parse_elf(data, off):
    """Разбор заголовка ELF64 по смещению off. Возвращает dict или None."""
    if off + 64 > len(data):
        return None
    if data[off:off + 4] != ELF_MAGIC:
        return None
    ei_class = data[off + 4]
    ei_data = data[off + 5]
    if ei_class != 2 or ei_data != 1:
        return None  # ждём ELF64 little-endian
    (e_type, e_machine, _ver, e_entry, e_phoff, e_shoff, _flags,
     e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
     e_shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", data, off + 16)

    # размер образа = конец последней секции или program header
    end = off + 64
    if e_shoff and e_shnum:
        end = max(end, e_shoff + e_shnum * e_shentsize)
    if e_phoff and e_phnum:
        end = max(end, e_phoff + e_phnum * e_phentsize)
    return {
        "off": off, "type": e_type, "machine": e_machine,
        "entry": e_entry, "phoff": e_phoff, "shoff": e_shoff,
        "phnum": e_phnum, "shnum": e_shnum,
        "hdr_end": end,
    }


def main():
    path = sys.argv[1]
    data = io.open(path, "rb").read()
    print("файл   : %s" % path)
    print("размер : %d байт (%.1f МБ)" % (len(data), len(data) / 1048576.0))
    print("")

    print("=" * 78)
    print("1) магия IDB в начале")
    print("=" * 78)
    print("  первые 4 байта: %r  -> %s"
          % (data[:4], "IDB64 (IDA)" if data[:4] == IDB_MAGIC else "не IDB"))
    print("")

    print("=" * 78)
    print("2) поиск ELF внутри базы")
    print("=" * 78)
    offs = find_all(data, ELF_MAGIC, limit=40)
    print("  вхождений \\x7fELF: %d%s" % (len(offs),
          "" if len(offs) < 40 else " (обрезано)"))
    for o in offs[:20]:
        h = parse_elf(data, o)
        if h:
            print("  @0x%08X  ELF64  type=%d machine=%d entry=0x%X "
                  "phnum=%d shnum=%d конец~0x%X"
                  % (o, h["type"], h["machine"], h["entry"], h["phnum"],
                     h["shnum"], h["hdr_end"]))
        else:
            print("  @0x%08X  \x7fELF, но заголовок не разобран" % o)
    print("")

    print("=" * 78)
    print("3) читаемые строки (имена из IDA)")
    print("=" * 78)
    # ascii-строки длиной >= 8
    strs = re.findall(rb"[ -~]{8,}", data)
    print("  всего ascii-строк >=8 симв.: %d" % len(strs))
    interesting = [s for s in strs
                   if re.search(rb"(?i)(gsp|falcon|sec2|booter|whitelist|"
                                rb"pgraph|device.?id|0x[0-9a-f]{6})", s)]
    print("  из них с gpu/boot/whitelist в имени: %d" % len(interesting))
    seen = set()
    shown = 0
    for s in interesting:
        t = s.decode("ascii", "replace")
        if t in seen:
            continue
        seen.add(t)
        print("    %s" % t[:100])
        shown += 1
        if shown >= 40:
            print("    ... ещё")
            break
    print("")

    print("=" * 78)
    print("4) device ID в найденных ELF")
    print("=" * 78)
    IDS = {0x248A: "CMP 70HX", 0x220D: "CMP 90HX", 0x1E09: "CMP 50HX",
           0x2408: "RTX 3070 Ti", 0x1B06: "RTX 3080", 0x2204: "RTX 3090",
           0x2504: "RTX 4090", 0x2685: "RTX 4080 SUPER"}
    found_any = False
    for o in offs:
        h = parse_elf(data, o)
        if not h:
            continue
        found_any = True
        blob = data[o:h["hdr_end"]]
        print("  ELF @0x%08X, разбираем %d байт заголовков" % (o, len(blob)))
        for dev, name in IDS.items():
            p32 = struct.pack("<I", 0x10DE0000 | dev)
            p16 = struct.pack("<H", dev)
            n32 = blob.count(p32)
            n16 = blob.count(p16)
            if n32 or n16:
                print("    0x%04X %-16s 32-бит=%d 16-бит=%d"
                      % (dev, name, n32, n16))
        print("  (разбор только заголовков: полные секции по смещениям phoff/"
              "shoff не вырезались)")
    if not found_any:
        print("  ни одного разобранного ELF не найдено")
    print("")

    print("=" * 78)
    print("ВЫВОД")
    print("=" * 78)
    if offs:
        print("Исходный ELF найден внутри базы. Следующий шаг — вырезать его")
        print("целиком (границы по phoff/shoff/shnum) и искать структуры уже в нём.")
    else:
        print("ELF внутри не найден: IDB хранит его в сжатом виде.")
        print("Тогда нужен другой путь: либо IDA, либо анализ наших собственных")
        print("измерений в BAR0. Скачивание файла не дало прямого ответа.")


if __name__ == "__main__":
    main()
