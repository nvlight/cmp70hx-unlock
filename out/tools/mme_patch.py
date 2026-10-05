#!/usr/bin/env python3
"""
mme_patch.py -- правка аргумента MME-макроса в копии драйверной библиотеки.

Что делает
----------
Меняет РОВНО 4 байта -- счётчик итераций -- по заданным смещениям в файле.
Заголовок метода, программа макроса и всё остальное не трогаются.

    аргумент 0xF0 (240) -> 0x01 (одна итерация) или 0x00 (ноль итераций)

Смысл: CALL_MME_MACRO(slot), arg запускает макрос
    LOOP(arg x { PIPE_NOP ; WAIT_FOR_IDLE }) END_NEXT
Драйвер вставляет arg=240 при bind pipeline. Уменьшение arg убирает
искусственную задержку, не убирая сам вызов и не меняя программу макроса.

Безопасность
------------
* По умолчанию НИЧЕГО НЕ ПИШЕТ (режим list) -- только показывает было/станет.
* apply требует явного --apply и создаёт <файл>.bak + <файл>.mme.json.
* manifest хранит sha256 до и после, размер, список смещений и значение.
* restore проверяет, что текущий файл совпадает с записанным "после",
  и только потом возвращает "до"; иначе отказывается и ничего не портит.

Использование
-------------
    # 1. посмотреть, что изменится
    python out\\tools\\mme_patch.py list    <file> 0x1234 0x5678 --value 0x01

    # 2. применить (создаст .bak и .mme.json рядом)
    python out\\tools\\mme_patch.py apply  <file> 0x1234 0x5678 --value 0x01 --apply

    # 3. вернуть как было
    python out\\tools\\mme_patch.py restore <file>

    # 4. показать состояние манифеста
    python out\\tools\\mme_patch.py status  <file>
"""

import argparse
import hashlib
import json
import os
import shutil
import struct
import sys

MANIFEST_EXT = ".mme.json"
BACKUP_EXT = ".bak"


def sha256(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def manifest_path(path):
    return path + MANIFEST_EXT


def backup_path(path):
    return path + BACKUP_EXT


def read_dword(data, off):
    return struct.unpack_from("<I", data, off)[0]


def cmd_list(args):
    with open(args.file, "rb") as f:
        data = f.read()
    val = args.value & 0xFFFFFFFF
    print("файл   : %s (%d байт)" % (args.file, len(data)))
    print("значение: 0x%08x -> 0x%08x" % (read_dword(data, args.offsets[0]), val))
    print("смещений: %d" % len(args.offsets))
    ok = True
    for off in args.offsets:
        if off < 0 or off + 4 > len(data):
            print("  0x%08x  НЕВЫХОДИТ ЗА ГРАНИЦЫ ФАЙЛА" % off)
            ok = False
            continue
        cur = read_dword(data, off)
        print("  0x%08x: %02x %02x %02x %02x  ->  %02x %02x %02x %02x   (было %d, станет %d)"
              % (off,
                 data[off], data[off + 1], data[off + 2], data[off + 3],
                 val & 0xFF, (val >> 8) & 0xFF, (val >> 16) & 0xFF, (val >> 24) & 0xFF,
                 cur, val))
    if not ok:
        return 1
    print("\nЭто dry-run: файл не изменён.")
    return 0


def cmd_apply(args):
    if not args.apply:
        print("REFUSED: без флага --apply файл не изменяется. Показать dry-run: list")
        return 2
    path = args.file
    if not os.path.isfile(path):
        print("нет файла: %s" % path)
        return 1
    if os.path.exists(manifest_path(path)):
        print("REFUSED: манифест уже существует -- %s" % manifest_path(path))
        print("Сначала restore, иначе цепочка отката порвётся.")
        return 2
    val = args.value & 0xFFFFFFFF
    before_sha = sha256(path)
    with open(path, "rb") as f:
        data = bytearray(f.read())
    for off in args.offsets:
        if off < 0 or off + 4 > len(data):
            print("REFUSED: смещение 0x%08x вне файла" % off)
            return 2
    for off in args.offsets:
        data[off:off + 4] = struct.pack("<I", val)
    tmp = path + ".mme.tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    shutil.copystat(path, tmp) if hasattr(shutil, "copystat") else None
    shutil.copy2(path, backup_path(path))
    os.replace(tmp, path)
    after_sha = sha256(path)

    man = {
        "file": path,
        "size": len(data),
        "sha256_before": before_sha,
        "sha256_after": after_sha,
        "offsets": [hex(o) for o in args.offsets],
        "value": "0x%08x" % val,
        "created": __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "backup": backup_path(path),
    }
    with open(manifest_path(path), "w", encoding="utf-8") as f:
        json.dump(man, f, indent=2)

    print("ПРИМЕНЕНО")
    for o in args.offsets:
        print("  0x%08x -> 0x%08x" % (o, val))
    print("backup   : %s" % backup_path(path))
    print("manifest : %s" % manifest_path(path))
    print("sha256 до: %s" % before_sha)
    print("sha256   : %s" % after_sha)
    print("\nОткат:  python out\\tools\\mme_patch.py restore \"%s\"" % path)
    return 0


def cmd_restore(args):
    path = args.file
    mp, bp = manifest_path(path), backup_path(path)
    if not os.path.isfile(mp):
        print("нет манифеста: %s -- значит правка не применялась этим инструментом" % mp)
        return 1
    if not os.path.isfile(bp):
        print("нет резервной копии: %s" % bp)
        return 1
    with open(mp, "r", encoding="utf-8") as f:
        man = json.load(f)
    cur = sha256(path)
    if cur != man["sha256_after"]:
        print("REFUSED: текущий файл не совпадает с состоянием 'после правки'.")
        print("  ожидалось: %s" % man["sha256_after"])
        print("  получено : %s" % cur)
        print("Файл меняли чем-то ещё -- автоматический откат небезопасен.")
        return 2
    shutil.copy2(bp, path)
    back = sha256(path)
    if back != man["sha256_before"]:
        print("ВНИМАНИЕ: после отката sha256 не сошёлся с 'до'!")
        return 1
    os.remove(mp)
    print("ОТКАТ ВЫПОЛНЕН, файл байт в байт как до правки.")
    print("  sha256: %s" % back)
    print("Манифест удалён, повторная apply разрешена.")
    print("Резервную копию можно удалить: %s" % bp)
    return 0


def cmd_status(args):
    mp = manifest_path(args.file)
    if not os.path.isfile(mp):
        print("правок не применялось (%s отсутствует)" % mp)
        return 0
    with open(mp, "r", encoding="utf-8") as f:
        man = json.load(f)
    print(json.dumps(man, indent=2, ensure_ascii=False))
    print("\nтекущий sha256: %s" % sha256(args.file))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="правка аргумента MME-макроса в копии библиотеки")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("list", help="dry-run: показать изменения")
    p.add_argument("file")
    p.add_argument("offsets", nargs="+", type=lambda x: int(x, 0))
    p.add_argument("--value", type=lambda x: int(x, 0), default=0x01)
    p.set_defaults(fn=cmd_list)

    p = sub.add_parser("apply", help="применить (нужен --apply)")
    p.add_argument("file")
    p.add_argument("offsets", nargs="+", type=lambda x: int(x, 0))
    p.add_argument("--value", type=lambda x: int(x, 0), default=0x01)
    p.add_argument("--apply", action="store_true")
    p.set_defaults(fn=cmd_apply)

    p = sub.add_parser("restore", help="откатить по манифесту")
    p.add_argument("file")
    p.set_defaults(fn=cmd_restore)

    p = sub.add_parser("status", help="показать манифест")
    p.add_argument("file")
    p.set_defaults(fn=cmd_status)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())