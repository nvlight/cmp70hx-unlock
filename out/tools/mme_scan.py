#!/usr/bin/env python3
"""
mme_scan.py -- поиск MME-тормоза (CALL_MME_MACRO) в драйверных библиотеках NVIDIA.

ИСТОЧНИК
--------
Cyridd/cmpunlocker (форк PZH1gdmu/CMP40HX-Unlock),
CMP40_GSP_PIPELINE_THROTTLE_FINDINGS.md. Документировано, что пользовательский
драйвер NVIDIA на классическом пути bind pipeline (Vulkan vkCmdBindPipeline)
вставляет искусственную задержку:

    NVC597_CALL_MME_MACRO(52), argument 0xf0  ->  240 итераций
                                                  (PIPE_NOP + WAIT_FOR_IDLE)

Затрагивает ТОЛЬКО аргумент, программа макроса не меняется.

КАК ЭТО ВЫГЛЯДИТ В ДВОЙНИКЕ
--------------------------
Эмиттер в libnvidia-glcore.so.610.57.04 -- одна команда movabs, в
непосредственном операнде лежит пара pushbuffer-слов (заголовок, аргумент):

    48 b9 68 0e 01 20 f0 00 00 00      movabs rcx, 0x000000f0_20010e68
    48 89 08                            mov    qword ptr [rax], rcx
    48 83 c0 08                         add    rax, 8

Т.е. 8 байт 68 0e 01 20 <аргумент:4> -- это НЕ две команды push, а один
непосредственный операнд. Отсюда важная поправка: главный якорь -- голый
dword 0x20010e68 (байты 68 0e 01 20), а не последовательность с опкодом push.

САМА ПРОГРАММА МАКРОСА (48 байт, 4 инструкции по 3 dword)
----------------------------------------------------------
    00000003 1cc00000 b1cc5f00      LOOP  (счётчик приходит аргументом вызова)
    9d140113 18c001a2 f18c0300      PIPE_NOP
    00000003 18c00000 318c0301      WAIT_FOR_IDLE
    00000003 18c00000 318c0300      END_NEXT

Первый dword первой инструкции зависит от адреса программы в IRAM, поэтому
48-байтный якорь может не совпасть. Адресонезависимая часть -- инструкция
PIPE_NOP: байты a2 01 c0 18 00 03 8c f1. Именно он и находится надёжно.

ЯКОРЯ
-----
    MME_HDR   68 0e 01 20                  dword заголовка CALL_MME_MACRO(52)
    ARG_F0    68 0e 01 20 f0 00 00 00      точная 8-байтная последовательность эталона
    MME_BODY  a2 01 c0 18 00 03 8c f1      инструкция PIPE_NOP -- тело макроса
    WAIT_IDLE 00 00 c0 18 01 03 8c 31      инструкция WAIT_FOR_IDLE
    END_NEXT  00 00 c0 18 00 03 8c 31      инструкция END_NEXT
    MACRO48   полные 48 байт программы (может не совпасть: зависит от адреса)

СЕМАНТИЧЕСКАЯ ПРОБА
-------------------
--probe ищет вызовы вида «метод из семейства 0x20010eXX + рядом аргумент из
диапазона счётчика». Это не зависит от номера слота, поэтому переносится на
другие сборки драйвера.

ИСПОЛЬЗОВАНИЕ
-------------
    python out\\tools\\mme_scan.py <файл> [<файл> ...] [--out F] [--json F] [--quiet]
    python out\\tools\\mme_scan.py <файл> --probe
    python out\\tools\\mme_scan.py <файл> --dword 20010e68
    python out\\tools\\mme_scan.py <файл> --hist 40

Код возврата всегда 0: отрицательный результат -- это данные, а не ошибка.
"""

import argparse
import json
import os
import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

# --------------------------------------------------------------------------
# Якоря
# --------------------------------------------------------------------------

MME_HDR_DWORD   = 0x20010E68
MME_HDR_LE      = MME_HDR_DWORD.to_bytes(4, "little")      # 68 0e 01 20
ARG_F0_LE       = (0x000000F0).to_bytes(4, "little")       # f0 00 00 00
ARGBYTE_PUSH    = b"\x68"                                    # x86-64 push imm32
ARGBYTE_MOVABS  = b"\x48"                                    # REX.W

MME_INSTR_PIPE_NOP    = bytes.fromhex("a2 01 c0 18 00 03 8c f1")
MME_INSTR_WAIT_IDLE   = bytes.fromhex("00 00 c0 18 01 03 8c 31")
MME_INSTR_END_NEXT    = bytes.fromhex("00 00 c0 18 00 03 8c 31")

MACRO48_WORDS = (
    0x00000003, 0x1CC00000, 0xB1CC5F00,
    0x9D140113, 0x18C001A2, 0xF18C0300,
    0x00000003, 0x18C00000, 0x318C0301,
    0x00000003, 0x18C00000, 0x318C0300,
)
MACRO48_LE = b"".join(w.to_bytes(4, "little") for w in MACRO48_WORDS)

ANCHORS = (
    ("MME_HDR",  MME_HDR_LE,
     "dword заголовка CALL_MME_MACRO(52) -- главный якорь"),
    ("ARG_F0",   MME_HDR_LE + ARG_F0_LE,
     "пара (заголовок, аргумент 240) как в эталоне -- 8 байт, аргумент на +4"),
    ("MME_BODY", MME_INSTR_PIPE_NOP,
     "инструкция PIPE_NOP -- адресонезависимая часть тела макроса"),
    ("WAIT_IDLE", MME_INSTR_WAIT_IDLE,
     "инструкция WAIT_FOR_IDLE"),
    ("END_NEXT", MME_INSTR_END_NEXT,
     "инструкция END_NEXT (завершение макроса)"),
)

MME_FAMILY_PAIR = b"\x0e\x01\x20"      # младшие байты dword вида 0x20010eXX
MME_FAMILY_HI  = 0x20010000
MME_FAMILY_LO  = 0x0E00
ARG_MIN, ARG_MAX = 0x08, 0x400

CTX_BEFORE, CTX_AFTER = 48, 48
MACRO48_BACK = 16           # PIPE_NOP лежит на dword+1 второй инструкции


# --------------------------------------------------------------------------
# PE: секция и RVA по смещению
# --------------------------------------------------------------------------

class PEInfo(object):
    def __init__(self, data):
        self.ok = False
        self.image_base = 0
        self.sections = []
        try:
            if data[:2] != b"MZ":
                return
            lfanew = struct.unpack_from("<I", data, 0x3C)[0]
            if data[lfanew:lfanew + 4] != b"PE\0\0":
                return
            coff = lfanew + 4
            nsec = struct.unpack_from("<H", data, coff + 2)[0]
            optsz = struct.unpack_from("<H", data, coff + 16)[0]
            opt = coff + 20
            magic = struct.unpack_from("<H", data, opt)[0]
            if magic == 0x20B:
                self.image_base = struct.unpack_from("<Q", data, opt + 24)[0]
            elif magic == 0x10B:
                self.image_base = struct.unpack_from("<I", data, opt + 28)[0]
            else:
                return
            sec = opt + optsz
            for i in range(nsec):
                o = sec + i * 40
                raw = data[o:o + 40]
                if len(raw) < 40:
                    break
                self.sections.append((
                    raw[:8].split(b"\0")[0].decode("ascii", "replace"),
                ) + struct.unpack_from("<IIII", raw, 8))
            self.ok = bool(self.sections)
        except Exception:
            self.ok = False

    def where(self, off):
        for name, vaddr, vsize, rptr, rsize in self.sections:
            if rptr <= off < rptr + rsize:
                return name, vaddr + (off - rptr)
        return "?", 0


class Dis(object):
    def __init__(self):
        try:
            self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
            self.cs.detail = False
            self.have = True
        except Exception:
            self.cs = None
            self.have = False

    def disasm(self, data, base):
        if not self.have:
            return []
        return [(i.address, i.mnemonic, i.op_str) for i in self.cs.disasm(data, base)]


def hexdump(data, base_off, width=16):
    out = []
    for i in range(0, len(data), width):
        c = data[i:i + width]
        out.append("    %08x  %-*s  |%s|"
                   % (base_off + i, width * 3, " ".join("%02x" % b for b in c),
                      "".join(chr(b) if 32 <= b < 127 else "." for b in c)))
    return out


def find_all(hay, needle):
    out, i = [], hay.find(needle)
    while i >= 0:
        out.append(i)
        i = hay.find(needle, i + 1)
    return out


def macro_at(data, pipe_nop_off):
    """Смещение начала 48-байтной программы по найденной инструкции PIPE_NOP."""
    start = pipe_nop_off - 4 - MACRO48_BACK
    return start if start >= 0 else None


# --------------------------------------------------------------------------
# Основной проход
# --------------------------------------------------------------------------

def scan_file(path, dis, verbose=True):
    with open(path, "rb") as f:
        data = f.read()
    pe = PEInfo(data)
    rep = {"file": path, "size": len(data), "pe": pe.ok,
           "image_base": pe.image_base, "anchors": {}, "macros": [], "candidates": []}

    L = []
    add = L.append
    add("=" * 100)
    add("FILE  %s" % path)
    add("SIZE  %d bytes (%.1f MiB)" % (len(data), len(data) / 1048576.0))
    add("PE    %s%s" % ("разобран" if pe.ok else "нет (не PE) -- смещения файловые",
                        (", image_base=0x%X" % pe.image_base) if pe.ok else ""))
    add("=" * 100)

    for name, pat, desc in ANCHORS:
        hits = find_all(data, pat)
        rep["anchors"][name] = {"pattern": pat.hex(" "), "desc": desc,
                                "count": len(hits), "offsets": hits}
        add("")
        add("--- якорь %-9s %s" % (name, pat.hex(" ")))
        add("    %s" % desc)
        add("    вхождений: %d" % len(hits))
        if name == "MME_BODY":
            for h in hits:
                st = macro_at(data, h)
                w = struct.unpack_from("<12I", data, st) if st is not None else ()
                rep["macros"].append({"pipe_nop_off": h, "macro_off": st})
                add("    offset 0x%08x  %s  тело макроса с 0x%08x"
                    % (h, pe.where(h)[0], st if st is not None else -1))
                for r in range(4):
                    if len(w) >= (r + 1) * 3:
                        add("        inst%d: %08x %08x %08x"
                            % (r + 1, w[r * 3], w[r * 3 + 1], w[r * 3 + 2]))
                add("        байты тела: %s" % data[st:st + 48].hex(" ") if st is not None else "")
        else:
            for h in hits[:32]:
                add("    offset 0x%08x  %s  rva 0x%08x" % (h, pe.where(h)[0], pe.where(h)[1]))
                lo = max(0, h - CTX_BEFORE)
                for hl in hexdump(data[lo:min(len(data), h + len(pat) + CTX_AFTER)], lo):
                    add(hl)
            if len(hits) > 32:
                add("    ... ещё %d" % (len(hits) - 32))

    # полная 48-байтная программа
    hits48 = find_all(data, MACRO48_LE)
    rep["macros_full"] = hits48
    add("")
    add("--- якорь MACRO48  полная программа макроса, 48 байт")
    add("    вхождений: %d  %s" % (len(hits48), [hex(h) for h in hits48[:16]]))
    if not hits48:
        add("    (0 -- нормально: первый dword LOOP кодирует адрес программы в IRAM")
        add("("     "и в другой сборке драйвера будет другим)")

    # ---- семантическая проба: метод + аргумент ----
    add("")
    add("--- ПРОБА: CALL_MME_MACRO (0x20010eXX) + аргумент-счётчик 0x%X..0x%X"
        % (ARG_MIN, ARG_MAX))
    cand = []
    i = data.find(MME_FAMILY_PAIR)
    while i >= 0:
        if i >= 1:
            meth = struct.unpack_from("<I", data, i - 1)[0]
            if ((meth & 0xFFFF0000) == MME_FAMILY_HI
                    and (meth & 0xFF00) == MME_FAMILY_LO):
                for delta, tag in ((4, "arg@+4"), (-4, "arg@-4")):
                    j = i - 1 + delta
                    if 0 <= j <= len(data) - 4:
                        a = struct.unpack_from("<I", data, j)[0]
                        if ARG_MIN <= a <= ARG_MAX:
                            cand.append({"method": "0x%08x" % meth, "arg": "0x%08x" % a,
                                         "arg_val": a, "at": tag, "off": i - 1})
        i = data.find(MME_FAMILY_PAIR, i + 1)
    rep["candidates"] = cand
    add("    кандидатов: %d" % len(cand))
    for c in cand[:64]:
        add("      method %s  arg %s (%d)  %s  offset 0x%08x"
            % (c["method"], c["arg"], c["arg_val"], c["at"], c["off"]))
    if len(cand) > 64:
        add("      ... ещё %d" % (len(cand) - 64))

    # ---- контекст всех мест с аргументом ----
    if verbose and cand:
        add("")
        add("--- дизассемблер вокруг кандидатов (если capstone доступен) ---")
        for c in cand[:16]:
            lo = max(0, c["off"] - 40)
            add("    offset 0x%08x  method %s arg %s" % (c["off"], c["method"], c["arg"]))
            for addr, mnem, ops in dis.disasm(data[lo:c["off"] + 32], lo):
                mark = "   <== метод" if addr <= c["off"] < addr + 10 else ""
                add("      %08x  %-8s %-42s%s" % (addr, mnem, ops, mark))

    rep["text"] = "\n".join(L)
    return rep


# --------------------------------------------------------------------------
# Дополнительные режимы
# --------------------------------------------------------------------------

def scan_dword(path, hexval):
    v = int(hexval, 16)
    pat = v.to_bytes(4, "little")
    with open(path, "rb") as f:
        data = f.read()
    pe = PEInfo(data)
    hits = find_all(data, pat)
    print("dword 0x%08x -> %s : %d вхождений" % (v, pat.hex(" "), len(hits)))
    dis = Dis()
    for h in hits[:48]:
        sec, rva = pe.where(h)
        print("  offset 0x%08x  %s  rva 0x%08x" % (h, sec, rva))
        lo = max(0, h - 32)
        for hl in hexdump(data[lo:min(len(data), h + 40)], lo):
            print(hl)
        if dis.have:
            for addr, mnem, ops in dis.disasm(data[lo:h + 40], lo):
                mark = "   <== dword" if addr + 4 > h >= addr else ""
                print("      %08x  %-8s %-38s%s" % (addr, mnem, ops, mark))
    return hits


def scan_push_hist(path, top=40, lo_val=0x10000000, hi_val=0x40000000):
    import collections
    with open(path, "rb") as f:
        data = f.read()
    c = collections.Counter()
    i = 0
    while True:
        i = data.find(b"\x48", i)
        if i < 0 or i + 10 > len(data):
            break
        if 0xB8 <= data[i + 1] <= 0xBF:
            v = struct.unpack_from("<Q", data, i + 2)[0]
            if lo_val <= v < hi_val:
                c[v] += 1
        i += 1
    print("=== movabs-гистограмма %s" % os.path.basename(path))
    print("уникальных: %d, всего: %d" % (len(c), sum(c.values())))
    for v, n in c.most_common(top):
        print("   %016x  %d" % (v, n))


def summarize(reps):
    L = ["# ИТОГ", ""]
    L.append("%-26s %11s %8s %8s %8s %8s %10s" %
             ("файл", "размер", "MMEHDR", "ARGF0", "BODY", "MACRO48", "кандидатов"))
    L.append("-" * 88)
    for r in reps:
        g = lambda n: r["anchors"].get(n, {}).get("count", 0)
        L.append("%-26s %11d %8d %8d %8d %8d %10d"
                 % (os.path.basename(r["file"]), r["size"], g("MME_HDR"),
                    g("ARG_F0"), g("MME_BODY"), len(r.get("macros_full", [])),
                    len(r["candidates"])))
    L.append("")
    L.append("MME_BODY > 0  -> программа-задержка (PIPE_NOP+WAIT_FOR_IDLE) присутствует в файле.")
    L.append("MME_HDR > 0  -> найден вызов CALL_MME_MACRO(52) с аргументом в immediate.")
    L.append("кандидатов>0 -> найден вызов CALL_MME_MACRO с аргументом-счётчиком рядом.")
    return "\n".join(L)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="поиск MME-тормоза (CALL_MME_MACRO) в драйвере NVIDIA")
    ap.add_argument("files", nargs="+")
    ap.add_argument("--out")
    ap.add_argument("--json", dest="json_out")
    ap.add_argument("--quiet", action="store_true", help="не печатать hexdump/дизассемблер")
    ap.add_argument("--dword", metavar="HEX", help="искать голый 4-байтный dword")
    ap.add_argument("--hist", type=int, metavar="N", help="гистограмма movabs-констант")
    ap.add_argument("--probe", action="store_true", help="только семантическая проба")
    args = ap.parse_args(argv)

    dis = Dis()
    if args.dword:
        for p in args.files:
            scan_dword(p, args.dword)
        return 0
    if args.hist:
        for p in args.files:
            scan_push_hist(p, args.hist)
        return 0

    reps = []
    for path in args.files:
        if not os.path.isfile(path):
            sys.stderr.write("нет файла: %s\n" % path)
            continue
        rep = scan_file(path, dis, verbose=not args.quiet)
        reps.append(rep)
        if not args.probe:
            print(rep["text"])
            print()

    if not reps:
        return 0
    s = summarize(reps)
    print(s)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            for r in reps:
                f.write(r["text"] + "\n\n")
            f.write(s + "\n")
        print("\nтекстовый отчёт -> %s" % args.out)
    if args.json_out:
        slim = [{k: v for k, v in r.items() if k != "text"} for r in reps]
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(slim, f, indent=2)
        print("json отчёт     -> %s" % args.json_out)
    return 0


if __name__ == "__main__":
    sys.exit(main())