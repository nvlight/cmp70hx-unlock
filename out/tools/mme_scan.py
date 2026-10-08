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

Затрагивается ТОЛЬКО аргумент, программа макроса не меняется.

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

В драйвере 616.92 под Windows форма записи другая -- метод кладётся отдельной
командой mov в pushbuffer, а аргумент пишется отдельно:

    mov dword ptr [rbx + 0x10], 0x20010e78     ; заголовок метода
    mov dword ptr [rbx + 0x14], r13d            ; аргумент

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

РАЗДЕЛЕНИЕ КОДА И ДАННЫХ (--text-sites)
---------------------------------------
Семантическая проба ищет dword вида 0x20010eXX ЛЮБЫМ байтовым поиском, поэтому
она даёт ложные срабатывания в данных и в байткоде шейдеров: те же четыре
байта попадаются внутрь таблиц и SASS-операций. Поэтому режим --text-sites
сначала отсеивает всё, что лежит не в .text, а для оставшегося показывает
границы функции по таблице .pdata и ДИЗАССЕМБЛИРУЕТ функцию целиком --
аргумент виден прямо в инструкциях.

    python out\\tools\\mme_scan.py nvoglv64.dll --text-sites

ГРАНИЦЫ ФУНКЦИЙ
--------------
Формат PE: у PE32+ каталог data directories начинается с opt+112
(16 записей по 8 байт; запись 3 -- IMAGE_DIRECTORY_ENTRY_EXCEPTION),
у PE32 -- с opt+96. В каталоге лежит RUNTIME_FUNCTION {Begin, End, Unwind},
то есть .pdata даёт точные границы каждой функции: 81902 в nvoglv64.dll,
32625 в nvvkscv64.dll. Это надёжнее эвристики по int3/epilog.

ИСПОЛЬЗОВАНИЕ
-------------
    python out\\tools\\mme_scan.py <файл> [<файл> ...] [--out F] [--json F] [--quiet]
    python out\\tools\\mme_scan.py <файл> --text-sites [--arg]
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
try:
    from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM
except ImportError:                      # pragma: no cover
    X86_OP_REG, X86_OP_IMM, X86_OP_MEM = 1, 2, 3

# --------------------------------------------------------------------------
# Якоря
# --------------------------------------------------------------------------

MME_HDR_DWORD   = 0x20010E68
MME_HDR_LE      = MME_HDR_DWORD.to_bytes(4, "little")      # 68 0e 01 20
ARG_F0_LE       = (0x000000F0).to_bytes(4, "little")       # f0 00 00 00

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
MME_FAMILY      = 0x20010E00
MME_FAMILY_MASK = 0xFFFFFF00

CTX_BEFORE, CTX_AFTER = 48, 48
MACRO48_BACK = 16           # PIPE_NOP лежит на dword+1 второй инструкции

FUNC_MAX = 0x4000           # предохранитель на размер функции


# --------------------------------------------------------------------------
# PE: секции, каталоги, границы функций по .pdata
# --------------------------------------------------------------------------

class PEInfo(object):
    def __init__(self, data):
        self.ok = False
        self.pe32p = False
        self.image_base = 0
        self.sections = []
        self.datadirs = []
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
                self.pe32p = True
                self.image_base = struct.unpack_from("<Q", data, opt + 24)[0]
                # PE32+: PE32-общие 24 байт, ImageBase 8, ... NumberOfRvaAndSizes
                # на opt+108, каталоги на opt+112
                ndd_off = opt + 108
                dd_off = opt + 112
            elif magic == 0x10B:
                self.image_base = struct.unpack_from("<I", data, opt + 28)[0]
                ndd_off = opt + 92
                dd_off = opt + 96
            else:
                return
            ndd = struct.unpack_from("<I", data, ndd_off)[0]
            for i in range(min(ndd, 16)):
                rva, size = struct.unpack_from("<II", data, dd_off + 8 * i)
                self.datadirs.append((rva, size))

            sec = opt + optsz
            for i in range(nsec):
                o = sec + i * 40
                raw = data[o:o + 40]
                if len(raw) < 40:
                    break
                # порядок полей в IMAGE_SECTION_HEADER: VirtualSize,
                # VirtualAddress, SizeOfRawData, PointerToRawData. Храним в
                # порядке (vaddr, vsize, rptr, rsize) -- как ожидают where()
                # и off_of_rva().
                vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", raw, 8)
                self.sections.append((
                    raw[:8].split(b"\0")[0].decode("ascii", "replace"),
                    vaddr, vsize, rptr, rsize))
            self.ok = bool(self.sections)
        except Exception:
            self.ok = False
        self._funcs = None

    def where(self, off):
        for name, vaddr, vsize, rptr, rsize in self.sections:
            if rptr <= off < rptr + rsize:
                return name, vaddr + (off - rptr)
        return "?", 0

    def off_of_rva(self, rva):
        for name, vaddr, vsize, rptr, rsize in self.sections:
            if vaddr <= rva < vaddr + max(vsize, rsize):
                return rptr + (rva - vaddr)
        return None

    def is_code(self, off):
        return self.where(off)[0] == ".text"

    # ---- .pdata -> точные границы функций --------------------------------

    def funcs(self):
        """[(begin_rva, end_rva), ...] по IMAGE_DIRECTORY_ENTRY_EXCEPTION."""
        if self._funcs is not None:
            return self._funcs
        self._funcs = []
        if len(self.datadirs) <= 3:
            return self._funcs
        rva, size = self.datadirs[3]
        if not rva or not size:
            return self._funcs
        base = self.off_of_rva(rva)
        if base is None:
            return self._funcs
        # размер каталога задан по виртуальной памяти и может выходить за конец
        # файла -- режем по реальному буферу
        avail = (len(self._raw) - base) // 12
        for i in range(min(size // 12, avail)):
            b, e, _u = struct.unpack_from("<III", self._raw, base + 12 * i)
            if b < e and e - b <= FUNC_MAX:
                self._funcs.append((b, e))
        self._funcs.sort()
        return self._funcs

    def func_of_rva(self, rva):
        """Функция, содержащая rva, либо None."""
        fs = self.funcs()
        lo, hi = 0, len(fs) - 1
        best = None
        while lo <= hi:
            mid = (lo + hi) // 2
            b, e = fs[mid]
            if rva < b:
                hi = mid - 1
            elif rva >= e:
                lo = mid + 1
            else:
                best = fs[mid]
                break
        if best and best[0] <= rva < best[1]:
            return best
        return None


class PEFacade(PEInfo):
    """PEInfo, которому передан весь файл целиком (нужен для .pdata)."""

    def __init__(self, data):
        PEInfo.__init__(self, data)
        self._raw = data


class ELFInfo(object):
    """
    Минимальный разбор ELF64: секции, программные заголовки, символы.

    Нужен для калибровки на эталоне -- libnvidia-glcore.so.610.57.04 не PE,
    там границ функций из .pdata не существует, а опорная точка одна: два
    известных эмиттера из CMP40_GSP_PIPELINE_THROTTLE_FINDINGS.md.
    """

    def __init__(self, data):
        self.ok = False
        self.sections = []
        self.segs = []
        self.funcs = []
        try:
            if data[:4] != b"\x7fELF" or data[4] != 2:
                return
            e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
            e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
            e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
            e_phnum = struct.unpack_from("<H", data, 0x38)[0]
            e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
            e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
            e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
            for i in range(e_phnum):
                o = e_phoff + i * e_phentsize
                ptype = struct.unpack_from("<I", data, o)[0]
                off, vaddr, _pa, filesz, _msz = struct.unpack_from("<QQQQQ", data, o + 8)
                if ptype == 1:                       # PT_LOAD
                    self.segs.append((vaddr, vaddr + filesz, off))
            raw = []
            for i in range(e_shnum):
                o = e_shoff + i * e_shentsize
                (nameoff, typ, _fl, addr, offset, size,
                 link, _inf, _al, entsize) = struct.unpack_from("<IIQQQQIIQQ", data, o)
                raw.append({"nameoff": nameoff, "typ": typ, "addr": addr,
                            "off": offset, "size": size, "link": link,
                            "entsize": entsize})
            shstr = raw[e_shstrndx]
            sdata = data[shstr["off"]:shstr["off"] + shstr["size"]]
            for s in raw:
                nm = sdata[s["nameoff"]:sdata.index(b"\0", s["nameoff"])].decode("ascii", "replace")
                s["nm"] = nm
            self.sections = raw
            # .symtab -> границы функций (STT_FUNC)
            sym = next((s for s in raw if s["nm"] == ".symtab"), None)
            strt = next((s for s in raw if s["nm"] == ".strtab"), None)
            if sym and strt:
                sd = data[strt["off"]:strt["off"] + strt["size"]]
                for i in range(sym["size"] // 24):
                    o = sym["off"] + i * 24
                    noff, info, _oth, _shndx, value, size = struct.unpack_from("<IBBHQQ", data, o)
                    if (info & 0xF) == 2 and value and size:
                        self.funcs.append((value, value + size))
                self.funcs.sort()
            self.ok = True
        except Exception:
            self.ok = False

    def rva2off(self, vaddr):
        for a, b, off in self.segs:
            if a <= vaddr < b:
                return off + (vaddr - a)
        return None

    def section_of(self, off):
        for s in self.sections:
            if s["off"] <= off < s["off"] + s["size"]:
                return s["nm"]
        return "?"

    def is_code(self, off):
        return self.section_of(off) == ".text"

    def func_of(self, vaddr):
        for b, e in self.funcs:
            if b <= vaddr < e:
                return (b, e)
        return None


# --------------------------------------------------------------------------
# Дизассемблер
# --------------------------------------------------------------------------

class Dis(object):
    def __init__(self):
        try:
            self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
            # detail нужен для trace_arg: доступ к операндам (регистр/immediate)
            self.cs.detail = True
            self.have = True
        except Exception:
            self.cs = None
            self.have = False

    def disasm(self, data, base):
        if not self.have:
            return []
        return [(i.address, i.mnemonic, i.op_str) for i in self.cs.disasm(data, base)]

    def raw(self, data, base):
        if not self.have:
            return []
        return list(self.cs.disasm(data, base))


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
    pe = PEFacade(data)
    rep = {"file": path, "size": len(data), "pe": pe.ok,
           "image_base": pe.image_base, "anchors": {}, "macros": [], "candidates": []}

    L = []
    add = L.append
    add("=" * 100)
    add("FILE  %s" % path)
    add("SIZE  %d bytes (%.1f MiB)" % (len(data), len(data) / 1048576.0))
    add("PE    %s%s" % ("разобран" if pe.ok else "нет (не PE) -- смещения файловые",
                        (", %s, image_base=0x%X" % ("PE32+" if pe.pe32p else "PE32",
                                                    pe.image_base)) if pe.ok else ""))
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
                sec, rva = pe.where(h)
                rep["macros"].append({"pipe_nop_off": h, "macro_off": st, "section": sec})
                add("    offset 0x%08x  %s  тело макроса с 0x%08x" % (h, sec, st if st is not None else -1))
                for r in range(4):
                    if len(w) >= (r + 1) * 3:
                        add("        inst%d: %08x %08x %08x"
                            % (r + 1, w[r * 3], w[r * 3 + 1], w[r * 3 + 2]))
                add("        байты тела: %s" % data[st:st + 48].hex(" ") if st is not None else "")
        else:
            for h in hits[:32]:
                sec, rva = pe.where(h)
                tag = "" if sec == ".text" else "   <- не код (%s)" % sec
                add("    offset 0x%08x  %s  rva 0x%08x%s" % (h, sec, rva, tag))
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
                            sec, rva = pe.where(i - 1)
                            cand.append({"method": "0x%08x" % meth, "arg": "0x%08x" % a,
                                         "arg_val": a, "at": tag, "off": i - 1,
                                         "section": sec})
        i = data.find(MME_FAMILY_PAIR, i + 1)
    rep["candidates"] = cand
    add("    кандидатов: %d" % len(cand))
    for c in cand[:64]:
        add("      method %s  arg %s (%d)  %s  offset 0x%08x  %s"
            % (c["method"], c["arg"], c["arg_val"], c["at"], c["off"], c["section"]))
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
# Режим --text-sites: только настоящие места вызова в коде
# --------------------------------------------------------------------------

def text_sites(path, dis, want_arg=True):
    with open(path, "rb") as f:
        data = f.read()
    pe = PEFacade(data)
    name = os.path.basename(path)

    L = []
    add = L.append
    add("=" * 100)
    add("TEXT-SITES  %s" % path)
    add("PE32+ %s, image_base 0x%X, функций по .pdata: %d"
        % (pe.pe32p, pe.image_base, len(pe.funcs())))
    add("=" * 100)

    if not pe.ok:
        add("\nPE не разобран -- раздел кода/данных недоступен.")
        return {"file": path, "ok": False, "text": "\n".join(L), "sites": []}

    # 1) все dword семейства 0x20010eXX
    fam = []
    i = data.find(MME_FAMILY_PAIR)
    while i >= 0:
        if i >= 1:
            v = struct.unpack_from("<I", data, i - 1)[0]
            if (v & MME_FAMILY_MASK) == MME_FAMILY:
                fam.append((i - 1, v))
        i = data.find(MME_FAMILY_PAIR, i + 1)

    in_code = [(o, v) for o, v in fam if pe.is_code(o)]
    in_data = [(o, v) for o, v in fam if not pe.is_code(o)]

    # Второй фильтр. Эмиттер CALL_MME_MACRO кладёт заголовок метода в память
    # командой mov -- C7 modrm [disp] imm32. Байтовый поиск по dword не видит
    # границ инструкций, поэтому тот же рисунок попадается внутрь данных
    # jump-table внутри .text (capstone там выдаёт мусор вроде "pop rbx").
    #
    # Проверка идёт от ГРАНИЦЫ ФУНКЦИИ (её даёт .pdata), а не от сырого
    # смещения: разбираем функцию целиком и смотрим, какая инструкция реально
    # покрывает dword. Настоящий эмиттер -- это mov/movabs, у которого
    # непосредственный операнд равен этому dword.
    confirmed, rejected = [], []
    for o, v in in_code:
        if is_emitter_instruction(data, pe, o, v, dis):
            confirmed.append((o, v))
        else:
            rejected.append((o, v))

    add("")
    add("--- dword семейства 0x20010eXX: всего %d" % len(fam))
    add("    в .text (кандидаты в коде): %d" % len(in_code))
    for o, v in in_code:
        add("      offset 0x%08x  rva 0x%08x  method 0x%08x" % (o, pe.where(o)[1], v))
    add("    вне .text (данные/байткод, НЕ вызовы): %d" % len(in_data))
    add("")
    add("--- проверка кодировки инструкции (C7 modrm disp imm32 = mov [mem],imm32)")
    add("    подтверждено как эмиттер: %d" % len(confirmed))
    for o, v in confirmed:
        add("      offset 0x%08x  rva 0x%08x  method 0x%08x" % (o, pe.where(o)[1], v))
    add("    в .text, но НЕ mov [mem],imm32 (мусор / jump-table): %d" % len(rejected))
    for o, v in rejected:
        # причина отказа: за сколько байт назад нашёлся ближайший ret/jmp --
        # если дword лежит уже после epilog, это данные, а не инструкция
        why = data_region_reason(data, pe, o)
        add("      offset 0x%08x  rva 0x%08x  method 0x%08x  %s"
            % (o, pe.where(o)[1], v, why))
    secs = {}
    for o, v in in_data:
        secs.setdefault(pe.where(o)[0], []).append(o)
    for s, offs in secs.items():
        add("      %-10s %d: %s%s" % (s, len(offs),
                                      ", ".join(hex(x) for x in offs[:8]),
                                      " ..." if len(offs) > 8 else ""))

    # 2) по каждому кандидату -- функция по .pdata и её дизассемблирование
    sites = []
    for off, meth in confirmed:
        sec, rva = pe.where(off)
        fn = pe.func_of_rva(rva)
        add("")
        add("=" * 100)
        add("SITE  offset 0x%08x  rva 0x%08x  method 0x%08x" % (off, rva, meth))
        if fn is None:
            add("  функция по .pdata не найдена")
            insns = dis.raw(data[max(0, off - 96):off + 96], off - 96)
            site = {"off": off, "rva": rva, "method": meth, "func": None,
                    "arg_const": None, "arg_expr": None}
            sites.append(site)
            for ins in insns:
                mark = "   <== METHOD" if ins.address <= off < ins.address + 12 else ""
                add("    %016x  %-8s %-44s%s" % (ins.address, ins.mnemonic, ins.op_str, mark))
            continue

        fbeg, fend = fn
        add("  функция rva 0x%08x..0x%08x  (%d Б)" % (fbeg, fend, fend - fbeg))
        foff = pe.off_of_rva(fbeg)
        fdata = data[foff:foff + (fend - fbeg)]
        insns = dis.raw(fdata, pe.image_base + fbeg)

        hit_idx = None
        for i2, ins in enumerate(insns):
            if ins.address <= pe.image_base + rva < ins.address + ins.size:
                hit_idx = i2
                break

        site = {"off": off, "rva": rva, "method": meth,
                "func": [fbeg, fend], "arg_const": None, "arg_expr": None,
                "arg_reg": None, "arg_def": None}
        for ins in insns:
            mark = ""
            if hit_idx is not None and ins.address <= pe.image_base + rva < ins.address + ins.size:
                mark = "   <== METHOD"
            add("    %016x  %-8s %-44s%s" % (ins.address, ins.mnemonic, ins.op_str, mark))

        # разбор аргумента: инструкции с mov [..+4], reg
        if want_arg and hit_idx is not None:
            site.update(trace_arg(data, pe, insns, hit_idx))
        sites.append(site)

    # 3) итог
    add("")
    add("=" * 100)
    add("ИТОГ по %s" % name)
    add("  мест вызова в .text: %d" % len(sites))
    consts = [s for s in sites if s.get("arg_const") is not None]
    add("  из них с КОНСТАНТНЫМ аргументом: %d" % len(consts))
    for s in consts:
        add("    offset 0x%08x method 0x%08x arg = %d (0x%X)"
            % (s["off"], s["method"], s["arg_const"], s["arg_const"]))
    hit240 = [s for s in consts if s["arg_const"] == 0xF0]
    add("  с аргументом 0xF0 (240): %d  %s"
        % (len(hit240), "<-- ТОРМОЗ" if hit240 else "(нет)"))
    add("  с аргументом из регистра/памяти: %d"
        % len([s for s in sites if s.get("arg_const") is None]))

    return {"file": path, "ok": True, "pe32p": pe.pe32p, "size": len(data),
            "funcs": len(pe.funcs()), "family_total": len(fam),
            "in_code": len(in_code), "in_data": len(in_data),
            "confirmed": len(confirmed), "rejected": len(rejected),
            "sites": sites, "text": "\n".join(L)}


def elf_sites(path, dis):
    """
    Места вызова CALL_MME_MACRO в ELF-библиотеке (эталон Linux).

    В эталоне эмиттер записан одной командой movabs, в непосредственном
    операнде которой лежит ПАРА pushbuffer-слов: метод в младших 32 битах,
    аргумент в старших.

        movabs rcx, 0x000000f0_20010e68    ; метод 0x20010e68, аргумент 240

    Поэтому искать надо 8-байтовое окно, где dword метода стоит на +4 от
    начала immediate, а аргумент -- на +0. Это и есть калибровка: зная
    верное разбиение на (метод, аргумент) на эталоне, мы можем утверждать,
    что в Windows-драйвере искали правильную вещь.
    """
    with open(path, "rb") as f:
        data = f.read()
    ei = ELFInfo(data)
    name = os.path.basename(path)

    L = []
    add = L.append
    add("=" * 100)
    add("ELF-SITES  %s" % path)
    add("ELF64, секций %d, функций по .symtab: %d" % (len(ei.sections), len(ei.funcs)))
    add("=" * 100)
    if not ei.ok:
        add("\nELF не разобран.")
        return {"file": path, "ok": False, "text": "\n".join(L), "sites": []}

    fam = []
    i = data.find(MME_FAMILY_PAIR)
    while i >= 0:
        if i >= 1:
            v = struct.unpack_from("<I", data, i - 1)[0]
            if (v & MME_FAMILY_MASK) == MME_FAMILY:
                fam.append((i - 1, v))
        i = data.find(MME_FAMILY_PAIR, i + 1)

    in_code = [(o, v) for o, v in fam if ei.is_code(o)]
    in_data = [(o, v) for o, v in fam if not ei.is_code(o)]
    add("")
    add("--- dword семейства 0x20010eXX: всего %d" % len(fam))
    add("    в .text: %d      вне .text: %d" % (len(in_code), len(in_data)))

    # ищем movabs, у которого immediate = (arg<<32)|method
    sites = []
    for off, meth in in_code:
        # movabs: REX(48/49) B8+r imm64 -> immediate начинается на off+2
        if off + 2 < len(data) and data[off + 1] in range(0xB8, 0xC0) \
                and data[off] in (0x48, 0x49):
            ins = next(iter(dis.raw(data[off:off + 10], off)), None)
        elif off >= 2 and data[off - 1] in range(0xB8, 0xC0) and data[off - 2] in (0x48, 0x49):
            ins = next(iter(dis.raw(data[off - 2:off + 8], off - 2)), None)
        else:
            ins = None
        if ins is None or ins.mnemonic != "movabs":
            continue
        for o_ in ins.operands:
            if o_.type == X86_OP_IMM and (o_.imm & 0xFFFFFFFF) == meth:
                arg = o_.imm >> 32
                sites.append({"off": off, "method": meth, "arg": arg,
                              "arg_const": arg, "insn": ins.op_str})
                break

    add("")
    add("--- подтверждённые эмиттеры movabs: %d" % len(sites))
    for s in sites:
        add("    offset 0x%08x  method 0x%08x  arg=%-10d %s"
            % (s["off"], s["method"], s["arg"], ins and s["insn"] or ""))
    hit = [s for s in sites if s["arg"] == 0xF0]
    add("")
    add("  из них с аргументом 0xF0 (240): %d  %s"
        % (len(hit), "<== ТОРМОЗ, места: %s" % [hex(s["off"]) for s in hit] if hit else "(нет)"))

    # сводка по парам (метод, аргумент)
    pairs = {}
    for s in sites:
        pairs.setdefault((s["method"], s["arg"]), []).append(s["off"])
    add("")
    add("--- сводка (метод, аргумент) ---")
    for (m, a), offs in sorted(pairs.items()):
        add("    0x%08x  arg=%-10d x%d  %s%s"
            % (m, a, len(offs), ", ".join(hex(x) for x in offs[:6]),
               "  <== ТОРМОЗ 240" if a == 0xF0 else ""))

    return {"file": path, "ok": True, "family_total": len(fam),
            "in_code": len(in_code), "in_data": len(in_data),
            "sites": sites, "pairs": {"0x%08x/%d" % (m, a): [hex(x) for x in o]
                                      for (m, a), o in pairs.items()},
            "throttle_hits": [hex(s["off"]) for s in hit],
            "text": "\n".join(L)}


def data_region_reason(data, pe, off):
    """
    Человекочитаемое объяснение, почему dword внутри .text не признан
    эмиттером: ищем назад ближайшую границу функции / epilog.
    """
    rva = pe.where(off)[1]
    fn = pe.func_of_rva(rva)
    if fn is None:
        return "вне функции по .pdata"
    fbeg, fend = fn
    if off - fbeg > 0x40:
        return ("в %d Б после начала функции -- похоже на данные "
                "(jump-table/строка), не инструкция" % (off - fbeg))
    return "не mov/movabs с этим immediate"


def is_emitter_instruction(data, pe, off, meth, dis):
    """
    Является ли dword по смещению off непосредственным операндом инструкции
    mov/movabs, которая кладёт этот dword в память?

    Разбор ведётся ОТ НАЧАЛА ФУНКЦИИ (границу даёт .pdata), поэтому мы стоим
    на настоящей границе инструкции, а не внутри данных jump-table.
    Настоящий эмиттер: mov/movabs, у которого операнд-immediate равен dword.
    """
    if not dis.have:
        return False
    rva = pe.where(off)[1]
    fn = pe.func_of_rva(rva)
    if fn is None:
        return False
    fbeg, fend = fn
    foff = pe.off_of_rva(fbeg)
    if foff is None:
        return False
    body = data[foff:foff + (fend - fbeg)]
    for ins in dis.raw(body, pe.image_base + fbeg):
        if not (ins.address <= pe.image_base + rva < ins.address + ins.size):
            continue
        if ins.mnemonic not in ("mov", "movabs"):
            return False
        for o in ins.operands:
            if o.type == X86_OP_IMM and (o.imm & 0xFFFFFFFF) == meth:
                return True
        return False
    return False


def trace_arg(data, pe, insns, hit_idx):
    """
    Ищет инструкцию, которая кладёт АРГУМЕНТ макроса, и пытается свести его
    к константе или к выражению. Работает по факту записи: mov dword ptr [X], reg
    сразу после (или в пределах нескольких инструкций после) записи метода.
    """
    out = {"arg_const": None, "arg_expr": None, "arg_reg": None, "arg_def": None}
    if hit_idx is None:
        return out

    # запись аргумента может идти как ДО, так и ПОСле записи метода:
    #      lea eax, [rcx*4] ; mov [rdx+0x14], eax ; mov [rdx+0x10], 0x20010e78
    # берём окно вокруг метода: сначала назад, потом вперёд
    lo = max(0, hit_idx - 8)
    order = list(range(lo, hit_idx))[::-1] + list(range(hit_idx, min(len(insns), hit_idx + 8)))
    target = None
    for k in order:
        ins = insns[k]
        if ins.mnemonic != "mov" or not ins.operands or len(ins.operands) < 2:
            continue
        dst, src = ins.operands[0], ins.operands[1]
        if dst.type != X86_OP_MEM:
            continue
        # ищем запись dword по смещению +0x14/+4 (слово после заголовка)
        disp = dst.mem.disp
        if disp not in (4, 0x14):
            continue
        # та же база памяти, что и у записи метода
        if hit_idx < len(insns):
            hd = insns[hit_idx].operands
            if hd and hd[0].type == X86_OP_MEM:
                if dst.mem.base != hd[0].mem.base or dst.mem.index != hd[0].mem.index:
                    continue
        if src.type == X86_OP_IMM:
            out["arg_const"] = src.imm & 0xFFFFFFFF
            out["arg_expr"] = ins.op_str
            return out
        if src.type == X86_OP_REG:
            target = (ins, ins.reg_name(src.reg))
            out["arg_reg"] = ins.reg_name(src.reg)
            out["arg_expr"] = ins.op_str
            break
    if target is None:
        return out

    # обратный поиск определения регистра внутри функции
    reg = target[1]
    at = target[0].address
    for ins in reversed(insns[:hit_idx + 8]):
        if ins.address >= at:
            continue
        if writes_reg(ins, reg):
            out["arg_def"] = ("%016x  %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))
            if ins.operands and ins.operands[0].type == X86_OP_IMM:
                out["arg_const"] = ins.operands[0].imm & 0xFFFFFFFF
            elif ins.operands and ins.operands[0].type == X86_OP_REG:
                # определение -- другой регистр: идём ещё на шаг назад
                pre = ins.reg_name(ins.operands[0].reg)
                out["arg_def"] += "   <- из %s" % pre
                for ins2 in reversed(insns[:hit_idx + 8]):
                    if ins2.address >= ins.address:
                        continue
                    if writes_reg(ins2, pre):
                        out["arg_def"] += " ; %016x  %-8s %s" % (
                            ins2.address, ins2.mnemonic, ins2.op_str)
                        break
            break
    return out


def writes_reg(ins, reg_name):
    """Грубая эвристика: пишет ли инструкция (первый операнд) в reg_name."""
    if not ins.operands:
        return False
    first = ins.operands[0]
    if first.type == X86_OP_REG and ins.reg_name(first.reg) == reg_name:
        # mov r,r / xor r,r -- запись есть (кроме cmp/test)
        if ins.mnemonic not in ("cmp", "test", "push", "jmp", "bt", "call"):
            return True
    # lea / add / sub / and / or / shl / inc / dec / imul ...
    if ins.mnemonic in ("lea", "add", "sub", "and", "or", "xor", "shl", "shr",
                        "sar", "inc", "dec", "imul", "movzx", "movsxd", "neg", "not"):
        for o in ins.operands:
            if o.type == X86_OP_REG and ins.reg_name(o.reg) == reg_name:
                return True
    return False


# --------------------------------------------------------------------------
# Дополнительные режимы
# --------------------------------------------------------------------------

def scan_dword(path, hexval):
    v = int(hexval, 16)
    pat = v.to_bytes(4, "little")
    with open(path, "rb") as f:
        data = f.read()
    pe = PEFacade(data)
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
    ap.add_argument("--text-sites", action="store_true",
                    help="разбор настоящих мест вызова в .text (с границами по .pdata)")
    ap.add_argument("--arg", action="store_true",
                    help="в --text-sites: трассировать аргумент макроса")
    ap.add_argument("--elf-sites", action="store_true",
                    help="разбор мест вызова в ELF (эталон libnvidia-glcore.so)")
    args = ap.parse_args(argv)

    dis = Dis()
    if args.elf_sites:
        reps = []
        L = []
        for path in args.files:
            if not os.path.isfile(path):
                sys.stderr.write("нет файла: %s\n" % path)
                continue
            rep = elf_sites(path, dis)
            reps.append(rep)
            L.append(rep["text"])
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write("\n\n".join(L) + "\n")
            print("\nтекстовый отчёт -> %s" % args.out)
        if args.json_out:
            slim = [{k: v for k, v in r.items() if k != "text"} for r in reps]
            with open(args.json_out, "w", encoding="utf-8") as f:
                json.dump(slim, f, indent=2, ensure_ascii=False)
            print("json отчёт     -> %s" % args.json_out)
        if not args.quiet:
            print("\n\n".join(L))
        return 0
    if args.dword:
        for p in args.files:
            scan_dword(p, args.dword)
        return 0
    if args.hist:
        for p in args.files:
            scan_push_hist(p, args.hist)
        return 0

    # --text-sites: свой путь, без якорного отчёта
    if args.text_sites:
        reps = []
        L = []
        for path in args.files:
            if not os.path.isfile(path):
                sys.stderr.write("нет файла: %s\n" % path)
                continue
            rep = text_sites(path, dis, want_arg=args.arg)
            reps.append(rep)
            L.append(rep["text"])
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write("\n\n".join(L) + "\n")
            print("\nтекстовый отчёт -> %s" % args.out)
        if args.json_out:
            slim = [{k: v for k, v in r.items() if k != "text"} for r in reps]
            with open(args.json_out, "w", encoding="utf-8") as f:
                json.dump(slim, f, indent=2, ensure_ascii=False)
            print("json отчёт     -> %s" % args.json_out)
        if not args.quiet:
            print("\n\n".join(L))
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