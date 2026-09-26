#!/usr/bin/env python3
"""
read-log.py — прочитать лог, который unlock_v2 пишет на флешку.

Формат (см. log_init()/log_write() в src/unlock_v2.c):
  * LBA 4 000 000, область 2048 секторов по 512 байт
  * сектор 0 НЕ пишется никогда (там старое содержимое флешки)
  * лог начинается с сектора 1, ASCII, хвост каждого сектора добит нулями
  * заканчивается строкой  END   ---- end of log ----

Читать нужно ОСТОРОЖНО, и в этом весь смысл скрипта:
  1) искать магию CMPUNLOG и начинать с её сектора, а не с нуля —
     иначе печатается старый мусор флешки;
  2) останавливаться на первом секторе, который начинается с нуля —
     это не записанный хвост области, там тоже мусор;
  3) резать каждый сектор по первому нулю.

Запуск:  python out\\read-log.py
Опции:   --disk N    (по умолчанию ищется сам через метку тома)
         --lba N     (по умолчанию 4000000)
         --out FILE  сохранить ВЕСЬ отчёт (лог + ключевые строки + выводы)
                    в файл в кодировке UTF-8
"""
import argparse
import os
import re
import sys

# На Windows консоль по умолчанию cp1251/cp866, и русский текст в отчёте
# превращается в мусор. Принудительно UTF-8 на вывод, иначе придётся
# каждый раз ставить PYTHONIOENCODING вручную.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

SECTOR = 512
MAXSEC = 2048
DEFAULT_LBA = 4000000
MAGIC = b"CMPUNLOG"
MARKER = b"END   ---- end of log ----"


def find_stick_drive():
    """Ищем флешку с нашим разделом: метка CMP70UNLOCK."""
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        # проще: перебрать физические диски и проверить метку тома
        import subprocess
        ps = ("Get-Volume | Where-Object { $_.FileSystemLabel -eq 'CMP70UNLOCK' } "
              "| ForEach-Object { $p = Get-Partition -DriveLetter $_.DriveLetter; "
              "(Get-Disk -Number $p.DiskNumber).Number }")
        r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           capture_output=True, text=True)
        for line in r.stdout.split():
            if line.isdigit():
                return int(line)
    except Exception:
        pass
    return None


def read_area(drive, lba, count):
    path = r"\\.\PhysicalDrive%d" % drive
    with open(path, "rb", buffering=0) as f:
        f.seek(lba * SECTOR)
        data = bytearray()
        # один read() может вернуть меньше — читаем до нужного объёма
        while len(data) < count * SECTOR:
            chunk = f.read(count * SECTOR - len(data))
            if not chunk:
                break
            data += chunk
    return bytes(data)


def extract(raw, lba, first_only=False):
    """Возвращает (текст, откуда остановились, номер первого сектора).

    Ловушки, каждая стоила абракадабры:
      1) сектор 0 области не пишется никогда — там старое содержимое
         флешки, поэтому начинаем с сектора, где нашлась магия;
      2) незаписанный хвост области может начинаться с НЕНУЛЕВОГО байта
         (остатки лога от прошлой загрузки), поэтому признак «это лог» —
         наличие перевода строки в начале сектора, а не первый байт;
      3) каждый сектор режем по первому нулю;
      4) с v3n прогон ПРОДОЛЖАЕТ лог, а не начинает с сектора 1, поэтому
         между прогонами остаются пустые секторы. Обходим их и склеиваем
         прогоны разделителем, иначе теряем всё после первого.
    """
    idx = raw.find(MAGIC)
    if idx < 0:
        return None, "магия не найдена", None
    first = idx // SECTOR
    parts = []
    why = "весь буфер"
    gap = False
    runs = 0
    for i in range(first, min(MAXSEC, len(raw) // SECTOR)):
        off = i * SECTOR
        sec = raw[off:off + SECTOR]
        if len(sec) < SECTOR:
            why = "конец буфера"
            break
        if sec.count(b"\0") == len(sec):          # сектор не записан
            if gap and not parts:
                continue
            gap = True
            continue
        if sec[0] == 0 and b"\n" not in sec[:300]:
            if gap and not parts:
                continue
            gap = True
            continue
        if b"\n" not in sec[:300]:
            why = "сектор %d не похож на лог (нет перевода строки)" % i
            break
        if gap:
            parts.append("\n=== разрыв: далее следующий прогон ===\n".encode("utf-8"))
            gap = False
            runs += 1
            if first_only:
                why = "маркер конца в секторе %d" % (i - 1)
                break
        end = sec.find(b"\0")
        parts.append(sec[:end] if end >= 0 else sec)
        if MARKER in sec and first_only:
            why = "маркер конца в секторе %d" % i
            break
    if runs:
        why += " (склеено прогонов: %d)" % (runs + 1)
    return b"".join(parts), why, first


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--disk", type=int, default=None)
    ap.add_argument("--lba", type=int, default=DEFAULT_LBA)
    ap.add_argument("--out", default=None,
                    help="сохранить ВЕСЬ отчёт в файл (UTF-8)")
    ap.add_argument("--raw", default=None,
                    help="сохранить сырые секторы области лога как есть (бинарно)")
    a = ap.parse_args()

    # Собираем отчёт в список строк, а не печатаем сразу: так его можно
    # и показать на экране, и целиком записать в файл (--out).
    report = []

    def say(line=""):
        report.append(line)
        print(line)

    drive = a.disk if a.disk is not None else find_stick_drive()
    if drive is None:
        say("Флешка не найдена: нет тома с меткой CMP70UNLOCK.")
        say("Укажите диск вручную:  python read-log.py --disk N")
        return 2

    say("Читаю PhysicalDrive%d с LBA %d (%d секторов)..."
        % (drive, a.lba, MAXSEC))
    try:
        raw = read_area(drive, a.lba, MAXSEC)
    except OSError as e:
        say("Не удалось прочитать диск: %s" % e)
        say("Нужен запуск от администратора.")
        return 2

    text, why, first = extract(raw, a.lba)
    if text is None:
        nz = sum(1 for b in raw if b != 0)
        say("")
        say("ЛОГА НЕТ — по адресу LBA %d записаны чужие данные." % a.lba)
        say("  ненулевых байт: %d из %d" % (nz, len(raw)))
        say("  это старое содержимое флешки, а не лог.")
        say("")
        say("Приложение пишет лог только во время загрузки с флешки.")
        say("Перезагрузитесь, загрузитесь с неё и потом запустите скрипт.")
        return 2

    if first:
        say("Магия в секторе %d (LBA %d). Останов: %s"
            % (first, a.lba + first, why))
    s = text.decode("ascii", errors="replace")

    say("")
    say("=" * 24 + " ЛОГ С ФЛЕШКИ " + "=" * 24)
    for line in s.split("\n"):
        say(line)
    say("=" * 25 + " КОНЕЦ ЛОГА " + "=" * 25)

    keys = [l for l in s.split("\n")
            if re.match(r"^(PRE|FWSEC|FIND|PICK|PROBE|FBIOS|META|END|STICK|profile)", l)]
    say("")
    say("--- ключевые строки (%d) ---" % len(keys))
    for l in keys:
        say("  " + l)

    say("")
    say("--- что это значит ---")

    # В логах, записанных ДО починки форматтера, метки OK/MISMATCH
    # печатались как 'O' и 'MSAC': %s в AsciiVSPrint читает широкие строки
    # и печатает младшие байты, останавливаясь на первом 0x0000. Восстанавливаем
    # их по длине: 1 символ = OK, 4 = MISMATCH.
    fixed = 0
    for l in keys:
        m = re.search(r"\bgot=(0x[0-9A-Fa-f]+) want=(0x[0-9A-Fa-f]+) (O|MSAC)\b", l)
        if not m:
            m2 = re.search(r"\b(gfw=0x[0-9A-Fa-f]+) (O|MSAC)\b", l)
            if m2 and m2.group(2) in ("O", "MSAC"):
                say("  " + l)
            continue
        got, want, tail = m.group(1), m.group(2), m.group(3)
        verdict = "OK" if tail == "O" else "MISMATCH"
        same = got.lower() == want.lower()
        say("  %-16s got=%s want=%-10s %s%s"
            % ("<поле>", got, want, verdict, "" if same else "   <-- НЕ СОВПАДАЕТ"))
        fixed += 1
    if fixed:
        say("  (метки OK/MISMATCH восстановлены по длине: форматтер был сломан)")

    probe = [l for l in keys if l.startswith("PROBE")]
    for l in probe:
        say("  " + l)
    # 'bar0=0' без продолжения — иначе подстрока совпадёт и с 'bar0=0xF6000000'
    nobar = [l for l in probe if re.search(r"\bbar0=0(?!x)", l)]
    if nobar:
        say("  => есть функция БЕЗ BAR0: это НЕ рабочая карта (фантом).")
        real = [l for l in probe if l not in nobar]
        if real:
            say("  => настоящая карта: " + real[0].strip())
    if any("chip=0xFFFFFFFF" in l for l in probe):
        say("  => BAR0 не отображён: зонд вернул 0xFFFFFFFF, ответ не получен.")
        say("     НУЖНО СДЕЛАТЬ: сначала поднять BAR0 (PCIE_CMD) и повторить.")
    if re.search(r"imem_card=0x0{8}\b", s):
        say("  => imem_card=0: в GSP IMEM пусто, штатного FWSEC на карте нет.")
    if "dbg=0x00780009" in s:
        say("  => dbg=0x780009: ядро стартует и гибнет (проверка подписи).")
    ok = [l for l in keys if l.startswith("FWSEC try=")]
    if ok:
        say("")
        say("  попытки FWSEC: " + "; ".join(l.split("FWSEC ")[-1] for l in ok))
        if any("OK with sig" in l for l in keys):
            say("  => ЕСТЬ СРАБОТАВШАЯ ПОДПИСЬ — см. строку 'OK with sig'.")
    if a.out:
        with open(a.out, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(report) + "\n")
        say("")
        say("Отчёт сохранён: %s (%d строк)" % (a.out, len(report)))
    if a.raw:
        with open(a.raw, "wb") as f:
            f.write(raw)
        say("Сырые секторы сохранены: %s (%d байт)" % (a.raw, len(raw)))
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)


if __name__ == "__main__":
    main()
