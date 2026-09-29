"""Повторные замеры issue-rate с проверкой стабильности.

Зачем. `issrate.py` меряет каждую единицу ОДНИМ окном ~100 мс. Этого мало:
в замере 2026-09-30 одна единица (FFMA32) попала в 1972 G inst/s при
соседних 5415 — и это выглядело как регрессия в 2,7 раза. Три
немедленных повтора дали 5415 / 5417 / 5417, то есть падение было
разовым, а не состоянием карты.

Вывод, который стоит запомнить: единичный выход FFMA32 за 4000 G inst/s —
не повод объявлять поломку. Но и молчать об этом нельзя: настоящая
регрессия в 2,7 раза выглядела бы точно так же, если бы попала в другое
окно. Поэтому здесь каждая единица меряется N раз, и решение принимается
по медиане, а отклонения печатаются явно.

Порог тревоги — 60% от медианы по этой же единице. Ниже него считаем, что
это настоящая регрессия, а не шум.
"""
import argparse
import json
import re
import statistics
import subprocess
import sys

FFMA_LINE = re.compile(
    r"^(FFMA32|FADD32|FMA16|FMA32BF|DP4A|IADD32)\s+\S+\s+([0-9.]+)\s+"
    r"([0-9.]+)\s+([0-9]+)\s+([0-9.]+)\s+([0-9.]+)\s+([0-9.]+)%")

THRESH = 0.60


def run(tag):
    p = subprocess.run(
        [sys.executable, r"src\tools\issrate.py", "--tag", tag],
        capture_output=True, text=True, encoding="utf-8", errors="replace")
    out = {}
    for ln in p.stdout.splitlines():
        m = FFMA_LINE.match(ln.strip())
        if m:
            out[m.group(1)] = {
                "ginst": float(m.group(2)),
                "tflop": float(m.group(3)),
                "mhz": int(m.group(4)),
                "watt": float(m.group(5)),
                "pct": float(m.group(7)),
            }
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", "--runs", type=int, default=3)
    ap.add_argument("--tag", default="stable")
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    runs = [run("%s-r%d" % (args.tag, i + 1)) for i in range(args.runs)]
    units = sorted(set().union(*[set(r) for r in runs]))
    if not units:
        raise SystemExit("no unit lines parsed — is issrate.py working?")

    print("=" * 78)
    print("issrate-stable  %d прогонов, решение по МЕДИАНЕ" % args.runs)
    print("=" * 78)
    print("%-8s %10s %10s %10s %8s" % ("unit", "медиана", "мин", "макс", "%пик"))
    print("-" * 78)

    result, alarms = {}, []
    for u in units:
        vals = [r[u]["ginst"] for r in runs if u in r]
        if not vals:
            continue
        med = statistics.median(vals)
        lo, hi = min(vals), max(vals)
        pct = statistics.median([r[u]["pct"] for r in runs if u in r])
        result[u] = {"median": med, "min": lo, "max": hi, "pct": pct,
                     "runs": vals}
        flag = ""
        if lo < med * THRESH:
            flag = "  *** ПАДЕНИЕ НИЖЕ 60% ОТ МЕДИАНЫ ***"
            alarms.append(u)
        print("%-8s %10.1f %10.1f %10.1f %7.1f%%%s"
              % (u, med, lo, hi, pct, flag))

    print()
    if alarms:
        print("ТРЕВОГА: %s — разброс больше, чем можно списать на шум."
              % ", ".join(alarms))
        print("Нужен разбор: это регрессия или попадание в чужое окно.")
        rc = 1
    else:
        print("Все единицы стабильны в пределах %.0f%% от медианы. Регрессии нет."
              % (100 * THRESH))
        rc = 0
    print()
    print("Порог тревоги: мин < %.0f%% от медианы этой же единицы." % (100 * THRESH))
    print("Почему медиана, а не первый замер: см. описание в начале файла —")
    print("одно окно ~100 мс однажды дало FFMA32=1972 при соседних 5415.")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"runs": args.runs, "threshold": THRESH,
                       "units": result, "alarms": alarms}, f, indent=2)
        print("json: %s" % args.json)
    return rc


if __name__ == "__main__":
    sys.exit(main())
