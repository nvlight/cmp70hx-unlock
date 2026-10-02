#!/bin/bash
# verify_v316.sh — приёмка оптимизации v3.16 (docs/SPEED-REFACTOR.md).
#
# Запуск из корня репозитория (или из src/):
#     bash src/tools/verify_v316.sh
#
# Что проверяет и почему это не «просто собрать и посмотреть»:
#
#  1) Сборка проходит без warning. В этом проекте предупреждение
#     компилятора уже один раз стоило рабочего бинаря: «excess elements
#     in array initializer» молча отбросил 7 элементов из таблицы масок,
#     и из-за этого селектор не вставал (см. комментарий в
#     render_open_gfx_masks). Молчаливый сбой — норма здесь.
#
#  2) Юнит-тесты проходят: crc32_check (табличный CRC == побитовый) и
#     poll_model (модель нового ожидания очереди DMA). Оба обязательны:
#     первый защищает значения CRC в логе от тихой смены, второй —
#     от тихой смены поведения на живой очереди.
#
#  3) Все маркерные строки новой диагностики ДОШЛИ до .efi. Это не
#     формальность: objcopy вырезает секции поимённо, и строка, не
#     дошедшая до бинаря, означает вырезанный кусок логики. Именно так
#     уже терялся маркер END (см. комментарий у log_flush_sector).
#
#  4) ОТКАТ СОБИРАЕТСЯ И ДАЁТ ПИН DEE0BAAB. Проверка идёт в
#     отдельном git worktree, чтобы не трогать рабочее дерево.
#     Это та самая проверка, ради которой существует тег
#     rollback-2026-10-01: откат обязан воспроизводиться, а не лежать
#     файлом. Если оптимизация сломала её — отката нет.
# БЕЗ `set -e`: скрипт обязан ДОЙТИ до итога и показать, сколько пунктов
# пройдено. С `set -e` первый упавший gcc роняет всё молча, и отчёт
# выглядит как «ничего не проверено» — то есть как «всё хорошо».
# Каждая проверка ниже сама решает, ошибка это или нет.
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SRC="$ROOT/src"
PASS=0
FAIL=0

ok()   { printf '  \033[32mOK\033[0m   %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
hdr()  { printf '\n=== %s ===\n' "$1"; }

# ---------------------------------------------------------------- 1. сборка
hdr "1. сборка"
BUILD_LOG=$(cd "$SRC" && bash build.sh 2>&1) || { printf '%s\n' "$BUILD_LOG"; bad "build.sh завершился с ошибкой"; exit 1; }

WARN=$(printf '%s' "$BUILD_LOG" | grep -Ei 'warning:' || true)
if [ -n "$WARN" ]; then
    printf '%s\n' "$WARN"
    bad "есть предупреждения компилятора"
else
    ok "собрано без предупреждений"
fi

NEW_MD5=$(cd "$SRC" && md5sum unlock_v3r.efi | cut -d' ' -f1)
NEW_SIZE=$(cd "$SRC" && stat -c%s unlock_v3r.efi)
printf '  новый бинарь: md5 %s (%s байт)\n' "$NEW_MD5" "$NEW_SIZE"

# Предупреждение, а не проверка: md5 обязан отличаться от пинованного,
# иначе либо оптимизация не попала в сборку, либо REF_MD5 устарел.
PIN=DEE0BAAB1B7C222399C091EAD15D071B
if [ "$NEW_MD5" = "$PIN" ]; then
    bad "md5 совпал с пинованием ДО оптимизации — правки не в сборке?"
else
    ok "md5 отличается от пинования до оптимизации (ожидаемо)"
fi

# ------------------------------------------------------------ 2. юнит-тесты
hdr "2. юнит-тесты"
cd "$SRC"
if gcc -O2 -Wall -o /tmp/v316_crc32 tools/crc32_check.c 2>/tmp/v316_crc32.log \
   && /tmp/v316_crc32 >/tmp/v316_crc32.out 2>&1; then
    ok "crc32_check: табличный CRC == побитовый ($(grep -c OK /tmp/v316_crc32.out) проверок)"
else
    cat /tmp/v316_crc32.log /tmp/v316_crc32.out
    bad "crc32_check упал — значения CRC в логе могли измениться"
fi

if gcc -O2 -Wall -o /tmp/v316_poll tools/poll_model.c 2>/tmp/v316_poll.log \
   && /tmp/v316_poll >/tmp/v316_poll.out 2>&1; then
    ok "poll_model: поведение на живой очереди не изменилось"
else
    cat /tmp/v316_poll.log /tmp/v316_poll.out
    bad "poll_model упал — сценарий живой очереди изменился"
fi
cd "$ROOT"

# ----------------------------------------------- 3. маркеры дошли до .efi
hdr "3. маркерные строки в .efi"
EFITEXT="$SRC/unlock_v3r.efi"
if [ ! -f "$EFITEXT" ]; then
    bad "нет $EFITEXT"
else
    # Лог пишется широкими строками, читать надо и как UTF-16LE.
    for m in \
        'CLOCK tsc=' \
        'timing summary' \
        'repeat gate' \
        'BL settle' \
        'DMAQ2' \
        'FWL' \
        'SCRUB' \
        'phase accounting' \
        'fwsec: v2.43 cmd scan' \
        'full dump throttled' \
        'PROBE  throttled' \
        'BOOTER iters=' \
        'XVE window open' \
        'end of log'
    do
        n=$( { strings -a "$EFITEXT"; strings -a -el "$EFITEXT"; } | grep -cF "$m" || true)
        if [ "$n" -gt 0 ]; then
            ok "маркер найден ($n): $m"
        else
            bad "маркер ПОТЕРЯН при сборке: $m"
        fi
    done
fi

# -------------------------------------------------------- 4. откат собирается
hdr "4. откат (git tag rollback-2026-10-01) воспроизводится"
WT="$ROOT/.verify-rollback-wt"
rm -rf "$WT"
if git -C "$ROOT" worktree add --detach "$WT" rollback-2026-10-01 >/dev/null 2>&1; then
    # Блобы не в git, поэтому копируем из основного дерева.
    mkdir -p "$WT/src/blobs"
    cp "$SRC"/blobs/*.bin "$WT/src/blobs/" 2>/dev/null || true
    RB=$(cd "$WT/src" && bash build.sh 2>&1 | tail -3) || true
    RB_MD5=$(cd "$WT/src" && md5sum unlock_v3r.efi 2>/dev/null | cut -d' ' -f1 || echo none)
    RB_SIZE=$(cd "$WT/src" && stat -c%s unlock_v3r.efi 2>/dev/null || echo 0)
    # md5sum печатает в нижнем регистре, а REF_MD5 в build.sh и
    # flash-build.ps1 — в верхнем. Сравнивать нужно в одном регистре,
    # иначе проверка отката даёт ложный FAIL на правильной сборке.
    if [ "$(printf '%s' "$RB_MD5" | tr 'a-f' 'A-F')" = "$PIN" ]; then
        ok "откат собирается и даёт пин $RB_MD5 ($RB_SIZE байт)"
    else
        printf '%s\n' "$RB"
        bad "откат дал $RB_MD5 ($RB_SIZE байт), ожидался $PIN (657408)"
    fi
    git -C "$ROOT" worktree remove --force "$WT" >/dev/null 2>&1 || rm -rf "$WT"
else
    bad "не удалось создать worktree для проверки отката"
fi

# ------------------------------------------------------------------ итог
hdr "итог"
printf '  пройдено: %d, провалено: %d\n' "$PASS" "$FAIL"
if [ "$FAIL" -ne 0 ]; then
    printf '\n\033[31mПРИЁМКА НЕ ПРОЙДЕНА\033[0m — на флешку ничего прошивать.\n'
    exit 1
fi
cat <<EOF

  \033[32mПРИЁМКА ПРОЙДЕНА\033[0m. Это проверка сборки и эквивалентности,
  НЕ проверка разблокировки. Следующий обязательный шаг — прогон на
  карте и сверка строк (docs/SPEED-REFACTOR.md, раздел «Что нужно
  проверить на железе»), по убыванию важности:

      G2RMS ... TOTAL: XVE window open 24 of 25   <- рендер жив
      WPR2 ESTABLISHED = 24 раза, нигде dbg=0x007E0009
      END   ss0=0x88888888 ss1=0x00000008 PLM=0xFFFFFFFF
      SCRUB  ...                      <- сколько стоит скраб (не знаем)
      CLOCK tsc=... BAR0 read=...ns   <- цена ОБЯЗАНА быть на 2-м вызове

  ФАКТИЧЕСКОЕ ВРЕМЯ (2026-10-02, исправленная сборка): 1 мин 53 с против
  5 мин 30 с исходных, при ЖИВОЙ разблокировке (24 из 25). То есть
  оптимизация ожиданий дала реальный выигрыш в ~2,9 раза — но не потому,
  что время шло в пустое вращение DMA, как считалось раньше, а потому что
  убраны слепые паузы и ожидания, которые не ждали события. Следующая
  строка, которая разбирает ОСТАВШЕЕСЯ время, — фазовый учёт:

      TIME   === phase accounting ===

  Без этого лога сборка не проверена, а md5 записывать в build.sh рано.
EOF
