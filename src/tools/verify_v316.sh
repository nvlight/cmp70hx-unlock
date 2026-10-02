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
    #
    # ВНИМАНИЕ: список соответствует ТОМУ, ЧТО РЕАЛЬНО ЕСТЬ в сборке.
    # Маркеры ещё не восстановленных возможностей сюда НЕ входят, иначе
    # приёмка всегда красная и перестаёт что-либо значить:
    #   'CLOCK tsc=' ... BAR0 read=   — замер цены MMIO (шаг «цена чтения»)
    #   'timing summary'               — сводка TIME
    #   'repeat gate'                  — разрежение повторов
    #   'full dump throttled'          — разрежение повторов sec2_window_dump
    #   'PROBE  throttled'             — разрежение повторов wpr2_probe
    # Они добавляются вместе с самой возможностью.
    #
    # v3.17: 'sweep_all(POST) took' заменена на 'sweep_all(POST) SKIPPED'.
    # Свип ушёл за флаг FX_DIAG_SWEEPS (=0), поэтому в релизной сборке
    # обязана присутствовать строка ОТКАЗА, а не отчёт о выполнении:
    # пропуск обязан быть виден (BUILDING 6.0). Проверка не ослаблена, а
    # перенаправлена на ту строку, которая теперь обязана быть в бинаре.
    # Три новых маркера - итог v3.17 по прямой записи масок и по цене вывода.
    #
    # v3.18: прямой записи масок в релизе больше нет - гипотеза опровергнута
    # замером (BEFORE и ПОСЛЕ совпали побайтово), попытка убрана за флаг
    # FX_DIAG_DIRECTMASK. Поэтому маркер 'render masks: direct=' заменён на
    # итог новой стратегии 'render masks: fast=' и на строку пропуска пробы
    # доступа к кадровому буферу. Добавлен 'CHECK' - это сверка суммы фаз с
    # реально прошедшим временем: если двойной счёт вернётся, в логе будет
    # 'CHECK *** FAILED', и приёмка обязана это заметить.
    #
    # v3.18: 'booter_load_v67: load+reset' заменён тремя частями. Эта фаза
    # стоила 1196 мс на вызов при 49 мкс фактического исполнения ботера,
    # то есть почти всё время уходило в подготовку, и одним именем
    # разложить её было нельзя.
    #
    # v3.19: 'FAST ' убран - быстрый путь промахнулся 7 из 7 и удалён.
    # Взамен добавлен 'depth OK': это строка проверки перекоса счётчика
    # глубины. Лишний fx_ph_end уводил глубину в минус и делал ВСЕ фазы
    # вложенными (прогон v3.18: 16 из 16 (inside), SUM top-level = 0).
    # Теперь такой перекос печатается как 'DEPTH UNDERFLOW x N', а его
    # отсутствие - как 'depth OK'. Маркер 'depth OK' означает: строка в
    # бинаре есть, и в логе она ОБЯЗАТЕЛЬНО появится, то есть механизм
    # защиты не вырезан оптимизатором.
    for m in \
        'BL settle' \
        'DMAQ2' \
        'FWL' \
        'SCRUB' \
        'phase accounting' \
        'v2.43 cmd scan' \
        'render: FLR' \
        'render: early_unlock_path' \
        'render: ROP write' \
        'booter: reset+scrub' \
        'booter: wpr2+setup' \
        'booter: dma image' \
        'sweep_all(POST) SKIPPED' \
        'render masks: booter#1 done' \
        'render masks: sweep finished' \
        'final: before return' \
        'BOOTER iters=' \
        'XVE window open' \
        'FBP    SKIPPED' \
        'render masks: fast=' \
        'depth OK' \
        'CHECK' \
        'PRN   ==== console ring' \
        'console ring NOT DUMPED' \
        '=== unlock done' \
        '=== last ' \
        'I/O: Print n=' \
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

      G2RMS ... TOTAL: XVE window open 8 of 8     <- рендер жив
      G2GFX ... GFX_SPEED_SELECT=0x00000004 ВСТАЛ <- главный признак
      WPR2 ESTABLISHED, нигде dbg=0x007E0009
      END   ss0=0x88888888 ss1=0x00000008 PLM=0xFFFFFFFF
      TIME  I/O: Print n=... measured=...us/call  <- цена вывода
      TIME  render masks: fast=... fast_miss=...   <- сработал ли быстрый путь
      TIME   === phase accounting ===
      TIME   CHECK ... unaccounted ...             <- остаток вне фаз

  'CHECK *** FAILED' в логе означает, что сумма фаз больше прошедшего
  времени, то есть вернулся двойной счёт, и таблице верить нельзя.

  Без этого лога сборка не проверена, а md5 записывать в build.sh рано.

  ОСТАВШЕЕСЯ ВРЕМЯ. Бюджет прогона 3:40 и его разложение — в
  ../PLAN-SPEED.md; разбор прошлых неудачных оптимизаций и почему
  оценка без измерения дала три регрессии подряд — в
  docs/SPEED-REFACTOR.md. Читать перед следующей правкой.
EOF
