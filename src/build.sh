#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# build.sh — build the CMP 70HX unlock EFI loader from unlock_v2.c (gnu-efi)
#
# Usage:
#   BLOBS=/path/to/blobs bash build.sh
#
# ONE TARGET, ONE OUTPUT. The tree builds exactly one binary, unlock_v3r.efi,
# which is simultaneously the loader you flash and the rollback you flash to go
# back. There is deliberately no second variant.
#
# The compute-only release build (unlock_v3n, 3D disabled) was retired
# 2026-10-01. Reason: it sat in out/ next to the working build under a name that
# read like "the current release", and the flash instructions were followed
# literally once — which put the card back to zero in games while compute kept
# working, so nothing looked broken. A rollback that is a *degraded* build is
# worse than no rollback: do not reintroduce a parallel compute-only target.
#
# Reproducibility, which is what makes this binary the rollback:
#
#   ПРЕДЫДУЩИЙ отпечаток (состояние ДО v3.16, до сих пор действителен):
#     unlock_v3r.efi  md5 DEE0BAAB1B7C222399C091EAD15D071B  657408 bytes
#   Verified on hardware 2026-09-30, and again after a reboot run on 2026-10-01
#   (G2GFX ... GFX_SPEED_SELECT=0x00000004 ***ВСТАЛ***, END marker in the log).
#   That md5 is pinned by git tag rollback-2026-10-01. If a rebuild stops
#   matching it, a string or a helper leaked in outside an #ifdef — see
#   BUILDING.md §6.0.
#
#   НОВЫЙ отпечаток НЕ ВПИСАН СЮДА НАМЕРЕННО. Код тронут, значит md5
#   изменился. Вписать новое значение можно только ПОСЛЕ успешного
#   прогона на железе: отпечаток, который не совпадает с фактической
#   сборкой, хуже отсутствующего — он создаёт видимость проверки. До
#   этого момента out/flash-build.ps1 обязан ругаться (-AllowNewBuild).
#   Обновлено 2026-10-04: v3.40 (2 маски рендера) проверен на железе дважды,
#   8 470 и 8 451 мс, поэтому 2abf59a0 внесён в список проверенных выше.
#
#   ИСТОРИЯ v3.16, КОТОРУЮ НУЖНО ЗНАТЬ ПЕРЕД СЛЕДУЮЩЕЙ ПРАВКОЙ.
#   Первая версия оптимизации по скорости была основана на разборе,
#   где время делилось по статическому чтению кода: «74 % на
#   gsp_dma_wait_not_full, 15 % на слепые 2 с, 7 % на слепую паузу 1 с».
#   Прогон на реальной карте это опроверг: вышло 4:53 вместо обещанных
#   40-60 с, И разблокировка сломалась (маски 5 из 25 вместо 24 из 25,
#   WPR2 защёлкнулся 8 раз вместо 24, dbg=0x007E0009 вместо 0x00000000).
#
#   Причина одна: стоимость MMIO-чтения в том разборе была ПРИКИДКОЙ
#   (~8 мкс), а не измерением. Реально — единицы микросекунд. На этой
#   неверной оценке стояло всё решение, и из неё же выросли три правки,
#   которые и сломали результат:
#     * выход по «регистры не меняются» в ожидании скраба IMEM и
#       RESET_READY — там тишина означает «работа идёт», а не «готово»,
#       и DMA уходила в ещё затираемую память;
#     * ожидание HALT по «CPUCTL != STARTCPU» — запись posted, чтение
#       сразу после неё отдаёт старое значение, выход срабатывал через
#       0-2 мкс вместо 200 мс;
#     * признак «BAR0 отображён» никогда не становился истинным.
#   Все три откатаны. Подробно — PLAN-SPEED.md (часть II, ретроспектива v3.16).
#
#   ПРАВИЛО НА БУДУЩЕЕ: сначала измерить (строки CLOCK/SCRUB/FWL/TIME в
#   логе), потом решать. Не прикидывать стоимость доступа.
#
#   ЧТО ПРОВЕРИТЬ НА ЖЕЛЕЗЕ (одним прогоном; полные строки в
#   PLAN-SPEED.md (часть II, ретроспектива v3.16)). По убыванию важности:
#     1) результат разблокировки не изменился:
#          G2RMS ... TOTAL: XVE window open 24 of 25
#          END   ss0=0x88888888 ss1=0x00000008 PLM=0xFFFFFFFF
#        Ориентир — прогон 2026-10-01.
#     2) `WPR2 ESTABLISHED` — должно быть 24 раза (в сломанной сборке
#        было 8). И нигде не должно встречаться dbg=0x007E0009.
#     3) `SCRUB  ...` — сколько на самом деле стоит скраб после ресета.
#        Этих данных раньше не было, и они определяют, есть ли запас.
#     4) `CLOCK tsc=... BAR0 read=...ns` — строка обязана содержать цену
#        чтения. Если на ВТОРОМ вызове написано «BAR0 not mapped yet»,
#        измерение снова сломано.
#     5) `G2RMK ... became ... (polls=N)`: если хоть одна маска встала
#        с polls > 0, запись ROP асинхронна и сокращённых 100 попыток
#        ей мало — вернуть FX_MASK_POLL_TRIES = 400.
#     6) время прогона: ожидается около 1:50 (факт 2026-10-02). Если
#        выросло — смотреть `TIME   === phase accounting ===` в конце
#        лога: там разложение по фазам.
set -e

WORK="$(cd "$(dirname "$0")" && pwd)"
cd "$WORK"
BLOBS="${BLOBS:-$WORK/blobs}"

# ---- target profile: chip, FB size and the matching FWSEC blob -------------
# The FWSEC ucode is per-die (extracted from that die's VBIOS), so the profile
# and the blob go together. See the TARGET PROFILE block in unlock_v2.c.
# CMP 90HX / GA102 is no longer a build target. The port is 70HX-only, and the
# 10 GB card must never be driven with this 8 GB profile — the alt device ID
# still open to it is a known latent hazard, tracked in KNOWN-ISSUES.
DEF="-DTARGET_CMP70HX"
FWSEC="fwsec_ga104"          # extracted from a GA104 VBIOS
export DEF FWSEC

echo "=== NVIDIA CMP unlock EFI build — target: CMP 70HX / GA104 / 8 GB ==="

# ---- required firmware/payload blobs (NOT in git — see BUILDING.md) ----
for f in \
    v67_payload.bin \
    booter_ucode_dbg_patched.bin \
    booter_ucode_prod_patched.bin \
    gsp_rm_boot_dbg.bin \
    ${FWSEC}.bin ${FWSEC}_sig.bin \
    sec2_ucode_vbios_49_patched.bin sec2_ucode_vbios_89_patched.bin
do
    [ -f "$BLOBS/$f" ] || { echo "ERROR: $BLOBS/$f not found — see BUILDING.md"; exit 1; }
done
# objcopy encodes the input FILE PATH into generated symbol names, so blobs
# must be embedded under their bare names — copy them next to the script.
cp -f "$BLOBS"/*.bin .

EFI_INC=/usr/include/efi
EFI_LIB=/usr/lib

# objcopy embeds a blob as an object file; auto-generated symbols are named
# after the input FILE NAME (path included!), e.g. foo/bar.bin becomes
# _binary_foo_bar_bin_start. Embed under the BARE name and derive the symbol
# stem mechanically, then VERIFY the target symbol actually appeared —
# with -shared a silent mismatch would leave the reference unresolved and
# produce a broken .efi instead of a link error.
embed() { # embed <bare-file-name-in-cwd> <target-sym>
    local f="$1" tgt="$2"
    local base="${f//./_}"   # v67_payload.bin -> _binary_v67_payload_bin_*
    objcopy --input-target binary --output-target elf64-x86-64 \
        --binary-architecture i386:x86-64 \
        --redefine-sym "_binary_${base}_start=${tgt}" \
        --redefine-sym "_binary_${base}_end=${tgt}_end" \
        --redefine-sym "_binary_${base}_size=${tgt}_size" \
        "$f" "${tgt}.o"
    nm "${tgt}.o" | grep -q " ${tgt}$" || {
        echo "ERROR: symbol $tgt missing in ${tgt}.o"; exit 1;
    }
}
embed "v67_payload.bin"                  v67_payload_bin
embed "booter_ucode_dbg_patched.bin"     booter_ucode_dbg
embed "booter_ucode_prod_patched.bin"    booter_ucode_prod
embed "gsp_rm_boot_dbg.bin"              gsp_rm_boot_dbg
embed "${FWSEC}.bin"                     fwsec_ga104_bin
embed "${FWSEC}_sig.bin"                 fwsec_ga104_sig
# Три версии подписи FWSEC из VBIOS самой карты: подпись НЕ считается по
# образу (у GA102 и GA104 она байт-в-байт одинакова), а версионируется по
# fuse-ревизии. Приложение перебирает их по очереди (v2.106).
embed "fwsec_ga104_prod_sig0.bin"        fwsec_ga104_prod_sig0
embed "fwsec_ga104_prod_sig1.bin"        fwsec_ga104_prod_sig1
embed "fwsec_ga104_prod_sig2.bin"        fwsec_ga104_prod_sig2
embed "sec2_ucode_vbios_49_patched.bin"  sec2_ucode_vbios_49
embed "sec2_ucode_vbios_89_patched.bin"  sec2_ucode_vbios_89
OBJECTS="v67_payload_bin.o booter_ucode_dbg.o booter_ucode_prod.o \
gsp_rm_boot_dbg.o fwsec_ga104_bin.o fwsec_ga104_sig.o \
fwsec_ga104_prod_sig0.o fwsec_ga104_prod_sig1.o fwsec_ga104_prod_sig2.o \
sec2_ucode_vbios_49.o sec2_ucode_vbios_89.o"

# build_one <output-base> <extra -D flags...>
# Flags are load-bearing: they decide which phases exist in the binary.
build_one() {
    local out="$1"; shift
    local name="L\"${FWSEC}.bin\""
    gcc -c -fno-stack-protector -fpic -fshort-wchar -mno-red-zone -O2 \
        -I "$EFI_INC" -I "$EFI_INC/x86_64" \
        -DEFI_FUNCTION_WRAPPER "$DEF" -DFWSEC_BLOB_NAME="$name" "$@" \
        -o "$out.o" unlock_v2.c
    ld -shared -Bsymbolic -L "$EFI_LIB" -T "$EFI_LIB/elf_x86_64_efi.lds" \
        "$EFI_LIB/crt0-efi-x86_64.o" \
        "$out.o" $OBJECTS \
        -lgnuefi -lefi -o "$out.so"
# objcopy needs the INPUT format spelled out on binutils >= 2.40: without -I it
# guesses from its own defaults and bails with "file format not recognized" on
# a stripped ELF shared object. Use -O (not the long --target= form) for the
# output: with -j between them the long form mis-parses the same way.
    SO="$out.so"
    EFI="$out.efi"
    objcopy -I elf64-x86-64 -O elf64-x86-64 --remove-section=.note* --remove-section=.eh_frame* \
       --strip-all "$SO" "${SO}.tmp"
# Section list is spelled out, NOT globbed. Two traps:
#  * .rodata is not optional — gcc puts every L"..." Print() literal there.
#    Drop it and the app still runs but prints nothing at all: no version
#    banner, no WPR2/PLM/SS0 values. Exactly the output you need to tell a
#    70HX from a 90HX and to read the FWSEC poll results off the screen.
#  * do NOT glob .rel* / .rela*: that also matches .rela.plt, whose 9-char
#    name does not fit a PE section header, so objcopy emits a bogus "/4"
#    string-table reference. Name the sections explicitly instead.
    objcopy -I elf64-x86-64 \
        -j .text -j .sdata -j .data -j .rodata \
        -j .dynamic -j .dynsym -j .reloc -j .rela \
        -O pei-x86-64 --subsystem=10 --image-base=0 \
        "${SO}.tmp" "$EFI"
    rm -f "${SO}.tmp"
    echo "[*] Built: $out.efi ($(stat -c%s "$out.efi") bytes)"
}

# ---- единственная сборка ----------------------------------------------------
# Все варианты, кроме этого, удалены 2026-10-01. Их история — в git: история
# ступеней (dev-ветка, QEMU-стенд, plan-B endgame, релизы v3/v3f/v3n и
# промежуточная v3g) восстанавливается из коммитов и раздела PORT-STATUS §1.
# Хронология нужна для понимания, почему выбран именно этот набор флагов, но
# сами бинарники не нужны: ни один из них не является точкой возврата.
#
# РАБОЧАЯ СБОРКА (состояние исходников на v3.15). Именно она в проекте даёт и
# compute-анлок (x11,25 по pp512), и игровую разблокировку (Cyberpunk 2077,
# 50 fps / 135 Вт при GFX_SPEED_SELECT=0x4). ЭТО ТО, ЧТО ПРОШИВАЕТСЯ НА ФЛЕШКУ.
#
#   -DRENDER_MASKS     открывает маски, запирающие GFX_SPEED_SELECT, через
#                      параметризованный V67-ROP (адрес/значение берутся из
#                      v67Phys+0xf960/+0xf948 — payload менять не нужно), и
#                      записывает сам селектор. Без этого флага сборка
#                      compute-only и в играх даёт ноль.
#   -DCHIP_SIZE_SCAN=1 сканирует BAR0 на признак размера кристалла
#                      (v3.15, только чтение).
#
# Селекторы и фикс Code 43 обычного хвоста не трогаем, g_gen2Fire не
# выставляется (Gen2 выключен рубильником, см. PORT-STATUS §3a).
#
# Проверено на железе дважды: 2026-09-30 и прогон после перезагрузки
# 2026-10-01. md5 DEE0BAAB1B7C222399C091EAD15D071B, 657408 байт.
# Подробности — PORT-STATUS §1t, §1u, §9.
#
# ЭТА СБОРКА — ОДНОВРЕМЕННО И РАБОЧАЯ, И ОТКАТ. Отдельной откатной сборки
# больше нет: прошивается и запасной вариант — один и тот же файл. Откат
# держится не «замороженным бинарником», а воспроизводимостью от исходников
# на теге rollback-2026-10-01:
#
#     git checkout rollback-2026-10-01 && bash build.sh   ->  DEE0BAAB…
#
# Пока пересборка даёт этот md5 — откат существует. Перестала давать — код
# ушёл от известного-good состояния, и возвращаться некуда, пока тег не
# передвинут осознанно. Механизм проверки — BUILDING.md §6.0 и out/flash-build.ps1.
build_one unlock_v3r          -DRELEASE_BUILD -DMULTI_CARD -DPCIE_GEN2_REJOIN \
                              -DFULL_NOGEN2 -DGEN2_LINK_TRY -DRENDER_MASKS -DCHIP_SIZE_SCAN=1

# ---- ОПЦИОНАЛЬНАЯ МАТРИЦА (по умолчанию выключена, 2026-10-06) --------------
if [ -n "$RENDER_MATRIX" ]; then
#
# Ничего из перечисленного не меняет релизную сборку выше: блок выполняется
# только при RENDER_MATRIX=1 в окружении. Нужен для трёх экспериментов из
# docs/RENDER-LIMITS.md, у каждого из которых ровно один измеряемый вопрос и
# ровно один критерий.
#
#   RENDER_MATRIX=1 bash build.sh
#
# ВНИМАНИЕ О ТРАКТОВКЕ: каждый бинарь здесь - НЕ откат. Откат остаётся за
# unlock_v3r и за тегом rollback-*. Экспериментальные сборки делаются ради
# одной прошивки флешки и одного замера; класть их в out/ не нужно.
#
# E3 - binselector GFX_SPEED_SELECT. Поле трёхбитное. Измеренная лестница
#      (Cyberpunk, High, без лучей, тот же пресет):
#         0x2 ->  9 fps    0x4 -> 50 fps / 135 Вт   (единственный рабочий пик)
#         0x5 -> 26 fps    0x6 -> 16 fps    0x7 ->  9 fps
#      Проверено 6 значений из 8. Не проверены только 0x1 и 0x3.
#      0x6 ОПРОВЕРГНУТ как «более высокий бин»: выше 0x4 отклик падает
#      монотонно, пик единственный и лежит на 0x4.
for V in 0x1 0x3 0x6; do
    build_one "gfxsel_$V"      -DRELEASE_BUILD -DMULTI_CARD -DPCIE_GEN2_REJOIN \
                                  -DFULL_NOGEN2 -DGEN2_LINK_TRY -DRENDER_MASKS \
                                  -DCHIP_SIZE_SCAN=1 -DGFX_SPEED_SEL_VALUE=$V
done

# E1 - положительный контроль над GspFwWprMeta.fbSize. Намеренно ЗАНИЖАЕМ
#      размер кадра вдвое: если totalGlobalMem в Windows последует за полем,
#      поле управляет тем, что видит драйвер, и рычаг "управлять чипом до
#      BAR0" жив. Если нет - класс гипотез закрыт.
build_one wprfb_4g            -DRELEASE_BUILD -DMULTI_CARD -DPCIE_GEN2_REJOIN \
                              -DFULL_NOGEN2 -DGEN2_LINK_TRY -DRENDER_MASKS \
                              -DCHIP_SIZE_SCAN=1 -DWPR_META_FB_SIZE=0x100000000

# E2 - обратный тест на байт flags: снимаем GSP_FW_FLAGS_CLOCK_BOOST. Часы
#      падают -> поле живое, вопрос "можно ли им управлять" открыт. Часы те
#      же -> поле мертво, класс закрыт.
build_one wprflags_0           -DRELEASE_BUILD -DMULTI_CARD -DPCIE_GEN2_REJOIN \
                              -DFULL_NOGEN2 -DGEN2_LINK_TRY -DRENDER_MASKS \
                              -DCHIP_SIZE_SCAN=1 -DWPR_META_FLAGS=0x0

# E4 (2026-10-08) - A1 + A3 из docs/POWER-SEARCH-LIST.md, ОДИН прогон флешки.
#
#   A3: перепроверка блока OPTB 0x8200D0..0x8200F4. Вычеркнут как «валит
#       гостя в ресет» ДО того, как в v3.40 нашли баг гарда «ботер#1
#       срабатывает только на первой записи». Тот же класс молчаливого
#       отказа стоил 7 масок рендера, поэтому вердикт перепроверяется.
#   A1: страница физов 0x820Cxx, где CHIP_SCAN находит пять регистров = 48
#       (полное число SM у GA104). Ни один не записывался. Рядом по
#       официальному заголовку NVIDIA лежит NV_FUSE_STATUS_OPT_DISPLAY
#       (0x820C04), то есть это фича-фузы.
#
# Фазы внутри идут строго по возрастанию риска, и фаза 0 (только чтение,
# полный дамп страницы) идёт ПЕРВОЙ: даже жёсткое зависание в фазе 1
# оставит дамп в логе на флешке. Подробности - в комментарии
# FUSE_TABLE_PROBE в unlock_v2.c.
build_one fusetab             -DRELEASE_BUILD -DMULTI_CARD -DPCIE_GEN2_REJOIN \
                              -DFULL_NOGEN2 -DGEN2_LINK_TRY -DRENDER_MASKS \
                              -DCHIP_SIZE_SCAN=1 -DFUSE_TABLE_PROBE

# E5 (2026-10-08) - уровень 2 по итогам прогона fusetab. Тот же блок плюс
# FUSE_NB. Четыре добавления, каждое отвечает на конкретный вопрос:
#
#   NB0 - дамп страницы физов 0x823800..0x823B0F. Первый прогон её не
#         смотрел, а там лежат и загадка A2 («стоковый 0x3» физически по
#         адресу 0x823834, мы пишем в 0x823830), и вопрос A4
#         (FEAT_READOUT_0 против 3090 = 0x233 расходятся биты 8 И 9).
#   NB1 - «8 of 10» при десяти индивидуальных OPEN: печатаем адреса тех,
#         кто не удержался, и пробуем второй проход (прецедент
#         KNOWN-ISSUES #10).
#   NB2 - контроль writability на ЖИВОМ регистре 0x820C08 (15->14->15).
#         Прежний контроль стоял на 0x820C04, который документирован R-I4R,
#         то есть вывод из него был неверен.
#   NB3 (A2) - одно возмущение 0x823834: 3 -> 4 -> 3. Значение 4 выбрано
#         потому, что ровно его мы доказано пишем в 0x823830, и оно
#         ОТЛИЧАЕТСЯ от стокового 3, то есть запись различима.
#
# Фаза 0 остаётся ПЕРВОЙ и только на чтении, поэтому даже зависание в NB1
# не отнимает дамп ни 0x820Cxx, ни 0x8238xx.
build_one fusetab2            -DRELEASE_BUILD -DMULTI_CARD -DPCIE_GEN2_REJOIN \
                              -DFULL_NOGEN2 -DGEN2_LINK_TRY -DRENDER_MASKS \
                              -DCHIP_SIZE_SCAN=1 -DFUSE_TABLE_PROBE -DFUSE_NB

# E-A (2026-10-09) - гейт XP3G привилегированным писателем V67. ОДИН вопрос,
# закрываемый ОДНИМ прогоном: откроет ли V67 гейт 0x8E1B0 в точный 0xFFFFFFFF,
# который с хоста не открывается ни одной записью из 36 (PORT-STATUS 1r).
#
# Не повторяет 1q/1r: там били mmio_write32 С ХОСТА, а маска и есть защита от
# такой записи. V67 - другой, привилегированный писатель, и интерфейс блоба
# проекту уже известен (pv=payload+0xf948 -> значение, pa=payload+0x960 ->
# адрес). Реверс блоба не нужен, меняется только адрес.
#
# Три фазы строго по возрастанию риска, как требует правило проекта:
#   фаза 0 - ТОЛЬКО ЧТЕНИЕ (дамп гейта и семейства), всегда оставляет след;
#   фаза 1 - ЦЕЛЬ 0x8E1B0 <- 0xFFFFFFFF (решающий выстрел);
#   фаза 2 - КОНТРОЛЬ 0x8E1B4 <- 0xFFFFFFFF, тот же код, свой FLR-цикл.
# Контроль обязателен: без него отрицательный результат фазы 1 не отличает
# "гейт особенный" от "механизм не выстрелил" (FINAL-SUMMARY 4 - три самые
# дорогие ошибки проекта были именно такого рода).
#
# Живой линк блок НЕ трогает: ни кика 0x8872C, ни TLS, ни ретрейна, ни записей
# политики PCIe. Только снятие защиты с записи, ни одного функционального бита.
# Цена - два полных ботер-цикла, ~2,5 с прогона.
#
# Приёмка - строки в логе, читается out\pull-log.ps1:
#   XGATE phase0: gate 0x0008e1b0=0x...
#   XGATE phase1: target 0x0008e1b0 <- 0xffffffff gave 0x... OPEN|NOT OPEN
#   XGATE phase2: control 0x0008e1b4 <- 0xffffffff gave 0x... OPEN|NOT OPEN
#   XGATE VERDICT: OPEN | GATE-ONLY-LOCKED | INCONCLUSIVE
# Разбор всех трёх исходов - docs/70HX-XP3G-GATE-V67.md.
build_one xgate               -DRELEASE_BUILD -DMULTI_CARD -DPCIE_GEN2_REJOIN \
                              -DFULL_NOGEN2 -DGEN2_LINK_TRY -DRENDER_MASKS \
                              -DCHIP_SIZE_SCAN=1 -DXP3G_GATE_V67

# E-B (2026-10-09) - заливается ли policy set, когда гейт открыт. Продолжение
# E-A, вопрос который 1q назвал ДО всяких экспериментов: при закрытом гейте из
# семи полей вставало шесть, и проваливалось ровно одно - XP3G_OVR0 (0x8E110).
#
# Собирает ВМЕСТЕ с E-A: без открытого гейта E-B бессмыслен, и блок сам это
# проверяет и пишет XGPOL VERDICT: SKIPPED, а не молчит.
#
# ПОЧЕМУ ПОЛИТИКА ПИШЕТСЯ С ХОСТА, а НЕ ЧЕРЕЗ V67. Вопрос не "можно ли записать
# поле", а "снимает ли ОТКРЫТИЙ ГЕЙТ защиту с хостовой записи". Писать policy
# тоже через V67 - тавтология: привилегированный писатель пишет куда угодно, и
# результат ничего не скажет о гейте. Все семь полей - обычный mmio_write32.
#
# ЗАЩИТА ОТ ТАВТОЛОГИИ. Поле, у которого цель совпала с "до", доказывает
# ничего: запись ничего не меняет и readback совпадает по построению. Такие
# помечаются NOOP и в счёт пройденных не идут (FINAL-SUMMARY 4, ошибка N1).
#
# Живой линк не трогаем: ни кика 0x8872C, ни TLS, ни ретрейна. LnkSta читается
# до и после как контроль, что линок остался Gen1.
#
# Приёмка - строки в логе:
#   XGPOL precondition: XP3G gate 0x0008e1b0 = 0x... OPEN
#   XGPOL XP3G_OVR0 0x0008e110 before=0x... want=0x... CHANGE
#   XGPOL XP3G_OVR0 0x0008e110 wrote 0x... got 0x... STUCK|DROPPED
#   XGPOL summary: N of M changed fields stuck (K NOOP not counted)
#   XGPOL VERDICT: POLICY-OK | POLICY-PARTIAL | NO-CHANGE
# Разбор - docs/70HX-XP3G-GATE-V67.md раздел 5.
build_one xgate2              -DRELEASE_BUILD -DMULTI_CARD -DPCIE_GEN2_REJOIN \
                              -DFULL_NOGEN2 -DGEN2_LINK_TRY -DRENDER_MASKS \
                              -DCHIP_SIZE_SCAN=1 -DXP3G_GATE_V67 -DXP3G_GATE_POLICY

# E6 (2026-10-08) - проверка отчётчика селектора. САМЫЙ ДЕШЁВЫЙ ЭКСПЕРИМЕНТ
# ИЗ ВСЕХ: НОЛЬ новых записей.
#
#   Установлено: мы пишем SS0=0x88888888 в 0x82381C, а 0x82380C читается
#   0x00888888 и записи не принимает - похоже на схему "команда + отчётчик".
#   Тот же вид у селектора: пишем 0x823830=0x4, а 0x823834 стабильно 0x3.
#
#   Гипотеза: 0x823834 - отчётчик активного бина графики. Если он станет 0x4,
#   то мы (а) понимаем механизм GFX_SPEED_SELECT правильно и (б) получаем
#   ORACLE: способ узнать вступивший бин чтением регистра, вместо запуска
#   игры и замера fps. Сегодня другого способа нет.
#
#   Селекторы и так пишутся штатным путём в каждом прогоне, поэтому здесь
#   добавлены ТОЛЬКО ЧТЕНИЯ: 21 регистр до записи и 21 после. Секунды,
#   ноль риска, отката не требует.
#
#   Печатаются только ИЗМЕНИВШИЕСЯ регистры: иначе 42 строки шума вместо
#   двух. Плюс FTPO5 отвечает на вопрос A2 напрямую, без интерпретаций.
build_one oracle              -DRELEASE_BUILD -DMULTI_CARD -DPCIE_GEN2_REJOIN \
                              -DFULL_NOGEN2 -DGEN2_LINK_TRY -DRENDER_MASKS \
                              -DCHIP_SIZE_SCAN=1 -DFUSE_ORACLE

# E7 (2026-10-08) - тот же oracle, но на НЕРАБОЧИХ значениях селектора.
#
#   Установлено прогоном oracle: 0x823834 жива и связана с записью
#   селектора (3 -> 0 при записи 0x4), но НЕ повторяет его значение,
#   то есть это не эхо. Два возможных прочтения:
#     "флаг engaged" - 3 означает "стоковый режим", 0 означает "override
#                      применён"; тогда 0x823834 годится для проверки,
#                      что запись вступила, но ничего не говорит о том,
#                      осмысленно ли значение;
#     "различитель кодировок" - при бессмысленном значении регистр
#                      покажет не 0. Тогда лестницу 0x0..0xFF можно
#                      перебирать ЧТЕНИЕМ одного регистра, без игр и без
#                      замера fps, и тратить перезагрузку только на
#                      действительно перспектные значения.
#
#   Второе прочтение - практическая находка всего проекта: сейчас лестница
#   из восьми значений намерена восемью перезагрузками с ручным замером
#   fps в игре.
#
#   Что добавляет сборка: ноль записей сверх штатного пути селекторов.
#   Оба значения берутся из УЖЕ СУЩЕСТВУЮЩЕГО рычага GFX_SPEED_SEL_VALUE.
build_one gfxsel0x6_oracle    -DRELEASE_BUILD -DMULTI_CARD -DPCIE_GEN2_REJOIN \
                              -DFULL_NOGEN2 -DGEN2_LINK_TRY -DRENDER_MASKS \
                              -DCHIP_SIZE_SCAN=1 -DFUSE_ORACLE \
                              -DGFX_SPEED_SEL_VALUE=0x6
build_one gfxsel0x7_oracle    -DRELEASE_BUILD -DMULTI_CARD -DPCIE_GEN2_REJOIN \
                              -DFULL_NOGEN2 -DGEN2_LINK_TRY -DRENDER_MASKS \
                              -DCHIP_SIZE_SCAN=1 -DFUSE_ORACLE \
                              -DGFX_SPEED_SEL_VALUE=0x7

# E8 (2026-10-08) - ШАГ A: решающий прогон между двумя моделями 0x823834.
#
#   Установлено прогонами 0x4/0x6/0x7: CAND-ID идёт 3->0, 3->2, 3->3,
#   то есть градация. Но ровно те же три точки попадают под
#   cand = sel - 4, и это арифметика, а не градация. Обе модели
#   различаются ТОЛЬКО на значениях ниже 0x4:
#       селектор 0x3 (измерен как 9 fps, то есть базовый уровень)
#         градация    ждёт cand = 3
#         арифметика  ждёт cand = -1, то есть мусор вида 0xFFFFFFFF
#
#   Стоимость нулевая: значение 0x3 уже измерено игрой как 9 fps, так
#   что прогон не добавляет новой ручной работы. Риск нулевой - все
#   записи штатные.
#
#   Косвенный довод в пользу градации: в стоке cand не следует за sel
#   (стоковый sel был 0 в прогоне 0x7 и 3 в прогоне 0x6, а cand = 3 в
#   обоих). При арифметике стоковый sel=0 дал бы -4. Это довод, а не
#   доказательство: стоковое состояние не обязано обновляться по тому
#   же правилу.
#
#   Если подтвердится градация, следующий шаг - свип 0x8..0xFF (поле
#   может быть шире трёх бит), и тогда лестницу можно перебирать
#   чтением одного регистра. Если подтвердится арифметика, свип
#   неинформативен и тратить на него 256 записей нельзя.
build_one gfxsel_0x3_oracle   -DRELEASE_BUILD -DMULTI_CARD -DPCIE_GEN2_REJOIN \
                              -DFULL_NOGEN2 -DGEN2_LINK_TRY -DRENDER_MASKS \
                              -DCHIP_SIZE_SCAN=1 -DFUSE_ORACLE \
                              -DGFX_SPEED_SEL_VALUE=0x3

# E9 (2026-10-08) - ШАГ B: проверка ширины поля селектора одной записью.
#
#   Шаг A показал, что CAND-ID градуирован, а не арифметика sel-4.
#   Из этого следует новая возможность: поле может быть ШИРЕ трёх бит,
#   а этого никто никогда не проверял. Трёхбитность была утверждением,
#   которое я сам же зашил в статический assert в unlock_v2.c, выведенный
#   из факта "мы перебрали восемь значений". Перебор не доказывает
#   границу - он доказывает только, что внутри неё есть восемь значений.
#
#   Поэтому сначала ОДНА запись 0x8, а не свип 0x8..0xFF. Она отвечает
#   сразу на оба вопроса и стоит одну запись вместо 256:
#     - держится ли значение в 0x823830 после записи 0x8;
#     - во что становится CAND-ID в 0x823834.
#
#   Исходы и что из них следует:
#     0x8 НЕ застрял (readback != 8)  -> поле трёхбитное. Лестница закрыта
#                                         окончательно, остаётся C3.
#     застрял и CAND-ID = 0           -> значение ЛУЧШЕ 0x4. Цель проекта.
#     застрял и CAND-ID = 3           -> поле шире, но вовлечённости нет;
#                                         тогда свип оправдан.
#     застрял и иное                  -> поле шире, есть ступени между.
#
#   Риск нулевой: если поле трёхбитное, железо отмаскирует 0x8 в 0, а 0x0 -
#   это те же базовые 9 fps. Откат = перезагрузка.
#
#   Цель gfxsel_0x8_oracle УДАЛЕНА 2026-10-09 вместе с ослаблением проверки.
#   Шаг B выполнен: железо отмаскировало 0x8 в 0x0, поле измерено как
#   трёхбитное. Собирать 0x8 больше нельзя -- статическая проверка в
#   unlock_v2.c возвращена к 0x7 и отвергает это значение. Проверено сборкой:
#   с возвращённой проверкой RENDER_MATRIX=1 падает ровно на этой цели.
#   Отчёт о прогоне сохранён в POWER-SEARCH-LIST.md часть 9.

#   Последняя дыра шкалы: значение 0x5 никогда не снималось с CAND-ID.
#   В лестнице оно есть (RENDER-LIMITS.md §3, 26 fps по замеру пользователя),
#   но машинного признака для него нет, то есть строка градации неполна.
#   Предсказание модели: CAND-ID = 1 (0x4 -> 0, 0x6 -> 2, 0x7 -> 3).
#   На решения уже не влияет, это заполнение шкалы.
build_one gfxsel_0x5_oracle   -DRELEASE_BUILD -DMULTI_CARD -DPCIE_GEN2_REJOIN \
                              -DFULL_NOGEN2 -DGEN2_LINK_TRY -DRENDER_MASKS \
                              -DCHIP_SIZE_SCAN=1 -DFUSE_ORACLE \
                              -DGFX_SPEED_SEL_VALUE=0x5

#   СКАН ОКНА SM: сколько юнитов реально отвечает живым значением, в
#   отличие от заявленного multiProcessorCount. Только чтение, записи в
#   железо нет, откат = перезагрузка. Нужно потому, что «урезанный
#   кристалл, 30 SM» держится на трёх представлениях ОДНОГО заявленного
#   поля (multiProcessorCount, GPU-Z Shaders 3840, NVAPI), то есть это
#   один источник, а не три независимых. Часть 11 §5 признаёт, что
#   сколько SM реально отдаёт драйвер, никто не считал.
#
#   Критерий один, и оба исхода полезны:
#     больше 30 -> гипотеза «урезанный кристалл» опровергнута, часть
#                   кремния физически есть, но выключена. Косвенно за это
#                   говорит 30/48 x 230 Вт = 143,75 Вт против наших
#                   133 Вт в игре;
#     ровно 30  -> вопрос закрыт окончательно.
#
#   Стоимость: 512 итераций x 4 регистра, единицы миллисекунд.
build_one smacf               -DRELEASE_BUILD -DMULTI_CARD -DPCIE_GEN2_REJOIN \
                              -DFULL_NOGEN2 -DGEN2_LINK_TRY -DRENDER_MASKS \
                              -DCHIP_SIZE_SCAN=1 -DFUSE_ORACLE \
                              -DSM_ACF=1
fi

# Баннер печатает md5 и размер, посчитанные по только что собранному файлу.
# Раньше здесь стоял зашитый DEE0BAAB — отпечаток тега rollback-2026-10-01, то
# есть v3.15. Сборка не переставала быть правильной, но баннер объявлял её
# скомпрометированной: «если не DEE0BAAB — откат скомпрометирован». Проверка
# была тождественно ложной и всё равно выглядела как проверка.
OUT_MD5=$(md5sum unlock_v3r.efi | cut -d' ' -f1)
OUT_SZ=$(stat -c%s unlock_v3r.efi)

cat <<EOF

================================================================================
Deploy to USB (FAT32, EFI/BOOT/BOOTX64.EFI) + gsp_ga10x.bin from the
NVIDIA 610.43.03 package next to it.

  ЕДИНСТВЕННЫЙ БИНАРНИК:  unlock_v3r.efi
      md5 $OUT_MD5, $OUT_SZ байт
      compute x11.25 (pp512) + графика, Cyberpunk 2077 50 fps / 135 Вт

  Это одновременно и то, что прошивается, и ОТКАТ. Отдельной откатной сборки
  больше нет и не должно появляться: compute-only вариант unlock_v3n удалён
  2026-10-01 именно потому, что его присутствие рядом с рабочим уже один раз
  привело к прошивке без графики — compute при этом работал, и выглядело всё
  исправно.

  ПРОВЕРЬТЕ md5 ПЕРЕД ЗАПИСЬЮ — сверьте его с файлом на флешке. НЕ СВЕРЯЙТЕ
  его с отпечатком, зашитым в исходники: баннер печатает md5, посчитанный по
  только что собранному файлу, так что расхождение означает, что записан не
  тот файл (BUILDING.md §6.0).

  Проверенные НА ЖЕЛЕЗЕ отпечатки (сверять надо с этими, а не с баннером):
      2abf59a0d147b9d5744cfbec5d58ec65   v3.40, 2 маски рендера, 8 470 / 8 451 мс
      67f7b5a84f8efeba5a4718004b0589ed   v3.39, 8 масок рендера, 15 964 / 15 958 мс
      DEE0BAAB1B7C222399C091EAD15D071B   v3.15, тег rollback-2026-10-01

  Настоящий откат — git, а не замороженный бинарник:
      git revert <коммит этого изменения>
      git checkout rollback-2026-10-01 && bash build.sh   ->  DEE0BAAB…

Весь цикл сборки, записи и проверки — одной командой:
    powershell -ExecutionPolicy Bypass -File out\flash-build.ps1
================================================================================
EOF
