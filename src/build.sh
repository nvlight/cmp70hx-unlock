#!/bin/bash
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
      67f7b5a84f8efeba5a4718004b0589ed   v3.39, 8 масок рендера, 15 964 мс
      DEE0BAAB1B7C222399C091EAD15D071B   v3.15, тег rollback-2026-10-01

  Настоящий откат — git, а не замороженный бинарник:
      git revert <коммит этого изменения>
      git checkout rollback-2026-10-01 && bash build.sh   ->  DEE0BAAB…

Весь цикл сборки, записи и проверки — одной командой:
    powershell -ExecutionPolicy Bypass -File out\flash-build.ps1
================================================================================
EOF
