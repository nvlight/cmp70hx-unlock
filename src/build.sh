#!/bin/bash
# build.sh — build all CMP unlock EFI variants from unlock_v2.c (gnu-efi)
#
# Usage:
#   bash build.sh                 # CMP 70HX / GA104 / 8 GB  (default target)
#   TARGET=90HX bash build.sh     # original CMP 90HX / GA102 / 10 GB target
#   BLOBS=/path/to/blobs bash build.sh
#
# The resulting binaries are byte-identical to the released ones when built
# against the same blobs (release v3.03: unlock_v3n.efi md5 e27221f5ddd56360…).
set -e

WORK="$(cd "$(dirname "$0")" && pwd)"
cd "$WORK"
BLOBS="${BLOBS:-$WORK/blobs}"
TARGET="${TARGET:-70HX}"

# ---- target profile: chip, FB size and the matching FWSEC blob -------------
# The FWSEC ucode is per-die (extracted from that die's VBIOS), so a target
# and a blob go together. See the TARGET PROFILE block in unlock_v2.c.
case "$TARGET" in
    70hx|70HX)
        DEF="-DTARGET_CMP70HX"
        FWSEC="fwsec_ga104"          # extracted from a GA104 VBIOS
        ;;
    90hx|90HX)
        DEF="-DTARGET_CMP90HX"
        FWSEC="fwsec_ga102"          # extracted from the 10de:220d VBIOS
        ;;
    *)
        echo "ERROR: unknown TARGET='$TARGET' (use 70HX or 90HX)"; exit 1
        ;;
esac
export DEF FWSEC

echo "=== NVIDIA CMP unlock EFI build — target: $TARGET ==="

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

# dev branch: interactive pauses, gen experiments, full fire machinery
build_one unlock_v2      -DPCIE_GEN_EXPERIMENT -DMULTI_CARD -DPCIE_GEN2_REJOIN

# QEMU test-stand builds (auto-advance, extra dumps)
build_one unlock_v2_test      -DEFI_AUTOTEST -DPCIE_GEN_EXPERIMENT \
                              -DMULTI_CARD -DPCIE_GEN2_REJOIN
build_one unlock_v3n_test     -DEFI_AUTOTEST -DPCIE_GEN_EXPERIMENT \
                              -DMULTI_CARD -DPCIE_GEN2_REJOIN -DFULL_NOGEN2

# plan-B endgame (BootNext + warm reset) — not used in the field
build_one unlock_v2_wr        -DEFI_AUTOTEST -DENDGAME_WARMRESET

# releases
build_one unlock_v3           -DRELEASE_BUILD -DMULTI_CARD
build_one unlock_v3f          -DRELEASE_BUILD -DMULTI_CARD -DPCIE_GEN2_REJOIN
build_one unlock_v3n          -DRELEASE_BUILD -DMULTI_CARD -DPCIE_GEN2_REJOIN \
                              -DFULL_NOGEN2

# v3.07: unlock_v3n + запись GFX_SPEED_SELECT=4 (рендер-селектор) с проверкой
# обоих порядков. Замер показал: запись не липнет, пока маски 0x823800/0x823B04
# заперты; обе в таблице g_rj16 и с хоста не открываются.
# ОТКАТ: прошить unlock_v3n.efi (git-тег gen2-baseline-2026-09-29).
build_one unlock_v3g          -DRELEASE_BUILD -DMULTI_CARD -DPCIE_GEN2_REJOIN \
                              -DFULL_NOGEN2 -DGEN2_LINK_TRY

# v3.08: unlock_v3g + РЕНДЕР-МАСКИ. Открывает ровно две маски, запирающие
# GFX_SPEED_SELECT (0x823800 и 0x823B04), через параметризованный V67-ROP
# (адрес/значение берутся из v67Phys+0xf960/+0xf948, payload менять не нужно).
# Не полный свип: максимум 6 FLR-минициклов против ~30, на которых референс
# ловил зависание гостя. Селекторы и фикс Code 43 обычного хвоста не трогаем,
# g_gen2Fire не выставляется.
# ОТКАТ: прошить unlock_v3n.efi.
build_one unlock_v3r          -DRELEASE_BUILD -DMULTI_CARD -DPCIE_GEN2_REJOIN \
                              -DFULL_NOGEN2 -DGEN2_LINK_TRY -DRENDER_MASKS

echo
echo "Deploy to USB (FAT32, EFI/BOOT/BOOTX64.EFI) + gsp_ga10x.bin from the"
echo "NVIDIA 610.43.03 package next to it. For real hardware use"
echo "unlock_v3n.efi (v3.03, target $TARGET). See BUILDING.md."
