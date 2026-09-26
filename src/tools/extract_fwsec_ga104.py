#!/usr/bin/env python3
"""Extract FWSEC ucode from GA104 VBIOS ROM (adapted from ga102 version).

GA104 ROM: pciOffset=0x9200, expansionRomOffset=0x14800,
FALCON_DATA token at BIT+0x1B0, idx=14, ptr=0x401.
"""
import struct, sys, hashlib

def u16(b, o): return struct.unpack_from('<H', b, o)[0]
def u32(b, o): return struct.unpack_from('<I', b, o)[0]

img = open(sys.argv[1] if len(sys.argv) > 1 else 'GA104.rom', 'rb').read()
print(f'ROM: {len(img)} bytes')

# Constants for GA104
BASE = 0x9200
EXP  = 0x14800

# Find BIT header in first PCI image
BIT_IMG_OFF = 0x1B0
bit_abs = BASE + BIT_IMG_OFF
hdr_sz = img[bit_abs + 8]
tok_sz = img[bit_abs + 9]
entries = img[bit_abs + 10]
print(f'BIT @0x{bit_abs:x}: hdrSz={hdr_sz} tokSz={tok_sz} entries={entries}')

# FALCON_DATA token index=14
tok_off = bit_abs + hdr_sz + 14 * tok_sz
data_ptr = u16(img, tok_off + 4)
table_ptr = u32(img, BASE + data_ptr)
tbl = BASE + EXP + table_ptr

ver_t, t_hdr, t_ent, t_cnt = img[tbl], img[tbl+1], img[tbl+2], img[tbl+3]
print(f'ucode table @ROM 0x{tbl:x}: ver={ver_t} hdrSz={t_hdr} entSz={t_ent} cnt={t_cnt}')

# Collect entry descriptors
entries_dict = {}
for e in range(t_cnt):
    eo = tbl + t_hdr + e * t_ent
    appid = img[eo]
    desc_off = u32(img, eo + 2) + EXP  # relative to expansion
    entries_dict[appid] = BASE + desc_off
    if appid in (0x45, 0x85):
        dp_abs = entries_dict[appid]
        vdesc = u32(img, dp_abs)
        dver = (vdesc >> 8) & 0xFF
        dsz = (vdesc >> 16) & 0xFFFF
        print(f'  FWSEC appid=0x{appid:02x} desc@0x{dp_abs:x} vdesc=0x{vdesc:08x} ver={dver} size={dsz}')

# Extract FWSEC PROD (0x85) — primary; fall back to DBG (0x45)
for appid, tag in [(0x85, 'prod'), (0x45, 'dbg')]:
    if appid not in entries_dict:
        continue
    dp = entries_dict[appid]
    vdesc = u32(img, dp)
    dver = (vdesc >> 8) & 0xFF
    dsz = (vdesc >> 16) & 0xFFFF
    if dver != 3 or dsz < 44:
        print(f'FWSEC {tag}: unsupported desc version {dver}'); continue

    (stored, pkc_off, iface_off, imem_phys, imem_load, imem_virt,
     dmem_phys, dmem_load, engmask16, ucodeid, sigcount, sigver16,
     reserved) = struct.unpack_from('<8IH2B2H', img, dp + 4)

    print(f'--- FWSEC {tag} appid=0x{appid:02x}')
    print(f'  StoredSize=0x{stored:x} PKCDataOffset=0x{pkc_off:x} InterfaceOffset=0x{iface_off:x}')
    print(f'  IMEM: load=0x{imem_load:x}')
    print(f'  DMEM: load=0x{dmem_load:x}')
    print(f'  engMask=0x{engmask16:x} ucodeId={ucodeid} sigCount={sigcount} sigVer=0x{sigver16:x}')

    img_size = (stored + 0xFF) & ~0xFF
    sigs = img[dp + 44 : dp + 44 + (dsz - 44)]
    code_data = img[dp + dsz : dp + dsz + img_size]
    print(f'  sigs: {len(sigs)} bytes ({len(sigs)//384} x RSA3K); code+data: {len(code_data)} bytes')

    if len(code_data) < img_size:
        print('  WARNING: image truncated'); continue

    # Verify expected params (same as GA102 — both are Ampere)
    ok = (imem_load == 0xE200 and dmem_load == 0x800 and pkc_off == 0x5A4 and ucodeid == 9)
    print(f'  driver sanity check: {"OK" if ok else "MISMATCH"}')

    # Write fwsec_<tag>.bin (code + data, same layout as GA102)
    out_bin = f'fwsec_ga104_{tag}.bin'
    open(out_bin, 'wb').write(code_data)
    print(f'  -> {out_bin} ({len(code_data)} bytes), md5 {hashlib.md5(code_data).hexdigest()}')

    # Write sigs (single sig[2] = 384 bytes for RSA3K)
    out_sig = f'fwsec_ga104_{tag}_sig.bin'
    # sig[2] is at offset sigcount-1 (PROD sig, the one driver picks)
    sig2 = sigs[-384:] if len(sigs) >= 384 else sigs
    open(out_sig, 'wb').write(sig2)
    print(f'  -> {out_sig} ({len(sig2)} bytes), md5 {hashlib.md5(sig2).hexdigest()}')

    # Also write combined (matching original extract_fwsec.py format)
    open(f'fwsec_ga104.bin', 'wb').write(code_data)
    open(f'fwsec_ga104_sig.bin', 'wb').write(sig2)
    print(f'  -> fwsec_ga104.bin + fwsec_ga104_sig.bin (primary outputs)')
    break
else:
    print('FWSEC not found')
