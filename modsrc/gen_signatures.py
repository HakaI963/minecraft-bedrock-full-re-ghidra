#!/usr/bin/env python3
"""Generate unique wildcard instruction-byte signatures for target RVAs.

For each RVA, take the first N bytes of the function prologue, then wildcard
the 4-byte words of any PC-relative / branch instructions (BL, B, ADRP, ADR,
LDR literal, B.cond, CBZ/CBNZ/TBZ/TBNZ) so the pattern survives code shifts
across game patches. The remaining literal opcodes + immediate fields are the
signature. Verify the masked pattern matches EXACTLY ONCE in the whole binary.
"""
import re, sys

BIN = '/home/flux/libminecraftpe.so'
data = open(BIN, 'rb').read()

def pc_relative(w):
    """True if a 32-bit ARM64 instruction is PC-relative / a branch."""
    # BL / B  (imm26): 0x94000000 / 0x14000000
    if (w & 0xfc000000) in (0x94000000, 0x14000000): return True
    # ADRP / ADR: 0x90000000 / 0x10000000
    if (w & 0x9f000000) in (0x90000000, 0x10000000): return True
    # B.cond: 0x54000000
    if (w & 0xff000010) == 0x54000000: return True
    # CBZ / CBNZ: 0x34000000 / 0x35000000
    if (w & 0x7f000000) in (0x34000000, 0x35000000): return True
    # TBZ / TBNZ: 0x36000000 / 0x37000000
    if (w & 0x7f000000) in (0x36000000, 0x37000000): return True
    # LDR literal: 0x58000000 (64-bit), 0x18000000 (32-bit), 0x1c000000,0x5c000000
    if (w & 0x3b000000) == 0x18000000: return True
    return False

def gen(rva, nwords=10):
    off = rva
    words = [int.from_bytes(data[off+i*4:off+i*4+4], 'little') for i in range(nwords)]
    pat = []
    for w in words:
        if pc_relative(w):
            pat += ['??']*4
        else:
            b = w.to_bytes(4, 'little')
            pat += [f'{x:02x}' for x in b]
    return ' '.join(pat)

def count_hits(pat):
    rx = b''.join(b'.' if x == '??' else re.escape(bytes([int(x, 16)])) for x in pat.split())
    return len(re.findall(rx, data, re.DOTALL))

# target name -> RVA (from offsets.h + raw constants)
TARGETS = {
 'REGISTER_BLOCK':0x989ef20,'BLOCKTYPE_CTOR':0x10920f8c,'BLOCKITEM_CTOR':0x10816530,
 'MATERIAL_GET':0x111c9918,'HASHED_CTOR':0x134ee764,'HASHED_GETSTR':0x134eea5c,
 'REGISTER_ITEM_WRAPPER':0x1039c800,'ITEM_GET_ID':0x10797f54,
 'I18N_GET':0xcc9db5c,'I18N_GET_PARAMS':0xcc9e630,'CSL_STRING_INIT':0xe8313bc,
 'BUILD_DESC_NAME':0x107914b4,'BLOCKLEGACY_DESC':0x10924fa4,
 'ADD_SHAPED_WRAPPER':0x1040f840,'ADD_SHAPED_RECIPE':0x1040e50c,
 'FN_BLOCKS_LOADER':0xab092b0,'FN_TERRAIN_LOADER':0xcf37454,
 'JSON_PARSE_CSTR':0x886e948,'JSON_PARSE_STR':0x886e5c8,
 'SCREEN_CREATOR':0x8a812a4,'NETID_NEXT':0x103db7f0,'ADD_RECIPE':0x10411dc4,
 'SET_CREATIVE_CATEGORY':0x1079d000,'DESC_CTOR':0x107ae7d0,'TAG_COPY':0x134ee534,
 'TEXSET_LOAD':0xff2d9f4,'PNG_DECODE':0x135c0d14,
 'ITEM_INST_CTOR':0x1076d284,'ITEM_INST_COPY':0x1076d69c,'ITEM_INST_INIT':0x10772d54,
 'CREATIVE_ADD_ITEM':0x107ebae8,'CREATIVE_GROUP_CTOR':0x103d6628,
 'CREATIVE_FINALIZE':0x1038de58,'SHAPED_CTOR':0x10416d50,'STRING_INIT':0x88a6328,
 'BLOCK_GRAPHICS_GET':0xab0532c,
}

for name, rva in TARGETS.items():
    # 24/40-word patterns are needed for functions whose short prologues are
    # not unique (e.g. SCREEN_CREATOR, ITEM_INST_CTOR, ITEM_INST_COPY).
    for nw in (10, 12, 16, 24, 40):
        pat = gen(rva, nw)
        hits = count_hits(pat)
        if hits == 1:
            print(f'{name} @ 0x{rva:x} [{nw} words] hits=1')
            print(f'  "{pat}"')
            break
    else:
        print(f'{name} @ 0x{rva:x} NO UNIQUE PATTERN (last hits={hits})')
