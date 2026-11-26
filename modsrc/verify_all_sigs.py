#!/usr/bin/env python3
"""Verify every runtime signature in FinalMod.cpp matches exactly once.

Extracts all signature string literals from the S table (and any direct
scanUnique calls) and checks each against libminecraftpe.so's r-x range.
Not hardcoded to 17 signatures: the count is derived from the source.
"""
import re
data = open('/home/flux/libminecraftpe.so', 'rb').read()
LO, HI = 0x6834bc0, 0x14000000   # .text + .plt (runtime r-x)
seg = data[LO:HI]

s = open('/home/flux/final_mod/src/FinalMod.cpp').read()

# All signature-looking string literals in the file (hex pairs + ??)
sigs = []
for m in re.finditer(r'"([0-9a-fA-F?][0-9a-fA-F ?]*)"', s):
    g = m.group(1)
    toks = g.split()
    if len(toks) >= 6 and all(len(t) == 2 for t in toks):  # instruction pattern
        sigs.append((g, len(toks)))

table = s[s.index('struct S{ uintptr_t* dst'):s.index('for(auto& s:tbl)')]
entries = len(re.findall(r'\{&p\w+,"', table))
assert entries >= 17, entries
assert len(sigs) == entries, (len(sigs), entries)

print(f'found {len(sigs)} signature literals (>=6 tokens), {entries} table entries')
fail = 0
for g, n in sigs:
    rx = b''.join(b'.' if t == '??' else re.escape(bytes([int(t, 16)])) for t in g.split())
    hits = len(re.findall(rx, seg, re.DOTALL))
    status = 'OK' if hits == 1 else f'FAIL({hits})'
    if hits != 1:
        fail += 1
    print(f'  [{status}] {n}toks  {g[:60]}')
print(f'TOTAL {len(sigs)} signatures, {fail} failures')
raise SystemExit(1 if fail else 0)
