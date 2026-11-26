#!/usr/bin/env python3
"""Verify EVERY runtime signature in FinalMod.cpp matches exactly once.

Not limited to the original 17 entries: the table is parsed from source, so
any newly added signature is checked too. No signature may match zero times
(or more than once); the runtime code has NO RVA fallback for a miss.
"""
import re
data = open('/home/flux/libminecraftpe.so', 'rb').read()
s = open('/home/flux/final_mod/src/FinalMod.cpp').read()
t = s[s.index('struct S{ uintptr_t* dst'):s.index('for(auto& s:tbl)')]
sigs = [m.group(1) for m in re.finditer(
    r'"([0-9a-fA-F?][0-9a-fA-F?](?: [0-9a-fA-F?][0-9a-fA-F?])*)"', t)]
entries = len(re.findall(r'\{&p\w+,"', t))
assert len(sigs) == entries, (len(sigs), entries)
assert entries >= 17, entries
for i, g in enumerate(sigs):
    rx = b''.join(b'.' if x == '??' else re.escape(bytes([int(x, 16)])) for x in g.split())
    hits = len(re.findall(rx, data, re.DOTALL))
    assert hits == 1, (i, g[:48], hits)
print(f'{len(sigs)} signatures match uniquely (no RVA fallback)')
