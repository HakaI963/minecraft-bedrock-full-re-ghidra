#!/usr/bin/env python3
"""Migrate a mod's RVA/signature table from an old libminecraftpe.so to a new one.

Strategy: the mod's signatures wildcard every PC-relative instruction, so the
literal opcodes/immediates are version-stable. Search each old signature in the
new binary; a unique hit gives the new address. Then regenerate a fresh
signature at the new address (longer word count if needed, still unique).
"""
import re,sys,json
NEW=sys.argv[1]           # new libminecraftpe.so
SRC=sys.argv[2]           # FinalMod.cpp of the mod
OUT=sys.argv[3]           # output json + report dir
import os
os.makedirs(OUT,exist_ok=True)
data=open(NEW,'rb').read()
src=open(SRC,errors='replace').read()

# ---- 1. parse the runtime signature table from FinalMod.cpp ----
start=src.index('struct S{ uintptr_t* dst')
end=src.index('for(auto& s:tbl)')
block=src[start:end]
entries=re.findall(r'\{&(p\w+),"([^"]+)",\s*\n?\s*"([^"]+)",\s*(-?\w+)\}',block)
if not entries:
    entries=[(m.group(1),m.group(2),m.group(3),m.group(4)) for m in
             re.finditer(r'\{&(\w+),\s*"([^"]+)",\s*"([^"]+)",\s*([^}]+)\}',block)]
print('parsed entries',len(entries))

def rx_of(pat):
    return b''.join(b'.' if x=='??' else re.escape(bytes([int(x,16)])) for x in pat.split())

def find_unique(pat):
    rx=rx_of(pat)
    hits=[m.start() for m in re.finditer(rx,data,re.DOTALL)]
    return hits

def pc_relative(w):
    if (w & 0xfc000000) in (0x94000000,0x14000000): return True
    if (w & 0x9f000000) in (0x90000000,0x10000000): return True
    if (w & 0xff000010)==0x54000000: return True
    if (w & 0x7f000000) in (0x34000000,0x35000000): return True
    if (w & 0x7f000000) in (0x36000000,0x37000000): return True
    if (w & 0x3b000000)==0x18000000: return True
    return False

def gen(off,nwords):
    out=[]
    for i in range(nwords):
        w=int.from_bytes(data[off+i*4:off+i*4+4],'little')
        if pc_relative(w): out+=['??']*4
        else: out+=['%02x'%b for b in w.to_bytes(4,'little')]
    return ' '.join(out)

rows=[]; ok=0; fail=[]
for var,label,pat,adj in entries:
    hits=find_unique(pat)
    name=label.split('_')[0] if '_' in label else label
    if len(hits)==1:
        # the wildcarded pattern's hit is where the masked words line up.
        # The mod's adj moves from the pattern anchor to the function entry.
        addr=hits[0]
        # regenerate a stronger signature at the same anchor
        best=None
        for nw in (10,12,16,24,40,64):
            if addr+nw*4>len(data): break
            p=gen(addr,nw)
            h=find_unique(p)
            if len(h)==1: best=p; break
        rows.append({'var':var,'label':label,'old_adj':adj,'new_anchor':hex(addr),
                     'new_sig':best or pat,'unique':bool(best)})
        if best: ok+=1
        else: fail.append((label,'sig not unique after regen'))
    elif len(hits)==0:
        fail.append((label,'NOT FOUND in new binary'))
        rows.append({'var':var,'label':label,'old_adj':adj,'new_anchor':None,'new_sig':None,'unique':False})
    else:
        # multiple hits: try longer versions of the ORIGINAL pattern by extending
        # from each hit using the new binary's bytes
        solved=False
        for h in hits:
            for nw in (12,16,24,40,64):
                p=gen(h,nw)
                if len(find_unique(p))==1:
                    rows.append({'var':var,'label':label,'old_adj':adj,'new_anchor':hex(h),
                                 'new_sig':p,'unique':True})
                    ok+=1; solved=True; break
            if solved: break
        if not solved:
            fail.append((label,'ambiguous (%d hits)'%len(hits)))
            rows.append({'var':var,'label':label,'old_adj':adj,'new_anchor':None,'new_sig':None,'unique':False})
print('resolved',ok,'of',len(entries))
json.dump(rows,open(OUT+'/migrated_signatures.json','w'),indent=2)
with open(OUT+'/MIGRATION_REPORT.md','w') as f:
    f.write('# Mod migration report (1.26.60.4 -> 1.26.66.1)\n\n')
    f.write('| Var | Label | New anchor | Unique |\n|---|---|---:|:-:|\n')
    for r in rows:
        f.write('| `%s` | %s | %s | %s |\n'%(r['var'],r['label'],r['new_anchor'] or '-', 'Y' if r['unique'] else 'N'))
    if fail:
        f.write('\n## Failed\n\n')
        for n,why in fail: f.write('- `%s`: %s\n'%(n,why))
with open(OUT+'/migrated_signatures.tsv','w') as f:
    f.write('var\tlabel\tnew_anchor\tnew_signature\tunique\n')
    for r in rows:
        f.write('%s\t%s\t%s\t%s\t%s\n'%(r['var'],r['label'],r['new_anchor'] or '',r['new_sig'] or '','Y' if r['unique'] else 'N'))
print('fail list',fail)
