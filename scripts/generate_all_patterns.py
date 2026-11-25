#!/usr/bin/env python3
"""For every function entry: first 12 instructions -> unique ARM64 byte pattern + string refs."""
import os,re,json,collections,zstandard,bisect
D='/root/workspace/Minecraft, reverse engineer/results'
OUT=os.path.join(D,'reconstruction')
lib=open('/root/workspace/Minecraft, reverse engineer/native/libminecraftpe.so','rb').read()
entries=[]
for line in open(os.path.join(OUT,'ALL_FUNCTION_ENTRIES.txt')):
    p=line.split('\t'); entries.append((int(p[0],16),int(p[1])))
addrs=[e[0] for e in entries]
via=set(os.path.join(OUT,x) for x in [])
# first 12 instruction addresses per function from disassembly
ASM_Z=os.path.join(D,'per_function','DISASSEMBLY_FULL.asm.zst')
ins_map=collections.defaultdict(list)  # func -> [(addr, mnemonic)]
idx=0
bl_re=re.compile(r'^([0-9a-f]+)\s+(\S+)')
n=0; carry=b''
with open(ASM_Z,'rb') as fh:
    dec=zstandard.ZstdDecompressor().stream_reader(fh)
    while True:
        chunk=dec.read(8*1024*1024)
        if not chunk: break
        data=carry+chunk; lines=data.split(b'\n'); carry=lines.pop()
        for raw in lines:
            n+=1
            m=bl_re.match(raw.decode('utf-8','replace').strip())
            if not m: continue
            a=int(m.group(1),16); mn=m.group(2)
            pos=bisect.bisect_right(addrs,a)-1
            if pos<0: continue
            f=addrs[pos]
            if len(ins_map[f])<24: ins_map[f].append((a,mn))
        if n%15000000<1000000: print('scan',n,'funcs with ins',len(ins_map),flush=True)
print('scan done',n,flush=True)
# generate patterns
def mask_bytes(a,mn):
    b=lib[a:a+4]
    if mn.startswith('b.') or mn in ('b','bl','br','blr','cbz','cbnz','tbz','tbnz'):
        return '?? ?? ?? ??'
    return ' '.join('%02x'%x for x in b)
pat_count=collections.Counter()
rows=[]
for a,calls in entries:
    ins=ins_map.get(a,[])
    pat=' '.join(mask_bytes(x,m) for x,m in ins[:24])
    if not pat: continue
    pat_count[pat]+=1
    rows.append((a,calls,pat,ins))
with open(os.path.join(OUT,'ALL_FUNCTION_SIGNATURES.tsv'),'w') as f:
    f.write('function_address\tpattern\tcall_count\tunique_in_set\n')
    for a,c,pat,ins in rows:
        f.write('0x%x\t%s\t%d\t%s\n'%(a,pat,c,'Y' if pat_count[pat]==1 else 'N'))
print('functions with patterns',len(rows),'unique patterns',sum(1 for v in pat_count.values() if v==1))
json.dump({'functions':len(rows),'unique_patterns':sum(1 for v in pat_count.values() if v==1),
           'duplicate_patterns':sum(1 for v in pat_count.values() if v>1)},
          open(os.path.join(OUT,'pattern_summary.json'),'w'),indent=2)
