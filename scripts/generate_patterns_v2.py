#!/usr/bin/env python3
"""Generate byte patterns in the mod-menu style: branches masked, other bytes literal."""
import os,re,json,collections,zstandard,bisect
D='/root/workspace/Minecraft, reverse engineer/results'; OUT=os.path.join(D,'reconstruction')
lib=open('/root/workspace/Minecraft, reverse engineer/native/libminecraftpe.so','rb').read()
addrs=[]
for line in open(os.path.join(OUT,'ALL_FUNCTION_ENTRIES.txt')):
    addrs.append(int(line.split('\t')[0],16))
ASM_Z=os.path.join(D,'per_function','DISASSEMBLY_FULL.asm.zst')
ins_map=collections.defaultdict(list)
bl_re=re.compile(r'^([0-9a-f]+)\s+(\S+)')
n=0;carry=b''
with open(ASM_Z,'rb') as fh:
    dec=zstandard.ZstdDecompressor().stream_reader(fh)
    while True:
        ch=dec.read(8*1024*1024)
        if not ch: break
        data=carry+ch; lines=data.split(b'\n'); carry=lines.pop()
        for raw in lines:
            n+=1; m=bl_re.match(raw.decode('utf-8','replace').strip())
            if not m: continue
            a=int(m.group(1),16);mn=m.group(2)
            pos=bisect.bisect_right(addrs,a)-1
            if pos<0: continue
            f=addrs[pos]
            if len(ins_map[f])<32: ins_map[f].append((a,mn))
print('scanned',n,flush=True)
def pat_bytes(a,mn):
    b=lib[a:a+4]
    if mn=='bl': return '?? ?? ?? 95'
    if mn=='b': return '?? ?? ?? 14'
    if mn in ('b.eq','b.ne','b.lt','b.ge','b.gt','b.le','b.cs','b.cc','b.mi','b.pl','b.vs','b.vc','b.hi','b.ls','cbz','cbnz','tbz','tbnz'):
        return '?? ?? ?? ??'
    if mn in ('br','blr','ret'): return ' '.join('%02x'%x for x in b)
    return ' '.join('%02x'%x for x in b)
rows=[];cnt=collections.Counter()
for a in addrs:
    ins=ins_map.get(a,[])
    if not ins: continue
    pat=' '.join(pat_bytes(x,m) for x,m in ins[:24])
    cnt[pat]+=1; rows.append((a,pat))
with open(os.path.join(OUT,'ALL_FUNCTION_PATTERNS_V2.tsv'),'w') as f:
    f.write('function_address\tpattern\tunique\n')
    for a,p in rows: f.write('0x%x\t%s\t%s\n'%(a,p,'Y' if cnt[p]==1 else 'N'))
print('functions',len(rows),'unique',sum(1 for v in cnt.values() if v==1))
# verify known
for a in [0x989ef20,0x1079d000,0x1040e50c]:
    for aa,p in rows:
        if aa==a:
            print(hex(a),p[:160]);break
