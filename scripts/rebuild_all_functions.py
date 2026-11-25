#!/usr/bin/env python3
import os,re,collections,json,zstandard
D='/root/workspace/Minecraft, reverse engineer/results'
ASM_Z=os.path.join(D,'per_function','DISASSEMBLY_FULL.asm.zst')
OUT=os.path.join(D,'reconstruction')
TEXT_START=0x6834bc0; TEXT_END=TEXT_START+0xcd9e7c8
targets=collections.Counter()
bl_re=re.compile(r'^([0-9a-f]+)\s+bl\s+([0-9a-f]+)')
n=0; carry=b''
with open(ASM_Z,'rb') as fh:
    dec=zstandard.ZstdDecompressor().stream_reader(fh)
    while True:
        chunk=dec.read(8*1024*1024)
        if not chunk: break
        data=carry+chunk
        lines=data.split(b'\n'); carry=lines.pop()
        for raw in lines:
            n+=1
            m=bl_re.match(raw.decode('utf-8','replace').strip())
            if m:
                t=int(m.group(2),16)
                if TEXT_START<=t<TEXT_END: targets[t]+=1
        if n%10000000<1000000: print('lines',n,'targets',len(targets),flush=True)
if carry:
    m=bl_re.match(carry.decode('utf-8','replace').strip())
    if m:
        t=int(m.group(2),16)
        if TEXT_START<=t<TEXT_END: targets[t]+=1
print('DONE lines',n,'call targets',len(targets),flush=True)
have=set()
for line in open(os.path.join(D,'extracted/ghidra-fast/ghidra/04_functions.tsv'),errors='replace'):
    p=line.split('\t')
    if p and re.fullmatch(r'[0-9a-fA-F]+',p[0]): have.add(int(p[0],16))
all_starts=sorted(set(targets)|have)
json.dump({'call_targets':len(targets),'existing':len(have),'combined':len(all_starts)},
          open(os.path.join(OUT,'function_enumeration_summary.json'),'w'),indent=2)
with open(os.path.join(OUT,'ALL_FUNCTION_ENTRIES.txt'),'w') as f:
    for a in all_starts: f.write('%08x\t%d\t%d\n'%(a,targets.get(a,0),1 if a in have else 0))
print('combined',len(all_starts))
