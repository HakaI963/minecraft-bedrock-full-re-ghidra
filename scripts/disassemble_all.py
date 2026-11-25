#!/usr/bin/env python3
"""Full ARM64 disassembly of libminecraftpe.so split into one file per function."""
import os,re,sys,bisect,subprocess,zstandard
D='/root/workspace/Minecraft, reverse engineer/results'
LIB='/root/workspace/Minecraft, reverse engineer/native/libminecraftpe.so'
OUT=os.path.join(D,'per_function'); ASM=os.path.join(OUT,'asm')
os.makedirs(ASM,exist_ok=True)
funcs=[]
with open(os.path.join(D,'extracted/ghidra-fast/ghidra/04_functions.tsv'),errors='replace') as f:
    next(f)
    for line in f:
        p=line.rstrip('\n').split('\t')
        if len(p)>=3 and re.fullmatch(r'[0-9a-fA-F]+',p[0]):
            try: size=int(p[3]) if len(p)>3 and p[3].isdigit() else 1
            except Exception: size=1
            funcs.append((int(p[0],16),size,p[1],p[2]))
funcs.sort()
addrs=[f[0] for f in funcs]
for i,(a,s,n,sig) in enumerate(funcs):
    if s<=1: funcs[i]=(a,(funcs[i+1][0]-a) if i+1<len(funcs) else 4,n,sig)
ends=[a+(s if s>4 else s) for a,s,n,sig in funcs]
paths=[os.path.join(ASM,'%04x'%(a>>16),'%08x.asm'%a) for a,s,n,sig in funcs]
for p in set(os.path.dirname(x) for x in paths): os.makedirs(p,exist_ok=True)
print('functions',len(funcs),flush=True)
zout=zstandard.ZstdCompressor(threads=4,level=3).stream_writer(open(os.path.join(OUT,'DISASSEMBLY_FULL.asm.zst'),'wb'))
lines=0; assigned=0; cur=-1; fh=None
proc=subprocess.Popen(['objdump','-d','-b','elf64-littleaarch64','-m','aarch64','--no-show-raw-insn',LIB],
                      stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1024*1024)
pat=re.compile(r'^\s*([0-9a-fA-F]+):\s+(.*)$')
for line in proc.stdout:
    lines+=1
    m=pat.match(line)
    if not m: continue
    a=int(m.group(1),16)
    i=bisect.bisect_right(addrs,a)-1
    if i<0 or a>=ends[i]: continue
    if i!=cur:
        if fh: fh.close()
        fh=open(paths[i],'w'); cur=i
        a0,s0,n0,sig0=funcs[i]
        fh.write('// FUNCTION %08x %s\n// SIGNATURE %s\n// SIZE %d\n'%(a0,n0,sig0,s0))
    fh.write('%08x  %s\n'%(a,m.group(2).strip()))
    zout.write(('%08x  %s\n'%(a,m.group(2).strip())).encode('utf-8','replace'))
    assigned+=1
    if lines%5000000==0: print('lines',lines,'assigned',assigned,flush=True)
if fh: fh.close()
zout.close()
proc.wait()
print('DONE lines',lines,'assigned',assigned,'files',len(funcs),flush=True)
