#!/usr/bin/env python3
import os,re,glob,collections
D='/root/workspace/Minecraft, reverse engineer/results'
PF=os.path.join(D,'per_function'); ASM=os.path.join(PF,'asm'); DEC=os.path.join(PF,'decompiled')
os.makedirs(DEC,exist_ok=True)
funcs=[]
with open(os.path.join(D,'extracted/ghidra-fast/ghidra/04_functions.tsv'),errors='replace') as f:
    next(f)
    for line in f:
        p=line.rstrip('\n').split('\t')
        if len(p)>=3 and re.fullmatch(r'[0-9a-fA-F]+',p[0]): funcs.append((p[0].lower(),p[1],p[2]))
print('functions',len(funcs))
for a,n,s in funcs:
    ap=os.path.join(ASM,'%04x'%(int(a,16)>>16),'%s.asm'%a)
    if not os.path.exists(ap):
        os.makedirs(os.path.dirname(ap),exist_ok=True)
        open(ap,'w').write('// FUNCTION %s %s\n// SIGNATURE %s\n// No instructions in executable mapping (stub or unmapped).\n'%(a,n,s))
# split decompiled bodies into one file per function
count=0
for fp in glob.glob(os.path.join(D,'extracted/decompiled-full/decompiled_all','*.c'))+glob.glob(os.path.join(D,'decompiled_all','*.c'))+glob.glob(os.path.join(D,'decompiled_extracted/decompiled_all','*.c')):
    cur=[]; curaddr=None
    for line in open(fp,errors='replace'):
        m=re.match(r'// FUNCTION\s+([0-9a-fA-F]+)',line)
        if m:
            if curaddr:
                with open(os.path.join(DEC,'%s.c'%curaddr),'w') as o: o.write(''.join(cur))
                count+=1
            curaddr=m.group(1).lower(); cur=[line]
        elif curaddr is not None: cur.append(line)
    if curaddr:
        with open(os.path.join(DEC,'%s.c'%curaddr),'w') as o: o.write(''.join(cur))
        count+=1
print('decompiled files',count)
# index
with open(os.path.join(PF,'FUNCTION_INDEX.tsv'),'w') as f:
    f.write('address\tname\tsignature\tasm_file\tc_file\n')
    for a,n,s in funcs:
        ap=os.path.join('asm','%04x'%(int(a,16)>>16),'%s.asm'%a)
        cp=os.path.join('decompiled','%s.c'%a)
        f.write('%s\t%s\t%s\t%s\t%s\n'%(a,n,s.replace('\t',' '),ap,cp if os.path.exists(os.path.join(PF,cp)) else ''))
print('index written')
