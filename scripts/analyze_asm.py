#!/usr/bin/env python3
"""Deep annotated analysis of functions without decompiled C: calls, branches, constants, strings."""
import os,re,collections,json,bisect
D='/root/workspace/Minecraft, reverse engineer/results'
PF=os.path.join(D,'per_function'); ASM=os.path.join(PF,'asm'); DEC=os.path.join(PF,'decompiled')
OUT=os.path.join(D,'reconstruction'); os.makedirs(OUT,exist_ok=True)
# refresh C files
for fn in os.listdir(D+'/decompiled_COMPLETE'):
    if fn.endswith('.c'):
        import shutil; shutil.copy(os.path.join(D,'decompiled_COMPLETE',fn),os.path.join(DEC,fn))
syms={}
for line in open(os.path.join(D,'extracted/elf-fasttrack/elf/symbols_all.txt'),errors='replace'):
    m=re.match(r'\s*(\d+):\s+([0-9a-fA-F]+)\s+(\d+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\S+)\s+(.+)$',line.rstrip())
    if m:
        a=int(m.group(2),16)
        if a and m.group(7)!='UND': syms.setdefault(a,m.group(8).strip())
missing=[x.strip() for x in open(D+'/still_missing_functions.txt') if x.strip()]
out=os.path.join(OUT,'UNDECOMPILED_DEEP_ASM.md')
n=0
with open(out,'w') as f:
    f.write('# Deep disassembly analysis for functions without decompiled C\n\n')
    f.write('%d functions. Every instruction, resolved call target, branch and immediate is listed.\n'%len(missing))
    f.write('Source: full ARM64 disassembly of libminecraftpe.so (53.8M instructions).\n\n')
    for h in missing:
        p=os.path.join(ASM,'%04x'%(int(h,16)>>16),'%s.asm'%h)
        if not os.path.exists(p): continue
        lines=open(p,errors='replace').read().splitlines()
        hdr=lines[:3]; ins=[l for l in lines[3:] if l.strip()]
        calls=[]; brs=[]; imms=[]
        for l in ins:
            m=re.match(r'\s*([0-9a-f]+)\s+(.*)',l)
            if not m: continue
            ad,body=m.group(1),m.group(2)
            if re.search(r'\bbl\s',body):
                t=re.search(r'#\s*([0-9a-f]+)',body)
                if t:
                    ta=int(t.group(1),16); calls.append((ad,hex(ta),syms.get(ta,'')))
            if re.search(r'\b(b\.|b\s|cb|tb)',body): brs.append((ad,body))
            for q in re.findall(r'#\s*0x([0-9a-f]+)',body): imms.append((ad,q))
        f.write('## Function `%s` — %d instructions\n\n'%(h,len(ins)))
        f.write('Header: `%s`\n\n'%(' | '.join(x.strip('// ') for x in hdr[:2])))
        f.write('Calls: %d, branches: %d, immediates: %d\n\n'%(len(calls),len(brs),len(imms)))
        if calls:
            f.write('| From | Target | Resolved symbol |\n|---|---|---|\n')
            for a,t,s in calls[:100]: f.write('| `%s` | `%s` | `%s` |\n'%(a,t,s))
            f.write('\n')
        f.write('```asm\n%s\n```\n\n'%('\n'.join(ins[:400])))
        if len(ins)>400: f.write('_... %d more instructions in per_function/asm/%s_\n\n'%(len(ins)-400,p))
        n+=1
print('wrote',n,'deep ASM reports')
# update index
idx=os.path.join(PF,'FUNCTION_INDEX.tsv')
with open(idx,'w') as f:
    f.write('address\tname\tsignature\tasm_file\tc_file\n')
    for line in open(os.path.join(D,'extracted/ghidra-fast/ghidra/04_functions.tsv'),errors='replace'):
        p=line.rstrip('\n').split('\t')
        if len(p)>=3 and re.fullmatch(r'[0-9a-fA-F]+',p[0]):
            a=p[0].lower(); ap=os.path.join('asm','%04x'%(int(a,16)>>16),'%s.asm'%a)
            cp=os.path.join('decompiled','%s.c'%a)
            f.write('%s\t%s\t%s\t%s\t%s\n'%(a,p[1],p[2],ap,cp if os.path.exists(os.path.join(PF,cp)) else ''))
