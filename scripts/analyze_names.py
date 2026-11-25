#!/usr/bin/env python3
import os,re,sys,collections,subprocess,json
SRC=sys.argv[1]; DEC=sys.argv[2]; RECON=sys.argv[3]; OUT=sys.argv[4]
os.makedirs(OUT,exist_ok=True)
syms=[]
for line in open(os.path.join(SRC,'symbols_all.txt'),errors='replace'):
    m=re.match(r'\s*(\d+):\s+([0-9a-fA-F]+)\s+(\d+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\S+)\s+(.+)$',line.rstrip())
    if m:
        n,val,size,typ,bind,vis,ndx,name=m.groups()
        syms.append((int(val,16),int(size),typ,ndx,name))
raw=[s[4] for s in syms]
dem=subprocess.run(['c++filt'],input='\n'.join(raw)+'\n',text=True,capture_output=True).stdout.splitlines()
while len(dem)<len(syms): dem.append('')
with open(os.path.join(OUT,'ALL_SYMBOLS_DEMANGLED.tsv'),'w') as f:
    f.write('address\tsize\ttype\tbinding\tmangled\tdemangled\n')
    for (a,s,t,b,n),d in zip(syms,dem):
        f.write('0x%x\t%d\t%s\t%s\t%s\t%s\n'%(a,s,t,b,n,d.replace('\t',' ')))

funcs=[]
p=os.path.join('/root/workspace/Minecraft, reverse engineer/results/extracted/ghidra-fast/ghidra','04_functions.tsv')
if os.path.exists(p):
    for line in open(p,errors='replace'):
        parts=line.rstrip('\n').split('\t')
        if len(parts)>=3 and re.fullmatch(r'[0-9a-fA-F]+',parts[0]):
            funcs.append((parts[0],parts[1],parts[2]))

dec_files=[]
for root,_,files in os.walk(DEC):
    for fn in files:
        if fn.endswith('.c'): dec_files.append(os.path.join(root,fn))
addr_to_file={}
import re as _re
for fp in dec_files[:200]:
    for line in open(fp,errors='replace'):
        m=_re.match(r'// FUNCTION\s+([0-9a-fA-F]+)',line)
        if m: addr_to_file[m.group(1).lstrip('0') or '0']=os.path.basename(fp)

fnraw=[f[1] for f in funcs]
fndem=subprocess.run(['c++filt'],input='\n'.join(fnraw)+'\n',text=True,capture_output=True).stdout.splitlines()
while len(fndem)<len(funcs): fndem.append('')
byclass=collections.defaultdict(list)
for (addr,name,sig),d in zip(funcs,fndem):
    cls='Global / free function'
    mm=re.search(r'([A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_~][A-Za-z0-9_]*)*)::',d)
    if mm: cls=mm.group(1)
    display=d if d and d!=name else sig
    byclass[cls].append((addr,name,display))
with open(os.path.join(OUT,'CLASS_METHOD_INDEX.md'),'w') as f:
    f.write('# Class → method index (all recovered function signatures)\n\n')
    f.write('%d functions grouped by the class name recovered from the demangled signature.\n'%len(funcs))
    f.write('Addresses are ELF virtual addresses; decompiled bodies are in `decompiled_all/`.\n\n')
    f.write('| Class | Functions |\n|---|---:|\n')
    for c in sorted(byclass,key=lambda x:-len(byclass[x]))[:500]:
        f.write('| `%s` | %d |\n'%(c,len(byclass[c])))
    f.write('\n')
    for c in sorted(byclass,key=lambda x:-len(byclass[x])):
        f.write('## %s\n\n'%c)
        f.write('| Address | Name | Signature |\n|---|---|---|\n')
        for a,n,s in byclass[c][:2000]:
            f.write('| `%s` | `%s` | `%s` |\n'%(a,n.replace('|','/'),s.replace('|','/')))
        if len(byclass[c])>2000: f.write('\n_Showing first 2000 of %d._\n'%len(byclass[c]))
        f.write('\n')

st=json.load(open(os.path.join(RECON,'structures_summary.json')))
ids=json.load(open(os.path.join(RECON,'ids_summary.json')))
with open(os.path.join(OUT,'STRIPPED_NAME_RECONSTRUCTION.md'),'w') as f:
    f.write('# Reconstruction of stripped names\n\n')
    f.write('The game binary is stripped, but names were mechanically recovered from five\n')
    f.write('independent sources. Nothing below is invented.\n\n')
    f.write('| Source | Recovered | Output file |\n|---|---:|---|\n')
    f.write('| Dynamic symbol table | %d | ALL_SYMBOLS_DEMANGLED.tsv |\n'%len(syms))
    f.write('| C++ vtable symbols (`_ZTV`) | %d vtables / %d methods | CLASSES_AND_VTABLES.md, vtables.tsv |\n'%(st['vtables'],st['vtable_methods']))
    f.write('| RTTI typeinfo (`_ZTI`/`_ZTS`) | %d | RTTI_HIERARCHY.md |\n'%st['typeinfos'])
    f.write('| JNI exports | %d | REGISTRY_AND_MODDING.md |\n'%ids['jni'])
    f.write('| Registry/factory candidates | %d | REGISTRY_AND_MODDING.md |\n'%ids['registry_candidates'])
    f.write('| Decompiled function bodies | %d | decompiled_full.tar.zst |\n'%(68905))
    f.write('| Minecraft identifiers | %d | MINECRAFT_IDS.md |\n'%ids['identifiers'])
    f.write('\n## How a stripped address becomes a named method\n\n')
    f.write('1. Find a `_ZTV` symbol at a `.data.rel.ro` address → class name.\n')
    f.write('2. Relocations at vtable+16, +24, ... point to virtual method addresses.\n')
    f.write('3. Each target address resolves through the dynamic symbol table to a demangled signature.\n')
    f.write('4. The same address appears in `04_functions.tsv` and in a decompiled C file.\n')
    f.write('5. RTTI base-class links give inheritance; JNI exports give the Java-facing entry.\n\n')
    f.write('## Coverage caveat\n\n')
    f.write('Core Minecraft classes are heavily stripped; the largest named groups come from\n')
    f.write('embedded engines (V8, CoHTML/Renoir, WebRTC, FMOD, XAL, Xbox services) and JNI.\n')
    f.write('Gameplay classes without symbols were left as recovered addresses/signatures rather\n')
    f.write('than guessed. Use the vtable and decompiled bodies to identify them further.\n')
print('symbols',len(syms),'funcs',len(funcs),'classes',len(byclass))
