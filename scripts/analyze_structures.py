#!/usr/bin/env python3
"""Reconstruct C++ vtables, virtual methods and RTTI hierarchy from ELF symbols+relocations."""
import os, re, json, collections, subprocess, sys
SRC=sys.argv[1]; OUT=sys.argv[2]
os.makedirs(OUT,exist_ok=True)

sym_by_addr={}; sym_by_name={}; all_syms=[]
for line in open(os.path.join(SRC,'symbols_all.txt'),errors='replace'):
    m=re.match(r'\s*(\d+):\s+([0-9a-fA-F]+)\s+(\d+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\S+)\s+(.+)$',line.rstrip())
    if not m: continue
    n,val,size,typ,bind,vis,ndx,name=m.groups()
    if ndx=='UND': continue
    a=int(val,16)
    if not a: continue
    rec=(a,int(size),typ,name)
    all_syms.append(rec); sym_by_addr[a]=rec
    sym_by_name.setdefault(name,rec)

raw=[s[3] for s in all_syms]
dem=subprocess.run(['c++filt'],input='\n'.join(raw)+'\n',text=True,capture_output=True).stdout.splitlines()
demand={s[0]:(dem[i] if i<len(dem) else s[3]) for i,s in enumerate(all_syms)}

reloc={}
pat=re.compile(r'^([0-9a-fA-F]{16})\s+\S+\s+R_AARCH64_ABS64\s+([0-9a-fA-F]+)\s+(\S+)\s*\+\s*(\S+)$')
for line in open(os.path.join(SRC,'relocations.txt'),errors='replace'):
    m=pat.match(line)
    if m:
        add=m.group(4)
        try: addv=int(add,0) if add.lower().startswith('0x') or add.isdigit() else int(add,16)
        except ValueError: addv=0
        reloc[int(m.group(1),16)]=(m.group(3),int(m.group(2),16),addv)

def classname(sym):
    if sym.startswith('_ZTV'): return sym[4:]
    if sym.startswith('_ZTI'): return sym[4:]
    return sym
def pretty(sym):
    if sym in demand: return demand[sym]
    r=subprocess.run(['c++filt'],input=sym+'\n',text=True,capture_output=True).stdout.strip()
    if r.startswith('typeinfo name for '): r=r[len('typeinfo name for '):]
    return r or sym

vt=[]
vtset=[s for s in all_syms if s[3].startswith('_ZTV')]
for a,size,typ,name in vtset:
    slots=[]
    # slot 0 = offset-to-top, slot 1 = typeinfo
    ti=reloc.get(a+8)
    ti_name=ti[0] if ti else ''
    for off in range(a+16,a+size-7,8):
        r=reloc.get(off)
        if not r: continue
        target,val,add=r
        d=pretty(target)
        slots.append({'slot':(off-a)//8,'offset':hex(off),'target':hex(val),'symbol':target,'signature':d})
    vt.append({'vtable_symbol':name,'class':pretty('_ZTS'+name[4:]),'address':hex(a),'size':size,
               'typeinfo':ti_name,'typeinfo_class':pretty('_ZTS'+ti_name[4:]) if ti_name.startswith('_ZTI') else '',
               'methods':slots})

with open(os.path.join(OUT,'vtables.tsv'),'w') as f:
    f.write('vtable_address\tvtable_symbol\tclass\tsize\ttypeinfo\tmethod_slot\tmethod_address\tmethod_signature\n')
    for v in vt:
        for m in v['methods']:
            f.write('%s\t%s\t%s\t%d\t%s\t%d\t%s\t%s\n'%(v['address'],v['vtable_symbol'],v['class'],v['size'],v['typeinfo'],m['slot'],m['target'],m['signature']))
        if not v['methods']:
            f.write('%s\t%s\t%s\t%d\t%s\t0\t\t\n'%(v['address'],v['vtable_symbol'],v['class'],v['size'],v['typeinfo']))

with open(os.path.join(OUT,'CLASSES_AND_VTABLES.md'),'w') as f:
    f.write('# Reconstructed C++ classes, vtables and virtual methods\n\n')
    f.write('%d defined vtables. Each row: slot index, virtual address, demangled signature.\n\n'%len(vt))
    f.write('| Class | Vtable address | Size | Typeinfo | Virtual methods |\n|---|---|---:|---|---|\n')
    for v in sorted(vt,key=lambda x:int(x['address'],16)):
        f.write('| `%s` | `%s` | %d | `%s` | %d |\n'%(v['class'],v['address'],v['size'],v['typeinfo'],len(v['methods'])))
    f.write('\n## Per-class vtable layouts\n\n')
    for v in sorted(vt,key=lambda x:-len(x['methods']))[:400]:
        f.write('### %s — `%s` (%d methods)\n\n'%(v['class'],v['address'],len(v['methods'])))
        for m in v['methods']:
            f.write('- slot %d @ `%s` → `%s` — `%s`\n'%(m['slot'],m['offset'],m['target'],m['signature']))
        f.write('\n')

# RTTI hierarchy via typeinfo relocations
hier=[]
for a,size,typ,name in all_syms:
    if not name.startswith('_ZTI'): continue
    bases=[]
    for off in (a+8,a+16,a+24,a+32):
        r=reloc.get(off)
        if r and r[0].startswith('_ZTI') and r[0]!=name:
            bases.append(r[0])
    hier.append((name,hex(a),pretty('_ZTS'+name[4:]),[pretty('_ZTS'+b[4:]) for b in bases],hex(size)))
with open(os.path.join(OUT,'RTTI_HIERARCHY.md'),'w') as f:
    f.write('# RTTI class hierarchy (recovered from typeinfo relocations)\n\n')
    f.write('%d typeinfo objects.\n\n'%len(hier))
    f.write('| Typeinfo symbol | Address | Demangled class | Base classes | Size |\n|---|---|---|---|---|\n')
    for n,a,d,b,s in sorted(hier,key=lambda x:x[1]):
        f.write('| `%s` | `%s` | `%s` | %s | %s |\n'%(n,a,d,', '.join('`%s`'%x for x in b),s))

json.dump({'vtables':len(vt),'vtable_methods':sum(len(v['methods']) for v in vt),
           'typeinfos':len(hier),'relocations_indexed':len(reloc)},open(os.path.join(OUT,'structures_summary.json'),'w'),indent=2)
print('vtables',len(vt),'methods',sum(len(v['methods']) for v in vt),'typeinfos',len(hier),'relocs',len(reloc))
