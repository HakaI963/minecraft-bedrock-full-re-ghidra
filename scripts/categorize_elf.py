#!/usr/bin/env python3
"""Categorise ELF symbols (offset + demangled signature) and mapped strings.
Works even if Ghidra analysis is incomplete. No filtering by 'importance'.
"""
import os, re, sys, json, collections, subprocess

src = sys.argv[1] if len(sys.argv) > 1 else 'elf'
out = sys.argv[2] if len(sys.argv) > 2 else 'categories_elf'
os.makedirs(out, exist_ok=True)

CATS = {
 'Block & World': ['block','chunk','level','world','dimension','biome','terrain','village','structure','region','heightmap','light'],
 'Item & Inventory': ['item','inventory','container','recipe','craft','enchant','armor','equipment','itemstack','trade'],
 'Entity & Mob': ['entity','mob','player','actor','ai','behavior','pathfind','monster','animal','villager','damage','health','attribute'],
 'UI & Main Menu': ['ui','gui','menu','screen','widget','button','hud','text','font','title','pause','setting','option','cohtml','yoga'],
 'Networking': ['net','packet','network','connection','server','client','socket','login','handshake','compression','encrypt','raknet','playfab'],
 'Rendering & Graphics': ['render','renderer','shader','mesh','texture','material','camera','frame','gpu','vulkan','opengl','model','particle','lighting','renoir','gles'],
 'Audio': ['audio','sound','fmod','music','voice','sfx'],
 'Physics & Math': ['physics','collision','aabb','vector','matrix','math','ray','pose','rotation','quaternion','motion'],
 'Storage & NBT': ['nbt','save','storage','database','serialize','deserialize','json','tag','leveldat'],
 'Redstone & Mechanisms': ['redstone','circuit','piston','rail','hopper','dispenser','command','blockentity','tileentity'],
 'Input & Controls': ['input','key','touch','mouse','controller','gesture','keyboard'],
 'Character & Skin': ['skin','character','cape','animation','pose'],
 'Security & DRM': ['pairip','license','crypto','sign','verify','checksum','anti','tamper','integrity','obfusc'],
 'Runtime & OS': ['jni','android','java','vm','thread','memory','alloc','log','assert','exception','malloc','free','time','locale','v8','zone'],
}

def cat_of(name):
    n = name.lower()
    best, score = 'Other / Uncategorised', 0
    for c, kws in CATS.items():
        s = sum(3 if re.search(r'(^|[^a-z])'+re.escape(k)+r'($|[^a-z])', n) else (1 if k in n else 0) for k in kws)
        if s > score:
            best, score = c, s
    return best

def read_symbols(path):
    rows=[]
    if not os.path.exists(path): return rows
    for line in open(path,errors='replace'):
        m=re.match(r'\s*(\d+):\s+([0-9a-fA-F]+)\s+(\d+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\S+)\s+(.+)$',line.rstrip())
        if not m: continue
        num,val,size,typ,bind,vis,ndx,name=m.groups()
        if ndx=='UND' or int(val,16)==0: continue
        rows.append((int(val,16),int(size),typ,ndx,name.rstrip()))
    return rows

syms=read_symbols(os.path.join(src,'symbols_all.txt'))
if not syms: syms=read_symbols(os.path.join(src,'nm_dynamic_defined.txt'))
print('parsed symbols',len(syms))
raw=[s[4] for s in syms]
p=subprocess.run(['c++filt'],input='\n'.join(raw)+'\n',text=True,capture_output=True)
dem=p.stdout.splitlines() if p.returncode==0 else raw
while len(dem)<len(syms): dem.append('')

by=collections.defaultdict(list)
for (val,size,typ,ndx,name),dsig in zip(syms,dem):
    by[cat_of(dsig)].append(('symbol', '0x%x'%val, dsig, '%s / section %s'%(typ,ndx), str(size)))

sp=os.path.join(src,'strings_mapped.tsv')
if os.path.exists(sp):
    with open(sp,errors='replace') as f:
        next(f,None)
        for line in f:
            p2=line.rstrip('\n').split('\t')
            if len(p2)<4: continue
            text=p2[3]
            if text:
                by[cat_of(text)].append(('string',p2[0],text[:180],p2[2],p2[1]))

idx=['# Minecraft Bedrock - ELF offset/signature catalogue','',
     'Source: libminecraftpe.so (arm64), 342,231,392 bytes, sha256 in elf/sha256.txt.',
     'Offsets are virtual addresses from the ELF symbol table; file offsets are in',
     '`strings_mapped.tsv`. Every defined symbol and string is listed.', '',
     '| Category | Entries | Report |','|---|---:|---|']
for c in sorted(by,key=lambda x:-len(by[x])):
    n=len(by[c]); fn=c.lower().replace(' & ','_').replace(' ','_').replace('/','_')+'.md'
    idx.append('| %s | %d | [%s](%s) |'%(c,n,fn,fn))
idx.append('| **TOTAL** | **%d** | |'%sum(len(v) for v in by.values()))
open(os.path.join(out,'INDEX.md'),'w').write('\n'.join(idx)+'\n')
for c,items in by.items():
    fn=c.lower().replace(' & ','_').replace(' ','_').replace('/','_')+'.md'
    with open(os.path.join(out,fn),'w') as f:
        f.write('# %s\n\n%d entries.\n\n'%(c,len(items)))
        f.write('| Kind | Offset / Address | Name / Signature | Type / Section | Size / VADDR |\n|---|---|---|---|---|\n')
        for k,off,name,sig,size in items:
            name=str(name).replace('|','\\|').replace('`','')[:250]
            sig=str(sig).replace('|','\\|')[:120]
            f.write('| %s | `%s` | `%s` | `%s` | `%s` |\n'%(k,off,name,sig,size))
json.dump({'symbols':len(syms),'total':sum(len(v) for v in by.values()),
           'categories':{k:len(v) for k,v in by.items()}},
          open(os.path.join(out,'summary.json'),'w'),indent=2)
print('wrote',out,'total',sum(len(v) for v in by.values()))
