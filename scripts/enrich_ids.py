#!/usr/bin/env python3
"""Rebuild per-identifier reports with contextual evidence from adjacent .rodata strings."""
import os,re,csv,collections,json
D='/root/workspace/Minecraft, reverse engineer/results'
SRC=os.path.join(D,'extracted/elf-fasttrack/elf'); OUT=os.path.join(D,'reconstruction'); SEP=os.path.join(D,'separated')
allstr=[]
for line in open(os.path.join(SRC,'strings_mapped.tsv'),errors='replace'):
    p=line.rstrip('\n').split('\t')
    if len(p)>=4 and p[0].isdigit():
        allstr.append((int(p[0]),p[2],p[3]))
allstr.sort()
offs=[x[0] for x in allstr]
import bisect
def context(off,r=300):
    i=bisect.bisect_left(offs,off)
    out=[]
    for j in range(max(0,i-6),min(len(allstr),i+7)):
        o,s,t=allstr[j]
        if abs(o-off)<=r and t and len(t)<120 and 'minecraft:' not in t:
            out.append((o,s,t))
    return out[:8]
rows=[]
with open(os.path.join(OUT,'minecraft_ids.tsv'),errors='replace') as f:
    for row in csv.DictReader(f,delimiter='\t'): rows.append(row)
for r in rows:
    ctx=context(int(r['file_offset']))
    r['context']=ctx
    base=r['description']
    # re-derive description with last-token priority (specific subtype wins over material)
    name=r['identifier'].split(':',1)[-1]
    toks=[t for t in re.split(r'[_\-./]',name) if t]
    TERMS={'stone':'a primary underground solid block','dirt':'a common soil block','grass':'a grass-covered surface block','sand':'a granular desert/beach block','gravel':'a gravity-affected granular block','log':'a tree trunk block','planks':'a wooden building block','leaves':'a foliage block from trees','ore':'a mineral-bearing block','glass':'a transparent building block','wool':'a colored soft block','bricks':'a masonry building block','furnace':'a smelting station block','chest':'a storage container block','door':'an openable barrier block','rail':'a minecart track block','torch':'a light-emitting block','bed':'a sleep/spawn-point block','sword':'a melee weapon item','pickaxe':'a mining tool item','axe':'a woodcutting tool item','shovel':'a digging tool item','hoe':'a farming tool item','helmet':'head armor item','chestplate':'torso armor item','potion':'a consumable effect item','bucket':'a liquid container item','spider':'an arthropod mob','zombie':'an undead hostile mob','creeper':'an exploding hostile mob','villager':'a tradable NPC mob','pig':'a passive livestock mob','cow':'a passive livestock mob','boat':'a water vehicle entity','minecart':'a rail vehicle entity','biome':'a worldgen climate region','structure':'a generated structure feature','sound':'an audio event identifier','particle':'a visual effect identifier','block':'a placeable world block','item':'an inventory item','entity':'a live world entity','recipe':'a crafting recipe definition','loot':'a loot table definition','advancement':'a progression achievement','enchantment':'an item enchantment definition','effect':'a status effect definition','command':'a server command','screen':'a UI screen','packet':'a network packet type','texture':'a rendered texture asset'}
    desc=[]
    for t in reversed(toks):
        if t in TERMS and TERMS[t] not in desc: desc.append(TERMS[t])
        if len(desc)>=2: break
    base='; '.join(desc) if desc else 'Identifier-derived: '+' '.join(toks)
    r['description']=base
    hints=[]
    for o,s,t in ctx:
        tl=t.lower()
        if any(k in tl for k in ('block','item','entity','sound','particle','recipe','advancement','enchant','effect','structure','biome')):
            hints.append(t)
    r['evidence']= 'Context strings: '+ '; '.join('`%s` @%d'%(t,o) for o,s,t in ctx[:5]) if ctx else 'No adjacent readable strings'
    if hints: r['description']=base+' | evidence: '+hints[0][:80]
with open(os.path.join(OUT,'minecraft_ids.tsv'),'w') as f:
    w=csv.DictWriter(f,fieldnames=['identifier','category','file_offset','vaddr','section','description','decompiled_files','evidence'],delimiter='\t')
    w.writeheader()
    for r in rows:
        w.writerow({k:r.get(k,'') for k in w.fieldnames})
# per-category markdown
by=collections.defaultdict(list)
for r in rows: by[r['category']].append(r)
with open(os.path.join(OUT,'MINECRAFT_IDS.md'),'w') as f:
    f.write('# Every Minecraft identifier — verified with contextual evidence\n\n')
    f.write('%d identifiers. File offsets and VADDRs are from strings_mapped.tsv.\n'%len(rows))
    f.write('Evidence lists adjacent `.rodata` strings within 300 bytes; descriptions\n')
    f.write('are inferred, not Mojang source. This is static evidence, not runtime proof.\n\n')
    f.write('| Category | Count |\n|---|---:|\n')
    for c in sorted(by,key=lambda x:-len(by[x])): f.write('| %s | %d |\n'%(c,len(by[c])))
    f.write('\n')
    for c in sorted(by,key=lambda x:-len(by[x])):
        f.write('## %s\n\n'%c)
        f.write('| Identifier | File offset | VADDR | Section | Purpose | Evidence |\n|---|---:|---:|---|---|---|\n')
        for r in by[c]:
            ev=r['evidence'].replace('|','/').replace('`','')[:200]
            f.write('| `%s` | %s | %s | %s | %s | %s |\n'%(r['identifier'],r['file_offset'],r['vaddr'],r['section'],r['description'].replace('|','/')[:200],ev))
        f.write('\n')
# separated files
for d in os.listdir(SEP):
    p=os.path.join(SEP,d)
    if os.path.isdir(p):
        for fn in os.listdir(p):
            if fn.endswith('.md'): os.remove(os.path.join(p,fn))
for r in rows:
    cat=re.sub(r'[^A-Za-z0-9]+','_',r['category']).strip('_')
    d=os.path.join(SEP,cat); os.makedirs(d,exist_ok=True)
    sid=r['identifier'].replace(':','__').replace('/','_')
    with open(os.path.join(d,sid+'.md'),'w') as f:
        f.write('# %s\n\n'%r['identifier'])
        f.write('| Field | Value |\n|---|---|\n')
        for k in ['category','file_offset','vaddr','section','description','decompiled_files','evidence']:
            f.write('| %s | %s |\n'%(k.replace('_',' ').title(),str(r.get(k,'')).replace('|','/')))
        f.write('\n## End-to-end lookup\n\n')
        f.write('1. File offset `%s` → patch/rename the string in the binary.\n'%r['file_offset'])
        f.write('2. VADDR `%s` → look up in `MASTER_OFFSET_SIGNATURE_TABLE.tsv` for owning function.\n'%r['vaddr'])
        f.write('3. `vtables.tsv` → find the class vtable to hook.\n')
        f.write('4. `REGISTRY_AND_MODDING.md` → registry/factory function to add or modify.\n')
json.dump({'identifiers':len(rows),'with_evidence':sum(1 for r in rows if r['context'])},
          open(os.path.join(OUT,'ids_enrichment_summary.json'),'w'),indent=2)
print('enriched',len(rows),'with evidence',sum(1 for r in rows if r['context']))
