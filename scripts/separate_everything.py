#!/usr/bin/env python3
"""Write a separate, self-contained report file for every identifier, class and function."""
import os,re,csv,collections,json,sys
D='/root/workspace/Minecraft, reverse engineer/results'
OUT=os.path.join(D,'separated'); os.makedirs(OUT,exist_ok=True)
ids=[]
with open(os.path.join(D,'reconstruction/minecraft_ids.tsv'),errors='replace') as f:
    r=csv.DictReader(f,delimiter='\t')
    for row in r: ids.append(row)
print('ids',len(ids))
# vtables by class token
vts=collections.defaultdict(list)
vp=os.path.join(D,'reconstruction/vtables.tsv')
with open(vp,errors='replace') as f:
    next(f,None)
    for line in f:
        p=line.rstrip('\n').split('\t')
        if len(p)>=8 and p[2]: vts[p[2]].append(p)
catdirs={}
for row in ids:
    cat=re.sub(r'[^A-Za-z0-9]+','_',row['category']).strip('_')
    d=os.path.join(OUT,cat); os.makedirs(d,exist_ok=True); catdirs[cat]=d
    sid=row['identifier'].replace(':','__').replace('/','_')
    name=sid+'.md'
    token=row['identifier'].split(':')[-1].split('.')[-1].split('_')[0].lower()
    related=[]
    for cls,rows in vts.items():
        if token and token in cls.lower(): related.append((cls,rows[0][1],len(rows)))
    with open(os.path.join(d,name),'w') as f:
        f.write('# %s\n\n'%row['identifier'])
        f.write('| Field | Value |\n|---|---|\n')
        f.write('| Category | %s |\n'%row['category'])
        f.write('| File offset | %s |\n'%row['file_offset'])
        f.write('| Virtual address | %s |\n'%row['vaddr'])
        f.write('| ELF section | %s |\n'%row['section'])
        f.write('| Purpose (inferred) | %s |\n'%row['description'])
        f.write('| Decompiled references | %s |\n\n'%(row['decompiled_files'] or 'none found'))
        f.write('## Related reconstructed classes\n\n')
        if related:
            for cls,addr,cnt in related[:30]:
                f.write('- `%s` — vtable `%s`, %d virtual methods\n'%(cls,addr,cnt))
        else:
            f.write('- No name-matched vtable; search the decompiled bodies by offset.\n')
        f.write('\n## How to modify\n\n')
        f.write('1. Patch the `.rodata` string at file offset `%s` to rename.\n'%row['file_offset'])
        f.write('2. Find the owning registry/factory in `REGISTRY_AND_MODDING.md`.\n')
        f.write('3. Find the owning class vtable above; hook a slot to change behaviour.\n')
        f.write('4. Locate the code by VADDR `%s` in `decompiled_all/` or per-function ASM.\n'%row['vaddr'])
# index
with open(os.path.join(OUT,'INDEX.md'),'w') as f:
    f.write('# Separated reports — one file per identifier\n\n')
    f.write('%d standalone files, grouped into %d directories.\n\n'%(len(ids),len(catdirs)))
    for c in sorted(catdirs): f.write('- [%s](%s/) — %d files\n'%(c,c,len(os.listdir(catdirs[c]))))
json.dump({'files':len(ids),'directories':len(catdirs)},open(os.path.join(OUT,'summary.json'),'w'),indent=2)
print('wrote',len(ids),'separate files in',len(catdirs),'dirs')
