#!/usr/bin/env python3
"""Build clean categorized database: name, file offset, byte pattern, description."""
import os,re,csv,collections,json,struct
D='/root/workspace/Minecraft, reverse engineer/results'; OUT=D+'/FINAL'
lib=open('/root/workspace/Minecraft, reverse engineer/native/libminecraftpe.so','rb').read()
SRC=D+'/extracted/elf-fasttrack/elf'
# load identifiers
rows=[]
for r in csv.DictReader(open(D+'/reconstruction/minecraft_ids.tsv'),delimiter='\t'):
    rows.append(r)
print('identifiers',len(rows))
def pat(off,n=32):
    b=lib[off:off+n]
    if not b: return ''
    return ' '.join('%02x'%x for x in b)
def hexv(x):
    try:return '0x%x'%int(x)
    except:return str(x)
# categories via existing category field + keywords
CATS=collections.defaultdict(list)
for r in rows:
    c=r['category']
    CATS[c].append(r)
# write per-category files with byte pattern
for c,items in CATS.items():
    fn=re.sub(r'[^A-Za-z0-9]+','_',c).strip('_')+'.md'
    with open(os.path.join(OUT,'categories',fn),'w') as f:
        f.write('# %s\n\n%d entries.\n\n'%(c,len(items)))
        f.write('| Name | File offset | VADDR | Section | Byte pattern (32 bytes at offset) | Description |\n')
        f.write('|---|---:|---:|---|---|---|\n')
        for r in items:
            off=int(r['file_offset'])
            f.write('| `%s` | %s | %s | %s | `%s` | %s |\n'%(
                r['identifier'],hexv(off),hexv(r['vaddr']),r['section'],pat(off),
                r['description'].replace('|','/')[:160]))
# also TSV complete
with open(os.path.join(OUT,'ALL_VANILLA.tsv'),'w') as f:
    f.write('category\tname\tfile_offset\tvaddr\tsection\tbyte_pattern\tdescription\n')
    for c,items in CATS.items():
        for r in items:
            off=int(r['file_offset'])
            f.write('%s\t%s\t%s\t%s\t%s\t%s\t%s\n'%(c,r['identifier'],hexv(off),hexv(r['vaddr']),
                r['section'],pat(off),r['description'].replace('\t',' ')))
json.dump({'identifiers':len(rows),'categories':{k:len(v) for k,v in CATS.items()}},
          open(os.path.join(OUT,'vanilla_summary.json'),'w'),indent=2)
print('wrote',len(CATS),'categories')
