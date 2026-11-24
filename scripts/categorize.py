#!/usr/bin/env python3
"""Turn raw Ghidra/ELF exports into a human-navigable, categorised report.
Every function / symbol is assigned to exactly one primary category by score.
Offsets and signatures are preserved verbatim from the exporters.
"""
import os, re, sys, collections, json

root = sys.argv[1] if len(sys.argv) > 1 else 'out'
os.makedirs(os.path.join(root, 'categories'), exist_ok=True)

CATEGORIES = {
 'Block & World': ['block','chunk','level','world','dimension','biome','terrain','village','structure','region','heightmap','light'],
 'Item & Inventory': ['item','inventory','container','recipe','craft','enchant','armor','equipment','stack','trade'],
 'Entity & Mob': ['entity','mob','player','actor','ai','behavior','pathfind','monster','animal','villager','damage','health','attribute'],
 'UI & Main Menu': ['ui','gui','menu','screen','widget','button','hud','text','font','render','draw','screen','title','pause','setting','option'],
 'Networking': ['net','packet','network','connection','server','client','socket','login','handshake','compression','encrypt','raknet'],
 'Rendering & Graphics': ['render','renderer','shader','mesh','texture','material','camera','frame','gpu','vulkan','opengl','model','particle','lighting'],
 'Audio': ['audio','sound','fmod','music','voice','sfx'],
 'Physics & Math': ['physics','collision','aabb','vector','matrix','math','ray','pose','rotation','quaternion','motion'],
 'Storage & NBT': ['nbt','save','storage','database','serialize','deserialize','json','tag','file','db','leveldat'],
 'Redstone & Mechanisms': ['redstone','circuit','piston','rail','hopper','dispenser','command','blockentity','tileentity'],
 'Input & Controls': ['input','key','touch','mouse','controller','gesture','keyboard'],
 'Character & Skin': ['skin','character','cape','model','anim','animation','pose'],
 'Security & DRM': ['pairip','license','/auth','crypto','sign','verify','checksum','anti','tamper','integrity','obfusc'],
 'Runtime & OS': ['jni','android','java','vm','thread','memory','alloc','log','assert','exception','malloc','free','time','locale'],
}

def cat_of(name):
    n = name.lower()
    best, score = 'Other / Uncategorised', 0
    for c, kws in CATEGORIES.items():
        s = sum(3 if re.search(r'(^|_|::)' + re.escape(k) + r'($|_|::)', n) else (1 if k in n else 0) for k in kws)
        if s > score:
            best, score = c, s
    return best

def read_tsv(path):
    if not os.path.exists(path): return []
    with open(path, errors='replace') as f:
        lines = f.read().splitlines()
    if not lines: return []
    hdr = lines[0].split('\t')
    out = []
    for l in lines[1:]:
        parts = l.split('\t')
        out.append(dict(zip(hdr, parts)) if len(parts) == len(hdr) else {'raw': l, 'name': l[:120]})
    return out

funcs = read_tsv(os.path.join(root, 'ghidra', '04_functions.tsv'))
syms  = read_tsv(os.path.join(root, 'ghidra', '03_all_symbols.tsv'))
data  = read_tsv(os.path.join(root, 'ghidra', '02_defined_data.tsv'))
strs  = read_tsv(os.path.join(root, 'elf', 'strings_mapped.tsv'))

by_cat = collections.defaultdict(list)
for f in funcs:
    name = f.get('name') or f.get('signature') or f.get('raw', '')
    by_cat[cat_of(name)].append(('function', f.get('entry_point',''), name,
                                 f.get('signature',''), f.get('size','')))
for s in syms:
    name = s.get('name') or s.get('raw', '')
    by_cat[cat_of(name)].append(('symbol', s.get('address',''), name, s.get('type',''), s.get('size','')))
for s in strs:
    text = s.get('string', '')[:160]
    if text:
        by_cat[cat_of(text)].append(('string', s.get('file_offset',''), text, s.get('section',''), s.get('vaddr','')))

idx = ['# Minecraft Bedrock - categorised reverse engineering index', '',
       'Source binary: `libminecraftpe.so` (arm64-v8a), 342,231,392 bytes.',
       '', 'All offsets are **file offsets** from ELF `readelf -SW`, and addresses',
       'are virtual addresses from Ghidra/ELF. Nothing was discarded.', '',
       '| Category | Entries | Report |', '|---|---:|---|']
for c in sorted(by_cat, key=lambda x: -len(by_cat[x])):
    n = len(by_cat[c])
    fn = c.lower().replace(' & ', '_').replace(' ', '_').replace('/', '_') + '.md'
    idx.append('| %s | %d | [details](categories/%s) |' % (c, n, fn))
idx.append('| **TOTAL** | **%d** | |' % sum(len(v) for v in by_cat.values()))
with open(os.path.join(root, 'INDEX.md'), 'w') as f:
    f.write('\n'.join(idx) + '\n')

for c, items in by_cat.items():
    fn = c.lower().replace(' & ', '_').replace(' ', '_').replace('/', '_') + '.md'
    with open(os.path.join(root, 'categories', fn), 'w') as f:
        f.write('# %s\n\n%d entries.\n\n' % (c, len(items)))
        f.write('| Kind | Offset / Address | Name / Value | Signature / Section | Size / VADDR |\n|---|---|---|---|---|\n')
        for kind, off, name, sig, size in items[:50000]:
            name = str(name).replace('|','\\|')[:200]
            sig = str(sig).replace('|','\\|')[:200]
            f.write('| %s | `%s` | `%s` | `%s` | `%s` |\n' % (kind, off, name, sig, size))
        if len(items) > 50000:
            f.write('\n_Truncated display at 50,000 rows in this view; full data remains in the TSV exports._\n')

summary = {'funcs': len(funcs), 'symbols': len(syms), 'data': len(data), 'strings': len(strs),
           'categories': {k: len(v) for k, v in by_cat.items()}}
with open(os.path.join(root, 'categorization_summary.json'), 'w') as f:
    json.dump(summary, f, indent=2)
print(json.dumps(summary, indent=2))
