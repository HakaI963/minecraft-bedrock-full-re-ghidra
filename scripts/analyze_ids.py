#!/usr/bin/env python3
"""Enumerate all Minecraft identifiers with offsets, classify them, link to decompiled code,
and generate a registry/modding reference from recovered symbols and vtables."""
import os, re, sys, collections, json
SRC=sys.argv[1]; DEC=sys.argv[2]; OUT=sys.argv[3]
os.makedirs(OUT,exist_ok=True)

RULES=[
 ('Blocks', ['block','stone','dirt','grass','sand','gravel','log','wood','plank','leaves','ore','ingot','glass','wool','brick','slab','stair','fence','door','trapdoor','gate','wall','torch','rail','chest','furnace','anvil','bed','sign','banner','carpet','concrete','terracotta','mushroom','netherrack','obsidian','ice','snow','clay','portal','sponge','ladder','hopper','dispenser','observer','piston','pressure_plate','button','lever','tnt','cake','farm','crop','wheat','carrot','potato','melon','pumpkin','bamboo','copper','deepslate','tuff','andesite','diorite','granite','basalt','blackstone','crimson','warped','sculk','amethyst','netherite','chorus','end_rod','sea_lantern','lantern','campfire','barrel','lectern','composter','beehive','honey','scaffolding','loom','smithing','brewing','cauldron','jukebox','noteblock','daylight','sensor','target','beacon','conduit','shulker','structure_void','barrier','air','water','lava','fire','cobweb','vine','kelp','seaweed','coral','anvil']),
 ('Items & Equipment', ['item','sword','pickaxe','axe','shovel','hoe','spear','helmet','chestplate','leggings','boots','elytra','shield','bow','crossbow','arrow','trident','potion','splash_potion','lingering_potion','bucket','flint','stick','string','feather','gunpowder','redstone','glowstone','diamond','emerald','sapphire','ruby','ingot','nugget','apple','bread','meat','fish','cookie','pumpkin_pie','mushroom_stew','bucket_of','egg','pearl','eye_of_ender','blaze_rod','slime_ball','magma_cream','golden','enchanted_book','name_tag','saddle','lead','carrier','armor','trim','smithing_template','record','disc','compass','clock','spyglass','book','writable_book','map','minecart','boat','firework','rocket','chorus_fruit','ender_pearl']),
 ('Entities & Mobs', ['entity','mob','monster','villager','zombie','skeleton','creeper','spider','enderman','cow','pig','sheep','chicken','horse','wolf','cat','rabbit','bear','panda','llama','camel','goat','axolotl','glow_squid','dolphin','squid','fish','salmon','cod','tropical_fish','pufferfish','bat','blaze','ghast','magma_cube','slime','witch','wither','ender_dragon','guardian','elder_guardian','shulker','silverfish','endermite','phantom','ravager','pillager','vindicator','evoker','illusioner','vex','stray','husk','drowned','zombified','piglin','hoglin','zoglin','strider','frog','tadpole','warden','allay','vex','boat','minecart','arrow','fireball','snowball','egg','ender_pearl','experience_bottle','item_frame','painting','armor_stand','player','npc']),
 ('Structures & Worldgen', ['structure','village','bastion','fortress','temple','pyramid','igloo','mansion','monument','outpost','ruin','shipwreck','mine','mineshaft','stronghold','endcity','nether','overworld','the_end','biome','plains','forest','desert','taiga','swamp','jungle','savanna','snowy','ocean','river','beach','cave','cliff','mountain','chunk','feature','tree','leaf','ore vein','archaeology','ruined_portal','geode','fossil','buried_treasure']),
 ('UI & Menus', ['menu','screen','gui','ui_','button','hud','title','inventory','crafting','enchanting','anvil','creative','pause','settings','options','toast','popup','widget','text','font','color','skin','main_menu','start_menu','loading',' chat','scoreboard','bossbar','book','sign','lectern','cartography','loom','smithing','stonecutter','grindstone','furnace','brewing','beacon']),
 ('Networking', ['packet','network','login','handshake','status','server','client','play_','message','chat','command','rank','permission','transfer','kick','disconnect','ping','raknet','session','profile','skin','textures','resource_pack','cookie','encrypt','auth']),
 ('Rendering & Audio', ['render','shader','texture','model','particle','sound','music','ambient','block_sound','item_sound','entity_sound','step','fmod','gui_sound','level_sound','weather_sound','record','noise','atlas','material','light','sky','fog','cloud','rain','snow']),
 ('Effects, Enchantments & Stats', ['effect','potion','enchant','enchantment','status','buff','debuff','poison','wither','regeneration','speed','strength','jump','fire_resistance','water_breathing','invisibility','levitation','slow_falling','statistic','achievement','advancement','recipe','loot','trade','experience','level','attribute','damage','armor','toughness','critical','knockback']),
 ('Commands & Events', ['command','event','trigger','tick','schedule','function','tag','objective','scoreboard','selector','execute','teleport','give','summon','setblock','fill','replace','gamerule','weather','time','difficulty','gamemode','advancement','bossbar','title','tellraw','effect','enchant','xp']),
]

def classify(s):
    n=s.lower()
    best,score='Other / Uncategorised',0
    parts=re.split(r'[:/_\-.]',n)
    for cat,kws in RULES:
        sc=0
        for k in kws:
            if k in parts: sc+=3
            elif k in n: sc+=1
        if sc>score: best,score=cat,sc
    return best

TERMS={
 'stone':'a primary underground solid block','dirt':'a common soil block','grass':'a grass-covered surface block',
 'sand':'a granular desert/beach block','gravel':'a gravity-affected granular block','log':'a tree trunk block',
 'planks':'a wooden building block','leaves':'a foliage block from trees','ore':'a mineral-bearing block',
 'glass':'a transparent building block','wool':'a colored soft block','bricks':'a masonry building block',
 'furnace':'a smelting station block','chest':'a storage container block','door':'an openable barrier block',
 'rail':'a minecart track block','torch':'a light-emitting block','bed':'a sleep/spawn-point block',
 'sword':'a melee weapon item','pickaxe':'a mining tool item','axe':'a woodcutting tool item',
 'shovel':'a digging tool item','hoe':'a farming tool item','helmet':'head armor item',
 'chestplate':'torso armor item','potion':'a consumable effect item','bucket':'a liquid container item',
 'spider':'an arthropod mob','zombie':'an undead hostile mob','creeper':'an exploding hostile mob',
 'villager':'a tradable NPC mob','pig':'a passive livestock mob','cow':'a passive livestock mob',
 'boat':'a water vehicle entity','minecart':'a rail vehicle entity','biome':'a worldgen climate region',
 'structure':'a generated structure feature','sound':'an audio event identifier','particle':'a visual effect identifier',
 'block':'a placeable world block','item':'an inventory item','entity':'a live world entity',
 'recipe':'a crafting recipe definition','loot':'a loot table definition','advancement':'a progression achievement',
 'enchantment':'an item enchantment definition','effect':'a status effect definition','command':'a server command',
 'screen':'a UI screen','packet':'a network packet type','texture':'a rendered texture asset',
}

def humanize(sid):
    name=sid.split(':',1)[-1]
    toks=[t for t in re.split(r'[_\-./]',name) if t]
    desc=[]
    for t in toks:
        if t in TERMS: desc.append(TERMS[t])
    if desc: return '; '.join(dict.fromkeys(desc))
    return 'Identifier-derived: '+ ' '.join(toks).replace('_',' ')

ids=[]
with open(os.path.join(SRC,'strings_mapped.tsv'),errors='replace') as f:
    next(f,None)
    for line in f:
        p=line.rstrip('\n').split('\t')
        if len(p)<4: continue
        off,va,sec,text=p[0],p[1],p[2],p[3]
        if 'minecraft:' not in text: continue
        for m in re.finditer(r'minecraft:[A-Za-z0-9_.\-/]+',text):
            sid=m.group(0)
            ids.append({'id':sid,'file_offset':int(off),'vaddr':int(va) if va.isdigit() else -1,
                        'section':sec,'category':classify(sid),'description':humanize(sid)})
ids.sort(key=lambda x:x['file_offset'])
print('identifiers',len(ids))

# link to decompiled code
idset={i['id'] for i in ids}
code_refs=collections.defaultdict(set)
if os.path.isdir(DEC):
    for root,_,files in os.walk(DEC):
        for fn in files:
            if not fn.endswith('.c'): continue
            path=os.path.join(root,fn)
            try: txt=open(path,errors='replace').read()
            except Exception: continue
            for m in re.finditer(r'minecraft:[A-Za-z0-9_.\-/]+',txt):
                code_refs[m.group(0)].add(fn)

with open(os.path.join(OUT,'minecraft_ids.tsv'),'w') as f:
    f.write('identifier\tcategory\tfile_offset\tvaddr\tsection\tdescription\tdecompiled_files\n')
    for i in ids:
        f.write('%s\t%s\t%d\t%d\t%s\t%s\t%s\n'%(i['id'],i['category'],i['file_offset'],i['vaddr'],
            i['section'],i['description'],','.join(sorted(code_refs.get(i['id'],[])))))

by=collections.defaultdict(list)
for i in ids: by[i['category']].append(i)
with open(os.path.join(OUT,'MINECRAFT_IDS.md'),'w') as f:
    f.write('# Every Minecraft identifier found in libminecraftpe.so\n\n')
    f.write('%d identifiers. Each row gives the exact file offset, virtual address, section,\n'%len(ids))
    f.write('inferred purpose and the decompiled file(s) that reference it. Identifiers are\n')
    f.write('mechanical observations; descriptions are inferred from the identifier tokens.\n\n')
    f.write('| Category | Count |\n|---|---:|\n')
    for c in sorted(by,key=lambda x:-len(by[x])): f.write('| %s | %d |\n'%(c,len(by[c])))
    f.write('\n')
    for c in sorted(by,key=lambda x:-len(by[x])):
        f.write('## %s\n\n'%c)
        f.write('| Identifier | File offset | VADDR | Section | Purpose | Code refs |\n|---|---:|---:|---|---|---|\n')
        for i in by[c]:
            f.write('| `%s` | %d | %d | %s | %s | %s |\n'%(i['id'],i['file_offset'],i['vaddr'],i['section'],
                i['description'].replace('|','/'),','.join(sorted(code_refs.get(i['id'],[]))[:4])))
        f.write('\n')

# modding reference: registry candidates from symbols, JNI entry points, vtable hook points
syms=[]
for line in open(os.path.join(SRC,'symbols_all.txt'),errors='replace'):
    m=re.match(r'\s*(\d+):\s+([0-9a-fA-F]+)\s+(\d+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\S+)\s+(.+)$',line.rstrip())
    if m:
        n,val,size,typ,bind,vis,ndx,name=m.groups()
        if ndx!='UND' and int(val,16): syms.append((int(val,16),int(size),typ,name))
import subprocess
raw=[s[3] for s in syms]
dem=subprocess.run(['c++filt'],input='\n'.join(raw)+'\n',text=True,capture_output=True).stdout.splitlines()
pat=re.compile(r'(Registry|register|Factory|create|Create|add|Add|remove|Remove|rename|Rename|serialize|deserialize|parse|load|save|bind|Bind|lookup|Lookup|find|Find)',re.I)
cands=[]
for (a,size,typ,name),d in zip(syms,dem):
    if pat.search(d) and (typ=='FUNC' or 'Registry' in d):
        cands.append((a,size,typ,name,d))
jni=[(a,size,name,d) for (a,size,typ,name),d in zip(syms,dem) if name.startswith('Java_com_mojang')]
with open(os.path.join(OUT,'REGISTRY_AND_MODDING.md'),'w') as f:
    f.write('# Registry, modding and reconstruction reference\n\n')
    f.write('## 1. What exists in the binary\n\n')
    f.write('- %d `minecraft:` identifiers (blocks, items, entities, sounds, structures, recipes, ...)\n'%len(ids))
    f.write('- %d recovered vtables / %d virtual methods for class reconstruction and hooking\n'%(
        json.load(open('/root/workspace/Minecraft, reverse engineer/results/reconstruction/structures_summary.json'))['vtables'],
        json.load(open('/root/workspace/Minecraft, reverse engineer/results/reconstruction/structures_summary.json'))['vtable_methods']))
    f.write('- %d RTTI typeinfo objects for class-name and inheritance recovery\n'%(
        json.load(open('/root/workspace/Minecraft, reverse engineer/results/reconstruction/structures_summary.json'))['typeinfos']))
    f.write('- %d candidate registry/factory/create/add/parse functions (below)\n'%len(cands))
    f.write('- %d JNI entry points into the native game (below)\n\n'%len(jni))
    f.write('## 2. Address -> meaning workflow\n\n')
    f.write('1. Find an identifier in `MINECRAFT_IDS.md`; note its file offset and VADDR.\n')
    f.write('2. Search `vtables.tsv` for a class whose methods reference nearby code.\n')
    f.write('3. Search `04_functions.tsv` / `decompiled_all/*.c` for the VADDR or identifier.\n')
    f.write('4. To change behaviour, patch the function at that VADDR or hook the vtable slot.\n\n')
    f.write('## 3. JNI entry points (native bridge)\n\n')
    f.write('| Address | Size | JNI symbol | Demangled |\n|---|---:|---|---|\n')
    for a,s,n,d in sorted(jni)[:400]: f.write('| `0x%x` | %d | `%s` | `%s` |\n'%(a,s,n,d))
    f.write('\n## 4. Registry / factory / parse functions\n\n')
    f.write('| Address | Size | Type | Symbol | Demangled signature |\n|---|---:|---|---|---|\n')
    for a,s,t,n,d in sorted(cands)[:4000]: f.write('| `0x%x` | %d | %s | `%s` | `%s` |\n'%(a,s,t,n,d))
    f.write('\n## 5. How to add / rename / modify content\n\n')
    f.write('- **Register a new block/item**: use an ID from `MINECRAFT_IDS.md` as a template;\n')
    f.write('  locate the matching registry/factory function in section 4 and its vtable in\n')
    f.write('  `CLASSES_AND_VTABLES.md`; patch or hook the create/register call.\n')
    f.write('- **Rename content**: the human-readable name is a `.rodata` string at the listed\n')
    f.write('  file offset; keep byte length <= original or patch the length field too.\n')
    f.write('- **Modify behaviour**: find the method by VADDR in `decompiled_all/` and patch\n')
    f.write('  the ARM64 instructions, or replace the vtable slot with your function.\n')
    f.write('- **Add new content**: copy an existing registry entry struct (block/item) and\n')
    f.write('  append a new entry using the same factory signature shown in section 4.\n\n')
    f.write('## 6. Stripped-name reconstruction\n\n')
    f.write('Symbols were largely stripped, but names were recovered from: dynamic symbol table,\n')
    f.write('RTTI `_ZTS`/`_ZTI` type names, `_ZTV` vtable symbols, relocation target names,\n')
    f.write('JNI exported symbols and decompiler-generated names. See `CLASSES_AND_VTABLES.md`,\n')
    f.write('`RTTI_HIERARCHY.md` and `04_functions.tsv`. Function bodies for %d functions are\n'%(
        sum(1 for _ in open(os.path.join(DEC,'part_000.c')) if _.startswith('// FUNCTION')) if os.path.exists(os.path.join(DEC,'part_000.c')) else 0))
    f.write('in `decompiled_all/`.\n')

json.dump({'identifiers':len(ids),'categories':{k:len(v) for k,v in by.items()},
           'code_linked':len(code_refs),'registry_candidates':len(cands),'jni':len(jni)},
          open(os.path.join(OUT,'ids_summary.json'),'w'),indent=2)
print('identifiers',len(ids),'linked',len(code_refs),'cands',len(cands),'jni',len(jni))
