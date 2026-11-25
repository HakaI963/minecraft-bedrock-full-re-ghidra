#!/usr/bin/env python3
import os,re,collections,json,bisect
D='/root/workspace/Minecraft, reverse engineer/results'; OUT=D+'/FINAL2'
lib=open('/root/workspace/Minecraft, reverse engineer/native/libminecraftpe.so','rb').read()
STR=D+'/extracted/elf-fasttrack/elf/strings_offsets.txt'
# comprehensive categories with keyword sets
CATS={
 'BLOCKS':['block','stone','dirt','grass','ore','log','plank','brick','slab','stair','fence','door','wall','glass','wool','concrete','terracotta','sand','gravel','obsidian','bedrock','portal','chest','furnace','anvil','hopper','rail','torch','bed','sign','banner','carpet','pressure_plate','button','lever','piston','tnt','crop','sapling','leaves','vine','kelp','coral','ice','snow','clay','mushroom','netherrack','sculk','copper','deepslate','amethyst','netherite'],
 'ITEMS':['item','sword','pickaxe','axe','shovel','hoe','helmet','chestplate','leggings','boots','elytra','shield','bow','arrow','trident','potion','bucket','flint','stick','string','feather','ingot','nugget','gem','apple','bread','meat','fish','cookie','egg','pearl','ender','blaze','slime','book','map','compass','clock','spyglass','minecart','boat','saddle','lead','record','disc','enchant','armor','tool','weapon','food'],
 'ENTITIES_MOBS':['entity','mob','actor','monster','villager','player','zombie','skeleton','creeper','spider','enderman','cow','pig','sheep','chicken','horse','wolf','cat','rabbit','bear','panda','llama','camel','goat','axolotl','squid','dolphin','fish','bat','blaze','ghast','slime','witch','wither','dragon','guardian','shulker','phantom','ravager','pillager','vindicator','evoker','vex','stray','husk','drowned','piglin','strider','frog','warden','allay','spawn','breed','tame','ai','goal','behavior','brain','navigation','pathfind'],
 'BIOMES_WORLDGEN':['biome','worldgen','dimension','overworld','nether','end','terrain','chunk','feature','structure','village','temple','mineshaft','stronghold','fortress','bastion','ruin','shipwreck','geode','cave','tree','forest','desert','taiga','swamp','jungle','savanna','ocean','river','beach','mountain','climate','temperature','rainfall','heightmap','noise','ore_vein'],
 'VEHICLES':['vehicle','boat','minecart','cart','ride','mount','saddle','steer','horse','camel','pig','strider','controller','movement','acceleration','speed','wheel','rail'],
 'ANIMATIONS':['animation','anim','controller','pose','bone','skeleton','keyframe','transition','state','clip','emote','dance','walk','run','idle','attack_anim','death_anim','spawn_anim'],
 'RENDERING_DRAW':['render','draw','line','vertex','mesh','texture','material','shader','camera','model','particle','light','fog','sky','cloud','shadow','frame','gpu','vulkan','gles','display','canvas','sprite','font','text','glyph','color','overlay','hud'],
 'AUDIO':['sound','audio','music','fmod','voice','sfx','ambient','step','impact','loop','pitch','volume','play_sound','level_sound','block_sound','item_sound','entity_sound','weather_sound'],
 'UI_MENUS':['ui','gui','screen','menu','widget','button','hud','tab','form','modal','window','panel','inventory_screen','crafting_screen','pause','settings','options','title','scoreboard','bossbar','toast','chat','text','font','label','slider','dropdown','toggle','textfield'],
 'RECIPES_CRAFTING':['recipe','craft','shaped','shapeless','furnace','brewing','smelting','blasting','smoking','campfire','stonecutter','loom','smithing','anvil','enchanting','ingredient','result','output','input'],
 'LOOT_ADVANCEMENTS':['loot','drop','advancement','achievement','statistic','reward','table','pool','entry','condition','function','trigger','criterion','experience','xp'],
 'EFFECTS_ENCHANTMENTS':['effect','potion','enchant','buff','debuff','status','poison','wither','regeneration','speed','strength','jump','fire_resistance','invisibility','levitation','slow_falling','night_vision','water_breathing','curse','vanishing','mending','sharpness','protection'],
 'COMMANDS_SCRIPTING':['command','script','javascript','scripting','event','trigger','bind','register','callback','listener','api','module','function','execute','teleport','give','summon','setblock','fill','gamerule','scoreboard','execute','tellraw'],
 'COMPONENTS_SCHEMAS':['component','schema','definition','deserialize','serialize','cereal','json','nbt','tag','property','attribute','field','value','descriptor','factory','builder','holder','instance','holder','componentregistry'],
 'NETWORKING':['packet','network','server','client','connection','login','handshake','status','raknet','session','message','chat','compression','encrypt','send','recv','sync','replication'],
 'STORAGE_DATA':['save','storage','database','file','leveldat','db','serialize','json','nbt','tag','region','chunk','persist','load','write','read','backup','world'],
 'PARTICLES':['particle','emitter','effect','smoke','flame','spark','explosion','trail','burst','sprite','billboard','texture','render'],
}
# load all strings with offsets
allstr=[]
for line in open(STR,errors='replace'):
    p=line.rstrip('\n').split(' ',1)
    if len(p)==2 and p[0].isdigit(): allstr.append((int(p[0]),p[1]))
print('strings',len(allstr))
def pat(off,n=40):
    return ' '.join('%02x'%x for x in lib[off:off+n])
# categorize
by=collections.defaultdict(list)
for off,s in allstr:
    sl=s.lower()
    for c,kws in CATS.items():
        score=sum(1 for k in kws if k in sl)
        if score>=2:
            by[c].append((off,s,score)); break
for c,items in by.items():
    fn=c+'.md'
    with open(os.path.join(OUT,'categories',fn),'w') as f:
        f.write('# %s — %d entries\n\n'%(c,len(items)))
        f.write('| Name | File offset | Byte pattern (40 bytes) | Score |\n|---|---:|---|---:|\n')
        for off,s,score in items:
            nm=s.replace('|','/').replace('\t',' ')[:180]
            f.write('| `%s` | 0x%x | `%s` | %d |\n'%(nm,off,pat(off),score))
    with open(os.path.join(OUT,'categories',c+'.tsv'),'w') as f:
        f.write('name\tfile_offset\tbyte_pattern\tscore\n')
        for off,s,score in items:
            f.write('%s\t0x%x\t%s\t%d\n'%(s.replace('\t',' ')[:200],off,pat(off),score))
json.dump({c:len(v) for c,v in by.items()},open(OUT+'/full_summary.json','w'),indent=2)
print('categories',len(by),'total entries',sum(len(v) for v in by.values()))
