#!/usr/bin/env python3
import os,re,collections,json,csv
D='/root/workspace/Minecraft, reverse engineer/results'; OUT=D+'/FINAL3'
lib=open('/root/workspace/Minecraft, reverse engineer/native/libminecraftpe.so','rb').read()
STR=D+'/extracted/elf-fasttrack/elf/strings_offsets.txt'
# expanded 30 categories
CATS={
 'BLOCKS':['block','stone','dirt','grass','ore','log','plank','brick','slab','stair','fence','door','wall','glass','wool','concrete','terracotta','sand','gravel','obsidian','bedrock','portal','chest','furnace','anvil','hopper','rail','torch','bed','sign','banner','carpet','pressure_plate','button','lever','piston','tnt','crop','sapling','leaves','vine','kelp','coral','ice','snow','clay','mushroom','netherrack','sculk','copper','deepslate','amethyst','netherite','blockstate','block_entity','blockentity'],
 'ITEMS':['item','sword','pickaxe','axe','shovel','hoe','helmet','chestplate','leggings','boots','elytra','shield','bow','arrow','trident','potion','bucket','flint','stick','string','feather','ingot','nugget','gem','apple','bread','meat','fish','cookie','egg','pearl','ender','blaze','slime','book','map','compass','clock','spyglass','minecart','boat','saddle','lead','record','disc','enchant','armor','tool','weapon','food','itemstack','item_definition'],
 'ENTITIES_MOBS':['entity','mob','actor','monster','villager','player','zombie','skeleton','creeper','spider','enderman','cow','pig','sheep','chicken','horse','wolf','cat','rabbit','bear','panda','llama','camel','goat','axolotl','squid','dolphin','fish','bat','blaze','ghast','slime','witch','wither','dragon','guardian','shulker','phantom','ravager','pillager','vindicator','evoker','vex','stray','husk','drowned','piglin','strider','frog','warden','allay','spawn','breed','tame','ai','goal','behavior','brain','navigation','pathfind','mob_effect','entity_definition'],
 'BIOMES_WORLDGEN':['biome','worldgen','dimension','overworld','nether','end','terrain','chunk','feature','structure','village','temple','mineshaft','stronghold','fortress','bastion','ruin','shipwreck','geode','cave','tree','forest','desert','taiga','swamp','jungle','savanna','ocean','river','beach','mountain','climate','temperature','rainfall','heightmap','noise','ore_vein','worldgen','generator'],
 'VEHICLES':['vehicle','boat','minecart','cart','ride','mount','saddle','steer','horse','camel','pig','strider','controller','movement','acceleration','speed','wheel','rail','vehicle_definition'],
 'ANIMATIONS':['animation','anim','controller','pose','bone','skeleton','keyframe','transition','state','clip','emote','dance','walk','run','idle','attack_anim','death_anim','spawn_anim','animation_controller','molang'],
 'RENDERING_DRAW':['render','draw','line','vertex','mesh','texture','material','shader','camera','model','particle','light','fog','sky','cloud','shadow','frame','gpu','vulkan','gles','display','canvas','sprite','font','text','glyph','color','overlay','hud','geometry','primitive','quad','triangle','batch'],
 'AUDIO':['sound','audio','music','fmod','voice','sfx','ambient','step','impact','loop','pitch','volume','play_sound','level_sound','block_sound','item_sound','entity_sound','weather_sound','sound_definition','sound_event'],
 'UI_MENUS':['ui','gui','screen','menu','widget','button','hud','tab','form','modal','window','panel','inventory_screen','crafting_screen','pause','settings','options','title','scoreboard','bossbar','toast','chat','text','font','label','slider','dropdown','toggle','textfield','ui_definition','screen_handler'],
 'RECIPES_CRAFTING':['recipe','craft','shaped','shapeless','furnace','brewing','smelting','blasting','smoking','campfire','stonecutter','loom','smithing','anvil','enchanting','ingredient','result','output','input','recipe_definition'],
 'LOOT_ADVANCEMENTS':['loot','drop','advancement','achievement','statistic','reward','table','pool','entry','condition','function','trigger','criterion','experience','xp','loot_table'],
 'EFFECTS_ENCHANTMENTS':['effect','potion','enchant','buff','debuff','status','poison','wither','regeneration','speed','strength','jump','fire_resistance','invisibility','levitation','slow_falling','night_vision','water_breathing','curse','vanishing','mending','sharpness','protection','effect_definition'],
 'COMMANDS_SCRIPTING':['command','script','javascript','scripting','event','trigger','bind','register','callback','listener','api','module','execute','teleport','give','summon','setblock','fill','gamerule','scoreboard','tellraw','script_api','weak_typed_object_handle'],
 'COMPONENTS_SCHEMAS':['component','schema','definition','deserialize','serialize','cereal','json','nbt','tag','property','attribute','field','value','descriptor','factory','builder','holder','instance','componentregistry','component_group'],
 'NETWORKING':['packet','network','server','client','connection','login','handshake','status','raknet','session','message','chat','compression','encrypt','send','recv','sync','replication','packet_id','networkid'],
 'STORAGE_DATA':['save','storage','database','file','leveldat','db','nbt','tag','region','chunk','persist','load','write','read','backup','world','file_format'],
 'PARTICLES':['particle','emitter','effect','smoke','flame','spark','explosion','trail','burst','sprite','billboard','particle_definition','particle_effect'],
 'REDSTONE_MECHANISMS':['redstone','circuit','piston','dispenser','dropper','hopper','observer','comparator','repeater','daylight','sensor','lever','button','pressure_plate','command_block','structure_block','barrier','movingblock','pistonarmcollision'],
 'FLUIDS_WEATHER':['water','lava','fluid','flow','liquid','bucket','weather','rain','snow','storm','thunder','lightning','fog','temperature','freeze','melt','hydration'],
 'PHYSICS_COLLISION':['physics','collision','aabb','bounding','box','raycast','ray','hitbox','gravity','velocity','motion','friction','bounce','collide','solid','push','entity_collision'],
 'DAMAGE_COMBAT':['damage','attack','health','hurt','heal','death','kill','combat','weapon','armor','protection','knockback','critical','projectile','arrow','explosion','fire','fall','drown','suffocate','damage_type','damage_source'],
 'TRADING_ECONOMY':['trade','villager','merchant','price','currency','emerald','buy','sell','offer','recipe','barter','piglin','trading','economy','discount','reputation'],
 'FARMING_PLANTS':['farm','crop','wheat','carrot','potato','beetroot','melon','pumpkin','sugarcane','bamboo','cactus','sapling','tree','leaf','seed','grow','harvest','plant','soil','farmland','compost','beehive','honey'],
 'STRUCTURES_BUILDING':['structure','build','blueprint','template','schematic','placement','rotation','mirror','integrity','piston','blockentity','structure_block','structure_void','jigsaw','pool','element'],
 'SECURITY_DRM':['pairip','license','auth','crypto','sign','verify','checksum','anti','tamper','integrity','obfusc','protect','encryption','secure','token','certificate'],
 'TELEMETRY_ANALYTICS':['telemetry','analytics','event','metric','log','crash','error','report','track','measure','count','stat','diagnostic','profiler','performance'],
 'MULTIPLAYER_XBOX':['multiplayer','xbox','xal','live','gamertag','friend','party','lobby','session','match','coop','server','realm','marketplace','skin','avatar','privilege','permission','rank'],
 'ASSETS_PACKAGING':['asset','texture','model','geometry','attachable','render_controller','animation','sound','music','font','language','pack','resource_pack','behavior_pack','manifest','definition','identifier'],
 'EDUCATION':['education','edu','classroom','lesson','experiment','chemistry','compound','element','lab','student','teacher','cookie','blocked'],
 'MISC_OTHER':['data','value','type','name','id','key','entry','list','vector','map','set','string','buffer','pointer','index','size','count','offset','handle','ref','ptr','flags','mode','state','status','result'],
}
allstr=[]
for line in open(STR,errors='replace'):
    p=line.rstrip('\n').split(' ',1)
    if len(p)==2 and p[0].isdigit(): allstr.append((int(p[0]),p[1]))
print('strings',len(allstr))
def pat(off,n=40): return ' '.join('%02x'%x for x in lib[off:off+n])
by=collections.defaultdict(list)
for off,s in allstr:
    sl=s.lower()
    best=None;bs=0
    for c,kws in CATS.items():
        sc=sum(1 for k in kws if k in sl)
        if sc>bs: bs=sc;best=c
    if bs>=1: by[best].append((off,s,bs))
for c,items in by.items():
    with open(os.path.join(OUT,'categories',c+'.md'),'w') as f:
        f.write('# %s — %d entries\n\n'%(c,len(items)))
        f.write('| Name | File offset | Byte pattern (40 bytes) | Score |\n|---|---:|---|---:|\n')
        for off,s,sc in items:
            f.write('| `%s` | 0x%x | `%s` | %d |\n'%(s.replace('|','/').replace('\t',' ')[:180],off,pat(off),sc))
    with open(os.path.join(OUT,'categories',c+'.tsv'),'w') as f:
        f.write('name\tfile_offset\tbyte_pattern\tscore\n')
        for off,s,sc in items: f.write('%s\t0x%x\t%s\t%d\n'%(s.replace('\t',' ')[:200],off,pat(off),sc))
json.dump({c:len(v) for c,v in by.items()},open(OUT+'/expanded_summary.json','w'),indent=2)
print('categories',len(by),'entries',sum(len(v) for v in by.values()))
