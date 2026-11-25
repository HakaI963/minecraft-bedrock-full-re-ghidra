#!/usr/bin/env python3
D='/root/workspace/Minecraft, reverse engineer/results'; OUT=D+'/FINAL'
lib=open('/root/workspace/Minecraft, reverse engineer/native/libminecraftpe.so','rb').read()
import os,json
ENT=D+'/reconstruction/ALL_FUNCTION_ENTRIES.txt'
PAT=D+'/reconstruction/ALL_FUNCTION_PATTERNS_V2.tsv'
pats={}
for l in open(PAT):
 p=l.split('\t');pats[p[0]]=p[1]
import bisect
addrs=[int(l.split('\t')[0],16) for l in open(ENT)]
funcs=[
 (0x1017be30,'SET_ATTACK_DAMAGE','Sets attack damage on an entity component; references minecraft:attack_damage (0x26E48B1)'),
 (0x1017be8c,'SET_FOLLOW_RANGE','Sets follow range; references minecraft:follow_range (0x2690C7B)'),
 (0x1017bf44,'SET_ATTACK_DAMAGE_2','Second attack damage setter variant'),
 (0x1017bfa0,'SET_FOLLOW_RANGE_2','Second follow range setter variant'),
 (0x1017bffc,'SET_HEALTH','Sets health; references minecraft:health (0x24C5305)'),
 (0x1017c1c8,'SET_HEALTH_2','Second health setter variant'),
 (0x1018e750,'MOB_COMPONENT_PROXY','Mob component proxy: health, attack damage, follow range'),
 (0x133a430c,'MOB_DEFINITION_LOADER','Mob definition loader: health, attack, follow range'),
 (0xe31878c,'HEALTH_QUERY','Script health query handler (minecraft:health)'),
 (0xe32d340,'ENTITY_HEALTH_COMPONENT','EntityHealthComponent type handler'),
 (0xfdfb0f8,'HEALTH_COMPONENT_INIT','Health component initializer'),
 (0xfdfecfc,'HEALTH_COMPONENT_INIT2','Health component initializer variant'),
 (0xff9dc00,'MAX_HEALTH_QUERY','query.max_health handler'),
]
with open(OUT+'/hooks/MOBS_AND_COMPONENTS.md','w') as f:
 f.write('# Mob / entity components - verified xrefs and byte patterns\n\n')
 f.write('| Name | Function address | File offset | Byte pattern | Evidence |\n|---|---:|---:|---|---|\n')
 for a,n,d in funcs:
  f.write('| %s | `0x%x` | `0x%x` | `%s` | %s |\n'%(n,a,a,pats.get('0x%x'%a,'')[:230],d))
 f.write('\n## Component data string offsets\n\n')
 f.write('| Property | File offset | VADDR | Byte pattern (string bytes) |\n|---|---:|---:|---|\n')
 for name,off in [('minecraft:health',38584365),('minecraft:attack_damage',40800743),('minecraft:follow_range',40415243),('query.max_health',40544493),('EntityHealthComponent',41031917)]:
  f.write('| %s | 0x%x | 0x%x | `%s` |\n'%(name,off,off,' '.join('%02x'%x for x in lib[off:off+min(32,len(name))])))
 f.write('\n## Field offsets observed in setters\n')
 f.write('The setter functions use `strb`/`str` instructions with immediate field offsets.\n')
 f.write('Disassemble each function address above to read the exact field offset from the\n')
 f.write('`str` instruction (e.g. `strb w1,[x0,#320]` in SET_CREATIVE_CATEGORY).\n')
print('mob db written')
