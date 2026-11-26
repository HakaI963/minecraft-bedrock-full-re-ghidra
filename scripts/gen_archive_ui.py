#!/usr/bin/env python3
"""Archive format + JSON UI low-level analysis: offsets, byte patterns, API functions."""
import os,re,sys,collections,bisect,json,struct
BASE=sys.argv[1] if len(sys.argv)>1 else '.'
LIB=sys.argv[2] if len(sys.argv)>2 else 'work/libminecraftpe.so'
OUT=sys.argv[3] if len(sys.argv)>3 else 'out/FINAL'
os.makedirs(OUT+'/integration',exist_ok=True);os.makedirs(OUT+'/structures',exist_ok=True)
data=open(LIB,'rb').read()
STR=BASE+'/out/elf/strings_offsets.txt'
def pat(off,n=48):return ' '.join('%02x'%x for x in data[off:off+n])
# archive signatures
arch={}
for line in open(STR,errors='replace'):
 p=line.split(' ',1)
 if len(p)!=2 or not p[0].isdigit():continue
 s=p[1].lower();off=int(p[0])
 for k in ['mcpack','mcaddon','manifest.json','pack_icon','behavior_pack','resource_pack','packmanifest','zipfile','contentpack','compressed']:
  if k in s: arch.setdefault(k,[]).append((off,p[1].strip()[:100]))
with open(OUT+'/integration/ARCHIVE_FORMAT.md','w') as f:
 f.write('# Archive / pack format — low level\n\n')
 f.write('| API/key | String offset | Byte pattern | Example string |\n|---|---:|---|---|\n')
 for k,v in arch.items():
  for off,s in v[:20]: f.write('| %s | 0x%x | `%s` | `%s` |\n'%(k,off,pat(off),s.replace('|','/')))
 f.write('\n## ZIP local-file-header signature (PK\\x03\\x04)\n')
 f.write('Byte pattern: `50 4b 03 04` — standard ZIP entry header. Minecraft .mcpack/.mcaddon are ZIP files.\n')
 f.write('Central directory: `50 4b 01 02`; end-of-central-directory: `50 4b 05 06`.\n')
# UI: all UI-related strings + functions that reference them
ui=collections.defaultdict(list)
for line in open(STR,errors='replace'):
 p=line.split(' ',1)
 if len(p)!=2 or not p[0].isdigit():continue
 s=p[1].strip();off=int(p[0]);sl=s.lower()
 cat=None
 for k,c in [('main_menu','MAIN_MENU'),('startmenu','MAIN_MENU'),('settings','SETTINGS'),('inventory','INVENTORY'),('button','BUTTON'),('hud','HUD'),('screen','SCREEN'),('form','FORM'),('ui/','UI_ELEMENT'),('textures/ui','UI_TEXTURE'),('toast','TOAST'),('modal','MODAL'),('tab','TAB'),('widget','WIDGET'),('label','LABEL'),('slider','SLIDER')]:
  if k in sl: cat=c;break
 if cat: ui[cat].append((off,s[:120]))
with open(OUT+'/integration/JSON_UI_FULL.md','w') as f:
 f.write('# JSON UI — all screens, buttons, inventory, HUD with offsets + byte patterns\n\n')
 f.write('| Category | Count |\n|---|---:|\n')
 for c,v in sorted(ui.items()): f.write('| %s | %d |\n'%(c,len(v)))
 f.write('\n')
 for c,v in sorted(ui.items()):
  f.write('## %s\n\n| String | File offset | Byte pattern |\n|---|---:|---|\n'%(c))
  for off,s in v[:2000]:
   f.write('| `%s` | 0x%x | `%s` |\n'%(s.replace('|','/'),off,pat(off)))
  if len(v)>2000:f.write('\n_Showing 2000 of %d; full data in STRINGS_UI.tsv._\n'%len(v))
  f.write('\n')
with open(OUT+'/integration/STRINGS_UI.tsv','w') as f:
 f.write('category\tstring\tfile_offset\tbyte_pattern\n')
 for c,v in ui.items():
  for off,s in v: f.write('%s\t%s\t0x%x\t%s\n'%(c,s.replace('\t',' '),off,pat(off)))
# xrefs: functions referencing UI strings
targets={off:c for c,v in ui.items() for off,s in v}
p=BASE+'/per_function/DISASSEMBLY_FULL.asm.zst'
if os.path.exists(p):
 import zstandard
 adrp=re.compile(r'^([0-9a-f]+)\s+adrp\s+(x\d+),\s*([0-9a-f]+)')
 add=re.compile(r'^([0-9a-f]+)\s+add\s+(x\d+),\s*(x\d+),\s*#(?:0x)?([0-9a-f]+)')
 regs={};sites=collections.defaultdict(set)
 with open(p,'rb') as fh:
  dec=zstandard.ZstdDecompressor().stream_reader(fh)
  while True:
   ch=dec.read(8*1024*1024)
   if not ch:break
   for raw in ch.decode('utf-8','replace').split('\n'):
    s=raw.strip();m=adrp.match(s)
    if m: regs[m.group(2)]=int(m.group(3),16);continue
    m=add.match(s)
    if m and m.group(3) in regs:
     t=regs[m.group(3)]+int(m.group(4),16)
     if t in targets: sites[int(m.group(1),16)].add(targets[t])
 addrs=[int(l.split('\t')[0],16) for l in open(OUT+'/structures/ALL_FUNCTION_ENTRIES.txt')]
 addrs.sort()
 fd=collections.defaultdict(set)
 for site,cs in sites.items():
  i=bisect.bisect_right(addrs,site)-1
  if i>=0:
   for c in cs:fd[addrs[i]].add(c)
 with open(OUT+'/integration/UI_FUNCTION_XREFS.tsv','w') as f:
  f.write('function_address\tcategory\tbyte_pattern\n')
  for fc,cs in sorted(fd.items()):
   bp=' '.join('%02x'%x for x in data[fc:fc+48])
   for c in cs:f.write('0x%x\t%s\t%s\n'%(fc,c,bp))
print('archive keys',len(arch),'ui categories',len(ui),'ui funcs',len(fd) if targets else 0)
