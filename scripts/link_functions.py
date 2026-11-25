#!/usr/bin/env python3
import zstandard,re,bisect,collections,json,os
D='/root/workspace/Minecraft, reverse engineer/results'; OUT=D+'/FINAL2'
# load categorized string offsets
cat_of={}
for fn in os.listdir(OUT+'/categories'):
    if not fn.endswith('.tsv'): continue
    c=fn[:-4]
    for line in open(os.path.join(OUT,'categories',fn),errors='replace'):
        p=line.split('\t')
        if len(p)>=2 and p[1].startswith('0x'):
            cat_of[int(p[1],16)]=c
print('mapped string offsets',len(cat_of))
# scan disassembly for adrp+add to those strings
p=D+'/per_function/DISASSEMBLY_FULL.asm.zst'
adrp=re.compile(r'^([0-9a-f]+)\s+adrp\s+(x\d+),\s*([0-9a-f]+)')
add=re.compile(r'^([0-9a-f]+)\s+add\s+(x\d+),\s*(x\d+),\s*#(?:0x)?([0-9a-f]+)')
regs={}; site_cat=collections.defaultdict(set); n=0
with open(p,'rb') as fh:
 dec=zstandard.ZstdDecompressor().stream_reader(fh)
 while True:
  c=dec.read(8*1024*1024)
  if not c:break
  for raw in c.decode('utf-8','replace').split('\n'):
   n+=1;s=raw.strip();m=adrp.match(s)
   if m: regs[m.group(2)]=int(m.group(3),16);continue
   m=add.match(s)
   if m and m.group(3) in regs:
    t=regs[m.group(3)]+int(m.group(4),16)
    if t in cat_of:
     site_cat[int(m.group(1),16)].add(cat_of[t])
  if n%15000000<1000000: print('scan',n,'linked sites',len(site_cat),flush=True)
print('scan done',n,'linked sites',len(site_cat))
# map sites to functions
addrs=[int(l.split('\t')[0],16) for l in open(D+'/reconstruction/ALL_FUNCTION_ENTRIES.txt')]
pats={}
for l in open(D+'/reconstruction/ALL_FUNCTION_PATTERNS_V2.tsv'):
 q=l.split('\t'); pats[q[0]]=q[1]
func_cat=collections.defaultdict(set)
for site,cats in site_cat.items():
 i=bisect.bisect_right(addrs,site)-1
 if i>=0:
  f=addrs[i]
  for c in cats: func_cat[f].add(c)
print('functions with categories',len(func_cat))
with open(OUT+'/INTEGRATION_FUNCTIONS.tsv','w') as f:
 f.write('function_address\tcategory\tbyte_pattern\n')
 for fc,cats in sorted(func_cat.items()):
  for c in sorted(cats):
   f.write('0x%x\t%s\t%s\n'%(fc,c,pats.get('0x%x'%fc,'')[:400]))
json.dump({'linked_sites':len(site_cat),'functions':len(func_cat)},open(OUT+'/link_summary.json','w'),indent=2)
