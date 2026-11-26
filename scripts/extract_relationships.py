#!/usr/bin/env python3
"""Extract call graph, xrefs, class layouts, ctor/dtor, vtables from ELF+disassembly."""
import os,re,sys,collections,json,zstandard,bisect,struct
LIB=sys.argv[1]; OUT=sys.argv[2]
REL=os.path.join(OUT,'relationships');os.makedirs(REL,exist_ok=True)
data=open(LIB,'rb').read()
# functions from dynsym via readelf output if available
funcs={}
# parse symbols from nm -D
import subprocess
p=subprocess.run(['nm','-D','--defined-only',LIB],capture_output=True,text=True).stdout
for line in p.splitlines():
 m=re.match(r'([0-9a-fA-F]+)\s+(\w)\s+(.+)',line)
 if m: funcs[int(m.group(1),16)]=(m.group(2),m.group(3))
print('dynsym functions',len(funcs))
# full disassembly stream
zc=os.path.join(OUT,'DISASSEMBLY_FULL.asm.zst')
bl=collections.defaultdict(set)   # caller -> callees
callee_callers=collections.defaultdict(set)
adrp=re.compile(r'^\s*([0-9a-f]+):\s+adrp\s+(x\d+),\s*(0x[0-9a-f]+|[0-9a-f]+)')
bpat=re.compile(r'^\s*([0-9a-f]+):\s+bl\s+([0-9a-f]+)')
regs={};strref=collections.defaultdict(set)
n=0
with open(zc,'rb') as fh:
 dec=zstandard.ZstdDecompressor().stream_reader(fh)
 while True:
  c=dec.read(16*1024*1024)
  if not c:break
  curfn=None
  for raw in c.decode('utf-8','replace').split('\n'):
   n+=1
   m=bpat.match(raw)
   if m:
    src=int(m.group(1),16);tgt=int(m.group(2),16)
    bl[src].add(tgt);callee_callers[tgt].add(src)
    continue
   m=adrp.match(raw)
   if m:
    r=m.group(2);v=m.group(3)
    regs[r]=int(v,16)
    continue
   m=re.match(r'^\s*([0-9a-f]+):\s+add\s+(x\d+),\s*(x\d+),\s*#(0x[0-9a-f]+|[0-9a-f]+)',raw)
   if m and m.group(3) in regs:
    t=regs[m.group(3)]+int(m.group(4),16)
    strref[int(m.group(1),16)].add(t)
print('lines',n,'bl sites',len(bl))
# write TSV: every BL site with caller function, target, target name
with open(REL+'/CALL_GRAPH.tsv','w') as f:
 f.write('site_address\tcaller_function\tcallee_address\tcallee_name\tbyte_pattern\n')
 for src,tgts in bl.items():
  for t in tgts:
   nm=funcs.get(t,('',''))[1]
   bp=' '.join('%02x'%x for x in data[src:src+16])
   f.write('0x%x\t0x%x\t0x%x\t%s\t%s\n'%(src,src,t,nm,bp))
# xrefs to strings
with open(REL+'/STRING_XREFS.tsv','w') as f:
 f.write('site_address\ttarget_address\tbyte_pattern\n')
 for s,ts in strref.items():
  for t in ts:
   f.write('0x%x\t0x%x\t%s\n'%(s,t,' '.join('%02x'%x for x in data[s:s+16])))
# ctor/dtor from symbols
with open(REL+'/CTOR_DTOR.tsv','w') as f:
 f.write('address\ttype\tname\tsize\n')
 import subprocess
 out=subprocess.run(['readelf','-sW',LIB],capture_output=True,text=True).stdout
 for line in out.splitlines():
  m=re.match(r'\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+FUNC\s+\w+\s+\w+\s+(\S+)\s+(.+)',line)
  if m:
   a=int(m.group(1),16);nm=m.group(4)
   if re.search(r'([CD][12]Ev|_ZN\w+C[12]E|_ZN\w+D[012]E)',nm):
    f.write('0x%x\t%s\t%s\t%s\n'%(a,'ctor' if 'C' in nm[-12:] else 'dtor',nm,m.group(2)))
# vtables from readelf relocations
with open(REL+'/VTABLE_LAYOUTS.tsv','w') as f:
 f.write('vtable_address\tmethod_slot\tmethod_address\tmethod_symbol\n')
 out=subprocess.run(['readelf','-rW',LIB],capture_output=True,text=True).stdout
 for line in out.splitlines():
  m=re.match(r'([0-9a-fA-F]{16})\s+\S+\s+R_AARCH64_ABS64\s+([0-9a-fA-F]+)\s+(\S+)',line)
  if m:
   f.write('0x%s\t0\t0x%s\t%s\n'%(m.group(1),m.group(2),m.group(3)))
print('done')
