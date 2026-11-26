#!/usr/bin/env python3
"""Generate proper masked ARM64 byte patterns: branch/call operands wildcarded."""
import os,re,sys,collections
BASE=sys.argv[1] if len(sys.argv)>1 else '.'
LIB=sys.argv[2] if len(sys.argv)>2 else 'work/libminecraftpe.so'
OUT=sys.argv[3] if len(sys.argv)>3 else 'out/reconstruction'
os.makedirs(OUT,exist_ok=True)
data=open(LIB,'rb').read()
funcs=[]
for line in open(BASE+'/out/ghidra/04_functions.tsv',errors='replace'):
 p=line.rstrip('\n').split('\t')
 if len(p)>=3 and re.fullmatch(r'[0-9a-fA-F]+',p[0]): funcs.append((int(p[0],16),p[1],p[2]))
funcs.sort()
# decode ARM64 instructions: mask branches (bits 31-24 opcode), keep others
def sig(a,n=16):
 out=[]
 for i in range(a,a+4*n,4):
  if i+4>len(data): break
  w=int.from_bytes(data[i:i+4],'little')
  op=(w>>24)&0xfc
  # branch (b/bl) op 0x14/0x94 in top 6 bits: 0b000101 / 0b100101
  if (w & 0xfc000000) in (0x14000000,0x94000000):
   out.append('?? ?? ?? ??')
  elif (w & 0xff000010)==0x54000000 or (w & 0x7f000000)==0x34000000 or (w & 0x7f000000)==0x36000000:
   out.append('?? ?? ?? ??')
  else:
   out.append(' '.join('%02x'%x for x in data[i:i+4]))
 return ' '.join(out)
cnt=collections.Counter(); rows=[]
for a,n,s in funcs:
 z=sig(a);cnt[z]+=1;rows.append((a,n,z))
with open(OUT+'/FUNCTION_SIGNATURES_MASKED.tsv','w') as f:
 f.write('address\tname\tbyte_pattern\tunique\n')
 for a,n,z in rows: f.write('0x%x\t%s\t%s\t%s\n'%(a,n,z,'Y' if cnt[z]==1 else 'N'))
print('functions',len(rows),'unique masked patterns',sum(1 for v in cnt.values() if v==1))
