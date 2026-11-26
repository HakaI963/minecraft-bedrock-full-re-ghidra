#!/usr/bin/env python3
"""Pure-Python ARM64 relationship extraction: decode BL/ADR/ADD, build call graph.
No objdump, no Ghidra - works on any host."""
import os,re,sys,struct,collections,json
LIB=sys.argv[1]; OUT=sys.argv[2]
REL=os.path.join(OUT,'relationships'); os.makedirs(REL,exist_ok=True)
data=open(LIB,'rb').read()
print('lib bytes',len(data))
# ---- parse section headers to find .text range ----
e_shoff=struct.unpack_from('<Q',data,0x28)[0]
e_shentsize=struct.unpack_from('<H',data,0x3a)[0]
e_shnum=struct.unpack_from('<H',data,0x3c)[0]
e_shstrndx=struct.unpack_from('<H',data,0x3e)[0]
def sh(i):
    o=e_shoff+i*e_shentsize
    return dict(name=struct.unpack_from('<I',data,o)[0],
                type=struct.unpack_from('<I',data,o+4)[0],
                addr=struct.unpack_from('<Q',data,o+16)[0],
                off=struct.unpack_from('<Q',data,o+24)[0],
                size=struct.unpack_from('<Q',data,o+32)[0])
shstr=sh(e_shstrndx)
def nm(n):
    p=shstr['off']+n; e=data.index(b'\0',p); return data[p:e].decode()
secs={nm(sh(i)['name']):sh(i) for i in range(e_shnum)}
text=secs.get('.text'); print('text',hex(text['addr']),hex(text['off']),hex(text['size']))
# ---- functions from readelf symbols (parse locally) ----
funcs={}
import subprocess
out=subprocess.run(['readelf','-sW',LIB],capture_output=True,text=True).stdout
for line in out.splitlines():
    m=re.match(r'\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+FUNC\s+\w+\s+\w+\s+\S+\s+(.+)',line)
    if m:
        a=int(m.group(1),16)
        if a: funcs[a]=(m.group(3).strip(),int(m.group(2)))
print('funcs',len(funcs))
# ---- decode BL instructions in .text ----
base_addr=text['addr']; base_off=text['off']; size=text['size']
bl=collections.defaultdict(set); callers=collections.defaultdict(set)
bl_rows=[]
mv=data[base_off:base_off+size]
for i in range(0,len(mv)-3,4):
    w=struct.unpack_from('<I',mv,i)[0]
    # BL: 100101 imm26
    if (w & 0xFC000000)==0x94000000:
        imm=w & 0x03FFFFFF
        if imm & 0x02000000: imm-=0x04000000
        site=base_addr+i
        tgt=site+imm*4
        bl[site].add(tgt); callers[tgt].add(site)
        bl_rows.append((site,tgt))
print('BL sites',len(bl_rows),'unique targets',len(callers))
# ---- decode ADRP+ADD pairs -> absolute data addresses (string xrefs) ----
adrp={}
strref=[]
for i in range(0,len(mv)-3,4):
    w=struct.unpack_from('<I',mv,i)[0]
    rd=w & 0x1F
    # ADRP: 1xx10000 immlo immhi Rd
    if (w & 0x9F000000)==0x90000000:
        immlo=(w>>29)&3; immhi=(w>>5)&0x7FFFF
        imm=(immhi<<2)|immlo
        if imm & (1<<20): imm-=1<<21
        page=(base_addr+i)&~0xFFF
        adrp[rd]=page+(imm<<12)
        continue
    # ADD (immediate, 64-bit): 100100010x imm12 Rn Rd
    if (w & 0x7F800000)==0x11000000:
        rn=(w>>5)&0x1F; imm12=(w>>10)&0xFFF; sh=(w>>22)&1
        if rn in adrp:
            val=adrp[rn]+(imm12<<(12 if sh else 0))
            if val: strref.append((base_addr+i,val))
print('strref sites',len(strref))
# ---- write outputs ----
pat=lambda a,n=16:' '.join('%02x'%x for x in data[a:a+n])
with open(REL+'/CALL_GRAPH.tsv','w') as f:
    f.write('site_address\tcallee_address\tcallee_name\tcallee_size\tbyte_pattern\n')
    for site,tgt in bl_rows:
        n,s=funcs.get(tgt,('',0))
        f.write('0x%x\t0x%x\t%s\t%d\t%s\n'%(site,tgt,n,s,pat(site)))
with open(REL+'/CALLEES_BY_FUNCTION.tsv','w') as f:
    f.write('function_address\tfunction_name\tcallee_address\tcallee_name\tcall_site_byte_pattern\n')
    for tgt,sites in callers.items():
        n=funcs.get(tgt,('',0))[0]
        for s in sorted(sites):
            cn=funcs.get(tgt,('',''))[0]
            f.write('0x%x\t%s\t0x%x\t%s\t%s\n'%(tgt,n,tgt,cn,pat(s)))
with open(REL+'/STRING_XREFS.tsv','w') as f:
    f.write('site_address\ttarget_address\tbyte_pattern\n')
    for s,t in strref:
        f.write('0x%x\t0x%x\t%s\n'%(s,t,pat(s)))
# CTOR/DTOR
with open(REL+'/CTOR_DTOR.tsv','w') as f:
    f.write('address\tkind\tname\tsize\tcaller_count\tbyte_pattern\n')
    for a,(n,s) in funcs.items():
        if re.search(r'C[12]E|D[012]E',n):
            kind='ctor' if re.search(r'C[12]E',n) else 'dtor'
            f.write('0x%x\t%s\t%s\t%d\t%d\t%s\n'%(a,kind,n,s,len(callers.get(a,())),pat(a,8)))
json.dump({'bl_sites':len(bl_rows),'unique_callees':len(callers),
           'strref_sites':len(strref),'funcs':len(funcs)},
          open(REL+'/SUMMARY.json','w'),indent=2)
print('DONE')
