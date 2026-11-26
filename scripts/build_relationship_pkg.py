#!/usr/bin/env python3
"""Build relationship package: resolve names, make .md/.tsv/.docx spider-web linkage."""
import os,re,sys,struct,collections,json,subprocess,bisect
LIB=sys.argv[1]; OUT=sys.argv[2]; MASTER=sys.argv[3] if len(sys.argv)>3 else ''
REL=os.path.join(OUT,'relationships'); os.makedirs(REL,exist_ok=True)
data=open(LIB,'rb').read()
# --- name resolution: dynsym + master table + nearest ---
names={}; sizes={}
out=subprocess.run(['readelf','-sW',LIB],capture_output=True,text=True).stdout
for line in out.splitlines():
    m=re.match(r'\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+FUNC\s+\w+\s+\w+\s+\S+\s+(.+)',line)
    if m:
        a=int(m.group(1),16)
        if a: names[a]=m.group(3).strip(); sizes[a]=int(m.group(2))
if MASTER and os.path.exists(MASTER):
    for line in open(MASTER,errors='replace'):
        p=line.rstrip('\n').split('\t')
        if len(p)>=5 and p[0].startswith('0x'):
            try:
                a=int(p[0],16)
                if a not in names: names[a]=p[3]
            except: pass
print('names',len(names))
# batch demangle once (fast)
keys=sorted(names)
uniq=sorted(set(names.values()))
DM={}
if uniq:
    try:
        r=subprocess.run(['c++filt'],input='\n'.join(uniq)+'\n',text=True,capture_output=True).stdout
        lines=r.splitlines()
        for i,n in enumerate(uniq):
            DM[n]=lines[i] if i<len(lines) else n
    except: pass
def dmg(n): return DM.get(n,n)
def resolve(a):
    if a in names: return names[a]
    i=bisect.bisect_right(keys,a)-1
    if i>=0 and a-keys[i]<0x400: return names[keys[i]]+'+%d'%(a-keys[i])
    return ''
# --- section/state ---
e_shoff=struct.unpack_from('<Q',data,0x28)[0]; e_shentsize=struct.unpack_from('<H',data,0x3a)[0]
e_shnum=struct.unpack_from('<H',data,0x3c)[0]; e_shstrndx=struct.unpack_from('<H',data,0x3e)[0]
def sh(i):
    o=e_shoff+i*e_shentsize
    return dict(n=struct.unpack_from('<I',data,o)[0],addr=struct.unpack_from('<Q',data,o+16)[0],
                off=struct.unpack_from('<Q',data,o+24)[0],size=struct.unpack_from('<Q',data,o+32)[0])
shstr=sh(e_shstrndx)
def nmz(n):
    p=shstr['off']+n; e=data.index(b'\0',p); return data[p:e].decode()
secs={nmz(sh(i)['n']):sh(i) for i in range(e_shnum)}
text=secs['.text']; base=text['addr']; moff=text['off']; tsz=text['size']
mv=data[moff:moff+tsz]
pat=lambda a,n=16:' '.join('%02x'%x for x in data[a:a+n])
# --- decode ---
bl=[]; callers=collections.defaultdict(list); adrp={}; strx=[]
for i in range(0,len(mv)-3,4):
    w=struct.unpack_from('<I',mv,i)[0]; site=base+i
    if (w & 0xFC000000)==0x94000000:
        imm=w & 0x03FFFFFF
        if imm & 0x02000000: imm-=0x04000000
        tgt=site+imm*4
        bl.append((site,tgt)); callers[tgt].append(site)
        continue
    if (w & 0x9F000000)==0x90000000:
        rd=w & 0x1F; immlo=(w>>29)&3; immhi=(w>>5)&0x7FFFF
        imm=(immhi<<2)|immlo
        if imm & (1<<20): imm-=1<<21
        adrp[rd]=(site & ~0xFFF)+(imm<<12); continue
    if (w & 0x7F800000)==0x11000000:
        rn=(w>>5)&0x1F; imm12=(w>>10)&0xFFF; shf=(w>>22)&1
        if rn in adrp:
            v=adrp[rn]+(imm12<<(12 if shf else 0))
            if v: strx.append((site,v))
print('bl',len(bl),'strx',len(strx))
# --- write enriched TSVs ---
with open(REL+'/RELATIONSHIP_CALLS.tsv','w') as f:
    f.write('call_site\tcallee_addr\tcallee_name\tcallee_demangled\tcallee_size\tcall_site_byte_pattern\n')
    for s,t in bl:
        n=resolve(t)
        f.write('0x%x\t0x%x\t%s\t%s\t%d\t%s\n'%(s,t,n,dmg(n) if n else '',sizes.get(t,0),pat(s)))
with open(REL+'/RELATIONSHIP_STRINGS.tsv','w') as f:
    f.write('xref_site\ttarget_addr\ttarget_string\tbyte_pattern\n')
    # string table for reverse lookup
    for s,t in strx:
        txt=''
        if 0<t<len(data):
            e=data.find(b'\0',t,t+200)
            if e>t:
                try: txt=data[t:e].decode('utf-8')
                except: txt=''
                if not txt.isprintable() or len(txt)<2: txt=''
        f.write('0x%x\t0x%x\t%s\t%s\n'%(s,t,txt[:150].replace('\t',' '),pat(s)))
# top functions by fan-in / fan-out
fanout=collections.Counter(); fanin=collections.Counter()
for s,t in bl:
    fanout[s]+=1; fanin[t]+=1
with open(REL+'/RELATIONSHIP_TOP_HUBS.tsv','w') as f:
    f.write('address\tname\tdemangled\tfan_in\tfan_out\tbyte_pattern\n')
    for a,c in fanin.most_common(3000):
        n=resolve(a)
        f.write('0x%x\t%s\t%s\t%d\t%d\t%s\n'%(a,n,dmg(n) if n else '',c,fanout.get(a,0),pat(a)))
json.dump({'call_sites':len(bl),'string_xrefs':len(strx),'unique_callees':len(callers),
           'named_functions':len(names),'top_hubs':3000},open(REL+'/SUMMARY.json','w'),indent=2)
print('DONE')
