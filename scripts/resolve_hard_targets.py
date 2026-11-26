#!/usr/bin/env python3
"""Resolve the mod targets whose old signatures no longer exist, using structure:
string anchors -> xref function -> callee fingerprint, and progressive pattern relaxation."""
import os,re,sys,json,sqlite3,struct
NEW=sys.argv[1]; DB=sys.argv[2]; OUT=sys.argv[3]
os.makedirs(OUT,exist_ok=True)
data=open(NEW,'rb').read()
con=sqlite3.connect('file:%s?mode=ro'%DB,uri=True); c=con.cursor()
def pc_rel(w):
    if (w&0xfc000000) in (0x94000000,0x14000000): return True
    if (w&0x9f000000) in (0x90000000,0x10000000): return True
    if (w&0xff000010)==0x54000000: return True
    if (w&0x7f000000) in (0x34000000,0x35000000): return True
    if (w&0x7f000000) in (0x36000000,0x37000000): return True
    if (w&0x3b000000)==0x18000000: return True
    return False
def gen(off,nw):
    o=[]
    for i in range(nw):
        w=int.from_bytes(data[off+i*4:off+i*4+4],'little')
        o+=(['??']*4) if pc_rel(w) else ['%02x'%b for b in w.to_bytes(4,'little')]
    return ' '.join(o)
def uniq(anchor,tries=(10,12,16,24,32,40,64,96,128)):
    for nw in tries:
        if anchor+nw*4>len(data): break
        p=gen(anchor,nw)
        bs=b''.join(b'.' if x=='??' else re.escape(bytes([int(x,16)])) for x in p.split())
        if len(re.findall(bs,data,re.DOTALL))==1: return p
    return None
def literal_words(pat):
    """return list of (word_index, 4-byte literal) for non-wildcard words"""
    t=pat.split(); out=[]
    for i in range(0,len(t),4):
        w=t[i:i+4]
        if len(w)<4 or w==['??']*4: continue
        out.append((i//4,bytes(int(x,16) for x in w)))
    return out
def find_anchor(pat, max_shift=0):
    """find the position whose literal words match best, allowing gaps"""
    lw=literal_words(pat)
    if not lw: return None,0
    # seed on the LAST literal word (often most unique / least affected)
    seed=lw[-1]
    bs=seed[1]; hits=[]
    i=0
    while True:
        i=data.find(bs,i)
        if i<0: break
        hits.append(i); i+=1
        if len(hits)>5000: break
    best=None
    for h in hits:
        a=h-seed[0]*4
        if a<0: continue
        sc=0
        for idx,b in lw:
            pr=a+idx*4
            if 0<=pr and pr+len(b)<=len(data) and data[pr:pr+len(b)]==b: sc+=1
        if best is None or sc>best[0]: best=(sc,a)
    if not best: return None,0
    return best[1],best[0]/len(lw)
def callees_of(addr):
    return [r[0] for r in c.execute('SELECT DISTINCT callee FROM calls WHERE site=?',(addr,))]
def strrefs_of(addr):
    return [r for r in c.execute('SELECT target,text FROM strxref WHERE site BETWEEN ? AND ? LIMIT 400',(addr,addr+0x2000))]
def find_fn_by_string(sub):
    """find functions that reference a string containing sub"""
    rows=c.execute('SELECT target,text FROM strxref WHERE text LIKE ? LIMIT 20',('%'+sub+'%',)).fetchall()
    out=[]
    for tgt,txt in rows:
        for r in c.execute('SELECT DISTINCT site FROM strxref WHERE target=?',(tgt,)):
            fr=c.execute('SELECT addr,name FROM functions WHERE addr<=? ORDER BY addr DESC LIMIT 1',(r[0],)).fetchone()
            if fr: out.append((fr[0],fr[1],txt))
    return out
TARGETS=['REGISTER_BLOCK','BLOCKITEM_CTOR','MATERIAL_GET','FN_TERRAIN_LOADER',
         'NETID_NEXT','DESC_CTOR','ITEM_INST_CTOR','ITEM_INST_COPY','CREATIVE_GROUP_CTOR']
# load old patterns from mod source
src=open('/root/workspace/Minecraft, reverse engineer/repo/modsrc/src/FinalMod.cpp',errors='replace').read()
blk=src[src.index('struct S{ uintptr_t* dst'):src.index('for(auto& s:tbl)')]
old={}
for m in re.finditer(r'\{&(\w+),\s*"([^"]+)",\s*"([^"]+)",\s*([^},]+)',blk):
    lab=m.group(2)
    old[lab.split('_0x')[0]]=(m.group(3),m.group(4).strip())
res={}
for t in TARGETS:
    pat,adj=old.get(t,(None,None))
    if not pat: res[t]={'status':'no pattern'}; continue
    a,score=find_anchor(pat)
    entry={'anchor':a,'literal_match':round(score,3) if a else 0,'adj':adj}
    if a is not None and score>=0.6:
        entry['sig']=uniq(a)
        entry['status']='fuzzy-ok' if entry['sig'] else 'anchor-only'
    else:
        entry['status']='not found by pattern'
    # structural hint for REGISTER_BLOCK-like: find via error string
    if t=='REGISTER_BLOCK':
        cands=find_fn_by_string('Failed to register Block')
        entry['string_candidates']=[{'fn':hex(x[0]),'name':x[1][:60],'str':x[2][:50]} for x in cands[:5]]
        # the registrar is a callee of that function
        for c0,nm,txt in cands[:3]:
            for cal in callees_of(c0):
                fr=c.execute('SELECT name FROM functions WHERE addr=?',(cal,)).fetchone()
                entry.setdefault('callee_candidates',[]).append({'addr':hex(cal),'name':(fr[0][:50] if fr else '')})
    res[t]=entry
    print(t,entry.get('status'),hex(a) if a else '-',entry.get('literal_match'))
json.dump(res,open(OUT+'/hard_targets.json','w'),indent=2)
print(json.dumps({k:{'status':v.get('status'),'anchor':hex(v['anchor']) if v.get('anchor') else None} for k,v in res.items()},indent=2))
