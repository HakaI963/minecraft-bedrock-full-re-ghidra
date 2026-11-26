#!/usr/bin/env python3
"""Fuzzy mod migration: match literal-word runs, tolerate instruction shifts, fix PLT by delta."""
import re,sys,json,os
NEW=sys.argv[1]; SRC=sys.argv[2]; OUT=sys.argv[3]
os.makedirs(OUT,exist_ok=True)
data=open(NEW,'rb').read(); src=open(SRC,errors='replace').read()
block=src[src.index('struct S{ uintptr_t* dst'):src.index('for(auto& s:tbl)')]
entries=[(m.group(1),m.group(2),m.group(3),m.group(4)) for m in
         re.finditer(r'\{&(\w+),\s*"([^"]+)",\s*"([^"]+)",\s*([^},]+)',block)]
print('entries',len(entries))

def runs_of(pat):
    """Split pattern into runs of consecutive literal words -> [(start_word_idx, bytes)]"""
    toks=pat.split(); runs=[]; cur=[]; start=0
    for i in range(0,len(toks),4):
        w=toks[i:i+4]
        if len(w)<4: break
        if w==['??','??','??','??']:
            if cur: runs.append((start,b''.join(bytes([int(x,16)]) for x in cur))); cur=[]
        else:
            if not cur: start=i//4
            cur+=w
    if cur: runs.append((start,b''.join(bytes([int(x,16)]) for x in cur)))
    return runs

def all_hits(bs):
    out=[];i=0
    while True:
        i=data.find(bs,i)
        if i<0: break
        out.append(i); i+=1
        if len(out)>4000: break
    return out

def pc_relative(w):
    if (w & 0xfc000000) in (0x94000000,0x14000000): return True
    if (w & 0x9f000000) in (0x90000000,0x10000000): return True
    if (w & 0xff000010)==0x54000000: return True
    if (w & 0x7f000000) in (0x34000000,0x35000000): return True
    if (w & 0x7f000000) in (0x36000000,0x37000000): return True
    if (w & 0x3b000000)==0x18000000: return True
    return False

def gen(off,nwords):
    out=[]
    for i in range(nwords):
        w=int.from_bytes(data[off+i*4:off+i*4+4],'little')
        out+=(['??']*4) if pc_relative(w) else ['%02x'%b for b in w.to_bytes(4,'little')]
    return ' '.join(out)

def uniq_sig(anchor,tries=(10,12,16,24,32,40,64,96)):
    for nw in tries:
        if anchor+nw*4>len(data): break
        p=gen(anchor,nw)
        # uniqueness = the FIRST 3 words are rare enough
        bs=b''.join(b'.' if x=='??' else re.escape(bytes([int(x,16)])) for x in p.split())
        n=len(re.findall(bs,data,re.DOTALL))
        if n==1: return p
    return None

results=[]
for var,label,pat,adj in entries:
    runs=runs_of(pat)
    if not runs:
        results.append((var,label,None,None,'no literal runs')); continue
    # use the longest run as the seed
    seed=max(runs,key=lambda r:len(r[1]))
    hits=all_hits(seed[1])
    if not hits:
        results.append((var,label,None,None,'seed not found')); continue
    # candidate anchors: work back from seed offset
    cands=[h-seed[0]*4 for h in hits]
    chosen=None
    if len(cands)==1: chosen=cands[0]
    else:
        # score each candidate: count matching literal runs within tolerance
        scored=[]
        for c in cands:
            if c<0: continue
            score=0
            for start,bs in runs:
                probe=c+start*4
                if probe<0 or probe+len(bs)>len(data): continue
                if data[probe:probe+len(bs)]==bs: score+=len(bs)
            scored.append((score,c))
        scored.sort(reverse=True)
        if scored and (len(scored)==1 or scored[0][0]>scored[1][0]): chosen=scored[0][1]
    if chosen is None:
        results.append((var,label,None,None,'ambiguous %d cands'%len(cands))); continue
    sig=uniq_sig(chosen)
    results.append((var,label,chosen,sig,'ok' if sig else 'not unique'))
res_ok=[r for r in results if r[3]]
print('resolved',len(res_ok),'of',len(results))
# PLT repair: any label containing PLT_0x<addr> -> apply delta from median shift
plt=[r for r in results if 'PLT_0x' in r[1]]
if plt:
    deltas=[]
    for var,label,anchor,sig,st in plt:
        if anchor: deltas.append(anchor-int(label.split('PLT_0x')[1],16))
    if deltas:
        deltas.sort(); delta=deltas[len(deltas)//2]
        print('PLT delta',hex(delta),'from',len(deltas),'samples')
        for i,(var,label,anchor,sig,st) in enumerate(results):
            if 'PLT_0x' in label and not anchor:
                results[i]=(var,label,int(label.split('PLT_0x')[1],16)+delta,None,'plt-delta')
json.dump([{'var':v,'label':l,'anchor':hex(a) if a else None,'sig':s,'status':st}
           for v,l,a,s,st in results],open(OUT+'/migrated_v2.json','w'),indent=2)
with open(OUT+'/MIGRATION_V2.md','w') as f:
    f.write('# Mod migration v2 (fuzzy) — 1.26.60.4 -> 1.26.66.1\n\n')
    f.write('| Var | Label | New anchor | Status |\n|---|---|---:|---|\n')
    for v,l,a,s,st in results:
        f.write('| `%s` | %s | %s | %s |\n'%(v,l,hex(a) if a else '-',st))
    f.write('\n## Signatures\n\n')
    for v,l,a,s,st in results:
        if s: f.write('- `%s` @ `%s`\n  ```\n  %s\n  ```\n'%(l,hex(a),s))
with open(OUT+'/migrated_v2.tsv','w') as f:
    f.write('var\tlabel\tanchor\tsignature\tstatus\n')
    for v,l,a,s,st in results:
        f.write('%s\t%s\t%s\t%s\t%s\n'%(v,l,hex(a) if a else '',s or '',st))
print('fails:',[(l,st) for v,l,a,s,st in results if not s])
