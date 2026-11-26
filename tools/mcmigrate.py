#!/usr/bin/env python3
"""Cross-version offset migrator.

Maps a mod's RVA + wildcard-signature table from an OLD libminecraftpe.so to a
NEW one. Uses fuzzy literal-run matching so instruction shifts are tolerated,
and repairs PLT thunks by median delta.

Usage:
  mcmigrate.py --old old.so --new new.so --src FinalMod.cpp --out out_dir
  mcmigrate.py --new new.so --patterns patterns.txt --out out_dir
"""
import sys,re,os,json,argparse
def pc_relative(w):
    if (w & 0xfc000000) in (0x94000000,0x14000000): return True
    if (w & 0x9f000000) in (0x90000000,0x10000000): return True
    if (w & 0xff000010)==0x54000000: return True
    if (w & 0x7f000000) in (0x34000000,0x35000000): return True
    if (w & 0x7f000000) in (0x36000000,0x37000000): return True
    if (w & 0x3b000000)==0x18000000: return True
    return False
def gen(data,off,nwords):
    out=[]
    for i in range(nwords):
        w=int.from_bytes(data[off+i*4:off+i*4+4],'little')
        out+=(['??']*4) if pc_relative(w) else ['%02x'%b for b in w.to_bytes(4,'little')]
    return ' '.join(out)
def runs_of(pat):
    toks=pat.split(); runs=[]; cur=[]; start=0
    for i in range(0,len(toks),4):
        w=toks[i:i+4]
        if len(w)<4: break
        if w==['??']*4:
            if cur: runs.append((start,b''.join(bytes([int(x,16)]) for x in cur))); cur=[]
        else:
            if not cur: start=i//4
            cur+=w
    if cur: runs.append((start,b''.join(bytes([int(x,16)]) for x in cur)))
    return runs
def hits_of(data,bs,cap=6000):
    out=[];i=0
    while True:
        i=data.find(bs,i)
        if i<0: break
        out.append(i); i+=1
        if len(out)>=cap: break
    return out
def uniq_sig(data,anchor,tries=(10,12,16,24,32,40,64,96)):
    for nw in tries:
        if anchor+nw*4>len(data): break
        p=gen(data,anchor,nw)
        bs=b''.join(b'.' if x=='??' else re.escape(bytes([int(x,16)])) for x in p.split())
        if len(re.findall(bs,data,re.DOTALL))==1: return p
    return None
def fuzzy_locate(data,pat,max_cand=4000):
    runs=runs_of(pat)
    if not runs: return None,'no literal runs'
    seed=max(runs,key=lambda r:len(r[1]))
    hs=hits_of(data,seed[1],max_cand)
    if not hs: return None,'signature not present'
    cands=[]
    for h in hs:
        a=h-seed[0]*4
        if a<0: continue
        score=0
        for st,bs in runs:
            pr=a+st*4
            if 0<=pr and pr+len(bs)<=len(data) and data[pr:pr+len(bs)]==bs: score+=len(bs)
        cands.append((score,a))
    cands.sort(reverse=True)
    if not cands: return None,'no candidate'
    if len(cands)>1 and cands[0][0]==cands[1][0]: return None,'ambiguous (%d equal-score)'%sum(1 for s,_ in cands if s==cands[0][0])
    return cands[0][1],'ok'
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--old'); ap.add_argument('--new',required=True)
    ap.add_argument('--src'); ap.add_argument('--patterns')
    ap.add_argument('--out',default='out')
    a=ap.parse_args()
    os.makedirs(a.out,exist_ok=True)
    new=open(a.new,'rb').read(); print('new lib %d bytes'%len(new))
    entries=[]
    if a.src:
        src=open(a.src,errors='replace').read()
        blk=src[src.index('struct S{ uintptr_t* dst'):src.index('for(auto& s:tbl)')]
        for m in re.finditer(r'\{&(\w+),\s*"([^"]+)",\s*"([^"]+)",\s*([^},]+)',blk):
            entries.append((m.group(1),m.group(2),m.group(3),m.group(4).strip()))
    elif a.patterns:
        for i,line in enumerate(open(a.patterns,errors='replace')):
            line=line.strip()
            if not line or line.startswith('#'): continue
            parts=line.split('\t')
            entries.append(('p%d'%i,parts[0],parts[1],parts[2] if len(parts)>2 else '0'))
    print('entries',len(entries))
    res=[]
    for var,label,pat,adj in entries:
        addr,why=fuzzy_locate(new,pat)
        sig=None
        if addr is not None:
            sig=uniq_sig(new,addr)
            if sig is None: why='found but signature not unique'
        res.append(dict(var=var,label=label,old_adj=adj,new_addr=addr,new_sig=sig,status=why))
    # PLT delta repair
    plt=[r for r in res if 'PLT_0x' in r['label'] and r['new_addr']]
    if plt:
        ds=sorted(r['new_addr']-int(r['label'].split('PLT_0x')[1],16) for r in plt)
        delta=ds[len(ds)//2]
        print('PLT delta 0x%x'%delta)
        for r in res:
            if 'PLT_0x' in r['label'] and not r['new_addr']:
                r['new_addr']=int(r['label'].split('PLT_0x')[1],16)+delta
                r['status']='plt-delta'; r['new_sig']=gen(new,r['new_addr'],10)
    ok=sum(1 for r in res if r['new_sig'])
    print('resolved %d/%d'%(ok,len(res)))
    json.dump(res,open(os.path.join(a.out,'migration.json'),'w'),indent=2)
    with open(os.path.join(a.out,'MIGRATION.md'),'w') as f:
        f.write('# Migration report\n\n| Var | Label | New addr | Status |\n|---|---|---:|---|\n')
        for r in res:
            f.write('| `%s` | %s | %s | %s |\n'%(r['var'],r['label'],hex(r['new_addr']) if r['new_addr'] else '-',r['status']))
        f.write('\n## New signatures\n\n```\n')
        for r in res:
            if r['new_sig']: f.write('// %s @ %s\n"%s",\n'%(r['label'],hex(r['new_addr']),r['new_sig']))
        f.write('```\n')
    with open(os.path.join(a.out,'offsets_new.h'),'w') as f:
        f.write('// Generated by mcmigrate.py for the new library\n#pragma once\n#include <cstdint>\nnamespace off {\n')
        for r in res:
            if r['new_addr']: f.write('constexpr uintptr_t %-26s = 0x%x; // %s\n'%(r['label'].split('_0x')[0],r['new_addr'],r['status']))
        f.write('}\n')
    print('wrote',a.out)
main()
