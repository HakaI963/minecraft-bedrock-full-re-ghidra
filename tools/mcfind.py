#!/usr/bin/env python3
"""Fuzzy byte-pattern finder for libminecraftpe.so.

Handles instruction-layout shifts between game versions by matching runs of
literal words and tolerating gaps where PC-relative instructions were wildcarded.

Usage:
  mcfind.py <lib.so> exact "00 75 80 52 ?? ?? ?? 95 ..."
  mcfind.py <lib.so> fuzzy "00 75 80 52 ?? ?? ?? 95 ..." [--max-drift 8]
  mcfind.py <lib.so> at 0x989ef20 [--words 24]
"""
import sys,re
def load(p): return open(p,'rb').read()
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
def all_hits(data,bs,cap=10000):
    out=[];i=0
    while True:
        i=data.find(bs,i)
        if i<0: break
        out.append(i); i+=1
        if len(out)>=cap: break
    return out
def main():
    if len(sys.argv)<3: print(__doc__); return
    lib=sys.argv[1]; mode=sys.argv[2]; arg=sys.argv[3] if len(sys.argv)>3 else ''
    data=load(lib); print('lib %s (%d bytes)'%(lib,len(data)))
    if mode=='exact':
        rx=b''.join(b'.' if x=='??' else re.escape(bytes([int(x,16)])) for x in arg.split())
        hits=[m.start() for m in re.finditer(rx,data,re.DOTALL)]
        print('exact hits: %d'%len(hits))
        for h in hits[:40]:
            f=re.search(rb'([A-Za-z_][A-Za-z0-9_]{6,})', data[max(0,h-80):h]) 
            print('  0x%x'%h)
    elif mode=='fuzzy':
        runs=runs_of(arg)
        print('literal runs: %d (longest %d bytes)'%(len(runs),max(len(r[1]) for r in runs) if runs else 0))
        if not runs: return
        seed=max(runs,key=lambda r:len(r[1]))
        hits=all_hits(data,seed[1])
        print('seed hits: %d'%len(hits))
        cands=[]
        for h in hits:
            a=h-seed[0]*4
            if a<0: continue
            score=0; total=0
            for st,bs in runs:
                total+=len(bs)
                pr=a+st*4
                if 0<=pr and pr+len(bs)<=len(data) and data[pr:pr+len(bs)]==bs: score+=len(bs)
            cands.append((score,total,a))
        cands.sort(reverse=True)
        if not cands: print('no candidates'); return
        best=cands[0]
        print('best match: 0x%x  (%d/%d literal bytes matched)'%(best[2],best[0],best[1]))
        for s,t,a in cands[:10]:
            print('  cand 0x%x  score %d/%d'%(a,s,t))
        print('\nregenerated signature @0x%x:'%best[2])
        print('  "%s"'%gen(data,best[2],max(10,(max(len(r[1])//4 for r in runs)+8))))
    elif mode=='at':
        off=int(arg,16) if arg.startswith('0x') else int(arg)
        nw=24
        if '--words' in sys.argv:
            nw=int(sys.argv[sys.argv.index('--words')+1])
        print('signature @0x%x (%d words):'%(off,nw))
        print('  "%s"'%gen(data,off,nw))
    else: print(__doc__)
main()
