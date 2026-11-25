import os,re,sys
D='/root/workspace/Minecraft, reverse engineer/results/per_function/asm'
targets={0x2727f1f:'Failed to register Block with identifier: %s',0x26e9550:'Block %s has a name conflict',
         0x27dd3a1:'CreativeItemCategory',0x2592262:'CreativeItemCategory(v1_19_40)',0x2622f29:'CreativeItemCategory(SharedTypes)'}
hits={t:[] for t in targets}
adrp_re=re.compile(r'adrp\s+(x\d+),\s*(?:0x)?([0-9a-f]+)')
add_re=re.compile(r'add\s+(x\d+),\s*(x\d+),\s*#(?:0x)?([0-9a-f]+)')
n=0
for root,_,files in os.walk(D):
    for fn in files:
        if not fn.endswith('.asm'): continue
        p=os.path.join(root,fn); n+=1
        regs={}
        for line in open(p,errors='replace'):
            m=adrp_re.search(line)
            if m:
                regs[m.group(1)]=int(m.group(2),16); continue
            m=add_re.search(line)
            if m and m.group(2) in regs:
                t=regs[m.group(2)]+int(m.group(3),16)
                if t in targets: hits[t].append((fn,line.strip()))
print('scanned',n,'files')
for t,desc in targets.items():
    print(hex(t),desc,'hits',len(hits[t]))
    for h in hits[t][:10]: print('  ',h)
