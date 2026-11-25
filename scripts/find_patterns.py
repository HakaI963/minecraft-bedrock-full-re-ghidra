import re,os,sys
lib='/root/workspace/Minecraft, reverse engineer/native/libminecraftpe.so'
data=open(lib,'rb').read()
pats={
 'REGISTER_BLOCK':('00 75 80 52 ?? ?? ?? 95 f3 03 00 aa c2 02 40 b9 a1 c3 00 d1 e3 03 15 aa fd 07 c2 95 89 a2 53 a9',-0x60),
 'SET_CREATIVE_CATEGORY':('01 00 05 39 c0 03 5f d6 fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa 00 40 05 91 ?? ?? ?? ?? e0 03 13 aa f3 0b 40 f9',0),
}
def compile_pat(s):
    parts=[]
    for tok in s.split():
        parts.append(b'.' if tok=='??' else bytes.fromhex(tok))
    return b''.join(parts)
for name,(s,off) in pats.items():
    p=compile_pat(s)
    rx=re.compile(re.escape(p).replace(b'\\.',b'.'),re.DOTALL)
    hits=[m.start() for m in rx.finditer(data)]
    print(name,'len',len(p),'hits',len(hits),[hex(h) for h in hits[:10]])
    for h in hits[:10]:
        tgt=(h+off)&0xffffffffffffffff
        print('  match',hex(h),'target',hex(tgt),'target bytes',' '.join('%02x'%x for x in data[tgt:tgt+32]))
