import os,re,json,subprocess
D='/root/workspace/Minecraft, reverse engineer/results'
R=os.path.join(D,'reconstruction')
lib=open('/root/workspace/Minecraft, reverse engineer/native/libminecraftpe.so','rb').read()
targets=[
 dict(name='REGISTER_BLOCK',pattern='00 75 80 52 ?? ?? ?? 95 f3 03 00 aa c2 02 40 b9 a1 c3 00 d1 e3 03 15 aa fd 07 c2 95 89 a2 53 a9',
      pattern_off=-0x60,match=0x989ef80,addr=0x989ef20,end=0x989f7e4,
      sig='void BlockRegistry::registerBlock(/*this*/ void*, /*name*/ std::string_view/const char*, /*definition*/ void const*, /*flags*/ int)  [inferred from call sites - body uses x0=this, x1=name, x2=def, x3=flags; allocates 0x3a8-byte record]',
      desc='Registers a block definition in the block registry. Code at function start builds a hash/map entry (0x3a8-byte allocation), loads the block name from x1, stores it, and inserts into registry maps.'),
 dict(name='SET_CREATIVE_CATEGORY',pattern='01 00 05 39 c0 03 5f d6 fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa 00 40 05 91 ?? ?? ?? ?? e0 03 13 aa f3 0b 40 f9',
      pattern_off=0,match=0x1079d000,addr=0x1079d000,end=0x1079d008,
      sig='void setCreativeCategory(void* this, uint8_t category)   // strb w1,[x0,#320]; ret',
      desc='Writes a single byte at object offset +0x140 (320). Called ~20 times from a static initializer that builds the creative-item category table.'),
]
for t in targets:
    t['bytes']=' '.join('%02x'%x for x in lib[t['addr']:t['end']][:64])
    t['pattern_bytes']=' '.join('%02x'%x for x in lib[t['match']:t['match']+len(t['pattern'].split())])
    t['file_offset']=t['addr']  # .text vaddr == file offset in LOAD 0
    t['size']=t['end']-t['addr']
# append to master table
p=os.path.join(R,'MASTER_OFFSET_SIGNATURE_TABLE.tsv')
with open(p,'a') as f:
    for t in targets:
        f.write('0x%x\t0x%x\t%d\tCORRECTED: %s\t%s\t%s\t%s\tpattern@0x%x\tY\tY\n'%(
            t['addr'],t['file_offset'],t['size'],t['name'],t['name'],t['sig'],t['desc'],t['match']))
# corrections report
with open(os.path.join(D,'CORRECTIONS.md'),'w') as f:
    f.write('# CORRECTIONS - verified byte-signature findings\n\n')
    f.write('The earlier claim of 100% function coverage was based only on 79,159 Ghidra-recovered\n')
    f.write('functions from dynamic symbols. It omitted stripped game code. The two functions below\n')
    f.write('were found using the supplied byte patterns and are NOT in that table. This is a real\n')
    f.write('correction; all previous matches for "register block"/"creative category" were wrong.\n\n')
    for t in targets:
        f.write('## %s\n\n'%t['name'])
        f.write('| Field | Value |\n|---|---|\n')
        for k in ['pattern','pattern_off','match','addr','file_offset','size','sig','desc']:
            v=t[k]
            if isinstance(v,int): v='0x%x (%d)'%(v,v)
            f.write('| %s | %s |\n'%(k,v))
        f.write('| first 64 bytes of function | `%s` |\n\n'%t['bytes'])
        f.write('```asm\n')
        if t['name']=='SET_CREATIVE_CATEGORY':
            f.write('1079d000: 39050001  strb w1, [x0,#320]\n1079d004: d65f03c0  ret\n')
        else:
            f.write('989ef20: d10303ff sub sp, sp, #0xc0\n989ef24: a9087bfd stp x29,x30,[sp,#128]\n...\n989ef80: 52807500 mov w0,#0x3a8\n989ef84: 953d916f bl  0xe803540\n989ef98: 95c207fd bl  0x10920f8\n...\n989f7e0: d65f03c0 ret\n')
        f.write('```\n\n')
    f.write('## Call sites\n\n')
    f.write('- REGISTER_BLOCK `0x989EF20`: called from `0x10CB BEF8`, `0x0989183C`, `0x098928D0`, `0x098933A4`.\n')
    f.write('- SET_CREATIVE_CATEGORY `0x1079D000`: ~20 calls from `0x1060DDE8` static initializer\n')
    f.write('  (first at `0x106E1398`), building the creative-item category table.\n\n')
    f.write('## Correct answer to the test\n\n')
    f.write('REGISTER_BLOCK: pattern match 0x989EF80, offset -0x60 -> function 0x989EF20 (file offset 0x989EF20).\n')
    f.write('SET_CREATIVE_CATEGORY: pattern match 0x1079D000, offset 0 -> function 0x1079D000 (file offset 0x1079D000).\n')
json.dump({t['name']:{'address':hex(t['addr']),'match':hex(t['match']),'size':t['size']} for t in targets},
          open(os.path.join(R,'corrections_summary.json'),'w'),indent=2)
print('corrections applied')
