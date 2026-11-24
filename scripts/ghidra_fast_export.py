# Ghidra Jython post-script: guaranteed export without waiting for full auto-analysis.
# Creates functions at ELF symbol addresses, exports all symbols/data/strings,
# and decompiles as many functions as the time budget allows.
import os, time, json
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import SymbolType

args = getScriptArgs(); OUT = args[0]; BUDGET = int(args[1]) if len(args) > 1 else 1800
START = time.time()
if not os.path.isdir(OUT): os.makedirs(OUT)

def w(name, lines):
    with open(os.path.join(OUT, name), 'wb') as f:
        for l in lines:
            s = l if isinstance(l, unicode) else unicode(l)
            f.write(s.encode('utf-8', 'replace')); f.write('\n')
    print('[fast] %s: %d rows' % (name, len(lines)))

prog = currentProgram
fm = prog.getFunctionManager()
sm = prog.getSymbolTable()

# create functions at every defined FUNC symbol inside executable memory that has none
created = 0
for s in sm.getAllSymbols(True):
    if time.time() - START > BUDGET * 0.15: break
    if s.getSymbolType() != SymbolType.FUNCTION: continue
    a = s.getAddress()
    if a is None or fm.getFunctionAt(a) is not None: continue
    try:
        fm.createFunction(a, 'FUNC_%s' % a)
        created += 1
    except Exception:
        pass
print('[fast] created %d functions from ELF symbols' % created)

# memory blocks = exact file offsets / virtual addresses
blocks = ['offset_start\toffset_end\tname\tpermissions\ttype\tbase']
for b in prog.getMemory().getBlocks():
    blocks.append('%s\t%s\t%s\t%s\t%s\t%s' % (b.getStart(), b.getEnd(), b.getName(),
        ('R' if b.isRead() else '-')+('W' if b.isWrite() else '-')+('X' if b.isExecute() else '-'),
        b.getType().toString(), b.getBaseAddress()))
w('01_memory_blocks.tsv', blocks)

# every symbol
syms = ['address\tname\ttype\tsource\tnamespace\tsize']
for s in sm.getAllSymbols(True):
    try:
        syms.append('%s\t%s\t%s\t%s\t%s\t%d' % (s.getAddress(), s.getName(), s.getSymbolType(),
            s.getSource(), s.getParentNamespace().getName(True), s.getSize()))
    except Exception: pass
w('03_all_symbols.tsv', syms)

# all defined data
data = ['address\tsize\ttype\trepresentation']
for d in prog.getListing().getDefinedData(True):
    try: data.append('%s\t%d\t%s\t%s' % (d.getAddress(), d.getLength(), d.getDataType().getName(),
                                        d.getDefaultValueRepresentation()))
    except Exception: pass
    if time.time() - START > BUDGET * 0.3: break
w('02_defined_data.tsv', data)

# functions with signatures
frows = ['entry_point\tname\tsignature\tsize\tcalling_convention\treturn_type\tparameters']
flist = []
for fn in fm.getFunctions(True):
    try:
        ps = ['%s:%s' % (v.getName(), v.getDataType().getName()) for v in fn.getParameters()]
        frows.append('\t'.join([str(fn.getEntryPoint()), fn.getName(), fn.getSignature().getPrototypeString(),
            str(fn.getBody().getNumAddresses()), fn.getCallingConventionName(), fn.getReturnType().getName(), '|'.join(ps)]))
        flist.append(fn)
    except Exception: pass
w('04_functions.tsv', frows)
print('[fast] functions total: %d' % len(flist))

# decompile with time budget
if not os.path.isdir(os.path.join(OUT, 'decompiled')): os.makedirs(os.path.join(OUT, 'decompiled'))
dec = DecompInterface(); dec.openProgram(prog)
CHUNK=2000; chunks=[]; cur=[]; n=0; done=0
for fn in flist:
    if time.time() - START > BUDGET: print('[fast] decompilation budget reached'); break
    try:
        r = dec.decompileFunction(fn, 30, ConsoleTaskMonitor())
        if r and r.decompileCompleted():
            cur.append('// FUNCTION %s %s\n%s\n' % (fn.getEntryPoint(), fn.getName(), r.getDecompiledFunction().getC()))
            n += 1; done += 1
            if n >= CHUNK: chunks.append(cur); cur=[]; n=0
    except Exception: pass
if cur: chunks.append(cur)
for i,c in enumerate(chunks):
    open(os.path.join(OUT,'decompiled','part_%04d.c'%i),'wb').write('\n'.join(c).encode('utf-8','replace'))
print('[fast] decompiled %d functions in %d chunks' % (done, len(chunks)))

json.dump({'created_functions':created,'functions':len(flist),'decompiled':done,
           'chunks':len(chunks),'seconds':time.time()-START},
          open(os.path.join(OUT,'EXPORT_SUMMARY.json'),'w'), indent=2)
print('[fast] DONE')
