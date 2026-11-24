# Ghidra Jython post-script: guaranteed export, no full auto-analysis required.
import os, time, json, traceback
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import SymbolType

args = getScriptArgs()
OUT = args[0] if len(args) > 0 else 'out'
BUDGET = int(args[1]) if len(args) > 1 else 1800
START = time.time()
if not os.path.isdir(OUT): os.makedirs(OUT)

def w(name, lines):
    try:
        with open(os.path.join(OUT, name), 'wb') as f:
            for l in lines:
                s = l if isinstance(l, unicode) else unicode(l)
                f.write(s.encode('utf-8', 'replace')); f.write('\n')
        print('[fast] wrote %s: %d rows' % (name, len(lines)))
    except Exception:
        print('[fast] FAILED writing %s' % name)
        traceback.print_exc()

def st(x):
    try: return str(x)
    except Exception: return ''

try:
    prog = currentProgram
    fm = prog.getFunctionManager()
    sm = prog.getSymbolTable()

    created = 0
    try:
        for s in sm.getAllSymbols(True):
            if time.time() - START > BUDGET * 0.15: break
            try:
                if s.getSymbolType() != SymbolType.FUNCTION: continue
                a = s.getAddress()
                if a is None or fm.getFunctionAt(a) is not None: continue
                fm.createFunction(a, 'FUNC_%s' % a); created += 1
            except Exception: pass
    except Exception: pass
    print('[fast] created %d functions from ELF symbols' % created)

    blocks = ['offset_start\toffset_end\tname\tpermissions\ttype\tbase']
    try:
        for b in prog.getMemory().getBlocks():
            try:
                blocks.append('%s\t%s\t%s\t%s\t%s\t%s' % (
                    st(b.getStart()), st(b.getEnd()), st(b.getName()),
                    ('R' if b.isRead() else '-')+('W' if b.isWrite() else '-')+('X' if b.isExecute() else '-'),
                    st(b.getType()), st(b.getBaseAddress())))
            except Exception: pass
    except Exception: pass
    w('01_memory_blocks.tsv', blocks)

    syms = ['address\tname\ttype\tsource\tnamespace\tsize']
    try:
        for s in sm.getAllSymbols(True):
            try:
                syms.append('%s\t%s\t%s\t%s\t%s\t%s' % (
                    st(s.getAddress()), st(s.getName()), st(s.getSymbolType()),
                    st(s.getSource()), st(s.getParentNamespace().getName(True)), st(s.getSize())))
            except Exception: pass
            if time.time() - START > BUDGET * 0.25: break
    except Exception: pass
    w('03_all_symbols.tsv', syms)

    data = ['address\tsize\ttype\trepresentation']
    try:
        for d in prog.getListing().getDefinedData(True):
            try:
                data.append('%s\t%s\t%s\t%s' % (st(d.getAddress()), st(d.getLength()),
                    st(d.getDataType().getName()), st(d.getDefaultValueRepresentation())))
            except Exception: pass
            if time.time() - START > BUDGET * 0.3: break
    except Exception: pass
    w('02_defined_data.tsv', data)

    frows = ['entry_point\tname\tsignature\tsize\tcalling_convention\treturn_type\tparameters']
    flist = []
    try:
        for fn in fm.getFunctions(True):
            try:
                ps = ['%s:%s' % (st(v.getName()), st(v.getDataType().getName())) for v in fn.getParameters()]
                frows.append('\t'.join([st(fn.getEntryPoint()), st(fn.getName()),
                    st(fn.getSignature().getPrototypeString()), st(fn.getBody().getNumAddresses()),
                    st(fn.getCallingConventionName()), st(fn.getReturnType().getName()), '|'.join(ps)]))
                flist.append(fn)
            except Exception: pass
    except Exception: pass
    w('04_functions.tsv', frows)
    print('[fast] functions total: %d' % len(flist))

    if not os.path.isdir(os.path.join(OUT, 'decompiled')): os.makedirs(os.path.join(OUT, 'decompiled'))
    dec = None
    try:
        dec = DecompInterface(); dec.openProgram(prog)
    except Exception:
        print('[fast] decompiler init failed'); traceback.print_exc()
    if dec is not None:
        CHUNK=2000; chunks=[]; cur=[]; n=0; done=0
        for fn in flist:
            if time.time() - START > BUDGET: print('[fast] decompile budget reached'); break
            try:
                r = dec.decompileFunction(fn, 30, ConsoleTaskMonitor())
                if r and r.decompileCompleted():
                    c = r.getDecompiledFunction()
                    if c:
                        cur.append('// FUNCTION %s %s\n%s\n' % (st(fn.getEntryPoint()), st(fn.getName()), st(c.getC())))
                        n += 1; done += 1
                        if n >= CHUNK: chunks.append(cur); cur=[]; n=0
            except Exception: pass
        if cur: chunks.append(cur)
        for i,c in enumerate(chunks):
            try:
                open(os.path.join(OUT,'decompiled','part_%04d.c'%i),'wb').write('\n'.join(c).encode('utf-8','replace'))
            except Exception: pass
        print('[fast] decompiled %d functions in %d chunks' % (done, len(chunks)))
    else:
        done=0; chunks=[]

    json.dump({'created_functions':created,'functions':len(flist),'decompiled':done,
               'chunks':len(chunks),'seconds':time.time()-START},
              open(os.path.join(OUT,'EXPORT_SUMMARY.json'),'w'), indent=2)
    print('[fast] DONE')
except Exception:
    print('[fast] TOP LEVEL ERROR')
    traceback.print_exc()
    try:
        open(os.path.join(OUT,'ERROR.txt'),'w').write(traceback.format_exc())
    except Exception: pass
