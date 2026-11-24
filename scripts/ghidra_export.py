# Ghidra Jython 2.7 post-script. Exports EVERYTHING reachable from the program
# database into plain text/CSV/JSON under the output directory.
import os, sys, time, json, traceback
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import SymbolType, SourceType
from ghidra.program.model.mem import MemoryBlockType

args = getScriptArgs()
OUT = args[0] if len(args) > 0 else 'out'
BUDGET = int(args[1]) if len(args) > 1 else 9600
START = time.time()
os.makedirs(OUT)

def w(name, lines):
    p = os.path.join(OUT, name)
    with open(p, 'w') as f:
        for l in lines:
            f.write(unicode(l).encode('utf-8', 'replace') if False else (l if isinstance(l, unicode) else unicode(l)))
            f.write('\n')
    print('[export]', name, len(lines))

def deadline():
    return (time.time() - START) > BUDGET

# ---------- program metadata ----------
meta = []
prog = currentProgram
meta.append('program_name=%s' % prog.getName())
meta.append('image_base=%s' % prog.getImageBase())
meta.append('address_factory=%s' % prog.getAddressFactory())
meta.append('language=%s %s' % (prog.getLanguage().getLanguageID(), prog.getLanguage().getVersion()))
meta.append('compiler=%s' % prog.getCompilerSpec().getCompilerSpecID())
meta.append('sha256_from_elf_sidecar=see elf/sha256.txt')
w('00_program_metadata.txt', meta)

# ---------- memory blocks / offsets ----------
blocks = ['offset_start\toffset_end\tname\tpermissions\ttype\tinitialised\tbase']
for b in prog.getMemory().getBlocks():
    try:
        start = b.getStart(); end = b.getEnd()
        perm = ('R' if b.isRead() else '-') + ('W' if b.isWrite() else '-') + ('X' if b.isExecute() else '-')
        blocks.append('%s\t%s\t%s\t%s\t%s\t%s\t%s' % (
            start, end, b.getName(), perm, b.getType().toString(), b.isInitialized(), b.getBaseAddress()))
    except Exception:
        pass
w('01_memory_blocks.tsv', blocks)

# ---------- defined data ----------
data = ['address\tsize\ttype\trepresentation\tvalue']
dm = prog.getMinimalAddressSet()
try:
    for d in prog.getListing().getDefinedData(True):
        try:
            data.append('%s\t%d\t%s\t%s\t%s' % (d.getAddress(), d.getLength(), d.getDataType().getName(),
                                                 d.getDefaultValueRepresentation(), repr(d.getValue())))
        except Exception:
            pass
        if deadline(): break
except Exception:
    pass
w('02_defined_data.tsv', data)

# ---------- symbols (every kind, every source) ----------
syms = ['address\tname\ttype\tsource\tnamespace\tsize\tdemangled']
sm = prog.getSymbolTable()
try:
    for s in sm.getAllSymbols(True):
        try:
            syms.append('%s\t%s\t%s\t%s\t%s\t%d\t%s' % (
                s.getAddress(), s.getName(), s.getSymbolType(), s.getSource(),
                s.getParentNamespace().getName(True), s.getSize(), s.getName(True)))
        except Exception:
            pass
        if deadline(): break
except Exception:
    pass
w('03_all_symbols.tsv', syms)

# ---------- functions: name, signature, offset, size, params, xrefs ----------
fm = prog.getFunctionManager()
funcs = fm.getFunctions(True)
frows = ['entry_point\tname\tsignature\tsize\tcalling_convention\treturn_type\tparameters\txref_count']
function_list = []
while funcs.hasNext() and not deadline():
    fn = funcs.next()
    try:
        params = []
        for v in fn.getParameters():
            params.append('%s:%s@%s' % (v.getName(), v.getDataType().getName(), v.getVariableLocation()))
        sig = fn.getSignature().getPrototypeString()
        xrefs = fn.getSymbol().getReferenceCount() if fn.getSymbol() else 0
        row = [str(fn.getEntryPoint()), fn.getName(), sig, fn.getBody().getNumAddresses(),
               fn.getCallingConventionName(), fn.getReturnType().getName(), '|'.join(params), str(xrefs)]
        frows.append('\t'.join(row))
        function_list.append(fn)
    except Exception:
        pass
w('04_functions.tsv', frows)
print('[export] functions:', len(function_list))

# ---------- strings (all printable byte sequences, with addresses) ----------
strs = ['address\tlength\tstring']
try:
    for s in getScriptArgs():
        pass
except Exception:
    pass
try:
    from ghidra.program.model.data import StringDataType
    for addr in prog.getMemory().getBlocks():
        pass
except Exception:
    pass
# Ghidra's defined strings from the listing
defined_strings = ['address\tvaddr\tlength\tstring']
try:
    for d in prog.getListing().getDefinedData(True):
        try:
            if d.getDataType().getName().lower().find('string') >= 0 or d.getDataType() instanceof StringDataType:
                defined_strings.append('%s\t%s\t%d\t%s' % (d.getAddress(), d.getAddress(), d.getLength(),
                                                           str(d.getDefaultValueRepresentation()).replace('\t', ' ')))
        except Exception:
            pass
        if deadline(): break
except Exception:
    pass
w('05_defined_strings.tsv', defined_strings)

# ---------- full decompilation of every function ----------
dec = DecompInterface()
dec.openProgram(prog)
os.makedirs(os.path.join(OUT, 'decompiled'))
CHUNK = 2000
chunks = []
cur = []
cur_n = 0
for fn in function_list:
    if deadline():
        print('[export] time budget reached during decompilation')
        break
    try:
        res = dec.decompileFunction(fn, 60, ConsoleTaskMonitor())
        if res and res.decompileCompleted():
            c = res.getDecompiledFunction().getC()
            cur.append('// FUNCTION %s  %s\n%s\n' % (fn.getEntryPoint(), fn.getName(), c))
            cur_n += 1
            if cur_n >= CHUNK:
                chunks.append(cur); cur = []; cur_n = 0
    except Exception:
        pass
if cur: chunks.append(cur)
for i, chunk in enumerate(chunks):
    with open(os.path.join(OUT, 'decompiled', 'part_%04d.c' % i), 'w') as f:
        f.write('\n'.join(chunk))
    print('[export] decompiled part_%04d.c: %d functions' % (i, len(chunk)))

# ---------- call graph / references ----------
xrefs = ['caller\tcallee\ttype']
try:
    for fn in function_list[:200000]:
        try:
            for ref in fn.getSymbol().getReferences():
                xrefs.append('%s\t%s\t%s' % (ref.getFromAddress(), fn.getEntryPoint(), ref.getReferenceType()))
        except Exception:
            pass
        if deadline(): break
except Exception:
    pass
w('06_xrefs.tsv', xrefs)

# ---------- data type archive ----------
types = []
try:
    dtm = prog.getDataTypeManager()
    t = dtm.getAllDataTypes()
    while t.hasNext() and not deadline():
        dt = t.next()
        try: types.append('%s\t%s' % (dt.getPathName(), dt.getName()))
        except Exception: pass
except Exception: pass
w('07_datatypes.tsv', types)

# ---------- external imports/exports ----------
ext = ['symbol\taddress\tlibrary']
try:
    em = prog.getExternalManager()
    for lib in em.getExternalLibraryNames():
        for s in em.getAllSymbols(lib):
            ext.append('%s\t%s\t%s' % (s.getName(), s.getAddress() if s.getAddress() else '', lib))
except Exception: pass
w('08_external_symbols.tsv', ext)

# ---------- bookmarks ----------
bm = []
try:
    for b in prog.getBookmarkManager().getBookmarks():
        bm.append('%s\t%s\t%s\t%s' % (b.getAddress(), b.getTypeString(), b.getCategory(), b.getComment()))
except Exception: pass
w('09_bookmarks.tsv', bm)

with open(os.path.join(OUT, 'EXPORT_SUMMARY.json'), 'w') as f:
    json.dump({'functions': len(function_list), 'symbols': len(syms) - 1,
               'defined_data': len(data) - 1, 'strings': len(defined_strings) - 1,
               'decompiled_functions': sum(len(c) for c in chunks),
               'chunks': len(chunks), 'seconds': time.time() - START,
               'budget_seconds': BUDGET}, f, indent=2)
print('[export] DONE in %d seconds' % (time.time() - START))
