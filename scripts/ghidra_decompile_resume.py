# Resume decompilation for an explicit list of function addresses.
import os,time,json,traceback
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import SymbolType
a=getScriptArgs(); OUT=a[0]; LIST=a[1]; START=int(a[2]); COUNT=int(a[3]); BUDGET=int(a[4]) if len(a)>4 else 15000
T0=time.time()
if not os.path.isdir(OUT): os.makedirs(OUT)
def st(x):
    try: return str(x)
    except Exception: return ''
try:
    prog=currentProgram; fm=prog.getFunctionManager(); sm=prog.getSymbolTable()
    for s in sm.getAllSymbols(True):
        try:
            if s.getSymbolType()!=SymbolType.FUNCTION: continue
            ad=s.getAddress()
            if ad is not None and fm.getFunctionAt(ad) is None: fm.createFunction(ad,'FUNC_%s'%ad)
        except Exception: pass
    addrs=[x.strip().lower() for x in open(LIST) if x.strip()][START:START+COUNT]
    print('[resume] slice',START,'count',len(addrs))
    di=DecompInterface(); di.openProgram(prog)
    done=0; fail=0; cur=[]; parts=0
    for i,h in enumerate(addrs):
        if time.time()-T0>BUDGET: print('[resume] budget reached'); break
        fn=None
        try:
            from ghidra.program.model.address import GenericAddress
            ad=prog.getAddressFactory().getAddress(h)
            if ad is not None: fn=fm.getFunctionAt(ad)
        except Exception: pass
        if fn is None:
            try:
                for f in fm.getFunctions(True):
                    if st(f.getEntryPoint()).lower().endswith(h): fn=f; break
            except Exception: pass
        if fn is None: fail+=1; continue
        try:
            r=di.decompileFunction(fn,120,ConsoleTaskMonitor())
            if r and r.decompileCompleted():
                c=r.getDecompiledFunction()
                if c:
                    cur.append('// FUNCTION %s %s\n%s\n'%(st(fn.getEntryPoint()),st(fn.getName()),st(c.getC()))); done+=1
                    if len(cur)>=500:
                        open(os.path.join(OUT,'part_%03d.c'%parts),'wb').write('\n'.join(cur).encode('utf-8','replace')); parts+=1; cur=[]
            else: fail+=1
        except Exception: fail+=1
        if i%500==0: print('[resume] progress',i,'done',done,'fail',fail)
    if cur: open(os.path.join(OUT,'part_%03d.c'%parts),'wb').write('\n'.join(cur).encode('utf-8','replace')); parts+=1
    json.dump({'slice':START,'requested':len(addrs),'decompiled':done,'failed':fail,'parts':parts,'seconds':time.time()-T0},
              open(os.path.join(OUT,'resume_summary.json'),'w'),indent=2)
    print('[resume] DONE',done,fail)
except Exception:
    print('[resume] ERROR'); traceback.print_exc()
