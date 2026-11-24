# Decompile a contiguous slice of functions. Invoked once per CI shard.
import os, time, json, traceback
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import SymbolType

a = getScriptArgs(); OUT=a[0]; START=int(a[1]); COUNT=int(a[2]); BUDGET=int(a[3]) if len(a)>3 else 17000
T0=time.time()
if not os.path.isdir(OUT): os.makedirs(OUT)
def st(x):
    try: return str(x)
    except Exception: return ''
try:
    prog=currentProgram; fm=prog.getFunctionManager(); sm=prog.getSymbolTable()
    made=0
    for s in sm.getAllSymbols(True):
        try:
            if s.getSymbolType()!=SymbolType.FUNCTION: continue
            ad=s.getAddress()
            if ad is not None and fm.getFunctionAt(ad) is None:
                fm.createFunction(ad,'FUNC_%s'%ad); made+=1
        except Exception: pass
    print('[shard] created',made)
    funcs=[]
    for fn in fm.getFunctions(True):
        try: funcs.append(fn)
        except Exception: pass
    print('[shard] total functions',len(funcs),'slice',START,'to',START+COUNT)
    END=min(START+COUNT,len(funcs))
    di=DecompInterface(); di.openProgram(prog)
    done=0; failed=0; CHUNK=1000; cur=[]; parts=0
    for i in range(START,END):
        if time.time()-T0>BUDGET: print('[shard] budget reached'); break
        fn=funcs[i]
        try:
            r=di.decompileFunction(fn,30,ConsoleTaskMonitor())
            if r and r.decompileCompleted():
                c=r.getDecompiledFunction()
                if c:
                    cur.append('// FUNCTION %s %s\n%s\n'%(st(fn.getEntryPoint()),st(fn.getName()),st(c.getC())))
                    done+=1
                    if len(cur)>=CHUNK:
                        open(os.path.join(OUT,'part_%03d.c'%parts),'wb').write('\n'.join(cur).encode('utf-8','replace'))
                        parts+=1; cur=[]
            else: failed+=1
        except Exception: failed+=1
        if (i-START)%2500==0: print('[shard] progress',i-START,'done',done,'failed',failed)
    if cur: open(os.path.join(OUT,'part_%03d.c'%parts),'wb').write('\n'.join(cur).encode('utf-8','replace')); parts+=1
    json.dump({'start':START,'count':COUNT,'total_functions':len(funcs),'decompiled':done,
               'failed':failed,'parts':parts,'seconds':time.time()-T0},
              open(os.path.join(OUT,'shard_summary.json'),'w'),indent=2)
    print('[shard] DONE',done,failed)
except Exception:
    print('[shard] ERROR'); traceback.print_exc()
