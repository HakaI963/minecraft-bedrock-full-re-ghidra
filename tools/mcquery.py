#!/usr/bin/env python3
"""Minecraft RE query tool. Works on minecraft_re.db (SQLite).

Usage:
  mcquery.py addr 0x989ef20            # what is at this address
  mcquery.py name registerBlock        # find functions by name
  mcquery.py string "crafting_table"   # strings + who references them
  mcquery.py callers 0x1039d434        # who calls this function
  mcquery.py callees 0x1039d434        # what this function calls
  mcquery.py class BlockGraphics       # vtable/methods of a class
  mcquery.py id minecraft:stone        # vanilla identifier
  mcquery.py search <regex>            # search everything
  mcquery.py info                      # database stats
"""
import sqlite3,sys,os,re,textwrap
DB=os.environ.get('MC_DB') or os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','minecraft_re.db')
if not os.path.exists(DB): DB=os.path.join(os.path.dirname(os.path.abspath(__file__)),'minecraft_re.db')
if not os.path.exists(DB):
    sys.exit('minecraft_re.db not found (set MC_DB=/path/to/minecraft_re.db)')
con=sqlite3.connect('file:%s?mode=ro'%DB,uri=True); con.row_factory=sqlite3.Row
c=con.cursor()
def hr(t): print('\n=== %s ==='%t)
def show(rows,cols=None,limit=200):
    rows=list(rows)
    if not rows: print('  (none)'); return
    cols=cols or rows[0].keys()
    w={k:min(max(len(k),*(len(str(r[k])) for r in rows[:limit])),70) for k in cols}
    print('  '+'  '.join(k[:w[k]].ljust(w[k]) for k in cols))
    print('  '+'  '.join('-'*w[k] for k in cols))
    for r in rows[:limit]:
        print('  '+'  '.join(str(r[k])[:w[k]].ljust(w[k]) for k in cols))
    if len(rows)>limit: print('  ... %d more'%len(rows))
def resolve_fn(addr):
    r=c.execute('SELECT * FROM functions WHERE addr=?',(addr,)).fetchone()
    if r: return dict(r)
    r=c.execute('SELECT * FROM functions WHERE addr<=? ORDER BY addr DESC LIMIT 1',(addr,)).fetchone()
    if r and addr-r['addr']<0x800:
        d=dict(r); d['delta']=addr-r['addr']; return d
    return None
cmd=sys.argv[1] if len(sys.argv)>1 else 'info'
arg=sys.argv[2] if len(sys.argv)>2 else ''
if cmd=='info':
    hr('database'); print('  file:',DB,'size: %.1f MB'%(os.path.getsize(DB)/1e6))
    for k,v in c.execute("SELECT k,v FROM meta ORDER BY k"): print('  %-22s %s'%(k,v))
elif cmd=='addr':
    a=int(arg,16) if arg.lower().startswith('0x') else int(arg)
    hr('address 0x%x'%a)
    f=resolve_fn(a)
    if f:
        print('  function : %s'%f['name'])
        print('  sig      : %s'%(f['sig'] or '')[:120])
        print('  class    : %s'%f['vclass'])
        off = f.get('delta',0)
        print('  pattern  : %s'%(f['pattern'] or '')[:160])
        if off: print('  NOTE: +0x%x into this function'%off)
    s=c.execute('SELECT * FROM symbols WHERE addr=?',(a,)).fetchone()
    if s: print('  symbol   : %s  (%s, %d bytes)'%(s['demangled'],s['stype'],s['size']))
    for r in c.execute('SELECT * FROM vtables WHERE vtable=? LIMIT 5',(a,)):
        print('  vtable   : class %s slot %d -> 0x%x'%(r['vclass'],r['slot'],r['method']))
    for r in c.execute('SELECT * FROM vtables WHERE method=? LIMIT 5',(a,)):
        print('  vmethod  : %s slot %d  %s'%(r['vclass'],r['slot'],(r['msig'] or '')[:80]))
    n=c.execute('SELECT COUNT(*) FROM calls WHERE callee=?',(a,)).fetchone()[0]
    print('  callers  : %d'%n)
elif cmd=='name':
    hr('functions matching %r'%arg)
    show(c.execute('SELECT addr,name,size,substr(sig,1,60) sig FROM functions WHERE name LIKE ? LIMIT 400',('%'+arg+'%',)),
         ['addr','name','size','sig'])
    hr('symbols matching %r'%arg)
    show(c.execute('SELECT addr,demangled,stype,size FROM symbols WHERE demangled LIKE ? LIMIT 400',('%'+arg+'%',)),
         ['addr','demangled','stype','size'])
elif cmd=='string':
    hr('strings matching %r'%arg)
    rs=c.execute('SELECT file_offset,text FROM strings WHERE text LIKE ? LIMIT 200',('%'+arg+'%',)).fetchall()
    show(rs,['file_offset','text'])
    if rs:
        hr('who references them (top 60)')
        out=[]
        for r in rs[:20]:
            for x in c.execute('SELECT site,target,substr(pattern,1,40) pattern FROM strxref WHERE target=? LIMIT 20',(r['file_offset'],)):
                out.append(x)
        show(out,['site','target','pattern'],60)
elif cmd in ('callers','callees'):
    a=int(arg,16) if arg.lower().startswith('0x') else int(arg)
    if cmd=='callers':
        hr('callers of 0x%x'%a)
        show(c.execute('SELECT site,callee_name,substr(pattern,1,40) pattern FROM calls WHERE callee=? LIMIT 300',(a,)),
             ['site','callee_name','pattern'])
        n=c.execute('SELECT COUNT(*) FROM calls WHERE callee=?',(a,)).fetchone()[0]
        print('  total callers: %d'%n)
    else:
        hr('callees of 0x%x'%a)
        show(c.execute('SELECT callee,callee_demangled,substr(pattern,1,40) pattern FROM calls WHERE site=? LIMIT 300',(a,)),
             ['callee','callee_demangled','pattern'])
elif cmd=='class':
    hr('class matching %r'%arg)
    show(c.execute('SELECT DISTINCT vtable,vclass,size FROM (SELECT vtable,vclass,COUNT(*) size FROM vtables WHERE vclass LIKE ? GROUP BY vtable) LIMIT 60',
                   ('%'+arg+'%',)),['vtable','vclass','size'])
    hr('methods')
    show(c.execute('SELECT vclass,slot,method,substr(msig,1,80) sig FROM vtables WHERE vclass LIKE ? ORDER BY vclass,slot LIMIT 200',('%'+arg+'%',)),
         ['vclass','slot','method','sig'])
elif cmd=='id':
    hr('identifiers matching %r'%arg)
    show(c.execute('SELECT ident,category,file_offset,description FROM ids WHERE ident LIKE ? LIMIT 200',('%'+arg+'%',)),
         ['ident','category','file_offset','description'])
elif cmd=='search':
    rx=arg
    hr('functions');       show(c.execute("SELECT addr,name,substr(sig,1,50) sig FROM functions WHERE name REGEXP ? LIMIT 60",(rx,)) if False else
                                c.execute("SELECT addr,name,substr(sig,1,50) sig FROM functions WHERE name LIKE ? LIMIT 60",('%'+rx+'%',)),['addr','name','sig'],60)
    hr('symbols');         show(c.execute("SELECT addr,demangled FROM symbols WHERE demangled LIKE ? LIMIT 60",('%'+rx+'%',)),['addr','demangled'],60)
    hr('strings');         show(c.execute("SELECT file_offset,text FROM strings WHERE text LIKE ? LIMIT 60",('%'+rx+'%',)),['file_offset','text'],60)
    hr('ids');             show(c.execute("SELECT ident,category,file_offset FROM ids WHERE ident LIKE ? LIMIT 60",('%'+rx+'%',)),['ident','category','file_offset'],60)
else:
    print(__doc__)
