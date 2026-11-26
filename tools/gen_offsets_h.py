#!/usr/bin/env python3
"""Generate offsets.h from minecraft_re.db for a set of names.
Usage: gen_offsets_h.py "REGISTER_BLOCK" "SET_CREATIVE_CATEGORY" ... > offsets.h
"""
import sqlite3,sys,os
db=os.environ.get('MC_DB') or os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','minecraft_re.db')
if not os.path.exists(db): db=os.path.join(os.path.dirname(os.path.abspath(__file__)),'minecraft_re.db')
con=sqlite3.connect('file:%s?mode=ro'%db,uri=True); c=con.cursor()
ver=c.execute("SELECT v FROM meta WHERE k='game_version'").fetchone()
sha=c.execute("SELECT v FROM meta WHERE k='lib_sha256'").fetchone()
print('// libminecraftpe.so %s  sha256 %s'%(ver[0] if ver else '?',sha[0] if sha else '?'))
print('#pragma once\n#include <cstdint>\nnamespace off {')
for want in sys.argv[1:]:
    r=c.execute('SELECT addr,name,pattern FROM functions WHERE name LIKE ? ORDER BY LENGTH(name) LIMIT 1',(want,)).fetchone()
    if not r:
        r=c.execute('SELECT addr,demangled,NULL FROM symbols WHERE demangled LIKE ? ORDER BY LENGTH(demangled) LIMIT 1',('%'+want+'%',)).fetchone()
    if r: print('constexpr uintptr_t %-28s = 0x%x; // %s'%(want.replace('::','_'),r[0],(r[1] or '')[:70]))
    else: print('// NOT FOUND: %s'%want)
print('}')
