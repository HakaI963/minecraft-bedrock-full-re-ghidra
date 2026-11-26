#!/usr/bin/env python3
"""Build minecraft_re.db (SQLite) from all extracted TSVs for fast querying."""
import sqlite3,os,sys,glob,json,re
OUT=sys.argv[1] if len(sys.argv)>1 else 'out'
DB=os.path.join(OUT,'minecraft_re.db')
if os.path.exists(DB): os.remove(DB)
def findfile(name):
    for root,dirs,files in os.walk(OUT):
        if name in files: return os.path.join(root,name)
    return None
con=sqlite3.connect(DB); cur=con.cursor()
cur.executescript('''
PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;
CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE functions(addr INTEGER PRIMARY KEY, file_offset INTEGER, name TEXT, demangled TEXT, sig TEXT, size INTEGER, pattern TEXT, vclass TEXT);
CREATE TABLE calls(site INTEGER, callee INTEGER, callee_name TEXT, callee_demangled TEXT, pattern TEXT);
CREATE TABLE strxref(site INTEGER, target INTEGER, text TEXT, pattern TEXT);
CREATE TABLE vtables(vtable INTEGER, vclass TEXT, slot INTEGER, method INTEGER, msig TEXT);
CREATE TABLE symbols(addr INTEGER, name TEXT, demangled TEXT, stype TEXT, size INTEGER);
CREATE TABLE ids(ident TEXT, category TEXT, file_offset INTEGER, description TEXT);
CREATE TABLE strings(file_offset INTEGER, section TEXT, text TEXT);
CREATE TABLE blocks_props(category TEXT, string TEXT, file_offset INTEGER, pattern TEXT);
CREATE TABLE features(feature TEXT, string TEXT, file_offset INTEGER, pattern TEXT);
CREATE TABLE func_feat(name TEXT, vclass TEXT, sig TEXT, size INTEGER, pattern TEXT);
''')
def meta(k,v): cur.execute('INSERT OR REPLACE INTO meta VALUES(?,?)',(k,str(v)))
meta('game_version','1.26.66.1')
meta('lib_sha256','f5e2118cae3e2583424650d5fe0b937fa055df171cc87091019c654834dc338d')
meta('generated_by','HakaI963/minecraft-bedrock-full-re-ghidra GitHub Actions')
# ---- functions from master table ----
p=findfile('MASTER_OFFSET_SIGNATURE_TABLE.tsv')
rows=0
if p and os.path.exists(p):
    for line in open(p,errors='replace'):
        q=line.rstrip('\n').split('\t')
        if len(q)<6 or not q[0].startswith('0x'): continue
        try: a=int(q[0],16)
        except: continue
        fo=int(q[1],16) if q[1].startswith('0x') else None
        cur.execute('INSERT OR REPLACE INTO functions VALUES(?,?,?,?,?,?,?,?)',
                    (a,fo,q[3],q[3],q[4],0,None,q[2]))
        rows+=1
print('functions',rows)
# ---- masked patterns ----
p=findfile('FUNCTION_SIGNATURES_MASKED.tsv')
if p and os.path.exists(p):
    for line in open(p,errors='replace'):
        q=line.rstrip('\n').split('\t')
        if len(q)<4 or not q[0].startswith('0x'): continue
        try: a=int(q[0],16)
        except: continue
        cur.execute('UPDATE functions SET pattern=? WHERE addr=?',(q[2],a))
print('patterns merged')
# ---- symbols ----
p=findfile('ALL_SYMBOLS_DEMANGLED.tsv')
if p and os.path.exists(p):
    n=0
    for line in open(p,errors='replace'):
        q=line.rstrip('\n').split('\t')
        if len(q)<6 or not q[0].startswith('0x'): continue
        try: a=int(q[0],16)
        except: continue
        cur.execute('INSERT INTO symbols VALUES(?,?,?,?,?)',(a,q[4],q[5],q[2],int(q[1]) if q[1].isdigit() else 0))
        n+=1
        if n%50000==0: con.commit()
    print('symbols',n)
# ---- vtables ----
p=findfile('vtables.tsv')
if p and os.path.exists(p):
    n=0
    for line in open(p,errors='replace'):
        q=line.rstrip('\n').split('\t')
        if len(q)<8 or not q[0].startswith('0x'): continue
        try:
            cur.execute('INSERT INTO vtables VALUES(?,?,?,?,?)',
                (int(q[0],16),q[2],int(q[5]) if q[5].isdigit() else 0,
                 int(q[6],16) if q[6].startswith('0x') else 0,q[7]))
            n+=1
        except: pass
        if n%50000==0: con.commit()
    print('vtables',n)
# ---- ids ----
p=findfile('minecraft_ids.tsv')
if p and os.path.exists(p):
    n=0
    for line in open(p,errors='replace'):
        q=line.rstrip('\n').split('\t')
        if len(q)<6 or not q[2].isdigit(): continue
        cur.execute('INSERT INTO ids VALUES(?,?,?,?)',(q[0],q[1],int(q[2]),q[5]))
        n+=1
    print('ids',n)
# ---- strings ----
p=findfile('strings_mapped.tsv')
if p and os.path.exists(p):
    n=0; batch=[]
    for line in open(p,errors='replace'):
        q=line.rstrip('\n').split('\t')
        if len(q)<4: continue
        try: batch.append((int(q[0]),q[2],q[3]))
        except: continue
        if len(batch)>=20000:
            cur.executemany('INSERT INTO strings VALUES(?,?,?)',batch); batch=[]; n+=20000
            con.commit()
    if batch: cur.executemany('INSERT INTO strings VALUES(?,?,?)',batch); n+=len(batch)
    con.commit(); print('strings',n)
# ---- call graph ----
for f in sorted(glob.glob(os.path.join(OUT,'relationships','RELATIONSHIP_CALLS.tsv.part*.tsv'))):
    n=0; batch=[]
    for line in open(f,errors='replace'):
        q=line.rstrip('\n').split('\t')
        if len(q)<6 or not q[0].startswith('0x'): continue
        try: batch.append((int(q[0],16),int(q[1],16),q[2],q[3],q[5]))
        except: continue
        if len(batch)>=50000:
            cur.executemany('INSERT INTO calls VALUES(?,?,?,?,?)',batch); batch=[]; n+=50000
    if batch: cur.executemany('INSERT INTO calls VALUES(?,?,?,?,?)',batch); n+=len(batch)
    con.commit(); print('calls from',os.path.basename(f),n)
# ---- string xrefs ----
for f in sorted(glob.glob(os.path.join(OUT,'relationships','RELATIONSHIP_STRINGS.tsv.part*.tsv'))):
    n=0; batch=[]
    for line in open(f,errors='replace'):
        q=line.rstrip('\n').split('\t')
        if len(q)<4 or not q[0].startswith('0x'): continue
        try: batch.append((int(q[0],16),int(q[1],16),q[2],q[3]))
        except: continue
        if len(batch)>=50000:
            cur.executemany('INSERT INTO strxref VALUES(?,?,?,?)',batch); batch=[]; n+=50000
    if batch: cur.executemany('INSERT INTO strxref VALUES(?,?,?,?)',batch); n+=len(batch)
    con.commit(); print('strxref from',os.path.basename(f),n)
# ---- block props / features ----
for tbl,fn in [('blocks_props','BLOCK_PROPERTIES.tsv'),('features','CUSTOM_CONTENT_FEATURES.tsv')]:
    p=findfile(fn)
    if p and os.path.exists(p):
        n=0
        for line in open(p,errors='replace'):
            q=line.rstrip('\n').split('\t')
            if len(q)<4 or not q[2].startswith('0x'): continue
            cur.execute('INSERT INTO %s VALUES(?,?,?,?)'%tbl,(q[0],q[1],int(q[2],16),q[3])); n+=1
        print(tbl,n)
# ---- indexes ----
cur.executescript('''
CREATE INDEX idx_fn_name ON functions(name);
CREATE INDEX idx_fn_pat ON functions(pattern);
CREATE INDEX idx_sym_name ON symbols(name);
CREATE INDEX idx_sym_dm ON symbols(demangled);
CREATE INDEX idx_calls_site ON calls(site);
CREATE INDEX idx_calls_callee ON calls(callee);
CREATE INDEX idx_strxref_site ON strxref(site);
CREATE INDEX idx_strxref_target ON strxref(target);
CREATE INDEX idx_strxref_text ON strxref(text);
CREATE INDEX idx_vt_method ON vtables(method);
CREATE INDEX idx_vt_class ON vtables(vclass);
CREATE INDEX idx_ids_ident ON ids(ident);
CREATE INDEX idx_strings_text ON strings(text);
''')
con.commit()
for t in ['functions','calls','strxref','vtables','symbols','ids','strings','blocks_props','features']:
    c=cur.execute('SELECT COUNT(*) FROM %s'%t).fetchone()[0]
    meta('count_'+t,c); print(t,c)
con.commit(); con.close()
print('DB',DB,os.path.getsize(DB))
