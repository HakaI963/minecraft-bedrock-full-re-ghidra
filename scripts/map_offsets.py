import re, sys, bisect
lib, sections_file, strings_file, out = sys.argv[1:5]
secs = []
lines = open(sections_file, errors='replace').read().splitlines()
for line in lines:
    m = re.match(r'^\s*\[\s*(\d+)\]\s+(.*)$', line)
    if not m:
        continue
    p = m.group(2).split()
    if len(p) < 5:
        continue
    name, typ = p[0], p[1]
    if re.fullmatch(r'[0-9a-fA-F]+', typ):   # section 0 (NULL) has no type column
        continue
    try:
        addr, off = int(p[2], 16), int(p[3], 16)
    except ValueError:
        continue
    size = 0
    if len(p) >= 5 and re.fullmatch(r'[0-9a-fA-F]+', p[4]):
        size = int(p[4], 16)
    elif lines.index(line) + 1 < len(lines):
        m2 = re.match(r'\s*([0-9a-fA-F]+)\s', lines[lines.index(line) + 1])
        if m2:
            size = int(m2.group(1), 16)
    if size:
        secs.append((off, off + size, addr, name))
secs.sort()
starts = [s[0] for s in secs]
with open(out, 'w', errors='replace') as o:
    o.write('file_offset\tvaddr\tsection\tstring\n')
    for line in open(strings_file, errors='replace'):
        if not line.strip():
            continue
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        try:
            off = int(parts[0])
        except ValueError:
            continue
        idx = bisect.bisect_right(starts, off) - 1
        vaddr, name = -1, 'UNMAPPED'
        if idx >= 0 and off < secs[idx][1]:
            _, _, base, name = secs[idx]
            vaddr = base + (off - secs[idx][0])
        o.write('%d\t%d\t%s\t%s' % (off, vaddr, name, parts[1].rstrip('\n')))
        o.write('\n')
print('mapped strings written to', out, 'sections', len(secs))
