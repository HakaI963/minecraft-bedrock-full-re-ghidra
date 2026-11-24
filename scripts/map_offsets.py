import re, sys, bisect
lib, sections_file, strings_file, out = sys.argv[1:5]
secs = []
lines = open(sections_file, errors='replace').read().splitlines()
for i, line in enumerate(lines):
    m = re.search(r'\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)', line)
    if not m:
        continue
    name, typ, addr, off = m.group(1), m.group(2), int(m.group(3), 16), int(m.group(4), 16)
    size = 0
    if i + 1 < len(lines):
        m2 = re.match(r'\s+([0-9a-fA-F]+)\s', lines[i + 1])
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
