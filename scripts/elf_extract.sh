#!/usr/bin/env bash
set -euo pipefail
LIB=$(realpath "$1"); OUT=$(realpath -m "$2"); SCRIPTDIR=$(realpath "$3")
mkdir -p "$OUT/elf"
cd "$OUT/elf"
sha256sum "$LIB" > sha256.txt
file "$LIB" > file.txt || true
stat -c '%n %s bytes' "$LIB" > size.txt
readelf -hW "$LIB" > header.txt
readelf -lW "$LIB" > program_headers.txt
readelf -SW "$LIB" > sections.txt
readelf -sW "$LIB" > symbols_all.txt
readelf --dyn-syms -W "$LIB" > symbols_dynamic.txt
readelf -dW "$LIB" > dynamic.txt
readelf -rW "$LIB" > relocations.txt
readelf -nW "$LIB" > notes.txt
objdump -f -p "$LIB" > objdump_private.txt || true
nm -D --defined-only "$LIB" > nm_dynamic_defined.txt || true
strings -a -t d "$LIB" > strings_offsets.txt
python3 "$SCRIPTDIR/map_offsets.py" "$LIB" sections.txt strings_offsets.txt strings_mapped.tsv
objdump -d -C --no-show-raw-insn "$LIB" | zstd -q -T4 -3 -o disassembly.txt.zst
ls -lh
