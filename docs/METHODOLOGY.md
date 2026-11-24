# Methodology

1. **Payload** - the 4-way split APK was concatenated (broken ZIP central directory).
   Native libraries were recovered by scanning local ZIP headers directly. `libminecraftpe.so`
   is 342,231,392 bytes uncompressed, deflate compressed to 102,301,784 bytes.
2. **ELF fast-track** - `readelf`/`objdump`/`nm`/`strings` extract section/file-offset maps,
   all symbol tables, relocations, notes and every printable string. `strings -t d` gives
   the exact **file offset**; `map_offsets.py` converts it into virtual address + section,
   so any string can be located in the binary or in Ghidra.
3. **Ghidra full analysis** - `analyzeHeadless` imports the library with all default
   analyzers (ARM64), auto-naming, demangling, and a decompiler pass over every function.
   Exports are TSV/JSON/C so they are diffable and searchable without Ghidra.
4. **Categorisation** - keyword scoring over demangled C++ names and string literals assigns
   each symbol/function/string into one of 15 gameplay/technical categories.
5. **Publication** - results are attached to a private GitHub release and committed as
   generated Markdown. Downloading the release gives the complete exported dataset.

## What "offset + signature" means here
- `file_offset` - byte position in `libminecraftpe.so` (from `readelf -SW` / `strings -t d`).
- `vaddr` - virtual address inside the mapped ELF image (Ghidra `entry_point` uses this).
- `signature` - Ghidra's demangled function prototype (return type, name, parameters).
- `section` - ELF section (`.text`, `.rodata`, `.data.rel.ro`, ...) the offset belongs to.

These let you go from, e.g., a string `"grass"` to the exact code that references it
(search `06_xrefs.tsv` for its vaddr) and from there to the function signature in
`04_functions.tsv` and the decompiled body in `decompiled/part_*.c`.
