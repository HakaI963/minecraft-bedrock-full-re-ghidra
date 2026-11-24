# Minecraft Bedrock - full automated reverse engineering

**Target:** `com.mojang.minecraftpe` v1.26.60.4 (arm64-v8a), `libminecraftpe.so` = 342,231,392 bytes.
**Method:** GitHub Actions runs Ghidra headless auto-analysis + ELF/binutils export, then categorises
every recovered name, offset, signature and string. Nothing is filtered by "importance".

## Repository layout
- `.github/workflows/full-re.yml` - whole pipeline (no local machine needed).
- `scripts/ghidra_export.py` - Ghidra Jython script: functions, signatures, symbols,
  defined data, strings, xrefs, decompiled C (all functions), datatypes, external symbols.
- `scripts/elf_extract.sh` - binutils fast path: every ELF section/program header,
  dynamic + full symbol tables, relocations, notes, all strings with file offsets, full disassembly.
- `scripts/categorize.py` - assigns every entry to a category (blocks, items, world,
  entities, menus, network, rendering, audio, physics, NBT, security, ...) preserving offsets/signatures.
- `native/` - local staging area (not committed; payload is a private release asset).
- release `native-payload` - compressed native libs uploaded by the operator.
- release `re-result` - all generated exports, downloaded locally at the end.

## Run
1. Upload `native-libs.tar.zst` to private release `native-payload`.
2. Push to `main` or use **Run workflow**.
3. Download release `re-result`.

## Scope / limits (read this)
Ghidra is a static analyser. It recovers names, addresses, signatures, decompiled C,
strings and cross references; it does **not** produce original Mojang source code, and
it cannot reliably label gameplay semantics (e.g. "this exact offset is the grass block")
without dynamic/runtime evidence. Categorisation is heuristic, based on recovered C++
symbol names and string literals. Full decompilation of a 342 MB stripped C++ binary is
large (multi-GB) and may hit GitHub-hosted runner resource limits; the ELF fast-track
results are published first so that useful output always exists.

Reverse engineering may be restricted by the game's EULA/local law. Use for interoperability,
security research or personal education only. No proprietary source is included - only
facts mechanically recovered from a binary you supplied.
