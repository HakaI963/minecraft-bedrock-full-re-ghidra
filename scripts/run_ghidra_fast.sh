#!/usr/bin/env bash
set -euo pipefail
GHIDRA_DIR="$1"; PROJECT="$2"; LIB="$3"; OUT="$4"; SCRIPTDIR="$5"; BUDGET="${6:-1800}"
mkdir -p "$PROJECT" "$OUT/ghidra"
export MAXMEM=8192
("$GHIDRA_DIR/support/analyzeHeadless" "$PROJECT" mcpe_fast \
  -import "$LIB" -noanalysis -scriptPath "$SCRIPTDIR" \
  -postScript ghidra_fast_export.py "$OUT/ghidra" "$BUDGET" \
  2>&1 || true) | grep -aE '^\[fast\]|ERROR|Exception|Headless|IMPORT|SCRIPT|REPORT|ANALYZ' | tail -200 | tee "$OUT/ghidra/ghidra_fast_console.log"
