#!/usr/bin/env bash
set -uo pipefail
GHIDRA_DIR="$1"; PROJECT="$2"; LIB="$3"; OUT="$4"; SCRIPTDIR="$5"; BUDGET="${6:-9600}"
mkdir -p "$PROJECT" "$OUT"
export MAXMEM=8192
("$GHIDRA_DIR/support/analyzeHeadless" "$PROJECT" mcpe \
  -import "$LIB" -scriptPath "$SCRIPTDIR" \
  -postScript ghidra_export.py "$OUT" "$BUDGET" \
  2>&1 || true) | grep -aE '^\[export\]|ERROR|Exception|Headless|IMPORT|SCRIPT|REPORT|ANALYZ|ANALYS' | tail -300 | tee "$OUT/ghidra_full_console.log"
