#!/usr/bin/env bash
set -euo pipefail
GHIDRA_DIR="$1"; PROJECT="$2"; LIB="$3"; OUT="$4"; SCRIPTDIR="$5"; BUDGET="${6:-9600}"
mkdir -p "$PROJECT" "$OUT/ghidra"
export MAXMEM=12288
export JAVA_OPTS="-Xmx12G -XX:+UseG1GC -Djava.awt.headless=true"
echo "[run_ghidra] Ghidra=$GHIDRA_DIR lib=$LIB budget=${BUDGET}s"
"$GHIDRA_DIR/support/analyzeHeadless" "$PROJECT" mcpe \
  -import "$LIB" \
  -scriptPath "$SCRIPTDIR" \
  -postScript ghidra_export.py "$OUT/ghidra" "$BUDGET" \
  -analysisTimeoutPerFile 0 \
  2>&1 | tee "$OUT/ghidra/ghidra_console.log"
