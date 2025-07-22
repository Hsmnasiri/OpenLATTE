#!/usr/bin/env bash
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 /path/to/binary.out"
  exit 1
fi

BINARY="$1"
BASE=$(basename "$BINARY")
BASE=${BASE%.*}

GHIDRA_ROOT="/mnt/z/Papers/RAG_Papers/ghidra_11.3.2_PUBLIC_20250415/ghidra_11.3.2_PUBLIC"
WORKSPACE="/mnt/z/Papers/MyRAG/LATTE_ReImplementing/ghidra-workspace"
SCRIPT_DIR="/mnt/z/Papers/MyRAG/LATTE_ReImplementing"
SINK_JSON="/mnt/z/Papers/MyRAG/LATTE_ReImplementing/results/sink_classification_CWE190_Integer_Overflow__char_fscanf_preinc_05.json"

# Run headless to export external functions
"$GHIDRA_ROOT/support/analyzeHeadless" \
  "$WORKSPACE" "${BASE}-Export" \
  -import "$BINARY" \
  -scriptPath "$SCRIPT_DIR" \
  -postScript VD_DF.py "$SINK_JSON" \
  -deleteProject

echo "Generated: $WORKSPACE/external_funcs_${BASE}.txt"