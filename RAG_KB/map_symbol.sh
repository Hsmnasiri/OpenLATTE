#!/usr/bin/env bash
set -euo pipefail

# Ghidra paths
GHIDRA_ROOT="/mnt/z/Papers/RAG_Papers/ghidra_11.3.2_PUBLIC_20250415/ghidra_11.3.2_PUBLIC"
WORKSPACE="/mnt/z/Papers/MyRAG/LATTE_ReImplementing/ghidra-workspace"
SCRIPT_DIR="/mnt/z/Papers/MyRAG/LATTE_ReImplementing"
BINARY_NAME="CWE190_Integer_Overflow__char_fscanf_preinc_05"

UNSTRIPPED_BINARY_PATH="$SCRIPT_DIR/build/dbg/${BINARY_NAME}.unstripped"

"$GHIDRA_ROOT/support/analyzeHeadless" \
  "$WORKSPACE" "${BINARY_NAME}-SymbolMap" \
  -import "$UNSTRIPPED_BINARY_PATH" \
  -scriptPath "$SCRIPT_DIR" \
  -postScript map_symbols.py \
  -deleteProject

echo "Symbol map created: build/symbol_map_${BINARY_NAME}.json"
