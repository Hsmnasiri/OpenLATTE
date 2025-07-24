#!/usr/bin/env bash
set -euo pipefail

# This script automates the process of extracting decompiled code for the knowledge base.
# It uses a symbol map (from an unstripped binary) to find the correct functions
# in a stripped binary.

# Usage: ./run_export_kb.sh <basename_of_testcase>
# Example: ./run_export_kb.sh CWE190_Integer_Overflow__char_fscanf_add_07

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <basename_of_testcase>"
    exit 1
fi

# --- CONFIGURATION ---
GHIDRA_ROOT="/mnt/z/Papers/RAG_Papers/ghidra_11.3.2_PUBLIC_20250415/ghidra_11.3.2_PUBLIC"
WORKSPACE="/mnt/z/Papers/MyRAG/LATTE_ReImplementing/ghidra-workspace"
SCRIPT_DIR="/mnt/z/Papers/MyRAG/LATTE_ReImplementing"
BINARY_NAME="$1"

# --- TARGET THE STRIPPED BINARY FOR ANALYSIS ---
STRIPPED_BINARY_PATH="$SCRIPT_DIR/build/stripped/${BINARY_NAME}.out"

# --- DEFINE INPUT AND OUTPUT FILE PATHS ---
SYMBOL_MAP_FILE="$SCRIPT_DIR/build/symbol_map_${BINARY_NAME}.json"
OUTPUT_KB_FILE="$SCRIPT_DIR/build/decompiled_kb_${BINARY_NAME}.json"

# Check if the required symbol map exists
if [ ! -f "$SYMBOL_MAP_FILE" ]; then
    echo "[ERROR] Symbol map not found at: $SYMBOL_MAP_FILE"
    echo "Please run the 'run_map_symbols.sh' script first for this test case."
    exit 1
fi

echo "[INFO] Starting Ghidra to export KB functions for: $BINARY_NAME"
echo "[INFO] Using symbol map: $SYMBOL_MAP_FILE"
echo "[INFO] Analyzing stripped binary: $STRIPPED_BINARY_PATH"
echo "[INFO] Saving output to: $OUTPUT_KB_FILE"

# --- RUN HEADLESS ANALYSIS ---
"$GHIDRA_ROOT/support/analyzeHeadless" \
  "$WORKSPACE" "${BINARY_NAME}-KB-Export" \
  -import "$STRIPPED_BINARY_PATH" \
  -scriptPath "$SCRIPT_DIR" \
  -postScript export_kb_functions.py --map "$SYMBOL_MAP_FILE" --output "$OUTPUT_KB_FILE" \
  -deleteProject

echo "[SUCCESS] Knowledge base function export complete."