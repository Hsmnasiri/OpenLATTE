#!/usr/bin/env bash
set -euo pipefail

GHIDRA_ROOT="/mnt/z/Papers/RAG_Papers/ghidra_11.3.2_PUBLIC_20250415/ghidra_11.3.2_PUBLIC"
WORKSPACE="/mnt/z/Papers/MyRAG/LATTE_ReImplementing/ghidra-workspace"
SCRIPT_DIR="/mnt/z/Papers/MyRAG/LATTE_ReImplementing" # Directory where find_dangerous_flows.py is located

# --- TARGET BINARY ---
BINARY_PATH="/mnt/z/Papers/MyRAG/LATTE_ReImplementing/build/build/stripped/CWE78_OS_Command_Injection__char_connect_socket_execl_05.out"
#dbg binary
#BINARY_PATH="/mnt/z/Papers/MyRAG/LATTE_ReImplementing/build/dbg/CWE190_Integer_Overflow__char_fscanf_preinc_05.unstripped"

BASE_NAME=$(basename "$BINARY_PATH" .out)

# Ensure these files exist before running!
SINK_FILE="$SCRIPT_DIR/results/sink_classification_${BASE_NAME}.json"
SOURCE_FILE="$SCRIPT_DIR/results/source_classification_${BASE_NAME}.json"
OUTPUT_FILE="$SCRIPT_DIR/results/dangerous_flows_${BASE_NAME}.json"
echo "find_dangerous_flows.py --sinks "$SINK_FILE" --sources "$SOURCE_FILE" --output "$OUTPUT_FILE""

if [[ ! -f "$SINK_FILE" ]]; then
  echo "Sink file not found: $SINK_FILE"
  exit 1
fi
if [[ ! -f "$SOURCE_FILE" ]]; then
  echo "Source file not found: $SOURCE_FILE"
  exit 1
fi
if [[ ! -f "$BINARY_PATH" ]]; then
  echo "Binary file not found: $BINARY_PATH"
  exit 1
fi
if [[ ! -d "$SCRIPT_DIR" ]]; then
  echo "Script directory not found: $SCRIPT_DIR"
  exit 1
fi

"$GHIDRA_ROOT/support/analyzeHeadless" \
  "$WORKSPACE" "${BASE_NAME}-DF-Analysis" \
  -import "$BINARY_PATH" \
  -scriptPath "$SCRIPT_DIR" \
  -postScript find_dangerous_flows.py --sinks "$SINK_FILE" --sources "$SOURCE_FILE" --output "$OUTPUT_FILE" \
  -deleteProject

echo "Analysis complete. DFs saved to $OUTPUT_FILE"