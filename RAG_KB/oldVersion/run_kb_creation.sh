#!/usr/bin/env bash
set -euo pipefail

# --- Configuration ---
BASE="CWE190_Integer_Overflow__char_fscanf_preinc_05"
ROOT_DIR="/mnt/z/Papers/MyRAG/LATTE_ReImplementing/RAG_KB/out/${BASE}"
SCRIPT_DIR="/mnt/z/Papers/MyRAG/LATTE_ReImplementing/RAG_KB"
PYTHON="${PYTHON:-python3}"
BACKEND="${BACKEND:-gemini}"

# --- File Paths ---
CALLCHAINS_IN="${ROOT_DIR}/build/kb_callchains_${BASE}.json"
PAIRED_FLOWS_OUT="${ROOT_DIR}/build/kb_paired_flows_${BASE}.json"
PROMPTS_DIR_OUT="${ROOT_DIR}/results/prompts_paired"
KB_FINAL_OUT="${ROOT_DIR}/results/kb_annotated_pairs.jsonl"

# --- Pipeline ---

# Step 1: Pair and filter the raw call chains from Ghidra
echo "[1/3] Pairing and filtering flows..."
$PYTHON "${SCRIPT_DIR}/pair_and_filter_flows.py" \
  --input "${CALLCHAINS_IN}" \
  --output "${PAIRED_FLOWS_OUT}"

# Step 2: Generate the structured annotation prompts for each pair
echo "[2/3] Generating paired annotation prompts..."
$PYTHON "${SCRIPT_DIR}/generate_paired_prompts.py" \
  --input "${PAIRED_FLOWS_OUT}" \
  --output-dir "${PROMPTS_DIR_OUT}"

# Step 3: Run the annotation and create the final knowledge base
echo "[3/3] Annotating pairs and creating the knowledge base..."
$PYTHON "${SCRIPT_DIR}/annotate_pairs.py" \
  --paired-flows "${PAIRED_FLOWS_OUT}" \
  --prompts-dir "${PROMPTS_DIR_OUT}" \
  --output "${KB_FINAL_OUT}" \
  --backend "${BACKEND}"

echo -e "\n\n✅ Knowledge Base creation complete!"
echo "   Final KB is located at: ${KB_FINAL_OUT}"
