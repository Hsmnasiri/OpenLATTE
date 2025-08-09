#!/usr/bin/env bash
set -euo pipefail

# Inputs
BASE="CWE190_Integer_Overflow__char_fscanf_preinc_05"  
ROOT="/mnt/z/Papers/MyRAG/LATTE_ReImplementing/RAG_KB/out/${BASE}"

FLOWCARDS="${ROOT}/results/kb_flowcards_${BASE}.jsonl"
PROMPTS_DIR="${ROOT}/results"

SEM_PROMPTS="${PROMPTS_DIR}/prompts_semantics.txt"
RC_PROMPTS="${PROMPTS_DIR}/prompts_rootcause.txt"
FIX_PROMPTS="${PROMPTS_DIR}/prompts_fix.txt"

ANN_SEM="${PROMPTS_DIR}/ann_semantics_${BASE}.jsonl"
ANN_RC="${PROMPTS_DIR}/ann_rootcause_${BASE}.jsonl"
ANN_FIX="${PROMPTS_DIR}/ann_fix_${BASE}.jsonl"

KB_READY="${ROOT}/results/kb_ready_${BASE}.jsonl"

# Choose backend: gemini | local
BACKEND="${BACKEND:-gemini}"
TEMPERATURE="${TEMPERATURE:-0.2}"
MAXTOK="${MAXTOK:-400}"
PYTHON="${PYTHON:-python3}"
SCRIPT_DIR="/mnt/z/Papers/MyRAG/LATTE_ReImplementing/RAG_KB"

echo "[1/3] Semantics..."
${PYTHON} "${SCRIPT_DIR}/run_stepwise_annotation.py" \
  --prompts "${SEM_PROMPTS}" \
  --out_jsonl "${ANN_SEM}" \
  --backend "${BACKEND}" \
  --temperature "${TEMPERATURE}" \
  --max_tokens "${MAXTOK}"

echo "[2/3] Root-cause..."
${PYTHON} "${SCRIPT_DIR}/run_stepwise_annotation.py" \
  --prompts "${RC_PROMPTS}" \
  --out_jsonl "${ANN_RC}" \
  --backend "${BACKEND}" \
  --temperature "${TEMPERATURE}" \
  --max_tokens "${MAXTOK}"

echo "[3/3] Fix..."
${PYTHON} "${SCRIPT_DIR}/run_stepwise_annotation.py" \
  --prompts "${FIX_PROMPTS}" \
  --out_jsonl "${ANN_FIX}" \
  --backend "${BACKEND}" \
  --temperature "${TEMPERATURE}" \
  --max_tokens "${MAXTOK}"

echo "[MERGE] Build final KB JSONL..."
${PYTHON} "${SCRIPT_DIR}/kb_merge_annotations.py" \
  --flowcards "${FLOWCARDS}" \
  --semantics_jsonl "${ANN_SEM}" \
  --rootcause_jsonl "${ANN_RC}" \
  --fix_jsonl "${ANN_FIX}" \
  --out_jsonl "${KB_READY}"

echo "Done."
echo "KB file: ${KB_READY}"
