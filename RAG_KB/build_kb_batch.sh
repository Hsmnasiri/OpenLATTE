#!/usr/bin/env bash
set -euo pipefail

# === CONFIGURATION ===
PROJECT_ROOT="/mnt/z/Papers/MyRAG/LATTE_ReImplementing"
RAG_KB_DIR="${PROJECT_ROOT}/RAG_KB"
OUTPUT_DIR="${RAG_KB_DIR}/out"
PYTHON="${PYTHON:-python3}"
BACKEND="${BACKEND:-gemini}"

# --- SCRIPT START ---
echo "### Starting Batch Knowledge Base Creation ###"

# Create temporary directories
ALL_PROMPTS_DIR="${RAG_KB_DIR}/all_prompts"
ALL_PAIRED_FLOWS_DIR="${RAG_KB_DIR}/all_paired_flows"
rm -rf "${ALL_PROMPTS_DIR}" "${ALL_PAIRED_FLOWS_DIR}"
mkdir -p "${ALL_PROMPTS_DIR}" "${ALL_PAIRED_FLOWS_DIR}"

# Step 1 & 2: Loop through all Ghidra outputs to pair flows and generate prompts
find "${OUTPUT_DIR}" -type f -name "kb_callchains_*.json" | while read -r CALLCHAINS_FILE; do
    BASE_NAME=$(basename "${CALLCHAINS_FILE}" .json | sed 's/kb_callchains_//')
    echo "--- Processing pairs and prompts for: ${BASE_NAME} ---"

    PAIRED_FLOWS_OUT="${OUTPUT_DIR}/${BASE_NAME}/build/kb_paired_flows_${BASE_NAME}.json"
    PROMPTS_DIR_OUT="${OUTPUT_DIR}/${BASE_NAME}/results/prompts_paired"

    # Pair and filter flows
    $PYTHON "${RAG_KB_DIR}/pair_and_filter_flows.py" \
      --input "${CALLCHAINS_FILE}" \
      --output "${PAIRED_FLOWS_OUT}"

    # Generate paired prompts
    $PYTHON "${RAG_KB_DIR}/generate_paired_prompts.py" \
      --input "${PAIRED_FLOWS_OUT}" \
      --output-dir "${PROMPTS_DIR_OUT}"

    # Copy generated prompts and paired_flows to central directories
    find "${PROMPTS_DIR_OUT}" -name "*.txt" -type f -exec cp {} "${ALL_PROMPTS_DIR}/" \;
    if [ -f "${PAIRED_FLOWS_OUT}" ]; then
        cp "${PAIRED_FLOWS_OUT}" "${ALL_PAIRED_FLOWS_DIR}/"
    fi
done

# --- Step 3: Consolidate all paired_flows.json files ---
echo -e "\n--- Consolidating all paired flow files ---"
CONSOLIDATED_PAIRED_FLOWS="${RAG_KB_DIR}/consolidated_paired_flows.json"
# Use jq to merge all JSON arrays into a single array
jq -s 'add' ${ALL_PAIRED_FLOWS_DIR}/*.json > "${CONSOLIDATED_PAIRED_FLOWS}"
echo "   Consolidated file created at: ${CONSOLIDATED_PAIRED_FLOWS}"


# --- Step 4: Annotate all prompts at once ---
echo -e "\n--- Annotating all generated prompts ---"
KB_FINAL_OUT="${RAG_KB_DIR}/final_knowledge_base.jsonl"
$PYTHON "${RAG_KB_DIR}/annotate_pairs.py" \
  --prompts-dir "${ALL_PROMPTS_DIR}" \
  --paired-flows "${CONSOLIDATED_PAIRED_FLOWS}" \
  --output "${KB_FINAL_OUT}" \
  --backend "${BACKEND}"

# Clean up temporary directories
rm -rf "${ALL_PROMPTS_DIR}" "${ALL_PAIRED_FLOWS_DIR}" "${CONSOLIDATED_PAIRED_FLOWS}"

echo -e "\n\n✅ Batch Knowledge Base creation complete!"
echo "   Final consolidated KB is located at: ${KB_FINAL_OUT}"