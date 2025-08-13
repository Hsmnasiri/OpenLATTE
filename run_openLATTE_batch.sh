#!/usr/bin/env bash
set -euo pipefail

# === CONFIGURATION ===
GHIDRA_DIR="/mnt/z/Papers/RAG_Papers/ghidra_11.3.2_PUBLIC_20250415/ghidra_11.3.2_PUBLIC"
PROJECT_ROOT="/mnt/z/Papers/MyRAG/LATTE_ReImplementing"
JULIET_BINARIES_DIR="${PROJECT_ROOT}/Data/build/stripped"
SCRIPT_DIR="${PROJECT_ROOT}"
RESULTS_DIR="${PROJECT_ROOT}/results"

ANALYZE_HEADLESS="${GHIDRA_DIR}/support/analyzeHeadless"
WORKSPACE_DIR_BASE="${PROJECT_ROOT}/ghidra-workspace" 

# --- SCRIPT START ---
echo "### Starting Batch OpenLATTE Analysis ###"
mkdir -p "${RESULTS_DIR}"

find "${JULIET_BINARIES_DIR}" -type f -name "*.out" | while read -r STRIPPED_BIN; do
    BASE_NAME=$(basename "${STRIPPED_BIN}" .out)
    WORKSPACE_DIR="${WORKSPACE_DIR_BASE}/${BASE_NAME}-analysis" 
    
    echo "--- Processing: ${BASE_NAME} ---"

    # --- Step 1: Export External Functions ---
    echo "[1/5] Exporting external functions for ${BASE_NAME}..."
    EXTERNAL_FUNCS_FILE="${RESULTS_DIR}/external_funcs_${BASE_NAME}.txt"
    "$ANALYZE_HEADLESS" "$WORKSPACE_DIR" "${BASE_NAME}-Export" \
      -import "$STRIPPED_BIN" \
      -scriptPath "$SCRIPT_DIR" \
      -postScript export_external_funcs.py \
      -deleteProjectOnCompletion &> /dev/null
    mv "${WORKSPACE_DIR_BASE}/external_funcs_${BASE_NAME}.out.txt" "${EXTERNAL_FUNCS_FILE}"


    # --- Step 2: Classify Sources and Sinks ---
    echo "[2/5] Classifying sources and sinks for ${BASE_NAME}..."
    SOURCE_FILE="${RESULTS_DIR}/source_classification_${BASE_NAME}.json"
    SINK_FILE="${RESULTS_DIR}/sink_classification_${BASE_NAME}.json"
    python3 "${SCRIPT_DIR}/batch_classify.py" --ext-funcs "${EXTERNAL_FUNCS_FILE}" --mode source --output-dir "${RESULTS_DIR}"
    python3 "${SCRIPT_DIR}/batch_classify.py" --ext-funcs "${EXTERNAL_FUNCS_FILE}" --mode sink --output-dir "${RESULTS_DIR}"

    # --- Step 3: Find Dangerous Flows ---
    echo "[3/5] Finding dangerous flows for ${BASE_NAME}..."
    DANGEROUS_FLOWS_FILE="${RESULTS_DIR}/dangerous_flows_${BASE_NAME}.json"
     "$ANALYZE_HEADLESS" "$WORKSPACE_DIR" "${BASE_NAME}-DF" \
      -import "$STRIPPED_BIN" \
      -scriptPath "$SCRIPT_DIR" \
      -postScript find_dangerous_flows.py --sinks "$SINK_FILE" --sources "$SOURCE_FILE" --output "$DANGEROUS_FLOWS_FILE" \
      -deleteProjectOnCompletion &> /dev/null
      
    # --- Step 4: Export Flow Code ---
    echo "[4/5] Exporting flow code for ${BASE_NAME}..."
    FLOWS_WITH_CODE_FILE="${RESULTS_DIR}/flows_with_code_${BASE_NAME}.json"
    "$ANALYZE_HEADLESS" "$WORKSPACE_DIR" "${BASE_NAME}-ExportCode" \
      -import "$STRIPPED_BIN" \
      -scriptPath "$SCRIPT_DIR" \
      -postScript export_flow_code.py \
      -deleteProjectOnCompletion &> /dev/null
    mv "${RESULTS_DIR}/dangerous_flows_${BASE_NAME}.out.json" "${DANGEROUS_FLOWS_FILE}"  
    mv "${RESULTS_DIR}/flows_with_code_${BASE_NAME}.out.json" "${FLOWS_WITH_CODE_FILE}"


    # --- Step 5: Inspect Flows with LLM ---
    echo "[5/5] Inspecting flows with LLM for ${BASE_NAME}..."
    VULN_REPORTS_FILE="${RESULTS_DIR}/vulnerability_reports_${BASE_NAME}.json"
    python3 "${SCRIPT_DIR}/inspect_flows_with_llm.py" \
        --flows-with-code "${FLOWS_WITH_CODE_FILE}" \
        --sources "${SOURCE_FILE}" \
        --output "${VULN_REPORTS_FILE}" \
        --llm-mode gemini # or 'local'

    echo "--- Finished: ${BASE_NAME} ---"
    echo
done

echo "### Batch OpenLATTE Analysis Complete ###"