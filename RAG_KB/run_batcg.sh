#!/usr/bin/env bash
set -euo pipefail

# === CONFIGURATION ===
GHIDRA_DIR="/mnt/z/Papers/RAG_Papers/ghidra_11.3.2_PUBLIC_20250415/ghidra_11.3.2_PUBLIC"
PROJECT_ROOT="/mnt/z/Papers/MyRAG/LATTE_ReImplementing"
JULIET_BINARIES_DIR="/mnt/z/juliet/C/dataset/train/CWE78_OS_Command_Injection/stripped"
RAG_KB_SCRIPT_DIR="${PROJECT_ROOT}/RAG_KB"

ANALYZE_HEADLESS="${GHIDRA_DIR}/support/analyzeHeadless"
MAX_DEPTH="${MAX_DEPTH:-6}"
export MAX_DEPTH

# --- Check for --force flag ---
FORCE_RUN=false
if [[ " $* " == *" --force "* ]]; then
  FORCE_RUN=true
  echo "Force flag detected. Re-running analysis for all binaries."
fi

# --- SCRIPT START ---
echo "### Starting Batch Ghidra Analysis ###"

# Find all stripped binaries in the Juliet build directory
find "${JULIET_BINARIES_DIR}" -type f -name "*.out" | while read -r STRIPPED_BIN; do
    BASE_NAME=$(basename "${STRIPPED_BIN}" .out)
    UNSTRIPPED_BIN="/mnt/z/juliet/C/dataset/train/CWE78_OS_Command_Injection/dbg/${BASE_NAME}.unstripped"

    # Define output paths for this specific binary
    OUT_ROOT="${RAG_KB_SCRIPT_DIR}/out/${BASE_NAME}"
    WORKSPACE_DIR="${OUT_ROOT}/workspace"
    BUILD_DIR="${OUT_ROOT}/build"
    SYMBOL_MAP_JSON="${BUILD_DIR}/symbol_map_${BASE_NAME}.json"
    KB_CALLCHAINS_JSON="${BUILD_DIR}/kb_callchains_${BASE_NAME}.json"

    export OUT_BASE="${OUT_ROOT}" # Export for Ghidra scripts

    # --- Skip Logic ---
    if [ "$FORCE_RUN" = false ] && [ -f "$KB_CALLCHAINS_JSON" ]; then
        echo "--- Skipping: ${BASE_NAME} (kb_callchains.json already exists) ---"
        continue
    fi

    echo "--- Processing: ${BASE_NAME} ---"

    # Clean up previous runs for this binary
    rm -rf "${WORKSPACE_DIR}"
    mkdir -p "${BUILD_DIR}" "${WORKSPACE_DIR}"

    # Step 1: Generate Symbol Map from the unstripped binary
    echo "[1/2] Generating symbol map for ${BASE_NAME}..."
    if [[ -f "${UNSTRIPPED_BIN}" ]]; then
        "${ANALYZE_HEADLESS}" "${WORKSPACE_DIR}" "Symbols_${BASE_NAME}" \
            -import "${UNSTRIPPED_BIN}" \
            -scriptPath "${RAG_KB_SCRIPT_DIR}" \
            -postScript map_symbols.py \
            -deleteProject
    else
        echo "[WARNING] Unstripped binary not found for ${BASE_NAME}. Skipping symbol map."
        continue
    fi

    # Step 2: Generate Call Chains from the stripped binary
    echo "[2/2] Generating call chains for ${BASE_NAME}..."
    "${ANALYZE_HEADLESS}" "${WORKSPACE_DIR}" "KB_${BASE_NAME}" \
        -import "${STRIPPED_BIN}" \
        -scriptPath "${RAG_KB_SCRIPT_DIR}" \
        -postScript export_kb_lattemode.py \
        -deleteProject

    echo "--- Finished: ${BASE_NAME} ---"
    echo
done

echo "### Batch Ghidra Analysis Complete ###"