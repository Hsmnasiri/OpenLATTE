#!/usr/bin/env bash
set -euo pipefail

# === CONFIGURATION ===
# Adjust these paths to match your system
GHIDRA_DIR="/mnt/z/Papers/RAG_Papers/ghidra_11.3.2_PUBLIC_20250415/ghidra_11.3.2_PUBLIC"
PROJECT_ROOT="/mnt/z/Papers/MyRAG/LATTE_ReImplementing"
JULIET_BINARIES_DIR="${PROJECT_ROOT}/Data/build/stripped"
RAG_KB_SCRIPT_DIR="${PROJECT_ROOT}/RAG_KB"

# Ghidra settings
ANALYZE_HEADLESS="${GHIDRA_DIR}/support/analyzeHeadless"
MAX_DEPTH="${MAX_DEPTH:-6}"
export MAX_DEPTH

# --- SCRIPT START ---
echo "### Starting Batch Ghidra Analysis ###"

# Find all stripped binaries in the Juliet build directory
find "${JULIET_BINARIES_DIR}" -type f -name "*.out" | while read -r STRIPPED_BIN; do
    BASE_NAME=$(basename "${STRIPPED_BIN}" .out)
    UNSTRIPPED_BIN="${PROJECT_ROOT}/Data/build/dbg/${BASE_NAME}.unstripped"

    # Define output paths for this specific binary
    OUT_ROOT="${RAG_KB_SCRIPT_DIR}/out/${BASE_NAME}"
    WORKSPACE_DIR="${OUT_ROOT}/workspace"
    BUILD_DIR="${OUT_ROOT}/build"
    SYMBOL_MAP_JSON="${BUILD_DIR}/symbol_map_${BASE_NAME}.json"
    KB_CALLCHAINS_JSON="${BUILD_DIR}/kb_callchains_${BASE_NAME}.json"

    export OUT_BASE="${OUT_ROOT}" # Export for Ghidra scripts

    echo "--- Processing: ${BASE_NAME} ---"

    # Clean up previous runs for this binary
    rm -rf "${WORKSPACE_DIR}"
    mkdir -p "${BUILD_DIR}"

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
