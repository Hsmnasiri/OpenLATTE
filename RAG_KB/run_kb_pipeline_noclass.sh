#!/usr/bin/env bash
set -euo pipefail

# === Fixed Configuration ===
GHIDRA_DIR="/mnt/z/Papers/RAG_Papers/ghidra_11.3.2_PUBLIC_20250415/ghidra_11.3.2_PUBLIC"
UNSTRIPPED_BIN="/mnt/z/Papers/MyRAG/LATTE_ReImplementing/build/dbg/CWE190_Integer_Overflow__char_fscanf_preinc_05.unstripped"
STRIPPED_BIN="/mnt/z/Papers/MyRAG/LATTE_ReImplementing/build/stripped/CWE190_Integer_Overflow__char_fscanf_preinc_05.out"
WORKSPACE_DIR="/mnt/z/Papers/MyRAG/LATTE_ReImplementing/ghidra-workspace"
SCRIPT_DIR="/mnt/z/Papers/MyRAG/LATTE_ReImplementing/RAG_KB"
PYTHON="python3"
MAX_DEPTH=10

# === Derived Variables ===
ANALYZE_HEADLESS="${GHIDRA_DIR}/support/analyzeHeadless"
BASE_STRIPPED="$(basename "${STRIPPED_BIN}")"
BASE="${BASE_STRIPPED%.*}"

mkdir -p build results "${WORKSPACE_DIR}"

# Ensure the Ghidra directory exists
OUT_BASE="/mnt/z/Papers/MyRAG/LATTE_ReImplementing"   
export OUT_BASE
SYMBOL_MAP_JSON="${OUT_BASE}/build/symbol_map_${BASE}.json"
KB_CALLCHAINS_JSON="${OUT_BASE}/build/kb_callchains_${BASE}.json"
KB_FULL_JSON="${OUT_BASE}/build/decompiled_kb_full_${BASE}.json"
ANNOT_PROMPTS_OUT="${OUT_BASE}/results/annotated_kb_full_${BASE}_prompts.txt"

mkdir -p "${OUT_BASE}/build" "${OUT_BASE}/results" "${WORKSPACE_DIR}"

rm -rf "${WORKSPACE_DIR}/Proj-Symbols" || true
rm -rf "${WORKSPACE_DIR}/Proj-KB" || true
# === Function to run Ghidra headless ===
run_headless() {
  local proj_name="$1"
  local import_path="$2"
  shift 2
  "${ANALYZE_HEADLESS}" "${WORKSPACE_DIR}" "${proj_name}" \
    -import "${import_path}" -scriptPath "${SCRIPT_DIR}" "$@" -deleteProject
}

# === Steps ===
echo "[1/4] Symbol map (unstripped, includes FUN_* wrappers)"
run_headless "Proj-Symbols" "${UNSTRIPPED_BIN}" \
  -postScript map_symbols_include_fun.py
test -f "${SYMBOL_MAP_JSON}" || echo "[WARN] Symbol map not found at ${SYMBOL_MAP_JSON}."

echo "[2/4] Export KB call-chains from good/bad starts until external (stripped)"
export MAX_DEPTH
run_headless "Proj-KB" "${STRIPPED_BIN}" \
  -postScript export_kb_lattemode.py

if [[ ! -f "${KB_CALLCHAINS_JSON}" ]]; then
  echo "[FATAL] Missing ${KB_CALLCHAINS_JSON}. Check script naming and base detection."
  exit 1
fi

echo "[3/4] Assemble KB for annotation"
${PYTHON} "${SCRIPT_DIR}/assemble_kb_for_annotation.py" \
  --input "${KB_CALLCHAINS_JSON}" \
  --output "${KB_FULL_JSON}"

echo "[4/4] Generate full-chain annotation prompts"
${PYTHON} "${SCRIPT_DIR}/annotate_kb_full.py" \
  --input "${KB_FULL_JSON}" \
  --output "${ANNOT_PROMPTS_OUT}"

# === Done ===
echo "Done."
echo "Artifacts:"
echo "  Symbol map:           ${SYMBOL_MAP_JSON}"
echo "  KB call-chains (raw): ${KB_CALLCHAINS_JSON}"
echo "  KB (assembled):       ${KB_FULL_JSON}"
echo "  Prompts:              ${ANNOT_PROMPTS_OUT}"
