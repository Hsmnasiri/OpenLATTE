#!/usr/bin/env bash
set -euo pipefail

# === Fixed Configuration ===
GHIDRA_DIR="/mnt/z/Papers/RAG_Papers/ghidra_11.3.2_PUBLIC_20250415/ghidra_11.3.2_PUBLIC"
UNSTRIPPED_BIN="/mnt/z/Papers/MyRAG/LATTE_ReImplementing/build/dbg/CWE190_Integer_Overflow__char_fscanf_preinc_05.unstripped"
STRIPPED_BIN="/mnt/z/Papers/MyRAG/LATTE_ReImplementing/build/stripped/CWE190_Integer_Overflow__char_fscanf_preinc_05.out"
SCRIPT_DIR="/mnt/z/Papers/MyRAG/LATTE_ReImplementing/RAG_KB"

PYTHON="${PYTHON:-python3}"
MAX_DEPTH="${MAX_DEPTH:-6}"   # traversal depth for export_kb_lattemode.py
ANALYZE_HEADLESS="${GHIDRA_DIR}/support/analyzeHeadless"

# ======= Derived paths (per-binary under RAG_KB/out/<BASE>) ===================
BASE_STRIPPED="$(basename "${STRIPPED_BIN}")"
BASE="${BASE_STRIPPED%.*}"

OUT_ROOT="${SCRIPT_DIR}/out/${BASE}"
BUILD_DIR="${OUT_ROOT}/build"
RESULTS_DIR="${OUT_ROOT}/results"
WORKSPACE_DIR="${OUT_ROOT}/workspace"

mkdir -p "${BUILD_DIR}" "${RESULTS_DIR}" "${WORKSPACE_DIR}"

SYMBOL_MAP_JSON="${BUILD_DIR}/symbol_map_${BASE}.json"
KB_CALLCHAINS_JSON="${BUILD_DIR}/kb_callchains_${BASE}.json"
KB_FLOWCARDS_JSONL="${RESULTS_DIR}/kb_flowcards_${BASE}.jsonl"
PROMPTS_DIR="${RESULTS_DIR}"

# Export environment for Ghidra scripts that rely on it
export OUT_BASE="${OUT_ROOT}"
export MAX_DEPTH

# ======= Helpers ==============================================================
run_headless() {
  local proj="$1"; local bin="$2"; shift 2
  "${ANALYZE_HEADLESS}" "${WORKSPACE_DIR}" "${proj}" \
    -import "${bin}" -scriptPath "${SCRIPT_DIR}" "$@" -deleteProject
}

# Clean conflicting project dirs for this base
rm -rf "${WORKSPACE_DIR}/Proj-Symbols" "${WORKSPACE_DIR}/Proj-KB" || true

# ======= [1/4] Symbol map from UNSTRIPPED ====================================
echo "[1/4] Symbol map (UNSTRIPPED → wrappers included)"
# Try to pass an explicit output path if your map_symbols.py supports argv[0]
if run_headless "Proj-Symbols" "${UNSTRIPPED_BIN}" -postScript map_symbols.py "${SYMBOL_MAP_JSON}"; then
  :
else
  # If the script doesn't take args, it will write somewhere else; fallback: find & copy
  CAND="$(find "${SCRIPT_DIR}" -maxdepth 3 -type f -name "symbol_map_${BASE}.json" 2>/dev/null | head -n1 || true)"
  if [[ -z "${CAND}" ]]; then
    CAND="$(find "$(dirname "${UNSTRIPPED_BIN}")" -maxdepth 3 -type f -name "symbol_map_${BASE}.json" 2>/dev/null | head -n1 || true)"
  fi
  if [[ -n "${CAND}" && "${CAND}" != "${SYMBOL_MAP_JSON}" ]]; then
    echo "[INFO] Found symbol map at ${CAND}; copying to ${SYMBOL_MAP_JSON}"
    cp -f "${CAND}" "${SYMBOL_MAP_JSON}"
  fi
fi

if [[ ! -f "${SYMBOL_MAP_JSON}" ]]; then
  echo "[FATAL] Missing symbol map at ${SYMBOL_MAP_JSON}"
  exit 1
fi

# ======= [2/4] Export call-chains from STRIPPED ===============================
echo "[2/4] Export KB call-chains (STRIPPED → externals)"
run_headless "Proj-KB" "${STRIPPED_BIN}" -postScript export_kb_lattemode.py

if [[ ! -f "${KB_CALLCHAINS_JSON}" ]]; then
  # Fallback: find misplaced output and copy in
  CAND="$(find "${OUT_ROOT}" -maxdepth 3 -type f -name "kb_callchains_${BASE}.json" 2>/dev/null | head -n1 || true)"
  if [[ -n "${CAND}" && "${CAND}" != "${KB_CALLCHAINS_JSON}" ]]; then
    echo "[INFO] Found call-chains at ${CAND}; copying to ${KB_CALLCHAINS_JSON}"
    cp -f "${CAND}" "${KB_CALLCHAINS_JSON}"
  fi
fi

if [[ ! -f "${KB_CALLCHAINS_JSON}" ]]; then
  echo "[FATAL] Missing ${KB_CALLCHAINS_JSON}"
  exit 1
fi

# ======= [3/4] Post-process → flow-cards =====================================
echo "[3/4] Post-process chains → compact flow-cards (RAG-ready)"
"${PYTHON}" "${SCRIPT_DIR}/postprocess_kb_chains.py" \
  --callchains "${KB_CALLCHAINS_JSON}" \
  --out_jsonl "${KB_FLOWCARDS_JSONL}"

# ======= [4/4] Stepwise prompts ==============================================
echo "[4/4] Generate stepwise prompts (semantics / root-cause / fix)"
"${PYTHON}" "${SCRIPT_DIR}/generate_annotation_prompts_stepwise.py" \
  --flowcards "${KB_FLOWCARDS_JSONL}" \
  --out_dir "${PROMPTS_DIR}"

echo "Done."
echo "Artifacts (per-binary under ${OUT_ROOT}):"
echo "  build/symbol_map_* : ${SYMBOL_MAP_JSON}"
echo "  build/kb_callchains_* : ${KB_CALLCHAINS_JSON}"
echo "  results/kb_flowcards_* : ${KB_FLOWCARDS_JSONL}"
echo "  results/prompts_semantics.txt"
echo "  results/prompts_rootcause.txt"
echo "  results/prompts_fix.txt"