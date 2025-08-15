#!/usr/bin/env bash
set -euo pipefail

# =========== CONFIG ===========
GHIDRA_DIR="/mnt/z/Papers/RAG_Papers/ghidra_11.3.2_PUBLIC_20250415/ghidra_11.3.2_PUBLIC"
PROJECT_ROOT="/mnt/z/Papers/MyRAG/LATTE_ReImplementing"
JULIET_BINARIES_DIR="/mnt/z/juliet/C/dataset/test/sampleTest/small"

SCRIPT_DIR="${PROJECT_ROOT}"
RESULTS_DIR="${PROJECT_ROOT}/resultss"
ANALYZE_HEADLESS="${GHIDRA_DIR}/support/analyzeHeadless"
WORKSPACE_DIR_BASE="${PROJECT_ROOT}/ghidra-workspace"

# Optional: uncomment for verbose debug
# set -x

echo "### Starting Batch OpenLATTE Analysis ###"
mkdir -p "${RESULTS_DIR}" "${WORKSPACE_DIR_BASE}"

# robust find (spaces-safe)
find "${JULIET_BINARIES_DIR}" -type f -name "*.out" -print0 | while IFS= read -r -d '' STRIPPED_BIN; do
  BASE_NAME="$(basename "${STRIPPED_BIN}" .out)"
  # یکتا برای جلوگیری از تداخل اجرای همزمان
  WORKSPACE_DIR="${WORKSPACE_DIR_BASE}/${BASE_NAME}-analysis-$$"
  PROJECT_NAME="${BASE_NAME}"

  echo
  echo "--- Processing: ${BASE_NAME} ---"

  # هر بار از صفر بساز تا مطمئن باشیم پوشه وجود داره و پاکه
  rm -rf "${WORKSPACE_DIR}" 2>/dev/null || true
  mkdir -p "${WORKSPACE_DIR}"

  # --------------------------------------
  # Step 1: Export External Functions
  # --------------------------------------
  echo "[1/5] Exporting external functions for ${BASE_NAME}..."
  EXTERNAL_FUNCS_FILE="${RESULTS_DIR}/external_funcs_${BASE_NAME}.txt"

  "${ANALYZE_HEADLESS}" "${WORKSPACE_DIR}" "${PROJECT_NAME}-Export" \
    -import "${STRIPPED_BIN}" \
    -scriptPath "${SCRIPT_DIR}" \
    -postScript export_external_funcs.py

  # تلاش برای پیدا کردن خروجی بسته به اسکریپت شما
  # مسیرهای محتمل را امتحان کن و در صورت وجود منتقل کن
  cand1="${WORKSPACE_DIR_BASE}/external_funcs_${BASE_NAME}.out.txt"
  cand2="${WORKSPACE_DIR}/external_funcs_${BASE_NAME}.out.txt"
  cand3="${RESULTS_DIR}/external_funcs_${BASE_NAME}.out.txt"
  if   [[ -f "${cand1}" ]]; then mv "${cand1}" "${EXTERNAL_FUNCS_FILE}";
  elif [[ -f "${cand2}" ]]; then mv "${cand2}" "${EXTERNAL_FUNCS_FILE}";
  elif [[ -f "${cand3}" ]]; then mv "${cand3}" "${EXTERNAL_FUNCS_FILE}";
  elif [[ -f "${EXTERNAL_FUNCS_FILE}" ]]; then :; # already written directly
  else
    echo "WARN: external functions file not found for ${BASE_NAME}" >&2
  fi

  # --------------------------------------
  # Step 2: Classify Sources and Sinks
  # --------------------------------------
  echo "[2/5] Classifying sources and sinks for ${BASE_NAME}..."
  SOURCE_FILE="${RESULTS_DIR}/source_classification_${BASE_NAME}.json"
  SINK_FILE="${RESULTS_DIR}/sink_classification_${BASE_NAME}.json"

  python3 "${SCRIPT_DIR}/batch_classify.py" \
    --ext-funcs "${EXTERNAL_FUNCS_FILE}" \
    --mode source \
    --output-dir "${RESULTS_DIR}"

  python3 "${SCRIPT_DIR}/batch_classify.py" \
    --ext-funcs "${EXTERNAL_FUNCS_FILE}" \
    --mode sink \
    --output-dir "${RESULTS_DIR}"

  # --------------------------------------
  # Step 3: Find Dangerous Flows
  # --------------------------------------
  echo "[3/5] Finding dangerous flows for ${BASE_NAME}..."
  # توجه: export_flow_code.py عموماً به فایل .out.json نگاه می‌کند.
  # اگر find_dangerous_flows.py آرگومان --output می‌گیرد، حتماً نام را با .out.json بده
  DF_OUT_REL="results/dangerous_flows_${BASE_NAME}.out.json"
  DF_OUT_ABS="${PROJECT_ROOT}/${DF_OUT_REL}"

  # تضمین cwd = PROJECT_ROOT برای مسیر نسبی "results/"
  pushd "${PROJECT_ROOT}" >/dev/null

  "${ANALYZE_HEADLESS}" "${WORKSPACE_DIR}" "${PROJECT_NAME}-DF" \
    -import "${STRIPPED_BIN}" \
    -scriptPath "${SCRIPT_DIR}" \
    -postScript find_dangerous_flows.py --sinks "${SINK_FILE}" --sources "${SOURCE_FILE}" --output "${DF_OUT_REL}"


  # --------------------------------------
  # Step 4: Export Flow Code
  # --------------------------------------
  echo "[4/5] Exporting flow code for ${BASE_NAME}..."
  FC_OUT_REL="results/flows_with_code_${BASE_NAME}.out.json"
  FC_OUT_ABS="${PROJECT_ROOT}/${FC_OUT_REL}"

  "${ANALYZE_HEADLESS}" "${WORKSPACE_DIR}" "${PROJECT_NAME}-ExportCode" \
    -import "${STRIPPED_BIN}" \
    -scriptPath "${SCRIPT_DIR}" \
    -postScript export_flow_code.py
  # ↑ این اسکریپت معمولاً خروجی را در results/ با .out.json می‌نویسد (وابسته به اسکریپت شما)

  popd >/dev/null

  DANGEROUS_FLOWS_FILE="${RESULTS_DIR}/dangerous_flows_${BASE_NAME}.json"
  FLOWS_WITH_CODE_FILE="${RESULTS_DIR}/flows_with_code_${BASE_NAME}.json"

  # اگر .out.json وجود داشت، rename کن؛ وگرنه اگر همان نام نهایی را قبلاً نوشته بود، دست نزن
  if [[ -f "${DF_OUT_ABS}" ]]; then mv -f "${DF_OUT_ABS}" "${DANGEROUS_FLOWS_FILE}"; fi
  if [[ -f "${FC_OUT_ABS}" ]]; then mv -f "${FC_OUT_ABS}" "${FLOWS_WITH_CODE_FILE}"; fi

  # امنیت: مطمئن شو فایل‌هایی که مرحله 5 لازم دارد وجود دارند
  if [[ ! -f "${FLOWS_WITH_CODE_FILE}" ]]; then
    echo "FATAL: flows_with_code file missing: ${FLOWS_WITH_CODE_FILE}" >&2
    exit 1
  fi
  if [[ ! -f "${DANGEROUS_FLOWS_FILE}" ]]; then
    echo "FATAL: dangerous_flows file missing: ${DANGEROUS_FLOWS_FILE}" >&2
    exit 1
  fi

  # --------------------------------------
  # Step 5: Inspect Flows with LLM
  # --------------------------------------
  echo "[5/5] Inspecting flows with LLM for ${BASE_NAME}..."
  VULN_REPORTS_FILE="${RESULTS_DIR}/vulnerability_reports_${BASE_NAME}.json"

  python3 "${SCRIPT_DIR}/inspect_flows_with_llm.py" \
    --flows-with-code "${FLOWS_WITH_CODE_FILE}" \
    --sources "${SOURCE_FILE}" \
    --output "${VULN_REPORTS_FILE}" \
    --llm-mode gemini

  # پاکسازی workspace (چون در دفعات بعد دوباره می‌سازیم)
  rm -rf "${WORKSPACE_DIR}" 2>/dev/null || true

  echo "--- Finished: ${BASE_NAME} ---"
done

echo
echo "### Batch OpenLATTE Analysis Complete ###"
