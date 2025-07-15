#!/usr/bin/env bash
#
#  run_lattechain.sh
#
#  0. One-time prerequisites (already installed):
#     - Ghidra 11.3.2  →  /opt/ghidra_11.3.2_PUBLIC
#     - Python venv at ~/llama-env  (contains llama-cpp-python, fastapi, uvicorn)
#     - classify.py  +  prompts.py  in  ~/latte-classifier
#     - LatteTrace.java              in  ~/ghidra-scripts
#
#  1. Usage:
#        ./run_lattechain.sh  <binary_or_directory>  [--threads 12]
#
#  2. What it does:
#        • activates venv and boots the FastAPI server on port 8123
#        • waits until the /docs endpoint is alive
#        • for every ELF/PE/Mach-O in the path you give, runs Ghidra
#          head-less with LatteTrace.java
#        • prints CDF results to  results/<binary>.cdf.txt
#        • kills the FastAPI server and cleans temp project dirs
#
# -------------------------------------------------------------------------

set -euo pipefail
shopt -s nullglob

GHIDRA_HOME=/mnt/z/Papers/RAG_Papers/ghidra_11.3.2_PUBLIC_20250415/ghidra_11.3.2_PUBLIC
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLASSIFIER_DIR="$SCRIPT_DIR"
VENV_DIR=~/llama-env
PORT=8123
THREADS=0               # auto
BIN_TARGET=$1

# optional flag
if [[ $# -gt 1 && $2 == --threads* ]]; then
  THREADS="${2#--threads }"
fi

echo "==> Activating Python venv"
source "$VENV_DIR/bin/activate"

echo "==> Launching FastAPI + Llama server in background …"
export LLAMA_MODEL=${LLAMA_MODEL:-~/models/llama-2-7b/llama-2-7b-chat.Q4_K_M.gguf}
export OMP_NUM_THREADS=${THREADS:-$(nproc)}
UVICORN_LOG=classifier.log
uvicorn classify:app --app-dir "$CLASSIFIER_DIR" --host 127.0.0.1 \
        --port "$PORT" >"$UVICORN_LOG" 2>&1 &
SERVER_PID=$!

# helper: wait until server answers
echo -n "   waiting for http://127.0.0.1:$PORT … "
for i in {1..30}; do
  curl -sSf "http://127.0.0.1:$PORT/docs" >/dev/null && { echo "up"; break; }
  sleep 1
done

echo "==> Preparing list of binaries"
declare -a BINS
if [[ -d $BIN_TARGET ]]; then
  while IFS= read -r -d '' f; do BINS+=("$f"); done < <(find "$BIN_TARGET" -type f -print0)
else
  BINS=("$BIN_TARGET")
fi

mkdir -p results

echo "==> Running Ghidra headless on ${#BINS[@]} file(s)"
for bin in "${BINS[@]}"; do
  base=$(basename "$bin")
  projdir=$(mktemp -d)
  echo "   • $base"
  "$GHIDRA_HOME/support/analyzeHeadless" "$projdir" LatteProj \
      -import "$bin" \
      -scriptPath "$SCRIPT_DIR" \
      -postScript LatteTrace \
      -deleteProject \
      -noanalysis \
      >"results/${base}.cdf.txt" 2>&1
  rm -rf "$projdir"
done

echo "==> Shutting down classifier (PID $SERVER_PID)"
kill "$SERVER_PID" && wait "$SERVER_PID" 2>/dev/null || true
echo "==> Done.  Check the 'results/' folder for CDF outputs."
