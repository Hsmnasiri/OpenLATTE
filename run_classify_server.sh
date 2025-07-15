# Assumes this script lives in project root next to .venv and classify.py
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
LOG_FILE="$SCRIPT_DIR/classifier.log"
PORT=8000

# Activate virtualenv: bin/activate or Scripts/activate
if [ -f "$VENV_DIR/bin/activate" ]; then
  source "$VENV_DIR/bin/activate"
elif [ -f "$VENV_DIR/Scripts/activate" ]; then
  source "$VENV_DIR/Scripts/activate"
else
  echo "Error: no activate script found in $VENV_DIR"
  exit 1
fi

# Start the FastAPI server and redirect output to log
exec uvicorn classify:app --host 127.0.0.1 --port $PORT \
  > "$LOG_FILE" 2>&1
```