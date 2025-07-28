import requests
import re

OLLAMA_API_URL = "http://localhost:11434/api/chat"
# OLLAMA_MODEL = "mistral"  
OLLAMA_MODEL = "codellama:7b-instruct"

SINK_PROMPT_TEMPLATE = """
You are an expert in taint-analysis. A "taint sink" is a function where tainted data could cause a vulnerability (e.g., command execution, memory corruption).

Is the C function `{func_name}` a potential taint sink?

Respond **only** with **one line** in **exactly** one of these formats:
  (FUNC; N[,M])   <- if it is a sink, where N,M are the 1-based tainted parameter indices.
  (NO)            <- if it is not a sink.

**Do not** output anything else. No explanations.

Examples:
FUNCTION: system
(system; 1)

FUNCTION: sprintf
(sprintf; 2)

FUNCTION: recv
(NO)

Now, please classify:
FUNCTION: {func_name}
"""

SOURCE_PROMPT_TEMPLATE = """
You are an expert in taint-analysis. A "taint source" is a function that introduces external, untrusted data into a program (e.g., reading from a socket or file).

Is the C function `{func_name}` a potential taint source?

Respond **only** with **one line** in **exactly** one of these formats:
  (FUNC; N[,M])   <- if it is a source, where N,M are the 1-based parameter indices that store external data.
  (NO)            <- if it is not a source.

**Do not** output anything else. No explanations.

Examples:
FUNCTION: recv
(recv; 2)

FUNCTION: read
(read; 2)

FUNCTION: system
(NO)

Now, please classify:
FUNCTION: {func_name}
"""

def classify_function(func_name: str, mode: str) -> dict:
    """
    Classifies a function as a taint source or sink using the Ollama LLM.

    Args:
        func_name: The name of the function to classify.
        mode: The classification mode, either 'source' or 'sink'.

    Returns:
        A dictionary containing the classification result.
    """
    if mode not in ["source", "sink"]:
        raise ValueError("Mode must be either 'source' or 'sink'.")

    template = SOURCE_PROMPT_TEMPLATE if mode == "source" else SINK_PROMPT_TEMPLATE
    prompt = template.format(func_name=func_name)

    try:
        response = requests.post(
            OLLAMA_API_URL,
            json={"model": OLLAMA_MODEL, "messages": [{"role": "user", "content": prompt}], "stream": False},
            timeout=180
        )
        response.raise_for_status()
        llm_output = response.json()['message']['content'].strip()
    except Exception as e:
        print(f"[WARN] LLM API call failed for '{func_name}': {e}")
        return {"is_true": False, "params": [], "answer": f"Error: {e}"}

    params = []
    is_true = False
    for line in reversed(llm_output.splitlines()):
        match = re.search(r"\(([^;]+);\s*([\d,]+)\)", line)
        if match and match.group(1).strip().lower() == func_name.lower():
            params = [int(p) for p in match.group(2).split(",")]
            is_true = True
            break  

    return {
        "is_true": is_true,
        "params": params,
        "answer": llm_output
    }