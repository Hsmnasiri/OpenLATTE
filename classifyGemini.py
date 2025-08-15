import os
import re
import time
import google.generativeai as genai
from dotenv import load_dotenv
load_dotenv()

API_KEY = os.getenv("GOOGLE_API_KEY42", "YOUR_API_KEY")

# --- Improved Prompts ---

SINK_PROMPT_TEMPLATE = """
You are an expert security analyst specializing in C/C++ static taint analysis. Your task is to identify "taint sinks".
A taint sink is a function where tainted data from an untrusted source could lead to a high-impact vulnerability.

Common sink categories include:
- **Memory Corruption:** Functions that write to buffers without bounds checks (e.g., strcpy, sprintf, memcpy).
- **Command Injection:** Functions that execute system commands (e.g., system, exec*).
- **Path Traversal:** Functions that open or manipulate file paths (e.g., open, fopen, unlink).
- **Format String:** Functions that can interpret tainted data as format specifiers (e.g., printf, fprintf).

Analyze the function with the following prototype:
**`{func_proto}`**

Is `{func_name}` a potential taint sink? Respond with **only one line** in one of these two formats:
1.  `(FUNC; N[,M])` if it IS a sink. N and M are the 1-based parameter indices that receive the tainted data.
2.  `(NO)` if it is NOT a sink.

**Do not provide any explanations or extra text.**

---
Examples:
FUNCTION: int system(char * __command) -> (system; 1)
FUNCTION: int sprintf(char * str, char * format, ...) -> (sprintf; 2)
FUNCTION: ssize_t recv(int __fd, void * __buf, size_t __n, int __flags) -> (NO)
---

Now, classify this function:
FUNCTION: {func_name}
"""

SOURCE_PROMPT_TEMPLATE = """
You are an expert security analyst specializing in C/C++ static taint analysis. Your task is to identify "taint sources".
A taint source is a function that introduces untrusted, external data into the program (e.g., from a file, network, standard input, or environment variables).

Analyze the function with the following prototype:
**`{func_proto}`**

Is `{func_name}` a potential taint source? Respond with **only one line** in one of these two formats:
1.  `(FUNC; N[,M])` if it IS a source. N and M are the 1-based parameter indices where the external data is stored.
2.  `(NO)` if it is NOT a source.

**Do not provide any explanations or extra text.**
---
Examples:
FUNCTION: ssize_t recv(int __fd, void * __buf, size_t __n, int __flags) -> (recv; 2)
FUNCTION: char * fgets(char * __s, int __n, FILE * __stream) -> (fgets; 1)
FUNCTION: int system(char * __command) -> (NO)
---

Now, classify this function:
FUNCTION: {func_name}
"""

# The rest of the file remains the same...
def classify_function(func_name: str, func_proto: str, mode: str, retries: int = 3) -> dict:
    if API_KEY == "YOUR_API_KEY":
        raise ValueError("Please set your GOOGLE_API_KEY environment variable.")

    genai.configure(api_key=API_KEY)
    model = genai.GenerativeModel('gemini-2.5-pro')

    if mode not in ["source", "sink"]:
        raise ValueError("Mode must be either 'source' or 'sink'.")

    template = SOURCE_PROMPT_TEMPLATE if mode == "source" else SINK_PROMPT_TEMPLATE
    # Pass both name and proto to the prompt
    prompt = template.format(func_name=func_name, func_proto=func_proto)

    # ... (the rest of the function for API call and parsing) ...
    # (No changes needed in the API call and parsing logic)
    response_data = {"is_true": False, "params": [], "answer": "API call failed after all retries."}

    for attempt in range(retries):
        try:
            safety_settings = {
                'HARM_CATEGORY_HARASSMENT': 'BLOCK_NONE',
                'HARM_CATEGORY_HATE_SPEECH': 'BLOCK_NONE',
                'HARM_CATEGORY_SEXUALLY_EXPLICIT': 'BLOCK_NONE',
                'HARM_CATEGORY_DANGEROUS_CONTENT': 'BLOCK_NONE',
            }
            response = model.generate_content(prompt, safety_settings=safety_settings)
            llm_output = response.text.strip()
            
            params = []
            is_true = False
            for line in reversed(llm_output.splitlines()):
                match = re.search(r"\(\s*([^;]+)\s*;\s*([\d,]+)\s*\)", line, re.IGNORECASE)
                if match and match.group(1).strip().lower() == func_name.lower():
                    params = [int(p.strip()) for p in match.group(2).split(",")]
                    is_true = True
                    break  
                elif re.search(r"\(\s*NO\s*\)", line, re.IGNORECASE):
                    is_true = False
                    break

            response_data = {
                "is_true": is_true,
                "params": params,
                "answer": llm_output
            }
            break 

        except Exception as e:
            print(f"[WARN] API call for '{func_name}' failed on attempt {attempt + 1}/{retries}: {e}")
            response_data = {"is_true": False, "params": [], "answer": f"API Error after {attempt + 1} attempts: {e}"}
            if "retry_delay" in str(e):
                time.sleep(30) 
            elif attempt < retries - 1:
                time.sleep(5 * (attempt + 1)) 

    time.sleep(1.2) # A slight delay to respect API rate limits

    return response_data