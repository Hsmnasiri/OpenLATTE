import os
import re
import time
import google.generativeai as genai
from dotenv import load_dotenv
load_dotenv()

API_KEY = os.getenv("GOOGLE_API_KEY42", "YOUR_API_KEY")

MySINK_PROMPT_TEMPLATE = """
You are an expert security analyst specializing in C/C++ static taint analysis.
Your task is to identify "taint sinks". A taint sink is a function where data from an untrusted source could lead to a vulnerability like memory corruption, command injection, or path traversal.

Analyze the function: `{func_name}`

Is it a taint sink? Respond with **only one line** in one of these two formats:
1.  `(FUNC; N[,M])` if it IS a sink. N and M are the 1-based parameter indices that receive the tainted data.
2.  `(NO)` if it is NOT a sink.

**Do not provide any explanations or extra text.**

---
Examples:
FUNCTION: system
(system; 1)

FUNCTION: sprintf
(sprintf; 2)

FUNCTION: recv
(NO)
---

Now, classify this function:
FUNCTION: {func_name}
"""

MySOURCE_PROMPT_TEMPLATE = """
You are an expert security analyst specializing in C/C++ static taint analysis.
Your task is to identify "taint sources". A taint source is a function that introduces untrusted, external data into the program (e.g., from a file, network, or user input).

Analyze the function: `{func_name}`

Is it a taint source? Respond with **only one line** in one of these two formats:
1.  `(FUNC; N[,M])` if it IS a source. N and M are the 1-based parameter indices where the external data is stored.
2.  `(NO)` if it is NOT a source.

**Do not provide any explanations or extra text.**

---
Examples:
FUNCTION: recv
(recv; 2)

FUNCTION: fgets
(fgets; 1)

FUNCTION: system
(NO)
---

Now, classify this function:
FUNCTION: {func_name}
"""
SINK_PROMPT_TEMPLATE="""
        As a program analyst, is it possible to use a call {func_name} as a sink when performing taint analysis? If so which parameters need to be checked for taint. 
        Please answer yes or no without additional explanation. If yes, please indicate the corresponding parameters. 
        For example, the system function can be used as a sink, and the first parameter needs to be checked as (system; 1).
        """
SOURCE_PROMPT_TEMPLATE = """
        As a program analyst, is it possible to use a call to {func_name} as a starting point (source) for taint analysis? 
        If the function can be used as a taint source, which parameter in the call stores the external input data. Please answer yes or no without additional explanation. 
        If yes, please indicate the corresponding parameters. For example, the recv function call can be used as a taint source, and the second parameter as a buffer stores the input data as (recv; 2).
        """
def classify_function(func_name: str, mode: str, retries: int = 3) -> dict:
    """
    Classifies a function as a taint source or sink using the Google Gemini API.

    Args:
        func_name: The name of the function to classify.
        mode: The classification mode, either 'source' or 'sink'.
        retries: The number of times to retry the API call on failure.

    Returns:
        A dictionary containing the classification result.
    """
    if API_KEY == "YOUR_API_KEY":
        raise ValueError("Please replace 'YOUR_API_KEY' with your actual Google Gemini API key.")

    genai.configure(api_key=API_KEY)
    model = genai.GenerativeModel('gemini-2.5-flash')

    if mode not in ["source", "sink"]:
        raise ValueError("Mode must be either 'source' or 'sink'.")

    template = SOURCE_PROMPT_TEMPLATE if mode == "source" else SINK_PROMPT_TEMPLATE
    prompt = template.format(func_name=func_name)

    response_data = {"is_true": False, "params": [], "answer": "API call failed after all retries."}

    # --- Gemini API Call with Retry Logic ---
    for attempt in range(retries):
        try:
            # Set safety settings to be less restrictive for this security context
            safety_settings = {
                'HARM_CATEGORY_HARASSMENT': 'BLOCK_NONE',
                'HARM_CATEGORY_HATE_SPEECH': 'BLOCK_NONE',
                'HARM_CATEGORY_SEXUALLY_EXPLICIT': 'BLOCK_NONE',
                'HARM_CATEGORY_DANGEROUS_CONTENT': 'BLOCK_NONE',
            }
            response = model.generate_content(prompt)
            llm_output = response.text.strip()
            
            # --- Parsing Logic ---
            params = []
            is_true = False
            # Search for the specific pattern like (func; 1,2)
            for line in reversed(llm_output.splitlines()):
                # A more robust regex to handle potential variations in spacing
                match = re.search(r"\(\s*([^;]+)\s*;\s*([\d,]+)\s*\)", line, re.IGNORECASE)
                if match and match.group(1).strip().lower() == func_name.lower():
                    params = [int(p.strip()) for p in match.group(2).split(",")]
                    is_true = True
                    break # Found a valid classification
                elif re.search(r"\(\s*NO\s*\)", line, re.IGNORECASE):
                    is_true = False
                    break

            response_data = {
                "is_true": is_true,
                "params": params,
                "answer": llm_output
            }
            break # Exit the retry loop on success

        except Exception as e:
            print(f"[WARN] API call for '{func_name}' failed on attempt {attempt + 1}/{retries}: {e}")
            response_data = {"is_true": False, "params": [], "answer": f"API Error after {attempt + 1} attempts: {e}"}
            # Respect the API's request to wait, especially for rate limit errors
            if "retry_delay" in str(e):
                time.sleep(30) # Wait longer for explicit rate limit errors
            elif attempt < retries - 1:
                time.sleep(5 * (attempt + 1)) # Exponential backoff for other errors

    # --- FIX: Add a delay to respect the API rate limit (15 requests/minute) ---
    # A 4.1-second delay ensures we stay under the limit (60s / 15 = 4s per request).
    time.sleep(4.1)

    return response_data