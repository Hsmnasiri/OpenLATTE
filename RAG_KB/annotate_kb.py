 
"""
This script reads a decompiled_kb.json file, automatically identifies the
vulnerable (_bad) and patched (goodB2G) functions, and uses an LLM
(Ollama or Gemini) to generate high-quality, structured annotations for a
knowledge base document.
"""
import json
import requests
import argparse
import os
import time
import re
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

OLLAMA_API_URL = "http://localhost:11434/api/chat"
OLLAMA_MODEL = "mistral"

GEMINI_API_KEY = os.getenv("GOOGLE_API_KEY", "GOOGLE_API_KEY42")
GEMINI_MODEL = 'gemini-1.5-pro'


ROOT_CAUSE_PROMPT_TEMPLATE = """
You are an expert security analyst specializing in identifying vulnerabilities in decompiled C/C++ code.
Your task is to analyze the following decompiled function and provide a precise, structured analysis of its root cause.

**Decompiled Vulnerable Function:**
```c
{bad_func_code}
```

**Analysis Request:**
1.  **Identify Vulnerable Line:** State the exact line of code that contains the primary vulnerability.
2.  **Explain Root Cause:** In one or two sentences, explain precisely *why* this line is vulnerable (e.g., "lack of a bounds check before an arithmetic operation," "user-controlled data is used in a dangerous function call").
3.  **State Vulnerability Type:** State the specific vulnerability type (e.g., "Integer Overflow," "Buffer Overflow").
"""

PATCH_PROMPT_TEMPLATE = """
You are an expert security analyst specializing in identifying vulnerabilities in decompiled C/C++ code.
Your task is to analyze the "good" (patched) function below and explain how it mitigates the vulnerability found in the "bad" (vulnerable) function.

**Decompiled Vulnerable Function (for context):**
```c
{bad_func_code}
```

**Decompiled Patched Function:**
```c
{good_func_code}
```

**Analysis Request:**
1.  **Identify Patching Code:** State the exact line(s) of code in the "Patched Function" that constitute the fix.
2.  **Explain Patch Mechanism:** In one or two sentences, explain precisely *how* this code mitigates the vulnerability (e.g., "by adding a bounds check to ensure the variable does not exceed its maximum value before the operation").
"""

def query_ollama(prompt):
    """Sends a prompt to a local Ollama instance."""
    print("  Querying Ollama...")
    try:
        response = requests.post(
            OLLAMA_API_URL,
            json={"model": OLLAMA_MODEL, "messages": [{"role": "user", "content": prompt}], "stream": False},
            timeout=180
        )
        response.raise_for_status()
        return response.json()['message']['content'].strip().replace('"', "'")
    except Exception as e:
        print(f"    [ERR] Ollama query failed: {e}")
        return f"Error: {e}"

def query_gemini(prompt, retries=3):
    """Sends a prompt to the Google Gemini API with retry logic."""
    print("  Querying Gemini...")
    if GEMINI_API_KEY == "YOUR_API_KEY":
        print("[FATAL] Please set your GOOGLE_API_KEY environment variable or in the script.")
        return None

    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel(GEMINI_MODEL)
    
    for attempt in range(retries):
        try:
            safety_settings = {
                'HARM_CATEGORY_HARASSMENT': 'BLOCK_NONE', 'HARM_CATEGORY_HATE_SPEECH': 'BLOCK_NONE',
                'HARM_CATEGORY_SEXUALLY_EXPLICIT': 'BLOCK_NONE', 'HARM_CATEGORY_DANGEROUS_CONTENT': 'BLOCK_NONE',
            }
            response = model.generate_content(prompt, safety_settings=safety_settings)
            time.sleep(1) # Be respectful of API rate limits
            return response.text.strip().replace('"', "'")
        except Exception as e:
            print(f"    [WARN] Gemini API call failed on attempt {attempt + 1}/{retries}: {e}")
            if attempt < retries - 1:
                time.sleep(5 * (attempt + 1))
    return f"API Error after {retries} attempts."

def find_function(data, keywords):
    """Finds the first function in the data that matches any of the keywords."""
    for func_name, func_data in data.items():
        if any(keyword in func_name for keyword in keywords):
            return func_data.get("decompiled_code", "Not found.")
    return "Representative function not found."

def main():
    parser = argparse.ArgumentParser(description="Generate LLM annotations for a decompiled KB file.")
    parser.add_argument('--input', required=True, help="Path to the input decompiled_kb.json file.")
    parser.add_argument('--output', required=True, help="Path to save the final structured .txt document or directory.")
    parser.add_argument('--llm-mode', choices=['local', 'gemini'], default='gemini', 
                        help="The LLM mode to use: 'local' for Ollama or 'gemini' for Google Gemini.")
    args = parser.parse_args()

    try:
        with open(args.input, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"[FATAL] Could not load input file '{args.input}': {e}")
        return

    cwe_id = "CWE-Unknown"
    match = re.search(r'CWE_(\d+)', args.input)
    if match:
        cwe_id = f"CWE-{match.group(1)}"
    print(f"[INFO] Detected CWE: {cwe_id}")

    print("[+] Automatically discovering vulnerable and patched functions...")
    bad_func_code = find_function(data, ["_bad", "::bad"])
    good_func_code = find_function(data, ["goodB2G"])
    
    if "not found" in bad_func_code.lower():
        print("[FATAL] Could not find a vulnerable (_bad) function. Cannot proceed.")
        return
    if "not found" in good_func_code.lower():
        print("[WARN] Could not find a patched (goodB2G) function. Patch annotation will be incomplete.")

    # Select the correct query function based on the mode
    query_llm = query_gemini if args.llm_mode == 'gemini' else query_ollama

    print(f"[+] Generating LLM annotations using {args.llm_mode.upper()}...")
    root_cause_prompt = ROOT_CAUSE_PROMPT_TEMPLATE.format(bad_func_code=bad_func_code)
    root_cause = query_llm(root_cause_prompt)
    print("  [OK] Got root cause annotation.")

    patch_prompt = PATCH_PROMPT_TEMPLATE.format(bad_func_code=bad_func_code, good_func_code=good_func_code)
    patch_desc = query_llm(patch_prompt)
    print("  [OK] Got patch description annotation.")

    # Auto-construct output path
    output_path = args.output
    if os.path.isdir(output_path):
        input_basename = os.path.basename(args.input)
        output_filename = input_basename.replace("decompiled_kb_", "annotated_kb_").replace(".json", ".txt")
        output_path = os.path.join(output_path, output_filename)

    # Assemble the final structured document
    structured_document = f"""CWE_ID: {cwe_id}
Vulnerable_Function_Decompiled:
{bad_func_code}
---
Patched_Function_Decompiled:
{good_func_code}
---
LLM_Annotation_Root_Cause:
{root_cause}
---
LLM_Annotation_Patch:
{patch_desc}
"""
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        f.write(structured_document)
    
    print(f"\n[DONE] Saved final structured document to {output_path}")

if __name__ == "__main__":
    main()
