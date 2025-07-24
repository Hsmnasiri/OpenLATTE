#!/usr/bin/env python3
"""
annotate_kb.py - GENERALIZED VERSION

This script reads a decompiled_kb.json file, automatically identifies the
vulnerable (_bad) and a representative patched (goodB2G) function,
and uses an LLM to generate annotations for a structured knowledge base document.
"""
import json
import requests
import argparse
import os

# --- Ollama Configuration ---
OLLAMA_API_URL = "http://localhost:11434/api/chat"
OLLAMA_MODEL = "mistral"

def get_llm_annotation(prompt):
    """Sends a prompt to Ollama and gets a response."""
    print(f"  Querying LLM...")
    try:
        response = requests.post(
            OLLAMA_API_URL,
            json={"model": OLLAMA_MODEL, "messages": [{"role": "user", "content": prompt}], "stream": False},
            timeout=180 # 3 minute timeout
        )
        response.raise_for_status()
        return response.json()['message']['content'].strip().replace('"', "'") # Sanitize quotes
    except Exception as e:
        print(f"    [ERR] LLM annotation failed: {e}")
        return f"Error getting annotation: {e}"

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
    args = parser.parse_args()

    try:
        with open(args.input, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"[FATAL] Could not load input file '{args.input}': {e}")
        return

    # --- Automatic Function Discovery ---
    print("[+] Automatically discovering vulnerable and patched functions...")
    bad_func_code = find_function(data, ["_bad", "::bad"])
    good_func_code = find_function(data, ["goodB2G"])
    
    if "not found" in bad_func_code.lower():
        print("[FATAL] Could not find a vulnerable (_bad) function in the input file. Cannot proceed.")
        return

    print("[+] Generating LLM annotations...")
    root_cause_prompt = f"Analyze this decompiled C code and describe the specific root cause of the vulnerability in one sentence.\n\n```c\n{bad_func_code}\n```"
    root_cause = get_llm_annotation(root_cause_prompt)
    print("  [OK] Got root cause.")

    patch_prompt = f"Analyze this 'good' version of the code and describe how it fixes the vulnerability in one sentence.\n\n```c\n{good_func_code}\n```"
    patch_desc = get_llm_annotation(patch_prompt)
    print("  [OK] Got patch description.")

    # --- NEW: Automatically construct output path if a directory is given ---
    output_path = args.output
    if os.path.isdir(output_path):
        print(f"  [INFO] Output path '{output_path}' is a directory. Constructing filename from input.")
        # Create a new filename based on the input file's name
        input_basename = os.path.basename(args.input)
        output_filename = input_basename.replace("decompiled_kb_", "annotated_kb_").replace(".json", ".txt")
        # Join the directory and filename to create the full path
        output_path = os.path.join(output_path, output_filename)
    # --- END NEW ---

    # Assemble the final structured document
    structured_document = f"""CWE_ID: CWE-190
    Vulnerable_Function_Decompiled:
    {bad_func_code}
    ---
    Patched_Function_Decompiled:
    {good_func_code}
    ---
    LLM_Annotation_Root_Cause: "{root_cause}"
    LLM_Annotation_Patch: "{patch_desc}"
    """
        
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        f.write(structured_document)
    
    print(f"\n[DONE] Saved final structured document to {output_path}")
    
if __name__ == "__main__":
    main()
