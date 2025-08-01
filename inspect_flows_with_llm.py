"""
inspect_flows_with_llm.py - Implements LATTE Phase 3: Prompt Sequence Construction.

This script takes the output from the Ghidra analysis (flows_with_code.json)
and converses with an LLM (either local Ollama or Google Gemini) to get a
final vulnerability judgment.
"""
import json
import requests
import argparse
import os
import time
import google.generativeai as genai
from dotenv import load_dotenv
load_dotenv()

OLLAMA_API_URL = "http://localhost:11434/api/chat"
OLLAMA_MODEL = "mistral"
    
GEMINI_API_KEY = os.getenv("GOOGLE_API_KEY42", "YOUR_API_KEY")
GEMINI_MODEL = 'gemini-1.5-pro' 

START_PROMPT_TEMPLATE = """
As a program analyst, I give you snippets of C code generated by decompilation, using
<{function}> as the taint source, and the <{parameter}> parameter marked as the taint label
to extract the taint data flow. Pay attention to the data alias and tainted data operations.
Output in the form of data flows.
<Code to be analyzed>
{code}
"""

MIDDLE_PROMPT_TEMPLATE = """
Continue to analyze function according to the above taint analysis results. Pay attention to
the data alias and tainted data operations.
<Code to be analyzed>
{code}
"""

END_PROMPT_TEMPLATE = """
Based on the above taint analysis results, analyze whether the code has vulnerabilities. If
there is a vulnerability, please explain what kind of vulnerability according to CWE.
"""

def query_ollama(messages):
    """
    Sends the entire conversation history to the Ollama API and gets the next response.
    """
    print("--- Sending Prompt to Ollama ---")
    print(messages[-1]['content'])
    
    try:
        response = requests.post(
            OLLAMA_API_URL,
            json={"model": OLLAMA_MODEL, "messages": messages, "stream": False},
            timeout=300 # 5 minute timeout for long responses
        )
        response.raise_for_status()
        response_json = response.json()
        response_text = response_json['message']['content']

        print("--- Ollama Response ---")
        print(response_text + "\n")
        return response_text

    except requests.exceptions.RequestException as e:
        print(f"\n[FATAL] API Error: Could not connect to Ollama at {OLLAMA_API_URL}.")
        print("Please ensure Ollama is running and you have pulled the model with 'ollama pull {}'".format(OLLAMA_MODEL))
        return None

def query_gemini(messages, retries=3):
    """
    Sends the entire conversation history to the Gemini API and gets the next response.
    """
    print("--- Sending Prompt to Gemini ---")
    print(messages[-1]['content'])
    
    if GEMINI_API_KEY == "YOUR_API_KEY":
        print("[FATAL] Please replace 'YOUR_API_KEY' with your actual Google Gemini API key.")
        return None

    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel(GEMINI_MODEL)
    
    gemini_messages = []
    for msg in messages:
        if msg['role'] == 'system':
            continue
        
        role = 'model' if msg['role'] == 'assistant' else 'user'
        
        gemini_messages.append({'role': role, 'parts': [msg['content']]})

    for attempt in range(retries):
        try:
            safety_settings = {
                'HARM_CATEGORY_HARASSMENT': 'BLOCK_NONE',
                'HARM_CATEGORY_HATE_SPEECH': 'BLOCK_NONE',
                'HARM_CATEGORY_SEXUALLY_EXPLICIT': 'BLOCK_NONE',
                'HARM_CATEGORY_DANGEROUS_CONTENT': 'BLOCK_NONE',
            }
            response = model.generate_content(gemini_messages, safety_settings=safety_settings)
            response_text = response.text.strip()
            
            print("--- Gemini Response ---")
            print(response_text + "\n")

            time.sleep(4.1)
            return response_text

        except Exception as e:
            print(f"[WARN] Gemini API call failed on attempt {attempt + 1}/{retries}: {e}")
            if attempt < retries - 1:
                time.sleep(5 * (attempt + 1))
            else:
                return f"API Error after {retries} attempts: {e}"
    
    return None


def main():
    parser = argparse.ArgumentParser(description="LATTE Phase 3: Inspect dangerous flows with an LLM.")
    parser.add_argument('--flows-with-code', required=True, help="Path to the flows_with_code.json file.")
    parser.add_argument('--sources', required=True, help="Path to the source classification JSON file.")
    parser.add_argument('--output', required=True, help="Path to save the final vulnerability reports.")
    parser.add_argument('--llm-mode', choices=['local', 'gemini'], default='local', 
                        help="The LLM mode to use: 'local' for Ollama or 'gemini' for Google Gemini.")
    args = parser.parse_args()

    with open(args.flows_with_code, 'r') as f:
        dangerous_flows = json.load(f)
    with open(args.sources, 'r') as f:
        sources_info = {s['function']: s for s in json.load(f)}

    vulnerability_reports = []

    for i, flow in enumerate(dangerous_flows):
        print(f"--- Analyzing Flow #{i+1} / {len(dangerous_flows)} using {args.llm_mode.upper()} mode ---")
        
        messages = [{'role': 'system', 'content': 'You are a helpful and concise C security analyst.'}]
        
        funcs_in_trace = list(dict.fromkeys([step['caller_func'] for step in flow['flow_trace']]))
        
        query_llm = query_gemini if args.llm_mode == 'gemini' else query_ollama

        # 1. Start Prompt
        start_func_name = funcs_in_trace[0]
        source_func_name = flow['source_info']['source_function_called']
        source_params = sources_info.get(source_func_name, {}).get('source_result', {}).get('params', '[Unknown]')
        code_for_start_prompt = next((step['code'] for step in flow['flow_trace'] if step['caller_func'] == start_func_name), "")
        
        start_prompt = START_PROMPT_TEMPLATE.format(function=source_func_name, parameter=str(source_params), code=code_for_start_prompt)
        messages.append({'role': 'user', 'content': start_prompt})
        
        response = query_llm(messages)
        if response is None: continue # Skip flow if API fails
        messages.append({'role': 'assistant', 'content': response})

        # 2. Middle Prompts (if any)
        if len(funcs_in_trace) > 1:
            for middle_func_name in funcs_in_trace[1:]:
                code_for_middle_prompt = next((step['code'] for step in flow['flow_trace'] if step['caller_func'] == middle_func_name), "")
                middle_prompt = MIDDLE_PROMPT_TEMPLATE.format(code=code_for_middle_prompt)
                messages.append({'role': 'user', 'content': middle_prompt})
                
                response = query_llm(messages)
                if response is None: break
                messages.append({'role': 'assistant', 'content': response})
        
        # 3. End Prompt
        messages.append({'role': 'user', 'content': END_PROMPT_TEMPLATE})
        final_judgment = query_llm(messages)
        if final_judgment is None: continue
        messages.append({'role': 'assistant', 'content': final_judgment})

        report = {
            'flow_info': flow,
            'conversation': messages, # Save the full conversation
            'final_judgment': final_judgment
        }
        vulnerability_reports.append(report)

    with open(args.output, 'w') as f:
        json.dump(vulnerability_reports, f, indent=2)
    print(f"\n[DONE] Saved {len(vulnerability_reports)} vulnerability reports to {args.output}")


if __name__ == "__main__":
    main()
