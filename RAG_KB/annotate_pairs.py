import json
import argparse
import os
import pathlib
import re
from llm_clients import LLMClient 

def extract_json_from_response(text):
    match = re.search(r'\{.*\}', text, re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return None

def annotate_and_create_kb(prompts_dir, paired_flows_path, output_path, backend):
    client = LLMClient(backend)
    knowledge_base = []
    with open(paired_flows_path, 'r') as f:
        paired_flows_data = json.load(f)
    
    flows_map = {pair['vulnerability_base_name']: pair for pair in paired_flows_data}

    prompt_files = [f for f in os.listdir(prompts_dir) if f.endswith('.txt')]

    for i, filename in enumerate(prompt_files):
        print(f"[*] Annotating prompt {i+1}/{len(prompt_files)}: {filename}")
        with open(os.path.join(prompts_dir, filename), 'r') as f:
            prompt = f.read()

        base_name = "_".join(filename.replace("prompt_", "").split("_")[:-1])

        try:
            response = client.generate(prompt)
            annotation = extract_json_from_response(response['text'])
            
            if annotation and base_name in flows_map:
                
                kb_entry = {
                    "vulnerability": base_name,
                    "functional_semantics": annotation.get("functional_semantics"),
                    "vulnerability_cause": annotation.get("vulnerability_cause"),
                    "fixing_solution": annotation.get("fixing_solution"),
                    "bad_code": flows_map[base_name]['bad_flow'][0].get("code"),
                    "good_code": flows_map[base_name]['good_flow'][0].get("code")
                }
                knowledge_base.append(kb_entry)
            else:
                if not annotation:
                    raise json.JSONDecodeError("Could not extract valid JSON from LLM response.", response['text'], 0)
                if base_name not in flows_map:
                    print(f"  [!] Warning: Could not find matching flow data for {base_name}")

        except (json.JSONDecodeError, KeyError) as e:
            print(f"  [!] Failed to parse LLM response for {filename}: {e}")
            if 'response' in locals():
                 print(f"      Response was: {response.get('text', 'N/A')}")
            continue

    pathlib.Path(os.path.dirname(output_path)).mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w')     as f:
        for entry in knowledge_base:
            f.write(json.dumps(entry) + '\n')

    print(f"\n[DONE] Created knowledge base with {len(knowledge_base)} entries at {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Annotate paired prompts and create the knowledge base.")
    parser.add_argument('--prompts-dir', required=True)
    parser.add_argument('--paired-flows', required=True, help="Path to the kb_paired_flows JSON file.")
    parser.add_argument('--output', required=True)
    parser.add_argument('--backend', default="gemini", choices=["gemini", "local"])
    args = parser.parse_args()
    annotate_and_create_kb(args.prompts_dir, args.paired_flows, args.output, args.backend)
