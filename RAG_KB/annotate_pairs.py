import json
import argparse
import os
import pathlib
import re
from llm_clients import LLMClient # Assuming your llm_clients.py is in the same directory

def extract_json_from_response(text):
    """
    Extracts a JSON object from a string, even if it's wrapped in markdown code blocks.
    """
    # Find the start of the JSON object
    json_start_match = re.search(r'\{', text)
    if not json_start_match:
        return None

    # Find the end of the JSON object by matching braces
    json_start_index = json_start_match.start()
    open_braces = 0
    for i, char in enumerate(text[json_start_index:]):
        if char == '{':
            open_braces += 1
        elif char == '}':
            open_braces -= 1
            if open_braces == 0:
                json_end_index = json_start_index + i + 1
                json_str = text[json_start_index:json_end_index]
                try:
                    return json.loads(json_str)
                except json.JSONDecodeError:
                    return None
    return None


def annotate_and_create_kb(prompts_dir, output_path, backend):
    """
    Reads all prompt files from a directory, gets annotations from the LLM,
    and creates the final knowledge base.
    """
    client = LLMClient(backend)
    knowledge_base = []

    prompt_files = [f for f in os.listdir(prompts_dir) if f.endswith('.txt')]

    for i, filename in enumerate(prompt_files):
        print(f"[*] Annotating prompt {i+1}/{len(prompt_files)}: {filename}")
        with open(os.path.join(prompts_dir, filename), 'r') as f:
            prompt = f.read()

        # Extract vulnerability base name from filename
        # e.g., prompt_CWE190_Integer_Overflow__char_fscanf_preinc_05_0.txt -> CWE190...
        base_name = "_".join(filename.replace("prompt_", "").split("_")[:-1])

        try:
            response = client.generate(prompt)
            # Use the robust extraction function to get the JSON
            annotation = extract_json_from_response(response['text'])
            
            if annotation:
                annotation['vulnerability'] = base_name
                knowledge_base.append(annotation)
            else:
                raise json.JSONDecodeError("Could not extract valid JSON from LLM response.", response['text'], 0)

        except (json.JSONDecodeError, KeyError) as e:
            print(f"  [!] Failed to parse LLM response for {filename}: {e}")
            if 'response' in locals():
                 print(f"      Response was: {response.get('text', 'N/A')}")
            continue

    # Write the final knowledge base to a JSONL file
    pathlib.Path(os.path.dirname(output_path)).mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        for entry in knowledge_base:
            f.write(json.dumps(entry) + '\n')

    print(f"\n[DONE] Created knowledge base with {len(knowledge_base)} entries at {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Annotate paired prompts and create the knowledge base.")
    parser.add_argument('--prompts-dir', required=True, help="Directory containing the prompt files.")
    parser.add_argument('--output', required=True, help="Path to save the final knowledge base JSONL file.")
    parser.add_argument('--backend', default="gemini", choices=["gemini", "local"], help="LLM backend to use.")
    args = parser.parse_args()
    annotate_and_create_kb(args.prompts_dir, args.output, args.backend)
