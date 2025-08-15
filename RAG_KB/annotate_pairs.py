# annotate_pairs.py

import json
import argparse
import os
import pathlib
import re
import logging
from llm_clients import LLMClient

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def extract_json_from_response(text):
    """
    Extracts a JSON object from a string, which might contain other text.
    """
    # This regex is robust enough to find a JSON object even if it's wrapped in text or markdown
    match = re.search(r'\{.*\}', text, re.DOTALL)
    if not match:
        logging.warning("No JSON object found in the LLM response.")
        return None
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError as e:
        logging.error(f"Failed to decode JSON from response: {e}")
        return None

def annotate_and_create_kb(prompts_dir, paired_flows_path, output_path, backend):
    """
    Annotates prompts and creates a knowledge base, now with resume and recovery.
    """
    client = LLMClient(backend)
    
    # --- RESILIENCY: Load already processed entries to allow resuming ---
    processed_prompts = set()
    if os.path.exists(output_path):
        logging.info(f"Found existing knowledge base. Loading processed entries from: {output_path}")
        with open(output_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    # We use a 'source_prompt' key to track which files are done
                    if 'source_prompt' in entry:
                        processed_prompts.add(entry['source_prompt'])
                except json.JSONDecodeError:
                    logging.warning(f"Skipping corrupted line in existing KB file: {line.strip()}")
                    continue
        logging.info(f"Resuming. Found {len(processed_prompts)} already annotated prompts.")

    # Load the mapping from vulnerability name to flow data
    with open(paired_flows_path, 'r', encoding='utf-8') as f:
        paired_flows_data = json.load(f)
    flows_map = {pair['vulnerability_base_name']: pair for pair in paired_flows_data}

    prompt_files = sorted([f for f in os.listdir(prompts_dir) if f.endswith('.txt')])

    for i, filename in enumerate(prompt_files):
        # --- RESILIENCY: Skip this file if it has already been processed ---
        if filename in processed_prompts:
            logging.info(f"Skipping prompt {i+1}/{len(prompt_files)} (already processed): {filename}")
            continue

        logging.info(f"[*] Annotating prompt {i+1}/{len(prompt_files)}: {filename}")
        
        with open(os.path.join(prompts_dir, filename), 'r', encoding='utf-8') as f:
            prompt = f.read()

        # Extract the base name to find the corresponding flow data
        base_name = "_".join(filename.replace("prompt_", "").split("_")[:-1])

        try:
            # This call now has a longer timeout thanks to the updated LLMClient
            response = client.generate(prompt)
            annotation = extract_json_from_response(response['text'])
            
            if annotation and base_name in flows_map:
                kb_entry = annotation
                # Enrich the annotation with data from the flows file
                kb_entry['vulnerability'] = flows_map[base_name].get('vulnerability_base_name')
                # Get the code of the first function in the flow as representative
                kb_entry['bad_code'] = flows_map[base_name]['bad_flow'][0]['code']
                kb_entry['good_code'] = flows_map[base_name]['good_flow'][0]['code']
                # Add the source filename for tracking and resuming
                kb_entry['source_prompt'] = filename

                # --- RESILIENCY: Append to the output file immediately after success ---
                with open(output_path, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(kb_entry) + '\n')
                
                logging.info(f"  [+] Successfully annotated and saved: {filename}")

            else:
                if not annotation:
                    logging.error(f"  [!] Could not extract valid JSON from LLM response for {filename}.")
                if base_name not in flows_map:
                    logging.warning(f"  [!] Could not find matching flow data for {base_name}")

        except Exception as e:
            # This will catch timeouts or any other API/network errors
            logging.critical(f"  [!] A critical error occurred while processing {filename}: {e}")
            logging.critical("      The process will continue with the next file. Progress up to this point is saved.")
            continue # Move to the next prompt

    logging.info(f"\n[DONE] Knowledge base creation complete. Results are in {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Annotate paired prompts and create the knowledge base.")
    parser.add_argument('--prompts-dir', required=True, help="Directory containing the prompt files.")
    parser.add_argument('--paired-flows', required=True, help="Path to the consolidated kb_paired_flows JSON file.")
    parser.add_argument('--output', required=True, help="Path for the final .jsonl knowledge base file.")
    parser.add_argument('--backend', default='gemini', choices=['gemini'], help="LLM backend to use.")
    args = parser.parse_args()
    
    annotate_and_create_kb(args.prompts_dir, args.paired_flows, args.output, args.backend)
