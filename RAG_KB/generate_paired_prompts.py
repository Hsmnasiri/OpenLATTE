import argparse
import json
import os
from pathlib import Path

def main():
    """
    Generates detailed analysis prompts from pre-processed paired-flow JSON files.
    This script reads a JSON file containing pairs of vulnerable ('bad_flow') and
    patched ('good_flow') execution chains and formats them into a structured
    prompt for an LLM security analyst.
    """
    parser = argparse.ArgumentParser(description="Generate flow-based prompts from paired flow data.")
    # These arguments match the ones used in your build_kb_batch.sh script
    parser.add_argument("--input", required=True, help="Path to the kb_paired_flows_...json file.")
    parser.add_argument("--output-dir", required=True, help="Directory to save the generated prompt files.")
    
    args = parser.parse_args()

    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            # The input JSON file contains a list of flow pairs
            paired_flows_data = json.load(f)
    except FileNotFoundError:
        print(f"Error: Input file not found at {input_path}")
        return
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from {input_path}")
        return

    # Process each pair of vulnerable/patched flows found in the input file
    for i, pair in enumerate(paired_flows_data):
        vulnerable_flow = pair.get("bad_flow")
        patched_flow = pair.get("good_flow")
        base_name = pair.get("vulnerability_base_name", f"unknown_pair_{i}")

        # Ensure both flows exist before creating a prompt
        if not vulnerable_flow or not patched_flow:
            print(f"Warning: Skipping pair for '{base_name}' due to missing vulnerable or patched flow data.")
            continue

        # This is the ideal prompt structure you requested
        prompt = {
            "analysis_task": {
                "instruction": "You are an expert security analyst. The following JSON contains two code execution paths: one vulnerable and one patched. Each path is an ordered sequence of functions from a data source to a sink. Your task is to analyze the entire flow of data and control between these functions. Based on the differences, provide a structured analysis in the specified JSON format without any additional text.",
                "vulnerable_flow": vulnerable_flow,
                "patched_flow": patched_flow
            },
            "output_format": {
                "functional_semantics": "Describe the overall purpose of this code flow across all provided functions.",
                "vulnerability_cause": "Based on the entire execution path, explain the root cause of the vulnerability. Detail how data flows from the source in the first function to the sink in the subsequent function(s) and where the logic fails in the vulnerable version.",
                "fixing_solution": "Describe the patch. Explain exactly how the changes in the patched flow, including any new checks or function calls, mitigate the vulnerability by interrupting the unsafe data flow."
            }
        }

        # Create a unique filename for each prompt
        output_filename = f"prompt_{base_name}_{i}.txt"
        output_path = output_dir / output_filename
        
        # Write the complete JSON prompt to the output text file
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(prompt, f, indent=4)

    print(f"Successfully generated {len(paired_flows_data)} prompts in: {output_dir}")

if __name__ == "__main__":
    main()
