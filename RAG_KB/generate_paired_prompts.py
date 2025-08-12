import json
import argparse
import os
import pathlib

# This prompt is inspired by the methodology in the Vul-RAG paper.
PAIRED_PROMPT_TEMPLATE = """
You are an expert security analyst. I will provide you with a pair of decompiled C functions: one is vulnerable, and the other is the patched, non-vulnerable version. Your task is to analyze both and provide a structured analysis in JSON format.

Here is the vulnerable code:
```c
{vulnerable_code}
```

Here is the patched (non-vulnerable) code:
```c
{patched_code}
```

Please provide your analysis in the following JSON format. Do not include any other text or explanations outside of the JSON block.

```json
{{
  "functional_semantics": "Describe the shared purpose of these two functions in 1-2 sentences. What are they supposed to do?",
  "vulnerability_cause": "Based on the differences between the vulnerable and patched code, explain the root cause of the vulnerability. Be specific about what is missing or incorrect in the vulnerable version.",
  "fixing_solution": "Describe the patch. Explain exactly how the changes in the patched code mitigate the vulnerability."
}}
```
"""

def generate_prompts(input_path, output_dir):
    with open(input_path, 'r') as f:
        paired_flows = json.load(f)

    # Ensure the output directory exists
    pathlib.Path(output_dir).mkdir(parents=True, exist_ok=True)

    for i, pair in enumerate(paired_flows):
        vulnerable_func = pair['bad_flow'][0] # The first function in the chain
        patched_func = pair['good_flow'][0]   # The first function in the chain

        prompt = PAIRED_PROMPT_TEMPLATE.format(
            vulnerable_code=vulnerable_func.get("code", "Code not available."),
            patched_code=patched_func.get("code", "Code not available.")
        )
        
        # FIX: Use the correct key 'vulnerability_base_name' instead of 'sink'
        base_name = pair['vulnerability_base_name']
        prompt_filename = f"prompt_{base_name}_{i}.txt"
        with open(os.path.join(output_dir, prompt_filename), 'w') as f:
            f.write(prompt)

    print(f"[DONE] Generated {len(paired_flows)} annotation prompts in {output_dir}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate annotation prompts for paired flows.")
    parser.add_argument('--input', required=True, help="Path to the paired flows JSON file.")
    parser.add_argument('--output-dir', required=True, help="Directory to save the prompt files.")
    args = parser.parse_args()
    generate_prompts(args.input, args.output_dir)
