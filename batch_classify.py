import argparse
import json
import os
import sys

# switch to the appropriate classification function based on the mode
from classifyLocal import classify_function as classify_functionLocal   
from classifyGemini import classify_function as classify_functionGemini

RESULTS_DIR = "results"

def load_external_funcs(path: str) -> list:
    """Return a list of external functions from a JSON file."""
    try:
        with open(path, "r", encoding="utf-8") as fp:
            return json.load(fp)
    except Exception as e:
        sys.exit(f"[ERR] Cannot parse input file {path}: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Batch-classify functions as taint sources or sinks using a local LLM.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--ext-funcs", required=True,
                        help="Path to the JSON file with exported functions (e.g., external_funcs_<binary>.out.txt).")
    parser.add_argument("--mode", required=True, choices=['source', 'sink'],
                        help="The classification mode: 'source' or 'sink'.")
    parser.add_argument("--output-dir", default=RESULTS_DIR,
                        help="Directory to save the output JSON file.")
    args = parser.parse_args()

    external_funcs = load_external_funcs(args.ext_funcs)

    base_name = os.path.basename(args.ext_funcs) \
                  .replace("external_funcs_", "") \
                  .replace(".out.txt", "")
    os.makedirs(args.output_dir, exist_ok=True)
    output_file = os.path.join(args.output_dir, f"{args.mode}_classification_{base_name}.json")

    results = []
    print(f"[*] Starting classification for {len(external_funcs)} functions in '{args.mode}' mode...")

    for i, func_info in enumerate(external_funcs, 1):
        func_name = func_info.get("name")
        if not func_name:
            continue

        print(f"  ({i}/{len(external_funcs)}) Querying for function: '{func_name}'...")
        
        # This is the key change: a direct call to our classification function
        response = classify_functionGemini(func_name, args.mode)

        if response and response.get("is_true"):
            results.append({
                "function": func_info["name"],
                "addr": func_info["addr"],
                "proto": func_info["proto"],
                f"{args.mode}_result": response
            })
            print(f"    [OK] Classified '{func_name}' as a {args.mode}. Result: {response['params']}")

    with open(output_file, "w", encoding="utf-8") as fp:
        json.dump(results, fp, indent=2, ensure_ascii=False)

    print(f"\n[DONE] Found {len(results)} {args.mode}(s). Results saved to {output_file}")

if __name__ == "__main__":
    main()