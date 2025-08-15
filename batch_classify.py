import argparse
import json
import os
import sys
import time

# switch to the appropriate classification function based on the mode
from classifyGemini import classify_function as classify_functionGemini

RESULTS_DIR = "resultss"
CACHE_FILE = os.path.join(RESULTS_DIR, "classification_cache.json")

def load_external_funcs(path: str) -> list:
    """Return a list of external functions from a JSON file."""
    try:
        with open(path, "r", encoding="utf-8") as fp:
            return json.load(fp)
    except Exception as e:
        sys.exit(f"[ERR] Cannot parse input file {path}: {e}")

def load_cache() -> dict:
    """Loads the classification cache from a JSON file."""
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

def save_cache(cache: dict):
    """Saves the classification cache to a JSON file."""
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2, ensure_ascii=False)

def main():
    parser = argparse.ArgumentParser(
        description="Batch-classify functions as taint sources or sinks using an LLM with caching.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--ext-funcs", required=True,
                        help="Path to the JSON file with exported functions.")
    parser.add_argument("--mode", required=True, choices=['source', 'sink'],
                        help="The classification mode: 'source' or 'sink'.")
    parser.add_argument("--output-dir", default=RESULTS_DIR,
                        help="Directory to save the output JSON file.")
    args = parser.parse_args()
    
    # Load the cache
    cache = load_cache()

    external_funcs = load_external_funcs(args.ext_funcs)

    base_name = os.path.basename(args.ext_funcs) \
                  .replace("external_funcs_", "") \
                  .replace(".txt", "") # Updated to handle new file extension
    os.makedirs(args.output_dir, exist_ok=True)
    output_file = os.path.join(args.output_dir, f"{args.mode}_classification_{base_name}.json")

    results = []
    print(f"[*] Starting classification for {len(external_funcs)} functions in '{args.mode}' mode...")

    cache_updated = False
    for i, func_info in enumerate(external_funcs, 1):
        func_name = func_info.get("name")
        func_proto = func_info.get("proto", "") # Get prototype
        if not func_name:
            continue
        
        # Create a unique key for the cache
        cache_key = f"{func_name}::{args.mode}"

        # Check cache first
        if cache_key in cache:
            print(f"  ({i}/{len(external_funcs)}) Found '{func_name}' in cache. Skipping API call.")
            response = cache[cache_key]
        else:
            print(f"  ({i}/{len(external_funcs)}) Querying for function: '{func_name}'...")
            response = classify_functionGemini(func_name, func_proto, args.mode) # Pass prototype
            cache[cache_key] = response
            cache_updated = True

        if response and response.get("is_true"):
            results.append({
                "function": func_info["name"],
                "addr": func_info["addr"],
                "proto": func_info["proto"],
                f"{args.mode}_result": response
            })
            if cache_key not in cache: # Only print if it was a new classification
                 print(f"    [OK] Classified '{func_name}' as a {args.mode}. Result: {response['params']}")

    # Save the updated cache if any new classifications were made
    if cache_updated:
        save_cache(cache)
        print("[*] Cache has been updated.")

    with open(output_file, "w", encoding="utf-8") as fp:
        json.dump(results, fp, indent=2, ensure_ascii=False)

    print(f"\n[DONE] Found {len(results)} {args.mode}(s). Results saved to {output_file}")

if __name__ == "__main__":
    main()