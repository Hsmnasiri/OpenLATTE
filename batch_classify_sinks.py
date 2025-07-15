import requests
import os
import argparse
import json

API_URL = "http://127.0.0.1:8123/check"
RESULTS_DIR = "results"

def parse_functions(file_path):
    funcs = []
    with open(file_path, "r") as f:
        for line in f:
            parts = line.strip().split(" : ")
            if len(parts) >= 1 and parts[0]:
                func_name = parts[0]
                funcs.append(func_name)
    return funcs

def classify_sink(func_name):
    payload = {"func": func_name, "mode": "sink"}
    try:
        response = requests.post(API_URL, json=payload, timeout=300)
        response.raise_for_status()
        print(response.json())
        return response.json()
    except Exception as e:
        print(f"[ERROR] Failed to classify '{func_name}' as sink: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description="Batch classify sinks for LATTE pipeline.")
    parser.add_argument(
        "--ext-funcs",
        required=True,
        help="Path to external_funcs_<binary>.out.txt"
    )
    parser.add_argument(
        "--output-dir",
        default=RESULTS_DIR,
        help="Directory to save results (default: results/)"
    )
    args = parser.parse_args()

    ext_funcs_file = args.ext_funcs
    binary_name = os.path.basename(ext_funcs_file).replace("external_funcs_", "").replace(".out.txt", "")
    out_dir = args.output_dir
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, f"sink_classification_{binary_name}.json")

    funcs = parse_functions(ext_funcs_file)
    print(f"[INFO] Loaded {len(funcs)} external functions from {ext_funcs_file}")

    all_results = []
    for func in funcs:
        result = classify_sink(func)
        all_results.append({"function": func, "sink_result": result})
        print(f"[LOG] Classified {func} | Sink: {result}")

    with open(out_file, "w") as fw:
        json.dump(all_results, fw, indent=2, ensure_ascii=False)

    print(f"[SUCCESS] All sinks classified. Results saved to {out_file}")
 



if __name__ == "__main__":
    main()
