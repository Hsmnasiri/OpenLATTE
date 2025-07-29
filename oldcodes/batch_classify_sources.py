#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Batch-classify sources via local LLM API (classify.py).
This is the counterpart to batch_classify_sinks.py.

Usage:
  python batch_classify_sources.py \
         --ext-funcs external_funcs_<binary>.out.txt \
         --output-dir results/
"""

import argparse, json, os, sys, requests

# Assumes classify.py is running and accessible
API_URL     = "http://127.0.0.1:8123/check"
RESULTS_DIR = "results"

# --------------------------------------------------------------------------- #
def load_external_funcs(path):
    """Return list[dict] of external functions from Ghidra export."""
    try:
        with open(path, "r", encoding="utf-8") as fp:
            return json.load(fp)               
    except Exception as e:
        sys.exit(f"[ERR] cannot parse {path}: {e}")

def query_source(func_name):
    """Query the LLM to classify if a function is a taint source."""
    # The key change is setting mode to "source"
    payload = {"func": func_name, "mode": "source"}
    try:
        r = requests.post(API_URL, json=payload, timeout=300)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"[WARN] API failed for {func_name}: {e}")
        return None

# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ext-funcs", required=True,
                    help="Path to external_funcs_<binary>.out.txt")
    ap.add_argument("--output-dir", default=RESULTS_DIR)
    args = ap.parse_args()

    externals = load_external_funcs(args.ext_funcs)
    bin_name  = os.path.basename(args.ext_funcs)          \
                     .replace("external_funcs_", "")      \
                     .replace(".out.txt", "")
    os.makedirs(args.output_dir, exist_ok=True)
    out_file  = os.path.join(args.output_dir,
                             f"source_classification_{bin_name}.json")

    results = []
    for item in externals:
        # Use the source-querying function
        resp = query_source(item["name"])
        if not resp or not resp.get("is_true"):
            continue                               
        results.append({
            "function"    : item["name"],
            "addr"        : item["addr"],
            "proto"       : item["proto"],
            "source_result" : resp                 
        })
        print(f"[OK] {item['name']} → {resp}")

    with open(out_file, "w", encoding="utf-8") as fp:
        json.dump(results, fp, indent=2, ensure_ascii=False)
    print(f"[DONE] {len(results)} source(s) saved to {out_file}")

if __name__ == "__main__":
    main()