# assemble_kb_for_annotation.py
# Assembles per-sink buckets of good/bad chains for downstream annotation.

import json
import argparse
import os

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)   # build/kb_callchains_<bin>.json
    ap.add_argument("--output", required=True)  # build/decompiled_kb_full_<bin>.json
    args = ap.parse_args()

    data = json.load(open(args.input, "r"))
    buckets = {}  # sink_name -> {"bad":[], "good":[], "unknown":[]}

    for p in data.get("paths", []):
        chain = p.get("call_chain", [])
        if not chain:
            continue
        sink_name = chain[-1].get("name", "<unknown_sink>")
        variant = p.get("variant", "unknown")
        b = buckets.setdefault(sink_name, {"bad": [], "good": [], "unknown": []})
        if variant not in b:
            variant = "unknown"
        b[variant].append(chain)

    out = {
        "program": data.get("program"),
        "items": [
            {
                "sink": sink,
                "bad_paths": grp["bad"],
                "good_paths": grp["good"],
                "unknown_paths": grp["unknown"],
            }
            for sink, grp in buckets.items()
        ],
    }

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(out, f, indent=2)
    print("[DONE] wrote", args.output)

if __name__ == "__main__":
    main()
