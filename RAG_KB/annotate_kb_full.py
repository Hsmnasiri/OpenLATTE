# annotate_kb_full.py
# Builds analysis prompts from full call chains (bad vs. good) and writes a consolidated report.
# This script does not call an LLM directly; it generates clean, structured prompts you can
# feed to your existing LLM runner (e.g., inspect_flows_with_llm.py) or any model of choice.

import json
import argparse
import os
from datetime import datetime

HEADER = """You are a security analyst. Analyze the FULL call flow(s) to the sink and produce a precise assessment.

Tasks:
1) Identify the exact vulnerable line(s) and function(s) along any BAD chain.
2) Explain the root cause (e.g., CWE-190 integer overflow due to pre-increment before bounds check).
3) If GOOD chains exist, point to the exact lines and mechanisms that mitigate the issue.
4) Name the vulnerability class and justify it.
5) If only a wrapper (e.g., FUN_*) is visible before the external sink, reason about the wrapper’s role and the sink behavior.
"""

def render_chain(chain):
    names = " -> ".join([n.get("name","?") for n in chain])
    blocks = []
    for n in chain:
        nm = n.get("name","?")
        addr = n.get("address","?")
        code = n.get("code","").rstrip()
        blocks.append(f"// {nm} @ {addr}\n{code}\n")
    return names, "\n".join(blocks)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)   # build/decompiled_kb_full_<bin>.json
    ap.add_argument("--output", required=True)  # results/annotated_kb_full_<bin>_prompts.txt
    args = ap.parse_args()

    data = json.load(open(args.input, "r"))
    program = data.get("program", "<unknown>")
    items = data.get("items", [])

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as w:
        w.write(f"# Program: {program}\n")
        w.write(f"# Generated: {datetime.utcnow().isoformat()}Z\n\n")
        w.write(HEADER.strip() + "\n\n")

        for idx, item in enumerate(items, 1):
            sink = item.get("sink","<unknown_sink>")
            bad_paths = item.get("bad_paths", [])
            good_paths = item.get("good_paths", [])

            w.write(f"=== ITEM {idx} | SINK: {sink} ===\n\n")

            if bad_paths:
                for i, chain in enumerate(bad_paths, 1):
                    path_str, code_block = render_chain(chain)
                    w.write(f"[BAD CHAIN {i}] {path_str}\n")
                    w.write(code_block + "\n")

            if good_paths:
                for i, chain in enumerate(good_paths, 1):
                    path_str, code_block = render_chain(chain)
                    w.write(f"[GOOD CHAIN {i}] {path_str}\n")
                    w.write(code_block + "\n")

            if not bad_paths and not good_paths:
                w.write("[INFO] No BAD/GOOD chains available for this sink.\n")

            w.write("\n---\n\n")

    print("[DONE] wrote", args.output)

if __name__ == "__main__":
    main()
