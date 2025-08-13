import json
import argparse
import os
import pathlib
import re

def is_meaningful_sink(chain):
    """
    Determines if a call chain ends in a meaningful sink, not noise or a source.
    """
    if not chain:
        return False, None
    sink_name = chain[-1].get("name")
    # Exclude common noise/source functions that aren't the vulnerability's manifestation point
    noise_sinks = {"__stack_chk_fail", "__isoc99_fscanf", "fscanf", "scanf"}
    return sink_name not in noise_sinks, sink_name

def pair_and_filter_by_vulnerability(input_path, output_path):
    """
    Pairs a vulnerable ('bad') flow with a patched ('good') flow by matching their sink functions.
    This creates a single, high-quality pair for each vulnerability.
    """
    bad_chains = []
    good_chains = []

    with open(input_path, 'r') as f:
        data = json.load(f)

    # 1. Separate all bad and good chains
    for path in data.get("paths", []):
        variant = path.get("variant", "unknown")
        chain = path.get("call_chain", [])
        if not chain or len(chain) < 2:  # Ignore trivial chains
            continue
        
        if variant == "bad":
            bad_chains.append(chain)
        elif "good" in variant:
            good_chains.append(chain)

    vulnerability_pairs = []
    processed_bad_funcs = set()
    print("[+] Processing flows for vulnerability pairing by matching sinks...")

    # 2. Iterate through bad chains to find a primary vulnerability example
    for bad_chain in bad_chains:
        is_meaningful, sink = is_meaningful_sink(bad_chain)
        if not is_meaningful:
            continue

        bad_start_func = bad_chain[0].get("name")
        if bad_start_func in processed_bad_funcs:
            continue # Already found a pair for this vulnerability

        vulnerability_base_name = re.sub(r'_bad$', '', bad_start_func)

        # 3. Find a corresponding 'good' flow with the same sink
        found_good_flow = None
        # Search through all available good chains for a matching sink
        for good_chain in good_chains:
            _, good_sink = is_meaningful_sink(good_chain)
            if good_sink == sink:
                found_good_flow = good_chain
                break  # Found the first matching good flow, so we stop
            
        if found_good_flow:
            print(f"  - Creating vulnerability pair for: {vulnerability_base_name}")
            print(f"    - Matched on sink: {sink}")
            
            vulnerability_pairs.append({
                "vulnerability_base_name": vulnerability_base_name,
                "bad_flow": bad_chain,
                "good_flow": found_good_flow
            })
            processed_bad_funcs.add(bad_start_func) # Mark as processed
        else:
            print(f"  - No matching good flow found for bad flow ending in sink: {sink}")

    # Ensure the output directory exists
    pathlib.Path(os.path.dirname(output_path)).mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(vulnerability_pairs, f, indent=2)

    print(f"\n[DONE] Wrote {len(vulnerability_pairs)} unique vulnerability pairs to {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pair flows by vulnerability to create a clean KB.")
    parser.add_argument('--input', required=True, help="Path to the input kb_callchains_*.json file.")
    parser.add_argument('--output', required=True, help="Path to save the paired flows JSON file.")
    args = parser.parse_args()
    pair_and_filter_by_vulnerability(args.input, args.output)
