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

# 1. Define a list of critical sinks in order of importance
CRITICAL_SINKS = [
    # Command Injection
    "execl", "execlp", "execv", "execve", "system", "popen",
    # Buffer Overflow
    "sprintf", "strcpy", "strcat", "memcpy", "memmove", "gets",
    # Format String
    "printf", "fprintf", "snprintf",
    # Other significant sinks
    "send", "sendto", "write", "fwrite", "recv", "recvfrom", "read"
]

def get_criticality(sink_name):
    """Returns the importance of a sink (lower is more important)."""
    try:
        return CRITICAL_SINKS.index(sink_name)
    except ValueError:
        return float('inf') # Not a critical sink, give it the lowest priority

def pair_and_filter_by_vulnerability(input_path, output_path):
    """
    Pairs a vulnerable ('bad') flow with a patched ('good') flow by matching their most critical sink.
    """
    with open(input_path, 'r') as f:
        data = json.load(f)

    bad_chains_by_start = {}
    good_chains = []

    # Separate chains into bad (grouped by start function) and good
    for path in data.get("paths", []):
        chain = path.get("call_chain", [])
        if not chain or len(chain) < 2:
            continue
        
        variant = path.get("variant", "unknown")
        if variant == "bad":
            start_func_name = chain[0].get("name")
            bad_chains_by_start.setdefault(start_func_name, []).append(chain)
        elif "good" in variant:
            good_chains.append(chain)

    vulnerability_pairs = []
    print("[+] Processing flows for vulnerability pairing by matching critical sinks...")

    # 2. Iterate through each bad function found
    for bad_start_func, chains in bad_chains_by_start.items():
        # Find the most critical sink among all chains for this bad function
        critical_sink_chain = None
        min_criticality = float('inf')
        
        for chain in chains:
            is_meaningful, sink = is_meaningful_sink(chain)
            if not is_meaningful:
                continue
            
            criticality = get_criticality(sink)
            if criticality < min_criticality:
                min_criticality = criticality
                critical_sink_chain = chain

        if not critical_sink_chain:
            print(f"  - No meaningful/critical sink found for bad function: {bad_start_func}")
            continue
        
        critical_sink_name = critical_sink_chain[-1].get("name")
        vulnerability_base_name = re.sub(r'_bad$', '', bad_start_func)

        # 3. Find a good chain that matches this single critical sink
        found_good_flow = None
        for good_chain in good_chains:
            _, good_sink = is_meaningful_sink(good_chain)
            if good_sink == critical_sink_name:
                # Optional: check if the good chain name seems related
                if vulnerability_base_name in good_chain[0].get("name").replace("good","CWE"):
                    found_good_flow = good_chain
                    break
        
        # If no directly related good chain was found, take the first match
        if not found_good_flow:
            for good_chain in good_chains:
                _, good_sink = is_meaningful_sink(good_chain)
                if good_sink == critical_sink_name:
                    found_good_flow = good_chain
                    break


        if found_good_flow:
            print(f"  - Creating vulnerability pair for: {vulnerability_base_name}")
            print(f"    - Matched on CRITICAL sink: {critical_sink_name}")
            
            vulnerability_pairs.append({
                "vulnerability_base_name": vulnerability_base_name,
                "bad_flow": critical_sink_chain,
                "good_flow": found_good_flow
            })
        else:
            print(f"  - No matching good flow found for CRITICAL sink '{critical_sink_name}' from {bad_start_func}")


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