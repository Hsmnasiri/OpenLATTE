#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Post-process kb_callchains_*.json into compact, RAG-ready "flow-cards":
- Filter by SOURCES/SINKS/NOISE
- Keep only valid sink-terminated chains
- Build numbered steps with short decompile windows around callsites
- Attach metadata: sample_name, cwe_family, variant, summary_string
- Output JSONL (one flow-card per chain)
"""

import argparse, json, os, re, pathlib
from typing import List, Dict, Any

LABEL_MODE = os.environ.get("LABEL_MODE", "addr")  # addr | both | seeded
SEED_PAT = re.compile(r'\b(good(?:B2G1|B2G2|G2B1|G2B2)?|good|.*_bad)\b')

def display_label(name: str, addr: str) -> str:
    if LABEL_MODE == "addr":
        return f"SUB_{addr}"
    if LABEL_MODE == "both":
        return f"{name}@{addr}"
    return name  # "seeded" (not recommended for unbiased prompts)
def redact_seed_names(text: str) -> str:
    if not text:
        return text
    return SEED_PAT.sub("FUNC", text)
SOURCES = {
    # integer-like sources
    "fscanf", "__isoc99_fscanf", "scanf", "gets", "getline", "read", "recv", "rand",
    # command injection sources
    "fopen", "fgets", "getenv", "_wgetenv",
}
SINKS = {
    # evidence (printing/logging)
    "printf", "puts", "sprintf", "snprintf", "write",
    # command execution
    "execv", "execl", "execve", "popen", "_popen", "system",
}
NOISE = {"__stack_chk_fail"}

def norm_ext(name: str) -> str:
    # strip ABI suffix like '@plt' or '@GLIBC'
    return (name or "").split("@")[0]

def classify_terminal(name: str) -> str:
    n = norm_ext(name)
    if n in NOISE:   return "noise"
    if n in SOURCES: return "source-terminal"
    if n in SINKS:   return "sink"
    return "other-external"

def parse_meta_from_program(program: str):
    # Examples:
    #   CWE190_Integer_Overflow__char_fscanf_preinc_05
    #   CWE78_OS_Command_Injection__char_file_w32_execv_04
    m = re.match(r'^(CWE\d+)_.*__(?:.*)_(\d+[a-z]?)$', program)
    cwe_family = m.group(1) if m else ""
    variant = m.group(2) if m else ""
    sample_name = program
    return cwe_family, variant, sample_name

def window_around_keyword(code: str, kw: str, radius: int = 5) -> str:
    if not code:
        return ""
    lines = code.splitlines()
    anchors = []
    if kw:
        anchors = [i for i, ln in enumerate(lines) if f"{kw}(" in ln]
    if not anchors and kw:
        anchors = [i for i, ln in enumerate(lines) if kw in ln]
    if not anchors:
        start = 0
        end = min(len(lines), radius * 2 + 1)
        return "\n".join(lines[start:end]).strip()
    i = anchors[0]
    start = max(0, i - radius)
    end = min(len(lines), i + radius + 1)
    return "\n".join(lines[start:end]).strip()

def build_steps(chain):
    steps = []
    for idx, node in enumerate(chain):
        name = node.get("name","")
        addr = node.get("address","")
        is_ext = bool(node.get("external", False))
        code = node.get("code","") if not is_ext else ""
        next_name = ""
        if idx + 1 < len(chain):
            next_name = norm_ext(chain[idx + 1].get("name",""))
        snippet = window_around_keyword(code, next_name) if code else ""
        snippet = redact_seed_names(snippet)  # <--- anti-bias
        steps.append({
            "step": idx + 1,
            "name": name,
            "display": display_label(name, addr),  # <--- for prompts
            "address": addr,
            "external": is_ext,
            "anchor": next_name if next_name else name,
            "snippet": snippet
        })
    return steps

def build_flow_edges(call_chain):
    edges = []
    for i in range(len(call_chain) - 1):
        a = call_chain[i]; b = call_chain[i+1]
        edges.append({
            "from": display_label(a.get("name",""), a.get("address","")),
            "to":   display_label(b.get("name",""), b.get("address","")),
            "to_external": bool(b.get("external", False))
        })
    return edges

def flow_summary(chain: List[Dict[str, Any]]) -> str:
    names = [norm_ext(n.get("name","")) for n in chain]
    return "FLOW: " + " -> ".join(names)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--callchains", required=True)
    ap.add_argument("--out_jsonl", required=True)
    args = ap.parse_args()

    with open(args.callchains, "r") as f:
        data = json.load(f)

    program = data.get("program", "sample")
    cwe_family, variant, sample_name = parse_meta_from_program(program)

    out_lines = []
    kept, dropped_noise, source_term = 0, 0, 0

    for p in data.get("paths", []):
        chain = p.get("call_chain", [])
        if not chain:
            continue
        term = chain[-1]
        term_name = norm_ext(term.get("name",""))
        tclass = classify_terminal(term_name)

        if tclass == "noise":
            dropped_noise += 1
            continue  # hard drop

        if tclass == "source-terminal":
            # keep only as a side artifact if you need stats; skip from KB main
            source_term += 1
            continue

        if tclass != "sink":
            # non-sink externals are rarely helpful for KB matching; skip
            continue

        # Valid sink-terminated chain
        steps = build_steps(chain)
        summary = flow_summary(chain)
        doc = {
            "kb_id": f"{program}::{term_name}::{len(out_lines)+1}",
            "program": program,
            "sample_name": sample_name,
            "cwe_family": cwe_family,
            "variant": variant,
            "terminal_class": tclass,
            "sink_name": term_name,
            "flow_edges": [norm_ext(n.get("name","")) for n in chain],
            "summary_string": summary,
            "steps": steps,
        }
        out_lines.append(json.dumps(doc, ensure_ascii=False))
        kept += 1

    pathlib.Path(os.path.dirname(args.out_jsonl)).mkdir(parents=True, exist_ok=True)
    with open(args.out_jsonl, "w") as f:
        f.write("\n".join(out_lines) + ("\n" if out_lines else ""))

    print(f"[DONE] wrote {kept} flow-cards → {args.out_jsonl}")
    print(f"       dropped noise: {dropped_noise}, source-terminal skipped: {source_term}")

if __name__ == "__main__":
    main()
