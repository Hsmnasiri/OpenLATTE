#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generate stepwise LLM prompts from RAG-ready flow-cards (JSONL).
- Input: kb_flowcards_*.jsonl (produced by postprocess_kb_chains.py)
- Output: prompts_semantics.txt, prompts_rootcause.txt, prompts_fix.txt
- Design goals:
  * No seed names (good*/bad) in prompts (we use steps[].display which is anonymized address labels).
  * Minimal metadata exposure; keep prompts focused on chain behavior and snippets.
  * Stable, batch-friendly format with clear item delimiters.
"""

import argparse
import json
import os
import pathlib
from typing import List, Dict, Any

ITEM_HDR = "# item {n}"

SEMANTICS_INSTR = """## TASK
You are given an anonymized call chain (address-labeled) with small decompiled snippets around callsites.
Describe concisely what the chain does, focusing on data flow and observable side effects (I/O, arithmetic, branching).
Keep it objective, do not invent missing details, and do not infer function names.
Return 3–5 sentences, no markdown, no code.
"""

ROOTCAUSE_INSTR = """## TASK
Analyze the same anonymized chain for potential vulnerability root cause(s), if any.
Discuss the risky operations (e.g., unchecked arithmetic, unsafe input use, format or command construction), and conditions under which exploitation is feasible.
If you see no realistic risk, say so briefly and explain why.
Return 3–6 sentences, no markdown, no code.
"""

FIX_INSTR = """## TASK
Suggest a minimal and concrete mitigation to make the chain safe if it were vulnerable.
Describe the guard/condition/check or alternative API choice and where in the chain it should be applied.
If the chain already appears safe, state the specific reason it is safe and what invariant or check enforces it.
Return 2–4 sentences, no markdown, no code.
"""

def load_jsonl(path: str) -> List[Dict[str, Any]]:
    items = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            items.append(json.loads(line))
    return items

def chain_display(fc: Dict[str, Any]) -> str:
    # Prefer the step-level anonymized labels prepared by postprocess_kb_chains.py
    steps = fc.get("steps", [])
    if steps:
        disp = [s.get("display", "") for s in steps if s.get("display")]
        if disp:
            return " → ".join(disp)
    # Fallback: compact summary_string if steps missing (should rarely happen)
    return fc.get("summary_string", "N/A")

def steps_block(fc: Dict[str, Any]) -> str:
    out = []
    for s in fc.get("steps", []):
        disp = s.get("display", "")
        snip = s.get("snippet", "") or ""
        if not disp:
            continue
        # Only include steps with any snippet to keep prompts short
        if snip.strip():
            out.append(f"- Step {s.get('step')}: {disp}\n```c\n{snip}\n```")
        else:
            out.append(f"- Step {s.get('step')}: {disp}")
    return "\n".join(out).strip()

def one_prompt(fc: Dict[str, Any], instr: str) -> str:
    kb_id = fc.get("kb_id", "kb:unknown")
    flow = chain_display(fc)
    steps_txt = steps_block(fc)
    # Strictly avoid seed/sample/cwe names in the prompt. We do not include sample_name/cwe_family/variant.
    body = [
        "## META",
        f"- kb_id: {kb_id}",
        "- anonymized: true",
        "",
        "## FLOW",
        flow,
        "",
        "## STEPS",
        steps_txt if steps_txt else "(no snippets available)"
    ]
    return "\n".join([instr.strip(), ""] + body).strip()

def write_prompts(flows: List[Dict[str, Any]], out_path: str, kind: str) -> None:
    """
    kind ∈ {semantics, rootcause, fix}
    """
    if kind == "semantics":
        instr = SEMANTICS_INSTR
    elif kind == "rootcause":
        instr = ROOTCAUSE_INSTR
    elif kind == "fix":
        instr = FIX_INSTR
    else:
        raise ValueError("unknown prompt kind")

    lines = []
    for i, fc in enumerate(flows, 1):
        lines.append(ITEM_HDR.format(n=i))
        lines.append(one_prompt(fc, instr))
        lines.append("")  # separator blank line
    text = "\n".join(lines).rstrip() + "\n"

    pathlib.Path(os.path.dirname(out_path)).mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        f.write(text)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--flowcards", required=True, help="Path to kb_flowcards_*.jsonl")
    ap.add_argument("--out_dir", required=True, help="Directory to write prompt files")
    args = ap.parse_args()

    flows = load_jsonl(args.flowcards)

    out_sem = os.path.join(args.out_dir, "prompts_semantics.txt")
    out_rc  = os.path.join(args.out_dir, "prompts_rootcause.txt")
    out_fix = os.path.join(args.out_dir, "prompts_fix.txt")

    write_prompts(flows, out_sem, "semantics")
    write_prompts(flows, out_rc,  "rootcause")
    write_prompts(flows, out_fix, "fix")

    print(f"[DONE] prompts → {out_sem}")
    print(f"[DONE] prompts → {out_rc}")
    print(f"[DONE] prompts → {out_fix}")

if __name__ == "__main__":
    main()
