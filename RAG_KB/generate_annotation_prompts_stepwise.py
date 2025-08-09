#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generate three separate prompt files (semantics, root cause, fix) from flow-cards JSONL.
No model calls here; just prompt construction with clear metadata for stable batching.
"""

import argparse, json, os, pathlib

SEMANTICS_TMPL = """You are a security analyst. Summarize the function-level semantics of the following flow.
Focus on what each step does (inputs, transformations, outputs). Avoid CWE labels or vulnerability claims.
Return a single concise paragraph (<=120 words).

META:
- kb_id: {kb_id}
- sample: {sample}
- cwe_family_hint: {cwe}

FLOW SUMMARY:
{summary}

STEPS (ordered):
{steps}
"""

ROOTCAUSE_TMPL = """You are a security analyst. Explain the likely ROOT CAUSE of the vulnerability pattern for this flow.
Use the CWE family hint if relevant, but base reasoning ONLY on the snippets and API usage.
Return 2-5 sentences, crisp, referencing concrete operations (e.g., increment without bounds).

META:
- kb_id: {kb_id}
- sample: {sample}
- cwe_family_hint: {cwe}

FLOW SUMMARY:
{summary}

STEPS (ordered):
{steps}
"""

FIX_TMPL = """You are a security analyst. Describe the PATCHED BEHAVIOR that would mitigate this flow's risk.
Be specific (what guard or transformation must be added, where). Avoid generic advice.
Return 2-5 sentences. If a guard on limits is appropriate, name the exact bound (e.g., CHAR_MAX, INT_MAX).

META:
- kb_id: {kb_id}
- sample: {sample}
- cwe_family_hint: {cwe}

FLOW SUMMARY:
{summary}

STEPS (ordered):
{steps}
"""

def steps_to_text(steps):
    chunks = []
    for s in steps:
        header = f"- Step {s['step']}: {s['name']} @ {s['address']}"
        body = s.get("snippet","").strip()
        if body:
            chunk = header + "\n" + body
        else:
            chunk = header
        chunks.append(chunk)
    return "\n\n".join(chunks)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--flowcards", required=True)
    ap.add_argument("--out_dir", required=True)
    args = ap.parse_args()

    semantics, rootcause, fix = [], [], []
    with open(args.flowcards, "r") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            d = json.loads(line)
            kb_id = d["kb_id"]
            sample = d.get("sample_name", d.get("program","sample"))
            cwe = d.get("cwe_family","")
            summary = d.get("summary_string","")
            steps_text = steps_to_text(d.get("steps", []))

            semantics.append(SEMANTICS_TMPL.format(kb_id=kb_id, sample=sample, cwe=cwe, summary=summary, steps=steps_text))
            rootcause.append(ROOTCAUSE_TMPL.format(kb_id=kb_id, sample=sample, cwe=cwe, summary=summary, steps=steps_text))
            fix.append(FIX_TMPL.format(kb_id=kb_id, sample=sample, cwe=cwe, summary=summary, steps=steps_text))

    pathlib.Path(args.out_dir).mkdir(parents=True, exist_ok=True)
    with open(os.path.join(args.out_dir, "prompts_semantics.txt"), "w") as f:
        f.write("\n\n".join(f"# item {i+1}\n{p}" for i,p in enumerate(semantics)))
    with open(os.path.join(args.out_dir, "prompts_rootcause.txt"), "w") as f:
        f.write("\n\n".join(f"# item {i+1}\n{p}" for i,p in enumerate(rootcause)))
    with open(os.path.join(args.out_dir, "prompts_fix.txt"), "w") as f:
        f.write("\n\n".join(f"# item {i+1}\n{p}" for i,p in enumerate(fix)))

    print(f"[DONE] prompts → {args.out_dir}/prompts_*.txt (semantics/rootcause/fix)")

if __name__ == "__main__":
    main()
