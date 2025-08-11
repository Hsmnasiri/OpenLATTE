#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
postprocess_kb_chains.py
- Build compact, anonymized, RAG-ready "flow-cards" from exported call-chains.
- Responsibilities:
  * Construct edges from raw nodes
  * Produce stepwise snippets anchored near callsites (radius configurable)
  * Redact Juliet seed names (good*/_bad) to avoid LLM bias
  * Anonymize labels by address (LABEL_MODE = addr|both|seeded; default addr)
  * Trim chains to meaningful sinks; drop noise externals and source-terminals
  * Extract metadata (cwe_family, variant, sample_name) from program name
  * Emit JSONL flow-cards

CLI:
  python postprocess_kb_chains.py \
    --input /path/to/kb_callchains_<BASE>.json \
    --output /path/to/results/kb_flowcards_<BASE>.jsonl

Environment:
  LABEL_MODE   : addr | both | seeded  (default: addr)
  SNIPPET_RADIUS : integer             (default: 5)

Author: you
"""

import os
import re
import json
import argparse
import hashlib
from typing import List, Dict, Any, Tuple

# --- Configuration ------------------------------------------------------------

LABEL_MODE = os.environ.get("LABEL_MODE", "addr").lower()      # addr|both|seeded
SNIPPET_RADIUS = int(os.environ.get("SNIPPET_RADIUS", "5"))

# Externals considered sinks (extend as needed)
DEFAULT_SINKS = {
    "printf", "fprintf", "sprintf", "snprintf", "puts", "putchar", "fwrite",
    "write", "send", "sendto", "execv", "execve", "system", "popen", "execl",
    "__printf_chk", "__fprintf_chk", "__sprintf_chk", "__snprintf_chk"
}

# Externals considered sources/terminals (we typically do not keep flows that end here)
DEFAULT_SOURCE_TERMINALS = {
    "__isoc99_scanf", "__isoc99_fscanf", "scanf", "fscanf", "gets", "fgets",
    "recv", "recvfrom", "read", "rand", "strtol", "strtoul", "strtoll", "strtoull"
}

# Noisy externals we always drop as terminal
DEFAULT_NOISE = {
    "__stack_chk_fail", "__assert_fail", "abort"
}

# Juliet seed-name redaction (anti-bias)
SEED_PAT = re.compile(r'\b(?:good(?:B2G1|B2G2|G2B1|G2B2)?|good|[A-Za-z0-9_]*_bad)\b')

# Program name → metadata (CWE family + variant)
CWE_VARIANT_RE = re.compile(r'^(CWE\d+)_.*__.*?_(\d+[a-z]?)$', re.IGNORECASE)

# --- Utilities ----------------------------------------------------------------

def log(msg: str) -> None:
    print(msg, flush=True)

def norm_ext(name: str) -> str:
    """Normalize common external symbol spellings (PLT, GLIBC suffixes)."""
    if not name:
        return name
    n = name
    # Strip common PLT/Glibc suffixes
    n = re.sub(r'@GLIBC.*$', '', n)
    n = re.sub(r'@plt$', '', n)
    n = n.strip()
    return n

def redact_seed_names(text: str) -> str:
    if not text:
        return text
    return SEED_PAT.sub("FUNC", text)

def display_label(seed_name: str, addr: str) -> str:
    """Return label used in prompts/cards (bias-free by default)."""
    if LABEL_MODE == "addr":
        return f"SUB_{addr}" if addr else "SUB_????"
    if LABEL_MODE == "both":
        base = seed_name or "FUNC"
        return f"{base}@{addr}" if addr else base
    # LABEL_MODE == seeded
    return seed_name or f"SUB_{addr}"

def parse_program_meta(program: str) -> Tuple[str, str, str]:
    """Return (sample_name, cwe_family, variant)."""
    sample_name = program
    cwe_family, variant = "", ""
    m = CWE_VARIANT_RE.match(program)
    if m:
        cwe_family, variant = m.group(1), m.group(2)
    return sample_name, cwe_family, variant

def snippet_window(code: str, kw: str, radius: int = SNIPPET_RADIUS) -> str:
    """Return a small window around the callsite anchor."""
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

def chain_signature(program: str, nodes: List[Dict[str, Any]]) -> str:
    """Build a stable id for the chain based on program and addresses."""
    addrs = [n.get("address", "") for n in nodes]
    payload = f"{program}|{'->'.join(addrs)}"
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:16]

def is_sink_external(name: str) -> bool:
    return norm_ext(name) in DEFAULT_SINKS

def is_source_terminal(name: str) -> bool:
    return norm_ext(name) in DEFAULT_SOURCE_TERMINALS

def is_noise_external(name: str) -> bool:
    return norm_ext(name) in DEFAULT_NOISE

# --- Core builders ------------------------------------------------------------

def build_edges(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Create edges from consecutive nodes using anonymized labels."""
    edges = []
    for i in range(len(nodes) - 1):
        a, b = nodes[i], nodes[i + 1]
        la = display_label(a.get("name", ""), a.get("address", ""))
        lb = display_label(b.get("name", ""), b.get("address", ""))
        edges.append({
            "from": la,
            "to": lb,
            "to_external": bool(b.get("external", False))
        })
    return edges

def build_steps(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Construct step list with snippets anchored on next callee."""
    steps = []
    for i, node in enumerate(nodes):
        name = node.get("name", "")
        addr = node.get("address", "")
        ext = bool(node.get("external", False))
        code = node.get("code", "") if not ext else ""
        next_name = ""
        if i + 1 < len(nodes):
            next_name = norm_ext(nodes[i + 1].get("name", ""))

        snip = snippet_window(code, next_name) if code else ""
        snip = redact_seed_names(snip)

        steps.append({
            "step": i + 1,
            "name": name,                      # original (kept for metadata/debug)
            "display": display_label(name, addr),  # anonymized for prompts
            "address": addr,
            "external": ext,
            "anchor": next_name if next_name else name,
            "snippet": snip
        })
    return steps

def trim_to_first_sink(nodes: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], str]:
    """
    Keep path from start to the first meaningful sink external.
    Drop if ends in noise or source-terminal.
    Return (trimmed_nodes, reason) where reason is empty on success.
    """
    # If last node external is noise/source-terminal → drop
    if nodes:
        last = nodes[-1]
        lname = norm_ext(last.get("name", ""))
        if bool(last.get("external", False)):
            if is_noise_external(lname):
                return [], f"noise:{lname}"
            if is_source_terminal(lname):
                return [], f"source-terminal:{lname}"

    # Prefer first external that is a sink; otherwise keep original if ends at external non-noise
    for i, n in enumerate(nodes):
        if bool(n.get("external", False)) and is_sink_external(n.get("name", "")):
            return nodes[: i + 1], ""

    # If there is any external and it's not noise/source-terminal, keep up to that external
    last_ext_idx = -1
    last_ext_name = ""
    for i, n in enumerate(nodes):
        if bool(n.get("external", False)):
            last_ext_idx = i
            last_ext_name = norm_ext(n.get("name", ""))
    if last_ext_idx >= 0:
        if is_noise_external(last_ext_name) or is_source_terminal(last_ext_name):
            return [], f"terminal:{last_ext_name}"
        return nodes[: last_ext_idx + 1], ""

    # No externals at all; keep full chain (may still be useful)
    return nodes, ""

# --- I/O ----------------------------------------------------------------------

def load_input(path: str) -> Dict[str, Any]:
    with open(path, "r") as f:
        return json.load(f)

def write_jsonl(path: str, items: List[Dict[str, Any]]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        for it in items:
            f.write(json.dumps(it, ensure_ascii=False) + "\n")

# --- Main ---------------------------------------------------------------------

def process(input_path: str, output_path: str) -> None:
    data = load_input(input_path)
    program = data.get("program") or data.get("binary") or data.get("name") or "unknown"
    chains: List[List[Dict[str, Any]]] = data.get("chains", [])

    sample_name, cwe_family, variant = parse_program_meta(program)

    saved = 0
    dropped_noise = 0
    dropped_source_terminal = 0
    dropped_other = 0

    out_cards: List[Dict[str, Any]] = []

    for chain in chains:
        # Basic sanity
        if not chain or len(chain) < 2:
            dropped_other += 1
            continue

        trimmed, reason = trim_to_first_sink(chain)
        if not trimmed:
            if reason.startswith("noise:"):
                dropped_noise += 1
            elif reason.startswith("source-terminal:") or reason.startswith("terminal:"):
                dropped_source_terminal += 1
            else:
                dropped_other += 1
            continue

        steps = build_steps(trimmed)
        edges = build_edges(trimmed)

        # Build a compact human line for quick glance (no seed names)
        chain_disp = " → ".join([s.get("display", "") for s in steps])

        # Construct kb_id (stable, anonymized)
        kbid = chain_signature(program, trimmed)

        card = {
            "kb_id": kbid,
            "program": program,
            "sample_name": sample_name,
            "cwe_family": cwe_family,
            "variant": variant,
            "flow_edges": edges,
            "steps": steps,
            "summary_string": chain_disp,
        }
        out_cards.append(card)
        saved += 1

    write_jsonl(output_path, out_cards)

    log(f"[DONE] wrote {saved} flow-cards → {output_path}")
    log(f"       dropped noise: {dropped_noise}, source-terminal: {dropped_source_terminal}, other: {dropped_other}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="kb_callchains_<BASE>.json")
    ap.add_argument("--output", required=True, help="results/kb_flowcards_<BASE>.jsonl")
    args = ap.parse_args()
    process(args.input, args.output)

if __name__ == "__main__":
    main()
