"""
latte_callchain_headless.py – LATTE Algorithm 1 (Lines 6‑15)
============================================================
**Headless‑only** implementation that runs via

```bash
analyzeHeadless <proj_dir> <proj_name> \
  -import <binary> \
  -postScript latte_callchain_headless.py <sink_json>
```

Prerequisites
-------------
* Ghidra 11.3.2 with **Ghidrathon 4.0**.
* The *sink‑classification* JSON (output of Algorithm 1 lines 1‑5).

Output
------
* `_latte_vds.json` – list of Vulnerable Destinations.
* `_latte_cc.json`  – corresponding call‑chains.
"""

import json
from pathlib import Path

# ---------------------------------------------------------------------------
#  Ghidra headless environment objects – injected by analyzeHeadless
# ---------------------------------------------------------------------------
#   currentProgram   – a *callable* that returns the Program object
#   getMonitor()     – provides a TaskMonitor
# ---------------------------------------------------------------------------
program  = currentProgram()          # type: ignore  – callable in headless
monitor  = getMonitor()              # type: ignore

from ghidra.program.flatapi import FlatProgramAPI
from ghidra.app.decompiler import DecompInterface, DecompileOptions

fapi      = FlatProgramAPI(program)
func_mgr  = program.getFunctionManager()
ref_mgr   = program.getReferenceManager()

# ---------------------------------------------------------------------------
#  Helper: load sinks produced by the earlier stage
# ---------------------------------------------------------------------------

def load_sink_spec(path: str):
    data = json.loads(Path(path).read_text())
    table = {}
    for entry in data:
        result = entry["sink_result"]
        if result.get("is_true"):
            table[entry["function"]] = [int(i) for i in result["params"]]
    return table

# ---------------------------------------------------------------------------
#  Vulnerable‑Destination discovery (Algorithm 1 6‑11)
# ---------------------------------------------------------------------------

def _normalize(name: str):
    """Strip common suffixes/prefixes so 'printf', 'printf@plt', '__printf_chk'
    all normalise to 'printf'."""
    if name.startswith("__imp_"):
        name = name[6:]
    if name.endswith("@plt"):
        name = name[:-4]
    if "@" in name:
        name = name.split("@", 1)[0]
    if name.endswith("_chk"):
        name = name[:-4]
    return name

# ---------------------------------------------------------------------------
#  Vulnerable‑Destination discovery (Algorithm 1 6‑11)
# ---------------------------------------------------------------------------

def collect_vds(sink_spec):
    """Return a list of VDs; tolerates PLT stubs & GLIBC versioned symbols."""
    vds     = []
    dci     = DecompInterface(); dci.openProgram(program); dci.setOptions(DecompileOptions())

    # 1) Map normalised sink‑name  →  [Function]
    norm2funcs = {}
    for fn in program.getFunctionManager().getFunctions(True):
        n = _normalize(fn.getName())
        if n in sink_spec and (fn.isExternal() or n.endswith("printf") or fn.getName().endswith("@plt")):
            norm2funcs.setdefault(n, []).append(fn)

    # 2) Iterate over each sink variant found in the binary
    for sink, param_list in sink_spec.items():
        for sink_fn in norm2funcs.get(sink, []):
            for ref in ref_mgr.getReferencesTo(sink_fn.getEntryPoint()):
                if not ref.getReferenceType().isCall():
                    continue
                call_site = ref.getFromAddress()
                caller_fn = func_mgr.getFunctionContaining(call_site)
                if caller_fn is None:
                    continue

                # Decompile caller once per function for speed
                result = dci.decompileFunction(caller_fn, 30, monitor)
                hf      = result.getHighFunction() if result.decompileCompleted() else None

                for param_idx in param_list:
                    arg_expr = f"arg[{param_idx}]"
                    if hf:
                        for op in hf.getPcodeOps():
                            if op.getSeqnum().getTarget() == call_site:
                                if param_idx + 1 < op.getNumInputs():
                                    arg_expr = op.getInput(param_idx + 1).toString()
                                break
                    vds.append({
                        "loc": str(call_site),
                        "sink": sink_fn.getName(),
                        "arg": arg_expr,
                        "caller": caller_fn.getName()
                    })
    return vds

# ---------------------------------------------------------------------------
#  Call‑Chain extraction (Algorithm 1 12‑15)
# ---------------------------------------------------------------------------

def build_call_chains(vds, max_depth=50):
    chains = []
    for vd in vds:
        start_addr = fapi.toAddr(vd["loc"])
        start_fn   = func_mgr.getFunctionContaining(start_addr)
        if start_fn is None:
            continue
        _dfs_callers(start_fn, [start_fn], chains, set(), 0, max_depth)
    return chains

def _dfs_callers(fn, path, out_chains, seen, depth, max_depth):
    if depth >= max_depth:
        out_chains.append([f.getName() for f in reversed(path)])
        return
    refs = ref_mgr.getReferencesTo(fn.getEntryPoint())
    callers = [func_mgr.getFunctionContaining(r.getFromAddress()) for r in refs if r.getReferenceType().isCall()]
    callers = [c for c in callers if c and c not in path]
    if not callers:
        out_chains.append([f.getName() for f in reversed(path)])
        return
    for cfn in callers:
        key = (cfn.getEntryPoint(), fn.getEntryPoint())
        if key in seen:
            continue
        seen.add(key)
        _dfs_callers(cfn, [cfn] + path, out_chains, seen, depth + 1, max_depth)

# ---------------------------------------------------------------------------
#  Script entry‑point – `sys.argv` after "postScript" are passed here
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    sink_json = "./results/sink_classification_CWE190_Integer_Overflow__char_fscanf_preinc_05.json"
    sink_spec = load_sink_spec(sink_json)
    print(f"[*] Loaded {len(sink_spec)} sink specifications from {sink_json}")
    print(f"[*] Sinks: {', '.join(sink_spec.keys())}")

    vds = collect_vds(sink_spec)
    print(f"[*] Collected {len(vds)} VDs")

    chains = build_call_chains(vds)
    print(f"[*] Extracted {len(chains)} call‑chains")

    Path("_latte_vds.json").write_text(json.dumps(vds, indent=2))
    Path("_latte_cc.json").write_text(json.dumps(chains, indent=2))
    print("[✓] Results written to _latte_vds.json / _latte_cc.json")
