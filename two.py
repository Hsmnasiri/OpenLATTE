#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ---------------------------------------------------------------------------
# find_dangerous_flows.py  (Ghidrathon 4  –  Ghidra 11.3.2)
#
# Usage inside analyzeHeadless:
#   -postScript find_dangerous_flows.py <sink_json> <source_json> <out_dir>
#
# where:
#   sink_json   : produced by your batch_classify_sinks.py
#   source_json : produced by your batch_classify_sources.py  (same schema)
#   out_dir     : directory for vds_*.json  dfs_*.json
#
# Output:
#   • vds_<bin>.json  – all Vulnerable Destinations
#   • dfs_<bin>.json  – unique Dangerous Flows (chains + matched sources)
#
# ---------------------------------------------------------------------------
# @category LATTE

import json, os, sys, hashlib, collections, traceback
from pathlib import Path
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompInterface
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.pcode import PcodeOp, HighParam, HighVariable
from ghidra.app.decompiler import DecompInterface
# ---------------------------------------------------------------------------
# 0.  argument parsing & helpers
# ---------------------------------------------------------------------------
args = getScriptArgs()
if len(sys.argv) < 4:
    raise SystemExit("Usage: find_dangerous_flows.py <sink_json> <source_json> <out_dir>")

SINK_JSON   = Path(sys.argv[1]).expanduser()
SOURCE_JSON = Path(sys.argv[2]).expanduser()
OUT_DIR     = Path(sys.argv[3]).expanduser()
OUT_DIR.mkdir(parents=True, exist_ok=True)

BIN_NAME = SINK_JSON.name.replace("sink_classification_", "").replace(".json", "")
VD_PATH  = OUT_DIR / f"vds_{BIN_NAME}.json"
DF_PATH  = OUT_DIR / f"dfs_{BIN_NAME}.json"

monitor   = ConsoleTaskMonitor()
PROGRAM   = currentProgram() if callable(currentProgram) else currentProgram
flapi     = FlatProgramAPI(PROGRAM)
dci       = DecompInterface(); dci.openProgram(PROGRAM)

# -----------------------------------------------
def hi_func(addr_hex: str):
    fn = flapi.getFunctionAt(toAddr(int(addr_hex, 16)))
    if not fn:
        return None
    res = dci.decompileFunction(fn, 60, monitor)
    return res.getHighFunction() if res and res.decompileCompleted() else None

def sinks_map():
    mp = collections.defaultdict(set)                 # {func → {idx,…}}
    for e in json.load(open(SINK_JSON)):
        mp[e["function"]].update(e["sink_result"]["params"])
    return mp

def sources_set():
    return {e["function"] for e in json.load(open(SOURCE_JSON))}

SINKS   = sinks_map()
SOURCES = sources_set()

MAX_CALL_DEPTH = 4   # قابل تغییر

# ---------------------------------------------------------------------------
# 1.  Phase-1: extract VDs
# ---------------------------------------------------------------------------
print("[+] Phase 1: Finding Vulnerable Destinations (VDs)…")
vds = []
for fn in PROGRAM.functionManager.getFunctions(True):
    hf = hi_func(str(fn.getEntryPoint()))
    if not hf: continue
    piter = hf.getPcodeOps()
    while piter.hasNext():
        op = piter.next()
        if op.getOpcode() != PcodeOp.CALL:
            continue
        callee_addr = op.getInput(0).getAddress()
        sym = PROGRAM.symbolTable.getPrimarySymbol(callee_addr)
        if not sym:
            continue
        name = sym.getName()
        if name not in SINKS:
            continue
        for idx1 in SINKS[name]:                       # idx1 = 1-based
            if op.getNumInputs() <= idx1:              # idx1→input idx1  (0=dest)
                continue
            arg_vn = op.getInput(idx1)
            arg_name = arg_vn.getHigh().getName() if arg_vn.getHigh() else str(arg_vn)
            vds.append({
                "loc"      : str(op.getSeqnum().getTarget()),
                "sink"     : name,
                "param_idx": idx1,
                "arg"      : arg_name,
                "func"     : fn.getName(),
                "func_addr": str(fn.getEntryPoint())
            })
print(f"[+]   Found {len(vds)} potential VDs.")
json.dump(vds, open(VD_PATH, "w"), indent=2)

# ---------------------------------------------------------------------------
# 2.  Phase-1: Generate Flow-Traces (backward slice)
# ---------------------------------------------------------------------------
def slice_to_params(vn):
    """
+    Return a set{slot_id} of formal parameters that, through data flow,
+    reach the given Varnode.  Implements a manual backward slice so we
+    don't depend on DecompilerUtils (absent in 11.3.2).
+    """
    seen, work, slots = set(), [vn], set()
    while work:
        cur = work.pop()
        if cur in seen:
            continue
        seen.add(cur)

        h = cur.getHigh()
        if isinstance(h, HighParam):               # HighParam is a formal parameter
            slots.add(h.getSymbol().getSlot())
            continue

        def_op = cur.getDef()
        if not def_op:
            continue

        # همهٔ ورودی‌های تعریف فعلی را دنبال کن
        for inp in def_op.getInputs():
            if inp.isConstant():
                continue
            work.append(inp)

        if def_op.getOpcode() in (PcodeOp.LOAD, PcodeOp.INDIRECT):
            for inp in def_op.getInputs():
                if inp != cur:
                    work.append(inp)
    return slots

def list_externals(names):
    out = []
    for n in names:
        g = flapi.getGlobalFunctions(n)
        if g and g[0].getSymbol().isExternal():
            out.append(n)
    return out

def trace_from_vd(vd):
    """return dict with keys flow_trace (list of frames) & externals_in_chain"""
    vd_func = flapi.getFunctionAt(toAddr(int(vd["func_addr"], 16)))
    hf_vd   = hi_func(vd["func_addr"])
    op_it   = hf_vd.getPcodeOps(toAddr(int(vd["loc"],16)))
    if not op_it.hasNext():
        return None
    call_op = op_it.next()
    arg_vn  = call_op.getInput(vd["param_idx"])
    work_slots = slice_to_params(arg_vn)
    chain, frames = [], []

    cur_fn = vd_func; depth = 0
    while cur_fn and depth <= MAX_CALL_DEPTH:
        chain.append(cur_fn.getName())
        # --- دیباگ: لیست اکسترنال‌های زنجیره فعلی
        depth += 1
        if not work_slots:
            break
        # backtrack به نخستین کالر که دیتافلو دارد
        parents = [c.getCallingFunction() for c in cur_fn.getCallingFunctions(monitor)]
        if not parents:
            break
        parent = parents[0]
        hf_par = hi_func(str(parent.getEntryPoint()))
        if not hf_par:
            break
        # call-site در پارنت
        for cs in parent.getCallSites(cur_fn):
            cop_it = hf_par.getPcodeOps(cs, cs)
            if not cop_it.hasNext():
                continue
            cop    = cop_it.next()
            for slot in work_slots:
                if cop.getNumInputs() <= slot+1:
                    continue
                argvn = cop.getInput(slot+1)
                new_slots = slice_to_params(argvn)
                frame = {
                    "caller_func": parent.getName(),
                    "callee_func": cur_fn.getName(),
                    "slot": slot,
                    "at": str(cop.getSeqnum().getTarget())
                }
                frames.append(frame)
                work_slots = new_slots
                cur_fn = parent
                break
            else:
                continue
            break
        else:
            break
    ext_in_chain = list_externals(chain)
    return {"flow_trace": frames, "chain": chain, "externals": ext_in_chain}

print("\n[+] Phase 1: Generating Flow Traces…")
flow_traces = []
for vd in vds:
    tr = trace_from_vd(vd)
    if not tr:
        continue
    ft_len = len(tr["flow_trace"])
    entry  = tr["chain"][-1] if tr["chain"] else "?"
    print(f"  Trace len={ft_len:<2}  entry={entry:<20} externals={tr['externals'] or '— none —'}")
    tr["vd"] = vd
    flow_traces.append(tr)

# de-duplicate identical chains + vd loc
uniq = {(t["vd"]["loc"], tuple(t["chain"])): t for t in flow_traces}.values()
print(f"[+]   Found {len(uniq)} unique flow trace(s).\n")
flow_traces = list(uniq)

# ---------------------------------------------------------------------------
# 3.  Phase-2: Source matching & DF generation
# ---------------------------------------------------------------------------
print("[+] Phase 2: Generating Dangerous Flows (DFs) with Source matching…")
dangerous_flows = []
for tr in flow_traces:
    if set(tr["externals"]) & SOURCES:
        vd = tr["vd"]
        df_id = hashlib.md5((vd["loc"] + "," + ",".join(tr["chain"])).encode()).hexdigest()[:12]
        dangerous_flows.append({
            "id"    : df_id,
            "sink"  : vd["sink"],
            "source": list(set(tr["externals"]) & SOURCES),
            "vdLoc" : vd["loc"],
            "arg"   : vd["arg"],
            "chain" : list(reversed(tr["chain"]))  # callers→callee
        })

print(f"[+]   Found {len(dangerous_flows)} source-matched DF(s).\n")

# ---------------------------------------------------------------------------
# 4.  Phase-3: (Optional) filter entrypoints
# ---------------------------------------------------------------------------
def keep(_name):     # اینجا می‌توانید شرط سفارشی بگذارید
    return True

filtered = [df for df in dangerous_flows if keep(df["chain"][0])]

print("[+] Analysis complete. Final DF(s):")
for df in filtered:
    print(f"    DF {df['id']}  src={df['source']}  → sink={df['sink']}")

json.dump(list(filtered), open(DF_PATH, "w"),  indent=2)
print(f"\n[SAVED] {len(filtered)} DF(s) → {DF_PATH}")
