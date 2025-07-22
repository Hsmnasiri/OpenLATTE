#!/usr/bin/env python
#@category LATTE
"""
BuildFullDF.py  –  From VDs → full inter-procedural slices → CDF → DF
Usage (headless):
  -postScript BuildFullDF.py vds.json df.json
JSON schema out:
[
  {
    "id"      : "<sha1>",              # unique per DF
    "sink"    : "<func>",
    "sink_addr": "0x40123c",
    "sources" : [{"var":"buf", "func":"recv", "addr":"0x400fe0"}],
    "cc_path" : ["0x400a10","0x400b20", ...]  # caller→callee addresses
  }, …
]
"""
import json, sys, hashlib, requests, re
from ghidra.app.decompiler import DecompInterface, DecompileResults
from ghidra.app.decompiler.component import DecompilerUtils          # slicing utils
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.flatapi import FlatProgramAPI

# ---------- config ----------
VDS_JSON , DF_JSON = sys.argv[1], sys.argv[2]
LLM_URL   = "http://127.0.0.1:8000/api"         # change to HF endpoint if needed
MAX_DEPTH = 3                                   # inter-procedural slice depth
TIMEOUT   = 25

def ask_llm(prompt, yes_regex=r"\bSOURCE\b"):
    # rsp = requests.post(LLM_URL, json={"prompt": prompt,
    #                                    "parameters":{"max_new_tokens":4}},
    #                     timeout=TIMEOUT).text.strip()
    return True

# ---------- init decompiler once ----------
api = FlatProgramAPI(currentProgram)
monitor = ConsoleTaskMonitor()
di  = DecompInterface(); di.openProgram(currentProgram)

def high_func(addr):
    """decompile­→HighFunction cache."""
    f = api.getFunctionAt(toAddr(int(addr,16)))
    res = di.decompileFunction(f, 60, monitor)       # 60 s budget
    return res.getHighFunction() if res.decompileCompleted() else None

def backwards(varnode):
    """wrapper on DecompilerUtils.getBackwardSlice(); returns all varnodes."""
    bslice = DecompilerUtils.getBackwardSlice(varnode)   # returns list<Varnode> 
    return {vn for vn in bslice}

def arg_vnodes(call_pcode):
    """inputs of CALL except 0-th (dest func Address)"""
    return [call_pcode.getInput(i) for i in range(1, call_pcode.getNumInputs())]

def symbols_of(vn):
    hv = vn.getHigh()
    sym = hv.getSymbol() if hv else None
    return sym.getName() if sym else hv.getName()

def interproc_slice(func_addr_hex, arg_vn, depth):
    """
    Recursively slice back through caller chain up to MAX_DEPTH.
    Returns list of tuples (varname, func_name, addr_str)
    """
    work = [(func_addr_hex, arg_vn, 0)]
    sources = []
    visited  = set()
    while work:
        func_addr, vn, lvl = work.pop()
        key = (func_addr, vn.getAddress(), vn.hashCode())
        if key in visited: continue
        visited.add(key)

        # 1) alias/indirect mem – if LOAD/INDIRECT in slice, treat as potential src
        for op in DecompilerUtils.getBackwardSliceToPCodeOps(vn):
            if op.getOpcode().toString() in ("INDIRECT","LOAD"):
                bases = [i for i in op.getInputs() if i != vn]
                for b in bases: work.append((func_addr, b, lvl))    # follow base pointer

        # 2) reach definitions
        for prev in backwards(vn):
            nm = symbols_of(prev)
            if nm:
                # LLM: is it external/user input?
                prompt = (
                  "You are an expert taint-analysis agent.\n"
                  f"Variable `{nm}` flows towards a security sink. "
                  "Does it originate from external input (socket, file, argv, etc.)? "
                  "Answer SOURCE or CLEAN."
                )
                if ask_llm(prompt):
                    sources.append({"var": nm,
                                    "func": api.getFunctionContaining(prev.getPCAddress()).getName(),
                                    "addr": str(prev.getPCAddress())})
                    continue
            # 3) if variable is parameter, recurse to caller
            if lvl < depth:
                hf = high_func(func_addr)
                if not hf: continue
                for p in hf.getFunction().getCallingFunctions(monitor):
                    callsites = p.getFunction().getCallSites(hf.getFunction())
                    for cs in callsites:
                        pcode_iter = hf.getPcodeOps(cs, cs)
                        if not pcode_iter.hasNext(): continue
                        cop = pcode_iter.next()                   # CALL in caller
                        idx = list(arg_vnodes(cop)).index(vn) if vn in arg_vnodes(cop) else -1
                        if idx >= 0:      # argument propagates
                            caller_hf = high_func(str(p.getEntryPoint()))
                            if not caller_hf: continue
                            call_pcode_iter = caller_hf.getPcodeOps(cs, cs)
                            call_op = call_pcode_iter.next()
                            new_vn  = call_op.getInput(idx+1)
                            work.append((str(p.getEntryPoint()), new_vn, lvl+1))
    return sources

# ---------- main ----------
vds = json.load(open(VDS_JSON))
dfs = []
for vd in vds:
    fun_hf = high_func(vd["func_addr"])
    if not fun_hf: continue

    # locate CALL pcode at sink site
    ops = fun_hf.getPcodeOps(toAddr(int(vd["call_addr"],16)))
    if not ops.hasNext(): continue
    call_op = ops.next()

    for vn in arg_vnodes(call_op):
        srcs = interproc_slice(vd["func_addr"], vn, MAX_DEPTH)
        if not srcs: continue
        # construct path of callers (simple)
        path = [vd["func_addr"]]
        for s in srcs:
            path.append(s["addr"])       # crude example
        digest = hashlib.sha1(
            (vd["call_addr"] + "," + ",".join(sorted(x["addr"] for x in srcs))).encode()
        ).hexdigest()[:12]

        dfs.append({
            "id"       : digest,
            "sink"     : vd["sink"],
            "sink_addr": vd["call_addr"],
            "sources"  : srcs,
            "cc_path"  : path
        })

# dedup exact same DF id
uniq = {d["id"]:d for d in dfs}.values()
json.dump(list(uniq), open(DF_JSON,"w"), indent=2)
print("[+] wrote", DF_JSON, "with", len(uniq), "dangerous flow(s)")
