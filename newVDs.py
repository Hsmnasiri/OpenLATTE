#!/usr/bin/env python
#@category LATTE
"""
Extract Vulnerable Destinations (VDs): each call-site where a detected sink
is *invoked*.  Usage:
  -postScript ExtractVDs.py sinks.json vds.json
"""
import json, sys
from ghidra.program.model.symbol import RefType

SINKS_JSON, VDS_JSON = sys.argv[1], sys.argv[2]
sink_names = {s["name"] for s in json.load(open(SINKS_JSON))}
listing = currentProgram.getListing()

vds = []  # [{sink, call_addr, func_addr}]
for func in currentProgram.functionManager.getFunctions(True):
    ins_iter = listing.getInstructions(func.getBody(), True)
    while ins_iter.hasNext():
        ins = ins_iter.next()
        if not ins.getFlowType().isCall():  # skip non-call
            continue
        callee = ins.getFlows()[0] if ins.getFlows() else None
        if not callee:  # unresolved
            continue
        sym = currentProgram.symbolTable.getPrimarySymbol(callee)
        if sym and sym.getName() in sink_names:
            vds.append({
                "sink": sym.getName(),
                "call_addr": str(ins.getAddress()),
                "func_addr": str(func.getEntryPoint())
            })

json.dump(vds, open(VDS_JSON, "w"), indent=2)
print("[+] wrote", VDS_JSON, "with", len(vds), "VD(s)")
