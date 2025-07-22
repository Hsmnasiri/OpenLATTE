# @category LATTE
"""
BuildVD_DF.py  –  from sink list → VDs → DFs (Ghidra 11.3.2, Ghidrathon)

CLI inside analyzeHeadless:
  -postScript BuildVD_DF.py <sink_json>

Writes:
  • <sink_json_base>.vds.json
  • <sink_json_base>.dfs.json
"""
import json, os, sys, hashlib, collections
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompInterface
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.pcode import PcodeOp

SINK_JSON = "/mnt/z/Papers/MyRAG/LATTE_ReImplementing/results/sink_classification_CWE190_Integer_Overflow__char_fscanf_preinc_05.json"
base_dir  = os.path.dirname(SINK_JSON)
base_name = os.path.basename(SINK_JSON).replace("sink_classification_","").replace(".json","")
VD_JSON   = os.path.join(base_dir, f"vds_{base_name}.json")
DF_JSON   = os.path.join(base_dir, f"dfs_{base_name}.json")

# -------------------------------------------------- helpers
PROGRAM = currentProgram() if callable(currentProgram) else currentProgram

dci = DecompInterface()
dci.openProgram(PROGRAM)
monitor = ConsoleTaskMonitor()
flat = FlatProgramAPI(PROGRAM)
def hi_func(addr):
    fn = flat.getFunctionAt(toAddr(int(addr,16)))
    res = dci.decompileFunction(fn, 60, monitor)
    return res.getHighFunction() if res and res.decompileCompleted() else None

def sinks_dict():
    out = collections.defaultdict(set)         # {func_name → {param_idx,…}}
    for e in json.load(open(SINK_JSON)):
        for p in e["sink_result"]["params"]:
            out[e["function"]].add(p)
    return out

def arg_vn(call_op, idx1):
    """return Varnode of (idx1-based) argument if exists"""
    if call_op.getNumInputs() > idx1+1:
        return call_op.getInput(idx1+1)
    return None

def slice_back(vn, seen):
    """simple backward slice with LOAD/INDIRECT alias following"""
    work = [vn]
    while work:
        cur = work.pop()
        if cur in seen: continue
        seen.add(cur)
        defop = cur.getDef()
        if defop:
            for inv in defop.getInputs():
                if inv.isConstant(): continue
                work.append(inv)
        # alias: اگر LOAD/INDIRECT بود، ورودی‌های دیگر را دنبال کن
        if defop and defop.getOpcode() in (PcodeOp.LOAD, PcodeOp.INDIRECT):
            for inv in defop.getInputs():
                if inv != cur:
                    work.append(inv)

def callers_of(func):
    return [c.getCallingFunction()
            for c in func.getCallingFunctions(monitor)]

# -------------------------------------------------- 1) build VDs
sink_mp  = sinks_dict()
vds      = []          # [{loc,sink,param_idx,arg,func,func_addr}]
for fn in PROGRAM.getFunctionManager().getFunctions(True):
    hf = hi_func(str(fn.getEntryPoint()))
    if not hf: continue
    it = hf.getPcodeOps()
    while it.hasNext():
        op = it.next()
        if op.getOpcode() != PcodeOp.CALL: continue
        calleeAddr = op.getInput(0).getAddress()
        sym = PROGRAM.getSymbolTable().getPrimarySymbol(calleeAddr)
        if not sym: continue
        name = sym.getName()
        if name not in sink_mp: continue
        for idx in sink_mp[name]:
            vn = arg_vn(op, idx-1)
            if not vn: continue
            arg_name = vn.getHigh().getName() if vn.getHigh() else str(vn)
            vds.append({
                "loc"      : str(op.getSeqnum().getTarget()),
                "sink"     : name,
                "param_idx": idx,
                "arg"      : arg_name,
                "func"     : fn.getName(),
                "func_addr": str(fn.getEntryPoint())
            })
json.dump(vds, open(VD_JSON,"w"), indent=2)
print(f"[+] {len(vds)} VDs  →  {VD_JSON}")

# -------------------------------------------------- 2) build DFs
dfs = []
for vd in vds:
    hf_sink = hi_func(vd["func_addr"]);         idx0 = vd["param_idx"]-1
    op_it = hf_sink.getPcodeOps(toAddr(int(vd["loc"],16)))
    if not op_it.hasNext(): continue
    call_op = op_it.next()
    vn_arg  = arg_vn(call_op, idx0)
    if not vn_arg: continue

    # backward slice & collect param slots feeding from callers
    seen = set(); slice_back(vn_arg, seen)
    slots = {vn.getHigh().getSymbol().getSlot()
             for vn in seen
             if vn.getHigh() and vn.getHigh().isHighParam()}

    # walk up caller chain while dependency برقرار است
    chain = [vd["func"]]; cur_fn = flat.getFunctionAt(toAddr(int(vd["func_addr"],16)))
    while slots and cur_fn:
        clist = callers_of(cur_fn)
        if not clist: break
        parent = clist[0]                 # اولین کالر کافیست (مثل LATTE که CC1…)
        chain.append(parent.getName())
        hf_p  = hi_func(str(parent.getEntryPoint()))
        if not hf_p: break
        new_slots = set()
        for cs in parent.getCallSites(cur_fn):
            opit = hf_p.getPcodeOps(cs, cs)
            if not opit.hasNext(): continue
            cop = opit.next()
            for s in slots:
                argvn = arg_vn(cop, s)
                if not argvn: continue
                slice_back(argvn, seen=set())
                for vn in seen:
                    hi = vn.getHigh()
                    if hi and hi.isHighParam():
                        new_slots.add(hi.getSymbol().getSlot())
        slots = new_slots
        cur_fn = parent
    chain = list(reversed(chain))

    df_id = hashlib.md5((','.join(chain)+vd["loc"]).encode()).hexdigest()[:12]
    dfs.append({
        "id"    : df_id,
        "vdLoc" : vd["loc"],
        "sink"  : vd["sink"],
        "arg"   : vd["arg"],
        "chain" : chain
    })

# dedup
uniq = {d["id"]:d for d in dfs}.values()
json.dump(list(uniq), open(DF_JSON,"w"), indent=2)
print(f"[+] {len(uniq)} DF(s)  →  {DF_JSON}")
