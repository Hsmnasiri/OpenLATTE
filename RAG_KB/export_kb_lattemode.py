# export_kb_lattemode.py
# Build call chains from GOOD/BAD starts to external on a STRIPPED program
# - Starts are seeded from symbol_map_<base>.json (written by unstripped pass)
# - No use of getThunkedFunction(); boundary checks are robust for stripped ELFs
# - External boundary if: func.isExternal() OR name endswith "@plt" OR block is .plt OR empty body
# - Writes outputs to ${OUT_BASE}/build if OUT_BASE is set

import json, os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import SourceType

OUT_BASE = os.getenv("OUT_BASE", os.getcwd())
MAX_DEPTH = int(os.getenv("MAX_DEPTH", "6"))
START_KEYS = ["_bad", "goodB2G", "goodG2B", "::bad", "::good"]

def log(msg): print("[KB-EXPORT]", msg)

def load_symbol_map(base):
    path = os.path.join(OUT_BASE, "build", f"symbol_map_{base}.json")
    if not os.path.exists(path):
        log(f"symbol_map not found: {path}")
        return {}
    with open(path, "r") as f:
        return json.load(f)

def is_start_name(name):
    return any(k in name or name.endswith(k) for k in START_KEYS)

def collect_starts_from_symbol_map(symmap):
    return [(n, addr) for n, addr in symmap.items() if is_start_name(n)]

def decompile(decomp, func):
    r = decomp.decompileFunction(func, 60, ConsoleTaskMonitor())
    if r and r.decompileCompleted():
        return r.getDecompiledFunction().getC()
    return ""

def get_block_name(addr):
    mem = currentProgram().getMemory()
    blk = mem.getBlock(addr)
    return blk.getName() if blk else None

def is_external_boundary(func):
    if func is None:
        return True
    if func.isExternal():
        return True
    # .plt or @plt
    name = func.getName()
    if name.endswith("@plt"):
        return True
    blk_name = get_block_name(func.getEntryPoint())
    if blk_name and ".plt" in blk_name:
        return True
    # function without body → treat as external boundary
    body = func.getBody()
    if body is None or body.isEmpty():
        return True
    return False

def get_callees_via_listing(func):
    listing = currentProgram().getListing()
    instrs = listing.getInstructions(func.getBody(), True)
    for ins in instrs:
        ft = ins.getFlowType()
        if ft and ft.isCall():
            to_addr = None
            refs = ins.getReferencesFrom()
            if refs:
                to_addr = refs[0].getToAddress()
            if to_addr is None:
                flows = ins.getFlows()
                if flows:
                    to_addr = flows[0]
            callee = getFunctionAt(to_addr) if to_addr else None
            yield (callee, str(ins.getAddress()), str(to_addr) if to_addr else "UNKNOWN")

def ensure_function_at(addr_str):
    addr = currentProgram().getAddressFactory().getAddress(addr_str)
    if addr is None:
        return None
    f = getFunctionAt(addr)
    if f is None:
        f = createFunction(addr, "FUN_"+addr_str.replace(":", "_"), SourceType.ANALYSIS)
    return f

def variant_of(name):
    if "_bad" in name or name.endswith("::bad"): return "bad"
    if "goodB2G" in name or "goodG2B" in name or name.endswith("::good"): return "good"
    return "unknown"

def run():
    program = currentProgram()
    base = program.getName().replace(".out","").replace(".unstripped","")
    log(f"Program (stripped): {base}")

    symmap = load_symbol_map(base)
    starts_meta = collect_starts_from_symbol_map(symmap)
    log(f"Starts from symbol_map: {len(starts_meta)} found")

    decomp = DecompInterface(); decomp.openProgram(program)

    paths, total_calls_seen = [], 0

    def strip_func(n):
        d = dict(n); d.pop("func", None); return d

    def dfs(chain, depth):
        nonlocal total_calls_seen
        cur = chain[-1]; f = cur["func"]
        if f is None or depth > MAX_DEPTH:
            return

        call_count = 0
        for (callee, from_addr, to_addr) in get_callees_via_listing(f):
            call_count += 1
            total_calls_seen += 1

            if callee is None:
                node = {"name":"<external?>","address":to_addr or "UNKNOWN","external":True,"code":""}
                edge = {"from": f.getName(), "to": node["name"], "site": from_addr}
                new_chain = chain + [dict(node, edge=edge, func=None)]
                paths.append({"variant": variant_of(chain[0]["name"]), "call_chain": [strip_func(n) for n in new_chain]})
                continue

            # No getThunkedFunction() here; rely on boundary checks
            rfunc = callee
            is_ext = is_external_boundary(rfunc)
            cname, caddr = rfunc.getName(), str(rfunc.getEntryPoint())
            code = "" if is_ext else decompile(decomp, rfunc)

            node = {"name": cname, "address": caddr, "external": bool(is_ext), "code": code}
            edge = {"from": f.getName(), "to": cname, "site": from_addr}
            new_chain = chain + [dict(node, edge=edge, func=(None if is_ext else rfunc))]

            if is_ext:
                paths.append({"variant": variant_of(chain[0]["name"]), "call_chain": [strip_func(n) for n in new_chain]})
            else:
                dfs(new_chain, depth+1)

        log(f"  {call_count} call(s) in {f.getName()}")

    for (start_name, start_addr) in starts_meta:
        f = ensure_function_at(start_addr)
        if f is None:
            log(f"Cannot ensure function at {start_addr}")
            continue
        root_code = decompile(decomp, f)
        root = {"name": start_name, "address": start_addr, "external": False, "code": root_code, "func": f}
        log(f"Traverse from start: {start_name} @ {start_addr}")
        dfs([root], 0)

    out_dir = os.path.join(OUT_BASE, "build")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"kb_callchains_{base}.json")
    with open(out_path,"w") as f:
        json.dump({"program": base, "max_depth": MAX_DEPTH, "paths": paths}, f, indent=2)
    log(f"Total calls seen: {total_calls_seen}")
    log(f"Total paths saved: {len(paths)}")
    print("[DONE] wrote", out_path)

if __name__ == "__main__":
    run()
