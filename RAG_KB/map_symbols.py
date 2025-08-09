# map_symbols.py — emit both "symbols" and "starts" for exporter; Ghidrathon-safe
import os, sys, json, re

START_PAT = re.compile(r'(?:_bad$)|(?:^good(?:B2G1|B2G2|G2B1|G2B2)?$)|(?:^good$)')

def _get_program():
    cp = currentProgram  # provided by Ghidra/Ghidrathon
    return cp() if callable(cp) else cp

def _program_basename(prog):
    name = prog.getName()
    return os.path.splitext(os.path.basename(name))[0]

def _resolve_output_path(default_base):
    if len(sys.argv) > 1 and sys.argv[1]:
        out = sys.argv[1]
    else:
        out_base = os.environ.get("OUT_BASE", os.getcwd())
        out = os.path.join(out_base, "build", f"symbol_map_{default_base}.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    return out

def main():
    print("[+] Generating symbol map...")
    prog = _get_program()
    base = _program_basename(prog)
    out_path = _resolve_output_path(base)

    symtbl = prog.getSymbolTable()
    symbols = []
    starts = []

    it = symtbl.getSymbolIterator(True)
    for sym in it:
        if sym.isExternal():
            continue
        stype = sym.getSymbolType().toString()
        if stype != "Function":
            continue

        # Use unqualified name so regex matches "bad", "goodB2G1", ...
        name = sym.getName(False)  # <-- important
        addr = str(sym.getAddress())

        symbols.append({"name": name, "address": addr, "type": stype})

        # mark Juliet entry points
        if START_PAT.search(name):
            starts.append({"name": name, "address": addr})

    data = {
        "program": base,
        "image_base": str(prog.getImageBase()),
        "starts": starts,
        "symbols": symbols
    }

    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"[DONE] symbol map → {out_path}")
    print(f"[INFO] starts: {len(starts)}, functions: {len(symbols)}")

if __name__ == "__main__":
    main()
