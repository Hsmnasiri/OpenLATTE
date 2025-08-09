# map_symbols_include_fun.py
# Save all functions including FUN_* wrappers. Writes to OUT_BASE/build.

import json, os

OUT_BASE = os.getenv("OUT_BASE", os.getcwd())

def main():
    program = currentProgram()
    fm = program.getFunctionManager()
    symbol_map = {}
    it = fm.getFunctions(True)
    for f in it:
        symbol_map[f.getName()] = str(f.getEntryPoint())

    base = program.getName().replace(".unstripped", "").replace(".out", "")
    out_dir = os.path.join(OUT_BASE, "build")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, f"symbol_map_{base}.json")

    with open(out, "w") as fp:
        json.dump(symbol_map, fp, indent=2)
    print("[DONE] wrote", out)

if __name__ == "__main__":
    main()
