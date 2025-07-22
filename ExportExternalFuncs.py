# ExportExternalFuncs.py
# @category Ghidrathon/Utils

import os
import json
def main():
    # 1) grab the Program object
    program = currentProgram()
    if program is None:
        print("No program loaded; exiting.")
        return

    binary_name = program.getName()
    out_path = os.path.expanduser(f"/mnt/z/Papers/MyRAG/LATTE_ReImplementing/ghidra-workspace/external_funcs_{binary_name}.txt")

    funcs = program.getFunctionManager().getExternalFunctions()
    count = 0
    out = []
    
    for f in funcs:
        proto = f.getPrototypeString(False, False)
        out.append({"name": f.getName(), "addr": hex(f.getEntryPoint().getOffset()),
                    "proto": proto})

    with open(out_path, "w") as fp:
        json.dump(out, fp, indent=2)


    print(f"Wrote {count} external function signatures to {out_path}")

if __name__ == "__main__":
    main()
