# ExportExternalFuncs.py
# @category Ghidrathon/Utils

import os

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
    with open(out_path, "w") as fw:
        for func in funcs:
            try:
                # full prototype: return type, name, params
                sig = func.getSignature(True)
            except Exception:
                sig = func.getName() + "()"
            fw.write(f"{func.getName()} : {sig}\n")
            count += 1

    print(f"Wrote {count} external function signatures to {out_path}")

if __name__ == "__main__":
    main()
