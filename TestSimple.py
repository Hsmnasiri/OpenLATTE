# ListExternalFuncs.py
# @category Ghidrathon/Utils

def main():
    # 1) grab the Program object
    program = currentProgram()
    if program is None:
        print("No current program loaded!")
        return

    # 2) get the FunctionManager
    func_mgr = program.getFunctionManager()

    # 3) retrieve all external functions
    external_funcs = func_mgr.getExternalFunctions()

    print("=== External Functions ===")
    count = 0
    for func in external_funcs:
        name = func.getName()
        try:
            sig = func.getSignature(True)
        except:
            sig = "<unknown signature>"
        print(f"{name} -> {sig}")
        count += 1

    print(f"\nTotal external functions: {count}")

if __name__ == "__main__":
    main()
