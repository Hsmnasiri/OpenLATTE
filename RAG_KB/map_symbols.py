# Save function names and addresses for the current program

import json

def create_symbol_map():
    """Write a JSON map from function name to entry address."""
    print("[+] Generating symbol map...")
    func_manager = currentProgram().getFunctionManager()
    symbol_map = {}

    for func in func_manager.getFunctions(True):
        if not func.getName().startswith("FUN_"):
            symbol_map[func.getName()] = str(func.getEntryPoint())
    
    output_filename = "build/symbol_map_{}.json".format(currentProgram().getName().replace(".unstripped", ""))
    with open(output_filename, 'w') as f:
        json.dump(symbol_map, f, indent=2)
    
    print("[+] Saved symbol map for {} functions to {}".format(len(symbol_map), output_filename))

if __name__ == "__main__":
    create_symbol_map()
