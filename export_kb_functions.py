import json
import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def export_kb_functions_generalized():
    program = currentProgram()
    decompiler = DecompInterface()
    decompiler.openProgram(program)

    # Automatically determine file paths
    base_name = program.getName().replace(".out", "").replace(".unstripped", "")
    map_path = "build/symbol_map_{}.json".format(base_name)
    output_path = "build/decompiled_kb_{}.json".format(base_name)

    try:
        with open(map_path, 'r') as f:
            symbol_map = json.load(f)
    except Exception as e:
        print("[FATAL] Could not load symbol map at '{}': {}".format(map_path, e))
        return

    # --- NEW, MORE ROBUST FUNCTION DISCOVERY ---
    # Automatically find all relevant functions based on C and C++ Juliet naming conventions.
    functions_to_extract = []
    # C-style keywords
    c_keywords = ["_bad", "goodG2B", "goodB2G"]
    # C++-style keywords (must appear at the end of the name)
    cpp_keywords = ["::bad", "::good"]

    for func_name in symbol_map.keys():
        # Check for C-style names
        if any(keyword in func_name for keyword in c_keywords):
            functions_to_extract.append(func_name)
        # Check for C++-style names
        elif any(func_name.endswith(keyword) for keyword in cpp_keywords):
            functions_to_extract.append(func_name)

    print("[+] Automatically discovered {} relevant functions to extract.".format(len(functions_to_extract)))
    
    extracted_data = {}
    print("[+] Extracting decompiled code...")

    for func_name in functions_to_extract:
        address_str = symbol_map[func_name]
        address = toAddr(address_str)
        func = getFunctionAt(address)

        if func:
            try:
                decomp_res = decompiler.decompileFunction(func, 60, ConsoleTaskMonitor())
                if decomp_res.decompileCompleted():
                    code = decomp_res.getDecompiledFunction().getC()
                    extracted_data[func_name] = {
                        "stripped_name": func.getName(),
                        "address": address_str,
                        "decompiled_code": code
                    }
                    print("  [OK] Extracted {} (as {})".format(func_name, func.getName()))
            except Exception as e:
                print("  [ERR] Could not decompile {}: {}".format(func_name, e))
    
    with open(output_path, 'w') as f:
        json.dump(extracted_data, f, indent=2)
    
    print("[DONE] Saved {} decompiled functions to {}".format(len(extracted_data), output_path))

if __name__ == "__main__":
    export_kb_functions_generalized()