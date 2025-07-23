# export_flow_code.py
# @author Gemini
# @category Gemini.Analysis
# @description Extracts the decompiled C code for each function in a dangerous flow trace.

import os
import json
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def export_code_for_flows():
    """
    Reads a dangerous_flows.json file, finds each function in the traces,
    decompiles it, and saves the augmented data to a new JSON file.
    """
    program = currentProgram()
    decompiler = DecompInterface()
    decompiler.openProgram(program)
    symbol_table = program.getSymbolTable()

    # Assumes the script is run from the project root
    flows_path = "results/dangerous_flows_{}.json".format(program.getName())
    output_path = "results/flows_with_code_{}.json".format(program.getName())
    
    try:
        with open(flows_path, 'r') as f:
            dangerous_flows = json.load(f)
    except Exception as e:
        print("[FATAL] Could not load '{}': {}".format(flows_path, e))
        return

    print("[+] Exporting decompiled code for {} flows...".format(len(dangerous_flows)))

    for flow in dangerous_flows:
        for step in flow['flow_trace']:
            func_name = step['caller_func']
            
            # Find the function and decompile it
            func = None
            symbol_iter = symbol_table.getSymbols(func_name)
            if symbol_iter.hasNext():
                func = getFunctionAt(symbol_iter.next().getAddress())
            
            if func:
                try:
                    decomp_res = decompiler.decompileFunction(func, 60, ConsoleTaskMonitor())
                    if decomp_res.decompileCompleted():
                        # Add the decompiled code to the trace step
                        step['code'] = decomp_res.getDecompiledFunction().getC()
                except Exception as e:
                    print("  [WARN] Could not decompile function {}: {}".format(func_name, e))
                    step['code'] = "// Decompilation failed for {}".format(func_name)
            else:
                 step['code'] = "// Could not find function {}".format(func_name)

    with open(output_path, 'w') as f:
        json.dump(dangerous_flows, f, indent=2)

    print("[DONE] Saved flows with decompiled code to {}".format(output_path))


if __name__ == "__main__":
    export_code_for_flows()