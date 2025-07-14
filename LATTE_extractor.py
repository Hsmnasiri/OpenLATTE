import json
from ghidra.program.model.pcode import PcodeOp
from ghidra.util.task import ConsoleTaskMonitor

# Ghidra specific imports
currentProgram = getCurrentProgram()
decompInterface = ghidra.app.decompiler.DecompInterface()
decompInterface.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

def get_function_decompilation(func):
    """Decompile a single function and return its C code."""
    results = decompInterface.decompileFunction(func, 0, monitor)
    if results.decompileCompleted():
        return results.getDecompiledFunction().getC()
    return None

def get_call_graph():
    """Build a simple call graph: {caller_addr: [callee_addr, ...]}."""
    call_graph = {}
    func_manager = currentProgram.getFunctionManager()
    for func in func_manager.getFunctions(True): # True for 'forward' order
        caller_addr = func.getEntryPoint().getOffset()
        call_graph[caller_addr] = []
        # Get functions called by this function
        called_funcs = func.getCalledFunctions(monitor)
        for called_func in called_funcs:
            callee_addr = called_func.getEntryPoint().getOffset()
            call_graph[caller_addr].append(callee_addr)
    return call_graph

def extract_all_data():
    """Main extraction function."""
    output_data = {
        "functions": {},
        "call_graph": get_call_graph(),
        "external_functions": []
    }
    
    func_manager = currentProgram.getFunctionManager()
    for func in func_manager.getFunctions(True):
        func_addr = func.getEntryPoint().getOffset()
        decompiled_code = get_function_decompilation(func)
        
        output_data["functions"][func_addr] = {
            "name": func.getName(),
            "decompiled_code": decompiled_code
        }
        
        if func.isExternal():
            output_data["external_functions"].append(func.getName())

    # Save to a file
    output_path = "./ghidra_projects/ghidra_export.json" 
    with open(output_path, "w") as f:
        json.dump(output_data, f, indent=2)
        
    print("Exported program data to: " + output_path)

# Run the extraction
if __name__ == "__main__":
    extract_all_data()