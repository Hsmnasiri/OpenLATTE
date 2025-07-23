# find_dangerous_flows.py
# @author Gemini & mnasi101
# @category Gemini.Analysis
# @description Implements the core dangerous flow discovery logic from the LATTE paper.

import os
import json
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.pcode import PcodeOp
from ghidra.app.decompiler.component import DecompilerUtils
from ghidra.program.model.pcode import PcodeOp, HighParam, HighVariable
# --- Constants --- #
CALL_DEPTH_LIMIT = 50 
def simple_backward_slice(varnode):
    """
    Returns list[PcodeOp] that define/propagate varnode
    – بدون نیاز به DecompilerUtils (سازگار با 11.3.2).
    """
    seen, work, ops = set(), [varnode], []
    while work:
        vn = work.pop()
        if vn in seen:
            continue
        seen.add(vn)

        def_op = vn.getDef()
        if def_op:
            ops.append(def_op)
            # تمام ورودی‌های غیر ثابت را دنبال کن
            for inp in def_op.getInputs():
                if not inp.isConstant():
                    work.append(inp)
            # alias: اگر LOAD یا INDIRECT بود، آدرس را هم دنبال کن
            if def_op.getOpcode() in (PcodeOp.LOAD, PcodeOp.INDIRECT):
                for inp in def_op.getInputs():
                    if inp != vn:
                        work.append(inp)
    return ops
def find_vulnerable_destinations(sinks, func_manager, decompiler):
    """
    Finds all call sites of sink functions using direct P-Code iteration.
    """
    print("[+] Phase 1: Finding Vulnerable Destinations (VDs)...")
    vds = []
    sink_names_set = {s["function"] for s in sinks}
    sinks_map = {s["function"]: s for s in sinks}

    for caller_func in func_manager.getFunctions(True):
        if caller_func.isThunk() or caller_func.isExternal():
            continue
        try:
            decomp_res = decompiler.decompileFunction(caller_func, 60, ConsoleTaskMonitor())
            if not decomp_res.decompileCompleted(): continue
            high_func = decomp_res.getHighFunction()
        except Exception:
            continue
        
        op_iter = high_func.getPcodeOps()
        while op_iter.hasNext():
            pcode_op = op_iter.next()
            if pcode_op.getOpcode() == PcodeOp.CALL:
                target_func = getFunctionAt(pcode_op.getInput(0).getAddress())
                if target_func and target_func.getName() in sink_names_set:
                    vd = {
                        "loc": pcode_op.getSeqnum().getTarget(),
                        "sink_name": target_func.getName(),
                        "sink_info": sinks_map[target_func.getName()],
                        "caller_func": caller_func
                    }
                    if vd not in vds: vds.append(vd)
    print("[+] Found {} potential VDs.".format(len(vds)))
    return vds

def backward_slicing(vd, decompiler):
    """
    Generates detailed flow traces by slicing backward from a sink call,
    capturing inter-procedural call sites and variables.
    """
    final_traces = []
    worklist = []
    
    try:
        high_func = decompiler.decompileFunction(vd["caller_func"], 30, ConsoleTaskMonitor()).getHighFunction()
        if high_func:
            call_op = high_func.getPcodeOps(vd["loc"]).next()
            initial_trace_step = {
                'caller_func': vd["caller_func"].getName(),
                'call_location': str(vd["loc"]),
                'callee_func': vd["sink_name"]
            }
            for i in vd["sink_info"]["sink_result"]["params"]:
                if i < call_op.getNumInputs():
                    arg_varnode = call_op.getInput(i)
                    worklist.append((vd["caller_func"], arg_varnode, [initial_trace_step], 0))
    except Exception as e:
        print("  [ERR] Initial decompilation for slicing failed: {}".format(e))
        return []

    visited = set()
    while worklist:
        current_func, varnode, trace, depth = worklist.pop(0)

        if depth >= CALL_DEPTH_LIMIT:
            if trace not in final_traces: final_traces.append(trace)
            continue

        state_key = (current_func.getEntryPoint(), varnode.getOffset(), varnode.getSize())
        if state_key in visited: continue
        visited.add(state_key)

        slice_ops = simple_backward_slice(varnode)
        if not slice_ops:
            if trace not in final_traces: final_traces.append(trace)
            continue
        
        found_next_link = False
        for op in slice_ops:
            for op_input in op.getInputs():
                high_var = op_input.getHigh()
                if isinstance(high_var, HighParam):
                    param_symbol = high_var.getSymbol()
                    for caller_func in current_func.getCallingFunctions(ConsoleTaskMonitor()):
                        if caller_func.isThunk() or caller_func.isExternal(): continue
                        try:
                            caller_high_func = decompiler.decompileFunction(caller_func, 30, ConsoleTaskMonitor()).getHighFunction()
                            if not caller_high_func: continue
                            
                            caller_op_iter = caller_high_func.getPcodeOps()
                            while caller_op_iter.hasNext():
                                cop = caller_op_iter.next()
                                if cop.getOpcode() == PcodeOp.CALL and cop.getInput(0).getAddress() == current_func.getEntryPoint():
                                    param_index = param_symbol.getCategoryIndex()
                                    if param_index + 1 < cop.getNumInputs():
                                        arg_varnode = cop.getInput(param_index + 1)
                                        new_trace_step = {
                                            'caller_func': caller_func.getName(),
                                            'call_location': str(cop.getSeqnum().getTarget()),
                                            'callee_func': current_func.getName()
                                        }
                                        new_trace = [new_trace_step] + trace
                                        worklist.append((caller_func, arg_varnode, new_trace, depth + 1))
                                        found_next_link = True
                        except Exception:
                            continue
        
        if not found_next_link:
            if trace not in final_traces: final_traces.append(trace)
                
    if not final_traces and trace:
        if trace not in final_traces: final_traces.append(trace)
            
    return final_traces

def generate_flow_traces(vds, decompiler):
    """
    Orchestrates the backward slicing for each VD to generate all possible flow traces.
    """
    print("\n[+] Phase 1: Generating Flow Traces...")
    all_traces = []
    for vd in vds:
        print("  Slicing backward from VD: Sink '{}' in '{}' at {}".format(vd['sink_name'], vd['caller_func'].getName(), vd['loc']))
        traces = backward_slicing(vd, decompiler)
        for trace in traces:
            if trace not in all_traces:
                all_traces.append(trace)
                print("    [Trace Found] Length: {}, Entry: {}".format(len(trace), trace[0]['caller_func']))
    
    print("[+] Found {} unique flow trace(s).".format(len(all_traces)))
    return all_traces
def generate_dangerous_flows(flow_traces, sources, func_manager, symbol_table, decompiler):
    """
    FINAL VERSION: Uses a robust P-Code iteration method to find all function calls,
    ensuring reliable source matching.
    """
    print("\n[+] Phase 2: Generating Dangerous Flows (DFs) with Source Matching...")
    source_names = {s["function"] for s in sources}
    dangerous_flows = []

    for trace in flow_traces:
        # Get the unique function names from the trace to inspect
        chain_funcs = list(dict.fromkeys([step['caller_func'] for step in trace]))

        for func_name in chain_funcs:
            # Get the Ghidra function object for the current function in the chain
            func = None
            symbol_iter = symbol_table.getSymbols(func_name)
            if symbol_iter.hasNext():
                func = getFunctionAt(symbol_iter.next().getAddress())
            if not func: continue

            # --- NEW ROBUST METHOD TO FIND CALLED FUNCTIONS ---
            # Instead of func.getCalledFunctions(), we iterate P-Code CALL ops.
            try:
                high_func = decompiler.decompileFunction(func, 30, ConsoleTaskMonitor()).getHighFunction()
                if not high_func: continue

                op_iter = high_func.getPcodeOps()
                called_funcs_in_current = set()
                while op_iter.hasNext():
                    pcode_op = op_iter.next()
                    if pcode_op.getOpcode() == PcodeOp.CALL:
                        target_func = getFunctionAt(pcode_op.getInput(0).getAddress())
                        if target_func:
                            called_funcs_in_current.add(target_func.getName())

                # This is the debug print you requested:
                print("  [Debug] Functions called by '{}': {}".format(func_name, called_funcs_in_current))

                # Check for an intersection with our known source functions
                found_sources = called_funcs_in_current.intersection(source_names)

                if found_sources:
                    source_func_name = list(found_sources)[0]
                    sink_step = trace[-1]
                    df_object = {
                        'sink_function': sink_step['callee_func'],
                        'sink_location': sink_step['call_location'],
                        'flow_trace': trace,
                        'source_info': {
                            'source_function_called': source_func_name,
                            'called_from_function': func_name
                        }
                    }
                    if df_object not in dangerous_flows:
                        dangerous_flows.append(df_object)
                    # Once a source is found in the chain, we can stop searching this chain
                    break 
            except Exception:
                continue
                
    print("[+] Found {} source-matched Dangerous Flow(s).".format(len(dangerous_flows)))
    return dangerous_flows

def run_latte_analysis(sinks_file, sources_file, output_file):
    """ 
    Main analysis workflow, with source matching and entrypoint filtering.
    """
    func_manager = currentProgram().getFunctionManager()
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram())
    symbol_table = currentProgram().getSymbolTable()
    try:
        with open(sinks_file, 'r') as f: sinks = json.load(f)
        with open(sources_file, 'r') as f: sources = json.load(f)
    except Exception as e:
        print("[FATAL] Could not load sinks/sources JSON files: {}".format(e))
        return

    vds = find_vulnerable_destinations(sinks, func_manager, decompiler)
    all_traces = generate_flow_traces(vds, decompiler)
    dangerous_flows = generate_dangerous_flows(all_traces, sources, func_manager, symbol_table, decompiler)

    # print("\n[+] Filtering DFs for meaningful entrypoints (non-'FUN_' names)...")
    # filtered_flows = []
    # for flow in dangerous_flows:
    #     entry_function_name = flow['flow_trace'][0]['caller_func']
    #     if not entry_function_name.startswith("FUN_"):
    #         filtered_flows.append(flow)
    #     else:
    #         print("  [Filtered Out] DF starting at stripped function: {}".format(entry_function_name))

    print("\n[+] Analysis Complete. Final Dangerous Flows:")
    for df in dangerous_flows:
        print("  - Flow from source '{}' to sink '{}'".format(
            df['source_info']['source_function_called'], df['sink_function']))
        
    with open(output_file, 'w') as f:
        json.dump(dangerous_flows, f, indent=2)
    print("\n[DONE] Saved {} filtered DFs to {}".format(len(dangerous_flows), output_file))

if __name__ == "__main__":
    args = getScriptArgs()
    sinks_path, sources_path, output_path = None, None, None

    try:
        if '--sinks' in args:
            sinks_path = args[args.index('--sinks') + 1]
        if '--sources' in args:
            sources_path = args[args.index('--sources') + 1]
        if '--output' in args:
            output_path = args[args.index('--output') + 1]
    except IndexError:
        print("[FATAL] A script argument flag was not followed by a path.")
        sinks_path = None

    if sinks_path and sources_path and output_path:
        print("[INFO] Running in Headless mode with provided arguments.")
        run_latte_analysis(sinks_path, sources_path, output_path)
    else:
        # Fallback for GUI mode
        print("[INFO] Could not parse script args. Running with hardcoded paths for GUI mode.")
        script_dir = "/mnt/z/Papers/MyRAG/LATTE_ReImplementing"
        binary_name = "CWE190_Integer_Overflow__char_fscanf_preinc_05"
        
        sinks_json_path = os.path.join(script_dir, "results", "sink_classification_{}.json".format(binary_name))
        sources_json_path = os.path.join(script_dir, "results", "source_classification_{}.json".format(binary_name))
        output_json_path = os.path.join(script_dir, "results", "dangerous_flows_{}.json".format(binary_name))

        if not os.path.exists(sinks_json_path) or not os.path.exists(sources_json_path):
            print("\n[FATAL] Sinks or Sources JSON file not found at the specified hardcoded path.")
        else:
            run_latte_analysis(sinks_json_path, sources_json_path, output_json_path)
