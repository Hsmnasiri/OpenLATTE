import json

class ProgramData:
    def __init__(self, ghidra_export_path):
        with open(ghidra_export_path, 'r') as f:
            self.data = json.load(f)
        self.functions = self.data.get("functions", {})
        self.call_graph = self.data.get("call_graph", {})
        self.external_functions = self.data.get("external_functions", [])
        # Create a reverse call graph for backward slicing
        self.reverse_call_graph = self._build_reverse_call_graph()

    def _build_reverse_call_graph(self):
        rcg = {}
        for caller, callees in self.call_graph.items():
            for callee in callees:
                if callee not in rcg:
                    rcg[callee] = []
                rcg[callee].append(caller)
        return rcg

    def get_decompiled_code(self, func_addr):
        return self.functions.get(func_addr, {}).get("decompiled_code")

    def get_callers(self, func_addr):
        return self.reverse_call_graph.get(func_addr, [])

# Example Usage:
# program_data = ProgramData("/tmp/ghidra_export.json")