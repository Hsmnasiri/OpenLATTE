from llm_client import query_llm_conversational
from data_loader import ProgramData

class Slicer:
    def __init__(self, program_data: ProgramData):
        self.data = program_data
        self.sinks = {} # {(func_name, param_index)}
        self.sources = {} # {(func_name, param_index)}

    # --- Step 3.1: Sink Identification (Ref: Fig 7) ---
    def identify_sinks(self):
        """Use LLM to identify sinks among external functions."""
        

        for func_name in self.data.external_functions:
            prompt = SINK_PROMPT_TEMPLATE.format(func_name=func_name)
            response = query_llm(prompt)
            
            if response and "Yes" in response:
                # Placeholder: Need robust parsing of the response format (e.g., "(printf; 1)")
                self._parse_and_store_sink(func_name, response)

    # --- Step 3.2: VD Identification & Backward Slicing ---
    def extract_call_chains(self):
        vds = self._identify_vulnerable_destinations()
        all_ccs = []
        
        for vd in vds:
            # Placeholder: Implement backward intra- and inter-procedural data dependency analysis
            # This is the most complex part of the static analysis, requiring tracing data flow 
            # backwards from the VD arguments up through the reverse call graph.
            ccs = self._backward_slice(vd)
            all_ccs.extend(ccs)
        
        return all_ccs

    def _identify_vulnerable_destinations(self):
        # Logic to find all call sites of identified sinks within the binary.
        # Result: List of VDs (Loc; sink; Arg)
        pass

    def _backward_slice(self, vd):
        # Logic for depth-first backward traversal of the call graph,
        # performing flow-insensitive, path-insensitive data dependency analysis.
        # Limits depth to 50 to manage complexity.

        pass

    # --- Step 4.1: Source Identification (Ref: Fig 9) ---
    def identify_sources(self):
       
        for func_name in self.data.external_functions:
            prompt = SOURCE_PROMPT_TEMPLATE.format(func_name=func_name)
            response = query_llm(prompt)

            if response and "Yes" in response:
                # Placeholder: Need robust parsing of the response format (e.g., "(recv; 2)")
                self._parse_and_store_source(func_name, response)

    # --- Step 4.2: Matching and Deduplication ---
    def generate_dangerous_flows(self, all_ccs):
        candidate_dfs = []
        
        for cc in all_ccs:
            # Check if any function in the CC calls an identified source
            # AND if the source argument overlaps with the dataflow path to the VD
            if self._match_source_in_cc(cc):
                # Create Candidate DF (CDF)
                cdf = self._create_cdf(cc)
                candidate_dfs.append(cdf)

        # Deduplication: Remove CDFs that are subchains of other CDFs
        dfs = self._deduplicate_flows(candidate_dfs)
        return dfs
    

    import re
from llm_client import query_llm_conversational
from data_loader import ProgramData

class Slicer:
    def __init__(self, program_data: ProgramData):
        self.data = program_data
        # Using sets to store tuples of (func_name, param_index) to avoid duplicates
        self.sinks = set()
        self.sources = set()

    def _parse_and_store_sink(self, func_name, response):
        """Parses LLM response to extract and store sink information."""
        # Use regex to find all occurrences of (function; param1, param2, ...)
        matches = re.findall(r'\((\w+);\s*([\d,\s\.]+)\)', response)
        for _, params_str in matches:
            # Handle "all" or numeric parameters
            if "all" in params_str.lower():
                 self.sinks.add((func_name, 'all'))
            else:
                params = [p.strip() for p in params_str.split(',')]
                for param in params:
                    if param.isdigit():
                        self.sinks.add((func_name, int(param)))

    def _parse_and_store_source(self, func_name, response):
        """Parses LLM response to extract and store source information."""
        matches = re.findall(r'\((\w+);\s*([\d,\s>]+)\)', response)
        for _, params_str in matches:
            params = [p.strip() for p in params_str.split(',')]
            for param in params:
                 if param.isdigit():
                    self.sources.add((func_name, int(param)))

    def identify_sinks(self):
        """Use LLM to identify sinks among external functions."""
        SINK_PROMPT_TEMPLATE = """
        As a program analyst, is it possible to use a call {func_name} as a sink when performing taint analysis? If so which parameters need to be checked for taint. 
        Please answer yes or no without additional explanation. If yes, please indicate the corresponding parameters. 
        For example, the system function can be used as a sink, and the first parameter needs to be checked as (system; 1).
        """
        print("Identifying sinks...")
        for func_name in self.data.external_functions:
            prompt = SINK_PROMPT_TEMPLATE.format(func_name=func_name)
            response = query_llm_conversational([{"role": "user", "content": prompt}])
            if response and "Yes" in response:
                self._parse_and_store_sink(func_name, response)
        print(f"Identified {len(self.sinks)} unique sinks.")

    def identify_sources(self):
        """Use LLM to identify sources among external functions."""
        SOURCE_PROMPT_TEMPLATE = """
As a program analyst, is it possible to use a call to {func_name} as a starting point (source) for taint analysis? If the function can be used as a taint source, which parameter in the call stores the external input data. Please answer yes or no without additional explanation. If yes, please indicate the corresponding parameters. For example, the recv function call can be used as a taint source, and the second parameter as a buffer stores the input data as (recv; 2).
"""
        print("Identifying sources...")
        for func_name in self.data.external_functions:
             prompt = SOURCE_PROMPT_TEMPLATE.format(func_name=func_name)
             response = query_llm_conversational([{"role": "user", "content": prompt}])
             if response and "Yes" in response:
                self._parse_and_store_source(func_name, response)
        print(f"Identified {len(self.sources)} unique sources.")

    def _identify_vulnerable_destinations(self):
        """Finds all call sites of identified sinks to create VDs."""
        vds = []
        sink_names = {s[0] for s in self.sinks}
        for func_addr, func_data in self.data.functions.items():
            if not func_data["decompiled_code"]:
                continue
            # Simple check to see if a sink function name appears in the code
            for sink_name in sink_names:
                if f"{sink_name}(" in func_data["decompiled_code"]:
                    # This is a simplification. A real implementation would parse the AST
                    # to get exact line numbers (Loc) and arguments (Arg).
                    vd = {"loc": func_addr, "sink": sink_name, "arg": "unknown"}
                    vds.append(vd)
        return vds

    def _backward_slice(self, vd, max_depth=50):
        """
        Performs a recursive depth-first backward traversal from a VD
        to generate all possible call chains (CCs).
        """
        all_chains = []
        
        def find_chains_recursive(func_addr, current_chain):
            # Prepend current function to the chain
            chain = [func_addr] + current_chain
            
            # Stop if max depth is reached
            if len(chain) >= max_depth:
                all_chains.append(chain)
                return

            callers = self.data.get_callers(func_addr)
            if not callers:
                # If no more callers, this chain is complete
                all_chains.append(chain)
                return
            
            # Recurse for each caller
            for caller_addr in callers:
                # Avoid infinite recursion in case of cyclic calls
                if caller_addr not in chain:
                    find_chains_recursive(caller_addr, chain)

        # Start the recursive search from the function containing the VD
        find_chains_recursive(vd["loc"], [])
        return all_chains

    def extract_call_chains(self):
        """Extracts all call chains ending in a Vulnerable Destination."""
        vds = self._identify_vulnerable_destinations()
        print(f"Found {len(vds)} potential Vulnerable Destinations (VDs).")
        all_ccs = []
        for vd in vds:
            ccs = self._backward_slice(vd)
            all_ccs.extend(ccs)
        print(f"Extracted {len(all_ccs)} potential Call Chains (CCs).")
        return all_ccs

    def _match_source_in_cc(self, cc):
        """Checks if a CC contains a call to an identified source."""
        source_names = {s[0] for s in self.sources}
        for func_addr in cc:
            func_data = self.data.functions.get(str(func_addr), {})
            if func_data and func_data["decompiled_code"]:
                for source_name in source_names:
                    if f"{source_name}(" in func_data["decompiled_code"]:
                        # Return the first function in the chain that calls a source
                        return func_addr
        return None
        
    def _deduplicate_flows(self, cdfs):
        """Removes CDFs that are subchains of other CDFs."""
        # Sort by length descending, so we compare shorter chains against longer ones
        cdfs.sort(key=len, reverse=True)
        unique_dfs = []
        for i, cdf1 in enumerate(cdfs):
            is_subchain = False
            for cdf2 in cdfs[:i]: # Only check against longer, already-processed chains
                # Convert to strings for easy substring check
                str1 = ",".join(map(str, cdf1))
                str2 = ",".join(map(str, cdf2))
                if str1 in str2:
                    is_subchain = True
                    break
            if not is_subchain:
                unique_dfs.append(cdf1)
        return unique_dfs

    def generate_dangerous_flows(self, all_ccs):
        """Filters CCs to create final Dangerous Flows (DFs)."""
        candidate_dfs = []
        for cc in all_ccs:
            source_caller_addr = self._match_source_in_cc(cc)
            if source_caller_addr:
                # The "Dangerous Flow" starts from the function that calls the source
                try:
                    start_index = cc.index(source_caller_addr)
                    candidate_dfs.append(cc[start_index:])
                except ValueError:
                    continue

        print(f"Found {len(candidate_dfs)} Candidate Dangerous Flows (CDFs).")
        dfs = self._deduplicate_flows(candidate_dfs)
        print(f"Filtered down to {len(dfs)} unique Dangerous Flows (DFs).")
        return dfs