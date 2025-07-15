import re
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from data_loader import ProgramData
from slicer import Slicer
from ps_builder import PromptSequenceBuilder
from llm_client import query_llm_conversational 

class LATTEAnalyzer:
    def __init__(self, ghidra_export_path):
        self.data = ProgramData(ghidra_export_path)
        self.slicer = Slicer(self.data)
        self.results = []

    def run_analysis(self):
        print("--- Phase 1: Identifying Sources and Sinks ---")
        self.slicer.identify_sinks()
        self.slicer.identify_sources()

        print("--- Phase 2: Extracting Call Chains and Dangerous Flows ---")
        ccs = self.slicer.extract_call_chains()
        if not ccs:
            print("No call chains found. Analysis cannot proceed.")
            return []
            
        dfs = self.slicer.generate_dangerous_flows(ccs)
        if not dfs:
            print("No dangerous flows found. Analysis complete.")
            return []

        print(f"--- Phase 3: LLM Analysis of {len(dfs)} DFs ---")
        for i, df in enumerate(dfs):
            print(f"\nAnalyzing DF {i+1}/{len(dfs)}...")
            self.analyze_df(df, i)
            
        return self.results

    def analyze_df(self, df, df_id):
        """Manages the conversational analysis of a single DF."""
        # This is a simplified DF structure for demonstration
        # A real implementation would have more structured data
        structured_df = [{"addr": addr} for addr in df]
        # Simplification: Assume source is in the first function
        structured_df[0]['source_func'] = 'some_source'
        structured_df[0]['source_param'] = '1'

        ps_builder = PromptSequenceBuilder(structured_df, self.data)
        prompt_sequence = ps_builder.build_sequence()
        
        conversation_history = []

        for prompt_data in prompt_sequence:
            current_prompt = {"role": "user", "content": prompt_data['content']}
            
            # The llm_client now handles the history
            response_text = query_llm_conversational(conversation_history + [current_prompt])
            
            if not response_text:
                print("LLM analysis failed for this DF.")
                return

            conversation_history.append(current_prompt)
            conversation_history.append({"role": "assistant", "content": response_text})

            if prompt_data.get('step_type') == 'end':
                self._parse_final_result(df, df_id, response_text)

    def _extract_cwe(self, llm_response):
        """Extracts a CWE identifier from the LLM's response."""
        match = re.search(r'CWE-\d+', llm_response, re.IGNORECASE)
        if match:
            return match.group(0).upper()
        return "Not specified"

    def _parse_final_result(self, df, df_id, llm_response):
        """Parses the final LLM output and stores the result."""
        # Check for keywords indicating a vulnerability
        is_vulnerable = any(keyword in llm_response.lower() for keyword in ["vulnerability", "overflow", "injection", "vulnerable"])
        
        cwe_id = self._extract_cwe(llm_response)
        
        result = {
            "DF_ID": df_id,
            "DF_Chain": [str(addr) for addr in df],
            "Vulnerable": is_vulnerable,
            "CWE": cwe_id,
            "LLM_Reasoning": llm_response.strip()
        }
        self.results.append(result)
        print(f"DF {df_id} Result: Vulnerable={is_vulnerable}, CWE={cwe_id}")