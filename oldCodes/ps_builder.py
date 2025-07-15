import ps_templates

class PromptSequenceBuilder:
    def __init__(self, dangerous_flow, program_data):
        self.df = dangerous_flow 
        self.data = program_data
        self.sequence = []

    def build_sequence(self):
        """Constructs the full prompt sequence for the DF."""
        
        # Start Prompt (First function in DF)
        f_start = self.df[0]
        start_prompt = ps_templates.START_PROMPT.format(
            function=f_start['source_func'], 
            parameter=f_start['source_param'],
            code_snippet=self.data.get_decompiled_code(f_start['addr'])
        )
        self.sequence.append({"role": "user", "content": start_prompt})

        
        for func in self.df[1:]:
            code = self.data.get_decompiled_code(func['addr'])
            
            # Check if this function introduces a new taint source
            new_source_note = ""
            if 'new_source' in func:
                 new_source_note = ps_templates.NEW_SOURCE_NOTE.format(
                     function=func['new_source']['func'],
                     parameter=func['new_source']['param']
                 )

            middle_prompt = ps_templates.MIDDLE_PROMPT.format(
                code_snippet=code,
                new_source_note=new_source_note
            )
            
            # Crucially, we must simulate the conversation. 
            # The LLM needs to respond to the previous prompt before receiving the next.
            self.sequence.append({"step_type": "middle", "content": middle_prompt})

       
        self.sequence.append({"step_type": "end", "content": ps_templates.END_PROMPT})
        
        return self.sequence

    def handle_context_limits(self):
        # If a DF is too long, the generated PS might exceed the LLM's context window. 
        # LATTE mitigates this by analyzing function-by-function (task splitting), 
        # relying on the LLM's short-term memory during the conversation.
        # If an individual function is too large, further intra-function slicing might be needed, 
        # although LATTE primarily relies on function-level splitting.
        pass