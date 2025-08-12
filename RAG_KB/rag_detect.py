import json
import argparse
import os
import pathlib
from llm_clients import LLMClient
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# --- Prompts for the Online Detection Phase ---

SEMANTICS_EXTRACTION_PROMPT = """
You are an expert security analyst. Your task is to summarize the high-level functionality of the following C code snippet in 1-2 sentences. Focus on what the code is trying to achieve.

Code Snippet:
```c
{code}
```

Functional Semantics:
"""

DETECTION_PROMPT = """
You are an expert security analyst. Your task is to determine if the "Code to Analyze" is vulnerable, based on the "Relevant Vulnerability Knowledge" provided.

**Relevant Vulnerability Knowledge:**
- **Vulnerability Cause:** {vulnerability_cause}
- **Fixing Solution:** {fixing_solution}

**Code to Analyze:**
```c
{candidate_code}
```

Based on the provided knowledge, does the 'Code to Analyze' contain the described vulnerability? Answer with "YES" or "NO" and provide a brief, one-sentence explanation.

**Analysis:**
"""

class RAGDetector:
    def __init__(self, kb_path, backend="gemini"):
        self.client = LLMClient(backend)
        self.knowledge_base = self._load_kb(kb_path)
        self.vectorizer_sem, self.kb_matrix_sem = self._build_semantic_retriever()
        self.vectorizer_code, self.kb_matrix_code = self._build_code_retriever()
        print(f"[+] RAG Detector initialized with {len(self.knowledge_base)} KB entries.")

    def _load_kb(self, kb_path):
        kb = []
        with open(kb_path, 'r') as f:
            for line in f:
                kb.append(json.loads(line))
        return kb

    def _build_semantic_retriever(self):
        """Creates a TF-IDF retriever for the functional semantics."""
        vectorizer = TfidfVectorizer(stop_words='english')
        corpus = [entry.get('functional_semantics', '') for entry in self.knowledge_base]
        matrix = vectorizer.fit_transform(corpus)
        return vectorizer, matrix

    def _build_code_retriever(self):
        """Creates a TF-IDF retriever for the vulnerable code snippets."""
        vectorizer = TfidfVectorizer(stop_words='english')
        corpus = [entry.get('bad_code', '') for entry in self.knowledge_base]
        matrix = vectorizer.fit_transform(corpus)
        return vectorizer, matrix

    def get_functional_semantics(self, code):
        """Uses an LLM to get the functional semantics of a code snippet."""
        prompt = SEMANTICS_EXTRACTION_PROMPT.format(code=code)
        response = self.client.generate(prompt)
        return response['text']

    def retrieve_relevant_knowledge(self, query_semantics, query_code, top_k=5, alpha=0.5):
        """
        Finds the most similar KB entry using a hybrid of semantic and code similarity.
        'alpha' controls the weight of code similarity vs. semantic similarity.
        """
        # Semantic search
        vec_sem = self.vectorizer_sem.transform([query_semantics])
        sim_sem = cosine_similarity(vec_sem, self.kb_matrix_sem).flatten()

        # Code similarity search
        vec_code = self.vectorizer_code.transform([query_code])
        sim_code = cosine_similarity(vec_code, self.kb_matrix_code).flatten()

        # Combine scores (simple weighted average)
        combined_scores = (alpha * sim_code) + ((1 - alpha) * sim_sem)
        
        best_match_idx = combined_scores.argmax()
        return self.knowledge_base[best_match_idx]

    def detect_vulnerability(self, candidate_flow):
        """
        Runs the full RAG pipeline for a single candidate flow.
        """
        candidate_code = candidate_flow['flow_trace'][0].get('code', "Code not available.")
        
        print("\n--- Analyzing New Candidate Flow ---")
        print(f"Sink: {candidate_flow['sink_function']}")

        # 1. Get functional semantics for the candidate code
        print("[1/3] Extracting functional semantics from candidate...")
        candidate_semantics = self.get_functional_semantics(candidate_code)
        print(f"  - Semantics: {candidate_semantics}")

        # 2. Retrieve the most relevant knowledge from the KB using the hybrid method
        print("[2/3] Retrieving most relevant knowledge from KB...")
        relevant_kb_entry = self.retrieve_relevant_knowledge(candidate_semantics, candidate_code)
        print(f"  - Retrieved knowledge for: {relevant_kb_entry['vulnerability']}")

        # 3. Build the final prompt and get the LLM's judgment
        print("[3/3] Performing knowledge-augmented detection...")
        detection_prompt = DETECTION_PROMPT.format(
            vulnerability_cause=relevant_kb_entry['vulnerability_cause'],
            fixing_solution=relevant_kb_entry['fixing_solution'],
            candidate_code=candidate_code
        )
        final_judgment = self.client.generate(detection_prompt)
        print(f"  - Final Judgment: {final_judgment['text']}")

        return {
            "candidate_flow": candidate_flow,
            "retrieved_knowledge": relevant_kb_entry,
            "final_judgment": final_judgment['text']
        }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vulnerability detection using a Knowledge-Level RAG.")
    parser.add_argument('--kb', required=True, help="Path to the annotated knowledge base JSONL file.")
    parser.add_argument('--input', required=True, help="Path to the JSON file with dangerous flows to analyze.")
    parser.add_argument('--output', required=True, help="Path to save the final vulnerability reports.")
    parser.add_argument('--backend', default="gemini", choices=["gemini", "local"], help="LLM backend to use.")
    args = parser.parse_args()

    detector = RAGDetector(args.kb, args.backend)

    with open(args.input, 'r') as f:
        dangerous_flows = json.load(f)

    reports = []
    for flow in dangerous_flows:
        report = detector.detect_vulnerability(flow)
        reports.append(report)

    pathlib.Path(os.path.dirname(args.output)).mkdir(parents=True, exist_ok=True)
    with open(args.output, 'w') as f:
        json.dump(reports, f, indent=2)
    
    print(f"\n\n✅ Detection complete! Saved {len(reports)} reports to {args.output}")
