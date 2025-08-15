# inspect_flows_with_rag.py

import json
import argparse
import os
import logging
from llm_clients import LLMClient
from rag_vector_db import RAGVectorDB

# --- Setup Detailed Logging ---
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
log_file_handler = logging.FileHandler('rag_analysis.log', mode='w')
log_file_handler.setFormatter(log_formatter)
log_file_handler.setLevel(logging.INFO)

console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
console_handler.setLevel(logging.INFO)

logger = logging.getLogger('rag_analyzer')
logger.addHandler(log_file_handler)
logger.addHandler(console_handler)
logger.setLevel(logging.INFO)

# --- Prompt Templates ---
SEMANTICS_PROMPT_TEMPLATE = """
As a senior security analyst, your task is to provide a concise, one-sentence functional description of the provided C code snippet. Focus on the overall purpose of the code flow. Do not describe vulnerabilities.

Code to analyze:
{code}

Functional Semantics:
"""

FINAL_ANALYSIS_PROMPT_TEMPLATE = """
You are an expert security analyst. Your task is to determine if the provided "Target Code" is vulnerable.

To assist you, I am providing several "Reference Examples" from a trusted knowledge base that are semantically or syntactically similar to the target code. Each example includes a description of its vulnerability and the solution.

Carefully analyze the Target Code in light of the Reference Examples and provide your final judgment in a structured JSON format.

--- REFERENCE EXAMPLES ---
{reference_examples}

--- TARGET CODE ---
{target_code}

--- ANALYSIS TASK ---
Based on your analysis, provide a structured analysis in the specified JSON format without any additional text.

{{
  "is_vulnerable": <true or false>,
  "confidence_score": <A float from 0.0 to 1.0 indicating your confidence>,
  "vulnerability_type": "Provide the CWE ID if vulnerable (e.g., 'CWE-78'), otherwise 'N/A'",
  "explanation": "Provide a detailed step-by-step explanation for your decision, referencing the similarities or differences with the provided examples."
}}
"""

def format_retrieved_examples(results):
    """Formats the retrieved documents into a string for the final prompt."""
    if not results:
        return "No relevant examples found in the knowledge base."
    
    formatted = ""
    # Unpack the 4-element list from reranking, ignoring the last element (boosted_score)
    for i, (metadata, score, match_type, _) in enumerate(results):
        formatted += f"### Example {i+1} (Retrieved via {match_type} similarity, Score: {score:.4f}) ###\n"
        formatted += f"- Vulnerability: {metadata.get('vulnerability', 'N/A')}\n"
        formatted += f"- Cause: {metadata.get('vulnerability_cause', 'N/A')}\n"
        formatted += f"- Fix: {metadata.get('fixing_solution', 'N/A')}\n\n"
    return formatted.strip()

def main():
    parser = argparse.ArgumentParser(description="Inspect dangerous flows using RAG-enhanced LLM analysis.")
    parser.add_argument('--flows-with-code', required=True, help="Path to the flows_with_code.json file.")
    parser.add_argument('--output', required=True, help="Path to save the final vulnerability reports.")
    parser.add_argument('--db-path', default='rag_db', help="Path to the RAG vector database.")
    parser.add_argument('--backend', choices=['gemini', 'ollama'], default='gemini', help="The LLM backend to use.")
    parser.add_argument('--top-k', type=int, default=3, help="Number of examples to retrieve from the KB.")
    args = parser.parse_args()

    vector_db = RAGVectorDB(db_path=args.db_path)
    if not vector_db.load():
        logger.error("Failed to load RAG database. Exiting.")
        return

    with open(args.flows_with_code, 'r', encoding='utf-8') as f:
        flows_to_analyze = json.load(f)

    llm_client = LLMClient(backend=args.backend)
    vulnerability_reports = []

    for i, flow in enumerate(flows_to_analyze):
        flow_id = flow.get('flow_id', f"flow_{i}")
        logger.info(f"--- Analyzing Flow #{i+1}/{len(flows_to_analyze)} (ID: {flow_id}) ---")

        target_code = "\n\n---\n\n".join([step['code'] for step in flow['flow_trace']])
        
        logger.info(f"[{flow_id}] Generating functional semantics for the target code...")
        semantics_prompt = SEMANTICS_PROMPT_TEMPLATE.format(code=target_code)
        try:
            # FIX: Access the .text attribute from the full response object
            response = llm_client.generate(semantics_prompt)
            target_semantics = response.text.strip()
            logger.info(f"[{flow_id}] Generated Semantics: {target_semantics}")
        except Exception as e:
            logger.error(f"[{flow_id}] Failed to generate semantics: {e}")
            target_semantics = ""

        logger.info(f"[{flow_id}] Retrieving top {args.top_k} examples from knowledge base...")
        code_results = vector_db.search(target_code, k=args.top_k, search_type='code')
        logger.info(f"[{flow_id}] Found {len(code_results)} candidates based on code similarity.")
        for res in code_results:
            logger.info(f"  - Code Match: {res[0]['vulnerability']} (Score: {res[1]:.4f})")

        semantic_results = []
        if target_semantics:
            semantic_results = vector_db.search(target_semantics, k=args.top_k, search_type='text')
            logger.info(f"[{flow_id}] Found {len(semantic_results)} candidates based on semantic similarity.")
            for res in semantic_results:
                logger.info(f"  - Semantic Match: {res[0]['vulnerability']} (Score: {res[1]:.4f})")

        all_results = {}
        for res in code_results + semantic_results:
            vuln_id = res[0]['vulnerability']
            score_boost = 1.0 if res[2] == 'code' else 0.9
            boosted_score = res[1] * score_boost
            
            if vuln_id not in all_results or boosted_score > all_results[vuln_id][3]:
                all_results[vuln_id] = [res[0], res[1], res[2], boosted_score]

        reranked_results = sorted(all_results.values(), key=lambda x: x[3], reverse=True)[:args.top_k]
        logger.info(f"[{flow_id}] Top {len(reranked_results)} reranked results selected for final prompt.")
        for res in reranked_results:
            logger.info(f"  - Final Candidate: {res[0]['vulnerability']} (Type: {res[2]}, Score: {res[1]:.4f})")

        logger.info(f"[{flow_id}] Generating final analysis with RAG context...")
        reference_examples_str = format_retrieved_examples(reranked_results)
        
        final_prompt = FINAL_ANALYSIS_PROMPT_TEMPLATE.format(
            reference_examples=reference_examples_str,
            target_code=target_code
        )
        
        try:
            # FIX: Access the .text attribute from the full response object
            final_response_obj = llm_client.generate(final_prompt)
            final_response_text = final_response_obj.text
            final_judgment = json.loads(final_response_text)
            logger.info(f"[{flow_id}] Final Judgment: {final_judgment}")
        except Exception as e:
            logger.error(f"[{flow_id}] Failed to get or parse final judgment: {e}")
            # FIX: Correctly access the response text from the object, even in case of error
            raw_response = getattr(final_response_obj, 'text', 'Response object was not generated or had no text.')
            final_judgment = {"error": str(e), "raw_response": raw_response}

        # FIX: Convert numpy.float32 to native Python float for JSON serialization
        clean_context = []
        for metadata, score, match_type, _ in reranked_results:
            clean_context.append([metadata, float(score), match_type])

        report = {
            'flow_id': flow_id,
            'retrieved_context': clean_context,
            'final_judgment': final_judgment
        }
        vulnerability_reports.append(report)

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(vulnerability_reports, f, indent=2)
    
    logger.info(f"\n[DONE] Saved {len(vulnerability_reports)} RAG-enhanced vulnerability reports to {args.output}")
    logger.info(f"Detailed logs are available in rag_analysis.log")

if __name__ == "__main__":
    main()
