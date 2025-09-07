# OpenLATTE

OpenLATTE is a reimplementation of the [LATTE](https://dl.acm.org/doi/10.1145/3711816) (LLM-Powered Static Binary Taint Analysis) static analysis pipeline for discovering vulnerabilities in stripped binaries.  The project automates the three major phases described in the paper:

1. **Function classification** – external library calls are labelled as potential taint sources or sinks using an LLM.
2. **Flow extraction** – Ghidra scripts identify vulnerable destinations and build call chains that trace the flow of tainted data.
3. **LLM inspection** – the discovered flows are analysed by an LLM to report possible vulnerabilities.  The `rag.py` script optionally augments these prompts with a retrieval‑augmented knowledge base (RAG).

The repository contains helper scripts for running Ghidra in headless mode, exporting code for a knowledge base and querying either a local Ollama model or Google Gemini.

## Repository layout

```
build/                 # Compiled test binaries and symbol maps
results/               # JSON output of each analysis stage
ghidra-workspace/      # Ghidra projects created during headless runs
*.py, *.sh             # Analysis scripts used in each LATTE phase
```

## Requirements

- Python 3.9+
- [Ghidra 11.3.2](https://ghidra-sre.org/) with the Ghidrathon 4.0 plugin
- A running LLM backend
  - Local model via [Ollama](https://ollama.ai/) (`classifyLocal.py`, `inspect_flows_with_llm.py`)
  - Google Gemini for higher quality results (`classifyGemini.py`, `rag.py`)
- `pip install -r requirement.txt`

Several scripts expect environment variables such as `GOOGLE_API_KEY` or `GOOGLE_API_KEY42` to be set with your Gemini key.

## Basic workflow

1. **Export external functions**
   ```bash
   ./flow.sh /path/to/binary.out   # runs Ghidra to dump external functions
   ```

2. **Classify as sources or sinks**
   ```bash
   python3 batch_classify.py --ext-funcs build/external_funcs_<binary>.out.txt \
       --mode sink   --output-dir results
   python3 batch_classify.py --ext-funcs build/external_funcs_<binary>.out.txt \
       --mode source --output-dir results
   ```

3. **Find dangerous flows** (headless Ghidra)
   ```bash
   ./DF.sh   # wrapper around find_dangerous_flows.py
   ```

4. **Export code for each flow**
   ```bash
   "<ghidra>/support/analyzeHeadless" <workspace> ProjectName \
       -import <binary> -scriptPath . -postScript export_flow_code.py -deleteProject
   ```

5. **Inspect flows with an LLM**
   ```bash
   python3 inspect_flows_with_llm.py \
       --flows-with-code results/flows_with_code_<binary>.json \
       --sources results/source_classification_<binary>.json \
       --output results/vulnerability_reports.json
   ```

