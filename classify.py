from fastapi import FastAPI
from pydantic import BaseModel
from llama_cpp import Llama
import os, json

SINK_PROMPT_TEMPLATE="""
        As a program analyst, is it possible to use a call {func_name} as a sink when performing taint analysis? If so which parameters need to be checked for taint. 
        Please answer yes or no without additional explanation. If yes, please indicate the corresponding parameters. 
        For example, the system function can be used as a sink, and the first parameter needs to be checked as (system; 1).
        """
SOURCE_PROMPT_TEMPLATE = """
        As a program analyst, is it possible to use a call to {func_name} as a starting point (source) for taint analysis? 
        If the function can be used as a taint source, which parameter in the call stores the external input data. Please answer yes or no without additional explanation. 
        If yes, please indicate the corresponding parameters. For example, the recv function call can be used as a taint source, and the second parameter as a buffer stores the input data as (recv; 2).
        """

MODEL_PATH = os.getenv("LLAMA_MODEL", "llama-2-7b.Q4_K_M.gguf")

llm = Llama(
    model_path=MODEL_PATH,
    n_ctx=2048,       # fits most extern-lists
    n_threads=os.cpu_count(),  # use all cores
    n_gpu_layers=0    # CPU-only
)

app = FastAPI()

class Q(BaseModel):
    func: str
    mode: str          

@app.post("/check")
def check(q: Q):
    tmpl = SOURCE_PROMPT_TEMPLATE if q.mode == "source" else SINK_PROMPT_TEMPLATE
    prompt = tmpl.format(func_name=q.func)

    out = llm(prompt, max_tokens=32, temperature=0.0, stop=["\n"])
    text = out["choices"][0]["text"].strip()

    # valid answers:  "no"  or  "(recv; 2,3)"
    result = {"is_true": text.lower().startswith("(")}
    if result["is_true"]:
        result["params"] = [
            int(tok.strip()) for tok in text.strip("()").split(";")[1].split(",")
        ]
    else:
        result["params"] = []
    return result
