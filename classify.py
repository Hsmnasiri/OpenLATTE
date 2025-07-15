#first time:
# python3 -m venv ~/llama-env
# source ~/llama-env/bin/activate
# pip install -U pip wheel
# pip install "llama-cpp-python[server]==0.2.28" fastapi uvicorn pydantic


#other times:
# source ~/llama-env/bin/activate
# export LLAMA_MODEL=/home/$USER/models/llama-2-7b/llama-2-7b-chat.Q4_K_M.gguf
# uvicorn classify:app --host 127.0.0.1 --port 8123

from fastapi import FastAPI
from pydantic import BaseModel
from llama_cpp import Llama
import os, json
import logging
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

SINK_PROMPT_TEMPLATE2 = """
You are a program‑analysis assistant.
Reply with **exactly one line** in one of the following forms:

  (FUNC; N[,M,...])    # the 1‑based index/indices that must be checked
  (NO)                 # if the call is NOT a sink

<EXAMPLES>
(system; 1)            # positive example  – system is a classic sink
(atoi; NO)             # negative example – atoi is not a sink
</EXAMPLES>

<QUESTION>
{func_name}
</QUESTION>
"""

MODEL_PATH = os.getenv("LLAMA_MODEL")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)s  %(message)s",
    handlers=[
        logging.FileHandler("llm_calls.log", encoding="utf-8"),
        logging.StreamHandler()
    ]
)
# Initialize the LLM model
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
    tmpl = SOURCE_PROMPT_TEMPLATE if q.mode == "source" else SINK_PROMPT_TEMPLATE2
    prompt = tmpl.format(func_name=q.func)
    raw = llm(prompt,
            max_tokens=256,
            temperature=0.5,
            stream=False)        

    logging.info("==== LLM CALL ====================")
    logging.info("PROMPT >\n%s", prompt)
    logging.info("RAW    < %s", json.dumps(raw, ensure_ascii=False))

    txt = raw["choices"][0].get("text") \
          or raw["choices"][0].get("message", {}).get("content", "")
    answer = txt.strip()
    logging.info("ANSWER < %s", answer)

    is_true = answer.startswith("(") or answer.lower().startswith("yes")
    params  = []
    if is_true and "(" in answer and ";" in answer:
        try:
            inside = answer.strip("()")
            _, plist = inside.split(";", 1)
            params = [int(p.strip()) for p in plist.split(",") if p.strip().isdigit()]
        except Exception as e:
            logging.warning("parse‑error: %s", e)

    return {"is_true": is_true, "params": params}


