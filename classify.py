#first time:
# python3 -m venv ~/llama-env
# source ~/llama-env/bin/activate
# pip install -U pip wheel
# pip install "llama-cpp-python[server]==0.2.28" fastapi uvicorn pydantic


#other times:
# source ~/llama-env/bin/activate
# export LLAMA_MODEL=/home/$USER/models/llama-2-7b/llama-2-7b-chat.Q4_K_M.gguf
# uvicorn classify:app --host 127.0.0.1 --port 8123
import logging
import re
from fastapi import FastAPI
from pydantic import BaseModel
from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline
import torch


# Configure logging
def configure_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
         handlers=[
        logging.FileHandler("llm_calls.log", encoding="utf-8"),
        logging.StreamHandler()
    ]
        
    )
    return logging.getLogger("classify_cpu")

logger = configure_logging()

# Model setup for CPU
MODEL_ID_GPTJ = "EleutherAI/gpt-j-6B"
MODEL_ID = "mistralai/Mistral-7B-Instruct-v0.2"
logger.info(f"Loading model '{MODEL_ID}' on CPU (32GB RAM, no GPU)...")
tokenizer = AutoTokenizer.from_pretrained(MODEL_ID, trust_remote_code=True,
    use_safetensors=True,
    use_auth_token=True)
model = AutoModelForCausalLM.from_pretrained(
    MODEL_ID,
    torch_dtype=torch.float16,
    device_map={"": "cpu"},  # force CPU
    use_auth_token=True
)
generator = pipeline(
    "text-generation",
    model=model,
    tokenizer=tokenizer,
    device_map={"": "cpu"},
    max_length=512,
    temperature=0.0,
    do_sample=False,
    repetition_penalty=1.1,
    return_full_text=False
)
logger.info("Model loaded successfully on CPU.")

# Request schema
typedef = BaseModel  # alias for readability
class Q(BaseModel):
    func: str
    mode: str

# Prompt template
SINK_PROMPT_TEMPLATE = """
You are an expert in taint‐analysis. When asked about a function call, respond **only** with **one line** in **exactly** one of these forms:

  (FUNC; N[,M])   ← if it is a sink, where N, M are the 1-based parameter indices  
  (NO)            ← if it is not a sink  

**Do not** output anything else—no “Yes”/“No”, no repetition of the question, no explanations.

Here are some examples:

FUNCTION: system  
(system; 1)

FUNCTION: printf  
(printf; 1,2,3)

Now answer:

FUNCTION: {func_name}
        """
 
SOURCE_PROMPT_TEMPLATE = """
        As a program analyst, is it possible to use a call to {func_name} as a starting point (source) for taint analysis? 
        If the function can be used as a taint source, which parameter in the call stores the external input data. Please answer yes or no without additional explanation. 
        If yes, please indicate the corresponding parameters. For example, the recv function call can be used as a taint source, and the second parameter as a buffer stores the input data as (recv; 2).
        """
# Classification logic
def classify_cpu(prompt: str) -> dict:
    logger.info(f"Sending prompt to model: {prompt}")
    out = generator(prompt)[0]["generated_text"].strip()
    logger.info(f"Model output: {out}")

    # Parse only the last parentheses match in the generated text
    params = []
    is_true = False
    for line in reversed(out.splitlines()):
        m = re.search(r"\(([^;]+);\s*([\d,]+)\)", line)
        if m:
            params = [int(x) for x in m.group(2).split(",")]
            is_true = True
            break


    return {
        "is_true": is_true,
        "params": params,
        "answer": out
    }

app = FastAPI()

@app.post("/check")
def check(q: Q):
    logger.info(f"Received request: func={q.func}, mode={q.mode}")
    tmpl = SOURCE_PROMPT_TEMPLATE if q.mode == "source" else SINK_PROMPT_TEMPLATE
    prompt = tmpl.format(func_name=q.func)
    response = classify_cpu(prompt)
    logger.info(f"Returning response: {response}")
    return response

# CLI entrypoint
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "classify_cpu:app",
        host="127.0.0.1",
        port=8123,
        log_level="info"
    )
