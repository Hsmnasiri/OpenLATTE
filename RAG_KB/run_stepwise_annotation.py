# run_stepwise_annotation.py
import os, re, json, argparse, pathlib
from llm_clients import LLMClient

META_KBID = re.compile(r'^\s*-\s*kb_id:\s*(.+)\s*$')

def split_items(text: str):
    # items separated by lines starting with "# item N"
    items = []
    cur = []
    for line in text.splitlines():
        if line.strip().startswith("# item "):
            if cur: items.append("\n".join(cur).strip())
            cur = []
            continue
        cur.append(line)
    if cur: items.append("\n".join(cur).strip())
    return items

def extract_kbid(prompt: str):
    for ln in prompt.splitlines():
        m = META_KBID.match(ln)
        if m:
            return m.group(1).strip()
    return None

def run(prompts_path: str, out_jsonl: str, backend: str, temperature: float, max_tokens: int):
    with open(prompts_path, "r") as f:
        txt = f.read()
    items = split_items(txt)
    cli = LLMClient(backend)

    out_lines = []
    for i, p in enumerate(items, 1):
        kbid = extract_kbid(p)
        if not kbid:
            # skip silently to be robust
            continue
        ans = cli.generate(p, temperature=temperature, max_tokens=max_tokens)
        rec = {
            "kb_id": kbid,
            "prompt": p,
            "answer": ans["text"],
            "model": ans["model"],
            "backend": ans["backend"],
            "ts": ans["ts"]
        }
        out_lines.append(json.dumps(rec, ensure_ascii=False))
        print(f"[{i}/{len(items)}] {kbid} ✓")

    pathlib.Path(os.path.dirname(out_jsonl)).mkdir(parents=True, exist_ok=True)
    with open(out_jsonl, "w") as f:
        f.write("\n".join(out_lines) + ("\n" if out_lines else ""))

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--prompts", required=True)
    ap.add_argument("--out_jsonl", required=True)
    ap.add_argument("--backend", default="gemini", choices=["gemini","local"])
    ap.add_argument("--temperature", type=float, default=0.2)
    ap.add_argument("--max_tokens", type=int, default=400)
    args = ap.parse_args()
    run(args.prompts, args.out_jsonl, args.backend, args.temperature, args.max_tokens)
