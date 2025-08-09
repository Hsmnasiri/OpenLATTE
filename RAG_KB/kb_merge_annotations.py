# kb_merge_annotations.py
import json, argparse, pathlib

def load_jsonl(path):
    data = {}
    with open(path, "r") as f:
        for line in f:
            line=line.strip()
            if not line: continue
            d = json.loads(line)
            k = d.get("kb_id")
            if k: data[k] = d
    return data

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--flowcards", required=True)
    ap.add_argument("--semantics_jsonl", required=True)
    ap.add_argument("--rootcause_jsonl", required=True)
    ap.add_argument("--fix_jsonl", required=True)
    ap.add_argument("--out_jsonl", required=True)
    args = ap.parse_args()

    # load base flow-cards
    base = []
    with open(args.flowcards, "r") as f:
        for line in f:
            line=line.strip()
            if line:
                base.append(json.loads(line))

    sem = load_jsonl(args.semantics_jsonl)
    root = load_jsonl(args.rootcause_jsonl)
    fix = load_jsonl(args.fix_jsonl)

    out_lines = []
    for card in base:
        kbid = card["kb_id"]
        card["annotation_semantics"] = sem.get(kbid, {}).get("answer", "")
        card["annotation_rootcause"] = root.get(kbid, {}).get("answer", "")
        card["annotation_fix"] = fix.get(kbid, {}).get("answer", "")
        card["annotation_meta"] = {
            "semantics_model": sem.get(kbid, {}).get("model"),
            "rootcause_model": root.get(kbid, {}).get("model"),
            "fix_model": fix.get(kbid, {}).get("model"),
        }
        out_lines.append(json.dumps(card, ensure_ascii=False))

    pathlib.Path(str(pathlib.Path(args.out_jsonl).parent)).mkdir(parents=True, exist_ok=True)
    with open(args.out_jsonl, "w") as f:
        f.write("\n".join(out_lines) + ("\n" if out_lines else ""))

    print(f"[DONE] KB ready → {args.out_jsonl} ({len(out_lines)} items)")

if __name__ == "__main__":
    main()
