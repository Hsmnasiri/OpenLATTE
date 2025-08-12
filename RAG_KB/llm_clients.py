import os, time, json
from typing import Dict, Any, Optional
from dotenv import load_dotenv

load_dotenv()
class LLMClient:
    def __init__(self, backend: str):
        self.backend = backend.lower()

        if self.backend == "gemini":
            import google.generativeai as genai  # pip install google-generativeai
            self.genai = genai
            self.model = os.environ.get("GOOGLE_API_MODEL", "gemini-2.5-pro")
            self.key = os.environ.get("GOOGLE_API_KEY42","gemini-2.5-pro")
            self.genai.configure(api_key=self.key)

        elif self.backend == "local":
            import requests  # pip install requests
            self.requests = requests
            self.model = os.environ.get("LOCAL_MODEL", "local-llm")
            self.url = os.environ.get("LOCAL_URL", "http://127.0.0.1:8000/generate")

        else:
            raise ValueError("Unsupported backend. Use: gemini | local")

    def generate(self, prompt: str, temperature: float = 0.2, max_tokens: int = 400) -> Dict[str, Any]:
        ts = int(time.time())
        if self.backend == "openai":
            raise NotImplementedError("OpenAI backend is not implemented in this client.")
        if self.backend == "gemini":
            model = self.genai.GenerativeModel(self.model)
            resp = model.generate_content(prompt)
            text = resp.text or ""
            return {"text": text, "model": self.model, "backend": "gemini", "ts": ts}

        if self.backend == "local":
            r = self.requests.post(self.url, json={"model": self.model, "prompt": prompt, "temperature": temperature, "max_tokens": max_tokens}, timeout=120)
            r.raise_for_status()
            data = r.json()
            return {"text": data.get("text",""), "model": self.model, "backend": "local", "ts": ts}

        raise RuntimeError("unreachable")
