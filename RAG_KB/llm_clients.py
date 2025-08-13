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
            self.key = os.environ.get("GOOGLE_API_KEY42", "gemini-2.5-pro")
            self.genai.configure(api_key=self.key)

        elif self.backend == "local":
            import requests  # pip install requests
            self.requests = requests
            self.model = os.environ.get("LOCAL_MODEL", "local-llm")
            self.url = os.environ.get("LOCAL_URL", "http://127.0.0.1:8000/generate")

        else:
            raise ValueError("Unsupported backend. Use: gemini | local")

    # Increase max_tokens and make the response handling more robust
    def generate(self, prompt: str, temperature: float = 0.2, max_tokens: int = 2048) -> Dict[str, Any]:
        ts = int(time.time())
        if self.backend == "openai":
            raise NotImplementedError("OpenAI backend is not implemented in this client.")
        
        if self.backend == "gemini":
            model = self.genai.GenerativeModel(self.model)
            # Configure generation to have a higher token limit
            generation_config = self.genai.types.GenerationConfig(
                max_output_tokens=max_tokens,
                temperature=temperature
            )
            resp = model.generate_content(prompt, generation_config=generation_config)
            
            # Safer way to access response text
            text = ""
            try:
                if resp.parts:
                    text = "".join(part.text for part in resp.parts if hasattr(part, 'text'))
                else: # Fallback for safety
                    text = resp.text
            except (ValueError, IndexError):
                print(f"[WARN] Could not access response text directly. Finish reason: {resp.candidates[0].finish_reason if resp.candidates else 'N/A'}")
                text = "" # Return empty string on failure

            return {"text": text, "model": self.model, "backend": "gemini", "ts": ts}

        if self.backend == "local":
            r = self.requests.post(self.url, json={"model": self.model, "prompt": prompt, "temperature": temperature, "max_tokens": max_tokens}, timeout=120)
            r.raise_for_status()
            data = r.json()
            return {"text": data.get("text",""), "model": self.model, "backend": "local", "ts": ts}

        raise RuntimeError("unreachable")