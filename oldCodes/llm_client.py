import requests

LLM_ENDPOINT = "http://localhost:8080/v1/chat/completions" 
HEADERS = {"Content-Type": "application/json"}

def query_llm_conversational(messages: list, temperature=0.5):
    """Sends a conversational history to the LLM endpoint."""
    payload = {
        "model": "local-model",
        "messages": messages, # Pass the entire conversation
        "temperature": temperature,
        "max_tokens": 1024 # Increased for final analysis
    }
    
    try:
        response = requests.post(LLM_ENDPOINT, headers=HEADERS, json=payload)
        response.raise_for_status()
        return response.json()['choices'][0]['message']['content']
    except requests.exceptions.RequestException as e:
        print(f"LLM request failed: {e}")
        return None