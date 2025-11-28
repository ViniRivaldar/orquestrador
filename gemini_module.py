# gemini_module.py
import os
import json
import time
from typing import List, Dict, Any, Optional
from google import genai

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash-001")  # ✅ Corrigido
BATCH_SIZE_DEFAULT = int(os.getenv("GEMINI_BATCH_SIZE", "20"))
MAX_RETRIES = 3
RETRY_BACKOFF = 2

if GEMINI_API_KEY:
    client = genai.Client(api_key=GEMINI_API_KEY)
else:
    client = None

def _build_prompt(instructions: str, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    events_json = json.dumps(events, ensure_ascii=False, indent=2)
    user_text = (
        instructions
        + "\n\nEVENTS_JSON:\n"
        + events_json
        + "\n\nReturn ONLY a JSON array of analysis objects for each event. "
        "Each object must include at least: id, threat_score, confidence."
    )
    return [{"role": "user", "parts": [{"text": user_text}]}]

def _call_model(contents: List[Dict[str, Any]], model: Optional[str] = None, timeout: int = 60) -> str:
    if client is None:
        raise RuntimeError("GEMINI_API_KEY not set in environment variables")
    
    used_model = model or GEMINI_MODEL
    
    try:
        resp = client.models.generate_content(
            model=used_model,
            contents=contents,
            config={"response_mime_type": "application/json"}  # ✅ Corrigido: 'config' ao invés de 'generation_config'
        )
        return resp.text
    except Exception as e:
        raise RuntimeError(f"Error calling Gemini API with model {used_model}: {str(e)}")

def analyze_logs_with_gemini(
    instructions: str, 
    normalized_events: List[Dict[str, Any]], 
    batch_size: int = BATCH_SIZE_DEFAULT
) -> List[Dict[str, Any]]:
    """
    Chunk normalized_events and call Gemini for each chunk.
    Returns concatenated list of analysis objects.
    """
    if not normalized_events:
        return []
    
    results: List[Dict[str, Any]] = []
    total = len(normalized_events)
    
    for i in range(0, total, batch_size):
        chunk = normalized_events[i:i+batch_size]
        contents = _build_prompt(instructions, chunk)
        
        last_exc = None
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                raw_text = _call_model(contents)
                parsed = json.loads(raw_text)
                
                if not isinstance(parsed, list):
                    raise ValueError(f"Gemini returned non-list JSON: {type(parsed)}")
                
                # Validação básica
                for item in parsed:
                    if "id" not in item:
                        raise ValueError(f"Analysis item missing 'id' field: {item}")
                
                results.extend(parsed)
                break  # Sucesso, sai do loop de retry
                
            except json.JSONDecodeError as e:
                last_exc = RuntimeError(f"Invalid JSON from Gemini: {e}")
            except Exception as e:
                last_exc = e
            
            if attempt == MAX_RETRIES:
                raise RuntimeError(
                    f"Failed after {MAX_RETRIES} attempts. Last error: {last_exc}"
                )
            
            # Backoff exponencial
            time.sleep(RETRY_BACKOFF ** (attempt - 1))
    
    return results