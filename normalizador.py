# normalizer.py
import json
import os
from typing import Any, Dict, List, Optional
from dotenv import load_dotenv

load_dotenv()

# Ajuste conforme necessário
MAX_BODY_CHARS = int(os.getenv("MAX_BODY_CHARS", "800"))  # truncamento para request_body
KEEP_HEADER_KEYS = {"user-agent", "x-forwarded-for", "referer", "content-type", "accept"}


def mask_email(email: Optional[str]) -> Optional[str]:
    if not email:
        return None
    if "@" not in email:
        return email
    user, domain = email.split("@", 1)
    if len(user) <= 1:
        masked = user + "***"
    else:
        masked = user[0] + "***"
    return f"{masked}@{domain}"


def redact_value(key: str, value: Any) -> Any:
    """
    Redige valores sensíveis por chave.
    - Se a chave indicar senha/token, substitui por <REDACTED>.
    - Caso contrário, retorna o valor simples (strings truncados quando muito longos).
    """
    if value is None:
        return None
    lower = key.lower()
    if any(s in lower for s in ("password", "passwd", "pwd", "token", "authorization", "secret", "api_key", "access_token")):
        return "<REDACTED>"
    # truncar strings muito longas
    if isinstance(value, str) and len(value) > MAX_BODY_CHARS:
        return value[:MAX_BODY_CHARS] + "…"
    return value


def reduce_headers(headers_raw: Any) -> Dict[str, Any]:
    """
    Recebe headers (dicionário ou string JSON) e mantém apenas chaves relevantes.
    Redige cookies/authorization se aparecerem.
    """
    if not headers_raw:
        return {}
    if isinstance(headers_raw, str):
        try:
            headers = json.loads(headers_raw)
        except Exception:
            return {}
    else:
        try:
            headers = dict(headers_raw)
        except Exception:
            headers = {}

    out = {}
    for k, v in headers.items():
        if k.lower() in KEEP_HEADER_KEYS:
            # se por acaso for auth-like, redige
            if "authorization" in k.lower() or "cookie" in k.lower():
                out[k] = "<REDACTED>"
            else:
                out[k] = v
    return out


def summarize_request_body(body_raw: Any) -> Any:
    """
    Tenta transformar o request_body em um resumo:
    - se dict: redige keys sensíveis e retorna dict reduzido
    - se list: retorna len + primeira entrada resumida
    - se string: tenta parsear JSON, senão trunca string
    """
    if body_raw is None:
        return None

    # parse if it's a JSON string
    parsed = body_raw
    if isinstance(body_raw, str):
        try:
            parsed = json.loads(body_raw)
        except Exception:
            parsed = body_raw

    if isinstance(parsed, dict):
        small = {}
        for k, v in parsed.items():
            small[k] = redact_value(k, v)
        return small
    if isinstance(parsed, list):
        out = {"len": len(parsed)}
        if parsed:
            out["first"] = summarize_request_body(parsed[0])
        return out
    # fallback: scalar -> string truncated
    txt = str(parsed)
    return txt[:MAX_BODY_CHARS] + ("…" if len(txt) > MAX_BODY_CHARS else "")


def normalize_event(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Produz um evento minimalista e seguro a partir do raw.
    Campos mantidos: id, timestamp, action, status, email_masked, ip, user_agent,
    headers (reduzido), request_body_summary, response_time, db_query_time, user_exists, threats (if small).
    """
    ev = {}
    ev["id"] = raw.get("id")
    ev["timestamp"] = raw.get("timestamp")
    ev["action"] = raw.get("action")
    ev["status"] = raw.get("status")
    ev["email_masked"] = mask_email(raw.get("email"))
    ev["ip"] = raw.get("ip")
    ev["user_agent"] = raw.get("user_agent")
    ev["headers"] = reduce_headers(raw.get("headers"))
    ev["request_body_summary"] = summarize_request_body(raw.get("request_body"))
    # preserve threats if present (assumed small JSON)
    threats = raw.get("threats")
    ev["threats"] = threats if (threats is None or isinstance(threats, (dict, list))) else None
    ev["response_time"] = raw.get("response_time")
    ev["db_query_time"] = raw.get("db_query_time")
    ev["user_exists"] = raw.get("user_exists")
    return ev


def normalize_logs(raw_logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Normalize a list of raw logs. Skips items without id."""
    out = []
    for r in raw_logs:
        if not isinstance(r, dict):
            continue
        if r.get("id") is None:
            # skip bad entries
            continue
        n = normalize_event(r)
        out.append(n)
    return out


# Quick demo when run directly
if __name__ == "__main__":
    import sys
    try:
        data = json.load(sys.stdin)
    except Exception:
        print("Provide JSON array on stdin.", file=sys.stderr)
        sys.exit(1)
    norm = normalize_logs(data)
    print(json.dumps(norm, ensure_ascii=False, indent=2))
