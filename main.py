# main.py
from orquestrador import buscar_todos_logs
from normalizador import normalize_logs
from gemini_module import analyze_logs_with_gemini
from saver_module import salvar_analise_no_banco
import json

INSTRUCTIONS = """
You are a senior SOC analyst specialized in authentication security. Analyze each event and return a JSON object with:
id, mitre_matches (array of {tactic, technique_id, technique_name, rationale}),
threat_score (0-100 int), confidence (0.0-1.0 float), detection_rule (short string),
recommended_actions (array[string]), priority (low|medium|high), notes (optional).

SCORING GUIDELINES (cumulative):
Base: 0 (innocent until proven guilty)

CRITICAL THREATS (40-50 points each):
- Known malicious IPs (threat intel match): +50
- SQL injection patterns in payload: +45
- Command injection attempts: +45
- Authentication bypass attempts: +40

HIGH SEVERITY (20-35 points):
- Multiple failed logins (5+ in 5 min) from same IP: +30
- Credential stuffing patterns (different users, same IP): +30
- Suspicious payload encoding (base64, hex with shell commands): +25
- Impossible travel (geo-location anomaly): +25
- Password spraying (same password, multiple users): +25

MEDIUM SEVERITY (10-20 points):
- Unusual response times (>5x normal AND failed): +15
- Uncommon user-agent for the service context: +10
- Access outside business hours (if pattern exists): +10
- Missing or suspicious headers: +10
- Failed login from same IP after recent success: +20
- Automation tool with mixed success/fail pattern: +15

LOW SEVERITY (5 points):
- Single failed login: +5
- Slightly elevated db_query_time: +5

CONTEXT RULES:
1. Automation tools (curl, wget, python-requests) are NEUTRAL by default
   - BUT add +10 if used with: failed logins, injection patterns, or unusual payloads
   
2. Consider temporal patterns across events:
   - Same IP with mixed success/fail is MORE suspicious
   - Rapid sequential attempts indicate automation/attack
   
3. Successful logins are LOW priority UNLESS:
   - From previously failed IP within 10 minutes (+15)
   - Unusual geo-location or timing (+10)
   - Followed suspicious failed attempts (+20)

4. Response/DB time anomalies are suspicious ONLY when:
   - Combined with failed status
   - OR 10x+ slower than baseline
   
5. Empty or minimal request bodies in authentication are SUSPICIOUS (+15)

MITRE ATT&CK MAPPING:
- Brute Force → T1110.001 (Password Guessing)
- Credential Stuffing → T1110.004 (Credential Stuffing)
- SQL Injection → T1190 (Exploit Public-Facing Application)
- Multiple IPs, same target → T1110.003 (Password Spraying)
- Automation tools with attack patterns → T1059 (Command and Scripting Interpreter)
- Failed login after successful registration → T1110.001 (Password Guessing - testing credentials)
- Same IP rapid sequence (register→login→fail) → T1078 (Valid Accounts - account testing)

PRIORITY ASSIGNMENT:
- LOW: threat_score 0-30 (normal operations, minor anomalies)
- MEDIUM: threat_score 31-60 (suspicious patterns, needs monitoring)
- HIGH: threat_score 61-100 (clear attack indicators, immediate action)

RECOMMENDED ACTIONS EXAMPLES:
- For brute force: ["Rate-limit IP", "Enable MFA", "Alert user", "Temporary IP block"]
- For injection: ["Block IP immediately", "Review WAF rules", "Check for data exfiltration", "Patch validation"]
- For anomalies: ["Monitor user activity", "Verify with user", "Check for account compromise"]
- For low-score events: [] (empty array, no action needed)

OUTPUT REQUIREMENTS:
- Be precise: only flag real threats with high scores
- Set confidence <0.5 for ambiguous cases
- Provide actionable recommendations, not generic advice
- Use notes to explain your reasoning for scores >50

Return ONLY a valid JSON array.
"""

def main():
    print("\n=== ETAPA 1: Buscar logs crus ===")
    raw_logs = buscar_todos_logs()

    if not raw_logs:
        print("Nenhum log encontrado. Encerrando.")
        return

    print(f"Total de logs crus: {len(raw_logs)}")
    print("\n=== ETAPA 2: Normalizar logs ===")
    normalized = normalize_logs(raw_logs)

    print(f"Total de logs normalizados: {len(normalized)}")

    print("=== ETAPA 3: Enviar para Gemini (análise) ===")
    analysis = analyze_logs_with_gemini(INSTRUCTIONS, normalized, batch_size=20)
    print(f"Análises retornadas: {len(analysis)}")
    salvar_analise_no_banco(analysis)

if __name__ == "__main__":
    main()
