import psycopg2
import json
import os

DATABASE_URL = os.getenv("DATABASE_URL")

def salvar_analise_no_banco(analises):
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()

    for a in analises:
        cur.execute("""
            INSERT INTO audit_analysis (
                log_id,
                threat_score,
                confidence,
                detection_rule,
                priority,
                mitre_matches,
                recommended_actions,
                notes
            ) VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s)
        """, (
            a.get("id"),
            a.get("threat_score"),
            a.get("confidence"),
            a.get("detection_rule"),
            a.get("priority"),
            json.dumps(a.get("mitre_matches")),
            json.dumps(a.get("recommended_actions")),
            a.get("notes")
        ))

    conn.commit()
    cur.close()
    conn.close()

    print("✓ Análises salvas no banco!")
