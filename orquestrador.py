import os
import requests
from dotenv import load_dotenv

load_dotenv()

# Configuração
API_URL = os.getenv("ENDPOINT")

def buscar_todos_logs():
    """
    Busca TODOS os logs da API (sem limit)
    
    Returns:
        lista com todos os logs
    """
    try:
        print(f"🔄 Buscando logs")
        response = requests.get(API_URL, timeout=60)
        response.raise_for_status()
        logs = response.json()
        
        print(f"✓ Buscados {len(logs)} logs com sucesso!")
        return logs
        
    except Exception as e:
        print(f"✗ Erro ao buscar logs: {e}")
        return []


if __name__ == "__main__":
    # Busca TODOS os logs
    meus_logs = buscar_todos_logs()
    
    # Mostra resumo
    print(f"\n📋 Total de logs: {len(meus_logs)}")
    
    if meus_logs:
        print("\n🔍logs:")
        for log in meus_logs[:3]:
            print(f"  - {log}")