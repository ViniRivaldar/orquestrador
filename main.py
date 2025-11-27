# main.py
from orquestrador import buscar_todos_logs
from normalizador import normalize_logs
import json

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

    # Mostra um preview
    print("\nExemplo de logs normalizados (até 3):")
    print(json.dumps(normalized[:3], indent=2, ensure_ascii=False))

    # Aqui seria o passo 3 e 4 futuramente:
    # - enviar ao Gemini
    # - salvar no banco
    # por enquanto, paramos aqui

if __name__ == "__main__":
    main()
