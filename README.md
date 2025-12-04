# Orquestrador de Análise de Logs de Segurança

Sistema automatizado de análise de logs de auditoria usando IA (Google Gemini) para detecção de ameaças e correlação com MITRE ATT&CK.

## 📋 Sobre o Projeto

Este orquestrador consome logs de auditoria de uma API externa, normaliza os dados removendo informações sensíveis, envia para análise via Google Gemini AI e salva os resultados estruturados em PostgreSQL. É projetado para equipes SOC (Security Operations Center) que precisam de análise automatizada e inteligente de eventos de segurança.

## 🏗️ Arquitetura

```
┌─────────────────┐
│   Audit Logs    │
│      API        │
└────────┬────────┘
         │ 1. Fetch logs
         │
┌────────▼────────┐
│  Orquestrador   │
│  (orquestrador) │
└────────┬────────┘
         │ 2. Raw logs
         │
┌────────▼────────┐
│  Normalizador   │
│  • Redact PII   │
│  • Mask emails  │
│  • Truncate     │
└────────┬────────┘
         │ 3. Normalized logs
         │
┌────────▼────────┐
│  Gemini AI      │
│  • Threat score │
│  • MITRE map    │
│  • Priority     │
└────────┬────────┘
         │ 4. Analysis
         │
┌────────▼────────┐
│   PostgreSQL    │
│ audit_analysis  │
└─────────────────┘
```

## 🚀 Funcionalidades

### 🔄 Pipeline Automatizado
1. **Coleta**: Busca logs da API de auditoria
2. **Normalização**: Remove dados sensíveis (senhas, tokens, PII)
3. **Análise IA**: Detecção de ameaças com scoring 0-100
4. **Persistência**: Salva análises estruturadas no banco

### 🛡️ Análise de Segurança
- **Threat Scoring**: Pontuação de 0-100 para cada evento
- **MITRE ATT&CK Mapping**: Correlação automática com táticas e técnicas
- **Priorização**: LOW/MEDIUM/HIGH baseado em severidade
- **Ações Recomendadas**: Sugestões contextuais de resposta

### 🔐 Privacidade e Compliance
- Mascaramento de emails (user → u***)
- Redação automática de senhas/tokens
- Truncamento de payloads grandes
- Sanitização de headers sensíveis

## 📦 Instalação

### Pré-requisitos

- Python 3.10+
- PostgreSQL com tabelas `audit_logs` e `audit_analysis`
- API Key do Google Gemini ([obter aqui](https://aistudio.google.com/apikey))
- Acesso à API de Audit Logs

### Passos

1. **Clone o repositório:**
```bash
git clone <url-do-repositorio>
cd orquestrador
```

2. **Crie ambiente virtual:**
```bash
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# ou
.venv\Scripts\activate  # Windows
```

3. **Instale dependências:**
```bash
pip install -r requirements.txt
```

4. **Configure variáveis de ambiente:**
```bash
cp .env.example .env
```

Edite o arquivo `.env`:
```env
# API de origem dos logs
ENDPOINT=http://localhost:8000/audit_logs

# Google Gemini
GEMINI_API_KEY=sua-chave-aqui
GEMINI_MODEL=gemini-2.0-flash-001
GEMINI_BATCH_SIZE=20

# PostgreSQL
DATABASE_URL=postgresql://usuario:senha@localhost:5432/nome_do_banco

# Normalizador (opcional)
MAX_BODY_CHARS=800
```

## 🗄️ Estrutura do Banco de Dados

### Tabela `audit_analysis`

```sql
CREATE TABLE audit_analysis (
    id SERIAL PRIMARY KEY,
    log_id INTEGER NOT NULL REFERENCES audit_logs(id),
    threat_score INTEGER CHECK (threat_score BETWEEN 0 AND 100),
    confidence DECIMAL(3,2) CHECK (confidence BETWEEN 0 AND 1),
    detection_rule VARCHAR(255),
    priority VARCHAR(20) CHECK (priority IN ('low', 'medium', 'high')),
    mitre_matches JSONB,
    recommended_actions JSONB,
    notes TEXT,
    analyzed_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(log_id)
);

CREATE INDEX idx_audit_analysis_priority ON audit_analysis(priority);
CREATE INDEX idx_audit_analysis_threat_score ON audit_analysis(threat_score DESC);
CREATE INDEX idx_audit_analysis_log_id ON audit_analysis(log_id);
```

### Exemplo de registro

```json
{
  "log_id": 1234,
  "threat_score": 75,
  "confidence": 0.92,
  "detection_rule": "Brute Force - Multiple Failed Logins",
  "priority": "high",
  "mitre_matches": [
    {
      "tactic": "Credential Access",
      "technique_id": "T1110.001",
      "technique_name": "Password Guessing",
      "rationale": "15 failed login attempts in 2 minutes"
    }
  ],
  "recommended_actions": [
    "Rate-limit IP immediately",
    "Enable MFA for affected account",
    "Alert user of suspicious activity"
  ],
  "notes": "IP 203.0.113.42 showed credential stuffing pattern"
}
```

## 🎯 Uso

### Executar análise completa

```bash
python main.py
```

**Saída esperada:**
```
=== ETAPA 1: Buscar logs crus ===
🔄 Buscando logs
✓ Buscados 1500 logs com sucesso!
Total de logs crus: 1500

=== ETAPA 2: Normalizar logs ===
Total de logs normalizados: 1500

=== ETAPA 3: Enviar para Gemini (análise) ===
Análises retornadas: 1500
✓ Análises salvas no banco!
```

### Testar módulos individuais

**Buscar logs:**
```bash
python orquestrador.py
```

**Normalizar logs:**
```bash
echo '[{"id":1,"email":"user@example.com","password":"secret"}]' | python normalizador.py
```

**Testar Gemini (requer logs normalizados):**
```bash
python -c "from gemini_module import analyze_logs_with_gemini; print('Gemini OK')"
```

## 📊 Scoring de Ameaças

### Matriz de Pontuação

| Categoria | Pontos | Exemplos |
|-----------|--------|----------|
| **CRÍTICO** | 40-50 | SQL injection, command injection, IPs maliciosos conhecidos |
| **ALTO** | 20-35 | Múltiplas tentativas falhas, credential stuffing, impossible travel |
| **MÉDIO** | 10-20 | User-agents suspeitos, horários incomuns, headers ausentes |
| **BAIXO** | 5 | Login falho único, query time elevado |

### Priorização

- **LOW** (0-30): Operações normais, anomalias menores
- **MEDIUM** (31-60): Padrões suspeitos, monitoramento necessário
- **HIGH** (61-100): Ataques claros, ação imediata

## 🔧 Módulos

### `orquestrador.py`
Busca logs da API externa via HTTP GET.

**Principais funções:**
- `buscar_todos_logs()`: Retorna lista de logs brutos

### `normalizador.py`
Sanitiza e reduz dados sensíveis antes do envio para IA.

**Principais funções:**
- `normalize_logs(raw_logs)`: Processa lista de logs
- `mask_email(email)`: Mascara endereços de email
- `redact_value(key, value)`: Redige senhas/tokens
- `summarize_request_body(body)`: Resume payloads grandes

**Campos preservados:**
- `id`, `timestamp`, `action`, `status`
- `email_masked` (não o original)
- `ip`, `user_agent`
- `headers` (apenas chaves seguras)
- `request_body_summary` (reduzido e redacted)
- `threats`, `response_time`, `db_query_time`, `user_exists`

### `gemini_module.py`
Interface com Google Gemini AI para análise de segurança.

**Principais funções:**
- `analyze_logs_with_gemini(instructions, normalized_events, batch_size)`: Analisa logs em lotes
- `_call_model(contents, model, timeout)`: Chama API do Gemini
- `_build_prompt(instructions, events)`: Constrói prompt para IA

**Recursos:**
- Batching automático (padrão: 20 logs por request)
- Retry com backoff exponencial (3 tentativas)
- Validação de resposta JSON
- Timeout configurável

### `saver_module.py`
Persiste análises no PostgreSQL.

**Principais funções:**
- `salvar_analise_no_banco(analises)`: Insere análises na tabela `audit_analysis`

**Campos salvos:**
- `log_id`, `threat_score`, `confidence`
- `detection_rule`, `priority`
- `mitre_matches` (JSONB)
- `recommended_actions` (JSONB)
- `notes`

## ⚙️ Configuração Avançada

### Ajustar Batch Size

Para APIs com rate limits ou memória limitada:
```env
GEMINI_BATCH_SIZE=10  # menor = mais chamadas, menos memória
```

### Customizar Normalização

Edite `normalizador.py`:
```python
# Aumentar truncamento de payloads
MAX_BODY_CHARS = 1500

# Adicionar headers permitidos
KEEP_HEADER_KEYS = {
    "user-agent", 
    "x-forwarded-for", 
    "referer",
    "x-real-ip"  # adicionar este
}
```

### Modificar Instruções de Análise

Edite `INSTRUCTIONS` em `main.py` para ajustar:
- Critérios de scoring
- Mapeamento MITRE
- Regras de priorização
- Formato de saída

## 🔒 Segurança

### Boas Práticas

✅ **Implementadas:**
- Redação automática de credenciais
- Mascaramento de PII (emails)
- Validação de JSON responses
- Timeout em requests HTTP

⚠️ **Recomendações adicionais:**
- Use HTTPS para `ENDPOINT`
- Armazene `GEMINI_API_KEY` em secret manager
- Configure PostgreSQL com SSL: `DATABASE_URL=...?sslmode=require`
- Limite permissões do usuário do banco (somente INSERT em `audit_analysis`)
- Implemente rate limiting no orquestrador
- Adicione logging estruturado (ex: com `structlog`)

## 📈 Monitoramento

### Métricas importantes

- **Taxa de sucesso**: % de logs analisados com sucesso
- **Latência Gemini**: Tempo médio de resposta da IA
- **Threat score distribution**: Histograma de scores 0-100
- **Prioridades geradas**: Contagem por LOW/MEDIUM/HIGH
- **Erros de API**: Taxa de retry/falhas

### Logs de erro

```python
# Adicionar em main.py para logging
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Usar no código
logger.error(f"Falha ao processar log {log_id}: {e}")
```

## 🚀 Deploy

### Com Docker

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Instalar dependências do sistema
RUN apt-get update && apt-get install -y \
    libpq-dev gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "main.py"]
```

### Com Cron (execução periódica)

```bash
# Executar a cada 15 minutos
*/15 * * * * cd /caminho/orquestrador && /caminho/.venv/bin/python main.py >> /var/log/orquestrador.log 2>&1
```

### Como serviço systemd

```ini
[Unit]
Description=Orquestrador de Análise de Logs
After=network.target postgresql.service

[Service]
Type=simple
User=orquestrador
WorkingDirectory=/opt/orquestrador
Environment="PATH=/opt/orquestrador/.venv/bin"
ExecStart=/opt/orquestrador/.venv/bin/python main.py
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

## 🛠️ Tecnologias

- **Python 3.10+**: Linguagem principal
- **Google Gemini AI**: Análise de ameaças com LLM
- **psycopg2**: Driver PostgreSQL
- **requests**: Cliente HTTP
- **python-dotenv**: Gerenciamento de variáveis de ambiente

## 📁 Estrutura do Projeto

```
orquestrador/
├── .gitignore
├── .env.example
├── README.md
├── requirements.txt
├── main.py              # Orquestrador principal
├── orquestrador.py      # Busca logs da API
├── normalizador.py      # Sanitização e normalização
├── gemini_module.py     # Interface com Gemini AI
└── saver_module.py      # Persistência no PostgreSQL
```

## 🐛 Troubleshooting

### Erro: "GEMINI_API_KEY not set"
```bash
# Verifique se o .env está correto
cat .env | grep GEMINI_API_KEY

# Exporte manualmente para testar
export GEMINI_API_KEY="sua-chave-aqui"
python main.py
```

### Erro: "Invalid JSON from Gemini"
- Verifique se `GEMINI_MODEL` está correto
- Reduza `GEMINI_BATCH_SIZE` (ex: de 20 para 10)
- Simplifique `INSTRUCTIONS` em `main.py`

### Erro: Connection refused (PostgreSQL)
```bash
# Teste conexão manual
psql "$DATABASE_URL"

# Verifique se PostgreSQL está rodando
sudo systemctl status postgresql
```

### Logs não aparecem
- Verifique se `ENDPOINT` está acessível:
  ```bash
  curl http://localhost:8000/audit_logs
  ```
- Confirme que a API retorna JSON array

## 🤝 Contribuindo

Contribuições são bem-vindas! Áreas de melhoria:

- [ ] Suporte a múltiplas fontes de logs
- [ ] Dashboard web para visualização de análises
- [ ] Alertas em tempo real (webhook, email, Slack)
- [ ] Enriquecimento com threat intelligence externa
- [ ] Suporte a outros LLMs (OpenAI, Anthropic Claude)
- [ ] Testes unitários e integração

## 📝 Licença

Este projeto está sob a licença MIT.

---

**⚠️ Aviso Legal**: Este sistema é para fins educacionais e de segurança defensiva. Não use para atividades maliciosas ou não autorizadas. Sempre tenha permissão explícita antes de analisar logs de sistemas.
