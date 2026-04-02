## 🔍 LeakHunter

LeakHunter é uma ferramenta de automação de reconhecimento e análise de exposição de dados sensíveis, desenvolvida para otimizar processos de Bug Bounty e Pentest.

Diferente de ferramentas focadas apenas em enumeração, o LeakHunter executa um pipeline completo:
coleta de URLs, download de artefatos, análise de conteúdo e detecção de credenciais expostas.

---

## ⚙️ Principais funcionalidades

###  Coleta de superfície de ataque
- Integração com **gau** e **waybackurls**
- Fallback via **Wayback Machine CDX API**
- Filtragem inteligente de endpoints relevantes

###  Download e processamento
- Download paralelo com controle de threads, timeout e tamanho
- Separação automática de arquivos potencialmente sensíveis
- Extração de arquivos compactados (.zip, .tar, .gz)

###  Engine de análise
Detecção baseada em regex para:
- API Keys (AWS, Google, Stripe, etc.)
- Tokens (JWT, Bearer, GitHub, Slack, etc.)
- Credenciais hardcoded
- Connection strings
- Arquivos sensíveis (.env, .sql, .pem, etc.)
- Padrões de vulnerabilidade (open redirect, debug artifacts, etc.)

###  Análises adicionais
- Parsing de `robots.txt` com validação ativa de endpoints
- Identificação de endpoints potencialmente restritos/expostos

###  Alertas e priorização
- Classificação por severidade: low, medium, high, critical
- Alertas em tempo real durante a execução

###  Relatórios
- JSON (automação)
- TXT (leitura rápida)
- HTML (visual)

---

##  Uso

```bash
python3 leakhunter.py exemplo.com
