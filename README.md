# ItensNotSuported-Analyser

Ferramenta para identificar itens Zabbix em estado não suportado (falhas de coleta) e gerar relatórios analíticos em múltiplos formatos.

## Descrição

O script consulta a API do Zabbix e produz três tipos de relatório:

- **unsupported** (padrão) — lista todos os itens ativos em estado não suportado, com host, tipo de coleta e mensagem de erro.
- **masters** — mapeia itens de coleta master (Script, HTTP Agent, SSH, etc.) nos templates e verifica se cada um possui uma trigger `nodata()` configurada (cobertura de alerta).
- **priorities** — agrupa as falhas por padrão de erro normalizado e as ordena por impacto (ranking Pareto), indicando o que resolver primeiro.

Suporta saída em tabela (terminal), CSV, JSON e Excel (.xlsx), além de um painel web interativo via Flask.

## Pré-requisitos

- Python 3.8+
- Acesso à API do Zabbix (token ou usuário/senha)

## Instalação

```bash
# 1. Crie e ative o ambiente virtual
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate

# 2. Instale as dependências
pip install -r requirements.txt

# 3. Configure as credenciais
cp .env.example .env
# Edite o .env com a URL e credenciais do seu Zabbix
```

## Configuração (.env)

| Variável | Obrigatória | Descrição |
|---|---|---|
| `ZABBIX_URL` | Sim | URL base do Zabbix (ex: `https://zabbix.empresa.com`) |
| `ZABBIX_TOKEN` | Prefere | Token de API do Zabbix (recomendado) |
| `ZABBIX_USER` | Alternativa | Usuário (se não usar token) |
| `ZABBIX_PASSWORD` | Alternativa | Senha (se não usar token) |
| `CACHE_TTL` | Não | Tempo de cache em segundos para o modo `--serve` (padrão: `300`) |
| `COLLECTION_KEYWORDS` | Não | Palavras-chave adicionais separadas por vírgula (padrão: `nodata,no data,not supported,unsupported`) |

## Uso

### Relatório de itens não suportados (padrão)

```bash
python main.py
```

### Escolher tipo de relatório

```bash
python main.py --report unsupported   # itens em estado não suportado (padrão)
python main.py --report masters       # cobertura de alertas nodata() nas coletas master
python main.py --report priorities    # ordem de resolução por impacto (Pareto)
```

### Escolher formato de saída

```bash
python main.py --format table                              # tabela no terminal (padrão)
python main.py --format csv    --output relatorio.csv
python main.py --format json   --output relatorio.json
python main.py --format excel  --output relatorio.xlsx
```

### Filtrar por período

```bash
python main.py --days 7    # apenas problemas dos últimos 7 dias
```

### Palavras-chave customizadas

```bash
python main.py --keywords "timeout,connection refused"
```

### Painel web interativo

```bash
python main.py --serve              # acesse http://localhost:5000
python main.py --serve --port 8080  # porta customizada
```

O painel expõe os três relatórios com exportação para Excel diretamente pelo navegador.

## Estrutura

```
.
├── main.py          — ponto de entrada e toda a lógica de coleta/geração
├── templates/
│   └── index.html   — frontend do painel web (--serve)
├── requirements.txt — dependências Python
└── .env.example     — modelo de configuração
```

## Licença

MIT
