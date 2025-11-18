# Phishing Guard – Ferramenta de Detecção de Phishing

Ferramenta completa de análise de URLs para detecção de phishing, implementando heurísticas avançadas e interface web interativa. Atende aos requisitos dos **Conceitos C e B** da prova final.

## 🎯 Funcionalidades Implementadas

### Conceito C (Requisitos Básicos)
- ✅ **Verificação em listas de phishing conhecidas** (Phishing Database, listas públicas)
- ✅ **Detecção de características suspeitas:**
  - Números substituindo letras no domínio (ex: `paypa1.com`)
  - Uso excessivo de subdomínios
  - Presença de caracteres especiais na URL
- ✅ **Interface web simples** com tabela de resultados e indicadores visuais (verde/vermelho)

### Conceito B (Requisitos Avançados)
- ✅ **Análise heurística completa:**
  - Verificação em listas de phishing (cache dinâmico)
  - Análise de idade do domínio via WHOIS
  - Detecção de DNS dinâmico (no-ip, dyndns, etc.)
  - Análise de certificados SSL (emissor, expiração, correspondência)
  - Detecção de redirecionamentos suspeitos
  - Similaridade com marcas conhecidas (distância de Levenshtein)
  - Análise de conteúdo HTML (formulários de login, palavras sensíveis)
- ✅ **Dashboard interativo:**
  - Visualização detalhada dos resultados
  - Histórico de URLs verificadas
  - Exportação para CSV
  - Gráficos de distribuição de risco
  - Explicações educativas sobre cada heurística

## 📁 Estrutura do Projeto

```
Prova-Final-TechHack/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py          # API FastAPI
│   │   ├── analyzer.py      # Lógica de análise
│   │   ├── config.py        # Configurações e listas
│   │   ├── models.py        # Modelos Pydantic
│   │   └── history.py       # Gerenciamento de histórico
│   └── requirements.txt     # Dependências Python
├── frontend/
│   └── index.html           # Dashboard web
├── data/
│   └── history.json         # Histórico persistido
└── README.md
```

## 🚀 Como Executar

### 1. Configurar o Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # No Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

O servidor estará rodando em `http://127.0.0.1:8000`

### 2. Abrir o Dashboard

**Opção 1:** Abrir diretamente no navegador
```bash
# Navegue até a pasta frontend e abra index.html
```

**Opção 2:** Servir com servidor HTTP (recomendado)
```bash
# Na raiz do projeto
python -m http.server 9000 -d frontend
# Acesse http://127.0.0.1:9000
```

### 3. Testar a API

```bash
# Exemplo com curl
curl -X POST "http://127.0.0.1:8000/analyze" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.github.com"}'
```

## 📡 Endpoints da API

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| `POST` | `/analyze` | Analisa uma URL e retorna relatório completo com todas as heurísticas |
| `GET` | `/history` | Retorna histórico de todas as análises realizadas |
| `GET` | `/history/export` | Exporta histórico em formato CSV |
| `GET` | `/health` | Verificação de saúde da API |

## 🔍 Heurísticas Implementadas

1. **Listas de Phishing**: Verifica domínios em bases de dados públicas
2. **Padrões do Domínio**: Detecta números, subdomínios excessivos, caracteres especiais
3. **DNS Dinâmico**: Identifica provedores de DNS dinâmico (suspeitos)
4. **Idade do Domínio**: Domínios muito novos (< 180 dias) são suspeitos
5. **Redirecionamentos**: Múltiplos redirecionamentos podem indicar ocultação
6. **Formulários Sensíveis**: Detecta formulários de login (coleta de credenciais)
7. **Palavras Sensíveis**: Identifica frases comuns em phishing ("verify your account", etc.)
8. **Certificado SSL**: Valida emissor, expiração e correspondência com domínio
9. **Similaridade com Marcas**: Usa Levenshtein para detectar typosquatting

## 📊 Níveis de Risco

- **BAIXO** (verde): Score ≥ 20 - URL parece segura
- **MÉDIO** (amarelo): Score entre -10 e 19 - Características suspeitas presentes
- **ALTO** (vermelho): Score ≤ -10 - Múltiplos indicadores de phishing

## 🛠️ Tecnologias Utilizadas

- **Backend**: FastAPI, Python 3.10+
- **Frontend**: HTML5, JavaScript (Vanilla), Chart.js, Pico CSS
- **Bibliotecas**: httpx, beautifulsoup4, python-whois, python-Levenshtein, dnspython


## ⚠️ Notas Importantes

- A primeira análise pode demorar alguns segundos enquanto baixa as listas de phishing
- Algumas verificações (WHOIS, SSL) podem falhar para domínios inacessíveis
- O histórico é persistido em `data/history.json`
- URLs de phishing reais não devem ser acessadas - use apenas para teste da ferramenta

## 📚 Documentação Adicional

Cada heurística na interface inclui explicações sobre:
- O que está sendo verificado
- Por que representa um risco
- Como ajuda na detecção de phishing

## 🔒 Segurança

- Não acesse URLs suspeitas diretamente
- Use apenas para análise e teste
- As listas de phishing são atualizadas dinamicamente