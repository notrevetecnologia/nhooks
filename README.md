<div align="center">

<img src="logo.svg" alt="NHooks" width="96" height="96" />

# NHooks

**Receba, inspecione e depure webhooks em segundos — self-hosted, open source e com IA.**

Um único binário em **Go**. URLs de ingestão **amigáveis**, painel ao vivo e IA opcional (bring-your-own-key).

`open source` · `MIT` · `Go` · `SQLite` (ou PostgreSQL) · `Docker ready` · `IA opcional`

</div>

---

## ✨ Por que usar?

Webhook receivers de terceiros funcionam, mas o NHooks deixa você no controle: roda **no seu servidor**,
os dados ficam **com você** e não existem limites impostos por outra empresa. Feito para testar callbacks,
integrações PIX, ERPs, CRMs, SaaS e automações.

E o melhor: **deploy de 1 arquivo.** `./nhooks` e pronto.

## 🚀 Principais recursos

- **URLs amigáveis**: `/hook/pix-teste-8F3k2a`.
- **Recebe qualquer método**: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`.
- **Painel ao vivo** por token administrativo, com polling e detalhes em modal.
- **Link de compartilhamento** somente leitura (`/share/{key}`).
- Visualização de **headers, body raw/JSON, query string, IP, content-type e método**.
- **Exportação** em JSON e CSV.
- **Limites por painel** (volume e eventos) e **retenção automática**.
- **Criptografia em repouso** do body raw/JSON (AES-256-GCM, opcional via `.env`).
- **HMAC-SHA256** opcional para validar a origem (`X-Nhooks-Signature-256`).
- **IA inclusa** — resumos, anomalias e mocks com a *sua* chave.
- **Rate limiting** (memória por padrão, **Redis** no modo escala).
- Publicação opcional de notificações `event.received` via **RabbitMQ**.

## 🏗️ Arquitetura

É um único processo Go:

```txt
HTTP
 ├─ /hook/{slug}   → ingestão (HMAC opcional, rate limit, idempotência, limites) → 202
 ├─ /api           → JSON (list_events, event_detail, ai_insight, export...)
 └─ / (UI)         → dashboard-first + /dash/{key} + /share/{key} + /admin
        │
        └─ Store (interface) → SQLite embutido (padrão) | PostgreSQL (DB_DRIVER)
```

## 🧭 Rotas principais

```txt
/                         abre o dashboard (cria seu link administrativo na 1ª visita)
/dash/{admin}             entra no painel com um token administrativo
/share/{shareKey}         painel somente leitura
/hook/{slug}              rota amigável de ingestão
/health                   healthcheck
/api?action=...           endpoints JSON do painel
```

## 📦 Instalação

### Docker (mais simples)

```bash
cp .env.example .env
docker compose up -d --build
# -> http://localhost:8080
```

Modo **escala** (Redis + PostgreSQL opcionais):

```bash
docker compose --profile scale up -d
```

### Binário direto (Go)

```bash
# build
go build -o nhooks ./cmd/nhooks
# roda
AI_ENABLED=true AI_API_KEY=sk-sua-chave ./nhooks
```

Pré-requisito: **Go 1.26+** para buildar (o binário final roda em qualquer sistema, sem dependências).

### PostgreSQL opcional

```env
DB_DRIVER=postgres
DB_DSN=host=127.0.0.1 port=5432 dbname=nhooks user=nhooks password=nhooks sslmode=disable
```

## ⚙️ Configuração (`.env`)

| Grupo | Variáveis |
|-------|-----------|
| **Servidor** | `LISTEN_ADDR`, `PUBLIC_URL` |
| **Banco** | `DB_DRIVER` (sqlite\|postgres), `DB_PATH` (sqlite) ou `DB_DSN` (postgres) |
| **Identidade** | `BRAND_NAME`, `BRAND_COLOR`, `BRAND_LOGO_URL`, `APP_TITLE`, `APP_DESCRIPTION`, `APP_THEME`, `COMPANY_URL` |
| **Rotas** | `APP_INGEST_ROUTE` (default `hook`), `APP_POLLING_MS`, `DASHBOARD_EVENTS_LIMIT` |
| **Limites/Retenção** | `EVENT_RETENTION_HOURS`, `USER_STORAGE_LIMIT`, `USER_EVENTS_LIMIT` |
| **Criptografia** | `EVENT_ENCRYPTION_ENABLED`, `EVENT_ENCRYPTION_KEY` |
| **Redis (opcional)** | `REDIS_ENABLED`, `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD`, `REDIS_DB` |
| **RabbitMQ (opcional)** | `AMQP_ENABLED`, `AMQP_URL`, `AMQP_QUEUE` |
| **IA** | `AI_ENABLED`, `AI_API_KEY`, `AI_MODEL`, `AI_BASE_URL`, `AI_KEYS_URL`, `AI_APP_NAME` |
| **Admin** | `SYSTEM_ADMIN_KEY` |

Defaults e parse em `internal/config`.

## 🤖 IA (bring-your-own-key)

A IA já vem embutida: **resumo em linguagem natural**, **detecção de anomalias** e **sugestões**.
Cada usuário pode usar a própria chave, salva somente no navegador e enviada ao servidor apenas durante
a análise. A chave nunca é ecoada na resposta. Também é possível configurar uma chave padrão no servidor:

```env
AI_ENABLED=true
AI_API_KEY=sk-sua-chave
AI_MODEL=notreve-v1-lite
AI_BASE_URL=https://api.ia.notreve.com.br
AI_KEYS_URL=https://ia.notreve.com.br
AI_APP_NAME=IA
```

Sem chave a ferramenta segue 100% funcional — só a IA fica desativada. Houve ainda proteção: chamada de IA
somente via `POST`, com rate limit por usuário e sem retorno da chave.

## 🔒 Segurança e privacidade

- Body raw/JSON **criptografado** em repouso (AES-256-GCM) quando `EVENT_ENCRYPTION_ENABLED=true` e uma chave válida está configurada.
- **Retenção automática** conforme `EVENT_RETENTION_HOURS`.
- **HMAC-SHA256** opcional por endpoint; quando um segredo é configurado, `X-Nhooks-Signature-256` é obrigatório.
- Chave compartilhada da IA fica no servidor; chaves individuais ficam no navegador e são usadas server-side durante a análise.
- Nenhuma credencial no código — tudo via `.env`.

## 📄 Licença

**MIT** — veja [`LICENSE`](LICENSE). Faça fork, adapte, use à vontade.

## 🤝 Autores

Criado e mantido pela **Notreve** — [notreve.com.br](https://notreve.com.br).
IA: [ia.notreve.com.br](https://ia.notreve.com.br).
