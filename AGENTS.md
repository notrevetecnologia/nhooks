# AGENTS.md

Informações factuais sobre o projeto **NHooks** (Go) para qualquer agente de IA ou novo dev.

## O que é

Receiver de webhooks self-hosted e open source (MIT). Gera URLs amigáveis de ingestão, recebe eventos
HTTP (`GET/POST/PUT/PATCH/DELETE`) e exibe headers, body raw/JSON, query, IP e método num painel em tempo
quase real. IA opcional (bring-your-own-key).

## Stack

- **Go 1.26+** — servidor HTTP único (`net/http`, stdlib), sem framework.
- **SQLite embutido** (padrão, `modernc.org/sqlite`, pure Go) ou **PostgreSQL** (`DB_DRIVER`).
- **Redis** opcional (rate limit) e **RabbitMQ** opcional (fila assíncrona) via `.env`.
- Assets da UI embutidos no binário (`go:embed`) — deploy de 1 arquivo.

## Estrutura

```txt
cmd/nhooks/main.go        entrypoint + roteamento
internal/config/          .env + defaults
internal/domain/          tipos Endpoint, Event
internal/store/           Store (interface) — SQLite | PostgreSQL
internal/ingest/          ingestão de eventos
internal/api/             JSON /api (list_events, event_detail, ai_insight...)
internal/ai/              agente de IA (BYOK)
internal/ratelimit/       Memory (padrão) | Redis
internal/async/           worker RabbitMQ (opcional)
internal/security/        tokens, slug, HMAC, AES-GCM
internal/web/             UI (dashboard-first) + go:embed root/
web/root/index.html       dashboard (HTML + JS que chama /api)
```

## Comandos

```bash
go build -o nhooks ./cmd/nhooks   # build binário
go run ./cmd/nhooks               # rodar (usa .env)
go vet ./... && go build ./...    # verificação
docker compose up -d --build      # subir via Docker
```

## Configuração chave (`.env`)

- Servidor: `LISTEN_ADDR`, `PUBLIC_URL`
- Banco: `DB_DRIVER=sqlite|postgres`, `DB_PATH` (sqlite), `DB_DSN` (postgres)
- Rotas: `APP_INGEST_ROUTE=hook` → `/hook/{slug}`
- Limites/Retenção: `EVENT_RETENTION_HOURS`, `USER_STORAGE_LIMIT`, `USER_EVENTS_LIMIT`
- Criptografia: `EVENT_ENCRYPTION_KEY`
- Redis (opcional): `REDIS_ENABLED`, `REDIS_HOST`, `REDIS_PORT`
- AMQP (opcional): `AMQP_ENABLED`, `AMQP_URL`
- IA (opcional): `AI_ENABLED`, `AI_API_KEY`, `AI_MODEL`, `AI_BASE_URL`, `AI_KEYS_URL`, `AI_APP_NAME`
- Admin: `SYSTEM_ADMIN_KEY`

## Convenções

- Um único processo binário; zero runtime externo.
- Config sempre via `internal/config` (`env`) com default — nunca hardcoded em outra camada.
- Respostas JSON do `/api`: `{"success":bool,"data":...}` ou `{"success":false,"message":"..."}`.
- Eventos: idempotência via header `X-Nhooks-Id`; ao configurar segredo HMAC, `X-Nhooks-Signature-256` torna-se obrigatório.
- A pasta `web/root` é embutida — alterações em UI exigem rebuild do binário.
- Sem credenciais/tokens reais; `.env` é gitignored.
