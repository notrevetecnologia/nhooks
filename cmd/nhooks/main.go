// NHooks — recebedor de webhooks self-hosted, open source, escrito em Go.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/notrevetecnologia/nhooks/internal/ai"
	"github.com/notrevetecnologia/nhooks/internal/api"
	"github.com/notrevetecnologia/nhooks/internal/async"
	"github.com/notrevetecnologia/nhooks/internal/config"
	"github.com/notrevetecnologia/nhooks/internal/domain"
	"github.com/notrevetecnologia/nhooks/internal/ingest"
	"github.com/notrevetecnologia/nhooks/internal/ratelimit"
	"github.com/notrevetecnologia/nhooks/internal/store"
	"github.com/notrevetecnologia/nhooks/internal/web"
)

func main() {
	cfg := config.Load(".env")
	log.SetFlags(log.LstdFlags)
	log.Printf("NHooks: DB=%s", cfg.DBDriver)

	dst, err := store.Open(cfg)
	if err != nil {
		log.Fatalf("erro ao abrir banco: %v", err)
	}
	defer dst.Close()

	// Reter se removido por retenção
	_ = dst.MetaSet("version", "go-1")

	// Rate limiter (Redis opcional, memória padrão)
	lim, err := newLimiter(cfg)
	if err != nil {
		log.Fatalf("erro no rate limiter: %v", err)
	}
	defer lim.Close()

	// Worker AMQP opcional
	wk, err := async.New(cfg.AMQPURL, cfg.AMQPQueue, cfg.AMQPEnabled && cfg.AMQPURL != "")
	if err != nil {
		log.Printf("aviso AMQP desativado: %v", err)
		wk, _ = async.New("", "", false)
	}
	defer wk.Close()

	// Criação de URL amigável p/ cada endpoint novo já é feita na API.
	_ = cfg

	aiclient := ai.New(cfg.AIKey, cfg.AIBaseURL, cfg.AIModel, cfg.AIAppName)
	maxEvents := 0
	if cfg.EventsLimitEnabled {
		maxEvents = cfg.EventsLimit
	}
	maxStorage := int64(0)
	if cfg.StorageLimitEnabled {
		maxStorage = cfg.StorageLimitBytes
	}
	ing := ingest.New(dst, lim, ingest.IngestConfig{
		MaxEventsPerEp:  maxEvents,
		MaxStorageBytes: maxStorage,
		OnEvent: func(ctx context.Context, ev *domain.Event) error {
			return wk.Publish(ctx, async.Job{Kind: "event.received", Event: ev.ID, Token: ev.EndpointToken, RunAt: time.Now()})
		},
	})
	apih := api.New(dst, aiclient, cfg)
	webr := web.New(dst, cfg)

	mux := http.NewServeMux()
	mux.Handle("/api", apih)
	mux.Handle("/api/", apih)

	// Rotas úteis (sempre ativas), sem conflito:
	//  - /hook/{slug} -> ingestão por slug amigável
	//  - /in(+ ?token=) -> ingestão por token (legado)
	mux.HandleFunc("/hook/", func(w http.ResponseWriter, r *http.Request) {
		slug := strings.Trim(strings.TrimPrefix(r.URL.Path, "/hook/"), "/")
		if slug == "" {
			http.NotFound(w, r)
			return
		}
		ep, err := dst.EndpointBySlug(slug)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		ing.Serve(w, r, ep)
	})
	mux.HandleFunc("/in/", func(w http.ResponseWriter, r *http.Request) {
		token := strings.Trim(strings.TrimPrefix(r.URL.Path, "/in/"), "/")
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		serveByToken(w, r, dst, ing, token)
	})
	mux.HandleFunc("/in", func(w http.ResponseWriter, r *http.Request) {
		serveByToken(w, r, dst, ing, r.URL.Query().Get("token"))
	})

	// Rota configurável de ingestão (ex.: APP_INGEST_ROUTE=receive -> /receive/{slug}).
	if r := "/" + strings.Trim(cfg.IngestRoute, "/") + "/"; r != "/hook/" {
		mux.HandleFunc(r, func(w http.ResponseWriter, rq *http.Request) {
			slug := strings.Trim(strings.TrimPrefix(rq.URL.Path, r), "/")
			ep, err := dst.EndpointBySlug(slug)
			if err != nil {
				http.NotFound(w, rq)
				return
			}
			ing.Serve(w, rq, ep)
		})
	}

	// healthcheck
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	// UI (dashboard-first) em /, /dash/{key}, /share/{key}, /admin
	mux.Handle("/", webr)

	// Limpeza por retenção (worker em background)
	go retentionLoop(dst, cfg.RetentionHours)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	go func() {
		log.Printf("NHooks ouvindo em %s — painel em %s/", cfg.ListenAddr, strings.TrimRight(cfg.PublicURL, "/"))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("http: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Println("encerrando...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

func serveByToken(w http.ResponseWriter, r *http.Request, dst *store.Store, ing *ingest.Handler, token string) {
	ep, err := dst.EndpointByToken(token)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ing.Serve(w, r, ep)
}

func newLimiter(cfg config.Config) (ratelimit.Limiter, error) {
	if cfg.RedisEnabled {
		l, err := ratelimit.NewRedis(cfg.RedisHost, cfg.RedisPort, cfg.RedisPassword, cfg.RedisDB, ratelimit.Config{Limit: 60, Window: time.Minute})
		if err == nil {
			log.Printf("rate limit: redis em %s:%d", cfg.RedisHost, cfg.RedisPort)
			return l, nil
		}
		if cfg.RedisRequired {
			return nil, err
		}
		log.Printf("aviso: redis indisponível (%v); usando memória", err)
	}
	return ratelimit.NewMemory(ratelimit.Config{Limit: 60, Window: time.Minute}), nil
}

func retentionLoop(dst *store.Store, hours int) {
	if hours <= 0 {
		return
	}
	for {
		time.Sleep(30 * time.Minute)
		if n, err := dst.RetentionRemove(hours); err == nil && n > 0 {
			log.Printf("retenção: removidos %d eventos", n)
		}
	}
}
