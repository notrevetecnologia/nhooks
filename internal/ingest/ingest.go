// Package ingest processa as requisições HTTP recebidas pelos endpoints.
package ingest

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/notrevetecnologia/nhooks/internal/domain"
	"github.com/notrevetecnologia/nhooks/internal/ratelimit"
	"github.com/notrevetecnologia/nhooks/internal/security"
	"github.com/notrevetecnologia/nhooks/internal/store"
)

// Handler recebe e registra eventos.
type Handler struct {
	store   *store.Store
	limiter ratelimit.Limiter
	cfg     IngestConfig
}

// IngestConfig reúne opções de ingestão.
type IngestConfig struct {
	MaxBodyBytes     int64
	MaxEventsPerEp   int
	MaxStorageBytes  int64
	IdempotencyHeads []string // headers usados p/ idempotência (ex: X-Nhooks-Id, X-Webhook-ID)
	OnEvent          func(context.Context, *domain.Event) error
}

// New cria um handler de ingestão.
func New(dst *store.Store, l ratelimit.Limiter, cfg IngestConfig) *Handler {
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 4 << 20 // 4MB
	}
	if len(cfg.IdempotencyHeads) == 0 {
		cfg.IdempotencyHeads = []string{"X-Nhooks-Id", "X-Webhook-ID", "X-Idempotency-Key"}
	}
	return &Handler{store: dst, limiter: l, cfg: cfg}
}

// Serve processa a requisição para o endpoint já resolvido.
func (h *Handler) Serve(w http.ResponseWriter, r *http.Request, ep *domain.Endpoint) {
	if !h.limiter.Allow(r.Context(), "ep:"+ep.Token) {
		respondJSON(w, http.StatusTooManyRequests, map[string]any{"success": false, "message": "Limite de requisições excedido."})
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, h.cfg.MaxBodyBytes+1))
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "Falha ao ler o corpo da requisição."})
		return
	}
	if int64(len(body)) > h.cfg.MaxBodyBytes {
		respondJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"success": false, "message": "Corpo da requisição excede o limite permitido."})
		return
	}

	if ep.HMACRequired {
		sig := r.Header.Get("X-Nhooks-Signature-256")
		if sig == "" || !security.HMACVerify([]byte(ep.Secret), body, sig) {
			respondJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "message": "Assinatura HMAC inválida ou ausente."})
			return
		}
	} else if ep.Secret != "" {
		if sig := r.Header.Get("X-Nhooks-Signature-256"); sig != "" && !security.HMACVerify([]byte(ep.Secret), body, sig) {
			respondJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "message": "Assinatura HMAC inválida."})
			return
		}
	}

	ev, err := h.capture(r, ep, body)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": err.Error()})
		return
	}
	created, reason, err := h.store.CreateEventWithinLimits(ev, firstIdem(r, h.cfg.IdempotencyHeads), h.cfg.MaxEventsPerEp, h.cfg.MaxStorageBytes)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "message": "Falha ao registrar evento."})
		return
	}
	if reason == "duplicate" {
		respondJSON(w, http.StatusOK, map[string]any{"success": true, "duplicate": true})
		return
	}
	if reason == "event_limit" {
		respondJSON(w, http.StatusTooManyRequests, map[string]any{"success": false, "message": "Limite de eventos atingido para este endpoint."})
		return
	}
	if reason == "storage_limit" {
		respondJSON(w, http.StatusInsufficientStorage, map[string]any{"success": false, "message": "Limite de armazenamento atingido."})
		return
	}
	if !created {
		respondJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "message": "Falha ao registrar evento."})
		return
	}
	h.store.TouchEndpoint(ep.Token)
	if h.cfg.OnEvent != nil {
		if err := h.cfg.OnEvent(r.Context(), ev); err != nil {
			log.Printf("falha ao publicar notificacao do evento %s: %v", ev.ID, err)
		}
	}

	// 202 Accepted, sem processar nada (ação rápida), com link do painel.
	respondJSON(w, http.StatusAccepted, map[string]any{
		"success": true,
		"id":      ev.ID,
		"ok":      true,
	})
}

// capture lê e estrutura o evento.
func (h *Handler) capture(r *http.Request, ep *domain.Endpoint, body []byte) (*domain.Event, error) {
	var bodyJSON []byte
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "json") {
		if json.Valid(body) {
			bodyJSON = append([]byte(nil), body...)
		}
	}
	ip := clientIP(r)
	now := time.Now().Unix()
	return &domain.Event{
		ID:            security.RandomHex(12),
		EndpointToken: ep.Token,
		Method:        r.Method,
		Path:          r.URL.Path,
		IP:            ip,
		ContentType:   ct,
		Query:         parseParams(r.URL.Query()),
		Post:          parsePost(body, ct),
		Headers:       headerMap(r.Header),
		Body:          string(body),
		BodyJSON:      bodyJSON,
		Size:          len(body),
		ReceivedAt:    now,
	}, nil
}

func parseParams(m map[string][]string) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		if len(v) == 1 {
			out[k] = v[0]
		} else {
			out[k] = v
		}
	}
	return out
}

func parsePost(body []byte, ct string) map[string]any {
	if strings.Contains(ct, "application/x-www-form-urlencoded") {
		form, err := url.ParseQuery(string(body))
		if err == nil {
			return parseParams(form)
		}
	}
	return nil
}

func headerMap(h http.Header) map[string]any {
	out := map[string]any{}
	for k, v := range h {
		if len(v) == 1 {
			out[k] = v[0]
		} else {
			out[k] = v
		}
	}
	return out
}

func firstIdem(r *http.Request, heads []string) string {
	for _, k := range heads {
		if v := strings.TrimSpace(r.Header.Get(k)); v != "" {
			return v
		}
	}
	return ""
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func respondJSON(w http.ResponseWriter, code int, payload map[string]any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}
