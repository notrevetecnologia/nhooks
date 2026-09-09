// Package domain define os tipos centrais do NHooks.
package domain

import (
	"encoding/json"
	"time"
)

// Endpoint é uma URL de ingestão (um "gancho").
type Endpoint struct {
	Token        string    `json:"token"`         // chave única da URL (idempotência)
	Slug         string    `json:"slug"`          // alias amigável (ex: pix-teste-8F3k2a)
	Name         string    `json:"name"`          // nome dado pelo usuário
	AdminKey     string    `json:"admin_key"`     // dono do endpoint
	ShareKey     string    `json:"share_key"`     // chave de compartilhamento (somente leitura)
	Secret       string    `json:"secret"`        // segredo para validar HMAC (vazio = sem validação)
	HMACRequired bool      `json:"hmac_required"` // assinatura obrigatória para este endpoint
	CreatedAt    time.Time `json:"created_at"`
	LastEventAt  int64     `json:"last_event_at"` // unix
}

// Event é uma requisição HTTP recebida por um endpoint.
type Event struct {
	ID            string          `json:"id"`
	EndpointToken string          `json:"endpoint_token"`
	Method        string          `json:"method"`
	Path          string          `json:"uri"`
	IP            string          `json:"ip"`
	ContentType   string          `json:"content_type"`
	Query         map[string]any  `json:"query,omitempty"`
	Post          map[string]any  `json:"post,omitempty"`
	Headers       map[string]any  `json:"headers,omitempty"`
	Body          string          `json:"body_raw"`
	BodyJSON      json.RawMessage `json:"body_json,omitempty"`
	Size          int             `json:"body_size"`
	ReceivedAt    int64           `json:"received_at"` // unix
}

// Summary gera um curto resumo textual do evento (para listagem/exibição).
func (e Event) Summary() string {
	s := e.Method + " " + e.Path
	if e.BodyJSON != nil && len(e.BodyJSON) > 0 {
		s += " · " + bodyPreview(e.BodyJSON)
	} else if e.Body != "" {
		s += " · " + bodyPreview([]byte(e.Body))
	}
	return s
}

// BodyJSONOrBody devolve o corpo em JSON (se parseável) ou o texto bruto, para a IA.
func (e Event) BodyJSONOrBody() any {
	if len(e.BodyJSON) > 0 {
		var v any
		if json.Unmarshal(e.BodyJSON, &v) == nil {
			return v
		}
		return e.Body
	}
	if json.Valid([]byte(e.Body)) {
		var v any
		if json.Unmarshal([]byte(e.Body), &v) == nil {
			return v
		}
	}
	return e.Body
}

func bodyPreview(b []byte) string {
	if len(b) > 120 {
		return string(b[:120]) + "…"
	}
	return string(b)
}

// JSONView é o formato enviado à API/dashboard (sem dados técnicos internos).
func (e Event) JSONView() map[string]any {
	return map[string]any{
		"id":             e.ID,
		"method":         e.Method,
		"endpoint_token": e.EndpointToken,
		"uri":            e.Path,
		"ip":             e.IP,
		"content_type":   e.ContentType,
		"query":          e.Query,
		"post":           e.Post,
		"headers":        e.Headers,
		"body_json":      e.BodyJSON,
		"body_raw":       e.Body,
		"body_size":      e.Size,
		"received_at":    datetime(e.ReceivedAt),
		"summary":        e.Summary(),
	}
}

func datetime(unix int64) string {
	return time.Unix(unix, 0).Format("02/01/2006 15:04:05")
}
