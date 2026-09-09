// Package views gera os trechos de HTML do painel (listas, linhas de evento, paginação)
// mantendo as mesmas classes/estrutura da UI original para reaproveitar a folha de estilo.
package views

import (
	"encoding/json"
	"html"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/notrevetecnologia/nhooks/internal/domain"
)

// Esc escapa HTML (anti-XSS).
func Esc(s string) string { return html.EscapeString(s) }

// FmtBytes formata bytes em B/KB/MB/GB.
func FmtBytes(b int64) string {
	if b <= 0 {
		return "0 B"
	}
	units := []string{"B", "KB", "MB", "GB", "TB"}
	i := 0
	f := float64(b)
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	return strconv.FormatFloat(f, 'f', 1, 64) + " " + units[i]
}

// PayloadType classifica o corpo do evento (JSON/XML/FORM/etc).
func PayloadType(ct string, bodyJSON bool, raw string, query map[string]any) string {
	ct = strings.ToLower(ct)
	if bodyJSON {
		return "JSON"
	}
	if strings.Contains(ct, "json") {
		return "JSON"
	}
	if strings.Contains(ct, "xml") {
		return "XML"
	}
	if strings.Contains(ct, "multipart") {
		return "MULTIPART"
	}
	if strings.Contains(ct, "x-www-form-urlencoded") {
		return "FORM"
	}
	if strings.Contains(ct, "text/") {
		return "TEXT"
	}
	if raw == "" && len(query) > 0 {
		return "QUERY"
	}
	return "RAW"
}

// DetectedSource tenta identificar o origem (Stripe, GitHub, Mercado Pago...).
func DetectedSource(headers map[string]any, userAgent string, ev any) string {
	content := strings.ToLower(mustJSON(ev))
	u := ""
	if userAgent != "" {
		u = strings.ToLower(userAgent)
	}
	checks := map[string][]string{
		"Stripe":       {"stripe-signature", "stripe"},
		"GitHub":       {"x-github-event", "github-hookshot", "github"},
		"Mercado Pago": {"mercadopago", "mercado_pago", "x-signature"},
		"Iugu":         {"iugu"},
		"Asaas":        {"asaas"},
		"Pagar.me":     {"pagarme", "pagar.me"},
		"N8N":          {"n8n"},
		"Typebot":      {"typebot"},
		"WhatsApp":     {"whatsapp", "waba"},
	}
	for label, needles := range checks {
		for _, n := range needles {
			if strings.Contains(content, n) || strings.Contains(u, n) {
				return label
			}
		}
	}
	return ""
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// EventSummary compõe um resumo de texto do evento.
func EventSummary(e *domain.Event) string {
	var txt strings.Builder
	if len(e.BodyJSON) > 0 {
		txt.Write(e.BodyJSON)
	}
	if txt.Len() == 0 && e.Body != "" {
		txt.WriteString(e.Body)
	}
	if txt.Len() == 0 && len(e.Query) > 0 {
		txt.WriteString(mustJSON(e.Query))
	}
	s := strings.TrimSpace(strings.Join(strings.Fields(txt.String()), " "))
	s = cut(s, 240)
	if s == "" {
		return "Sem body. Verifique query string, headers ou metodo usado."
	}
	return s
}

func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for len(s) > n {
		_, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
	}
	return s + "…"
}

// EventRowHTML produz o <article> de um evento (mesmas classes da UI original).
func EventRowHTML(id, method, summary, endpointName, receivedAt, ip string, size int64, payloadType, source string, allowDelete bool) string {
	methodClass := "get"
	for _, r := range method {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			methodClass = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(method), " ", ""))
			break
		}
	}
	shortID := id
	if runes := []rune(id); len(runes) > 24 {
		shortID = string(runes[:24])
	}
	src := ""
	if source != "" {
		src = `<span class="badge source-badge">Detectado: ` + Esc(source) + `</span>`
	}
	deleteButton := ""
	if allowDelete {
		deleteButton = `<button class="btn small danger ghost" onclick="askDeleteEvent('` + Esc(id) + `')">Excluir</button>`
	}
	return `<article class="event-row" id="row-` + Esc(id) + `" data-event-id="` + Esc(id) + `">
  <div class="event-main">
    <div class="event-top">
      <span class="badge method-` + Esc(methodClass) + `">` + Esc(method) + `</span>
      <span class="badge type-badge">` + Esc(payloadType) + `</span>
      ` + src + `
      <strong>` + Esc(endpointName) + `</strong>
      <small>` + Esc(receivedAt) + `</small>
    </div>
    <p>` + Esc(summary) + `</p>
    <div class="event-meta">
      <span>IP: ` + Esc(ip) + `</span>
      <span>Tamanho: ` + Esc(FmtBytes(size)) + `</span>
      <span>Tipo: ` + Esc(payloadType) + `</span>
      <span>ID: ` + Esc(shortID) + `</span>
    </div>
  </div>
  <div class="event-actions">
    <button class="btn small" onclick="openEvent('` + Esc(id) + `')">Detalhes</button>
    <button class="btn small ghost" onclick="quickCopyEvent('` + Esc(id) + `','body')">Copiar body</button>
    ` + deleteButton + `
  </div>
</article>`
}

// EventsListHTML gera a lista de eventos (ou o estado vazio).
type EventItem struct {
	ID, Method, EndpointName, ReceivedAt, IP, Summary, Source string
	Size                                                      int64
	PayloadType                                               string
	AllowDelete                                               bool
}

// EventsListHTML monta a lista completa.
func EventsListHTML(items []EventItem) string {
	if len(items) == 0 {
		return `<div class="empty">Nenhum evento encontrado.</div>`
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, EventRowHTML(it.ID, it.Method, it.Summary, it.EndpointName, it.ReceivedAt, it.IP, it.Size, it.PayloadType, it.Source, it.AllowDelete))
	}
	return strings.Join(out, "\n")
}

// PaginationHTML gera os controles de paginação.
func PaginationHTML(page, totalPages int, base url.Values) string {
	if totalPages <= 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<div class="pagination">`)
	if page > 1 {
		p := clone(base)
		p.Set("page", strconv.Itoa(page-1))
		b.WriteString(`<a class="btn small page-link" href="?` + Esc(p.Encode()) + `">Anterior</a>`)
	}
	b.WriteString(`<span>Pagina ` + strconv.Itoa(page) + ` de ` + strconv.Itoa(totalPages) + `</span>`)
	if page < totalPages {
		p := clone(base)
		p.Set("page", strconv.Itoa(page+1))
		b.WriteString(`<a class="btn small page-link" href="?` + Esc(p.Encode()) + `">Proxima</a>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}

func clone(v url.Values) url.Values {
	c := url.Values{}
	for k, vs := range v {
		c[k] = append([]string(nil), vs...)
	}
	return c
}
