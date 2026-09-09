// Package api implementa os endpoints JSON consumidos pelo painel (front via fetch).
package api

import (
	"crypto/subtle"
	"encoding/csv"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/notrevetecnologia/nhooks/internal/ai"
	"github.com/notrevetecnologia/nhooks/internal/config"
	"github.com/notrevetecnologia/nhooks/internal/domain"
	"github.com/notrevetecnologia/nhooks/internal/ratelimit"
	"github.com/notrevetecnologia/nhooks/internal/security"
	"github.com/notrevetecnologia/nhooks/internal/store"
	"github.com/notrevetecnologia/nhooks/internal/views"
)

// Handler agrega as dependências da API.
type Handler struct {
	Store *store.Store
	AI    *ai.Client
	Cfg   config.Config
	Now   func() time.Time
	aiLim *ratelimit.Memory
}

// New cria o handler da API.
func New(dst *store.Store, client *ai.Client, cfg config.Config) *Handler {
	return &Handler{Store: dst, AI: client, Cfg: cfg, Now: func() time.Time { return time.Now() },
		aiLim: ratelimit.NewMemory(ratelimit.Config{Limit: 5, Window: time.Minute})}
}

// Access mode.
const (
	ModeNone  = "none"
	ModeAdmin = "admin"
	ModeShare = "share"
)

// Route despacha a ação.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("action")
	if action == "" && r.Method == http.MethodPost {
		_ = r.ParseForm()
		action = r.PostFormValue("action")
	}
	if action == "" {
		writeJSON(w, http.StatusBadRequest, failMsg("acao invalida."))
		return
	}
	if mutationAction(action) && r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, failMsg("metodo nao permitido."))
		return
	}
	mode, key := h.identify(r)
	switch action {
	case "list_events":
		h.listEvents(w, r, mode, key)
	case "bootstrap":
		h.bootstrap(w, r)
	case "event_detail":
		h.eventDetail(w, r, mode, key)
	case "create_endpoint":
		h.createEndpoint(w, r, mode, key)
	case "delete_endpoint":
		h.deleteEndpoint(w, r, mode, key)
	case "delete_event":
		h.deleteEvent(w, r, mode, key)
	case "clear_events":
		h.clearEvents(w, r, mode, key)
	case "export_events":
		h.exportEvents(w, r, mode, key)
	case "ai_insight":
		h.aiInsight(w, r, mode, key)
	case "ai_status":
		writeJSON(w, http.StatusOK, okData(h.aiStatus()))
	case "admin_stats":
		h.adminStats(w, r)
	case "admin_endpoints":
		h.adminEndpoints(w, r)
	case "admin_events":
		h.adminEvents(w, r)
	case "admin_admins":
		h.adminAdmins(w, r)
	case "admin_delete_endpoint":
		h.adminDeleteEndpoint(w, r)
	case "admin_delete_admin":
		h.adminDeleteAdmin(w, r)
	case "admin_event_detail":
		h.adminEventDetail(w, r)
	case "admin_delete_event":
		h.adminDeleteEvent(w, r)
	case "admin_clear_all":
		h.adminClearAll(w, r)
	case "admin_clear_retention":
		h.adminClearRetention(w, r)
	default:
		writeJSON(w, http.StatusBadRequest, failMsg("acao invalida."))
	}
}

// identify resolve o modo (admin ou share) a partir do cookie, query ou header de sessão.
func (h *Handler) identify(r *http.Request) (string, string) {
	if v := r.URL.Query().Get("share"); v != "" {
		if _, err := h.Store.SharedEndpoint(v); err == nil {
			return ModeShare, v
		}
	}
	if v := cookie(r, adminCookie); v != "" && h.Store.AdminExists(v) {
		return ModeAdmin, v
	}
	return ModeNone, ""
}

// ---------- actions ----------

func (h *Handler) listEvents(w http.ResponseWriter, r *http.Request, mode, key string) {
	if mode != ModeAdmin && mode != ModeShare {
		writeJSON(w, http.StatusForbidden, failMsg("nao autorizado."))
		return
	}
	q := r.URL.Query()
	token := q.Get("endpoint")
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	perPage := h.Cfg.DashboardEventsLimit
	if perPage <= 0 {
		perPage = 200
	}
	if v, e := strconv.Atoi(q.Get("per_page")); e == nil && v > 0 && v <= 500 {
		perPage = v
	}
	filter := store.EventFilter{
		Token: token, Query: q.Get("q"), Method: q.Get("method"), Order: q.Get("order"),
		Limit: perPage, Offset: (page - 1) * perPage,
	}
	var rows []store.EventRow
	var err error
	var eventsCount int64
	filteredCount := 0
	var bytes int64
	adminURL := ""
	if mode == ModeShare {
		filter.Token = ""
		rows, err = h.Store.EventsForShareFiltered(key, filter)
		if err == nil {
			filteredCount, err = h.Store.CountEventsForShare(key, filter)
		}
		eventsCount = int64(0)
		if ep, e := h.Store.SharedEndpoint(key); e == nil {
			eventsCount = int64(h.Store.EventCountForEndpoint(ep.Token))
		}
	} else {
		rows, err = h.Store.EventsForAdminFiltered(key, filter)
		if err == nil {
			filteredCount, err = h.Store.CountEventsForAdmin(key, filter)
		}
		eventsCount, bytes = h.Store.Quota(key)
		adminURL = adminLink(h.Cfg, key)
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, failMsg("falha ao listar eventos."))
		return
	}
	endpoints := []domain.Endpoint{}
	if mode == ModeShare {
		if ep, e := h.Store.SharedEndpoint(key); e == nil {
			endpoints = []domain.Endpoint{*ep}
		}
	} else {
		endpoints, _ = h.Store.EndpointsByAdmin(key)
	}

	// montar itens de lista (HTML) com as mesmas classes da UI original
	items := make([]views.EventItem, 0, len(rows))
	lastEvent := int64(0)
	methodCounts := map[string]int{}
	for _, er := range rows {
		view := er.Event.JSONView()
		summary := views.EventSummary(&er.Event)
		payload := views.PayloadType(er.ContentType, len(er.BodyJSON) > 0, er.Body, er.Query)
		source := views.DetectedSource(er.Headers, "", er.Event)
		items = append(items, views.EventItem{
			ID: er.ID, Method: er.Method, EndpointName: er.EndpointName, ReceivedAt: view["received_at"].(string),
			IP: er.IP, Summary: summary, Size: int64(er.Size), PayloadType: payload, Source: source,
			AllowDelete: mode == ModeAdmin,
		})
		methodCounts[er.Method]++
		if er.ReceivedAt > lastEvent {
			lastEvent = er.ReceivedAt
		}
	}
	eventsHTML := views.EventsListHTML(items)
	subtitle := strconv.Itoa(filteredCount) + " evento(s) encontrado(s) nos filtros atuais."
	totalPages := (filteredCount + perPage - 1) / perPage

	exp := strings.ToLower(q.Get("format"))
	if exp != "" {
		h.exportEvents(w, r, mode, key)
		return
	}

	// quota labels
	storageLabel := quotaStorageLabel(bytes, h.Cfg)
	eventsLabel := quotaEventsLabel(eventsCount, h.Cfg)

	writeJSON(w, http.StatusOK, okData(map[string]any{
		"fingerprint": fingerprint(rows),
		"stats": map[string]any{
			"total":         eventsCount,
			"filtered":      filteredCount,
			"endpoints":     len(endpoints),
			"volume":        views.FmtBytes(bytes),
			"storage_limit": storageLabel,
			"events_limit":  eventsLabel,
			"last_event":    lastEventTime(lastEvent),
			"method_counts": methodCounts,
		},
		"endpoints": endpointsView(endpoints, h.Cfg, mode == ModeShare),
		"admin_url": adminURL,
		"html": map[string]any{
			"events":          eventsHTML,
			"pagination":      paginationHTML(page, totalPages),
			"events_subtitle": subtitle,
		},
		"ai": h.aiStatus(),
	}))
}

func (h *Handler) bootstrap(w http.ResponseWriter, r *http.Request) {
	key := cookie(r, adminCookie)
	if len(key) != 40 || !isHex(key) {
		writeJSON(w, http.StatusForbidden, failMsg("sessao invalida."))
		return
	}
	ep := &domain.Endpoint{
		Token: security.RandomHex(16), Slug: "principal-" + security.Base62(4), Name: "Principal",
		AdminKey: key, ShareKey: security.RandomHex(12), CreatedAt: h.Now(),
	}
	if err := h.Store.EnsureAdminWithDefault(key, ep); err != nil {
		writeJSON(w, http.StatusInternalServerError, failMsg("falha ao iniciar painel."))
		return
	}
	writeJSON(w, http.StatusOK, okData(nil))
}

func lastEventTime(unix int64) string {
	if unix <= 0 {
		return "---"
	}
	return time.Unix(unix, 0).Format("02/01/2006 15:04:05")
}

func quotaStorageLabel(bytes int64, cfg config.Config) string {
	if !cfg.StorageLimitEnabled || cfg.StorageLimitBytes <= 0 {
		return "Ilimitado"
	}
	return views.FmtBytes(bytes) + " / " + views.FmtBytes(cfg.StorageLimitBytes)
}

func quotaEventsLabel(n int64, cfg config.Config) string {
	if !cfg.EventsLimitEnabled || cfg.EventsLimit <= 0 {
		return "Ilimitado"
	}
	return strconv.FormatInt(n, 10) + " / " + strconv.Itoa(cfg.EventsLimit)
}

func fingerprint(rows []store.EventRow) string {
	var b strings.Builder
	for _, er := range rows {
		b.WriteString(er.ID)
		b.WriteByte('|')
		b.WriteString(strconv.FormatInt(er.ReceivedAt, 10))
		b.WriteByte('|')
		b.WriteString(strconv.Itoa(er.Size))
		b.WriteByte(';')
	}
	return b.String()
}

func endpointsView(eps []domain.Endpoint, cfg config.Config, shared bool) []map[string]any {
	out := make([]map[string]any, 0, len(eps))
	for _, e := range eps {
		item := map[string]any{"slug": e.Slug, "name": e.Name, "url": ingestURL(cfg, e.Slug)}
		if !shared {
			item["token"] = e.Token
			item["share"] = shareLink(cfg, e.ShareKey)
		}
		out = append(out, item)
	}
	return out
}

func (h *Handler) eventDetail(w http.ResponseWriter, r *http.Request, mode, key string) {
	if mode == ModeNone {
		writeJSON(w, http.StatusForbidden, failMsg("nao autorizado."))
		return
	}
	id := r.URL.Query().Get("event_id")
	if id == "" {
		id = r.URL.Query().Get("id")
	}
	var ev *domain.Event
	var err error
	if mode == ModeShare {
		ev, err = h.Store.EventByIDForShare(key, id)
	} else {
		ev, err = h.Store.EventByIDForAdmin(key, id)
	}
	if err != nil {
		writeJSON(w, http.StatusNotFound, failMsg("evento nao encontrado."))
		return
	}
	v := ev.JSONView()
	if mode == ModeShare {
		delete(v, "endpoint_token")
	}
	v["payload_type"] = payloadType(ev)
	v["summary"] = ev.Summary()
	if ep, err := h.Store.EndpointByToken(ev.EndpointToken); err == nil {
		v["endpoint_name"] = ep.Name
		v["endpoint_slug"] = ep.Slug
	}
	writeJSON(w, http.StatusOK, okData(map[string]any{"event": v}))
}

func (h *Handler) createEndpoint(w http.ResponseWriter, r *http.Request, mode, key string) {
	if mode != ModeAdmin {
		writeJSON(w, http.StatusForbidden, failMsg("nao autorizado."))
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" || len([]rune(name)) > 100 {
		writeJSON(w, http.StatusUnprocessableEntity, failMsg("informe um nome entre 1 e 100 caracteres."))
		return
	}
	// gera slug amigável único
	base := security.Slugify(name)
	if base == "" {
		base = "endpoint"
	}
	slug := base + "-" + security.Base62(4)
	secret := strings.TrimSpace(r.PostFormValue("secret"))
	if len([]rune(secret)) > 200 {
		writeJSON(w, http.StatusUnprocessableEntity, failMsg("o segredo HMAC deve ter no maximo 200 caracteres."))
		return
	}
	ep := &domain.Endpoint{
		Token:        security.RandomHex(16),
		Slug:         slug,
		Name:         name,
		AdminKey:     key,
		ShareKey:     security.RandomHex(12),
		Secret:       secret,
		HMACRequired: secret != "",
		CreatedAt:    h.Now(),
	}
	if err := h.Store.CreateEndpoint(ep); err != nil {
		writeJSON(w, http.StatusInternalServerError, failMsg("falha ao criar URL."))
		return
	}
	writeJSON(w, http.StatusCreated, okData(map[string]any{
		"endpoint": map[string]any{"token": ep.Token, "slug": ep.Slug, "name": ep.Name}, "url": ingestURL(h.Cfg, ep.Slug),
		"admin_url": adminLink(h.Cfg, key), "share_url": shareLink(h.Cfg, ep.ShareKey),
	}))
}

func (h *Handler) deleteEndpoint(w http.ResponseWriter, r *http.Request, mode, key string) {
	if mode != ModeAdmin {
		writeJSON(w, http.StatusForbidden, failMsg("nao autorizado."))
		return
	}
	ok, err := h.Store.DeleteEndpoint(key, r.PostFormValue("token"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, failMsg("falha ao excluir URL."))
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, failMsg("URL nao encontrada."))
		return
	}
	writeJSON(w, http.StatusOK, okData(map[string]any{"deleted": ok}))
}

func (h *Handler) deleteEvent(w http.ResponseWriter, r *http.Request, mode, key string) {
	if mode != ModeAdmin {
		writeJSON(w, http.StatusForbidden, failMsg("nao autorizado."))
		return
	}
	ok, err := h.Store.DeleteEventForAdmin(key, r.PostFormValue("event_id"))
	if err != nil || !ok {
		writeJSON(w, http.StatusNotFound, failMsg("evento nao encontrado."))
		return
	}
	writeJSON(w, http.StatusOK, okData(map[string]any{"deleted": ok}))
}

func (h *Handler) clearEvents(w http.ResponseWriter, r *http.Request, mode, key string) {
	if mode != ModeAdmin {
		writeJSON(w, http.StatusForbidden, failMsg("nao autorizado."))
		return
	}
	token := r.PostFormValue("token")
	if token != "" && !h.Store.EndpointBelongsTo(key, token) {
		writeJSON(w, http.StatusNotFound, failMsg("URL nao encontrada."))
		return
	}
	n, err := h.Store.ClearEventsForAdmin(key, token)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, failMsg("falha ao limpar eventos."))
		return
	}
	writeJSON(w, http.StatusOK, okData(map[string]any{"deleted": n}))
}

func (h *Handler) exportEvents(w http.ResponseWriter, r *http.Request, mode, key string) {
	if mode != ModeAdmin {
		writeJSON(w, http.StatusForbidden, failMsg("nao autorizado."))
		return
	}
	token := r.URL.Query().Get("endpoint")
	rows, err := h.Store.EventsForAdmin(key, token, 5000, 0)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, failMsg("falha ao exportar."))
		return
	}
	if r.URL.Query().Get("format") == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="nhooks-events.csv"`)
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"id", "received_at", "method", "path", "ip", "body"})
		for _, er := range rows {
			_ = cw.Write([]string{csvSafe(er.ID), strconv.FormatInt(er.ReceivedAt, 10), csvSafe(er.Method), csvSafe(er.Path), csvSafe(er.IP), csvSafe(er.Body)})
		}
		cw.Flush()
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, er := range rows {
		out = append(out, er.Event.JSONView())
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="nhooks-events.json"`)
	_ = json.NewEncoder(w).Encode(map[string]any{"exported_at": time.Now().Format(time.RFC3339), "total": len(out), "events": out})
}

func (h *Handler) aiInsight(w http.ResponseWriter, r *http.Request, mode, key string) {
	if mode != ModeAdmin {
		writeJSON(w, http.StatusForbidden, failMsg("nao autorizado."))
		return
	}
	if !h.Cfg.AIEnabled {
		writeJSON(w, http.StatusNotFound, failMsg("IA desativada."))
		return
	}
	// Rate limit por usuário — evita abuso/custo.
	if !h.aiLim.Allow(r.Context(), "ai:"+key) {
		writeJSON(w, http.StatusTooManyRequests, failMsg("limite de analise de IA atingido. Tente em breve."))
		return
	}
	clientKey := strings.TrimSpace(r.PostFormValue("ai_key"))
	if !h.AI.HasKey(clientKey) {
		writeJSON(w, http.StatusBadRequest, failMsg("configure a chave da IA para usar. Sem chave, sem insights."))
		return
	}
	id := r.PostFormValue("event_id")
	model := h.Cfg.AIModel
	var ev *domain.Event
	var err error
	ev, err = h.Store.EventByIDForAdmin(key, id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, failMsg("evento nao encontrado."))
		return
	}
	blob, _ := json.Marshal(map[string]any{
		"method": ev.Method, "uri": ev.Path, "ip": ev.IP, "content_type": ev.ContentType,
		"query": ev.Query, "post": ev.Post, "headers": ev.Headers, "body": ev.BodyJSONOrBody(),
	})
	ins, err := h.AI.Insight(r.Context(), blob, model, clientKey)
	if err != nil {
		log.Printf("falha na analise de IA: %v", err)
		writeJSON(w, http.StatusBadGateway, failMsg("falha ao analisar o evento."))
		return
	}
	// NUNCA ecoar a chave na resposta.
	writeJSON(w, http.StatusOK, okData(map[string]any{
		"summary": ins.Summary, "anomalies": ins.Anomalies,
		"suggestion": ins.Suggestion, "status": ins.Status, "model": ins.Model, "tokens": ins.Tokens,
	}))
}

func (h *Handler) aiStatus() map[string]any {
	return map[string]any{
		"enabled":        h.Cfg.AIEnabled,
		"model":          h.Cfg.AIModel,
		"label":          h.AI.Label(),
		"server_key_set": h.AI.Enabled(),
		"keys_url":       h.Cfg.AIKeysURL,
	}
}

// adminOK valida a chave de administração (SYSTEM_ADMIN_KEY) via header.
func (h *Handler) adminOK(r *http.Request) bool {
	if h.Cfg.SystemAdminKey == "" {
		return false
	}
	k := r.Header.Get("X-Admin-Key")
	return k != "" && len(k) == len(h.Cfg.SystemAdminKey) && subtle.ConstantTimeCompare([]byte(k), []byte(h.Cfg.SystemAdminKey)) == 1
}

func (h *Handler) adminStats(w http.ResponseWriter, r *http.Request) {
	if !h.adminOK(r) {
		writeJSON(w, http.StatusForbidden, failMsg("nao autorizado."))
		return
	}
	writeJSON(w, http.StatusOK, okData(h.Store.AdminStats()))
}

func (h *Handler) adminEndpoints(w http.ResponseWriter, r *http.Request) {
	if !h.adminOK(r) {
		writeJSON(w, http.StatusForbidden, failMsg("nao autorizado."))
		return
	}
	eps, err := h.Store.AllEndpoints()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, failMsg("falha ao listar."))
		return
	}
	out := make([]map[string]any, 0, len(eps))
	for _, ei := range eps {
		out = append(out, map[string]any{
			"token": ei.Token, "slug": ei.Slug, "name": ei.Name, "admin_key": ei.AdminKey,
			"events": ei.EventsCount, "last_event": dt(ei.LastEventAt), "url": ingestURL(h.Cfg, ei.Slug),
		})
	}
	writeJSON(w, http.StatusOK, okData(map[string]any{"endpoints": out}))
}

func (h *Handler) adminEvents(w http.ResponseWriter, r *http.Request) {
	if !h.adminOK(r) {
		writeJSON(w, http.StatusForbidden, failMsg("nao autorizado."))
		return
	}
	rows, err := h.Store.AllEvents(300)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, failMsg("falha ao listar."))
		return
	}
	items := make([]views.EventItem, 0, len(rows))
	for _, er := range rows {
		items = append(items, views.EventItem{
			ID: er.ID, Method: er.Method, EndpointName: er.EndpointName, ReceivedAt: dt(er.ReceivedAt),
			IP: er.IP, Summary: views.EventSummary(&er.Event), Size: int64(er.Size),
			PayloadType: views.PayloadType(er.ContentType, len(er.BodyJSON) > 0, er.Body, er.Query),
			Source:      views.DetectedSource(er.Headers, "", er.Event),
			AllowDelete: true,
		})
	}
	writeJSON(w, http.StatusOK, okData(map[string]any{"html": views.EventsListHTML(items), "total": len(items)}))
}

func (h *Handler) adminAdmins(w http.ResponseWriter, r *http.Request) {
	if !h.adminOK(r) {
		writeJSON(w, http.StatusForbidden, failMsg("nao autorizado."))
		return
	}
	admins, err := h.Store.AllAdmins()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, failMsg("falha ao listar."))
		return
	}
	out := make([]map[string]any, 0, len(admins))
	for _, a := range admins {
		out = append(out, map[string]any{
			"admin_key": a.AdminKey, "created": dt(a.Created), "last_seen": dt(a.LastSeen),
			"endpoints": a.Endpoints, "events": a.Events,
		})
	}
	writeJSON(w, http.StatusOK, okData(map[string]any{"admins": out}))
}

func (h *Handler) adminDeleteEndpoint(w http.ResponseWriter, r *http.Request) {
	if !h.adminOK(r) {
		writeJSON(w, http.StatusForbidden, failMsg("nao autorizado."))
		return
	}
	ok, err := h.Store.DeleteEndpointAdmin(r.PostFormValue("token"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, failMsg("falha ao excluir URL."))
		return
	}
	writeJSON(w, http.StatusOK, okData(map[string]any{"deleted": ok}))
}

func (h *Handler) adminDeleteAdmin(w http.ResponseWriter, r *http.Request) {
	if !h.adminOK(r) {
		writeJSON(w, http.StatusForbidden, failMsg("nao autorizado."))
		return
	}
	n, err := h.Store.DeleteAdmin(r.PostFormValue("admin_key"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, failMsg("falha ao excluir cliente."))
		return
	}
	writeJSON(w, http.StatusOK, okData(map[string]any{"deleted": n}))
}

func (h *Handler) adminClearAll(w http.ResponseWriter, r *http.Request) {
	if !h.adminOK(r) {
		writeJSON(w, http.StatusForbidden, failMsg("nao autorizado."))
		return
	}
	n, err := h.Store.GlobalClearEvents()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, failMsg("falha ao limpar eventos."))
		return
	}
	writeJSON(w, http.StatusOK, okData(map[string]any{"deleted": n}))
}

func (h *Handler) adminClearRetention(w http.ResponseWriter, r *http.Request) {
	if !h.adminOK(r) {
		writeJSON(w, http.StatusForbidden, failMsg("nao autorizado."))
		return
	}
	n, err := h.Store.RetentionRemove(h.Cfg.RetentionHours)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, failMsg("falha ao aplicar retencao."))
		return
	}
	writeJSON(w, http.StatusOK, okData(map[string]any{"deleted": n}))
}

func dt(unix int64) string {
	if unix <= 0 {
		return "---"
	}
	return time.Unix(unix, 0).Format("02/01/2006 15:04:05")
}

// ---------- helpers ----------

const adminCookie = "nhooks_admin"

func cookie(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

func (h *Handler) purgeAdminKey(w http.ResponseWriter, key string) {
	http.SetCookie(w, &http.Cookie{Name: adminCookie, Value: key, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

// SetAdminCookie é chamado pelo handler web ao autenticar via admin hash.
func (h *Handler) SetAdminCookie(w http.ResponseWriter, r *http.Request, key string) {
	h.purgeAdminKey(w, key)
}

func okData(data any) map[string]any    { return map[string]any{"success": true, "data": data} }
func failMsg(msg string) map[string]any { return map[string]any{"success": false, "message": msg} }

func writeJSON(w http.ResponseWriter, code int, payload map[string]any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}

func (h *Handler) adminEventDetail(w http.ResponseWriter, r *http.Request) {
	if !h.adminOK(r) {
		writeJSON(w, http.StatusForbidden, failMsg("nao autorizado."))
		return
	}
	ev, err := h.Store.EventByID(r.URL.Query().Get("event_id"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, failMsg("evento nao encontrado."))
		return
	}
	v := ev.JSONView()
	v["payload_type"] = payloadType(ev)
	if ep, err := h.Store.EndpointByToken(ev.EndpointToken); err == nil {
		v["endpoint_name"] = ep.Name
		v["endpoint_slug"] = ep.Slug
	}
	writeJSON(w, http.StatusOK, okData(map[string]any{"event": v}))
}

func (h *Handler) adminDeleteEvent(w http.ResponseWriter, r *http.Request) {
	if !h.adminOK(r) {
		writeJSON(w, http.StatusForbidden, failMsg("nao autorizado."))
		return
	}
	ok, err := h.Store.DeleteEventAdmin(r.PostFormValue("event_id"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, failMsg("falha ao excluir evento."))
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, failMsg("evento nao encontrado."))
		return
	}
	writeJSON(w, http.StatusOK, okData(map[string]any{"deleted": true}))
}

func mutationAction(action string) bool {
	switch action {
	case "create_endpoint", "delete_endpoint", "delete_event", "clear_events", "ai_insight",
		"bootstrap", "admin_delete_endpoint", "admin_delete_admin", "admin_delete_event", "admin_clear_all", "admin_clear_retention":
		return true
	default:
		return false
	}
}

func isHex(v string) bool {
	for _, c := range v {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func csvSafe(v string) string {
	trimmed := strings.TrimLeft(v, "\t\r\n")
	if trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0])) {
		return "'" + v
	}
	return v
}

func paginationHTML(page, totalPages int) string {
	if totalPages <= 1 {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<div class="pagination">`)
	if page > 1 {
		b.WriteString(`<button class="btn small ghost" type="button" onclick="goPage(` + strconv.Itoa(page-1) + `)">Anterior</button>`)
	}
	b.WriteString(`<span>Página ` + strconv.Itoa(page) + ` de ` + strconv.Itoa(totalPages) + `</span>`)
	if page < totalPages {
		b.WriteString(`<button class="btn small ghost" type="button" onclick="goPage(` + strconv.Itoa(page+1) + `)">Próxima</button>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}

func publicURL(cfg config.Config) string             { return strings.TrimRight(cfg.PublicURL, "/") }
func adminLink(cfg config.Config, key string) string { return publicURL(cfg) + "/dash/" + key }
func shareLink(cfg config.Config, share string) string {
	if share == "" {
		return ""
	}
	return publicURL(cfg) + "/share/" + share
}

func ingestURL(cfg config.Config, slug string) string {
	route := strings.Trim(cfg.IngestRoute, "/")
	if route == "" {
		route = "hook"
	}
	return publicURL(cfg) + "/" + route + "/" + slug
}

func payloadType(ev *domain.Event) string {
	if strings.Contains(ev.ContentType, "json") {
		return "JSON"
	}
	if strings.Contains(ev.ContentType, "form") {
		return "Form"
	}
	return "Raw"
}
