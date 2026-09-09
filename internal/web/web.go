// Package web serve a interface (dashboard/admin) com assets embutidos via go:embed.
package web

import (
	"embed"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/notrevetecnologia/nhooks/internal/config"
	"github.com/notrevetecnologia/nhooks/internal/domain"
	"github.com/notrevetecnologia/nhooks/internal/security"
	"github.com/notrevetecnologia/nhooks/internal/store"
)

//go:embed root
var rootFS embed.FS

// Handler serve a UI.
type Handler struct {
	Store *store.Store
	Cfg   config.Config
}

// New cria o handler web.
func New(dst *store.Store, cfg config.Config) *Handler { return &Handler{Store: dst, Cfg: cfg} }

const cfgToken = "__NHOOKS_CONFIG__"

type viewConfig struct {
	BrandName   string `json:"brandName"`
	BrandColor  string `json:"brandColor"`
	Secondary   string `json:"secondary"`
	Dim         string `json:"dim"`
	LogoHeight  string `json:"logoHeight"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Eyebrow     string `json:"eyebrow"`
	FaviconURL  string `json:"faviconUrl"`
	CompanyURL  string `json:"companyUrl"`
	LogoURL     string `json:"logoUrl"`
	PublicURL   string `json:"publicUrl"`
	IngestRoute string `json:"ingestRoute"`
	Theme       string `json:"theme"`
	PollingMS   int    `json:"pollingMs"`
	AIEnabled   bool   `json:"aiEnabled"` // recurso IA ligado
	AIModel     string `json:"aiModel"`
	AILabel     string `json:"aiLabel"`
	AIKeysURL   string `json:"aiKeysURL"`
	AIServerKey bool   `json:"serverKeySet"` // há chave no servidor (AI_API_KEY)
	SystemAdmin bool   `json:"systemAdmin"`
	Mode        string `json:"mode"`  // "admin" | "share"
	Share       string `json:"share"` // chave de compartilhamento (somente leitura)
}

// ServeHTTP roteia as páginas.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimRight(r.URL.Path, "/")

	// assets estáticos embutidos
	if strings.HasPrefix(path, "/static/") {
		http.ServeFileFS(w, r, rootFS, "root/"+strings.TrimPrefix(path, "/static/"))
		return
	}

	switch {
	case path == "" || path == "/":
		h.dashboard(w, r)
	case strings.HasPrefix(path, "/dash/"):
		key := strings.TrimPrefix(path, "/dash/")
		if key == "" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		if h.Store.AdminExists(key) {
			h.setAdminCookie(w, r, key)
		}
		http.Redirect(w, r, "/", http.StatusFound)
	case strings.HasPrefix(path, "/share/"):
		h.dashboardShare(w, r, strings.TrimPrefix(path, "/share/"))
	case path == "/admin" || path == "/ia":
		h.admin(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) dashboard(w http.ResponseWriter, r *http.Request) {
	key := adminKey(r)
	// Um GET apenas entrega uma identidade candidata. A persistência acontece no
	// POST bootstrap da UI, evitando criar clientes para crawlers simples.
	if key == "" || !h.Store.AdminExists(key) {
		key = security.RandomHex(20)
		h.setAdminCookie(w, r, key)
		h.render(w, h.viewConfig("admin"))
		return
	}
	// Garante pelo menos uma URL de ingestão (comportamento da UI original).
	h.createDefaultEndpoint(key)
	h.render(w, h.viewConfig("admin"))
}

func (h *Handler) setAdminCookie(w http.ResponseWriter, r *http.Request, key string) {
	secure := r.TLS != nil || strings.HasPrefix(strings.ToLower(h.Cfg.PublicURL), "https://")
	http.SetCookie(w, &http.Cookie{
		Name: "nhooks_admin", Value: key, Path: "/", HttpOnly: true, Secure: secure,
		SameSite: http.SameSiteStrictMode, MaxAge: 31536000,
	})
}

func (h *Handler) createDefaultEndpoint(adminKey string) {
	base := security.Slugify("Principal")
	if base == "" {
		base = "endpoint"
	}
	now := time.Now()
	ep := &domain.Endpoint{
		Token:     security.RandomHex(16),
		Slug:      base + "-" + security.Base62(4),
		Name:      "Principal",
		AdminKey:  adminKey,
		ShareKey:  security.RandomHex(12),
		Secret:    "",
		CreatedAt: now,
	}
	_ = h.Store.EnsureAdminWithDefault(adminKey, ep)
}

func (h *Handler) dashboardShare(w http.ResponseWriter, r *http.Request, share string) {
	if _, err := h.Store.SharedEndpoint(share); err != nil {
		http.NotFound(w, r)
		return
	}
	h.render(w, h.viewConfigWithShare("share", share))
}

func (h *Handler) admin(w http.ResponseWriter, r *http.Request) {
	raw, err := rootFS.ReadFile("root/admin.html")
	if err != nil {
		http.Error(w, "Admin UI não encontrada", http.StatusInternalServerError)
		return
	}
	b, _ := json.Marshal(h.viewConfig("admin"))
	out := strings.ReplaceAll(string(raw), cfgToken, string(b))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(out))
}

func (h *Handler) render(w http.ResponseWriter, cfg viewConfig) {
	raw, err := rootFS.ReadFile("root/index.html")
	if err != nil {
		http.Error(w, "UI não encontrada", http.StatusInternalServerError)
		return
	}
	b, _ := json.Marshal(cfg)
	out := strings.ReplaceAll(string(raw), cfgToken, string(b))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(out))
}

func (h *Handler) viewConfig(mode string) viewConfig {
	return h.viewConfigWithShare(mode, "")
}

func (h *Handler) viewConfigWithShare(mode, share string) viewConfig {
	return viewConfig{
		BrandName:   h.Cfg.Name,
		BrandColor:  h.Cfg.Primary,
		Secondary:   h.Cfg.Secondary,
		Dim:         h.Cfg.Dim,
		LogoHeight:  h.Cfg.LogoHeight,
		Title:       h.Cfg.Title,
		Description: h.Cfg.Description,
		Eyebrow:     h.Cfg.Eyebrow,
		FaviconURL:  h.Cfg.FaviconURL,
		CompanyURL:  h.Cfg.CompanyURL,
		LogoURL:     h.Cfg.LogoURL,
		PublicURL:   strings.TrimRight(h.Cfg.PublicURL, "/"),
		IngestRoute: h.Cfg.IngestRoute,
		Theme:       h.Cfg.Theme,
		PollingMS:   h.Cfg.PollingMS,
		AIEnabled:   h.Cfg.AIEnabled,
		AIModel:     h.Cfg.AIModel,
		AILabel:     h.Cfg.AIAppName,
		AIKeysURL:   h.Cfg.AIKeysURL,
		AIServerKey: h.Cfg.AIKey != "",
		SystemAdmin: h.Cfg.SystemAdminKey != "",
		Mode:        mode,
		Share:       share,
	}
}

func adminKey(r *http.Request) string {
	if c, err := r.Cookie("nhooks_admin"); err == nil {
		return c.Value
	}
	return r.URL.Query().Get("admin")
}
