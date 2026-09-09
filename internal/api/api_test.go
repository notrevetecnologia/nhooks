package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/notrevetecnologia/nhooks/internal/ai"
	"github.com/notrevetecnologia/nhooks/internal/config"
	"github.com/notrevetecnologia/nhooks/internal/domain"
	"github.com/notrevetecnologia/nhooks/internal/store"
)

func setupAPI(t *testing.T) (*Handler, *store.Store) {
	t.Helper()
	cfg := config.Config{DBDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "test.db"), DBMaxOpenConns: 1, PublicURL: "http://example.test", IngestRoute: "hook", DashboardEventsLimit: 50, SystemAdminKey: "system"}
	s, err := store.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.EnsureAdmin("tenant"); err != nil {
		t.Fatal(err)
	}
	ep := &domain.Endpoint{Token: "private-token", Slug: "slug", Name: "Test", AdminKey: "tenant", ShareKey: "share-key", Secret: "private-secret", CreatedAt: time.Now()}
	if err := s.CreateEndpoint(ep); err != nil {
		t.Fatal(err)
	}
	return New(s, ai.New("", "", "model", "IA"), cfg), s
}

func TestShareListDoesNotExposeSecretsOrDeleteControls(t *testing.T) {
	h, s := setupAPI(t)
	if err := s.CreateEvent(&domain.Event{ID: "shared-event", EndpointToken: "private-token", Method: "POST", Body: "safe", ReceivedAt: time.Now().Unix()}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/api?action=list_events&share=share-key", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	raw := w.Body.String()
	for _, secret := range []string{"private-token", "private-secret", "askDeleteEvent"} {
		if strings.Contains(raw, secret) {
			t.Fatalf("share response exposed %q", secret)
		}
	}
	r = httptest.NewRequest(http.MethodGet, "/api?action=event_detail&share=share-key&event_id=shared-event", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if strings.Contains(w.Body.String(), "private-token") {
		t.Fatal("share detail exposed endpoint token")
	}
}

func TestMutationsRequirePostAndValidInput(t *testing.T) {
	h, _ := setupAPI(t)
	r := httptest.NewRequest(http.MethodGet, "/api?action=clear_events", nil)
	r.AddCookie(&http.Cookie{Name: adminCookie, Value: "tenant"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET mutation status = %d", w.Code)
	}

	form := url.Values{"name": {""}}.Encode()
	r = httptest.NewRequest(http.MethodPost, "/api?action=create_endpoint", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: adminCookie, Value: "tenant"})
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("empty name status = %d", w.Code)
	}
}

func TestSystemAdminKeyIsAcceptedOnlyInHeader(t *testing.T) {
	h, _ := setupAPI(t)
	r := httptest.NewRequest(http.MethodGet, "/api?action=admin_stats&adminkey=system", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("query key status = %d", w.Code)
	}
	r = httptest.NewRequest(http.MethodGet, "/api?action=admin_stats", nil)
	r.Header.Set("X-Admin-Key", "system")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("header key status = %d", w.Code)
	}
}

func TestShareCannotUseAI(t *testing.T) {
	h, _ := setupAPI(t)
	r := httptest.NewRequest(http.MethodPost, "/api?action=ai_insight&share=share-key", strings.NewReader("event_id=x"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("share AI status = %d", w.Code)
	}
}

func TestBootstrapCreatesPanelOnlyViaPost(t *testing.T) {
	h, s := setupAPI(t)
	key := strings.Repeat("a", 40)
	var wg sync.WaitGroup
	statuses := make(chan int, 4)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest(http.MethodPost, "/api?action=bootstrap", nil)
			r.AddCookie(&http.Cookie{Name: adminCookie, Value: key})
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			statuses <- w.Code
		}()
	}
	wg.Wait()
	close(statuses)
	for status := range statuses {
		if status != http.StatusOK {
			t.Fatalf("bootstrap status = %d", status)
		}
	}
	if !s.AdminExists(key) {
		t.Fatal("bootstrap did not create admin")
	}
	eps, err := s.EndpointsByAdmin(key)
	if err != nil || len(eps) != 1 {
		t.Fatalf("bootstrap endpoints = %d, %v", len(eps), err)
	}
}
