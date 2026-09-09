package ingest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/notrevetecnologia/nhooks/internal/config"
	"github.com/notrevetecnologia/nhooks/internal/domain"
	"github.com/notrevetecnologia/nhooks/internal/ratelimit"
	"github.com/notrevetecnologia/nhooks/internal/security"
	"github.com/notrevetecnologia/nhooks/internal/store"
)

func setupIngest(t *testing.T, cfg IngestConfig, secret string) (*Handler, *store.Store, *domain.Endpoint) {
	t.Helper()
	s, err := store.Open(config.Config{DBDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "test.db"), DBMaxOpenConns: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.EnsureAdmin("tenant"); err != nil {
		t.Fatal(err)
	}
	ep := &domain.Endpoint{Token: "token", Slug: "slug", Name: "Test", AdminKey: "tenant", ShareKey: "share", Secret: secret, HMACRequired: secret != "", CreatedAt: time.Now()}
	if err := s.CreateEndpoint(ep); err != nil {
		t.Fatal(err)
	}
	lim := ratelimit.NewMemory(ratelimit.Config{Limit: 100, Window: time.Minute})
	t.Cleanup(func() { _ = lim.Close() })
	return New(s, lim, cfg), s, ep
}

func TestRejectsMissingSignatureAndOversizedBody(t *testing.T) {
	h, s, ep := setupIngest(t, IngestConfig{MaxBodyBytes: 4}, "secret")
	req := httptest.NewRequest(http.MethodPost, "/hook/slug", strings.NewReader("test"))
	w := httptest.NewRecorder()
	h.Serve(w, req, ep)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("missing signature status = %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/hook/slug", strings.NewReader("12345"))
	req.Header.Set("X-Nhooks-Signature-256", security.HMACSign256([]byte("secret"), []byte("12345")))
	w = httptest.NewRecorder()
	h.Serve(w, req, ep)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status = %d", w.Code)
	}
	if got := s.EventCountForEndpoint(ep.Token); got != 0 {
		t.Fatalf("stored oversized events = %d", got)
	}
}

func TestCapturesFormAndDeduplicates(t *testing.T) {
	h, s, ep := setupIngest(t, IngestConfig{MaxBodyBytes: 1024}, "")
	form := url.Values{"name": {"Sara"}, "tag": {"a", "b"}}.Encode()
	request := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/hook/slug", strings.NewReader(form))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("X-Nhooks-Id", "once")
		return r
	}
	w := httptest.NewRecorder()
	h.Serve(w, request(), ep)
	if w.Code != http.StatusAccepted {
		t.Fatalf("first status = %d: %s", w.Code, w.Body.String())
	}
	var response struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	ev, err := s.EventByID(response.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Post["name"] != "Sara" {
		t.Fatalf("parsed form = %#v", ev.Post)
	}

	w = httptest.NewRecorder()
	h.Serve(w, request(), ep)
	if w.Code != http.StatusOK || s.EventCountForEndpoint(ep.Token) != 1 {
		t.Fatalf("duplicate status/count = %d/%d", w.Code, s.EventCountForEndpoint(ep.Token))
	}
}

func TestEnforcesStorageLimit(t *testing.T) {
	h, s, ep := setupIngest(t, IngestConfig{MaxBodyBytes: 1024, MaxStorageBytes: 3}, "")
	req := httptest.NewRequest(http.MethodPost, "/hook/slug", strings.NewReader("1234"))
	w := httptest.NewRecorder()
	h.Serve(w, req, ep)
	if w.Code != http.StatusInsufficientStorage {
		t.Fatalf("storage limit status = %d", w.Code)
	}
	if got := s.EventCountForEndpoint(ep.Token); got != 0 {
		t.Fatalf("stored events = %d", got)
	}
}

func TestDuplicateIsAcknowledgedAfterQuotaIsReached(t *testing.T) {
	h, _, ep := setupIngest(t, IngestConfig{MaxBodyBytes: 1024, MaxEventsPerEp: 1}, "")
	request := func(id string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/hook/slug", strings.NewReader("ok"))
		r.Header.Set("X-Nhooks-Id", id)
		return r
	}
	w := httptest.NewRecorder()
	h.Serve(w, request("first"), ep)
	if w.Code != http.StatusAccepted {
		t.Fatalf("first status = %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.Serve(w, request("first"), ep)
	if w.Code != http.StatusOK {
		t.Fatalf("duplicate after quota status = %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.Serve(w, request("second"), ep)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("new event after quota status = %d", w.Code)
	}
}
