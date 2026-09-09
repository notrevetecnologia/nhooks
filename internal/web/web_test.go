package web

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/notrevetecnologia/nhooks/internal/config"
	"github.com/notrevetecnologia/nhooks/internal/store"
)

func TestDashboardGETDoesNotPersistCrawlerAsClient(t *testing.T) {
	cfg := config.Config{DBDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "test.db"), DBMaxOpenConns: 1}
	s, err := store.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	New(s, cfg).ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	admins, err := s.AllAdmins()
	if err != nil || len(admins) != 0 {
		t.Fatalf("admins after GET = %d, %v", len(admins), err)
	}
	if len(w.Result().Cookies()) != 1 {
		t.Fatal("candidate session cookie was not set")
	}
}
