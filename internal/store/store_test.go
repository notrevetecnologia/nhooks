package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/notrevetecnologia/nhooks/internal/config"
	"github.com/notrevetecnologia/nhooks/internal/domain"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(config.Config{DBDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "test.db"), DBMaxOpenConns: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func seedEndpoint(t *testing.T, s *Store, admin, token string) *domain.Endpoint {
	t.Helper()
	if err := s.EnsureAdmin(admin); err != nil {
		t.Fatal(err)
	}
	ep := &domain.Endpoint{Token: token, Slug: token, Name: token, AdminKey: admin, ShareKey: token + "-share", CreatedAt: time.Now()}
	if err := s.CreateEndpoint(ep); err != nil {
		t.Fatal(err)
	}
	return ep
}

func seedEvent(t *testing.T, s *Store, id, token string) {
	t.Helper()
	if err := s.CreateEvent(&domain.Event{ID: id, EndpointToken: token, Method: "POST", Body: `{"ok":true}`, Size: 11, ReceivedAt: time.Now().Unix()}); err != nil {
		t.Fatal(err)
	}
}

func TestTenantCannotDeleteOrClearForeignEndpoint(t *testing.T) {
	s := testStore(t)
	seedEndpoint(t, s, "tenant-a", "endpoint-a")
	seedEndpoint(t, s, "tenant-b", "endpoint-b")
	seedEvent(t, s, "event-b", "endpoint-b")

	deleted, err := s.DeleteEndpoint("tenant-a", "endpoint-b")
	if err != nil || deleted {
		t.Fatalf("foreign delete = %v, %v", deleted, err)
	}
	if _, err := s.EventByID("event-b"); err != nil {
		t.Fatalf("foreign event was deleted: %v", err)
	}

	cleared, err := s.ClearEventsForAdmin("tenant-a", "endpoint-b")
	if err != nil || cleared != 0 {
		t.Fatalf("foreign clear = %d, %v", cleared, err)
	}
	if _, err := s.EventByID("event-b"); err != nil {
		t.Fatalf("foreign event was cleared: %v", err)
	}
}

func TestCreateEventOnceIsIdempotent(t *testing.T) {
	s := testStore(t)
	seedEndpoint(t, s, "tenant", "endpoint")
	event := &domain.Event{ID: "one", EndpointToken: "endpoint", Method: "POST", ReceivedAt: time.Now().Unix()}
	created, err := s.CreateEventOnce(event, "same-key")
	if err != nil || !created {
		t.Fatalf("first create = %v, %v", created, err)
	}
	event.ID = "two"
	created, err = s.CreateEventOnce(event, "same-key")
	if err != nil || created {
		t.Fatalf("duplicate create = %v, %v", created, err)
	}
	if got := s.EventCountForEndpoint("endpoint"); got != 1 {
		t.Fatalf("event count = %d", got)
	}
}

func TestEncryptionFlagControlsWritesAndPreservesEmptyJSON(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			s, err := Open(config.Config{DBDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "test.db"), DBMaxOpenConns: 1, EventEncryptionEnabled: enabled, EventEncryptionKey: "strong-test-key"})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			seedEndpoint(t, s, "tenant", "endpoint")
			seedEvent(t, s, "event", "endpoint")
			var raw string
			if err := s.queryRow(`SELECT body FROM events WHERE id=?`, "event").Scan(&raw); err != nil {
				t.Fatal(err)
			}
			if enabled == (raw == `{"ok":true}`) {
				t.Fatalf("unexpected stored body: %q", raw)
			}
			ev, err := s.EventByID("event")
			if err != nil || ev.Body != `{"ok":true}` || len(ev.BodyJSON) != 0 {
				t.Fatalf("decoded event = %#v, %v", ev, err)
			}
		})
	}
}

func TestDisabledRetentionDoesNotDeleteEvents(t *testing.T) {
	s := testStore(t)
	seedEndpoint(t, s, "tenant", "endpoint")
	seedEvent(t, s, "event", "endpoint")
	deleted, err := s.RetentionRemove(0)
	if err != nil || deleted != 0 {
		t.Fatalf("disabled retention = %d, %v", deleted, err)
	}
	if _, err := s.EventByID("event"); err != nil {
		t.Fatalf("event deleted with retention disabled: %v", err)
	}
}
