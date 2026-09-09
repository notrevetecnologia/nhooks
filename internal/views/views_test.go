package views

import (
	"strings"
	"testing"
)

func TestEventsListEscapesPayloadAndHonorsReadOnlyMode(t *testing.T) {
	html := EventsListHTML([]EventItem{{ID: "event", Method: "POST", Summary: `<img src=x onerror="alert(1)">`, AllowDelete: false}})
	if strings.Contains(html, "<img") {
		t.Fatal("summary was not escaped")
	}
	if strings.Contains(html, "askDeleteEvent") {
		t.Fatal("read-only row contains delete action")
	}

	html = EventsListHTML([]EventItem{{ID: "event", Method: "POST", AllowDelete: true}})
	if !strings.Contains(html, "askDeleteEvent") {
		t.Fatal("editable row is missing delete action")
	}
}
