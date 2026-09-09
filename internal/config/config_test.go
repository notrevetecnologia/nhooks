package config

import "testing"

func TestParseEnvValuePreservesHashInsideQuotes(t *testing.T) {
	tests := map[string]string{
		`"foo # bar"`:           "foo # bar",
		`"foo # bar" # comment`: "foo # bar",
		`foo # comment`:         "foo",
		`#12948e`:               "#12948e",
	}
	for input, want := range tests {
		if got := parseEnvValue(input); got != want {
			t.Errorf("parseEnvValue(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestSafeIngestRouteRejectsReservedPaths(t *testing.T) {
	for _, route := range []string{"", "api", "/admin/", "health", "in"} {
		if got := safeIngestRoute(route); got != "hook" {
			t.Errorf("safeIngestRoute(%q) = %q", route, got)
		}
	}
	if got := safeIngestRoute("receive"); got != "receive" {
		t.Fatalf("custom route = %q", got)
	}
}
