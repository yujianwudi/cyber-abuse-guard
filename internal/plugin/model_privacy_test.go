package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/yujianwudi/cyber-abuse-guard/internal/audit"
)

func TestCallerControlledAuditMetadataIsPrivateAcrossEventsSQLiteAndManagementAPI(t *testing.T) {
	dataDir := t.TempDir()
	p := New()
	register(t, p, "mode: audit\naudit:\n  enabled: true\n  data_dir: \""+filepath.ToSlash(dataDir)+"\"\nsubject_control:\n  enabled: false\n")

	const decisionCanary = "MODEL_PRIVACY_DECISION_CANARY_secret-model-name"
	const parseCanary = "MODEL_PRIVACY_PARSE_CANARY_secret-model-name"
	const sourceCanary = "SOURCE_FORMAT_PRIVACY_CANARY_secret-provider-name"
	callPrivacyModelRoute(t, p, decisionCanary, sourceCanary, []byte(maliciousRequest))
	callPrivacyModelRoute(t, p, parseCanary, sourceCanary, []byte(`{"messages":[`))

	management := managementJSON(t, p, http.MethodGet, managementBasePath+"/events", nil)
	managementRaw, err := json.Marshal(management)
	if err != nil {
		t.Fatal(err)
	}
	assertNoAuditCanary(t, managementRaw, decisionCanary, parseCanary, sourceCanary)

	items, ok := management["events"].([]any)
	if !ok || len(items) != 2 {
		t.Fatalf("management events = %#v, want two events", management["events"])
	}
	wantHashes := map[string]bool{
		audit.HashModel(decisionCanary): false,
		audit.HashModel(parseCanary):    false,
	}
	for _, item := range items {
		event, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("management event has type %T", item)
		}
		model, _ := event["model"].(string)
		if _, exists := wantHashes[model]; !exists {
			t.Fatalf("management event model = %q, want a domain-separated digest", model)
		}
		if event["source_format"] != audit.SourceFormatUnknown {
			t.Fatalf("management event source_format = %#v, want %q", event["source_format"], audit.SourceFormatUnknown)
		}
		wantHashes[model] = true
	}
	for model, seen := range wantHashes {
		if !seen {
			t.Fatalf("management API did not return expected model digest %q", model)
		}
	}

	state := p.runtime.Load()
	if state == nil || state.audit == nil {
		t.Fatal("audit runtime is unavailable")
	}
	if err := state.audit.Flush(context.Background()); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	events, err := state.audit.Query(context.Background(), audit.Query{Limit: 10})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	eventRaw, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	assertNoAuditCanary(t, eventRaw, decisionCanary, parseCanary, sourceCanary)
	for _, event := range events {
		if _, exists := wantHashes[event.Model]; !exists {
			t.Fatalf("persisted Event.Model = %q, want a domain-separated digest", event.Model)
		}
		if event.SourceFormat != audit.SourceFormatUnknown {
			t.Fatalf("persisted Event.SourceFormat = %q, want %q", event.SourceFormat, audit.SourceFormatUnknown)
		}
	}

	p.Shutdown()
	databaseFiles, err := filepath.Glob(filepath.Join(dataDir, "events.db*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(databaseFiles) == 0 {
		t.Fatal("audit SQLite database was not created")
	}
	for _, name := range databaseFiles {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("ReadFile(%q): %v", name, err)
		}
		assertNoAuditCanary(t, data, decisionCanary, parseCanary, sourceCanary)
	}
}

func callPrivacyModelRoute(t testing.TB, p *Plugin, requestedModel, sourceFormat string, body []byte) {
	t.Helper()
	rawRequest, err := json.Marshal(pluginapi.ModelRouteRequest{
		SourceFormat:   sourceFormat,
		RequestedModel: requestedModel,
		Body:           body,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, code := p.Call(pluginabi.MethodModelRoute, rawRequest)
	if code != 0 {
		t.Fatalf("model.route code=%d envelope=%s", code, raw)
	}
}

func assertNoAuditCanary(t testing.TB, data []byte, canaries ...string) {
	t.Helper()
	for _, canary := range canaries {
		if bytes.Contains(data, []byte(canary)) {
			t.Fatalf("plaintext audit metadata canary %q was retained in %s", canary, strings.TrimSpace(string(data)))
		}
	}
}
