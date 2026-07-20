package plugin

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/yujianwudi/cyber-abuse-guard/internal/audit"
)

func TestRawCaptureManagementRequiresCredentialAndStaysEmptyWhenDisabled(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, "audit:\n  enabled: false\n")

	response, body := callManagementResponse(t, p, pluginapi.ManagementRequest{
		Method: http.MethodGet,
		Path:   managementBasePath + "/raw-captures",
	})
	if response.StatusCode != http.StatusUnauthorized || bodyErrorCode(body) != "unauthorized" {
		t.Fatalf("missing credential response=%+v body=%s", response, body)
	}

	response, body = callManagementResponse(t, p, authenticatedManagementRequest(
		http.MethodGet,
		managementBasePath+"/raw-captures",
		nil,
	))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("disabled raw capture status=%d body=%s", response.StatusCode, body)
	}
	var result struct {
		Enabled                    bool             `json:"enabled"`
		Captures                   []map[string]any `json:"captures"`
		RequestedLimit             int              `json:"requested_limit"`
		ReturnedCount              int              `json:"returned_count"`
		ResponseTruncated          bool             `json:"response_truncated"`
		ResponsePreviewBudgetBytes int              `json:"response_preview_budget_bytes"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	if result.Enabled || len(result.Captures) != 0 || result.ReturnedCount != 0 || result.ResponseTruncated {
		t.Fatalf("disabled raw capture response=%s, want enabled=false and empty captures", body)
	}
	if result.RequestedLimit != defaultManagementRawCaptureLimit || result.ResponsePreviewBudgetBytes != maxManagementRawPreviewBytes {
		t.Fatalf("disabled raw capture bounds=%+v", result)
	}
}

func TestRawCaptureManagementBoundsEncodedPreviewResponse(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	dataDir := filepath.ToSlash(t.TempDir())
	register(t, p, "mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\n  retention_days: 30\n  raw_capture:\n    enabled: true\n    only_blocked: true\n    redact_secrets: true\n    max_bytes: 1048576\n    ttl_hours: 72\n")
	state := p.runtime.Load()
	rawRequest := []byte(strings.Repeat("<", 1<<20))
	for index := 0; index < 10; index++ {
		timestamp := time.Now().UTC().Add(time.Duration(index) * time.Nanosecond)
		eventID := newEventID()
		requestHash := audit.HashRequest(append(rawRequest, byte(index)))
		event := audit.Event{
			ID:          eventID,
			Timestamp:   timestamp,
			Action:      "block",
			Mode:        "balanced",
			RiskScore:   100,
			RequestHash: requestHash,
			Decision:    "block_malicious_text",
			Coverage:    "complete",
			Scanner:     "streaming-scanner-v1",
		}
		if !state.audit.Record(event) {
			t.Fatal("audit event was not queued")
		}
		if err := state.audit.RecordRawCapture(audit.RawCaptureInput{
			EventID:     eventID,
			Timestamp:   timestamp,
			RequestHash: requestHash,
			Action:      "block",
			Decision:    "block_malicious_text",
			RawRequest:  rawRequest,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := state.audit.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}

	// These 1 MiB rows predate a configuration downgrade. The query path must
	// use the audit store's fixed scan budget rather than trusting the new
	// one-byte per-record setting and materializing up to 100 historical rows.
	raw, code := p.Call(pluginabi.MethodPluginReconfigure, lifecyclePayload(t,
		"mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\n  retention_days: 30\n  raw_capture:\n    enabled: true\n    only_blocked: true\n    redact_secrets: true\n    max_bytes: 1\n    ttl_hours: 72\n"))
	if code != 0 {
		t.Fatalf("raw capture downgrade reconfigure code=%d envelope=%s", code, raw)
	}
	if current := p.runtime.Load().config.Audit.RawCapture.MaxBytes; current != 1 {
		t.Fatalf("current raw capture max_bytes=%d, want 1", current)
	}

	request := authenticatedManagementRequest(http.MethodGet, managementBasePath+"/raw-captures", nil)
	request.Query = url.Values{"limit": []string{"100"}}
	response, body := callManagementResponse(t, p, request)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("bounded raw capture status=%d body=%s", response.StatusCode, body)
	}
	var result struct {
		Captures                   []audit.RawRequestCapture `json:"captures"`
		RequestedLimit             int                       `json:"requested_limit"`
		ReturnedCount              int                       `json:"returned_count"`
		ResponseTruncated          bool                      `json:"response_truncated"`
		PreviewBytes               int                       `json:"preview_bytes"`
		EncodedPreviewBytes        int                       `json:"encoded_preview_bytes"`
		ResponsePreviewBudgetBytes int                       `json:"response_preview_budget_bytes"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	if result.RequestedLimit != 100 || result.ReturnedCount != 1 || len(result.Captures) != 1 || !result.ResponseTruncated {
		t.Fatalf("bounded raw capture metadata=%+v", result)
	}
	if result.PreviewBytes != 1<<20 || result.EncodedPreviewBytes <= result.PreviewBytes || result.EncodedPreviewBytes > maxManagementRawPreviewBytes {
		t.Fatalf("bounded raw capture bytes=%+v", result)
	}
	if result.ResponsePreviewBudgetBytes != maxManagementRawPreviewBytes || result.Captures[0].RawPreview == "" {
		t.Fatalf("bounded raw capture response=%+v", result)
	}
}

func TestRawCaptureHotDisablePurgesRetainedRows(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	dataDir := filepath.ToSlash(t.TempDir())
	register(t, p, "mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\n  raw_capture:\n    enabled: true\n    only_blocked: true\n    redact_secrets: true\n    max_bytes: 8192\n    ttl_hours: 72\nsubject_control:\n  enabled: false\n")

	if route := callRoute(t, p, maliciousRequest); !route.Handled {
		t.Fatalf("malicious fixture was not blocked: %+v", route)
	}
	oldState := p.runtime.Load()
	if err := oldState.audit.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, err := oldState.audit.QueryRawCapturesPage(context.Background(), audit.RawCaptureQuery{Limit: 100})
	if err != nil || len(before.Captures) != 1 {
		t.Fatalf("pre-disable captures=%#v err=%v, want one", before, err)
	}

	raw, code := p.Call(pluginabi.MethodPluginReconfigure, lifecyclePayload(t,
		"mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\n  raw_capture:\n    enabled: false\nsubject_control:\n  enabled: false\n"))
	if code != 0 {
		t.Fatalf("raw capture disable reconfigure code=%d envelope=%s", code, raw)
	}
	state := p.runtime.Load()
	if state.config.Audit.RawCapture.Enabled {
		t.Fatal("raw capture remained enabled after reconfigure")
	}
	if err := state.audit.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, err := state.audit.QueryRawCapturesPage(context.Background(), audit.RawCaptureQuery{Limit: 100})
	if err != nil || len(after.Captures) != 0 || after.HasMore {
		t.Fatalf("post-disable captures=%#v err=%v, want an empty purged table", after, err)
	}

	result := managementJSON(t, p, http.MethodGet, managementBasePath+"/raw-captures", nil)
	if enabled, _ := result["enabled"].(bool); enabled {
		t.Fatalf("disabled management response=%#v", result)
	}
}

func TestRawCaptureColdDisableRejectsWhenExistingPurgeCannotComplete(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "events.db")
	now := time.Date(2026, 7, 21, 17, 0, 0, 0, time.UTC)
	rawRequest := []byte(`{"messages":[{"role":"user","content":"retained cold-start review canary"}]}`)
	eventID := "01234567-89ab-4def-8123-456789abcdef"
	event := audit.Event{
		ID: eventID, Timestamp: now, Action: "block", Mode: "balanced",
		Category: "exploitation", RiskScore: 90, RequestHash: audit.HashRequest(rawRequest),
		Classifier: "raw-capture-cold-disable-test", Decision: "block_malicious_text",
		Coverage: "complete", Scanner: "streaming-scanner-v1",
	}
	store, err := audit.Open(audit.Config{
		Path: path, Retention: 24 * time.Hour, MaxBytes: 8 << 20,
		RawCapture: audit.RawCaptureConfig{
			Enabled: true, OnlyBlocked: true, MaxBytes: 8192, TTL: 72 * time.Hour, RedactSecrets: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !store.Record(event) {
		t.Fatal("audit event enqueue failed")
	}
	if err := store.RecordRawCapture(audit.RawCaptureInput{
		EventID: eventID, Timestamp: now, RequestHash: event.RequestHash,
		Action: "block", Decision: "block_malicious_text", RawRequest: rawRequest,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	locker, err := sql.Open("sqlite3", "file:"+filepath.ToSlash(path)+"?_busy_timeout=25")
	if err != nil {
		t.Fatal(err)
	}
	defer locker.Close()
	locker.SetMaxOpenConns(1)
	if _, err := locker.Exec("BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	locked := true
	defer func() {
		if locked {
			_, _ = locker.Exec("ROLLBACK")
		}
	}()

	p := New()
	defer p.Shutdown()
	raw, code := p.Call(pluginabi.MethodPluginRegister, lifecyclePayload(t,
		"mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+filepath.ToSlash(directory)+"\"\n  raw_capture:\n    enabled: false\nsubject_control:\n  enabled: false\n"))
	errEnvelope := assertEnvelopeError(t, raw, code, "invalid_config", 0)
	if !strings.Contains(errEnvelope.Message, "disabled raw-capture privacy gate") {
		t.Fatalf("cold-disable error=%q, want explicit privacy-gate failure", errEnvelope.Message)
	}
	if p.runtime.Load() != nil {
		t.Fatal("cold-start purge failure published a disabled runtime")
	}

	if _, err := locker.Exec("ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	locked = false
	reopened, err := audit.Open(audit.Config{
		Path: path, Retention: 24 * time.Hour, MaxBytes: 8 << 20,
		RawCapture: audit.RawCaptureConfig{
			Enabled: true, OnlyBlocked: true, MaxBytes: 8192, TTL: 72 * time.Hour, RedactSecrets: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	page, err := reopened.QueryRawCapturesPage(context.Background(), audit.RawCaptureQuery{Limit: 10})
	if err != nil || len(page.Captures) != 1 {
		t.Fatalf("retained capture page=%#v error=%v, want one row after rejected registration", page, err)
	}
}

func TestRawCaptureHotDisableRejectsWhenPurgeCannotComplete(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	directory := t.TempDir()
	dataDir := filepath.ToSlash(directory)
	register(t, p, "mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\n  raw_capture:\n    enabled: true\n    only_blocked: true\n    redact_secrets: true\n    max_bytes: 8192\n    ttl_hours: 72\nsubject_control:\n  enabled: false\n")
	if route := callRoute(t, p, maliciousRequest); !route.Handled {
		t.Fatalf("malicious fixture was not blocked: %+v", route)
	}
	oldState := p.runtime.Load()
	if err := oldState.audit.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}

	locker, err := sql.Open("sqlite3", "file:"+filepath.ToSlash(filepath.Join(directory, "events.db"))+"?_busy_timeout=50")
	if err != nil {
		t.Fatal(err)
	}
	defer locker.Close()
	locker.SetMaxOpenConns(1)
	if _, err := locker.Exec("BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	locked := true
	defer func() {
		if locked {
			_, _ = locker.Exec("ROLLBACK")
		}
	}()

	raw, code := p.Call(pluginabi.MethodPluginReconfigure, lifecyclePayload(t,
		"mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\n  raw_capture:\n    enabled: false\nsubject_control:\n  enabled: false\n"))
	if code != 0 {
		t.Fatalf("locked purge reconfigure code=%d envelope=%s", code, raw)
	}
	if p.runtime.Load() != oldState || !p.runtime.Load().config.Audit.RawCapture.Enabled {
		t.Fatal("failed purge published the disabled runtime")
	}
	if message := p.lastReconfigureErrorMessage(); !strings.Contains(message, "purge raw request captures") &&
		!strings.Contains(message, "disabled raw-capture privacy gate") {
		t.Fatalf("last reconfigure error=%q, want privacy-safe purge failure", message)
	}
	if _, err := locker.Exec("ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	locked = false

	page, err := oldState.audit.QueryRawCapturesPage(context.Background(), audit.RawCaptureQuery{Limit: 100})
	if err != nil || len(page.Captures) != 1 {
		t.Fatalf("rejected disable lost the active capture runtime: page=%#v err=%v", page, err)
	}
}

func TestRawCaptureFailedMigrationDoesNotPurgeBeforeDisableGate(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	dataDir := filepath.ToSlash(t.TempDir())
	register(t, p, "mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\n  raw_capture:\n    enabled: true\n    only_blocked: true\n    redact_secrets: true\n    max_bytes: 8192\n    ttl_hours: 72\nsubject_control:\n  enabled: true\n  max_subjects: 100\n")
	if route := callRoute(t, p, maliciousRequest); !route.Handled {
		t.Fatalf("malicious fixture was not blocked: %+v", route)
	}
	oldState := p.runtime.Load()
	if err := oldState.audit.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 2; index++ {
		headers := http.Header{"Authorization": []string{fmt.Sprintf("Bearer protected-manual-%d", index)}}
		subjectHash := p.identifier.FromHeaders(headers).Hash
		_ = oldState.subject.Evaluate(subjectHash, 100)
		_ = oldState.subject.Evaluate(subjectHash, 100)
		if decision := oldState.subject.Evaluate(subjectHash, 100); !decision.ManualBlocked {
			t.Fatalf("subject %d did not become a protected manual block: %#v", index, decision)
		}
	}

	raw, code := p.Call(pluginabi.MethodPluginReconfigure, lifecyclePayload(t,
		"mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\n  raw_capture:\n    enabled: false\nsubject_control:\n  enabled: true\n  max_subjects: 1\n"))
	if code != 0 {
		t.Fatalf("failed-migration reconfigure code=%d envelope=%s", code, raw)
	}
	if p.runtime.Load() != oldState || !oldState.config.Audit.RawCapture.Enabled {
		t.Fatal("failed subject migration replaced the previous capture-enabled runtime")
	}
	if !strings.Contains(p.lastReconfigureErrorMessage(), "protected manual blocks") {
		t.Fatalf("last reconfigure error=%q, want subject migration failure", p.lastReconfigureErrorMessage())
	}
	page, err := oldState.audit.QueryRawCapturesPage(context.Background(), audit.RawCaptureQuery{Limit: 100})
	if err != nil || len(page.Captures) != 1 {
		t.Fatalf("failed migration purged the old capture: page=%#v err=%v", page, err)
	}
}

func TestRawCaptureManagementQueryContract(t *testing.T) {
	const eventID = "01234567-89ab-4def-8123-456789abcdef"
	const requestHash = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	query, err := rawCaptureQuery(url.Values{
		"event_id":     []string{eventID},
		"request_hash": []string{requestHash},
		"limit":        []string{"100"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if query.EventID != eventID || query.RequestHash != requestHash || query.Limit != 100 {
		t.Fatalf("raw capture query=%+v", query)
	}

	for _, testCase := range []struct {
		name   string
		values url.Values
	}{
		{name: "unknown key", values: url.Values{"offset": []string{"1"}}},
		{name: "duplicate key", values: url.Values{"limit": []string{"1", "2"}}},
		{name: "invalid event id", values: url.Values{"event_id": []string{"../events"}}},
		{name: "invalid request hash", values: url.Values{"request_hash": []string{"sha256:not-a-digest"}}},
		{name: "limit zero", values: url.Values{"limit": []string{"0"}}},
		{name: "limit above maximum", values: url.Values{"limit": []string{"101"}}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := rawCaptureQuery(testCase.values); err == nil {
				t.Fatal("rawCaptureQuery accepted invalid input")
			}
		})
	}
}

func TestRawCaptureManagementRejectsBody(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, "audit:\n  enabled: false\n")

	request := authenticatedManagementRequest(http.MethodGet, managementBasePath+"/raw-captures", []byte(`{}`))
	response, body := callManagementResponse(t, p, request)
	if response.StatusCode != http.StatusBadRequest || bodyErrorCode(body) != "invalid_request" {
		t.Fatalf("raw capture body response=%+v body=%s", response, body)
	}
}
