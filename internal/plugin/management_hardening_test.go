package plugin

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/yujianwudi/cyber-abuse-guard/internal/audit"
	"github.com/yujianwudi/cyber-abuse-guard/internal/subject"
)

func TestManagementRejectsMissingCredentialAtPluginBoundary(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, "audit:\n  enabled: false\n")

	response, body := callManagementResponse(t, p, pluginapi.ManagementRequest{
		Method: http.MethodGet,
		Path:   managementBasePath + "/status",
	})
	if response.StatusCode != http.StatusUnauthorized || bodyErrorCode(body) != "unauthorized" {
		t.Fatalf("missing management credential response=%+v body=%s", response, body)
	}
}

func TestManagementUnblockAuthenticationAndBodyContract(t *testing.T) {
	const subjectHash = "hmac-sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	for _, testCase := range []struct {
		name          string
		body          string
		authenticated bool
		wantStatus    int
		wantCode      string
	}{
		{name: "official subject_hash", body: `{"subject_hash":"` + subjectHash + `"}`, authenticated: true, wantStatus: http.StatusOK},
		{name: "legacy hash", body: `{"hash":"` + subjectHash + `"}`, authenticated: true, wantStatus: http.StatusOK},
		{name: "matching official and legacy fields", body: `{"subject_hash":"` + subjectHash + `","hash":"` + subjectHash + `"}`, authenticated: true, wantStatus: http.StatusOK},
		{name: "conflicting fields", body: `{"subject_hash":"` + subjectHash + `","hash":"hmac-sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"}`, authenticated: true, wantStatus: http.StatusBadRequest, wantCode: "invalid_subject"},
		{name: "unknown field", body: `{"subject":"` + subjectHash + `"}`, authenticated: true, wantStatus: http.StatusBadRequest, wantCode: "invalid_subject"},
		{name: "missing credential", body: `{"subject_hash":"` + subjectHash + `"}`, authenticated: false, wantStatus: http.StatusUnauthorized, wantCode: "unauthorized"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			p := New()
			t.Cleanup(p.Shutdown)
			register(t, p, "audit:\n  enabled: false\nsubject_control:\n  enabled: true\n")
			state := p.runtime.Load()
			for iteration := 0; iteration < 3; iteration++ {
				state.subject.Evaluate(subjectHash, 100)
			}
			before, ok := state.subject.Snapshot(subjectHash)
			if !ok || !before.ManualBlocked {
				t.Fatalf("setup subject was not manually blocked: state=%+v found=%t", before, ok)
			}

			request := pluginapi.ManagementRequest{
				Method: http.MethodPost,
				Path:   managementBasePath + "/subjects/unblock",
				Body:   []byte(testCase.body),
			}
			if testCase.authenticated {
				request.Headers = http.Header{"X-Management-Key": []string{"unit-test-management-key"}}
			}
			response, body := callManagementResponse(t, p, request)
			if response.StatusCode != testCase.wantStatus || bodyErrorCode(body) != testCase.wantCode {
				t.Fatalf("response status=%d body=%s, want %d/%s", response.StatusCode, body, testCase.wantStatus, testCase.wantCode)
			}

			_, stillPresent := state.subject.Snapshot(subjectHash)
			if testCase.wantStatus == http.StatusOK {
				if stillPresent {
					t.Fatal("successful unblock left subject state allocated")
				}
				var result map[string]any
				if err := json.Unmarshal(body, &result); err != nil {
					t.Fatal(err)
				}
				if result["unblocked"] != true || result["subject_hash"] != subjectHash {
					t.Fatalf("unblock response did not use the official contract: %#v", result)
				}
			} else if !stillPresent {
				t.Fatal("rejected unblock mutated subject state")
			}
		})
	}
}

func TestManagementBoundsAndQueryWhitelist(t *testing.T) {
	const queryKeyCanary = "MANAGEMENT_QUERY_KEY_CANARY_2f64a9b1"
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, "audit:\n  enabled: false\n")
	auth := http.Header{"X-Management-Key": []string{"unit-test-management-key"}}

	tests := []struct {
		name       string
		request    pluginapi.ManagementRequest
		wantStatus int
		wantCode   string
		forbidden  string
	}{
		{
			name: "oversized body",
			request: pluginapi.ManagementRequest{Method: http.MethodPost, Path: managementBasePath + "/test", Headers: auth,
				Body: make([]byte, maxManagementBody+1)},
			wantStatus: http.StatusRequestEntityTooLarge,
			wantCode:   "request_too_large",
		},
		{
			name:       "oversized path",
			request:    pluginapi.ManagementRequest{Method: http.MethodGet, Path: "/" + strings.Repeat("a", maxManagementPathBytes), Headers: auth},
			wantStatus: http.StatusRequestURITooLong,
			wantCode:   "path_too_long",
		},
		{
			name:       "path traversal",
			request:    pluginapi.ManagementRequest{Method: http.MethodGet, Path: managementBasePath + "/../status", Headers: auth},
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_path",
		},
		{
			name:       "encoded path traversal",
			request:    pluginapi.ManagementRequest{Method: http.MethodGet, Path: managementBasePath + "/%2e%2e/status", Headers: auth},
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_path",
		},
		{
			name: "unknown query key",
			request: pluginapi.ManagementRequest{Method: http.MethodGet, Path: managementBasePath + "/events", Headers: auth,
				Query: url.Values{queryKeyCanary: []string{"timestamp"}}},
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_query",
			forbidden:  queryKeyCanary,
		},
		{
			name: "SQL injection style category",
			request: pluginapi.ManagementRequest{Method: http.MethodGet, Path: managementBasePath + "/events", Headers: auth,
				Query: url.Values{"category": []string{"x' OR 1=1 --"}}},
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_query",
		},
		{
			name: "SQL injection style delete query",
			request: pluginapi.ManagementRequest{Method: http.MethodDelete, Path: managementBasePath + "/events", Headers: auth,
				Query: url.Values{"category": []string{"x' OR 1=1 --"}}},
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_query",
		},
		{
			name: "duplicate query key",
			request: pluginapi.ManagementRequest{Method: http.MethodGet, Path: managementBasePath + "/events", Headers: auth,
				Query: url.Values{"limit": []string{"10", "20"}}},
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_query",
		},
		{
			name: "query forbidden on stats",
			request: pluginapi.ManagementRequest{Method: http.MethodGet, Path: managementBasePath + "/stats", Headers: auth,
				Query: url.Values{"limit": []string{"10"}}},
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_request",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			response, body := callManagementResponse(t, p, testCase.request)
			if response.StatusCode != testCase.wantStatus || bodyErrorCode(body) != testCase.wantCode {
				t.Fatalf("response status=%d body=%s, want %d/%s", response.StatusCode, body, testCase.wantStatus, testCase.wantCode)
			}
			if testCase.forbidden != "" && strings.Contains(string(body), testCase.forbidden) {
				t.Fatal("management error reflected a caller-controlled query key")
			}
		})
	}
}

func TestManagementRejectsOversizedRPCEnvelope(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)

	raw, code := p.Call(pluginabi.MethodManagementHandle, make([]byte, maxManagementEnvelope+1))
	if code != 0 {
		t.Fatalf("oversized management envelope call code = %d; envelope=%s", code, raw)
	}
	var response pluginapi.ManagementResponse
	decodeOKResult(t, raw, &response)
	if response.StatusCode != http.StatusRequestEntityTooLarge || bodyErrorCode(response.Body) != "request_too_large" {
		t.Fatalf("oversized management envelope response=%+v body=%s", response, response.Body)
	}
}

func TestManagementEventDeletionWritesPrivacySafeAuditMarker(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, "mode: audit\naudit:\n  enabled: true\n  data_dir: \""+strings.ReplaceAll(t.TempDir(), "\\", "/")+"\"\nsubject_control:\n  enabled: false\n")

	if route := callRoute(t, p, maliciousRequest); route.Handled {
		t.Fatalf("audit mode unexpectedly blocked setup request: %+v", route)
	}
	response, body := callManagementResponse(t, p, authenticatedManagementRequest(http.MethodDelete, managementBasePath+"/events", nil))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", response.StatusCode, body)
	}
	events := managementJSON(t, p, http.MethodGet, managementBasePath+"/events", nil)
	items, ok := events["events"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("post-delete audit events=%#v, want one mutation marker", events)
	}
	marker, ok := items[0].(map[string]any)
	if !ok || marker["classifier"] != "management_delete_events" || marker["category"] != "management_operation" || marker["action"] != "audit" {
		t.Fatalf("delete audit marker=%#v", items[0])
	}
	encoded, _ := json.Marshal(marker)
	if strings.Contains(string(encoded), "browser cookies") {
		t.Fatalf("delete marker contained request text: %s", encoded)
	}
}

func TestObserveManagementMutationsStillWriteAuditMarkers(t *testing.T) {
	t.Run("delete events", func(t *testing.T) {
		p := New()
		t.Cleanup(p.Shutdown)
		register(t, p, "mode: observe\naudit:\n  enabled: true\n  data_dir: \""+strings.ReplaceAll(t.TempDir(), "\\", "/")+"\"\nsubject_control:\n  enabled: false\n")

		response, body := callManagementResponse(t, p, authenticatedManagementRequest(http.MethodDelete, managementBasePath+"/events", nil))
		if response.StatusCode != http.StatusOK {
			t.Fatalf("observe delete status=%d body=%s", response.StatusCode, body)
		}
		events := managementJSON(t, p, http.MethodGet, managementBasePath+"/events", nil)
		items, ok := events["events"].([]any)
		if !ok || len(items) != 1 {
			t.Fatalf("observe delete events=%#v, want one mutation marker", events)
		}
		marker, ok := items[0].(map[string]any)
		if !ok || marker["classifier"] != "management_delete_events" || marker["category"] != "management_operation" {
			t.Fatalf("observe delete marker=%#v", items[0])
		}
	})

	t.Run("unblock subject", func(t *testing.T) {
		const subjectHash = "hmac-sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		p := New()
		t.Cleanup(p.Shutdown)
		register(t, p, "mode: observe\naudit:\n  enabled: true\n  data_dir: \""+strings.ReplaceAll(t.TempDir(), "\\", "/")+"\"\nsubject_control:\n  enabled: true\n")
		state := p.runtime.Load()
		for iteration := 0; iteration < 3; iteration++ {
			state.subject.Evaluate(subjectHash, 100)
		}

		response, body := callManagementResponse(t, p, authenticatedManagementRequest(
			http.MethodPost,
			managementBasePath+"/subjects/unblock",
			[]byte(`{"subject_hash":"`+subjectHash+`"}`),
		))
		if response.StatusCode != http.StatusOK {
			t.Fatalf("observe unblock status=%d body=%s", response.StatusCode, body)
		}
		events := managementJSON(t, p, http.MethodGet, managementBasePath+"/events", nil)
		items, ok := events["events"].([]any)
		if !ok || len(items) != 1 {
			t.Fatalf("observe unblock events=%#v, want one mutation marker", events)
		}
		marker, ok := items[0].(map[string]any)
		if !ok || marker["classifier"] != "management_unblock" || marker["category"] != "management_operation" || marker["subject_hash"] != subjectHash {
			t.Fatalf("observe unblock marker=%#v", items[0])
		}
	})
}

func TestManagementObserveActionFilterSupportsGetAndDelete(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, "mode: observe\naudit:\n  enabled: true\n  data_dir: \""+strings.ReplaceAll(t.TempDir(), "\\", "/")+"\"\nsubject_control:\n  enabled: false\n")

	state := p.runtime.Load()
	for _, event := range []audit.Event{
		{
			Action:     "observe",
			Mode:       "observe",
			Category:   "observe_fixture",
			Decision:   "observe_malicious_text",
			Coverage:   "complete",
			Scanner:    streamingScannerIdentity,
			Classifier: "management_filter_test",
		},
		{
			Action:     "audit",
			Mode:       "audit",
			Category:   "audit_fixture",
			Decision:   "audit_malicious_text",
			Coverage:   "complete",
			Scanner:    streamingScannerIdentity,
			Classifier: "management_filter_test",
		},
	} {
		if !state.audit.Record(event) {
			t.Fatalf("failed to enqueue %q fixture", event.Action)
		}
	}

	observeQuery := url.Values{"action": []string{"observe"}}
	request := authenticatedManagementRequest(http.MethodGet, managementBasePath+"/events", nil)
	request.Query = observeQuery
	response, body := callManagementResponse(t, p, request)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("observe GET status=%d body=%s", response.StatusCode, body)
	}
	var queried struct {
		Events []audit.Event `json:"events"`
	}
	if err := json.Unmarshal(body, &queried); err != nil {
		t.Fatal(err)
	}
	if len(queried.Events) != 1 || queried.Events[0].Action != "observe" || queried.Events[0].Category != "observe_fixture" {
		t.Fatalf("observe GET events=%+v, want only observe fixture", queried.Events)
	}

	request = authenticatedManagementRequest(http.MethodDelete, managementBasePath+"/events", nil)
	request.Query = observeQuery
	response, body = callManagementResponse(t, p, request)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("observe DELETE status=%d body=%s", response.StatusCode, body)
	}
	var deletion struct {
		Deleted int64 `json:"deleted"`
	}
	if err := json.Unmarshal(body, &deletion); err != nil {
		t.Fatal(err)
	}
	if deletion.Deleted != 1 {
		t.Fatalf("observe DELETE deleted=%d, want 1", deletion.Deleted)
	}

	request = authenticatedManagementRequest(http.MethodGet, managementBasePath+"/events", nil)
	request.Query = observeQuery
	response, body = callManagementResponse(t, p, request)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("post-delete observe GET status=%d body=%s", response.StatusCode, body)
	}
	if err := json.Unmarshal(body, &queried); err != nil {
		t.Fatal(err)
	}
	if len(queried.Events) != 0 {
		t.Fatalf("post-delete observe events=%+v, want none", queried.Events)
	}

	auditRequest := authenticatedManagementRequest(http.MethodGet, managementBasePath+"/events", nil)
	auditRequest.Query = url.Values{"action": []string{"audit"}, "category": []string{"audit_fixture"}}
	response, body = callManagementResponse(t, p, auditRequest)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("selective audit GET status=%d body=%s", response.StatusCode, body)
	}
	if err := json.Unmarshal(body, &queried); err != nil {
		t.Fatal(err)
	}
	if len(queried.Events) != 1 || queried.Events[0].Action != "audit" || queried.Events[0].Category != "audit_fixture" {
		t.Fatalf("observe DELETE removed non-observe fixture: %+v", queried.Events)
	}
}

func TestManagementHealthProbeIsLocalReadOnlyAndBounded(t *testing.T) {
	t.Setenv(subject.HMACKeyEnvironment, "0123456789abcdef0123456789abcdef")
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, "mode: observe\naudit:\n  enabled: false\nsubject_control:\n  enabled: true\n")

	beforeCounters := p.counters.snapshot()
	beforeSubjects := p.runtime.Load().subject.Stats().Subjects

	for _, testCase := range []struct {
		kind       string
		wantStatus int
		wantAction string
		wantSelf   bool
	}{
		{kind: "benign", wantStatus: http.StatusOK, wantAction: "allow", wantSelf: false},
		{kind: "malicious", wantStatus: http.StatusForbidden, wantAction: "block", wantSelf: true},
	} {
		request := authenticatedManagementRequest(http.MethodPost, managementHealthProbePath, []byte(`{"kind":"`+testCase.kind+`"}`))
		response, body := callManagementResponse(t, p, request)
		if response.StatusCode != testCase.wantStatus {
			t.Fatalf("%s probe status=%d body=%s", testCase.kind, response.StatusCode, body)
		}
		var result map[string]any
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatal(err)
		}
		if result["action"] != testCase.wantAction || result["local_only"] != true || result["upstream_attempted"] != false || result["self_route"] != testCase.wantSelf {
			t.Fatalf("%s probe result=%#v", testCase.kind, result)
		}
		if testCase.wantSelf && result["target_kind"] != string(pluginapi.ModelRouteTargetSelf) {
			t.Fatalf("malicious probe target=%#v", result["target_kind"])
		}
	}

	response, body := callManagementResponse(t, p, authenticatedManagementRequest(http.MethodPost, managementHealthProbePath,
		[]byte(`{"kind":"malicious","text":"caller supplied payload"}`)))
	if response.StatusCode != http.StatusBadRequest || bodyErrorCode(body) != "invalid_request" {
		t.Fatalf("health probe accepted arbitrary text: status=%d body=%s", response.StatusCode, body)
	}
	if got := p.counters.snapshot(); !equalCounters(got, beforeCounters) {
		t.Fatalf("read-only health probes changed counters: before=%v after=%v", beforeCounters, got)
	}
	if got := p.runtime.Load().subject.Stats().Subjects; got != beforeSubjects {
		t.Fatalf("read-only health probes changed subject state: before=%d after=%d", beforeSubjects, got)
	}
}

func TestManagementConcurrencyAndAuditDegradationDoNotWeakenRouting(t *testing.T) {
	t.Setenv(subject.HMACKeyEnvironment, "0123456789abcdef0123456789abcdef")
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, "mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+strings.ReplaceAll(t.TempDir(), "\\", "/")+"\"\nsubject_control:\n  enabled: false\n")

	state := p.runtime.Load()
	if err := state.audit.Close(); err != nil {
		t.Fatal(err)
	}
	if route := callRoute(t, p, maliciousRequest); !route.Handled || route.TargetKind != pluginapi.ModelRouteTargetSelf {
		t.Fatalf("closed audit store weakened router enforcement: %+v", route)
	}
	status := managementJSON(t, p, http.MethodGet, managementBasePath+"/status", nil)
	if status["audit_degraded"] != true || status["enforcement_ready"] != true {
		t.Fatalf("degraded audit health status=%#v", status)
	}

	var wait sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < 25; iteration++ {
				request := authenticatedManagementRequest(http.MethodGet, managementBasePath+"/events", nil)
				request.Query = url.Values{"limit": []string{"10"}}
				callManagementNoFail(p, request)
				callManagementNoFail(p, authenticatedManagementRequest(http.MethodDelete, managementBasePath+"/events", nil))
				callManagementNoFail(p, authenticatedManagementRequest(http.MethodGet, managementBasePath+"/status", nil))
			}
		}()
	}
	wait.Wait()
	if route := callRoute(t, p, maliciousRequest); !route.Handled {
		t.Fatalf("concurrent degraded management traffic weakened router: %+v", route)
	}
}

func authenticatedManagementRequest(method, path string, body []byte) pluginapi.ManagementRequest {
	return pluginapi.ManagementRequest{
		Method:  method,
		Path:    path,
		Headers: http.Header{"X-Management-Key": []string{"unit-test-management-key"}},
		Body:    body,
	}
}

func callManagementResponse(t testing.TB, p *Plugin, request pluginapi.ManagementRequest) (pluginapi.ManagementResponse, []byte) {
	t.Helper()
	rawRequest, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	raw, code := p.Call(pluginabi.MethodManagementHandle, rawRequest)
	if code != 0 {
		t.Fatalf("management.handle code=%d envelope=%s", code, raw)
	}
	var response pluginapi.ManagementResponse
	decodeOKResult(t, raw, &response)
	return response, response.Body
}

func callManagementNoFail(p *Plugin, request pluginapi.ManagementRequest) {
	rawRequest, _ := json.Marshal(request)
	p.Call(pluginabi.MethodManagementHandle, rawRequest)
}

func bodyErrorCode(body []byte) string {
	var response struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &response)
	return response.Error.Code
}

func equalCounters(left, right map[string]uint64) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}
