package plugin

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestOversizedModelRouteIsModeAwareAndFailClosed(t *testing.T) {
	oversized := make([]byte, maxRPCRequestBytes+1)
	for _, testCase := range []struct {
		mode        string
		wantHandled bool
	}{
		{mode: "balanced", wantHandled: true},
		{mode: "strict", wantHandled: true},
		{mode: "audit", wantHandled: false},
		{mode: "observe", wantHandled: false},
		{mode: "off", wantHandled: false},
	} {
		t.Run(testCase.mode, func(t *testing.T) {
			p := New()
			register(t, p, "mode: "+testCase.mode+"\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n")
			raw, code := p.Call(pluginabi.MethodModelRoute, oversized)
			p.Shutdown()
			if code != 0 {
				t.Fatalf("oversized model.route code=%d envelope=%s", code, raw)
			}
			var route pluginapi.ModelRouteResponse
			decodeOKResult(t, raw, &route)
			if route.Handled != testCase.wantHandled {
				t.Fatalf("mode=%s oversized route Handled=%v, want %v; route=%+v", testCase.mode, route.Handled, testCase.wantHandled, route)
			}
			if testCase.wantHandled && route.Reason != "cyber_abuse_guard_scan_limit" {
				t.Fatalf("mode=%s oversized route reason=%q", testCase.mode, route.Reason)
			}
		})
	}
}

func TestOversizedExecutorReturnsLocalPolicyRefusal(t *testing.T) {
	p := New()
	defer p.Shutdown()
	register(t, p, "mode: balanced\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n")
	for _, method := range []string{pluginabi.MethodExecutorExecute, pluginabi.MethodExecutorExecuteStream} {
		raw, code := p.CallOversized(method)
		if code != 0 {
			t.Fatalf("%s code=%d envelope=%s", method, code, raw)
		}
		var envelope struct {
			OK    bool `json:"ok"`
			Error struct {
				Code       string `json:"code"`
				HTTPStatus int    `json:"http_status"`
				Category   string `json:"category"`
			} `json:"error"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			t.Fatal(err)
		}
		if envelope.OK || envelope.Error.Code != blockedErrorCode || envelope.Error.HTTPStatus != 403 || envelope.Error.Category != "scan_limit" {
			t.Fatalf("%s oversized refusal=%s", method, raw)
		}
	}
}

func TestOversizedNonRoutingRPCRemainsRejected(t *testing.T) {
	p := New()
	defer p.Shutdown()
	raw, code := p.CallOversized(pluginabi.MethodPluginRegister)
	if code != 0 || !json.Valid(raw) || string(raw) == "" {
		t.Fatalf("oversized non-routing RPC code=%d envelope=%s", code, raw)
	}
	var envelope struct {
		OK    bool `json:"ok"`
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil || envelope.OK || envelope.Error.Code != "request_too_large" {
		t.Fatalf("oversized non-routing RPC envelope=%s err=%v", raw, err)
	}
}

func TestOversizedRouteWritesPrivacyMinimalAuditEvent(t *testing.T) {
	for _, testCase := range []struct {
		mode       string
		wantAction string
	}{
		{mode: "balanced", wantAction: "block"},
		{mode: "audit", wantAction: "audit"},
	} {
		t.Run(testCase.mode, func(t *testing.T) {
			p := New()
			defer p.Shutdown()
			dataDir := filepath.ToSlash(t.TempDir())
			register(t, p, "mode: "+testCase.mode+"\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\nsubject_control:\n  enabled: false\n")
			if _, code := p.CallOversized(pluginabi.MethodModelRoute); code != 0 {
				t.Fatalf("oversized model.route code=%d", code)
			}
			events := managementJSON(t, p, http.MethodGet, managementBasePath+"/events", nil)
			items, ok := events["events"].([]any)
			if !ok || len(items) != 1 {
				t.Fatalf("oversized audit events=%#v", events)
			}
			event := items[0].(map[string]any)
			if event["action"] != testCase.wantAction || event["category"] != "scan_limit" {
				t.Fatalf("oversized event=%#v", event)
			}
			for _, key := range []string{"request_hash", "model", "source_format"} {
				if value, exists := event[key]; exists && value != "" {
					t.Fatalf("oversized event invented unavailable %s: %#v", key, event)
				}
			}
			if scanned, ok := event["text_bytes_scanned"].(float64); !ok || scanned != 0 {
				t.Fatalf("oversized event claimed bytes were scanned: %#v", event)
			}
		})
	}
}
