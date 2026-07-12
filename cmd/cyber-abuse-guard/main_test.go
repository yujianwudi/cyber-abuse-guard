package main

import (
	"encoding/json"
	"net/http"
	"testing"

	guardplugin "cyber-abuse-guard/internal/plugin"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
)

func TestABIEnvelopeRegistrationAndFailClosedExecutor(t *testing.T) {
	if abiVersion != pluginabi.ABIVersion {
		t.Fatalf("abiVersion = %d, want %d", abiVersion, pluginabi.ABIVersion)
	}
	previous := activePlugin
	activePlugin = guardplugin.New()
	t.Cleanup(func() {
		activePlugin.Shutdown()
		activePlugin = previous
	})

	lifecycle, _ := json.Marshal(map[string]any{
		"schema_version": pluginabi.SchemaVersion,
		"config_yaml":    []byte("audit:\n  enabled: false\n"),
	})
	raw, code := handlePluginCall(pluginabi.MethodPluginRegister, lifecycle)
	if code != 0 {
		t.Fatalf("plugin.register code=%d envelope=%s", code, raw)
	}
	var registerEnvelope struct {
		OK     bool `json:"ok"`
		Result struct {
			SchemaVersion uint32 `json:"schema_version"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &registerEnvelope); err != nil || !registerEnvelope.OK || registerEnvelope.Result.SchemaVersion != 1 {
		t.Fatalf("invalid registration envelope %s: %v", raw, err)
	}

	raw, code = handlePluginCall(pluginabi.MethodExecutorExecuteStream, []byte(`{"OriginalRequest":"e30="}`))
	if code != 0 {
		t.Fatalf("executor.execute_stream controlled block code=%d envelope=%s", code, raw)
	}
	var blockEnvelope struct {
		OK    bool `json:"ok"`
		Error struct {
			Code       string `json:"code"`
			HTTPStatus int    `json:"http_status"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &blockEnvelope); err != nil {
		t.Fatalf("decode block envelope: %v", err)
	}
	if blockEnvelope.OK || blockEnvelope.Error.Code != "cyber_abuse_guard_blocked" || blockEnvelope.Error.HTTPStatus != http.StatusForbidden {
		t.Fatalf("block envelope = %s", raw)
	}
}

func TestABIUnknownMethodAndMalformedRequestAreContained(t *testing.T) {
	previous := activePlugin
	activePlugin = guardplugin.New()
	t.Cleanup(func() {
		activePlugin.Shutdown()
		activePlugin = previous
	})

	for _, tc := range []struct {
		method  string
		request []byte
		code    string
	}{
		{method: "not.a.real.method", request: []byte(`{}`), code: "unknown_method"},
		{method: pluginabi.MethodModelRoute, request: []byte(`{"Body":`), code: "invalid_request"},
	} {
		raw, callCode := handlePluginCall(tc.method, tc.request)
		if callCode != 0 {
			t.Fatalf("%s controlled error call code=%d envelope=%s", tc.method, callCode, raw)
		}
		var envelope struct {
			OK    bool `json:"ok"`
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil || envelope.OK || envelope.Error.Code != tc.code {
			t.Fatalf("%s envelope=%s err=%v", tc.method, raw, err)
		}
	}
}
