package plugin

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"cyber-abuse-guard/internal/audit"
	"cyber-abuse-guard/internal/classifier"
	"cyber-abuse-guard/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const (
	managementBasePath = "/v0/management/plugins/" + ID
	maxManagementBody  = 1 << 20
)

type managementRoute struct {
	Method      string `json:"Method"`
	Path        string `json:"Path"`
	Menu        string `json:"Menu,omitempty"`
	Description string `json:"Description,omitempty"`
}

type managementRegistration struct {
	Routes    []managementRoute `json:"routes"`
	Resources []any             `json:"resources"`
}

func (p *Plugin) registerManagement(raw []byte) []byte {
	if len(raw) != 0 {
		var request pluginapi.ManagementRegistrationRequest
		if err := json.Unmarshal(raw, &request); err != nil {
			return errorEnvelope("invalid_request", "invalid management registration request", 0, "")
		}
	}
	return okEnvelope(managementRegistration{
		Routes: []managementRoute{
			{Method: http.MethodGet, Path: managementBasePath + "/status"},
			{Method: http.MethodGet, Path: managementBasePath + "/events"},
			{Method: http.MethodGet, Path: managementBasePath + "/stats"},
			{Method: http.MethodPost, Path: managementBasePath + "/test"},
			{Method: http.MethodPost, Path: managementBasePath + "/subjects/unblock"},
			{Method: http.MethodDelete, Path: managementBasePath + "/events"},
		},
		Resources: []any{},
	})
}

func (p *Plugin) handleManagement(raw []byte) []byte {
	if len(raw) > maxManagementBody*2 {
		return managementError(http.StatusRequestEntityTooLarge, "request_too_large", "management request exceeds the size limit")
	}
	var request pluginapi.ManagementRequest
	if err := json.Unmarshal(raw, &request); err != nil {
		return errorEnvelope("invalid_request", "invalid management request", 0, "")
	}
	if len(request.Body) > maxManagementBody {
		return managementError(http.StatusRequestEntityTooLarge, "request_too_large", "management request body exceeds the size limit")
	}

	p.opMu.RLock()
	defer p.opMu.RUnlock()
	state, err := p.loadRuntime()
	if err != nil {
		return managementError(http.StatusServiceUnavailable, "not_initialized", err.Error())
	}

	switch {
	case request.Method == http.MethodGet && request.Path == managementBasePath+"/status":
		return p.managementStatus(state)
	case request.Method == http.MethodGet && request.Path == managementBasePath+"/events":
		return p.managementEvents(state, request.Query)
	case request.Method == http.MethodGet && request.Path == managementBasePath+"/stats":
		return p.managementStats(state)
	case request.Method == http.MethodPost && request.Path == managementBasePath+"/test":
		return p.managementTest(state, request.Body)
	case request.Method == http.MethodPost && request.Path == managementBasePath+"/subjects/unblock":
		return p.managementUnblock(state, request.Body)
	case request.Method == http.MethodDelete && request.Path == managementBasePath+"/events":
		return p.managementDeleteEvents(state, request.Query)
	default:
		return managementError(http.StatusNotFound, "not_found", "management route not found")
	}
}

func (p *Plugin) managementStatus(state *runtimeState) []byte {
	auditStatus := any(map[string]any{"enabled": false})
	if state.audit != nil {
		auditStatus = struct {
			Enabled bool `json:"enabled"`
			audit.Status
		}{Enabled: true, Status: state.audit.Status()}
	}
	identifierStatus := any(map[string]any{"degraded": true})
	if p.identifier != nil {
		identifierStatus = p.identifier.Status()
	}
	body := map[string]any{
		"id":                 ID,
		"name":               metadata.Name,
		"version":            Version,
		"initialized":        true,
		"enabled":            state.config.Enabled,
		"mode":               state.config.Mode,
		"priority":           state.config.Priority,
		"ruleset_version":    state.rulesVersion,
		"started_at":         state.startedAt,
		"last_config_error":  p.lastConfigErrorMessage(),
		"counters":           p.counters.snapshot(),
		"audit":              auditStatus,
		"subject_identifier": identifierStatus,
		"subjects":           state.subject.Count(),
		"classifier": map[string]any{
			"kind":    "deterministic_local_rules",
			"enabled": state.config.Enabled,
			"remote":  false,
		},
		"thresholds": state.config.Thresholds,
	}
	return managementJSONResponse(http.StatusOK, body)
}

func (p *Plugin) managementEvents(state *runtimeState, values url.Values) []byte {
	query, err := auditQuery(values)
	if err != nil {
		return managementError(http.StatusBadRequest, "invalid_query", err.Error())
	}
	if state.audit == nil {
		return managementJSONResponse(http.StatusOK, map[string]any{"events": []audit.Event{}})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = state.audit.Flush(ctx)
	events, err := state.audit.Query(ctx, query)
	if err != nil {
		return managementError(http.StatusServiceUnavailable, "audit_unavailable", "audit events are temporarily unavailable")
	}
	return managementJSONResponse(http.StatusOK, map[string]any{"events": events})
}

func (p *Plugin) managementStats(state *runtimeState) []byte {
	if state.audit == nil {
		return managementJSONResponse(http.StatusOK, map[string]any{
			"total":       0,
			"by_action":   map[string]int64{},
			"by_category": map[string]int64{},
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = state.audit.Flush(ctx)
	stats, err := state.audit.Stats(ctx)
	if err != nil {
		return managementError(http.StatusServiceUnavailable, "audit_unavailable", "audit statistics are temporarily unavailable")
	}
	return managementJSONResponse(http.StatusOK, stats)
}

type managementTestRequest struct {
	Text  string   `json:"text"`
	Parts []string `json:"parts"`
	Mode  string   `json:"mode"`
}

func (p *Plugin) managementTest(state *runtimeState, raw []byte) []byte {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var request managementTestRequest
	if err := decoder.Decode(&request); err != nil {
		return managementError(http.StatusBadRequest, "invalid_request", "test body must be a JSON object containing text or parts")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return managementError(http.StatusBadRequest, "invalid_request", "test body must contain exactly one JSON object")
	}
	parts := append([]string(nil), request.Parts...)
	if request.Text != "" {
		parts = append(parts, request.Text)
	}
	if len(parts) == 0 {
		return managementError(http.StatusBadRequest, "invalid_request", "test text is required")
	}
	if len(parts) > state.config.MaxTextParts {
		return managementError(http.StatusRequestEntityTooLarge, "request_too_large", "test input exceeds max_text_parts")
	}
	totalBytes := 0
	for _, part := range parts {
		totalBytes += len(part)
		if totalBytes > state.config.MaxScanBytes {
			return managementError(http.StatusRequestEntityTooLarge, "request_too_large", "test text exceeds max_scan_bytes")
		}
	}
	mode := state.config.Mode
	if request.Mode != "" {
		mode = config.Mode(strings.ToLower(strings.TrimSpace(request.Mode)))
		switch mode {
		case config.ModeOff, config.ModeObserve, config.ModeAudit, config.ModeBalanced, config.ModeStrict:
		default:
			return managementError(http.StatusBadRequest, "invalid_mode", "test mode is invalid")
		}
	}
	result := state.classifier.ClassifyWithPolicy(parts, classifierMode(mode), classifier.Thresholds{
		Audit:         state.config.Thresholds.Audit,
		BalancedBlock: state.config.Thresholds.BalancedBlock,
		HardBlock:     state.config.Thresholds.HardBlock,
	}, classifierPolicy(state.config))
	policyConfig := state.config
	policyConfig.Mode = mode
	if mode == config.ModeObserve && result.Score >= policyConfig.Thresholds.Audit {
		result.Action = classifier.ActionObserve
	}
	if mode == config.ModeAudit && result.Score >= policyConfig.Thresholds.Audit {
		result.Action = classifier.ActionAudit
	}
	p.counters.managementTests.Add(1)
	return managementJSONResponse(http.StatusOK, map[string]any{
		"score":           result.Score,
		"category":        result.Category,
		"action":          result.Action,
		"rule_ids":        result.RuleIDs,
		"context":         result.Context,
		"truncated":       result.Truncated,
		"ruleset_version": result.RuleSetVersion,
	})
}

type unblockRequest struct {
	Hash string `json:"hash"`
}

func (p *Plugin) managementUnblock(state *runtimeState, raw []byte) []byte {
	var request unblockRequest
	if err := json.Unmarshal(raw, &request); err != nil || !validSubjectHash(request.Hash) {
		return managementError(http.StatusBadRequest, "invalid_subject", "a valid subject hash is required")
	}
	if !state.subject.Unblock(request.Hash) {
		return managementError(http.StatusNotFound, "subject_not_found", "subject was not found")
	}
	return managementJSONResponse(http.StatusOK, map[string]any{"unblocked": true, "hash": request.Hash})
}

func (p *Plugin) managementDeleteEvents(state *runtimeState, values url.Values) []byte {
	if state.audit == nil {
		return managementJSONResponse(http.StatusOK, map[string]any{"deleted": 0})
	}
	query, err := auditQuery(values)
	if err != nil {
		return managementError(http.StatusBadRequest, "invalid_query", err.Error())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = state.audit.Flush(ctx)
	deleted, err := state.audit.Delete(ctx, query)
	if err != nil {
		return managementError(http.StatusServiceUnavailable, "audit_unavailable", "audit events could not be deleted")
	}
	return managementJSONResponse(http.StatusOK, map[string]any{"deleted": deleted})
}

func auditQuery(values url.Values) (audit.Query, error) {
	query := audit.Query{Action: values.Get("action"), Category: values.Get("category"), SubjectHash: values.Get("subject_hash")}
	if raw := values.Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 1000 {
			return audit.Query{}, fmt.Errorf("limit must be between 1 and 1000")
		}
		query.Limit = value
	}
	if raw := values.Get("offset"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 0 || value > 1_000_000 {
			return audit.Query{}, fmt.Errorf("offset must be between 0 and 1000000")
		}
		query.Offset = value
	}
	if raw := values.Get("since"); raw != "" {
		value, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return audit.Query{}, fmt.Errorf("since must be RFC3339")
		}
		query.Since = value
	}
	if raw := values.Get("until"); raw != "" {
		value, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return audit.Query{}, fmt.Errorf("until must be RFC3339")
		}
		query.Until = value
	}
	if !query.Since.IsZero() && !query.Until.IsZero() && query.Since.After(query.Until) {
		return audit.Query{}, fmt.Errorf("since must not be after until")
	}
	return query, nil
}

func validSubjectHash(value string) bool {
	const prefix = "hmac-sha256:"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil
}

func managementJSONResponse(status int, value any) []byte {
	body, err := json.Marshal(value)
	if err != nil {
		return managementError(http.StatusInternalServerError, "encode_error", "failed to encode management response")
	}
	return okEnvelope(pluginapi.ManagementResponse{
		StatusCode: status,
		Headers: http.Header{
			"Content-Type":  []string{"application/json; charset=utf-8"},
			"Cache-Control": []string{"no-store"},
		},
		Body: body,
	})
}

func managementError(status int, code, message string) []byte {
	return managementJSONResponse(status, map[string]any{
		"error": map[string]any{"code": code, "message": message},
	})
}
