// Package plugin implements the CPA v7.2.67 schema-v1 RPC surface for the
// cyber-abuse guard. The native C boundary in cmd/cyber-abuse-guard is kept
// deliberately thin; policy state and lifecycle semantics live here so they
// can be race-tested without loading a shared object.
package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"cyber-abuse-guard/internal/audit"
	"cyber-abuse-guard/internal/classifier"
	"cyber-abuse-guard/internal/config"
	"cyber-abuse-guard/internal/rules"
	"cyber-abuse-guard/internal/subject"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const (
	ID      = "cyber-abuse-guard"
	Version = "0.1.0"

	maxRPCRequestBytes = 8 << 20

	blockedErrorCode     = "cyber_abuse_guard_blocked"
	unsupportedErrorCode = "cyber_abuse_guard_unsupported"

	refusalMessage = "Request blocked by the local cyber-abuse policy. Defensive analysis, remediation, CTF/lab work, and explicitly authorized testing are supported."
)

var metadata = pluginapi.Metadata{
	Name:             "CPA Cyber Abuse Guard",
	Version:          Version,
	Author:           "Cyber Abuse Guard Contributors",
	GitHubRepository: "https://github.com/cyber-abuse-guard/cyber-abuse-guard",
	ConfigFields: []pluginapi.ConfigField{
		{Name: "enabled", Type: pluginapi.ConfigFieldTypeBoolean, Description: "Enable local cyber-abuse classification."},
		{Name: "mode", Type: pluginapi.ConfigFieldTypeEnum, EnumValues: []string{"off", "observe", "audit", "balanced", "strict"}, Description: "Select observation, auditing, or enforcement behavior."},
		{Name: "priority", Type: pluginapi.ConfigFieldTypeInteger, Description: "Run before provider and authentication selection."},
		{Name: "max_scan_bytes", Type: pluginapi.ConfigFieldTypeInteger, Description: "Maximum request bytes inspected before enforcing modes fail closed."},
		{Name: "max_json_depth", Type: pluginapi.ConfigFieldTypeInteger, Description: "Maximum JSON nesting depth inspected by the bounded extractor."},
		{Name: "max_text_parts", Type: pluginapi.ConfigFieldTypeInteger, Description: "Maximum number of text parts inspected per request."},
		{Name: "thresholds", Type: pluginapi.ConfigFieldTypeObject, Description: "Audit, balanced-block, and hard-block score thresholds."},
		{Name: "allow_context", Type: pluginapi.ConfigFieldTypeObject, Description: "Explicit defensive, remediation, CTF, lab, authorization, and static-analysis allowances."},
		{Name: "hard_block_even_if_authorized", Type: pluginapi.ConfigFieldTypeObject, Description: "Categories whose operational abuse remains protected from authorization score reductions."},
		{Name: "subject_control", Type: pluginapi.ConfigFieldTypeObject, Description: "Rolling subject-risk, cooldown, and manual-block settings."},
		{Name: "audit", Type: pluginapi.ConfigFieldTypeObject, Description: "Privacy-minimal SQLite audit retention and field settings; original text is never supported."},
		{Name: "trusted_proxy", Type: pluginapi.ConfigFieldTypeObject, Description: "Reserved for a future verified-peer API; enabling it is rejected on CPA v7.2.67."},
		{Name: "classifier", Type: pluginapi.ConfigFieldTypeObject, Description: "Reserved local-classifier interface; enabling it is unsupported in v0.1 and rejected."},
	},
}

type lifecycleRequest struct {
	ConfigYAML    []byte `json:"config_yaml"`
	SchemaVersion uint32 `json:"schema_version"`
}

type registration struct {
	SchemaVersion uint32                   `json:"schema_version"`
	Metadata      pluginapi.Metadata       `json:"metadata"`
	Capabilities  registrationCapabilities `json:"capabilities"`
}

type registrationCapabilities struct {
	ModelRouter           bool                         `json:"model_router"`
	Executor              bool                         `json:"executor"`
	ExecutorModelScope    pluginapi.ExecutorModelScope `json:"executor_model_scope"`
	ExecutorInputFormats  []string                     `json:"executor_input_formats"`
	ExecutorOutputFormats []string                     `json:"executor_output_formats"`
	ManagementAPI         bool                         `json:"management_api"`
}

type rpcEnvelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	Retryable  bool   `json:"retryable,omitempty"`
	HTTPStatus int    `json:"http_status,omitempty"`
	Category   string `json:"category,omitempty"`
}

type runtimeState struct {
	config       config.Config
	classifier   *classifier.Classifier
	rulesVersion string
	audit        *audit.Store
	subject      *subject.Controller
	startedAt    time.Time
}

func (state *runtimeState) close() {
	if state == nil || state.audit == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = state.audit.Flush(ctx)
	_ = state.audit.Close()
}

// Plugin is safe for concurrent CPA callbacks. A validated runtime is built
// completely before the atomic pointer is swapped; failed reconfiguration
// never exposes a partially initialized policy.
type Plugin struct {
	runtime atomic.Pointer[runtimeState]

	lifecycleMu sync.Mutex
	opMu        sync.RWMutex
	shutdown    atomic.Bool

	lastConfigError atomic.Pointer[string]
	identifier      *subject.Identifier
	identifierErr   error
	pending         pendingCache
	counters        counters
	loggerMu        sync.RWMutex
	logger          LogFunc
}

// LogFunc receives privacy-safe operational messages. The native entrypoint
// wires this only to CPA's host.log callback; execution paths never use it.
type LogFunc func(level, message string, fields map[string]any)

// New creates an unregistered plugin. Configuration and rules are activated
// only by plugin.register, matching the CPA native lifecycle.
func New() *Plugin {
	identifier, err := subject.NewIdentifier(subject.IdentifierConfig{})
	return &Plugin{
		identifier:    identifier,
		identifierErr: err,
		pending:       newPendingCache(4096, 2*time.Minute),
	}
}

// Call dispatches one schema-v1 RPC method. Controlled protocol/policy errors
// use a valid error envelope with return code zero. A recovered panic uses a
// non-zero ABI return code while still returning a parseable envelope.
func (p *Plugin) Call(method string, request []byte) (response []byte, returnCode int) {
	defer func() {
		if recovered := recover(); recovered != nil {
			response = errorEnvelope("panic_recovered", "plugin callback failed safely", 0, "")
			returnCode = 1
		}
	}()
	if p == nil {
		return errorEnvelope("plugin_unavailable", "plugin is unavailable", 0, ""), 0
	}
	if len(request) > maxRPCRequestBytes {
		return errorEnvelope("request_too_large", "plugin RPC request exceeds the size limit", 0, ""), 0
	}
	if method == "" {
		return errorEnvelope("invalid_method", "method is required", 0, ""), 0
	}
	if method == pluginabi.MethodPluginShutdown {
		p.Shutdown()
		return okEnvelope(struct{}{}), 0
	}
	if p.shutdown.Load() {
		return errorEnvelope("plugin_shutdown", "plugin has shut down", 0, ""), 0
	}

	switch method {
	case pluginabi.MethodPluginRegister:
		return p.configure(request, false), 0
	case pluginabi.MethodPluginReconfigure:
		return p.configure(request, true), 0
	case pluginabi.MethodModelRoute:
		return p.route(request), 0
	case pluginabi.MethodExecutorIdentifier:
		return okEnvelope(struct {
			Identifier string `json:"identifier"`
		}{Identifier: ID}), 0
	case pluginabi.MethodExecutorExecute, pluginabi.MethodExecutorExecuteStream:
		return p.blockExecution(request), 0
	case pluginabi.MethodExecutorCountTokens, pluginabi.MethodExecutorHTTPRequest:
		return errorEnvelope(unsupportedErrorCode, "this policy executor does not provide token counting or HTTP forwarding", 405, ""), 0
	case pluginabi.MethodManagementRegister:
		return p.registerManagement(request), 0
	case pluginabi.MethodManagementHandle:
		return p.handleManagement(request), 0
	default:
		return errorEnvelope("unknown_method", "unknown plugin method", 0, ""), 0
	}
}

func (p *Plugin) configure(raw []byte, reconfigure bool) []byte {
	var request lifecycleRequest
	if err := json.Unmarshal(raw, &request); err != nil {
		return errorEnvelope("invalid_request", "invalid lifecycle request", 0, "")
	}
	if request.SchemaVersion != pluginabi.SchemaVersion {
		return errorEnvelope("unsupported_schema", fmt.Sprintf("unsupported schema version %d", request.SchemaVersion), 0, "")
	}

	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	if p.shutdown.Load() {
		return errorEnvelope("plugin_shutdown", "plugin has shut down", 0, "")
	}

	state, err := p.buildRuntime(request.ConfigYAML)
	if err != nil {
		p.setLastConfigError(err)
		if reconfigure && p.runtime.Load() != nil {
			p.log("warn", "cyber-abuse-guard rejected a reconfiguration; the previous configuration remains active", map[string]any{
				"plugin": ID,
				"code":   "invalid_config",
			})
			return okEnvelope(currentRegistration())
		}
		return errorEnvelope("invalid_config", err.Error(), 0, "")
	}

	p.opMu.Lock()
	if p.shutdown.Load() {
		p.opMu.Unlock()
		state.close()
		return errorEnvelope("plugin_shutdown", "plugin has shut down", 0, "")
	}
	previous := p.runtime.Swap(state)
	p.pending.clear()
	p.setLastConfigError(nil)
	p.opMu.Unlock()
	previous.close()
	return okEnvelope(currentRegistration())
}

// SetLogger replaces the optional operational logger. Passing nil disables
// immediate log delivery; last_config_error remains available via status.
func (p *Plugin) SetLogger(logger LogFunc) {
	if p == nil {
		return
	}
	p.loggerMu.Lock()
	p.logger = logger
	p.loggerMu.Unlock()
}

func (p *Plugin) log(level, message string, fields map[string]any) {
	p.loggerMu.RLock()
	logger := p.logger
	p.loggerMu.RUnlock()
	if logger == nil {
		return
	}
	defer func() { _ = recover() }()
	logger(level, message, fields)
}

func (p *Plugin) buildRuntime(rawConfig []byte) (*runtimeState, error) {
	cfg, err := config.Parse(rawConfig)
	if err != nil {
		return nil, err
	}
	if cfg.Classifier.Enabled {
		return nil, fmt.Errorf("classifier.enabled is not supported in v%s; use deterministic local rules", Version)
	}
	if cfg.TrustedProxy.Enabled {
		return nil, fmt.Errorf("trusted_proxy.enabled is not supported because CPA v7.2.67 does not provide a verified direct peer address")
	}
	if cfg.Audit.LogOriginalText {
		return nil, fmt.Errorf("audit.log_original_text is not supported; prompts and request bodies are never persisted")
	}
	set, err := rules.LoadDefault()
	if err != nil {
		return nil, fmt.Errorf("load rules: %w", err)
	}
	compiled, err := classifier.New(set)
	if err != nil {
		return nil, fmt.Errorf("compile rules: %w", err)
	}
	if cfg.SubjectControl.Enabled && p.identifierErr != nil {
		return nil, fmt.Errorf("initialize subject identifier: %w", p.identifierErr)
	}

	controller, err := subject.NewController(subject.Config{
		Enabled:          cfg.SubjectControl.Enabled,
		Window:           time.Duration(cfg.SubjectControl.WindowMinutes) * time.Minute,
		AuditThreshold:   cfg.Thresholds.Audit,
		CooldownScore:    float64(cfg.SubjectControl.CooldownScore),
		ManualBlockScore: float64(cfg.SubjectControl.ManualBlockScore),
		Cooldown:         time.Duration(cfg.SubjectControl.CooldownMinutes) * time.Minute,
		RepeatMultiplier: 1.5,
		MaxMultiplier:    3,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize subject risk: %w", err)
	}

	state := &runtimeState{
		config:       cfg,
		classifier:   compiled,
		rulesVersion: set.Version,
		subject:      controller,
		startedAt:    time.Now().UTC(),
	}
	if cfg.Audit.Enabled {
		path, _ := auditDatabasePath(cfg.Audit.DataDir)
		store, _ := audit.Open(audit.Config{
			Path:            path,
			Retention:       time.Duration(cfg.Audit.RetentionDays) * 24 * time.Hour,
			MaxBytes:        int64(cfg.Audit.MaxDBMB) << 20,
			QueueSize:       1024,
			BusyTimeout:     2 * time.Second,
			CleanupInterval: time.Hour,
		})
		// Open intentionally returns a usable degraded store on database
		// failures, so enforcement remains available.
		state.audit = store
	}
	return state, nil
}

func auditDatabasePath(dataDir string) (string, error) {
	if dataDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve audit data directory: %w", err)
		}
		dataDir = filepath.Join(home, ".cli-proxy-api", "plugins", ID)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return "", fmt.Errorf("create audit data directory: %w", err)
	}
	return filepath.Join(dataDir, "events.db"), nil
}

func currentRegistration() registration {
	formats := []string{"openai", "openai-response", "claude", "gemini"}
	return registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata:      metadata,
		Capabilities: registrationCapabilities{
			ModelRouter:           true,
			Executor:              true,
			ExecutorModelScope:    pluginapi.ExecutorModelScopeStatic,
			ExecutorInputFormats:  append([]string(nil), formats...),
			ExecutorOutputFormats: append([]string(nil), formats...),
			ManagementAPI:         true,
		},
	}
}

func (p *Plugin) setLastConfigError(err error) {
	if err == nil {
		p.lastConfigError.Store(nil)
		return
	}
	message := err.Error()
	p.lastConfigError.Store(&message)
}

func (p *Plugin) lastConfigErrorMessage() string {
	value := p.lastConfigError.Load()
	if value == nil {
		return ""
	}
	return *value
}

func (p *Plugin) loadRuntime() (*runtimeState, error) {
	state := p.runtime.Load()
	if state == nil {
		return nil, errors.New("plugin is not registered")
	}
	return state, nil
}

// Shutdown is idempotent. It prevents new callbacks, waits for callbacks that
// hold the operation read lock, flushes audit work, and closes the store.
func (p *Plugin) Shutdown() {
	if p == nil || !p.shutdown.CompareAndSwap(false, true) {
		return
	}
	p.lifecycleMu.Lock()
	p.opMu.Lock()
	state := p.runtime.Swap(nil)
	p.pending.clear()
	p.opMu.Unlock()
	p.lifecycleMu.Unlock()
	state.close()
}

func okEnvelope(value any) []byte {
	result, err := json.Marshal(value)
	if err != nil {
		return errorEnvelope("encode_error", "failed to encode plugin response", 0, "")
	}
	raw, err := json.Marshal(rpcEnvelope{OK: true, Result: result})
	if err != nil {
		return []byte(`{"ok":false,"error":{"code":"encode_error","message":"failed to encode plugin response"}}`)
	}
	return raw
}

func errorEnvelope(code, message string, status int, category string) []byte {
	raw, err := json.Marshal(rpcEnvelope{OK: false, Error: &rpcError{
		Code:       code,
		Message:    message,
		HTTPStatus: status,
		Category:   category,
	}})
	if err != nil {
		return []byte(`{"ok":false,"error":{"code":"plugin_error","message":"plugin call failed"}}`)
	}
	return raw
}

type counters struct {
	total           atomic.Uint64
	allowed         atomic.Uint64
	observed        atomic.Uint64
	audited         atomic.Uint64
	blocked         atomic.Uint64
	parseErrors     atomic.Uint64
	truncated       atomic.Uint64
	executorBlocks  atomic.Uint64
	managementTests atomic.Uint64
}

func (c *counters) snapshot() map[string]uint64 {
	return map[string]uint64{
		"total":            c.total.Load(),
		"allowed":          c.allowed.Load(),
		"observed":         c.observed.Load(),
		"audited":          c.audited.Load(),
		"blocked":          c.blocked.Load(),
		"parse_errors":     c.parseErrors.Load(),
		"truncated":        c.truncated.Load(),
		"executor_blocks":  c.executorBlocks.Load(),
		"management_tests": c.managementTests.Load(),
	}
}
