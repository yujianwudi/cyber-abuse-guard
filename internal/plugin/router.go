package plugin

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"cyber-abuse-guard/internal/audit"
	"cyber-abuse-guard/internal/classifier"
	"cyber-abuse-guard/internal/config"
	"cyber-abuse-guard/internal/extract"
	guardrules "cyber-abuse-guard/internal/rules"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func (p *Plugin) route(raw []byte) []byte {
	var request pluginapi.ModelRouteRequest
	if err := json.Unmarshal(raw, &request); err != nil {
		return errorEnvelope("invalid_request", "invalid model route request", 0, "")
	}

	p.opMu.RLock()
	defer p.opMu.RUnlock()
	state, err := p.loadRuntime()
	if err != nil {
		return errorEnvelope("not_initialized", err.Error(), 0, "")
	}

	if !state.config.Enabled || state.config.Mode == config.ModeOff || !supportedSourceFormat(request.SourceFormat) {
		return okEnvelope(pluginapi.ModelRouteResponse{Handled: false})
	}
	p.counters.total.Add(1)

	started := time.Now()
	extracted, extractErr := extract.ExtractText(request.Body, extract.Limits{
		MaxScanBytes: state.config.MaxScanBytes,
		MaxJSONDepth: state.config.MaxJSONDepth,
		MaxTextParts: state.config.MaxTextParts,
	})
	requestHash := audit.HashRequest(request.Body)
	if extractErr != nil {
		p.counters.parseErrors.Add(1)
		p.counters.allowed.Add(1)
		p.recordParseError(state, request, requestHash, extracted.BytesScanned, time.Since(started))
		return okEnvelope(pluginapi.ModelRouteResponse{Handled: false})
	}

	result := state.classifier.ClassifyWithPolicy(extracted.Parts, classifierMode(state.config.Mode), classifier.Thresholds{
		Audit:         state.config.Thresholds.Audit,
		BalancedBlock: state.config.Thresholds.BalancedBlock,
		HardBlock:     state.config.Thresholds.HardBlock,
	}, classifierPolicy(state.config))
	result.Truncated = result.Truncated || extracted.Truncated
	if result.Truncated {
		p.counters.truncated.Add(1)
	}

	if state.config.Mode == config.ModeObserve {
		if result.Score >= state.config.Thresholds.Audit {
			p.counters.observed.Add(1)
		} else {
			p.counters.allowed.Add(1)
		}
		return okEnvelope(pluginapi.ModelRouteResponse{Handled: false})
	}

	subjectHash := ""
	if p.identifier != nil {
		subjectHash = p.identifier.FromHeaders(request.Headers).Hash
	}
	decision := state.subject.Evaluate(subjectHash, result.Score)
	truncationBlock := result.Truncated && (state.config.Mode == config.ModeBalanced || state.config.Mode == config.ModeStrict)
	blocked := state.config.Mode != config.ModeAudit && (result.Action == classifier.ActionBlock || truncationBlock)
	if state.config.Mode != config.ModeAudit && decision.Blocked {
		blocked = true
	}

	if blocked {
		p.counters.blocked.Add(1)
	} else if result.Action == classifier.ActionAudit || (state.config.Mode == config.ModeAudit && result.Score >= state.config.Thresholds.Audit) {
		p.counters.audited.Add(1)
	} else {
		p.counters.allowed.Add(1)
	}

	auditResult := result
	if state.config.Mode == config.ModeAudit && auditResult.Score >= state.config.Thresholds.Audit {
		auditResult.Action = classifier.ActionAudit
	}
	if result.Truncated {
		auditResult.Category = guardrules.Category("scan_limit")
	}
	if result.Action != classifier.ActionAllow || decision.Blocked || result.Truncated {
		p.recordDecision(state, request, requestHash, subjectHash, extracted.BytesScanned, auditResult, string(decision.Reason), blocked, time.Since(started))
	}
	if !blocked {
		return okEnvelope(pluginapi.ModelRouteResponse{Handled: false})
	}

	category := string(result.Category)
	if truncationBlock {
		category = "scan_limit"
	}
	p.pending.put(requestHash, category)
	reason := "cyber_abuse_guard_policy"
	if result.Score >= state.config.Thresholds.HardBlock {
		reason = "cyber_abuse_guard_hard_policy"
	}
	if truncationBlock {
		reason = "cyber_abuse_guard_scan_limit"
	}
	return okEnvelope(pluginapi.ModelRouteResponse{
		Handled:    true,
		TargetKind: pluginapi.ModelRouteTargetSelf,
		Reason:     reason,
	})
}

func classifierPolicy(cfg config.Config) classifier.Policy {
	policy := classifier.DefaultPolicy()
	policy.Allow.Defensive = cfg.AllowContext.DefensiveAnalysis
	policy.Allow.Remediation = cfg.AllowContext.Remediation
	policy.Allow.CTF = cfg.AllowContext.CTF
	policy.Allow.Lab = cfg.AllowContext.Lab
	policy.Allow.Authorized = cfg.AllowContext.AuthorizedTesting
	policy.Allow.StaticAnalysis = cfg.AllowContext.MalwareStaticAnalysis
	policy.HardBlockEvenIfAuthorized = classifier.HardBlockPolicy{
		CredentialTheft:      cfg.HardBlockEvenIfAuthorized.CredentialTheft,
		PhishingDeployment:   cfg.HardBlockEvenIfAuthorized.PhishingDeployment,
		RansomwareDeployment: cfg.HardBlockEvenIfAuthorized.RansomwareDeployment,
		DataExfiltration:     cfg.HardBlockEvenIfAuthorized.DataExfiltration,
	}
	return policy
}

func supportedSourceFormat(format string) bool {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "openai", "openai-response", "claude", "anthropic", "gemini":
		return true
	default:
		return false
	}
}

func classifierMode(mode config.Mode) classifier.Mode {
	switch mode {
	case config.ModeObserve:
		return classifier.ModeObserve
	case config.ModeAudit:
		return classifier.ModeAudit
	case config.ModeStrict:
		return classifier.ModeStrict
	case config.ModeBalanced:
		return classifier.ModeBalanced
	default:
		return classifier.ModeOff
	}
}

func (p *Plugin) recordParseError(state *runtimeState, request pluginapi.ModelRouteRequest, requestHash string, scanned int, latency time.Duration) {
	if state == nil || state.audit == nil || !state.config.Audit.Enabled || state.config.Mode == config.ModeObserve || state.config.Mode == config.ModeOff {
		return
	}
	event := audit.Event{
		ID:               newEventID(),
		Timestamp:        time.Now().UTC(),
		Action:           "audit",
		Mode:             string(state.config.Mode),
		Category:         "parse_error",
		Model:            request.RequestedModel,
		SourceFormat:     request.SourceFormat,
		Stream:           request.Stream,
		TextBytesScanned: scanned,
		Classifier:       "parse_error",
		LatencyUS:        latency.Microseconds(),
	}
	if state.config.Audit.LogRequestHash {
		event.RequestHash = requestHash
	}
	state.audit.Record(event)
}

func (p *Plugin) recordDecision(state *runtimeState, request pluginapi.ModelRouteRequest, requestHash, subjectHash string, scanned int, result classifier.Result, subjectReason string, blocked bool, latency time.Duration) {
	if state == nil || state.audit == nil || !state.config.Audit.Enabled {
		return
	}
	action := string(result.Action)
	if blocked {
		action = "block"
		if subjectReason == "cooldown" {
			action = "cooldown"
		}
	}
	event := audit.Event{
		ID:               newEventID(),
		Timestamp:        time.Now().UTC(),
		Action:           action,
		Mode:             string(state.config.Mode),
		RiskScore:        result.Score,
		Model:            request.RequestedModel,
		SourceFormat:     request.SourceFormat,
		Stream:           request.Stream,
		TextBytesScanned: scanned,
		Classifier:       result.RuleSetVersion,
		LatencyUS:        latency.Microseconds(),
	}
	if state.config.Audit.LogCategory {
		event.Category = string(result.Category)
	}
	if state.config.Audit.LogRuleIDs {
		event.RuleIDs = append([]string(nil), result.RuleIDs...)
	}
	if state.config.Audit.LogRequestHash {
		event.RequestHash = requestHash
	}
	if state.config.Audit.LogSubjectHash {
		event.SubjectHash = subjectHash
	}
	state.audit.Record(event)
}

func newEventID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err == nil {
		value[6] = (value[6] & 0x0f) | 0x40
		value[8] = (value[8] & 0x3f) | 0x80
		encoded := hex.EncodeToString(value[:])
		return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[0:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:32])
	}
	return fmt.Sprintf("event-%d", time.Now().UnixNano())
}
