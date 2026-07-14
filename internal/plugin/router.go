package plugin

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/yujianwudi/cyber-abuse-guard/internal/audit"
	"github.com/yujianwudi/cyber-abuse-guard/internal/classifier"
	"github.com/yujianwudi/cyber-abuse-guard/internal/config"
	"github.com/yujianwudi/cyber-abuse-guard/internal/extract"
)

type modelRouteFailure struct {
	code   string
	reason string
}

// callModelRoute captures the runtime's failure policy under the same read
// lock that protects the runtime itself. The lock is released before a
// privacy-safe failure is reported, and the captured policy survives either a
// concurrent runtime swap or a recovered panic.
func (p *Plugin) callModelRoute(raw []byte) (response []byte, returnCode int) {
	p.opMu.RLock()
	state := p.runtime.Load()
	policy := modelRoutePolicyFromState(state)
	if state == nil && p.shutdown.Load() {
		policy = decodeModelRouteFailurePolicy(p.shutdownModelRoutePolicy.Load())
	}
	locked := true
	defer func() {
		if locked {
			p.opMu.RUnlock()
		}
		if recovered := recover(); recovered != nil {
			p.counters.panicsRecovered.Add(1)
			response = p.modelRouteFailureWithPolicy(
				"panic_recovered",
				"cyber_abuse_guard_router_panic",
				policy,
			)
			returnCode = 0
		}
	}()

	var request pluginapi.ModelRouteRequest
	if err := json.Unmarshal(raw, &request); err != nil {
		p.opMu.RUnlock()
		locked = false
		return p.modelRouteFailureWithPolicy("invalid_request", "cyber_abuse_guard_invalid_request", policy), 0
	}
	if state == nil {
		p.opMu.RUnlock()
		locked = false
		code := "not_initialized"
		reason := "cyber_abuse_guard_not_initialized"
		if p.shutdown.Load() {
			code = "plugin_shutdown"
			reason = "cyber_abuse_guard_shutdown"
		}
		return p.modelRouteFailureWithPolicy(code, reason, policy), 0
	}

	response, failure := p.route(state, request)
	p.opMu.RUnlock()
	locked = false
	if failure != nil {
		return p.modelRouteFailureWithPolicy(failure.code, failure.reason, policy), 0
	}
	return response, 0
}

func (p *Plugin) route(state *runtimeState, request pluginapi.ModelRouteRequest) ([]byte, *modelRouteFailure) {
	if !state.config.Enabled || state.config.Mode == config.ModeOff {
		return okEnvelope(pluginapi.ModelRouteResponse{Handled: false}), nil
	}
	started := time.Now()
	p.counters.total.Add(1)
	unknownSourceFormat := !supportedSourceFormat(request.SourceFormat)
	if unknownSourceFormat {
		p.counters.unknownSourceFormats.Add(1)
		p.reportUnknownSourceFormat()
		if state.config.Mode == config.ModeStrict {
			requestHash := audit.HashRequest(request.Body)
			p.counters.blocked.Add(1)
			p.recordUnknownSourceBlock(state, requestHash, time.Since(started))
			p.pending.put(requestHash, "unknown_source_format")
			return blockedRouteEnvelope("cyber_abuse_guard_unknown_source_format"), nil
		}
		// Balanced/audit/observe still run the format-tolerant bounded extractor
		// instead of silently bypassing policy. Strict blocks before interpretation
		// because a future provider shape may hide semantics under unknown fields.
	}

	limits := extract.Limits{
		MaxScanBytes: state.config.MaxScanBytes,
		MaxRawBytes:  maxRPCRequestBytes,
		MaxJSONDepth: state.config.MaxJSONDepth,
		MaxTextParts: state.config.MaxTextParts,
	}
	var extracted extract.Result
	var extractErr error
	if unknownSourceFormat {
		extracted, extractErr = extract.ExtractUntrustedRequest(request.Body, request.Headers, limits)
	} else {
		extracted, extractErr = extract.ExtractRequest(request.Body, request.Headers, limits)
	}
	requestHash := audit.HashRequest(request.Body)
	if extractErr != nil && len(extracted.IncompleteReasons) == 0 {
		// Invalid limits or an extractor invariant failure is operational. It is
		// deliberately kept on the existing mode-aware runtime-failure path and
		// is never confused with request-content incompleteness.
		if errors.Is(extractErr, extract.ErrInvalidLimits) {
			return nil, &modelRouteFailure{code: "invalid_extractor_limits", reason: "cyber_abuse_guard_inspection_failure"}
		}
		return nil, &modelRouteFailure{code: "inspection_failure", reason: "cyber_abuse_guard_inspection_failure"}
	}
	incompleteReasons := append([]extract.IncompleteReason(nil), extracted.IncompleteReasons...)
	if !extracted.IsComplete() && len(incompleteReasons) == 0 {
		// Defensive invariant fallback. The category remains bounded and no raw
		// parser diagnostic is logged or persisted.
		incompleteReasons = append(incompleteReasons, extract.IncompleteParseError)
	}

	result := classifier.Result{
		Action:         classifier.ActionAllow,
		RuleSetVersion: state.rulesVersion,
	}
	if len(incompleteReasons) == 0 {
		mode := classifierMode(state.config.Mode)
		thresholds := classifier.Thresholds{
			Audit:         state.config.Thresholds.Audit,
			BalancedBlock: state.config.Thresholds.BalancedBlock,
			HardBlock:     state.config.Thresholds.HardBlock,
		}
		policy := classifierPolicy(state.config)
		if extracted.RoleAware {
			result = state.classifier.ClassifySegmentsWithPolicy(extracted.Segments, mode, thresholds, policy)
		} else {
			result = state.classifier.ClassifyUntrustedPartsWithPolicy(extracted.Parts, mode, thresholds, policy)
		}
		if result.Truncated {
			// Decoder/classifier budget exhaustion is still incomplete content
			// inspection. Discard the prefix score before policy or subject state
			// sees it; balanced must allow+audit and strict alone may enforce.
			incompleteReasons = append(incompleteReasons, extract.IncompleteScanByteLimit)
			result = classifier.Result{
				Action:         classifier.ActionAllow,
				RuleSetVersion: state.rulesVersion,
			}
		}
	}

	opaqueAudit, opaqueBlock := opaqueMediaDisposition(state.config, extracted.OpaqueMedia)
	if extracted.OpaqueMedia {
		p.counters.opaqueMedia.Add(1)
		for _, kind := range extracted.OpaqueMediaKinds {
			switch kind {
			case extract.OpaqueMediaHTTPSImageURL:
				p.counters.opaqueMediaHTTPSImageURL.Add(1)
			case extract.OpaqueMediaDataURL:
				p.counters.opaqueMediaDataURL.Add(1)
			case extract.OpaqueMediaBase64Image:
				p.counters.opaqueMediaBase64Image.Add(1)
			case extract.OpaqueMediaAudio:
				p.counters.opaqueMediaAudio.Add(1)
			case extract.OpaqueMediaVideo:
				p.counters.opaqueMediaVideo.Add(1)
			case extract.OpaqueMediaDocument:
				p.counters.opaqueMediaDocument.Add(1)
			case extract.OpaqueMediaRemoteURL:
				p.counters.opaqueMediaRemoteURL.Add(1)
			default:
				p.counters.opaqueMediaOther.Add(1)
			}
		}
		switch {
		case opaqueBlock:
			p.counters.opaqueMediaBlocked.Add(1)
		case opaqueAudit:
			p.counters.opaqueMediaAudited.Add(1)
		default:
			p.counters.opaqueMediaAllowed.Add(1)
		}
	}

	outcome := inspectionOutcome{
		Classification: result,
		Incomplete:     incompleteReasons,
		OpaqueMedia:    extracted.OpaqueMedia,
	}
	decision := inspectionDisposition(state.config.Mode, outcome, state.config.EffectiveOpaqueMediaPolicy())
	subjectHash := ""
	subjectReason := ""
	if decision.EvaluateSubject {
		if p.identifier != nil {
			subjectHash = p.identifier.FromHeaders(request.Headers).Hash
		}
		subjectDecision := state.subject.EvaluateRequest(subjectHash, requestHash, result.Score)
		state.markSubjectPersistenceDirty()
		subjectReason = string(subjectDecision.Reason)
		outcome.SubjectBlocked = subjectDecision.Blocked
		decision = inspectionDisposition(state.config.Mode, outcome, state.config.EffectiveOpaqueMediaPolicy())
	}

	if len(incompleteReasons) != 0 {
		p.recordIncompleteCounters(incompleteReasons, decision)
	}

	switch {
	case decision.Block:
		p.counters.blocked.Add(1)
	case decision.Audit:
		p.counters.audited.Add(1)
	case decision.Observe:
		p.counters.observed.Add(1)
	default:
		p.counters.allowed.Add(1)
	}

	if decision.Block || decision.Audit {
		p.recordDecision(state, request, requestHash, subjectHash, extracted.TextBytesScanned, result, decision, subjectReason, time.Since(started))
	}
	if !decision.Block {
		return okEnvelope(pluginapi.ModelRouteResponse{Handled: false}), nil
	}

	category := decision.Category
	if category == "" {
		category = string(result.Category)
	}
	p.pending.put(requestHash, category)
	reason := decision.RouteReason
	if reason == "" {
		reason = "cyber_abuse_guard_policy"
	}
	if decision.Code == "block_malicious_text" && result.Score >= state.config.Thresholds.HardBlock {
		reason = "cyber_abuse_guard_hard_policy"
	}
	return blockedRouteEnvelope(reason), nil
}

func opaqueMediaDisposition(cfg config.Config, present bool) (auditOnly, block bool) {
	if !present {
		return false, false
	}
	switch cfg.EffectiveOpaqueMediaPolicy() {
	case config.OpaqueMediaPolicyBlock:
		if cfg.Mode == config.ModeBalanced || cfg.Mode == config.ModeStrict {
			return false, true
		}
		// Observe/Audit modes never enforce, even when an explicit future
		// enforcing policy is being evaluated during a rollout.
		return true, false
	case config.OpaqueMediaPolicyAudit:
		return true, false
	default:
		return false, false
	}
}

func blockedRouteEnvelope(reason string) []byte {
	return okEnvelope(blockedRouteResponse(reason))
}

func blockedRouteResponse(reason string) pluginapi.ModelRouteResponse {
	return pluginapi.ModelRouteResponse{
		Handled:    true,
		TargetKind: pluginapi.ModelRouteTargetSelf,
		Reason:     reason,
	}
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
	return audit.CanonicalSourceFormat(format) != audit.SourceFormatUnknown
}

func (p *Plugin) reportUnknownSourceFormat() {
	now := time.Now().UnixNano()
	for {
		previous := p.lastUnknownSourceNotice.Load()
		if previous != 0 && time.Duration(now-previous) < time.Minute {
			return
		}
		if p.lastUnknownSourceNotice.CompareAndSwap(previous, now) {
			p.log("warn", "cyber-abuse-guard received an unknown CPA source format; bounded generic inspection remains active", map[string]any{
				"plugin": ID,
				"code":   "unknown_source_format",
			})
			return
		}
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

func (p *Plugin) recordUnknownSourceBlock(state *runtimeState, requestHash string, latency time.Duration) {
	if state == nil || state.audit == nil || !state.config.Audit.Enabled {
		return
	}
	event := audit.Event{
		ID:           newEventID(),
		Timestamp:    time.Now().UTC(),
		Action:       "block",
		Mode:         string(state.config.Mode),
		Category:     "unknown_source_format",
		SourceFormat: audit.SourceFormatUnknown,
		Classifier:   state.rulesVersion,
		LatencyUS:    latency.Microseconds(),
	}
	if state.config.Audit.LogRequestHash {
		event.RequestHash = requestHash
	}
	p.recordAuditEvent(state, event)
}

func (p *Plugin) recordIncompleteCounters(reasons []extract.IncompleteReason, decision inspectionDecision) {
	p.counters.incompleteInspections.Add(1)
	if decision.Block {
		p.counters.incompleteBlocked.Add(1)
	} else {
		p.counters.incompleteAllowed.Add(1)
	}

	var parseError, scanLimit, jsonDepth, textPart, multipartLimit, unsupported, rpcBody bool
	var truncated bool
	for _, reason := range reasons {
		switch reason {
		case extract.IncompleteParseError:
			parseError = true
		case extract.IncompleteScanByteLimit,
			extract.IncompleteJSONTokenLimit,
			extract.IncompleteJSONNodeLimit,
			extract.IncompleteTextPartByteLimit,
			extract.IncompleteRawBodyLimit:
			scanLimit = true
			truncated = true
		case extract.IncompleteJSONDepthLimit:
			jsonDepth = true
			truncated = true
		case extract.IncompleteTextPartLimit:
			textPart = true
			truncated = true
		case extract.IncompleteMultipartBoundaryLimit,
			extract.IncompleteMultipartPartLimit,
			extract.IncompleteMultipartHeaderLimit,
			extract.IncompleteMultipartTextLimit,
			extract.IncompleteMultipartParseError:
			multipartLimit = true
			if reason != extract.IncompleteMultipartParseError {
				truncated = true
			}
		case extract.IncompleteUnsupportedMediaType, extract.IncompleteUnsupportedContentEncoding:
			unsupported = true
		case extract.IncompleteRPCBodyLimit:
			rpcBody = true
			truncated = true
		}
	}
	if parseError {
		p.counters.incompleteParseError.Add(1)
		p.counters.parseErrors.Add(1)
	}
	if scanLimit {
		p.counters.incompleteScanLimit.Add(1)
	}
	if jsonDepth {
		p.counters.incompleteJSONDepthLimit.Add(1)
	}
	if textPart {
		p.counters.incompleteTextPartLimit.Add(1)
	}
	if multipartLimit {
		p.counters.incompleteMultipartLimit.Add(1)
	}
	if unsupported {
		p.counters.incompleteUnsupportedContentType.Add(1)
	}
	if rpcBody {
		p.counters.incompleteRPCBodyLimit.Add(1)
	}
	if truncated {
		p.counters.truncated.Add(1)
	}
}

func (p *Plugin) recordDecision(state *runtimeState, request pluginapi.ModelRouteRequest, requestHash, subjectHash string, scanned int, result classifier.Result, decision inspectionDecision, subjectReason string, latency time.Duration) {
	if state == nil || state.audit == nil || !state.config.Audit.Enabled {
		return
	}
	action := "audit"
	if decision.Block {
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
		Model:            audit.HashModel(request.RequestedModel),
		SourceFormat:     audit.CanonicalSourceFormat(request.SourceFormat),
		Stream:           request.Stream,
		TextBytesScanned: scanned,
		Classifier:       result.RuleSetVersion,
		LatencyUS:        latency.Microseconds(),
	}
	if state.config.Audit.LogCategory {
		event.Category = decision.Category
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
	p.recordAuditEvent(state, event)
}

// recordAuditEvent deliberately ignores persistence failure for policy
// decisions. A full queue, locked/unavailable SQLite database, or a closing
// store must never turn a local block into an upstream request. The audit store
// exposes detailed counters; this helper adds a privacy-safe, rate-limited host
// log without including request-derived fields.
func (p *Plugin) recordAuditEvent(state *runtimeState, event audit.Event) {
	if state == nil || state.audit == nil || state.audit.Record(event) {
		return
	}
	now := time.Now().UnixNano()
	for {
		previous := p.lastAuditNotice.Load()
		if previous != 0 && time.Duration(now-previous) < time.Minute {
			return
		}
		if p.lastAuditNotice.CompareAndSwap(previous, now) {
			p.log("warn", "cyber-abuse-guard audit event could not be queued; enforcement remains active", map[string]any{
				"plugin": ID,
				"code":   "audit_queue_degraded",
			})
			return
		}
	}
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
