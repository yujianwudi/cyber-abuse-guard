// Package audit stores a fixed, privacy-minimal security event schema. Request
// bodies, prompts, headers, and plaintext credentials are not representable by
// Event and therefore cannot accidentally be handed to the store.
package audit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
)

const (
	requestHashDomain = "cyber-abuse-guard/audit/request/v1\x00"
	modelHashDomain   = "cyber-abuse-guard/audit/model/v1\x00"
	modelHashPrefix   = "sha256-model-v1:"

	// SourceFormatUnknown is the only value retained for caller-supplied source
	// formats outside the fixed CPA provider enum.
	SourceFormatUnknown = "unknown"
)

// Event is the complete persistent audit schema. Keep this type deliberately
// boring: adding request text, arbitrary metadata, or headers would violate the
// package's privacy boundary.
type Event struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	Action      string    `json:"action"`
	Mode        string    `json:"mode"`
	Category    string    `json:"category,omitempty"`
	RiskScore   int       `json:"risk_score"`
	RuleIDs     []string  `json:"rule_ids,omitempty"`
	RequestHash string    `json:"request_hash,omitempty"`
	SubjectHash string    `json:"subject_hash,omitempty"`
	// Model is either empty or a domain-separated SHA-256 digest. The caller-
	// controlled model name is never retained in a prepared audit event.
	Model            string `json:"model,omitempty"`
	SourceFormat     string `json:"source_format,omitempty"`
	Stream           bool   `json:"stream"`
	TextBytesScanned int    `json:"text_bytes_scanned"`
	Classifier       string `json:"classifier,omitempty"`
	Decision         string `json:"decision"`
	Coverage         string `json:"coverage"`
	IncompleteReason string `json:"incomplete_reason,omitempty"`
	Scanner          string `json:"scanner"`
	LatencyUS        int64  `json:"latency_us"`
}

// HashRequest produces the one-way request correlation value accepted by an
// Event. Callers should discard the request bytes after classification.
func HashRequest(request []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(requestHashDomain))
	_, _ = hash.Write(request)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

// HashModel returns the deterministic, domain-separated correlation value used
// for caller-controlled requested model names. It deliberately uses a distinct
// domain and output prefix from HashRequest so equal inputs cannot be correlated
// across the two audit fields.
func HashModel(model string) string {
	if model == "" {
		return ""
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(modelHashDomain))
	_, _ = hash.Write([]byte(model))
	return modelHashPrefix + hex.EncodeToString(hash.Sum(nil))
}

// CanonicalSourceFormat converts CPA provider names to the fixed values that
// may cross the audit privacy boundary. The Anthropic alias maps to CPA's
// canonical "claude" value; all other inputs collapse to "unknown".
func CanonicalSourceFormat(sourceFormat string) string {
	switch strings.ToLower(strings.TrimSpace(sourceFormat)) {
	case "openai":
		return "openai"
	case "openai-response":
		return "openai-response"
	case "interactions":
		return "interactions"
	case "openai-image":
		return "openai-image"
	case "openai-video":
		return "openai-video"
	case "claude", "anthropic":
		return "claude"
	case "gemini":
		return "gemini"
	default:
		return SourceFormatUnknown
	}
}

func prepareEvent(event Event, now time.Time) (Event, error) {
	if event.ID == "" {
		id, err := randomID()
		if err != nil {
			return Event{}, err
		}
		event.ID = id
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = now.UTC()
	} else {
		event.Timestamp = event.Timestamp.UTC()
	}
	event.RuleIDs = append([]string(nil), event.RuleIDs...)
	event.Model = privacySafeModel(event.Model)
	event.SourceFormat = privacySafeSourceFormat(event.SourceFormat)
	// Source compatibility for pre-Round6 callers and migration tests. New
	// routing code always supplies explicit fixed values.
	if event.Decision == "" {
		event.Decision = "legacy_unspecified"
	}
	if event.Coverage == "" {
		event.Coverage = "legacy_unknown"
	}
	if event.Scanner == "" {
		event.Scanner = "legacy"
	}
	if err := validateEvent(event); err != nil {
		return Event{}, err
	}
	return event, nil
}

func validateEvent(event Event) error {
	if err := validateField("id", event.ID, 128, false); err != nil {
		return err
	}
	if event.Timestamp.Year() < 1970 || event.Timestamp.Year() > 9999 {
		return errors.New("audit: invalid event timestamp")
	}
	if !oneOf(event.Action, "allow", "observe", "audit", "block", "cooldown") {
		return fmt.Errorf("audit: invalid action %q", event.Action)
	}
	if !oneOf(event.Mode, "off", "observe", "audit", "balanced", "strict") {
		return fmt.Errorf("audit: invalid mode %q", event.Mode)
	}
	for name, field := range map[string]struct {
		value string
		limit int
	}{
		"category":          {event.Category, 128},
		"classifier":        {event.Classifier, 64},
		"decision":          {event.Decision, 96},
		"coverage":          {event.Coverage, 32},
		"incomplete_reason": {event.IncompleteReason, 64},
		"scanner":           {event.Scanner, 64},
	} {
		if err := validateField(name, field.value, field.limit, true); err != nil {
			return err
		}
	}
	if !validDecision(event.Decision) {
		return fmt.Errorf("audit: invalid decision %q", event.Decision)
	}
	if !oneOf(event.Coverage, "complete", "incomplete", "legacy_unknown") {
		return fmt.Errorf("audit: invalid coverage %q", event.Coverage)
	}
	if !validIncompleteReason(event.IncompleteReason) {
		return fmt.Errorf("audit: invalid incomplete_reason %q", event.IncompleteReason)
	}
	if !oneOf(event.Scanner, "legacy", "streaming-scanner-v1") {
		return fmt.Errorf("audit: invalid scanner %q", event.Scanner)
	}
	if event.Model != "" && !validDigest(event.Model, modelHashPrefix) {
		return errors.New("audit: model is not a domain-separated SHA-256 correlation value")
	}
	if event.SourceFormat != "" && !oneOf(event.SourceFormat, "openai", "openai-response", "interactions", "openai-image", "openai-video", "claude", "gemini", SourceFormatUnknown) {
		return errors.New("audit: source_format is not a canonical provider value")
	}
	if event.RiskScore < 0 || event.RiskScore > 1_000_000 {
		return errors.New("audit: risk score is outside the supported range")
	}
	if event.TextBytesScanned < 0 || event.TextBytesScanned > 1<<30 {
		return errors.New("audit: text_bytes_scanned is outside the supported range")
	}
	if event.LatencyUS < 0 {
		return errors.New("audit: latency_us must not be negative")
	}
	if len(event.RuleIDs) > 128 {
		return errors.New("audit: too many rule IDs")
	}
	for _, ruleID := range event.RuleIDs {
		if err := validateField("rule_id", ruleID, 128, false); err != nil {
			return err
		}
	}
	if event.RequestHash != "" && !validDigest(event.RequestHash, "sha256:") {
		return errors.New("audit: request_hash is not a SHA-256 correlation value")
	}
	if event.SubjectHash != "" && !validDigest(event.SubjectHash, "hmac-sha256:") {
		return errors.New("audit: subject_hash is not an HMAC-SHA256 correlation value")
	}
	return nil
}

func validDecision(value string) bool {
	return oneOf(value,
		"legacy_unspecified",
		"allow_clean",
		"observe_malicious_text", "audit_malicious_text", "block_malicious_text",
		"observe_suspicious_text", "audit_suspicious_text",
		"observe_incomplete_inspection", "audit_incomplete_inspection",
		"allow_due_to_incomplete_inspection", "block_due_to_incomplete_inspection",
		"allow_incomplete_inspection_off", "block_verified_hard_policy_under_incomplete_inspection",
		"observe_opaque_media", "audit_opaque_media", "allow_with_opaque_media_audit", "block_opaque_media",
		"audit_subject_risk", "block_subject_risk",
		"block_unknown_source_format", "cooldown_subject_risk")
}

func validIncompleteReason(value string) bool {
	return oneOf(value, "", "parse_error", "scan_limit", "rpc_body_limit", "json_depth_limit",
		"text_part_limit", "role_attribution", "classification_chunk_limit", "total_text_limit", "multipart_limit",
		"multipart_schema", "tool_schema", "deferred_text_limit", "unsupported_content_type",
		"incomplete_inspection")
}

// privacySafeModel is also used when reading legacy databases so management
// and export surfaces never echo historical plaintext model values.
func privacySafeModel(model string) string {
	if model == "" || validDigest(model, modelHashPrefix) {
		return model
	}
	return HashModel(model)
}

func privacySafeSourceFormat(sourceFormat string) string {
	if sourceFormat == "" {
		return ""
	}
	return CanonicalSourceFormat(sourceFormat)
}

func validateField(name, value string, limit int, emptyOK bool) error {
	if value == "" {
		if emptyOK {
			return nil
		}
		return fmt.Errorf("audit: %s must not be empty", name)
	}
	if len(value) > limit {
		return fmt.Errorf("audit: %s exceeds %d bytes", name, limit)
	}
	for _, r := range value {
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			return fmt.Errorf("audit: %s contains an unsafe character", name)
		}
	}
	return nil
}

func validDigest(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value[len(prefix):])
	return err == nil
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func randomID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("audit: generate event ID: %w", err)
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16]), nil
}
