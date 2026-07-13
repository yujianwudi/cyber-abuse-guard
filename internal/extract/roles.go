package extract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Role is a normalized provider conversation role. Unknown role values never
// enter a role-aware result; the extractor falls back to legacy Parts instead.
type Role string

const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleTool      Role = "tool"
)

// SegmentProvenance distinguishes natural conversation content from arguments
// that a provider-native tool call would execute. Content is the zero value so
// existing callers that construct role-aware segments remain source compatible.
type SegmentProvenance uint8

const (
	ProvenanceContent SegmentProvenance = iota
	ProvenanceToolPayload
)

// Segment is transient request text plus its normalized role and provenance.
// Neither the extractor nor classifier stores segments after the current route
// call.
type Segment struct {
	Role       Role
	Provenance SegmentProvenance
	Text       string
}

const (
	maxRoleSegments     = 64
	maxRoleSegmentBytes = 32 << 10
)

type segmentRing struct {
	items     []Segment
	start     int
	truncated bool
}

func (r *segmentRing) add(segment Segment) {
	if strings.TrimSpace(segment.Text) == "" {
		return
	}
	if len(r.items) < maxRoleSegments {
		r.items = append(r.items, segment)
		return
	}
	r.truncated = true
	r.items[r.start] = segment
	r.start = (r.start + 1) % len(r.items)
}

func (r *segmentRing) ordered() []Segment {
	if len(r.items) == 0 {
		return nil
	}
	result := make([]Segment, len(r.items))
	for index := range result {
		result[index] = r.items[(r.start+index)%len(r.items)]
	}
	return result
}

// extractRoleSegments recognizes only standard role-bearing request envelopes.
// It intentionally fails back to Parts on malformed, ambiguous, or unknown
// shapes so role labels can never make an untrusted protocol less strict.
func extractRoleSegments(body []byte, limits Limits) ([]Segment, bool, bool) {
	var historyKey string
	segments := segmentRing{items: make([]Segment, 0, maxRoleSegments)}
	truncated := false
	ambiguous := false
	unsafeRole := false

	err := walkRawObject(body, func(key string, raw json.RawMessage) error {
		standardKey := standardRoleKey(key)
		switch standardKey {
		case "messages", "contents":
			if historyKey != "" || !rawStartsWith(raw, '[') {
				ambiguous = true
				return nil
			}
			historyKey = standardKey
			historyTruncated, historyAmbiguous, historyUnsafeRole, err := addRoleHistorySegments(&segments, raw, historyKey, limits)
			if err != nil {
				return err
			}
			truncated = truncated || historyTruncated
			ambiguous = ambiguous || historyAmbiguous
			unsafeRole = unsafeRole || historyUnsafeRole
		case "input":
			// OpenAI Responses arrays carry the same top-level role shape as
			// messages. Scalar or otherwise unstructured input uses legacy mode.
			if !rawStartsWith(raw, '[') {
				return nil
			}
			if historyKey != "" {
				ambiguous = true
				return nil
			}
			historyKey = standardKey
			historyTruncated, historyAmbiguous, historyUnsafeRole, err := addRoleHistorySegments(&segments, raw, historyKey, limits)
			if err != nil {
				return err
			}
			truncated = truncated || historyTruncated
			ambiguous = ambiguous || historyAmbiguous
			unsafeRole = unsafeRole || historyUnsafeRole
		case "system", "instructions", "systeminstruction":
			partTruncated, partAmbiguous, err := addRoleContentSegments(&segments, raw, RoleSystem, limits)
			if err != nil {
				return err
			}
			truncated = truncated || partTruncated
			ambiguous = ambiguous || partAmbiguous
		default:
			if canonical := canonicalKey(key); canonical == "tools" || canonical == "functions" {
				// Provider tool declarations are system-level context, not user
				// intent and not executable invocation arguments. Retain their
				// semantic descriptions as content so a malicious definition is not
				// silently discarded, while actual calls are split per message below.
				partTruncated, err := addRoleSegment(&segments, raw, RoleSystem, ProvenanceContent, limits, contextTool)
				if err != nil {
					return err
				}
				truncated = truncated || partTruncated
				return nil
			}
			canonical := canonicalKey(key)
			if isMetadataKeyCanonical(canonical) || isProviderMetadataContainerCanonical(canonical) {
				return nil
			}
			// Preserve role isolation for the recognized history while treating
			// every semantic string under an unknown top-level field as untrusted
			// user content. A forged/future envelope therefore cannot hide text,
			// and harmless metadata cannot collapse the whole request into a
			// provenance-less fallback.
			parts, partTruncated, err := extractRawParts(raw, limits, contextText)
			if err != nil {
				return err
			}
			for _, part := range parts {
				segments.add(Segment{Role: RoleUser, Provenance: ProvenanceContent, Text: part})
			}
			truncated = truncated || partTruncated
		}
		return nil
	})
	if err != nil || ambiguous {
		return nil, false, unsafeRole
	}
	if historyKey == "" {
		return nil, false, false
	}

	return segments.ordered(), true, truncated || segments.truncated
}

func addRoleHistorySegments(segments *segmentRing, history json.RawMessage, historyKey string, limits Limits) (bool, bool, bool, error) {
	truncated := false
	ambiguous := false
	unsafeRole := false
	err := walkRawArray(history, func(raw json.RawMessage) error {
		if !rawStartsWith(raw, '{') {
			ambiguous = true
			return nil
		}
		role, present, ok, err := messageRole(raw, historyKey)
		if err != nil {
			unsafeRole = true
			ambiguous = true
			return nil
		}
		if !ok && !present {
			recognized, itemTruncated, err := addRolelessProviderItem(segments, raw, historyKey, limits)
			if err != nil {
				return err
			}
			if recognized {
				truncated = truncated || itemTruncated
				return nil
			}
		}
		if !ok {
			// Role-less Gemini content and OpenAI Responses items are valid
			// provider shapes. They use the conservative legacy fallback. An
			// explicit but unsupported role is different: it is attacker-
			// controlled provenance and enforcing modes must fail closed.
			unsafeRole = present
			ambiguous = true
			return nil
		}
		messageTruncated, messageAmbiguous, err := addRoleMessageSegments(segments, raw, role, limits)
		if err != nil {
			return err
		}
		if messageAmbiguous {
			ambiguous = true
			return nil
		}
		truncated = truncated || messageTruncated
		return nil
	})
	return truncated, ambiguous, unsafeRole, err
}

// addRoleMessageSegments separates rendered message content from executable
// tool-call arguments. Provider wrapper metadata (function names, call IDs,
// types) is deliberately excluded, while argument values remain inspectable.
func addRoleMessageSegments(segments *segmentRing, raw json.RawMessage, role Role, limits Limits) (bool, bool, error) {
	truncated := false
	ambiguous := false
	seenFields := make(map[string]struct{}, 4)

	err := walkRawObject(raw, func(key string, value json.RawMessage) error {
		canonical := canonicalKey(key)
		switch canonical {
		case "role":
			return nil
		case "content", "parts", "refusal":
			if _, seen := seenFields[canonical]; seen {
				ambiguous = true
				return nil
			}
			seenFields[canonical] = struct{}{}
			valueTruncated, valueAmbiguous, err := addRoleContentSegments(segments, value, role, limits)
			truncated = truncated || valueTruncated
			ambiguous = ambiguous || valueAmbiguous
			return err
		case "toolcalls", "toolcall", "functioncall", "tooluse":
			valueTruncated, err := addRoleSegment(segments, value, role, ProvenanceToolPayload, limits, contextTool)
			truncated = truncated || valueTruncated
			return err
		default:
			// Keep the known message content under its proven role, but treat text
			// below an unknown sibling field as a separate untrusted user segment.
			// This is conservative without allowing harmless metadata to erase role
			// isolation for assistant/system refusals and policies.
			if isProviderMetadataContainerCanonical(canonical) {
				return nil
			}
			parts, valueTruncated, err := extractRawParts(value, limits, contextText)
			if err != nil {
				return err
			}
			for _, part := range parts {
				segments.add(Segment{Role: RoleUser, Provenance: ProvenanceContent, Text: part})
			}
			truncated = truncated || valueTruncated
			return nil
		}
	})
	return truncated, ambiguous, err
}

// addRoleContentSegments keeps adjacent natural-language blocks from one
// provider message together. This preserves refusal/policy context when a
// provider splits rendered text into multiple blocks, while tool payload blocks
// remain separately identifiable and executable arguments are never merged
// into the surrounding prose.
func addRoleContentSegments(segments *segmentRing, raw json.RawMessage, role Role, limits Limits) (bool, bool, error) {
	local := segmentRing{items: make([]Segment, 0, 4)}
	truncated, ambiguous, err := addRoleContentValue(&local, raw, role, limits)
	if err != nil || ambiguous {
		return truncated || local.truncated, ambiguous, err
	}

	type pendingContent struct {
		role       Role
		provenance SegmentProvenance
		rawParts   []string
	}
	var pending *pendingContent
	flush := func() {
		if pending != nil {
			rawJoined, joinTruncated := joinRoleParts(pending.rawParts)
			truncated = truncated || joinTruncated
			analysisParts := make([]string, 0, 1+len(pending.rawParts)*2)
			seen := make(map[string]struct{}, 1+len(pending.rawParts)*2)
			appendUnique := func(value string) {
				if strings.TrimSpace(value) == "" {
					return
				}
				if _, exists := seen[value]; exists {
					return
				}
				seen[value] = struct{}{}
				analysisParts = append(analysisParts, value)
			}
			appendDecoded := func(value string) {
				decoded, encoded, incomplete := decodeBoundedText(value)
				if encoded && incomplete {
					truncated = true
				}
				for _, variant := range decoded {
					appendUnique(variant)
				}
			}
			appendUnique(rawJoined)
			for _, rawPart := range pending.rawParts {
				appendDecoded(rawPart)
			}
			// Decode the pristine joined source after the per-block views. This
			// closes both sub-threshold splits and independently decodable chunks;
			// decoded fragments never contaminate the reassembly candidate.
			appendDecoded(rawJoined)
			text, textTruncated := joinRoleParts(analysisParts)
			truncated = truncated || textTruncated
			segments.add(Segment{Role: pending.role, Provenance: pending.provenance, Text: text})
			pending = nil
		}
	}
	for _, segment := range local.ordered() {
		if segment.Provenance != ProvenanceContent {
			flush()
			segments.add(segment)
			continue
		}
		if pending == nil {
			pending = &pendingContent{role: segment.Role, provenance: segment.Provenance, rawParts: []string{segment.Text}}
			continue
		}
		if pending.role != segment.Role || pending.provenance != segment.Provenance {
			flush()
			pending = &pendingContent{role: segment.Role, provenance: segment.Provenance, rawParts: []string{segment.Text}}
			continue
		}
		pending.rawParts = append(pending.rawParts, segment.Text)
	}
	flush()
	return truncated || local.truncated, false, nil
}

func addRoleContentValue(segments *segmentRing, raw json.RawMessage, role Role, limits Limits) (bool, bool, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return false, false, nil
	}
	switch trimmed[0] {
	case '"':
		truncated, err := addRawRoleContentSegment(segments, raw, role, limits)
		return truncated, false, err
	case '{':
		return addRoleContentBlock(segments, raw, role, limits)
	case '[':
		truncated := false
		ambiguous := false
		err := walkRawArray(raw, func(item json.RawMessage) error {
			itemTruncated, itemAmbiguous, err := addRoleContentValue(segments, item, role, limits)
			truncated = truncated || itemTruncated
			ambiguous = ambiguous || itemAmbiguous
			return err
		})
		return truncated, ambiguous, err
	default:
		return false, true, nil
	}
}

func addRoleContentBlock(segments *segmentRing, raw json.RawMessage, role Role, limits Limits) (bool, bool, error) {
	blockType, hasToolPayloadKey, err := roleContentBlockShape(raw)
	if err != nil {
		return false, true, err
	}
	switch blockType {
	case "tooluse", "functioncall", "customtoolcall":
		truncated, err := addRoleSegment(segments, raw, role, ProvenanceToolPayload, limits, contextTool)
		return truncated, false, err
	case "toolresult", "functioncalloutput", "customtoolcalloutput":
		truncated, err := addRawRoleContentSegment(segments, raw, RoleTool, limits)
		return truncated, false, err
	}
	if hasToolPayloadKey {
		// An unknown block carrying argument-shaped fields is not safe to label as
		// ordinary assistant content. Force legacy classification instead.
		return false, true, nil
	}
	truncated, err := addRawRoleContentSegment(segments, raw, role, limits)
	return truncated, false, err
}

func addRawRoleContentSegment(segments *segmentRing, raw json.RawMessage, role Role, limits Limits) (bool, error) {
	parts, partTruncated, err := extractRawPartsWithoutDecode(raw, limits, contextText)
	if err != nil {
		return false, err
	}
	text, joinTruncated := joinRoleParts(parts)
	segments.add(Segment{Role: role, Provenance: ProvenanceContent, Text: text})
	return partTruncated || joinTruncated, nil
}

func roleContentBlockShape(raw json.RawMessage) (string, bool, error) {
	blockType := ""
	typeSeen := false
	wrapperType := ""
	hasToolPayloadKey := false
	err := walkRawObject(raw, func(key string, value json.RawMessage) error {
		canonical := canonicalKey(key)
		if isToolArgumentCanonical(canonical) || canonical == "input" {
			hasToolPayloadKey = true
		}
		if canonical == "functioncall" {
			if wrapperType != "" {
				return errors.New("duplicate content block tool wrapper")
			}
			trimmed := bytes.TrimSpace(value)
			if len(trimmed) == 0 || trimmed[0] != '{' {
				return errors.New("content block functionCall must be an object")
			}
			wrapperType = "functioncall"
			hasToolPayloadKey = true
		}
		if canonical != "type" {
			return nil
		}
		if typeSeen {
			return errors.New("duplicate content block type")
		}
		typeSeen = true
		var valueString string
		if err := json.Unmarshal(value, &valueString); err != nil {
			return err
		}
		blockType = canonicalKey(valueString)
		return nil
	})
	if err != nil {
		return "", hasToolPayloadKey, err
	}
	if wrapperType != "" {
		if blockType != "" && blockType != wrapperType {
			return "", hasToolPayloadKey, errors.New("conflicting content block type and tool wrapper")
		}
		blockType = wrapperType
	}
	return blockType, hasToolPayloadKey, err
}

func addRoleSegment(segments *segmentRing, raw json.RawMessage, role Role, provenance SegmentProvenance, limits Limits, initial contextKind) (bool, error) {
	parts, partTruncated, err := extractRawParts(raw, limits, initial)
	if err != nil {
		return false, err
	}
	if provenance == ProvenanceToolPayload || role == RoleTool {
		rawParts, rawTruncated, rawErr := extractRawPartsWithoutDecode(raw, limits, initial)
		if rawErr != nil {
			return false, rawErr
		}
		text, analysisTruncated := joinRolePartsWithPristineDecode(parts, rawParts)
		segments.add(Segment{Role: role, Provenance: provenance, Text: text})
		return partTruncated || rawTruncated || analysisTruncated, nil
	}
	text, joinTruncated := joinRoleParts(parts)
	segments.add(Segment{Role: role, Provenance: provenance, Text: text})
	return partTruncated || joinTruncated, nil
}

func joinRolePartsWithPristineDecode(parts, rawParts []string) (string, bool) {
	rawJoined, truncated := joinRoleParts(rawParts)
	analysisParts := make([]string, 0, len(parts)+3)
	seen := make(map[string]struct{}, len(parts)+3)
	appendUnique := func(value string) {
		if strings.TrimSpace(value) == "" {
			return
		}
		if _, exists := seen[value]; exists {
			return
		}
		seen[value] = struct{}{}
		analysisParts = append(analysisParts, value)
	}
	appendUnique(rawJoined)
	decoded, encoded, incomplete := decodeBoundedText(rawJoined)
	if encoded && incomplete {
		truncated = true
	}
	for _, variant := range decoded {
		appendUnique(variant)
	}
	for _, part := range parts {
		appendUnique(part)
	}
	text, joinTruncated := joinRoleParts(analysisParts)
	return text, truncated || joinTruncated
}

// addRolelessProviderItem recognizes only provider-native typed items whose
// provenance is intrinsic to the envelope. Other missing-role shapes retain
// the conservative legacy fallback.
func addRolelessProviderItem(segments *segmentRing, raw json.RawMessage, envelope string, limits Limits) (bool, bool, error) {
	if envelope != "input" {
		return false, false, nil
	}
	blockType, _, err := roleContentBlockShape(raw)
	if err != nil {
		return false, false, err
	}
	switch blockType {
	case "functioncall", "customtoolcall":
		truncated, err := addRoleSegment(segments, raw, RoleAssistant, ProvenanceToolPayload, limits, contextTool)
		return true, truncated, err
	case "functioncalloutput", "customtoolcalloutput":
		truncated, err := addRoleSegment(segments, raw, RoleTool, ProvenanceContent, limits, contextText)
		return true, truncated, err
	default:
		return false, false, nil
	}
}

func messageRole(raw json.RawMessage, envelope string) (Role, bool, bool, error) {
	seen := false
	value := ""
	err := walkRawObject(raw, func(key string, rawValue json.RawMessage) error {
		if !strings.EqualFold(strings.TrimSpace(key), "role") {
			return nil
		}
		if seen {
			return errors.New("duplicate message role")
		}
		seen = true
		return json.Unmarshal(rawValue, &value)
	})
	if err != nil || !seen {
		return "", seen, false, err
	}
	role := strings.ToLower(strings.TrimSpace(value))
	switch role {
	case "user":
		return RoleUser, true, true, nil
	case "system", "developer":
		return RoleSystem, true, true, nil
	case "assistant":
		return RoleAssistant, true, true, nil
	case "model":
		if envelope == "contents" {
			return RoleAssistant, true, true, nil
		}
	case "tool", "function":
		return RoleTool, true, true, nil
	}
	return "", true, false, nil
}

func standardRoleKey(key string) string {
	trimmed := strings.TrimSpace(key)
	switch {
	case strings.EqualFold(trimmed, "messages"):
		return "messages"
	case strings.EqualFold(trimmed, "contents"):
		return "contents"
	case strings.EqualFold(trimmed, "input"):
		return "input"
	case strings.EqualFold(trimmed, "system"):
		return "system"
	case strings.EqualFold(trimmed, "instructions"):
		return "instructions"
	case strings.EqualFold(trimmed, "system_instruction"), strings.EqualFold(trimmed, "systemInstruction"):
		return "systeminstruction"
	default:
		return ""
	}
}

func extractRawParts(raw []byte, limits Limits, initial contextKind) ([]string, bool, error) {
	result := Result{Parts: make([]string, 0, minInt(4, limits.MaxTextParts))}
	x := extractor{limits: limits, result: &result}
	if err := x.walkJSON(raw, initial, 0, false); err != nil {
		return nil, false, err
	}
	return result.Parts, result.Truncated, nil
}

func extractRawPartsWithoutDecode(raw []byte, limits Limits, initial contextKind) ([]string, bool, error) {
	result := Result{Parts: make([]string, 0, minInt(4, limits.MaxTextParts))}
	x := extractor{limits: limits, result: &result, skipDecode: true}
	if err := x.walkJSON(raw, initial, 0, false); err != nil {
		return nil, false, err
	}
	return result.Parts, result.Truncated, nil
}

func joinRoleParts(parts []string) (string, bool) {
	if len(parts) == 0 {
		return "", false
	}
	if len(parts) == 1 && len(parts[0]) <= maxRoleSegmentBytes {
		return parts[0], false
	}
	var builder strings.Builder
	builder.Grow(minInt(maxRoleSegmentBytes, totalPartBytes(parts)))
	truncated := false
	for _, part := range parts {
		if part == "" {
			continue
		}
		if builder.Len() > 0 {
			if builder.Len() == maxRoleSegmentBytes {
				truncated = true
				break
			}
			builder.WriteByte('\n')
		}
		remaining := maxRoleSegmentBytes - builder.Len()
		if len(part) > remaining {
			part = utf8Prefix(part, remaining)
			truncated = true
		}
		builder.WriteString(part)
		if truncated {
			break
		}
	}
	return builder.String(), truncated
}

func totalPartBytes(parts []string) int {
	total := 0
	for _, part := range parts {
		if total >= maxRoleSegmentBytes-len(part)-1 {
			return maxRoleSegmentBytes
		}
		total += len(part) + 1
	}
	return total
}

func utf8Prefix(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if len(value) <= limit {
		return value
	}
	for limit > 0 && !utf8.RuneStart(value[limit]) {
		limit--
	}
	return value[:limit]
}

func rawStartsWith(raw []byte, want byte) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == want
}

func walkRawObject(data []byte, visit func(string, json.RawMessage) error) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	opening, err := decoder.Token()
	if err != nil {
		return err
	}
	if opening != json.Delim('{') {
		return errors.New("role envelope is not an object")
	}
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return errors.New("role envelope key is not a string")
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return err
		}
		if err := visit(key, raw); err != nil {
			return err
		}
	}
	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	if closing != json.Delim('}') {
		return errors.New("role envelope has invalid closing delimiter")
	}
	return requireJSONEOF(decoder)
}

func walkRawArray(data []byte, visit func(json.RawMessage) error) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	opening, err := decoder.Token()
	if err != nil {
		return err
	}
	if opening != json.Delim('[') {
		return errors.New("role history is not an array")
	}
	for decoder.More() {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return err
		}
		if err := visit(raw); err != nil {
			return err
		}
	}
	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	if closing != json.Delim(']') {
		return errors.New("role history has invalid closing delimiter")
	}
	return requireJSONEOF(decoder)
}

func requireJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("role JSON contains trailing values")
		}
		return err
	}
	return nil
}
