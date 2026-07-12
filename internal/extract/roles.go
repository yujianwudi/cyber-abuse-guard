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

// Segment is transient request text plus its normalized role. Neither the
// extractor nor classifier stores segments after the current route call.
type Segment struct {
	Role Role
	Text string
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
	var history json.RawMessage
	segments := segmentRing{items: make([]Segment, 0, maxRoleSegments)}
	truncated := false
	ambiguous := false

	err := walkRawObject(body, func(key string, raw json.RawMessage) error {
		standardKey := standardRoleKey(key)
		switch standardKey {
		case "messages", "contents":
			if historyKey != "" || !rawStartsWith(raw, '[') {
				ambiguous = true
				return nil
			}
			historyKey = standardKey
			history = append(history[:0], raw...)
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
			history = append(history[:0], raw...)
		case "system", "instructions", "systeminstruction":
			parts, partTruncated, err := extractRawParts(raw, limits, contextText)
			if err != nil {
				return err
			}
			text, joinTruncated := joinRoleParts(parts)
			truncated = truncated || partTruncated || joinTruncated
			segments.add(Segment{Role: RoleSystem, Text: text})
		default:
			// Detect semantic text hidden beside an otherwise standard history.
			// Metadata/model/options produce no parts and remain compatible.
			parts, partTruncated, err := extractRawParts(raw, limits, childContext(contextNone, key))
			if err != nil {
				return err
			}
			if len(parts) > 0 || partTruncated {
				ambiguous = true
			}
		}
		return nil
	})
	if err != nil || ambiguous {
		return nil, false, false
	}
	if historyKey == "" {
		return nil, false, false
	}

	unsafeRole := false
	err = walkRawArray(history, func(raw json.RawMessage) error {
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
		if !ok {
			// Role-less Gemini content and OpenAI Responses items are valid
			// provider shapes. They use the conservative legacy fallback. An
			// explicit but unsupported role is different: it is attacker-
			// controlled provenance and enforcing modes must fail closed.
			unsafeRole = present
			ambiguous = true
			return nil
		}
		parts, partTruncated, err := extractRawParts(raw, limits, contextText)
		if err != nil {
			return err
		}
		text, joinTruncated := joinRoleParts(parts)
		truncated = truncated || partTruncated || joinTruncated
		segments.add(Segment{Role: role, Text: text})
		return nil
	})
	if err != nil || ambiguous {
		return nil, false, unsafeRole
	}
	return segments.ordered(), true, truncated || segments.truncated
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
