// Package extract performs bounded, format-tolerant extraction of text from
// supported LLM JSON request bodies. It deliberately has no dependency on the
// CPA plugin package so it can be fuzzed and reused independently.
package extract

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

const (
	DefaultMaxScanBytes = 262144
	DefaultMaxJSONDepth = 32
	DefaultMaxTextParts = 512

	HardMaxScanBytes = 4 << 20
	HardMaxJSONDepth = 128
	HardMaxTextParts = 4096

	// Keeping parts modest prevents a single prompt from forcing large
	// downstream classifier allocations. This is an implementation bound, not
	// a separately configurable policy knob.
	maxTextPartBytes = 16 << 10
)

var (
	ErrInvalidJSON   = errors.New("extract: invalid JSON")
	ErrInvalidLimits = errors.New("extract: invalid limits")
)

// Limits bounds both raw input processing and semantic traversal. A zero field
// uses its secure task-book default; negative or excessively large values are
// rejected.
type Limits struct {
	MaxScanBytes int
	MaxJSONDepth int
	MaxTextParts int
}

// Result contains only extracted text and bounded-processing metadata.
// ParseError is intentionally a message rather than the source body so callers
// can audit failures without retaining prompts.
type Result struct {
	Parts        []string
	BytesScanned int
	Truncated    bool
	ParseError   string
}

// ExtractText extracts text from OpenAI Chat/Responses, Anthropic Messages,
// Gemini, and common nested tool-call shapes. Invalid JSON returns
// ErrInvalidJSON and also populates Result.ParseError. A request cut by
// MaxScanBytes returns all complete text tokens before the boundary and sets
// Truncated instead of mislabelling the valid original request as malformed.
func ExtractText(body []byte, limits Limits) (Result, error) {
	limits, err := limits.normalized()
	if err != nil {
		return Result{}, err
	}

	scanBytes := len(body)
	if scanBytes > limits.MaxScanBytes {
		scanBytes = limits.MaxScanBytes
	}
	result := Result{
		Parts:        make([]string, 0, minInt(8, limits.MaxTextParts)),
		BytesScanned: scanBytes,
		Truncated:    len(body) > scanBytes,
	}
	x := extractor{limits: limits, result: &result}
	if err := x.walkJSON(body[:scanBytes], contextNone, 0, len(body) > scanBytes); err != nil {
		wrapped := fmt.Errorf("%w: %v", ErrInvalidJSON, err)
		result.ParseError = wrapped.Error()
		return result, wrapped
	}
	return result, nil
}

func (l Limits) normalized() (Limits, error) {
	if l.MaxScanBytes == 0 {
		l.MaxScanBytes = DefaultMaxScanBytes
	}
	if l.MaxJSONDepth == 0 {
		l.MaxJSONDepth = DefaultMaxJSONDepth
	}
	if l.MaxTextParts == 0 {
		l.MaxTextParts = DefaultMaxTextParts
	}
	if l.MaxScanBytes < 1 || l.MaxScanBytes > HardMaxScanBytes {
		return Limits{}, fmt.Errorf("%w: MaxScanBytes must be between 1 and %d", ErrInvalidLimits, HardMaxScanBytes)
	}
	if l.MaxJSONDepth < 1 || l.MaxJSONDepth > HardMaxJSONDepth {
		return Limits{}, fmt.Errorf("%w: MaxJSONDepth must be between 1 and %d", ErrInvalidLimits, HardMaxJSONDepth)
	}
	if l.MaxTextParts < 1 || l.MaxTextParts > HardMaxTextParts {
		return Limits{}, fmt.Errorf("%w: MaxTextParts must be between 1 and %d", ErrInvalidLimits, HardMaxTextParts)
	}
	return l, nil
}

type contextKind uint8

const (
	contextNone contextKind = iota
	contextText
	contextTool
)

type jsonFrame struct {
	kind      json.Delim
	context   contextKind
	media     bool
	expectKey bool
	key       string
}

type extractor struct {
	limits Limits
	result *Result
	stop   bool
}

// walkJSON uses Decoder.Token and an explicit stack. Consequently, semantic
// traversal does not recurse with attacker-controlled JSON nesting. Recursive
// calls are used only for JSON strings in tool arguments and are charged
// against the same MaxJSONDepth budget.
func (x *extractor) walkJSON(data []byte, initial contextKind, baseDepth int, boundaryTruncated bool) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()

	stack := make([]jsonFrame, 0, minInt(x.limits.MaxJSONDepth, 16))
	rootSeen := false
	rootDone := false

	for {
		token, err := decoder.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				switch {
				case rootDone:
					return nil
				case boundaryTruncated && rootSeen:
					return nil
				case !rootSeen:
					return errors.New("empty JSON input")
				default:
					return io.ErrUnexpectedEOF
				}
			}
			if boundaryTruncated && parseErrorAtBoundary(err) {
				return nil
			}
			return err
		}

		if rootDone {
			return errors.New("multiple JSON values")
		}

		if delim, ok := token.(json.Delim); ok && (delim == '}' || delim == ']') {
			if len(stack) == 0 {
				return fmt.Errorf("unexpected closing delimiter %q", delim)
			}
			top := stack[len(stack)-1]
			if (delim == '}' && top.kind != '{') || (delim == ']' && top.kind != '[') {
				return fmt.Errorf("mismatched closing delimiter %q", delim)
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				rootDone = true
			}
			continue
		}

		if len(stack) > 0 {
			top := &stack[len(stack)-1]
			if top.kind == '{' && top.expectKey {
				key, ok := token.(string)
				if !ok {
					return errors.New("object key is not a string")
				}
				top.key = key
				top.expectKey = false
				continue
			}
		}

		ctx, media, key := x.valueContext(stack, initial)
		if len(stack) > 0 && stack[len(stack)-1].kind == '{' {
			top := &stack[len(stack)-1]
			top.expectKey = true
			top.key = ""
		}
		rootSeen = true

		if delim, ok := token.(json.Delim); ok && (delim == '{' || delim == '[') {
			depth := baseDepth + len(stack) + 1
			if depth > x.limits.MaxJSONDepth {
				x.result.Truncated = true
				x.stop = true
				// Do not keep walking or growing a frame stack past the
				// configured semantic depth. A deeply nested JSON bomb must
				// consume O(MaxJSONDepth), not O(attacker depth), memory.
				return nil
			}
			stack = append(stack, jsonFrame{
				kind:      delim,
				context:   ctx,
				media:     media,
				expectKey: delim == '{',
			})
			canonical := canonicalKey(key)
			if media && (isOpaquePayloadKeyCanonical(canonical) || (delim == '[' && isDirectMediaValueKeyCanonical(canonical))) {
				x.result.Truncated = true
			}
			continue
		}

		if text, ok := token.(string); ok {
			if len(stack) > 0 && marksMediaContext(key, text) {
				stack[len(stack)-1].media = true
				media = true
			}
			x.processString(text, key, ctx, media, baseDepth+len(stack))
			if x.stop {
				return nil
			}
		}
		if len(stack) == 0 {
			rootDone = true
		}
	}
}

func (x *extractor) valueContext(stack []jsonFrame, initial contextKind) (contextKind, bool, string) {
	if len(stack) == 0 {
		return initial, false, ""
	}
	parent := stack[len(stack)-1]
	if parent.kind == '[' {
		return parent.context, parent.media, ""
	}

	key := parent.key
	media := parent.media || isMediaContainerKeyCanonical(canonicalKey(key))
	return childContext(parent.context, key), media, key
}

func childContext(parent contextKind, key string) contextKind {
	canonical := canonicalKey(key)
	if isToolKeyCanonical(canonical) {
		return contextTool
	}
	if canonical == "data" {
		if parent == contextTool {
			return contextTool
		}
		return contextText
	}
	if isTextKeyCanonical(canonical) || isTextContainerCanonical(canonical) {
		if parent == contextTool {
			return contextTool
		}
		return contextText
	}
	return parent
}

func (x *extractor) processString(text, key string, ctx contextKind, media bool, semanticDepth int) {
	canonical := canonicalKey(key)
	trimmed := strings.TrimSpace(text)
	if isOpaqueDataURL(text) || containsBinaryControl(text) {
		x.result.Truncated = true
		return
	}
	if media {
		if isHTTPURL(text) {
			return
		}
		if isDirectMediaValueKeyCanonical(canonical) || looksLikeBase64(trimmed) {
			x.result.Truncated = true
			return
		}
		if isMediaMetadataKeyCanonical(canonical) {
			return
		}
		if ctx == contextNone {
			x.addText(text, key)
			return
		}
	} else if looksLikeBase64(trimmed) {
		// An unknown field may be ordinary no-whitespace text rather than media,
		// so preserve it for deterministic inspection. It is still semantically
		// opaque, however, and enforcement modes must not treat it as fully
		// classified merely because it happens to decode as base64.
		x.result.Truncated = true
	}
	if isToolArgumentCanonical(canonical) {
		trimmed := strings.TrimSpace(text)
		if len(trimmed) > 1 && (trimmed[0] == '{' || trimmed[0] == '[') {
			if semanticDepth >= x.limits.MaxJSONDepth {
				x.result.Truncated = true
				x.stop = true
				return
			}
			if json.Valid([]byte(trimmed)) {
				// json.Valid above makes this transactional: malformed nested
				// arguments cannot leak partial parts before falling back to text.
				_ = x.walkJSON([]byte(trimmed), contextTool, semanticDepth, false)
				return
			}
		}
		x.addText(text, key)
		return
	}

	if ctx == contextNone || isMetadataKeyCanonical(canonical) {
		return
	}
	x.addText(text, key)
}

func (x *extractor) addText(text, key string) {
	if strings.TrimSpace(text) == "" {
		return
	}
	for len(text) > maxTextPartBytes {
		if len(x.result.Parts) >= x.limits.MaxTextParts {
			x.result.Truncated = true
			x.stop = true
			return
		}
		cut := maxTextPartBytes
		for cut > 0 && !utf8.RuneStart(text[cut]) {
			cut--
		}
		if cut == 0 {
			cut = maxTextPartBytes
		}
		x.result.Parts = append(x.result.Parts, text[:cut])
		text = text[cut:]
	}
	if text == "" {
		return
	}
	if len(x.result.Parts) >= x.limits.MaxTextParts {
		x.result.Truncated = true
		x.stop = true
		return
	}
	x.result.Parts = append(x.result.Parts, text)
}

func canonicalKey(key string) string {
	if key == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(key))
	for _, r := range key {
		switch r {
		case '_', '-', ' ':
			continue
		default:
			if r >= 'A' && r <= 'Z' {
				r += 'a' - 'A'
			}
			b.WriteRune(r)
		}
	}
	return b.String()
}

func isTextKeyCanonical(key string) bool {
	switch key {
	case "content", "text", "input", "inputtext", "outputtext", "system", "instructions", "systeminstruction", "prompt", "query":
		return true
	default:
		return false
	}
}

func isTextContainerCanonical(key string) bool {
	switch key {
	case "messages", "contents", "parts":
		return true
	default:
		return false
	}
}

func isToolKeyCanonical(key string) bool {
	switch key {
	case "toolcalls", "toolcall", "tooluse", "function", "functioncall", "arguments", "args", "parameters":
		return true
	default:
		return false
	}
}

func isToolArgumentCanonical(key string) bool {
	switch key {
	case "arguments", "args", "parameters":
		return true
	default:
		return false
	}
}

func isMetadataKeyCanonical(key string) bool {
	switch key {
	case "role", "type", "name", "id", "model", "status", "index", "mimetype", "mediatype", "encoding", "url", "callid", "toolcallid", "finishreason":
		return true
	default:
		return false
	}
}

func isMediaContainerKeyCanonical(key string) bool {
	switch key {
	case "image", "imageurl", "imagedata", "inputimage", "outputimage", "audio", "inputaudio", "inlineaudio", "inlinedata", "filedata":
		return true
	default:
		return false
	}
}

func isOpaquePayloadKeyCanonical(key string) bool {
	switch key {
	case "data", "bytes", "blob", "binary", "imagedata", "filedata":
		return true
	default:
		return false
	}
}

func isDirectMediaValueKeyCanonical(key string) bool {
	return isMediaContainerKeyCanonical(key) || isOpaquePayloadKeyCanonical(key)
}

func isMediaMetadataKeyCanonical(key string) bool {
	if isMetadataKeyCanonical(key) {
		return true
	}
	switch key {
	case "detail", "width", "height", "duration", "filename", "format":
		return true
	default:
		return false
	}
}

func marksMediaContext(key, value string) bool {
	canonical := canonicalKey(key)
	trimmed := strings.ToLower(strings.TrimSpace(value))
	switch canonical {
	case "type":
		switch canonicalKey(trimmed) {
		case "image", "imageurl", "inputimage", "outputimage", "audio", "inputaudio", "inlineaudio", "inlinedata":
			return true
		}
	case "mimetype", "mediatype":
		return isOpaqueMediaMIME(trimmed)
	}
	return false
}

func isOpaqueMediaMIME(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, prefix := range []string{"image/", "audio/", "video/"} {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return value == "application/octet-stream" || value == "application/pdf"
}

func isOpaqueDataURL(value string) bool {
	trimmed := strings.TrimSpace(value)
	lower := strings.ToLower(trimmed)
	if !strings.HasPrefix(lower, "data:") {
		return false
	}
	comma := strings.IndexByte(lower, ',')
	if comma < 0 {
		return true
	}
	header := lower[len("data:"):comma]
	mimeType := header
	if semicolon := strings.IndexByte(mimeType, ';'); semicolon >= 0 {
		mimeType = mimeType[:semicolon]
	}
	return strings.Contains(header, ";base64") || isOpaqueMediaMIME(mimeType)
}

func isHTTPURL(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.HasPrefix(value, "https://") || strings.HasPrefix(value, "http://")
}

func containsBinaryControl(value string) bool {
	for _, r := range value {
		if (r >= 0 && r < 0x20 && r != '\n' && r != '\r' && r != '\t') || r == 0x7f {
			return true
		}
	}
	return false
}

func looksLikeBase64(value string) bool {
	if len(value) < 128 {
		return false
	}
	var compact strings.Builder
	compact.Grow(len(value))
	urlAlphabet := false
	for _, r := range value {
		switch {
		case r == '\r' || r == '\n':
			continue
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '+', r == '/', r == '=':
			compact.WriteRune(r)
		case r == '-' || r == '_':
			urlAlphabet = true
			compact.WriteRune(r)
		default:
			return false
		}
	}
	encoded := compact.String()
	if len(encoded) < 128 || len(encoded)%4 == 1 {
		return false
	}

	var encoding *base64.Encoding
	switch {
	case urlAlphabet && strings.HasSuffix(encoded, "="):
		encoding = base64.URLEncoding
	case urlAlphabet:
		encoding = base64.RawURLEncoding
	case strings.HasSuffix(encoded, "=") || len(encoded)%4 == 0:
		encoding = base64.StdEncoding
	default:
		encoding = base64.RawStdEncoding
	}
	_, err := io.Copy(io.Discard, base64.NewDecoder(encoding, strings.NewReader(encoded)))
	return err == nil
}

func parseErrorAtBoundary(err error) bool {
	message := strings.ToLower(err.Error())
	if errors.Is(err, io.ErrUnexpectedEOF) || strings.Contains(message, "unexpected eof") || strings.Contains(message, "unexpected end of json") {
		return true
	}
	return false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
