// Package extract performs bounded, format-tolerant extraction of text from
// supported LLM JSON request bodies. It deliberately has no dependency on the
// CPA plugin package so it can be fuzzed and reused independently.
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
	Segments     []Segment
	RoleAware    bool
	BytesScanned int
	Truncated    bool
	// OpaqueMedia reports media that was deliberately not fetched or decoded.
	// It is separate from Truncated so routing policy can audit or allow
	// legitimate multimodal requests without weakening fail-closed handling for
	// genuinely incomplete text inspection.
	OpaqueMedia      bool
	OpaqueMediaKinds []OpaqueMediaKind
	ParseError       string
}

// OpaqueMediaKind is a content-free, bounded classification of media that was
// deliberately not fetched or decoded. It is safe for counters and health
// telemetry because it cannot contain a URL, filename, MIME parameter, or
// request fragment.
type OpaqueMediaKind string

const (
	OpaqueMediaHTTPSImageURL OpaqueMediaKind = "https_image_url"
	OpaqueMediaDataURL       OpaqueMediaKind = "data_url"
	OpaqueMediaBase64Image   OpaqueMediaKind = "base64_image"
	OpaqueMediaAudio         OpaqueMediaKind = "audio"
	OpaqueMediaVideo         OpaqueMediaKind = "video"
	OpaqueMediaDocument      OpaqueMediaKind = "document_attachment"
	OpaqueMediaRemoteURL     OpaqueMediaKind = "remote_media_url"
	OpaqueMediaOther         OpaqueMediaKind = "other"
)

// ExtractText extracts text from OpenAI Chat/Responses, Anthropic Messages,
// Gemini, and common nested tool-call shapes. Invalid JSON returns
// ErrInvalidJSON and also populates Result.ParseError. A request cut by
// MaxScanBytes returns all complete text tokens before the boundary and sets
// Truncated instead of mislabelling the valid original request as malformed.
func ExtractText(body []byte, limits Limits) (Result, error) {
	return extractText(body, limits, contextNone, true)
}

// ExtractUntrustedText performs a conservative bounded walk for an unknown
// provider shape. Every non-metadata string is treated as user-controlled
// text, including values nested below field names the current provider-aware
// extractor does not recognize. Role attribution is deliberately disabled:
// an unknown schema cannot safely prove that a field is a trusted system or
// assistant message.
func ExtractUntrustedText(body []byte, limits Limits) (Result, error) {
	return extractText(body, limits, contextText, false)
}

func extractText(body []byte, limits Limits, initial contextKind, roleIndex bool) (Result, error) {
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
	if err := x.walkJSON(body[:scanBytes], initial, 0, len(body) > scanBytes); err != nil {
		wrapped := fmt.Errorf("%w: %v", ErrInvalidJSON, err)
		result.ParseError = wrapped.Error()
		return result, wrapped
	}
	// Role indexing is attempted only for a complete JSON body. When the scan
	// boundary cuts the request, enforcing modes already fail closed on the
	// legacy truncation marker and partial role attribution would be misleading.
	// A bounded first pass that already found an incomplete decode or exceeded
	// semantic depth has established a fail-closed result. Do not feed the same
	// attacker-controlled body into the RawMessage role indexer afterward: that
	// would defeat the O(MaxJSONDepth) traversal guarantee with a second deep
	// parse and cannot make the incomplete request safe.
	if roleIndex && scanBytes == len(body) && !result.Truncated {
		segments, roleAware, roleTruncated := extractRoleSegments(body, limits)
		result.Truncated = result.Truncated || roleTruncated
		if roleAware {
			result.Segments = segments
			result.RoleAware = true
		}
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
	contextToolPayload
)

type jsonFrame struct {
	kind               json.Delim
	context            contextKind
	media              bool
	mediaKind          mediaContextKind
	pendingDirectMedia bool
	pendingHTTPURL     bool
	pendingHTTPSURL    bool
	expectKey          bool
	key                string
}

type mediaContextKind uint8

const (
	mediaContextNone mediaContextKind = iota
	mediaContextImage
	mediaContextAudio
	mediaContextVideo
	mediaContextDocument
	mediaContextOther
)

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
				case boundaryTruncated:
					return nil
				case !rootSeen:
					return errors.New("empty JSON input")
				default:
					return io.ErrUnexpectedEOF
				}
			}
			// The decoder validates a synthetic prefix when MaxScanBytes cuts a
			// larger request. EOF inside an escape or UTF-8 sequence can surface as
			// a syntax error other than unexpected EOF even though the complete
			// request is valid. Preserve the already-set truncation marker and let
			// enforcing modes fail closed instead of misclassifying that artificial
			// boundary as a parse error (which CPA routers handle fail-open).
			if boundaryTruncated {
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
			if len(stack) > 0 && !top.media {
				parent := &stack[len(stack)-1]
				parent.pendingDirectMedia = parent.pendingDirectMedia || top.pendingDirectMedia
				parent.pendingHTTPURL = parent.pendingHTTPURL || top.pendingHTTPURL
				parent.pendingHTTPSURL = parent.pendingHTTPSURL || top.pendingHTTPSURL
				if parent.media {
					x.markPendingOpaqueMedia(parent)
				}
			}
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

		ctx, media, mediaKind, key := x.valueContext(stack, initial)
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
			canonical := canonicalKey(key)
			if len(stack) > 0 && isOpaquePayloadKeyCanonical(canonical) {
				parent := &stack[len(stack)-1]
				parent.pendingDirectMedia = true
				if parent.media {
					x.markPendingOpaqueMedia(parent)
				}
			}
			stack = append(stack, jsonFrame{
				kind:      delim,
				context:   ctx,
				media:     media,
				mediaKind: mediaKind,
				expectKey: delim == '{',
			})
			if media && (isOpaquePayloadKeyCanonical(canonical) || (delim == '[' && isDirectMediaValueKeyCanonical(canonical))) {
				x.markOpaqueMedia(directOpaqueKind(mediaKind))
			}
			continue
		}

		if text, ok := token.(string); ok {
			if len(stack) > 0 {
				frame := &stack[len(stack)-1]
				x.rememberOpaqueMediaCandidate(frame, key, text)
				if marked, markedKind := marksMediaContext(key, text); marked {
					frame.media = true
					frame.mediaKind = markedKind
					media = true
					mediaKind = markedKind
					x.markPendingOpaqueMedia(frame)
				}
			}
			x.processString(text, key, ctx, media, mediaKind, baseDepth+len(stack))
			if x.stop {
				return nil
			}
		}
		if len(stack) == 0 {
			rootDone = true
		}
	}
}

// rememberOpaqueMediaCandidate retains constant-size evidence for values that
// appeared before their sibling type/MIME marker. JSON object members are
// unordered, so a later marker must classify earlier URL/data values exactly as
// it would if the marker had appeared first.
func (x *extractor) rememberOpaqueMediaCandidate(frame *jsonFrame, key, value string) {
	if frame == nil {
		return
	}
	if _, opaque := opaqueDataURLKind(value); opaque {
		// processString records the exact data-URL kind independently of sibling
		// metadata; retaining a generic direct-media candidate would double count.
		return
	}
	if isHTTPURL(value) {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "https://") {
			frame.pendingHTTPSURL = true
		} else {
			frame.pendingHTTPURL = true
		}
	} else if isDirectMediaValueKeyCanonical(canonicalKey(key)) {
		frame.pendingDirectMedia = true
	}
	if frame.media {
		x.markPendingOpaqueMedia(frame)
	}
}

func (x *extractor) markPendingOpaqueMedia(frame *jsonFrame) {
	if frame == nil || !frame.media {
		return
	}
	if frame.pendingDirectMedia {
		x.markOpaqueMedia(directOpaqueKind(frame.mediaKind))
	}
	if frame.pendingHTTPURL {
		x.markOpaqueMedia(remoteOpaqueKind(frame.mediaKind, "http://opaque.invalid"))
	}
	if frame.pendingHTTPSURL {
		x.markOpaqueMedia(remoteOpaqueKind(frame.mediaKind, "https://opaque.invalid"))
	}
}

func (x *extractor) valueContext(stack []jsonFrame, initial contextKind) (contextKind, bool, mediaContextKind, string) {
	if len(stack) == 0 {
		return initial, false, mediaContextNone, ""
	}
	parent := stack[len(stack)-1]
	if parent.kind == '[' {
		return parent.context, parent.media, parent.mediaKind, ""
	}

	key := parent.key
	keyKind := mediaContextForKey(canonicalKey(key))
	media := parent.media || keyKind != mediaContextNone
	mediaKind := parent.mediaKind
	if keyKind != mediaContextNone {
		mediaKind = keyKind
	}
	return childContext(parent.context, key), media, mediaKind, key
}

func childContext(parent contextKind, key string) contextKind {
	canonical := canonicalKey(key)
	if parent == contextToolPayload {
		return contextToolPayload
	}
	if isToolArgumentCanonical(canonical) || (canonical == "input" && (parent == contextTool || parent == contextText)) {
		return contextToolPayload
	}
	if isToolWrapperKeyCanonical(canonical) {
		return contextTool
	}
	if canonical == "data" {
		if parent == contextTool || parent == contextToolPayload {
			return contextToolPayload
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

func (x *extractor) processString(text, key string, ctx contextKind, media bool, mediaKind mediaContextKind, semanticDepth int) {
	canonical := canonicalKey(key)
	trimmed := strings.TrimSpace(text)
	if kind, opaque := opaqueDataURLKind(text); opaque {
		x.markOpaqueMedia(kind)
		return
	}
	if containsBinaryControl(text) {
		x.result.Truncated = true
		return
	}
	if media {
		if isHTTPURL(text) {
			x.markOpaqueMedia(remoteOpaqueKind(mediaKind, text))
			return
		}
		if isDirectMediaValueKeyCanonical(canonical) {
			x.markOpaqueMedia(directOpaqueKind(mediaKind))
			return
		}
		if isMediaMetadataKeyCanonical(canonical) {
			return
		}
		if ctx == contextNone {
			x.addText(text, key)
			return
		}
	}
	if isToolArgumentCanonical(canonical) {
		if x.processNestedToolJSON(trimmed, semanticDepth) {
			return
		}
	}

	if ctx == contextNone || (ctx != contextToolPayload && isMetadataKeyCanonical(canonical)) {
		return
	}
	x.addText(text, key)
	decoded, encoded, incomplete := decodeBoundedText(text)
	if encoded && incomplete {
		x.result.Truncated = true
	}
	for _, variant := range decoded {
		if isToolArgumentCanonical(canonical) && x.processNestedToolJSON(strings.TrimSpace(variant), semanticDepth) {
			if x.stop {
				return
			}
			continue
		}
		x.addText(variant, key)
		if x.stop {
			return
		}
	}
}

func (x *extractor) markOpaqueMedia(kind OpaqueMediaKind) {
	x.result.OpaqueMedia = true
	if kind == "" {
		kind = OpaqueMediaOther
	}
	for _, existing := range x.result.OpaqueMediaKinds {
		if existing == kind {
			return
		}
	}
	x.result.OpaqueMediaKinds = append(x.result.OpaqueMediaKinds, kind)
}

func (x *extractor) processNestedToolJSON(trimmed string, semanticDepth int) bool {
	if len(trimmed) <= 1 || (trimmed[0] != '{' && trimmed[0] != '[') || !json.Valid([]byte(trimmed)) {
		return false
	}
	if semanticDepth >= x.limits.MaxJSONDepth {
		x.result.Truncated = true
		x.stop = true
		return true
	}
	// json.Valid above makes this transactional: malformed nested arguments
	// cannot leak partial parts before falling back to text.
	_ = x.walkJSON([]byte(trimmed), contextToolPayload, semanticDepth, false)
	return true
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

func isToolWrapperKeyCanonical(key string) bool {
	switch key {
	case "toolcalls", "toolcall", "tooluse", "function", "functioncall":
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
	return mediaContextForKey(key) != mediaContextNone
}

func mediaContextForKey(key string) mediaContextKind {
	switch key {
	case "image", "imageurl", "imagedata", "inputimage", "outputimage":
		return mediaContextImage
	case "audio", "inputaudio", "inlineaudio":
		return mediaContextAudio
	case "video", "inputvideo", "outputvideo":
		return mediaContextVideo
	case "file", "filedata", "document", "attachment":
		return mediaContextDocument
	case "inlinedata":
		return mediaContextOther
	default:
		return mediaContextNone
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

func marksMediaContext(key, value string) (bool, mediaContextKind) {
	canonical := canonicalKey(key)
	trimmed := strings.ToLower(strings.TrimSpace(value))
	switch canonical {
	case "type":
		switch canonicalKey(trimmed) {
		case "image", "imageurl", "inputimage", "outputimage":
			return true, mediaContextImage
		case "audio", "inputaudio", "inlineaudio":
			return true, mediaContextAudio
		case "video", "inputvideo", "outputvideo":
			return true, mediaContextVideo
		case "file", "document", "attachment":
			return true, mediaContextDocument
		case "inlinedata":
			return true, mediaContextOther
		}
	case "mimetype", "mediatype":
		kind := mediaContextForMIME(trimmed)
		return kind != mediaContextNone, kind
	}
	return false, mediaContextNone
}

func isOpaqueMediaMIME(value string) bool {
	return mediaContextForMIME(value) != mediaContextNone
}

func mediaContextForMIME(value string) mediaContextKind {
	value = strings.ToLower(strings.TrimSpace(value))
	switch {
	case strings.HasPrefix(value, "image/"):
		return mediaContextImage
	case strings.HasPrefix(value, "audio/"):
		return mediaContextAudio
	case strings.HasPrefix(value, "video/"):
		return mediaContextVideo
	case value == "application/pdf", value == "application/octet-stream",
		value == "application/msword", strings.HasPrefix(value, "application/vnd.openxmlformats-officedocument"):
		return mediaContextDocument
	default:
		return mediaContextNone
	}
}

func opaqueDataURLKind(value string) (OpaqueMediaKind, bool) {
	trimmed := strings.TrimSpace(value)
	lower := strings.ToLower(trimmed)
	if !strings.HasPrefix(lower, "data:") {
		return "", false
	}
	comma := strings.IndexByte(lower, ',')
	if comma < 0 {
		return OpaqueMediaDataURL, true
	}
	header := lower[len("data:"):comma]
	mimeType := header
	if semicolon := strings.IndexByte(mimeType, ';'); semicolon >= 0 {
		mimeType = mimeType[:semicolon]
	}
	contextKind := mediaContextForMIME(mimeType)
	if contextKind == mediaContextNone {
		return "", false
	}
	if contextKind == mediaContextImage && strings.Contains(header, ";base64") {
		return OpaqueMediaBase64Image, true
	}
	switch contextKind {
	case mediaContextAudio:
		return OpaqueMediaAudio, true
	case mediaContextVideo:
		return OpaqueMediaVideo, true
	case mediaContextDocument:
		return OpaqueMediaDocument, true
	default:
		return OpaqueMediaDataURL, true
	}
}

func remoteOpaqueKind(kind mediaContextKind, value string) OpaqueMediaKind {
	switch kind {
	case mediaContextImage:
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "https://") {
			return OpaqueMediaHTTPSImageURL
		}
		return OpaqueMediaRemoteURL
	case mediaContextAudio:
		return OpaqueMediaAudio
	case mediaContextVideo:
		return OpaqueMediaVideo
	case mediaContextDocument:
		return OpaqueMediaDocument
	default:
		return OpaqueMediaRemoteURL
	}
}

func directOpaqueKind(kind mediaContextKind) OpaqueMediaKind {
	switch kind {
	case mediaContextImage:
		return OpaqueMediaBase64Image
	case mediaContextAudio:
		return OpaqueMediaAudio
	case mediaContextVideo:
		return OpaqueMediaVideo
	case mediaContextDocument:
		return OpaqueMediaDocument
	default:
		return OpaqueMediaOther
	}
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

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
