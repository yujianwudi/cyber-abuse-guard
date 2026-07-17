package extract

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"mime"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

var (
	errPlanBudget            = errors.New("extract: streaming plan budget exhausted")
	errClassificationLimited = errors.New("extract: classification chunk budget exhausted")
)

const (
	maxShadowKeyBytes     = 128
	maxShadowValueBytes   = 256
	shadowUnknownKey      = "_"
	shadowUnknownValue    = "_"
	spanMarkerPrefix      = "~c"
	spanMarkerSuffix      = "~"
	derivedFieldIDFlag    = uint64(1) << 63
	encodingSampleBytes   = 64 << 10
	base64ProbeBlock      = 4 << 10
	base64ProbeDecoded    = base64ProbeBlock / 4 * 3
	minDenseEncodings     = 16
	minEncodingDensity    = 10
	minEncodedTextRun     = 32
	minEncodedTextDensity = 90
)

type plannedText struct {
	id              uint64
	rawStart        int
	rawEnd          int
	owned           string
	role            Role
	provenance      SegmentProvenance
	scalarCarrier   bool
	messageOwner    uint64
	roleEligible    bool
	semanticOrdinal int
	fallbackText    bool
}

type planContext struct {
	role          Role
	provenance    SegmentProvenance
	messageOwner  uint64
	roleEligible  bool
	historyArray  bool
	messageObject bool
	atRoot        bool
	fallbackText  bool
	unknownRoot   bool
	metadata      bool
}

type valueSummary struct {
	text    string
	isText  bool
	bounded bool
}

type shadowPlanner struct {
	body       []byte
	limits     Limits
	position   int
	shadow     []byte
	spans      []plannedText
	tokens     int
	nodes      int
	reason     IncompleteReason
	nextOwner  uint64
	roleAware  bool
	unsafeRole bool
	trustRoles bool
}

// ScanProfiledRequest performs complete envelope validation, builds a bounded
// structural span plan, and replays only model-visible text through sink.
func ScanProfiledRequest(body []byte, headers http.Header, profile RequestProfile, limits Limits, sink ChunkSink) (Result, error) {
	initial := contextNone
	if profile.Source == SourceProfileInteractions {
		initial = contextText
	}
	return scanRequest(body, headers, profile, limits, initial, sink)
}

// ScanUntrustedRequest is the streaming entry point for an unknown provider
// schema. Every non-metadata string that is not proven opaque media is treated
// as untrusted user text.
func ScanUntrustedRequest(body []byte, headers http.Header, limits Limits, sink ChunkSink) (Result, error) {
	return scanRequest(body, headers, RequestProfile{Source: SourceProfileUnknown}, limits, contextText, sink)
}

// ScanRequest uses the conservative unknown source profile.
func ScanRequest(body []byte, headers http.Header, limits Limits, sink ChunkSink) (Result, error) {
	return ScanUntrustedRequest(body, headers, limits, sink)
}

func scanRequest(body []byte, headers http.Header, profile RequestProfile, limits Limits, initial contextKind, sink ChunkSink) (Result, error) {
	normalized, err := limits.normalized()
	if err != nil {
		return Result{}, err
	}
	result := newRequestResult(body, normalized)
	if sink == nil {
		sink = discardChunkSink{}
	}
	if len(body) > normalized.MaxRawBytes {
		result.Envelope = EnvelopeIncomplete
		result.TextCoverage = TextCoverageUnavailable
		result.addIncomplete(IncompleteRawBodyLimit)
		result.finish()
		sink.Abort()
		return result, nil
	}
	if unsupportedContentEncoding(headers) {
		result.Envelope = EnvelopeIncomplete
		result.TextCoverage = TextCoverageUnavailable
		result.addIncomplete(IncompleteUnsupportedContentEncoding)
		result.finish()
		sink.Abort()
		return result, nil
	}

	contentTypes := headerValues(headers, "Content-Type")
	if len(contentTypes) > 1 {
		result.Envelope = EnvelopeIncomplete
		result.TextCoverage = TextCoverageUnavailable
		result.addIncomplete(IncompleteUnsupportedMediaType)
		result.finish()
		sink.Abort()
		return result, nil
	}
	if len(contentTypes) == 0 || strings.TrimSpace(contentTypes[0]) == "" {
		if obviousJSON(body) {
			return scanRequestJSON(body, normalized, initial, initial == contextNone, sink)
		}
		result.Envelope = EnvelopeIncomplete
		result.TextCoverage = TextCoverageUnavailable
		result.addIncomplete(IncompleteUnsupportedMediaType)
		result.finish()
		sink.Abort()
		return result, nil
	}

	mediaType, params, parseErr := parseRequestMediaType(contentTypes[0])
	if parseErr != nil {
		result.Envelope = EnvelopeIncomplete
		result.TextCoverage = TextCoverageUnavailable
		result.addIncomplete(IncompleteUnsupportedMediaType)
		result.finish()
		sink.Abort()
		return result, nil
	}
	switch {
	case isJSONMediaType(mediaType):
		if !supportedJSONCharset(params) {
			result.Envelope = EnvelopeIncomplete
			result.TextCoverage = TextCoverageUnavailable
			result.addIncomplete(IncompleteUnsupportedMediaType)
			result.finish()
			sink.Abort()
			return result, nil
		}
		return scanRequestJSON(body, normalized, initial, initial == contextNone, sink)
	case mediaType == "multipart/form-data":
		if profile.Source != SourceProfileUnknown && obviousJSON(body) {
			return scanTransformedMultipartJSON(body, profile, normalized, sink)
		}
		boundary, ok := params["boundary"]
		if !ok || boundary == "" {
			result.Envelope = EnvelopeIncomplete
			result.TextCoverage = TextCoverageUnavailable
			result.addIncomplete(IncompleteMultipartParseError)
			result.finish()
			sink.Abort()
			return result, nil
		}
		if len(boundary) > normalized.MaxMultipartBoundaryBytes {
			result.Envelope = EnvelopeIncomplete
			result.TextCoverage = TextCoverageUnavailable
			result.addIncomplete(IncompleteMultipartBoundaryLimit)
			result.finish()
			sink.Abort()
			return result, nil
		}
		return scanMultipartRequest(body, boundary, profile, normalized, sink)
	default:
		result.Envelope = EnvelopeIncomplete
		result.TextCoverage = TextCoverageUnavailable
		result.addIncomplete(IncompleteUnsupportedMediaType)
		result.finish()
		sink.Abort()
		return result, nil
	}
}

func parseRequestMediaType(value string) (string, map[string]string, error) {
	// Kept in a small helper so stream_scan.go does not duplicate request.go's
	// dispatch semantics at each call site.
	mediaType, params, err := mime.ParseMediaType(value)
	return strings.ToLower(strings.TrimSpace(mediaType)), params, err
}

func scanRequestJSON(body []byte, limits Limits, initial contextKind, trustRoles bool, sink ChunkSink) (Result, error) {
	result := newRequestResult(body, limits)
	if !obviousJSON(body) || !utf8.Valid(body) || !json.Valid(body) {
		result.Envelope = EnvelopeIncomplete
		result.TextCoverage = TextCoverageUnavailable
		result.addIncomplete(IncompleteParseError)
		result.ParseError = ErrInvalidJSON.Error()
		result.finish()
		sink.Abort()
		return result, nil
	}
	result.Envelope = EnvelopeComplete

	planner := shadowPlanner{
		body:       body,
		limits:     limits,
		shadow:     make([]byte, 0, minInt(len(body), 64<<10)),
		spans:      make([]plannedText, 0, minInt(limits.MaxTextParts, 64)),
		trustRoles: trustRoles,
	}
	root := planContext{role: RoleUser, provenance: ProvenanceContent, atRoot: true}
	if _, err := planner.parseValue(root, "", 0); err != nil {
		if !errors.Is(err, errPlanBudget) {
			result.Envelope = EnvelopeIncomplete
			result.TextCoverage = TextCoverageUnavailable
			result.addIncomplete(IncompleteParseError)
			result.ParseError = ErrInvalidJSON.Error()
		} else {
			result.TextCoverage = TextCoverageExhausted
			result.addIncomplete(planner.reason)
		}
		result.finish()
		sink.Abort()
		return result, nil
	}
	planner.skipWhitespace()
	if planner.position != len(body) {
		result.Envelope = EnvelopeIncomplete
		result.TextCoverage = TextCoverageUnavailable
		result.addIncomplete(IncompleteParseError)
		result.ParseError = ErrInvalidJSON.Error()
		result.finish()
		sink.Abort()
		return result, nil
	}

	shadowLimits := limits
	shadowLimits.MaxScanBytes = HardMaxScanBytes
	shadowLimits.MaxRawBytes = HardMaxRawBytes
	shadowLimits.MaxTextPartBytes = HardMaxTextPartBytes
	shadowResult := extractRequestJSON(planner.shadow, shadowLimits, initial, false)
	result.OpaqueMedia = shadowResult.OpaqueMedia
	result.OpaqueMediaKinds = append(result.OpaqueMediaKinds, shadowResult.OpaqueMediaKinds...)
	if !shadowResult.IsComplete() {
		for _, reason := range shadowResult.IncompleteReasons {
			result.addIncomplete(reason)
		}
		result.TextCoverage = coverageForReasons(result.IncompleteReasons)
		result.finish()
		sink.Abort()
		return result, nil
	}

	selected, owned := planner.selected(shadowResult.Parts)
	result.RoleAware = planner.roleAware && !planner.unsafeRole
	if planner.unsafeRole {
		result.TextCoverage = TextCoverageUnavailable
		result.addIncomplete(IncompleteRoleAttribution)
		result.finish()
		sink.Abort()
		return result, nil
	}
	if !result.RoleAware {
		for index := range selected {
			selected[index].role = RoleUnknown
		}
		for index := range owned {
			owned[index].role = RoleUnknown
		}
	}
	result.LogicalTextParts = len(selected) + len(owned)
	if result.LogicalTextParts > limits.MaxTextParts {
		result.TextCoverage = TextCoverageExhausted
		result.addIncomplete(IncompleteTextPartLimit)
		result.finish()
		sink.Abort()
		return result, nil
	}

	stream := streamEmitter{limits: limits, sink: sink, result: &result}
	for _, span := range selected {
		if err := stream.emitSpan(body[span.rawStart:span.rawEnd], span); err != nil {
			return Result{}, err
		}
		if stream.aborted {
			result.finish()
			return result, nil
		}
	}
	for index := range owned {
		owned[index].id = uint64(len(planner.spans) + index + 1)
		if err := stream.emitOwned(owned[index]); err != nil {
			return Result{}, err
		}
		if stream.aborted {
			result.finish()
			return result, nil
		}
	}
	result.TextCoverage = TextCoverageComplete
	result.finish()
	return result, nil
}

func coverageForReasons(reasons []IncompleteReason) TextCoverage {
	for _, reason := range reasons {
		switch reason {
		case IncompleteParseError, IncompleteMultipartParseError,
			IncompleteMultipartUnknownField, IncompleteMultipartTextFieldTypeMismatch,
			IncompleteToolSchema, IncompleteRoleAttribution, IncompleteUnsupportedMediaType,
			IncompleteUnsupportedContentEncoding, IncompleteRawBodyLimit,
			IncompleteRPCBodyLimit:
			return TextCoverageUnavailable
		}
	}
	return TextCoverageExhausted
}

func (p *shadowPlanner) parseValue(ctx planContext, key string, depth int) (valueSummary, error) {
	p.skipWhitespace()
	if p.position >= len(p.body) {
		return valueSummary{}, errors.New("unexpected end of JSON")
	}
	if err := p.bump(true); err != nil {
		return valueSummary{}, err
	}
	if ctx.unknownRoot && (p.body[p.position] == '{' || p.body[p.position] == '[') {
		ctx.fallbackText = true
		ctx.unknownRoot = false
	}
	switch p.body[p.position] {
	case '{':
		return p.parseObject(ctx, depth+1)
	case '[':
		return p.parseArray(ctx, depth+1)
	case '"':
		start, end, err := p.takeString()
		if err != nil {
			return valueSummary{}, err
		}
		return p.appendStringValue(ctx, key, start, end), nil
	case 't':
		p.position += len("true")
		p.shadow = append(p.shadow, "true"...)
	case 'f':
		p.position += len("false")
		p.shadow = append(p.shadow, "false"...)
	case 'n':
		p.position += len("null")
		p.shadow = append(p.shadow, "null"...)
	default:
		p.takeNumber()
		p.shadow = append(p.shadow, '0')
	}
	return valueSummary{}, nil
}

func (p *shadowPlanner) parseObject(ctx planContext, depth int) (valueSummary, error) {
	if depth > p.limits.MaxJSONDepth {
		return valueSummary{}, p.exhaust(IncompleteJSONDepthLimit)
	}
	p.position++
	p.shadow = append(p.shadow, '{')
	messageOwner := uint64(0)
	spanStart := len(p.spans)
	if ctx.messageObject {
		p.nextOwner++
		messageOwner = p.nextOwner
		ctx.messageOwner = messageOwner
	}
	roleValue := ""
	roleSeen := false
	roleAmbiguous := false
	first := true
	for {
		p.skipWhitespace()
		if p.position < len(p.body) && p.body[p.position] == '}' {
			p.position++
			p.shadow = append(p.shadow, '}')
			if err := p.bumpTokenOnly(); err != nil {
				return valueSummary{}, err
			}
			break
		}
		if !first {
			if p.body[p.position] != ',' {
				return valueSummary{}, errors.New("object comma missing")
			}
			p.position++
			p.shadow = append(p.shadow, ',')
			p.skipWhitespace()
		}
		first = false
		if err := p.bumpTokenOnly(); err != nil {
			return valueSummary{}, err
		}
		keyStart, keyEnd, err := p.takeString()
		if err != nil {
			return valueSummary{}, err
		}
		keyValue, bounded := decodeShortJSONString(p.body[keyStart:keyEnd], maxShadowKeyBytes)
		if !bounded {
			keyValue = shadowUnknownKey
		}
		canonical := canonicalKey(keyValue)
		p.shadow = strconv.AppendQuote(p.shadow, compactShadowKey(canonical))
		p.skipWhitespace()
		if p.position >= len(p.body) || p.body[p.position] != ':' {
			return valueSummary{}, errors.New("object colon missing")
		}
		p.position++
		p.shadow = append(p.shadow, ':')
		child := derivePlanContext(ctx, canonical, depth == 1)
		summary, err := p.parseValue(child, canonical, depth)
		if err != nil {
			return valueSummary{}, err
		}
		if ctx.messageObject && canonical == "role" {
			if roleSeen {
				p.unsafeRole = true
				roleAmbiguous = true
			}
			roleSeen = true
			if !summary.isText {
				p.unsafeRole = true
				roleAmbiguous = true
			} else {
				roleValue = summary.text
			}
		}
	}
	if messageOwner != 0 {
		role, ok := normalizedMessageRole(roleValue)
		if roleSeen && !ok {
			p.unsafeRole = true
			roleAmbiguous = true
		}
		if !roleSeen || roleAmbiguous {
			role = RoleUser
		}
		if ok && !roleAmbiguous {
			p.roleAware = true
		}
		for index := spanStart; index < len(p.spans); index++ {
			if p.spans[index].messageOwner == messageOwner && p.spans[index].roleEligible {
				p.spans[index].role = role
			}
		}
	}
	return valueSummary{}, nil
}

func (p *shadowPlanner) parseArray(ctx planContext, depth int) (valueSummary, error) {
	if depth > p.limits.MaxJSONDepth {
		return valueSummary{}, p.exhaust(IncompleteJSONDepthLimit)
	}
	p.position++
	p.shadow = append(p.shadow, '[')
	first := true
	for {
		p.skipWhitespace()
		if p.position < len(p.body) && p.body[p.position] == ']' {
			p.position++
			p.shadow = append(p.shadow, ']')
			if err := p.bumpTokenOnly(); err != nil {
				return valueSummary{}, err
			}
			break
		}
		if !first {
			if p.body[p.position] != ',' {
				return valueSummary{}, errors.New("array comma missing")
			}
			p.position++
			p.shadow = append(p.shadow, ',')
		}
		first = false
		child := ctx
		child.atRoot = false
		if ctx.historyArray && p.trustRoles {
			child.historyArray = false
			child.messageObject = true
		}
		if _, err := p.parseValue(child, "", depth); err != nil {
			return valueSummary{}, err
		}
	}
	return valueSummary{}, nil
}

func derivePlanContext(parent planContext, key string, rootMember bool) planContext {
	child := parent
	child.atRoot = false
	child.historyArray = false
	child.messageObject = false
	if parent.metadata {
		return child
	}
	if isProviderMetadataContainerCanonical(key) && parent.provenance != ProvenanceToolPayload {
		child.messageOwner = 0
		child.roleEligible = false
		child.fallbackText = false
		child.unknownRoot = false
		child.metadata = true
		return child
	}
	if key == "messages" || key == "contents" || (rootMember && key == "input") {
		child.historyArray = true
		child.messageOwner = 0
		child.roleEligible = false
		return child
	}
	if rootMember && (key == "system" || key == "instructions" || key == "systeminstruction") {
		child.role = RoleSystem
		child.roleEligible = true
		return child
	}
	if rootMember && isProviderToolDefinitionContainerCanonical(key) {
		child.role = RoleSystem
		child.provenance = ProvenanceContent
		child.roleEligible = true
		return child
	}
	if parent.messageOwner != 0 {
		switch {
		case key == "content" || key == "parts" || key == "refusal":
			child.roleEligible = true
		case isToolWrapperKeyCanonical(key) || isToolArgumentCanonical(key):
			child.roleEligible = true
			child.provenance = ProvenanceToolPayload
		case isMetadataKeyCanonical(key):
			child.messageOwner = 0
			child.roleEligible = false
		default:
			child.messageOwner = 0
			child.roleEligible = false
			child.role = RoleUser
		}
		return child
	}
	if isToolWrapperKeyCanonical(key) || isToolArgumentCanonical(key) {
		child.provenance = ProvenanceToolPayload
	}
	if rootMember && !isKnownRootPlanKey(key) {
		child.unknownRoot = true
	}
	return child
}

func isKnownRootPlanKey(key string) bool {
	return isTextKeyCanonical(key) || isTextContainerCanonical(key) ||
		isProviderMetadataContainerCanonical(key) || isProviderToolDefinitionContainerCanonical(key) ||
		isMediaContainerKeyCanonical(key) || isMetadataKeyCanonical(key) ||
		isToolWrapperKeyCanonical(key) || isToolArgumentCanonical(key)
}

func normalizedMessageRole(value string) (Role, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "user":
		return RoleUser, true
	case "system", "developer":
		return RoleSystem, true
	case "assistant", "model":
		return RoleAssistant, true
	case "tool", "function":
		return RoleTool, true
	default:
		return RoleUser, false
	}
}

func (p *shadowPlanner) appendStringValue(ctx planContext, key string, start, end int) valueSummary {
	raw := p.body[start:end]
	value, bounded := decodeShortJSONString(raw, maxShadowValueBytes)
	if ctx.metadata {
		p.shadow = append(p.shadow, '"', '"')
		return valueSummary{}
	}
	if shouldPreserveSemanticString(key) {
		p.shadow = strconv.AppendQuote(p.shadow, compactShadowSemanticValue(key, value, bounded))
		return valueSummary{text: value, isText: true, bounded: bounded}
	}
	if bounded && strings.TrimSpace(value) == "" {
		p.shadow = append(p.shadow, '"', '"')
		return valueSummary{text: value, isText: true, bounded: true}
	}
	id := uint64(len(p.spans) + 1)
	fallbackText := ctx.fallbackText && fallbackPlanTextKey(key)
	scalarCarrier := isScalarMediaCarrierKeyCanonical(key)
	if representative, ok := opaqueScalarCarrierRepresentative(key, value, bounded, raw, id); ok {
		p.shadow = strconv.AppendQuote(p.shadow, representative)
		p.spans = append(p.spans, plannedText{
			id:              id,
			rawStart:        start,
			rawEnd:          end,
			role:            defaultRole(ctx.role),
			provenance:      ctx.provenance,
			scalarCarrier:   scalarCarrier,
			messageOwner:    ctx.messageOwner,
			roleEligible:    ctx.roleEligible,
			semanticOrdinal: len(p.spans),
			fallbackText:    fallbackText,
		})
		return valueSummary{text: representative, isText: true, bounded: bounded}
	}
	marker := spanMarker(id)
	p.shadow = strconv.AppendQuote(p.shadow, marker)
	p.spans = append(p.spans, plannedText{
		id:              id,
		rawStart:        start,
		rawEnd:          end,
		role:            defaultRole(ctx.role),
		provenance:      ctx.provenance,
		scalarCarrier:   scalarCarrier,
		messageOwner:    ctx.messageOwner,
		roleEligible:    ctx.roleEligible,
		semanticOrdinal: len(p.spans),
		fallbackText:    fallbackText,
	})
	return valueSummary{text: marker, isText: true, bounded: true}
}

func fallbackPlanTextKey(key string) bool {
	return !isMetadataKeyCanonical(key) && !isProviderMetadataContainerCanonical(key) &&
		!isMediaMetadataKeyCanonical(key) && !isMediaContainerKeyCanonical(key) &&
		!isScalarMediaCarrierKeyCanonical(key) && !isOpaquePayloadKeyCanonical(key)
}

func opaqueScalarCarrierRepresentative(key, value string, bounded bool, raw []byte, id uint64) (string, bool) {
	if !isScalarMediaCarrierKeyCanonical(key) {
		return "", false
	}
	candidate := value
	if !bounded {
		candidate = rawJSONStringPrefix(raw, 256)
	}
	trimmed := strings.ToLower(strings.TrimSpace(candidate))
	marker := spanMarker(id)
	switch {
	case strings.HasPrefix(trimmed, "data:image/"):
		return "data:image/png;base64," + marker, true
	case strings.HasPrefix(trimmed, "data:audio/"):
		return "data:audio/wav;base64," + marker, true
	case strings.HasPrefix(trimmed, "data:video/"):
		return "data:video/mp4;base64," + marker, true
	case strings.HasPrefix(trimmed, "data:application/pdf"):
		return "data:application/pdf;base64," + marker, true
	case strings.HasPrefix(trimmed, "https://"):
		return "https://opaque.invalid/" + marker, true
	case strings.HasPrefix(trimmed, "http://"):
		return "http://opaque.invalid/" + marker, true
	default:
		return "", false
	}
}

func defaultRole(role Role) Role {
	if role == "" {
		return RoleUser
	}
	return role
}

func shouldPreserveSemanticString(key string) bool {
	switch key {
	case "role", "type", "mimetype", "mediatype", toolControlSchemaKey:
		return true
	default:
		return false
	}
}

// compactShadowKey keeps only field identities that can change the legacy
// transactional media/tool/schema walk. Arbitrary caller-controlled property
// names collapse to one fixed unknown key. The planner already retains the
// original raw span and canonical context needed for fallback text, so copying
// long or unique keys into the shadow document adds memory without semantics.
func compactShadowKey(key string) string {
	if key == "" {
		return shadowUnknownKey
	}
	if isKnownRootPlanKey(key) || isMediaMetadataKeyCanonical(key) ||
		isScalarMediaCarrierKeyCanonical(key) || isOpaquePayloadKeyCanonical(key) ||
		isDeferredPayloadKeyCanonical(key) || key == toolControlSchemaKey {
		return key
	}
	if _, ok := toolControlBitForKey(key); ok {
		return key
	}
	if _, ok := toolAllowedTextForKey(key); ok {
		return key
	}
	return shadowUnknownKey
}

// compactShadowSemanticValue preserves only the closed semantic classes used
// by media and approved tool-control transactions. Role attribution uses the
// separately returned bounded valueSummary and never depends on this shadow
// representative.
func compactShadowSemanticValue(key, value string, bounded bool) string {
	if !bounded {
		return shadowUnknownValue
	}
	switch key {
	case "role":
		if role, ok := normalizedMessageRole(value); ok {
			return string(role)
		}
	case "type":
		if marked, kind := marksMediaContext(key, value); marked {
			return shadowMediaType(kind)
		}
	case "mimetype", "mediatype":
		if kind := mediaContextForMIME(value); kind != mediaContextNone {
			return shadowMediaMIME(kind)
		}
	case toolControlSchemaKey:
		trimmed := strings.ToLower(strings.TrimSpace(value))
		switch {
		case trimmed == toolControlSchemaV1:
			return toolControlSchemaV1
		case strings.HasPrefix(trimmed, toolControlSchemaReserved):
			return toolControlSchemaReserved + "unsupported"
		}
	}
	return shadowUnknownValue
}

func shadowMediaType(kind mediaContextKind) string {
	switch kind {
	case mediaContextImage:
		return "image"
	case mediaContextAudio:
		return "audio"
	case mediaContextVideo:
		return "video"
	case mediaContextDocument:
		return "file"
	case mediaContextOther:
		return "inline_data"
	default:
		return shadowUnknownValue
	}
}

func shadowMediaMIME(kind mediaContextKind) string {
	switch kind {
	case mediaContextImage:
		return "image/png"
	case mediaContextAudio:
		return "audio/wav"
	case mediaContextVideo:
		return "video/mp4"
	case mediaContextDocument:
		return "application/pdf"
	default:
		return shadowUnknownValue
	}
}

func decodeShortJSONString(raw []byte, limit int) (string, bool) {
	if len(raw) > limit+2 {
		return "", false
	}
	value, err := strconv.Unquote(string(raw))
	if err != nil || len(value) > limit {
		return "", false
	}
	return value, true
}

func rawJSONStringPrefix(raw []byte, limit int) string {
	if len(raw) < 2 || raw[0] != '"' {
		return ""
	}
	content := raw[1 : len(raw)-1]
	if slash := bytes.IndexByte(content, '\\'); slash >= 0 && slash < limit {
		content = content[:slash]
	}
	if len(content) > limit {
		content = content[:limit]
	}
	return string(content)
}

func (p *shadowPlanner) takeString() (int, int, error) {
	if p.position >= len(p.body) || p.body[p.position] != '"' {
		return 0, 0, errors.New("JSON string expected")
	}
	start := p.position
	p.position++
	for p.position < len(p.body) {
		switch p.body[p.position] {
		case '\\':
			p.position += 2
		case '"':
			p.position++
			return start, p.position, nil
		default:
			p.position++
		}
	}
	return 0, 0, errors.New("unterminated JSON string")
}

func (p *shadowPlanner) takeNumber() {
	for p.position < len(p.body) {
		switch p.body[p.position] {
		case ',', '}', ']', ' ', '\t', '\r', '\n':
			return
		default:
			p.position++
		}
	}
}

func (p *shadowPlanner) skipWhitespace() {
	for p.position < len(p.body) {
		switch p.body[p.position] {
		case ' ', '\t', '\r', '\n':
			p.position++
		default:
			return
		}
	}
}

func (p *shadowPlanner) bump(node bool) error {
	p.tokens++
	if p.tokens > p.limits.MaxJSONTokens {
		return p.exhaust(IncompleteJSONTokenLimit)
	}
	if node {
		p.nodes++
		if p.nodes > p.limits.MaxJSONNodes {
			return p.exhaust(IncompleteJSONNodeLimit)
		}
	}
	return nil
}

func (p *shadowPlanner) bumpTokenOnly() error { return p.bump(false) }

func (p *shadowPlanner) exhaust(reason IncompleteReason) error {
	if p.reason == "" {
		p.reason = reason
	}
	return errPlanBudget
}

func spanMarker(id uint64) string {
	return spanMarkerPrefix + strconv.FormatUint(id, 36) + spanMarkerSuffix
}

func markerID(value string) (uint64, bool) {
	if !strings.HasPrefix(value, spanMarkerPrefix) || !strings.HasSuffix(value, spanMarkerSuffix) {
		return 0, false
	}
	encoded := strings.TrimSuffix(strings.TrimPrefix(value, spanMarkerPrefix), spanMarkerSuffix)
	if encoded == "" {
		return 0, false
	}
	id, err := strconv.ParseUint(encoded, 36, 64)
	if err != nil || id == 0 {
		return 0, false
	}
	return id, true
}

func (p *shadowPlanner) selected(parts []string) ([]plannedText, []plannedText) {
	byID := make(map[uint64]plannedText, len(p.spans))
	for _, span := range p.spans {
		byID[span.id] = span
	}
	selected := make([]plannedText, 0, len(parts))
	seen := make(map[uint64]struct{}, len(parts))
	owned := make([]plannedText, 0, 8)
	for _, part := range parts {
		if id, ok := markerID(part); ok {
			if span, exists := byID[id]; exists {
				selected = append(selected, span)
				seen[id] = struct{}{}
			}
			continue
		}
		if id, ok := embeddedMarkerID(part); ok {
			if span, exists := byID[id]; exists {
				selected = append(selected, span)
				seen[id] = struct{}{}
			}
			continue
		}
		if strings.TrimSpace(part) != "" {
			owned = append(owned, plannedText{owned: part, role: RoleUser, provenance: ProvenanceToolPayload})
		}
	}
	for _, span := range p.spans {
		if !span.fallbackText {
			continue
		}
		if _, exists := seen[span.id]; exists {
			continue
		}
		selected = append(selected, span)
		seen[span.id] = struct{}{}
	}
	contentIndexes := make([]int, 0, len(selected))
	contentSpans := make([]plannedText, 0, len(selected))
	for index, span := range selected {
		if span.provenance == ProvenanceToolPayload {
			continue
		}
		contentIndexes = append(contentIndexes, index)
		contentSpans = append(contentSpans, span)
	}
	sort.SliceStable(contentSpans, func(left, right int) bool {
		return contentSpans[left].semanticOrdinal < contentSpans[right].semanticOrdinal
	})
	for index, selectedIndex := range contentIndexes {
		selected[selectedIndex] = contentSpans[index]
	}
	return selected, owned
}

func embeddedMarkerID(value string) (uint64, bool) {
	start := strings.Index(value, spanMarkerPrefix)
	if start < 0 {
		return 0, false
	}
	suffixStart := start + len(spanMarkerPrefix)
	suffixOffset := strings.Index(value[suffixStart:], spanMarkerSuffix)
	if suffixOffset < 0 {
		return 0, false
	}
	end := suffixStart + suffixOffset + len(spanMarkerSuffix)
	return markerID(value[start:end])
}

type streamEmitter struct {
	limits                Limits
	sink                  ChunkSink
	result                *Result
	binaryFailureReason   IncompleteReason
	binaryFailureCoverage TextCoverage
	decodeFailureReason   IncompleteReason
	decodeFailureCoverage TextCoverage
	aborted               bool
}

func (s *streamEmitter) emitOwned(span plannedText) error {
	return s.emitDecoded([]byte(span.owned), span)
}

func (s *streamEmitter) emitSpan(raw []byte, span plannedText) error {
	measurement, err := measureJSONString(raw)
	if err != nil {
		return s.operational(err)
	}
	if measurement.binary {
		reason := s.binaryFailureReason
		if reason == "" {
			reason = IncompleteTextPartByteLimit
		}
		coverage := s.binaryFailureCoverage
		if coverage == "" {
			coverage = TextCoverageUnavailable
		}
		s.abort(reason, coverage)
		return nil
	}
	if !measurement.nonSpace {
		return nil
	}
	variants, decodeIncomplete := measurement.decoder.finish(span.scalarCarrier)
	if decodeIncomplete {
		reason := s.decodeFailureReason
		if reason == "" {
			reason = IncompleteTextPartByteLimit
		}
		coverage := s.decodeFailureCoverage
		if coverage == "" {
			coverage = TextCoverageUnavailable
		}
		s.abort(reason, coverage)
		return nil
	}
	chunkSize := minInt(s.limits.MaxTextPartBytes, s.limits.MaxTextWindowBytes)
	chunks := (measurement.length + chunkSize - 1) / chunkSize
	if s.result.TextBytesScanned > s.limits.MaxTotalTextBytes-measurement.length {
		s.abort(IncompleteTotalTextLimit, TextCoverageExhausted)
		return nil
	}
	if s.result.ClassificationChunks > s.limits.MaxClassificationChunks-chunks {
		s.abort(IncompleteClassificationChunkLimit, TextCoverageExhausted)
		return nil
	}
	first := true
	emitted := 0
	err = decodeJSONStringChunks(raw, chunkSize, func(chunk []byte, final bool) error {
		if len(chunk) == 0 && !final {
			return nil
		}
		if !s.canAddClassificationChunk() {
			return errClassificationLimited
		}
		if err := s.sink.AddSegment(SegmentChunk{
			Role:       defaultRole(span.role),
			Provenance: span.provenance,
			FieldID:    span.id,
			Start:      first,
			End:        final,
			Text:       chunk,
		}); err != nil {
			return err
		}
		first = false
		emitted += len(chunk)
		s.result.ClassificationChunks++
		if len(chunk) > s.result.PeakTextBytesRetained {
			s.result.PeakTextBytesRetained = len(chunk)
		}
		return nil
	})
	if errors.Is(err, errClassificationLimited) {
		return nil
	}
	if err != nil {
		return s.operational(err)
	}
	s.result.TextBytesScanned += emitted
	for index, variant := range variants {
		derived := span
		derived.id = derivedFieldID(span.id, index)
		derived.owned = variant
		if err := s.emitOwned(derived); err != nil {
			return err
		}
		if s.aborted {
			return nil
		}
	}
	return nil
}

func (s *streamEmitter) emitDecoded(value []byte, span plannedText) error {
	if strings.TrimSpace(string(value)) == "" {
		return nil
	}
	chunkSize := minInt(s.limits.MaxTextPartBytes, s.limits.MaxTextWindowBytes)
	chunks := (len(value) + chunkSize - 1) / chunkSize
	if s.result.TextBytesScanned > s.limits.MaxTotalTextBytes-len(value) {
		s.abort(IncompleteTotalTextLimit, TextCoverageExhausted)
		return nil
	}
	if s.result.ClassificationChunks > s.limits.MaxClassificationChunks-chunks {
		s.abort(IncompleteClassificationChunkLimit, TextCoverageExhausted)
		return nil
	}
	for offset := 0; offset < len(value); {
		end := minInt(len(value), offset+chunkSize)
		for end < len(value) && !utf8.RuneStart(value[end]) {
			end--
		}
		if end == offset {
			end = minInt(len(value), offset+chunkSize)
		}
		chunk := value[offset:end]
		if !s.canAddClassificationChunk() {
			return nil
		}
		if err := s.sink.AddSegment(SegmentChunk{
			Role:       defaultRole(span.role),
			Provenance: span.provenance,
			FieldID:    span.id,
			Start:      offset == 0,
			End:        end == len(value),
			Text:       chunk,
		}); err != nil {
			return s.operational(err)
		}
		s.result.ClassificationChunks++
		s.result.TextBytesScanned += len(chunk)
		if len(chunk) > s.result.PeakTextBytesRetained {
			s.result.PeakTextBytesRetained = len(chunk)
		}
		offset = end
	}
	return nil
}

func (s *streamEmitter) canAddClassificationChunk() bool {
	if s.aborted {
		return false
	}
	if s.result.ClassificationChunks >= s.limits.MaxClassificationChunks {
		s.abort(IncompleteClassificationChunkLimit, TextCoverageExhausted)
		return false
	}
	return true
}

func (s *streamEmitter) abort(reason IncompleteReason, coverage TextCoverage) {
	if s.aborted {
		return
	}
	s.aborted = true
	s.result.TextCoverage = coverage
	s.result.addIncomplete(reason)
	s.sink.Abort()
}

func (s *streamEmitter) operational(err error) error {
	if !s.aborted {
		s.aborted = true
		s.sink.Abort()
	}
	return fmt.Errorf("extract: chunk sink: %w", err)
}

type jsonStringMeasurement struct {
	length   int
	nonSpace bool
	binary   bool
	decoder  boundedStreamingDecoder
}

func measureJSONString(raw []byte) (measurement jsonStringMeasurement, err error) {
	measurement.decoder = newBoundedStreamingDecoder(len(raw))
	err = decodeJSONStringChunks(raw, 16<<10, func(chunk []byte, _ bool) error {
		measurement.length += len(chunk)
		measurement.decoder.add(chunk)
		for len(chunk) > 0 {
			r, size := utf8.DecodeRune(chunk)
			if r == utf8.RuneError && size == 1 {
				return errors.New("invalid decoded UTF-8")
			}
			if !unicode.IsSpace(r) {
				measurement.nonSpace = true
			}
			if (r >= 0 && r < 0x20 && r != '\n' && r != '\r' && r != '\t') || r == 0x7f {
				measurement.binary = true
			}
			chunk = chunk[size:]
		}
		return nil
	})
	return
}

type boundedStreamingDecoder struct {
	value   []byte
	tooLong bool
	probe   streamingEncodingProbe
}

func newBoundedStreamingDecoder(sourceBytes int) boundedStreamingDecoder {
	valueCapacity := minInt(sourceBytes, maxDecodeSourceBytes)
	sampleCapacity := minInt(sourceBytes, encodingSampleBytes)
	return boundedStreamingDecoder{
		value: make([]byte, 0, valueCapacity),
		probe: streamingEncodingProbe{sample: make([]byte, 0, sampleCapacity)},
	}
}

func (d *boundedStreamingDecoder) add(value []byte) {
	if d == nil || len(value) == 0 {
		return
	}
	d.probe.add(value)
	if d.tooLong {
		return
	}
	if len(d.value) > maxDecodeSourceBytes-len(value) {
		d.tooLong = true
		clear(d.value)
		d.value = nil
		return
	}
	d.value = append(d.value, value...)
}

func (d *boundedStreamingDecoder) finish(failClosedBareEncoding bool) (variants []string, incomplete bool) {
	if d == nil {
		return nil, false
	}
	if d.tooLong {
		if failClosedBareEncoding && d.probe.strongBareEncodingCandidate() {
			return nil, true
		}
		return nil, d.probe.potentiallyEncoded()
	}
	variants, encoded, decodeIncomplete := decodeStreamingBoundedText(string(d.value), failClosedBareEncoding)
	return variants, encoded && decodeIncomplete
}

type streamingEncodingProbe struct {
	sample                  []byte
	initialized             bool
	base64Possible          bool
	base64Padding           bool
	base64PaddingN          int
	base64Standard          bool
	base64URL               bool
	base64CompactBytes      int
	base64Horizontal        bool
	base64HorizontalGap     bool
	base64HorizontalInvalid bool
	base64TokenBytes        int
	base64Block             [base64ProbeBlock]byte
	base64BlockN            int
	base64DecodeFailed      bool
	base64MalformedStrong   bool
	base64DecodedText       streamingTextSignal
	percentState            uint8
	validPercent            bool
	entityActive            bool
	entityLength            int
	validEntity             bool
	entity                  [32]byte
	base64Distinct          int
	base64Alphabet          [256]bool
	base64StrongSig         bool
	totalBytes              int
	percentCount            int
	entityCount             int
	entityBytes             int
}

func (p *streamingEncodingProbe) add(value []byte) {
	if p == nil {
		return
	}
	if !p.initialized {
		p.initialized = true
		p.base64Possible = true
	}
	p.totalBytes += len(value)
	if len(p.sample) < encodingSampleBytes {
		count := minInt(len(value), encodingSampleBytes-len(p.sample))
		p.sample = append(p.sample, value[:count]...)
	}
	for _, character := range value {
		p.observePercent(character)
		p.observeEntity(character)
		p.observeBase64(character)
	}
}

func (p *streamingEncodingProbe) observeBase64(character byte) {
	if !p.base64Possible {
		return
	}
	alphabetCharacter := false
	switch {
	case character >= 'A' && character <= 'Z', character >= 'a' && character <= 'z', character >= '0' && character <= '9':
		if p.base64Padding {
			p.invalidateBase64Candidate()
			return
		}
		alphabetCharacter = true
	case character == '+' || character == '/':
		if p.base64Padding || p.base64URL {
			p.invalidateBase64Candidate()
			return
		}
		p.base64Standard = true
		p.base64StrongSig = true
		alphabetCharacter = true
	case character == '-' || character == '_':
		if p.base64Padding || p.base64Standard {
			p.invalidateBase64Candidate()
			return
		}
		p.base64URL = true
		p.base64StrongSig = true
		alphabetCharacter = true
	case character == '=':
		if p.base64PaddingN >= 2 {
			p.invalidateBase64Candidate()
			return
		}
		p.base64Padding = true
		p.base64PaddingN++
		p.base64StrongSig = true
	case character == '\r' || character == '\n':
		p.base64StrongSig = true
		return
	case character == ' ' || character == '\t':
		p.base64Horizontal = true
		p.base64HorizontalGap = true
		return
	default:
		p.invalidateBase64Candidate()
		return
	}

	if p.base64HorizontalGap {
		if p.base64TokenBytes > 0 && p.base64TokenBytes%4 != 0 {
			p.base64HorizontalInvalid = true
		}
		p.base64TokenBytes = 0
		p.base64HorizontalGap = false
	}
	p.base64TokenBytes++
	p.base64CompactBytes++
	if alphabetCharacter && !p.base64Alphabet[character] {
		p.base64Alphabet[character] = true
		p.base64Distinct++
	}
	p.base64Block[p.base64BlockN] = character
	p.base64BlockN++
	if p.base64BlockN == len(p.base64Block) {
		p.decodeBase64Block()
	}
}

func (p *streamingEncodingProbe) decodeBase64Block() {
	if !decodeBase64ProbeBlock(p.base64Block[:p.base64BlockN], p.base64URL, false, &p.base64DecodedText) {
		p.latchStrongMalformedBase64()
		p.base64DecodeFailed = true
		p.base64Possible = false
		return
	}
	p.base64BlockN = 0
}

func (p *streamingEncodingProbe) invalidateBase64Candidate() {
	if p == nil || !p.base64Possible {
		return
	}
	p.latchStrongMalformedBase64()
	p.base64Possible = false
}

func (p *streamingEncodingProbe) latchStrongMalformedBase64() {
	if p == nil || p.base64MalformedStrong || p.base64DecodeFailed ||
		p.base64CompactBytes < minBase64SourceBytes ||
		p.base64Horizontal && !p.base64Padding && p.base64HorizontalInvalid {
		return
	}
	if p.base64DecodedText.textual() {
		p.base64MalformedStrong = true
		return
	}
	if !p.base64StrongSig && p.base64Distinct < 16 {
		return
	}
	complete, printable := p.completeBase64Candidate()
	if complete && printable {
		p.base64MalformedStrong = true
		return
	}
	if !complete && p.printableMalformedBase64Prefix() {
		p.base64MalformedStrong = true
	}
}

func (p *streamingEncodingProbe) printableMalformedBase64Prefix() bool {
	if p == nil || p.base64BlockN <= 1 {
		return false
	}
	maxTrim := minInt(3, p.base64BlockN-1)
	for trim := 1; trim <= maxTrim; trim++ {
		candidate := p.base64Block[:p.base64BlockN-trim]
		if len(candidate)%4 == 0 {
			textSignal := p.base64DecodedText
			if decodeBase64ProbeBlock(candidate, p.base64URL, false, &textSignal) && textSignal.textual() {
				return true
			}
		}
		if len(candidate)%4 != 1 {
			textSignal := p.base64DecodedText
			if decodeBase64ProbeBlock(candidate, p.base64URL, true, &textSignal) && textSignal.textual() {
				return true
			}
		}
	}
	return false
}

func (p *streamingEncodingProbe) observePercent(character byte) {
	switch p.percentState {
	case 1:
		if isHexByte(character) {
			p.percentState = 2
			return
		}
		p.percentState = 0
	case 2:
		if isHexByte(character) {
			p.validPercent = true
			p.percentCount++
			p.percentState = 0
			return
		}
		p.percentState = 0
	}
	if character == '%' {
		p.percentState = 1
	}
}

func (p *streamingEncodingProbe) observeEntity(character byte) {
	if character == '&' {
		p.entityActive = true
		p.entityLength = 1
		p.entity[0] = '&'
		return
	}
	if !p.entityActive {
		return
	}
	if character == ';' {
		if p.entityLength < len(p.entity) {
			p.entity[p.entityLength] = ';'
			p.entityLength++
			candidate := string(p.entity[:p.entityLength])
			if html.UnescapeString(candidate) != candidate {
				p.validEntity = true
				p.entityCount++
				p.entityBytes += p.entityLength
			}
		}
		p.entityActive = false
		p.entityLength = 0
		return
	}
	allowed := character == '#' || character == 'x' || character == 'X' ||
		character >= '0' && character <= '9' || character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z'
	if !allowed || p.entityLength >= len(p.entity)-1 {
		p.entityActive = false
		p.entityLength = 0
		return
	}
	p.entity[p.entityLength] = character
	p.entityLength++
}

func (p *streamingEncodingProbe) potentiallyEncoded() bool {
	if p == nil {
		return false
	}
	sample := strings.TrimSpace(string(p.sample))
	if isData, textual := streamingDataURLKind(sample); isData {
		return textual
	}
	if p.validPercent && denseEncodingSignal(p.percentCount, p.percentCount*3, p.totalBytes) ||
		p.validEntity && denseEncodingSignal(p.entityCount, p.entityBytes, p.totalBytes) {
		return true
	}
	if p.base64MalformedStrong {
		return true
	}
	if !p.base64Possible {
		return false
	}
	complete, printable := p.completeBase64Candidate()
	if !complete {
		p.latchStrongMalformedBase64()
		if p.base64MalformedStrong {
			return true
		}
	}
	if complete && printable {
		return true
	}
	if !p.base64StrongSig && p.base64Distinct < 16 {
		return false
	}
	return complete && printableBase64Sample(sample)
}

func (p *streamingEncodingProbe) strongBareEncodingCandidate() bool {
	if p == nil || p.base64CompactBytes < minBase64SourceBytes ||
		p.base64Horizontal && !p.base64Padding && p.base64HorizontalInvalid {
		return false
	}
	if p.base64MalformedStrong {
		return true
	}
	if p.base64DecodeFailed {
		return p.base64Horizontal || p.base64StrongSig || p.base64Distinct >= 16
	}
	if !p.base64Possible {
		return false
	}
	return p.base64Horizontal || p.base64StrongSig || p.base64Distinct >= 16
}

func (p *streamingEncodingProbe) completeBase64Candidate() (bool, bool) {
	if p.base64DecodeFailed || p.base64CompactBytes < minBase64SourceBytes ||
		p.base64Horizontal && !p.base64Padding && p.base64HorizontalInvalid {
		return false, false
	}
	textSignal := p.base64DecodedText
	if p.base64BlockN == 0 {
		return true, textSignal.textual()
	}
	raw := !p.base64Padding
	if raw && p.base64BlockN%4 == 1 || !raw && p.base64BlockN%4 != 0 {
		return false, false
	}
	if !decodeBase64ProbeBlock(p.base64Block[:p.base64BlockN], p.base64URL, raw, &textSignal) {
		return false, false
	}
	return true, textSignal.textual()
}

func decodeBase64ProbeBlock(value []byte, urlAlphabet, raw bool, textSignal *streamingTextSignal) bool {
	encoding := base64.StdEncoding
	if raw {
		encoding = base64.RawStdEncoding
	}
	if urlAlphabet {
		encoding = base64.URLEncoding
		if raw {
			encoding = base64.RawURLEncoding
		}
	}
	var decoded [base64ProbeDecoded]byte
	n, err := encoding.Decode(decoded[:], value)
	if err != nil {
		return false
	}
	textSignal.add(decoded[:n])
	return true
}

type streamingTextSignal struct {
	pending         [utf8.UTFMax]byte
	pendingN        int
	runBytes        int
	decodedBytes    int
	printableBytes  int
	meaningfulBytes int
	meaningful      bool
	found           bool
}

func (p *streamingTextSignal) add(value []byte) {
	if p == nil || p.found {
		return
	}
	p.decodedBytes += len(value)
	for _, character := range value {
		p.pending[p.pendingN] = character
		p.pendingN++
		for p.pendingN > 0 && utf8.FullRune(p.pending[:p.pendingN]) {
			r, size := utf8.DecodeRune(p.pending[:p.pendingN])
			if r == utf8.RuneError && size == 1 {
				p.resetRun()
			} else {
				p.observeRune(r, size)
			}
			copy(p.pending[:], p.pending[size:p.pendingN])
			p.pendingN -= size
		}
	}
}

func (p *streamingTextSignal) observeRune(r rune, size int) {
	if r != '\n' && r != '\r' && r != '\t' && (unicode.IsControl(r) || !unicode.IsPrint(r)) {
		p.resetRun()
		return
	}
	p.printableBytes += size
	p.runBytes += size
	if unicode.IsLetter(r) || unicode.IsNumber(r) {
		p.meaningful = true
		p.meaningfulBytes += size
	}
	if p.runBytes >= minEncodedTextRun && p.meaningful {
		p.found = true
	}
}

func (p streamingTextSignal) textual() bool {
	if p.found {
		return true
	}
	return p.decodedBytes >= minEncodedTextRun &&
		p.meaningfulBytes >= minEncodedTextRun &&
		p.printableBytes*100 >= p.decodedBytes*minEncodedTextDensity
}

func (p *streamingTextSignal) resetRun() {
	p.runBytes = 0
	p.meaningful = false
}

func denseEncodingSignal(count, encodedBytes, totalBytes int) bool {
	return count >= minDenseEncodings && totalBytes > 0 && encodedBytes*100 >= totalBytes*minEncodingDensity
}

func printableBase64Sample(value string) bool {
	value = strings.TrimSpace(value)
	if compact, ok := horizontalBase64Candidate(value); ok {
		value = compact
	}
	compact, _, valid := compactBase64(value)
	if !valid {
		return false
	}
	if remainder := len(compact) % 4; remainder != 0 {
		compact = compact[:len(compact)-remainder]
	}
	if len(compact) < minBase64SourceBytes {
		return false
	}
	decoded, found := decodeBase64Bytes(compact, minBase64SourceBytes)
	return found && isInspectableText(decoded)
}

func decodeStreamingBoundedText(value string, failClosedBareEncoding bool) ([]string, bool, bool) {
	if isData, textual := streamingDataURLKind(value); isData && !textual {
		// A media-looking prefix in an ordinary, unproven text field remains
		// classifier-visible. Only a structurally proven media transaction may
		// remove the source span from the shadow plan.
		return nil, false, false
	}
	variants, encoded, incomplete := decodeBoundedText(value)
	if encoded && incomplete && len(variants) == 0 && !failClosedBareEncoding && !hasExplicitTextEncodingEnvelope(value) {
		// Bare identifiers may be syntactically compatible with Base64 while
		// decoding only to binary. Ordinary text fields scan the original bytes and
		// do not turn such identifiers into request incompleteness. Ambiguous scalar
		// media carriers retain the legacy fail-closed contract because their value
		// may otherwise cross a provider media boundary without inspection.
		return nil, false, false
	}
	return variants, encoded, incomplete
}

func hasExplicitTextEncodingEnvelope(value string) bool {
	trimmed := strings.TrimSpace(value)
	if isData, textual := streamingDataURLKind(trimmed); isData {
		return textual
	}
	return strings.Contains(trimmed, "%") || strings.Contains(trimmed, "&") && strings.Contains(trimmed, ";")
}

func streamingDataURLKind(value string) (isData bool, textual bool) {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) < len("data:") || !strings.EqualFold(trimmed[:len("data:")], "data:") {
		return false, false
	}
	header := trimmed[len("data:"):]
	if comma := strings.IndexByte(header, ','); comma >= 0 {
		header = header[:comma]
	}
	mediaType := header
	if semicolon := strings.IndexByte(mediaType, ';'); semicolon >= 0 {
		mediaType = mediaType[:semicolon]
	}
	return true, isTextualDataMIME(mediaType)
}

func derivedFieldID(parent uint64, ordinal int) uint64 {
	return derivedFieldIDFlag | parent<<8 | uint64(ordinal+1)
}

func decodeJSONStringChunks(raw []byte, chunkSize int, emit func([]byte, bool) error) error {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return errors.New("invalid JSON string span")
	}
	content := raw[1 : len(raw)-1]
	buffer := make([]byte, 0, chunkSize)
	flush := func(final bool) error {
		if len(buffer) == 0 && !final {
			return nil
		}
		if err := emit(buffer, final); err != nil {
			return err
		}
		buffer = buffer[:0]
		return nil
	}
	for index := 0; index < len(content); {
		var decoded [utf8.UTFMax]byte
		decodedBytes := decoded[:0]
		if content[index] != '\\' {
			r, size := utf8.DecodeRune(content[index:])
			if r == utf8.RuneError && size == 1 {
				return errors.New("invalid UTF-8 in JSON string")
			}
			decodedBytes = append(decodedBytes, content[index:index+size]...)
			index += size
		} else {
			index++
			if index >= len(content) {
				return errors.New("unterminated JSON escape")
			}
			switch content[index] {
			case '"', '\\', '/':
				decodedBytes = append(decodedBytes, content[index])
				index++
			case 'b':
				decodedBytes = append(decodedBytes, '\b')
				index++
			case 'f':
				decodedBytes = append(decodedBytes, '\f')
				index++
			case 'n':
				decodedBytes = append(decodedBytes, '\n')
				index++
			case 'r':
				decodedBytes = append(decodedBytes, '\r')
				index++
			case 't':
				decodedBytes = append(decodedBytes, '\t')
				index++
			case 'u':
				first, next, ok := decodeHexRune(content, index+1)
				if !ok {
					return errors.New("invalid unicode escape")
				}
				index = next
				r := rune(first)
				if utf16.IsSurrogate(r) {
					if r >= 0xd800 && r <= 0xdbff && index+6 <= len(content) && content[index] == '\\' && content[index+1] == 'u' {
						second, after, secondOK := decodeHexRune(content, index+2)
						if secondOK && second >= 0xdc00 && second <= 0xdfff {
							r = utf16.DecodeRune(r, rune(second))
							index = after
						} else {
							r = utf8.RuneError
						}
					} else {
						r = utf8.RuneError
					}
				}
				var encoded [utf8.UTFMax]byte
				size := utf8.EncodeRune(encoded[:], r)
				decodedBytes = append(decodedBytes, encoded[:size]...)
			default:
				return errors.New("invalid JSON escape")
			}
		}
		if len(buffer) > 0 && len(buffer)+len(decodedBytes) > chunkSize {
			if err := flush(false); err != nil {
				return err
			}
		}
		buffer = append(buffer, decodedBytes...)
		if len(buffer) == chunkSize {
			if err := flush(index == len(content)); err != nil {
				return err
			}
		}
	}
	if len(buffer) > 0 || len(content) == 0 {
		return flush(true)
	}
	return nil
}

func decodeHexRune(value []byte, start int) (uint16, int, bool) {
	if start+4 > len(value) {
		return 0, start, false
	}
	var result uint16
	for index := start; index < start+4; index++ {
		result <<= 4
		switch c := value[index]; {
		case c >= '0' && c <= '9':
			result |= uint16(c - '0')
		case c >= 'a' && c <= 'f':
			result |= uint16(c-'a') + 10
		case c >= 'A' && c <= 'F':
			result |= uint16(c-'A') + 10
		default:
			return 0, start, false
		}
	}
	return result, start + 4, true
}

type discardChunkSink struct{}

func (discardChunkSink) AddSegment(SegmentChunk) error { return nil }
func (discardChunkSink) Abort()                        {}
