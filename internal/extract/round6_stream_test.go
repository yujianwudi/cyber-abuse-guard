package extract

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"
)

type round6RecordingSink struct {
	aborted     bool
	active      bool
	activeField uint64
	chunks      []SegmentChunk
	fieldText   map[uint64]*strings.Builder
	fieldRole   map[uint64]Role
	fieldProv   map[uint64]SegmentProvenance
}

func newRound6RecordingSink() *round6RecordingSink {
	return &round6RecordingSink{
		fieldText: make(map[uint64]*strings.Builder),
		fieldRole: make(map[uint64]Role),
		fieldProv: make(map[uint64]SegmentProvenance),
	}
}

func (s *round6RecordingSink) AddSegment(chunk SegmentChunk) error {
	if s.aborted {
		return fmt.Errorf("chunk delivered after abort")
	}
	if chunk.Start {
		if s.active {
			return fmt.Errorf("field %d started while field %d active", chunk.FieldID, s.activeField)
		}
		s.active = true
		s.activeField = chunk.FieldID
		s.fieldText[chunk.FieldID] = &strings.Builder{}
		s.fieldRole[chunk.FieldID] = chunk.Role
		s.fieldProv[chunk.FieldID] = chunk.Provenance
	} else if !s.active || s.activeField != chunk.FieldID {
		return fmt.Errorf("non-serial chunk for field %d", chunk.FieldID)
	}
	copyChunk := chunk
	copyChunk.Text = append([]byte(nil), chunk.Text...)
	s.chunks = append(s.chunks, copyChunk)
	s.fieldText[chunk.FieldID].Write(chunk.Text)
	if chunk.End {
		if !s.active || s.activeField != chunk.FieldID {
			return fmt.Errorf("field %d ended out of order", chunk.FieldID)
		}
		s.active = false
		s.activeField = 0
	}
	return nil
}

func (s *round6RecordingSink) Abort() {
	s.aborted = true
	s.active = false
	s.activeField = 0
}

func (s *round6RecordingSink) joined() string {
	var builder strings.Builder
	for _, chunk := range s.chunks {
		builder.Write(chunk.Text)
	}
	return builder.String()
}

func round6JSONHeaders() http.Header {
	return http.Header{"Content-Type": []string{"application/json"}}
}

func TestRound6ScanLongJSONFieldComplete(t *testing.T) {
	for _, size := range []int{270 << 10, 1 << 20} {
		for _, position := range []string{"start", "middle", "end"} {
			t.Run(fmt.Sprintf("%d/%s", size, position), func(t *testing.T) {
				const canary = "ROUND6_LONG_TEXT_CANARY"
				padding := strings.Repeat("x", size-len(canary))
				text := ""
				switch position {
				case "start":
					text = canary + padding
				case "middle":
					middle := len(padding) / 2
					text = padding[:middle] + canary + padding[middle:]
				default:
					text = padding + canary
				}
				body, err := json.Marshal(map[string]any{
					"messages": []any{map[string]any{"role": "user", "content": text}},
				})
				if err != nil {
					t.Fatal(err)
				}
				sink := newRound6RecordingSink()
				result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAI}, Limits{}, sink)
				if err != nil {
					t.Fatal(err)
				}
				if sink.aborted || result.Envelope != EnvelopeComplete || result.TextCoverage != TextCoverageComplete || !result.IsComplete() {
					t.Fatalf("result=%#v aborted=%v", result, sink.aborted)
				}
				if result.TextBytesScanned != len(text) || result.LogicalTextParts != 1 {
					t.Fatalf("bytes/parts=%d/%d want=%d/1", result.TextBytesScanned, result.LogicalTextParts, len(text))
				}
				if result.ClassificationChunks < 2 || result.PeakTextBytesRetained > DefaultMaxTextPartBytes {
					t.Fatalf("chunks=%d peak=%d", result.ClassificationChunks, result.PeakTextBytesRetained)
				}
				if !strings.Contains(sink.joined(), canary) || sink.joined() != text {
					t.Fatal("streamed text did not preserve the complete logical field")
				}
			})
		}
	}
}

func TestRound6ScanSixtyFiveRoleMessagesRemainComplete(t *testing.T) {
	messages := make([]any, 0, 65)
	for index := 0; index < 65; index++ {
		role := "user"
		if index%2 == 0 {
			role = "system"
		}
		messages = append(messages, map[string]any{"role": role, "content": fmt.Sprintf("turn-%03d", index)})
	}
	body, err := json.Marshal(map[string]any{"messages": messages})
	if err != nil {
		t.Fatal(err)
	}
	sink := newRound6RecordingSink()
	result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAI}, Limits{}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsComplete() || !result.RoleAware || result.LogicalTextParts != 65 || len(sink.fieldText) != 65 {
		t.Fatalf("result=%#v fields=%d", result, len(sink.fieldText))
	}
	for fieldID := uint64(1); fieldID <= 65; fieldID++ {
		wantRole := RoleUser
		if (fieldID-1)%2 == 0 {
			wantRole = RoleSystem
		}
		if got := sink.fieldRole[fieldID]; got != wantRole {
			t.Fatalf("field %d role=%q want=%q", fieldID, got, wantRole)
		}
	}
}

func TestRound6UnknownAndProvenUserRolesRemainDistinct(t *testing.T) {
	t.Run("unattributed top level input", func(t *testing.T) {
		body := []byte(`{"input":["first untrusted part","second untrusted part"]}`)
		sink := newRound6RecordingSink()
		result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, Limits{}, sink)
		if err != nil || !result.IsComplete() || result.RoleAware {
			t.Fatalf("result=%#v err=%v", result, err)
		}
		for fieldID, role := range sink.fieldRole {
			if role != RoleUnknown {
				t.Fatalf("field %d role=%q want=%q", fieldID, role, RoleUnknown)
			}
		}
	})
	t.Run("proven user message", func(t *testing.T) {
		body := []byte(`{"messages":[{"role":"user","content":"proven user text"}]}`)
		sink := newRound6RecordingSink()
		result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAI}, Limits{}, sink)
		if err != nil || !result.IsComplete() || !result.RoleAware || sink.fieldRole[1] != RoleUser {
			t.Fatalf("result=%#v roles=%#v err=%v", result, sink.fieldRole, err)
		}
	})
	t.Run("role-less message keeps mixed request globally untrusted", func(t *testing.T) {
		body := []byte(`{"messages":[{"content":"unattributed text"},{"role":"system","content":"proven system text"}]}`)
		sink := newRound6RecordingSink()
		result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAI}, Limits{}, sink)
		if err != nil || !result.IsComplete() || result.RoleAware || len(sink.fieldRole) != 2 {
			t.Fatalf("result=%#v roles=%#v err=%v", result, sink.fieldRole, err)
		}
		for fieldID, role := range sink.fieldRole {
			if role != RoleUnknown {
				t.Fatalf("field %d role=%q want=%q", fieldID, role, RoleUnknown)
			}
		}
	})
}

func TestRound6OneLogicalFieldMayUseFiveHundredThirteenChunks(t *testing.T) {
	text := strings.Repeat("a", 513*1024)
	body, err := json.Marshal(map[string]string{"input": text})
	if err != nil {
		t.Fatal(err)
	}
	sink := newRound6RecordingSink()
	result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, Limits{
		MaxTextParts:            1,
		MaxTextPartBytes:        1024,
		MaxTextWindowBytes:      MinTextWindowBytes,
		MaxTotalTextBytes:       DefaultMaxTotalTextBytes,
		MaxClassificationChunks: 600,
	}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsComplete() || result.LogicalTextParts != 1 || result.ClassificationChunks != 513 {
		t.Fatalf("result=%#v", result)
	}
	if sink.joined() != text {
		t.Fatal("513-chunk field did not reconstruct")
	}
}

func TestRound6ExactChunkBoundariesRemainComplete(t *testing.T) {
	for _, size := range []int{DefaultMaxTextPartBytes - 1, DefaultMaxTextPartBytes, DefaultMaxTextPartBytes + 1} {
		t.Run(fmt.Sprintf("bytes-%d", size), func(t *testing.T) {
			text := strings.Repeat("b", size)
			body, err := json.Marshal(map[string]string{"input": text})
			if err != nil {
				t.Fatal(err)
			}
			sink := newRound6RecordingSink()
			result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, Limits{}, sink)
			if err != nil {
				t.Fatal(err)
			}
			wantChunks := 1
			if size > DefaultMaxTextPartBytes {
				wantChunks = 2
			}
			if !result.IsComplete() || result.ClassificationChunks != wantChunks || sink.joined() != text {
				t.Fatalf("result=%#v streamed=%d", result, len(sink.joined()))
			}
		})
	}
}

func TestRound6FiveHundredThirteenLogicalFieldsAreIncomplete(t *testing.T) {
	values := make([]string, DefaultMaxTextParts+1)
	for index := range values {
		values[index] = fmt.Sprintf("field-%03d", index)
	}
	body, err := json.Marshal(map[string]any{"input": values})
	if err != nil {
		t.Fatal(err)
	}
	sink := newRound6RecordingSink()
	result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, Limits{}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if !sink.aborted || result.Envelope != EnvelopeComplete || result.TextCoverage != TextCoverageExhausted || !result.HasIncompleteReason(IncompleteTextPartLimit) {
		t.Fatalf("result=%#v aborted=%v", result, sink.aborted)
	}
}

func TestRound6ClassificationChunkLimitIsCoverageIncomplete(t *testing.T) {
	text := strings.Repeat("c", 3*1024)
	body, err := json.Marshal(map[string]string{"input": text})
	if err != nil {
		t.Fatal(err)
	}
	sink := newRound6RecordingSink()
	result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, Limits{
		MaxTextWindowBytes:      MinTextWindowBytes,
		MaxTextPartBytes:        1024,
		MaxTotalTextBytes:       MinTextWindowBytes,
		MaxClassificationChunks: 2,
	}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if !sink.aborted || result.Envelope != EnvelopeComplete || result.TextCoverage != TextCoverageExhausted || !result.HasIncompleteReason(IncompleteClassificationChunkLimit) {
		t.Fatalf("result=%#v aborted=%v", result, sink.aborted)
	}
}

func TestRound6ClassificationChunkLimitUsesActualUTF8Chunks(t *testing.T) {
	text := strings.Repeat("你é", 2)
	body, err := json.Marshal(map[string]string{"input": text})
	if err != nil {
		t.Fatal(err)
	}
	sink := newRound6RecordingSink()
	result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, Limits{
		MaxTextPartBytes:        4,
		MaxClassificationChunks: 3,
	}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if !sink.aborted || result.TextCoverage != TextCoverageExhausted || !result.HasIncompleteReason(IncompleteClassificationChunkLimit) {
		t.Fatalf("result=%#v aborted=%v", result, sink.aborted)
	}
	if result.ClassificationChunks != 3 || len(sink.chunks) != 3 {
		t.Fatalf("classification chunks=%d delivered=%d want=3", result.ClassificationChunks, len(sink.chunks))
	}
	for _, chunk := range sink.chunks {
		if !utf8.Valid(chunk.Text) {
			t.Fatalf("chunk split UTF-8: %x", chunk.Text)
		}
	}
}

func TestRound6UnicodeEscapesAndSurrogatesReplayExactly(t *testing.T) {
	body := []byte(`{"input":"A\u4f60\u597d\ud83d\ude80Z"}`)
	sink := newRound6RecordingSink()
	result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, Limits{
		MaxTextPartBytes: 1,
	}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsComplete() || sink.joined() != "A你好🚀Z" {
		t.Fatalf("result=%#v streamed=%q", result, sink.joined())
	}
	for _, chunk := range sink.chunks {
		if !utf8.Valid(chunk.Text) {
			t.Fatalf("chunk split UTF-8: %x", chunk.Text)
		}
	}
}

func TestRound6MetadataPaddingDoesNotConsumeTextCoverage(t *testing.T) {
	const prompt = "ROUND6_VISIBLE_PROMPT"
	body, err := json.Marshal(map[string]any{
		"metadata": map[string]string{"padding": strings.Repeat("m", 270<<10)},
		"input":    prompt,
	})
	if err != nil {
		t.Fatal(err)
	}
	sink := newRound6RecordingSink()
	result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, Limits{}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsComplete() || result.TextBytesScanned != len(prompt) || sink.joined() != prompt {
		t.Fatalf("result=%#v streamed=%q", result, sink.joined())
	}
}

func TestRound6FutureNonMetadataEnvelopeRemainsInspectable(t *testing.T) {
	const canary = "ROUND6_FUTURE_ENVELOPE_VISIBLE_CANARY"
	body, err := json.Marshal(map[string]any{
		"future_envelope": map[string]any{
			"payload": map[string]string{"request": canary},
		},
		"metadata": map[string]string{"private": "ROUND6_METADATA_MUST_STAY_HIDDEN"},
	})
	if err != nil {
		t.Fatal(err)
	}
	sink := newRound6RecordingSink()
	result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAI}, Limits{}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsComplete() || sink.aborted || !strings.Contains(sink.joined(), canary) {
		t.Fatalf("result=%#v aborted=%v streamed=%q", result, sink.aborted, sink.joined())
	}
	if strings.Contains(sink.joined(), "ROUND6_METADATA_MUST_STAY_HIDDEN") {
		t.Fatalf("provider metadata entered classifier text: %q", sink.joined())
	}
}

func TestRound6MarkerLastMediaRemainsTransactional(t *testing.T) {
	const caption = "ROUND6_VISIBLE_CAPTION"
	body, err := json.Marshal(map[string]any{
		"messages": []any{map[string]any{
			"role": "user",
			"content": []any{map[string]any{
				"source":  map[string]any{"data": strings.Repeat("A", 270<<10), "media_type": "image/png"},
				"caption": caption,
				"type":    "image",
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	sink := newRound6RecordingSink()
	result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAI}, Limits{}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsComplete() || !result.OpaqueMedia || sink.joined() != caption || result.TextBytesScanned != len(caption) {
		t.Fatalf("result=%#v streamed=%q", result, sink.joined())
	}
}

func TestRound6TransactionalSelectionPreservesSourceFieldOrder(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":{"source":"first field","caption":"second field"}}]}`)
	sink := newRound6RecordingSink()
	result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAI}, Limits{}, sink)
	if err != nil || !result.IsComplete() || !result.RoleAware {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if sink.joined() != "first fieldsecond field" {
		t.Fatalf("transactional replay order=%q", sink.joined())
	}
	for fieldID, role := range sink.fieldRole {
		if role != RoleUser {
			t.Fatalf("field %d role=%q", fieldID, role)
		}
	}
}

func TestRound6MediaLookingPrefixInOrdinaryTextRemainsInspectable(t *testing.T) {
	const canary = "ROUND6_MEDIA_PREFIX_VISIBLE_CANARY"
	value := "data:image/png;base64," + strings.Repeat("A", maxShadowValueBytes+1) + canary
	tests := []struct {
		name string
		body any
	}{
		{name: "ordinary input", body: map[string]any{"input": value}},
		{name: "scalar carrier explicitly non media", body: map[string]any{
			"input": map[string]any{"source": value, "type": "text"},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body, err := json.Marshal(test.body)
			if err != nil {
				t.Fatal(err)
			}
			sink := newRound6RecordingSink()
			result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, Limits{}, sink)
			if err != nil {
				t.Fatal(err)
			}
			if !result.IsComplete() || sink.aborted || !strings.Contains(sink.joined(), canary) {
				t.Fatalf("result=%#v aborted=%v streamed_canary=%v", result, sink.aborted, strings.Contains(sink.joined(), canary))
			}
		})
	}
}

func TestRound6AmbiguousRoleAbortsBeforeSinkConsumption(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "duplicate string role", body: `{"messages":[{"content":"role canary","role":"user","role":"assistant"}]}`},
		{name: "duplicate non string role", body: `{"messages":[{"content":"role canary","role":"assistant","role":false}]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sink := newRound6RecordingSink()
			result, err := ScanProfiledRequest([]byte(test.body), round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAI}, Limits{}, sink)
			if err != nil {
				t.Fatal(err)
			}
			if result.IsComplete() || result.Envelope != EnvelopeComplete || result.TextCoverage != TextCoverageUnavailable ||
				!result.HasIncompleteReason(IncompleteRoleAttribution) || result.RoleAware || !sink.aborted || len(sink.fieldRole) != 0 {
				t.Fatalf("result=%#v aborted=%v roles=%#v", result, sink.aborted, sink.fieldRole)
			}
		})
	}
}

func TestRound6StreamingRestoresBoundedEncodedTextViews(t *testing.T) {
	const decoded = "ROUND6 DERIVED VIEW CANARY"
	tests := []struct {
		name  string
		value string
	}{
		{name: "base64", value: base64.StdEncoding.EncodeToString([]byte(decoded))},
		{name: "percent", value: "ROUND6%20DERIVED%20VIEW%20CANARY"},
		{name: "html", value: "ROUND6&#32;DERIVED&#32;VIEW&#32;CANARY"},
		{name: "text data url", value: "data:text/plain,ROUND6%20DERIVED%20VIEW%20CANARY"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body, err := json.Marshal(map[string]string{"input": test.value})
			if err != nil {
				t.Fatal(err)
			}
			sink := newRound6RecordingSink()
			result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, Limits{}, sink)
			if err != nil {
				t.Fatal(err)
			}
			if !result.IsComplete() || sink.aborted || result.LogicalTextParts != 1 {
				t.Fatalf("result=%#v aborted=%v", result, sink.aborted)
			}
			found := false
			for fieldID, text := range sink.fieldText {
				if text.String() != decoded {
					continue
				}
				found = true
				if sink.fieldRole[fieldID] != RoleUnknown || sink.fieldProv[fieldID] != ProvenanceContent {
					t.Fatalf("derived field role/provenance=%q/%d", sink.fieldRole[fieldID], sink.fieldProv[fieldID])
				}
			}
			if !found {
				t.Fatalf("decoded view not emitted; fields=%d joined=%q", len(sink.fieldText), sink.joined())
			}
		})
	}
}

func TestRound6OversizedPrintableBase64IsIncomplete(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("round six bounded decode canary ", 6000)))
	if len(encoded) <= maxDecodeSourceBytes {
		t.Fatalf("fixture too small: %d", len(encoded))
	}
	body, err := json.Marshal(map[string]string{"input": encoded})
	if err != nil {
		t.Fatal(err)
	}
	sink := newRound6RecordingSink()
	result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, Limits{}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if !sink.aborted || result.TextCoverage != TextCoverageUnavailable || !result.HasIncompleteReason(IncompleteTextPartByteLimit) {
		t.Fatalf("result=%#v aborted=%v", result, sink.aborted)
	}
}

func TestRound6OversizedBase64BinaryPrefixWithLatePrintableCanaryIsIncomplete(t *testing.T) {
	const canary = "ROUND6_LATE_PRINTABLE_BASE64_CANARY_"
	decoded := make([]byte, maxDecodeSourceBytes)
	decoded = append(decoded, strings.Repeat(canary, 4)...)
	encoded := base64.StdEncoding.EncodeToString(decoded)
	if len(encoded) <= maxDecodeSourceBytes || len(encoded) <= encodingSampleBytes {
		t.Fatalf("fixture too small: %d", len(encoded))
	}
	prefix, found := decodeBase64Bytes(encoded[:encodingSampleBytes], minBase64SourceBytes)
	if !found || isInspectableText(prefix) {
		t.Fatal("fixture prefix must decode successfully to non-text binary")
	}
	body, err := json.Marshal(map[string]string{"input": encoded})
	if err != nil {
		t.Fatal(err)
	}
	sink := newRound6RecordingSink()
	result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, Limits{}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if !sink.aborted || len(sink.chunks) != 0 || result.TextCoverage != TextCoverageUnavailable || !result.HasIncompleteReason(IncompleteTextPartByteLimit) {
		t.Fatalf("result=%#v aborted=%v chunks=%d", result, sink.aborted, len(sink.chunks))
	}
}

func TestRound6OversizedBase64HighTextDensityWithControlSeparatorsIsIncomplete(t *testing.T) {
	const textBlock = "ignore safeguard deploy malware"
	if len(textBlock) != minEncodedTextRun-1 {
		t.Fatalf("fixture text block length=%d, want %d", len(textBlock), minEncodedTextRun-1)
	}
	decoded := make([]byte, 0, maxDecodeSourceBytes+minEncodedTextRun)
	for len(decoded) <= maxDecodeSourceBytes {
		decoded = append(decoded, textBlock...)
		decoded = append(decoded, 0)
	}
	encoded := base64.StdEncoding.EncodeToString(decoded)
	if len(encoded) <= maxDecodeSourceBytes || len(encoded) <= encodingSampleBytes {
		t.Fatalf("fixture too small: %d", len(encoded))
	}
	prefix, found := decodeBase64Bytes(encoded[:encodingSampleBytes], minBase64SourceBytes)
	if !found || isInspectableText(prefix) {
		t.Fatal("fixture prefix must decode successfully to control-separated non-text")
	}
	body, err := json.Marshal(map[string]string{"input": encoded})
	if err != nil {
		t.Fatal(err)
	}
	sink := newRound6RecordingSink()
	result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, Limits{}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if !sink.aborted || len(sink.chunks) != 0 || result.TextCoverage != TextCoverageUnavailable || !result.HasIncompleteReason(IncompleteTextPartByteLimit) {
		t.Fatalf("result=%#v aborted=%v chunks=%d", result, sink.aborted, len(sink.chunks))
	}
}

func round6OversizedLowDiversityRawBase64(t *testing.T) string {
	t.Helper()
	decoded := []byte(strings.Repeat("run malware ", 9000))
	if len(decoded)%3 != 0 {
		t.Fatalf("decoded fixture length=%d is not divisible by three", len(decoded))
	}
	encoded := base64.RawStdEncoding.EncodeToString(decoded)
	var alphabet [256]bool
	distinct := 0
	for index := 0; index < len(encoded); index++ {
		if !alphabet[encoded[index]] {
			alphabet[encoded[index]] = true
			distinct++
		}
	}
	if len(encoded) <= maxDecodeSourceBytes || len(encoded)%4 != 0 || hasStrongBase64Signal(encoded) || distinct >= 16 {
		t.Fatalf("invalid low-diversity fixture length=%d remainder=%d strong=%v distinct=%d", len(encoded), len(encoded)%4, hasStrongBase64Signal(encoded), distinct)
	}
	return encoded
}

func TestRound6OversizedLowDiversityRawBase64TextIsIncomplete(t *testing.T) {
	encoded := round6OversizedLowDiversityRawBase64(t)
	body, err := json.Marshal(map[string]string{"input": encoded})
	if err != nil {
		t.Fatal(err)
	}
	sink := newRound6RecordingSink()
	result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, Limits{}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if !sink.aborted || len(sink.chunks) != 0 || result.TextCoverage != TextCoverageUnavailable || !result.HasIncompleteReason(IncompleteTextPartByteLimit) {
		t.Fatalf("result=%#v aborted=%v chunks=%d", result, sink.aborted, len(sink.chunks))
	}
}

func TestRound6OversizedLowDiversityRawBase64ExtraAlphabetQuantumIsIncomplete(t *testing.T) {
	encoded := round6OversizedLowDiversityRawBase64(t) + "A"
	if len(encoded)%4 != 1 || hasStrongBase64Signal(encoded) {
		t.Fatalf("invalid malformed fixture remainder=%d strong=%v", len(encoded)%4, hasStrongBase64Signal(encoded))
	}
	body, err := json.Marshal(map[string]string{"input": encoded})
	if err != nil {
		t.Fatal(err)
	}
	sink := newRound6RecordingSink()
	result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, Limits{}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if !sink.aborted || len(sink.chunks) != 0 || result.TextCoverage != TextCoverageUnavailable || !result.HasIncompleteReason(IncompleteTextPartByteLimit) {
		t.Fatalf("result=%#v aborted=%v chunks=%d", result, sink.aborted, len(sink.chunks))
	}
}

func TestRound6OversizedLowDiversityBase64TrailingJunkIsIncomplete(t *testing.T) {
	encoded := round6OversizedLowDiversityRawBase64(t)
	body, err := json.Marshal(map[string]string{"input": encoded + "."})
	if err != nil {
		t.Fatal(err)
	}
	sink := newRound6RecordingSink()
	result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, Limits{}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if !sink.aborted || len(sink.chunks) != 0 || result.TextCoverage != TextCoverageUnavailable || !result.HasIncompleteReason(IncompleteTextPartByteLimit) {
		t.Fatalf("result=%#v aborted=%v chunks=%d", result, sink.aborted, len(sink.chunks))
	}
}

func TestRound6OversizedPrintableBase64WithTrailingJunkIsIncomplete(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("round six malformed base64 canary ", 6000)))
	if len(encoded) <= maxDecodeSourceBytes {
		t.Fatalf("fixture too small: %d", len(encoded))
	}
	body, err := json.Marshal(map[string]string{"input": encoded + "."})
	if err != nil {
		t.Fatal(err)
	}
	sink := newRound6RecordingSink()
	result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, Limits{}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if !sink.aborted || len(sink.chunks) != 0 || result.TextCoverage != TextCoverageUnavailable || !result.HasIncompleteReason(IncompleteTextPartByteLimit) {
		t.Fatalf("result=%#v aborted=%v chunks=%d", result, sink.aborted, len(sink.chunks))
	}
}

func TestRound6OversizedBase64CharactersAfterPaddingAreIncomplete(t *testing.T) {
	decoded := []byte(strings.Repeat("round six padding suffix canary ", 6000))
	for len(decoded)%3 != 2 {
		decoded = append(decoded, 'x')
	}
	encoded := base64.StdEncoding.EncodeToString(decoded)
	if len(encoded) <= maxDecodeSourceBytes || !strings.HasSuffix(encoded, "=") || strings.HasSuffix(encoded, "==") {
		t.Fatalf("invalid fixture length=%d suffix=%q", len(encoded), encoded[len(encoded)-2:])
	}
	body, err := json.Marshal(map[string]string{"input": encoded + "AAAAA"})
	if err != nil {
		t.Fatal(err)
	}
	sink := newRound6RecordingSink()
	result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, Limits{}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if !sink.aborted || len(sink.chunks) != 0 || result.TextCoverage != TextCoverageUnavailable || !result.HasIncompleteReason(IncompleteTextPartByteLimit) {
		t.Fatalf("result=%#v aborted=%v chunks=%d", result, sink.aborted, len(sink.chunks))
	}
}

func TestRound6OversizedBase64ThirdPaddingIsIncomplete(t *testing.T) {
	decoded := []byte(strings.Repeat("round six excess padding canary ", 6000))
	for len(decoded)%3 != 1 {
		decoded = append(decoded, 'x')
	}
	encoded := base64.StdEncoding.EncodeToString(decoded)
	if len(encoded) <= maxDecodeSourceBytes || !strings.HasSuffix(encoded, "==") {
		t.Fatalf("invalid fixture length=%d suffix=%q", len(encoded), encoded[len(encoded)-2:])
	}
	body, err := json.Marshal(map[string]string{"input": encoded + "="})
	if err != nil {
		t.Fatal(err)
	}
	sink := newRound6RecordingSink()
	result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, Limits{}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if !sink.aborted || len(sink.chunks) != 0 || result.TextCoverage != TextCoverageUnavailable || !result.HasIncompleteReason(IncompleteTextPartByteLimit) {
		t.Fatalf("result=%#v aborted=%v chunks=%d", result, sink.aborted, len(sink.chunks))
	}
}

func TestRound6OversizedBase64BinaryPrefixLateTextAndTrailingJunkIsIncomplete(t *testing.T) {
	const canary = "ROUND6_LATE_PRINTABLE_MALFORMED_BASE64_CANARY_"
	decoded := make([]byte, maxDecodeSourceBytes)
	decoded = append(decoded, strings.Repeat(canary, 4)...)
	encoded := base64.StdEncoding.EncodeToString(decoded)
	if len(encoded) <= maxDecodeSourceBytes || len(encoded) <= encodingSampleBytes {
		t.Fatalf("fixture too small: %d", len(encoded))
	}
	body, err := json.Marshal(map[string]string{"input": encoded + "."})
	if err != nil {
		t.Fatal(err)
	}
	sink := newRound6RecordingSink()
	result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, Limits{}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if !sink.aborted || len(sink.chunks) != 0 || result.TextCoverage != TextCoverageUnavailable || !result.HasIncompleteReason(IncompleteTextPartByteLimit) {
		t.Fatalf("result=%#v aborted=%v chunks=%d", result, sink.aborted, len(sink.chunks))
	}
}

func TestRound6OversizedBase64SecondPaddingWithInvalidQuantumIsIncomplete(t *testing.T) {
	decoded := []byte(strings.Repeat("round six invalid second padding canary ", 6000))
	for len(decoded)%3 != 2 {
		decoded = append(decoded, 'x')
	}
	encoded := base64.StdEncoding.EncodeToString(decoded)
	if len(encoded) <= maxDecodeSourceBytes || !strings.HasSuffix(encoded, "=") || strings.HasSuffix(encoded, "==") {
		t.Fatalf("invalid fixture length=%d suffix=%q", len(encoded), encoded[len(encoded)-2:])
	}
	body, err := json.Marshal(map[string]string{"input": encoded + "="})
	if err != nil {
		t.Fatal(err)
	}
	sink := newRound6RecordingSink()
	result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, Limits{}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if !sink.aborted || len(sink.chunks) != 0 || result.TextCoverage != TextCoverageUnavailable || !result.HasIncompleteReason(IncompleteTextPartByteLimit) {
		t.Fatalf("result=%#v aborted=%v chunks=%d", result, sink.aborted, len(sink.chunks))
	}
}

func TestRound6OversizedRawBase64ExtraAlphabetQuantumIsIncomplete(t *testing.T) {
	decoded := []byte(strings.Repeat("round six invalid raw quantum canary ", 6000))
	for len(decoded)%3 != 0 {
		decoded = append(decoded, 'x')
	}
	encoded := base64.RawStdEncoding.EncodeToString(decoded)
	if len(encoded) <= maxDecodeSourceBytes || len(encoded)%4 != 0 {
		t.Fatalf("invalid fixture length=%d", len(encoded))
	}
	body, err := json.Marshal(map[string]string{"input": encoded + "A"})
	if err != nil {
		t.Fatal(err)
	}
	sink := newRound6RecordingSink()
	result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, Limits{}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if !sink.aborted || len(sink.chunks) != 0 || result.TextCoverage != TextCoverageUnavailable || !result.HasIncompleteReason(IncompleteTextPartByteLimit) {
		t.Fatalf("result=%#v aborted=%v chunks=%d", result, sink.aborted, len(sink.chunks))
	}
}

func TestRound6OversizedRawBase64InvalidFirstPaddingIsIncomplete(t *testing.T) {
	decoded := []byte(strings.Repeat("round six invalid first padding canary ", 6000))
	for len(decoded)%3 != 0 {
		decoded = append(decoded, 'x')
	}
	encoded := base64.RawStdEncoding.EncodeToString(decoded)
	if len(encoded) <= maxDecodeSourceBytes || len(encoded)%4 != 0 {
		t.Fatalf("invalid fixture length=%d", len(encoded))
	}
	body, err := json.Marshal(map[string]string{"input": encoded + "="})
	if err != nil {
		t.Fatal(err)
	}
	sink := newRound6RecordingSink()
	result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, Limits{}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if !sink.aborted || len(sink.chunks) != 0 || result.TextCoverage != TextCoverageUnavailable || !result.HasIncompleteReason(IncompleteTextPartByteLimit) {
		t.Fatalf("result=%#v aborted=%v chunks=%d", result, sink.aborted, len(sink.chunks))
	}
}

func TestRound6OversizedBase64BinaryPrefixLateTextAndEOFPaddingIsIncomplete(t *testing.T) {
	const canary = "ROUND6_LATE_PRINTABLE_EOF_BASE64_CANARY_"
	decoded := make([]byte, maxDecodeSourceBytes)
	decoded = append(decoded, strings.Repeat(canary, 4)...)
	for len(decoded)%3 != 0 {
		decoded = append(decoded, 'x')
	}
	encoded := base64.RawStdEncoding.EncodeToString(decoded)
	if len(encoded) <= maxDecodeSourceBytes || len(encoded) <= encodingSampleBytes || len(encoded)%4 != 0 {
		t.Fatalf("invalid fixture length=%d", len(encoded))
	}
	body, err := json.Marshal(map[string]string{"input": encoded + "="})
	if err != nil {
		t.Fatal(err)
	}
	sink := newRound6RecordingSink()
	result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, Limits{}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if !sink.aborted || len(sink.chunks) != 0 || result.TextCoverage != TextCoverageUnavailable || !result.HasIncompleteReason(IncompleteTextPartByteLimit) {
		t.Fatalf("result=%#v aborted=%v chunks=%d", result, sink.aborted, len(sink.chunks))
	}
}

func TestRound6OversizedBase64AlphabetProseRemainsComplete(t *testing.T) {
	const canary = "ROUND6 ORDINARY LONG PROSE CANARY"
	value := strings.Repeat("ordinary long prose with words and spaces ", 4000) + canary
	if len(value) <= maxDecodeSourceBytes {
		t.Fatalf("fixture too small: %d", len(value))
	}
	body, err := json.Marshal(map[string]string{"input": value})
	if err != nil {
		t.Fatal(err)
	}
	sink := newRound6RecordingSink()
	result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, Limits{}, sink)
	if err != nil || !result.IsComplete() || sink.aborted || sink.joined() != value {
		t.Fatalf("result=%#v aborted=%v streamed=%d err=%v", result, sink.aborted, len(sink.joined()), err)
	}
}

func TestRound6LongOrdinaryPercentAndAmpersandRemainComplete(t *testing.T) {
	const canary = "ROUND6_LONG_PERCENT_VISIBLE_CANARY"
	value := strings.Repeat("ordinary long text ", 8000) + "100% complete & ordinary; " + canary
	if len(value) <= maxDecodeSourceBytes {
		t.Fatalf("fixture too small: %d", len(value))
	}
	body, err := json.Marshal(map[string]string{"input": value})
	if err != nil {
		t.Fatal(err)
	}
	sink := newRound6RecordingSink()
	result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, Limits{}, sink)
	if err != nil || !result.IsComplete() || sink.aborted || !strings.Contains(sink.joined(), canary) {
		t.Fatalf("result=%#v aborted=%v err=%v", result, sink.aborted, err)
	}
}

func TestRound6SparseEncodingSignalsCannotForceIncomplete(t *testing.T) {
	const canary = "ROUND6_EXPLICIT_MALICIOUS_LONG_TEXT_CANARY"
	tests := []struct {
		name   string
		suffix string
	}{
		{name: "single valid percent escape", suffix: " explicit malicious text " + canary + " %20 trailing text"},
		{name: "single real HTML entity", suffix: " explicit malicious text " + canary + " &amp; trailing text"},
		{name: "base64 padding suffix", suffix: canary + "=="},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			value := strings.Repeat("x", (270<<10)-len(testCase.suffix)) + testCase.suffix
			body, err := json.Marshal(map[string]string{"input": value})
			if err != nil {
				t.Fatal(err)
			}
			sink := newRound6RecordingSink()
			result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, Limits{}, sink)
			if err != nil || !result.IsComplete() || sink.aborted {
				t.Fatalf("result=%#v aborted=%v err=%v", result, sink.aborted, err)
			}
			if result.TextBytesScanned != len(value) || sink.joined() != value || !strings.Contains(sink.joined(), canary) {
				t.Fatalf("coverage bytes=%d/%d streamed=%d", result.TextBytesScanned, len(value), len(sink.joined()))
			}
		})
	}
}

func TestRound6OversizedValidPercentEnvelopeIsIncomplete(t *testing.T) {
	value := strings.Repeat("%41", 50000)
	body, err := json.Marshal(map[string]string{"input": value})
	if err != nil {
		t.Fatal(err)
	}
	sink := newRound6RecordingSink()
	result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, Limits{}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if !sink.aborted || result.TextCoverage != TextCoverageUnavailable || !result.HasIncompleteReason(IncompleteTextPartByteLimit) {
		t.Fatalf("result=%#v aborted=%v", result, sink.aborted)
	}
}

func TestRound6MultipartLongPromptStreamsWhileFileStaysOpaque(t *testing.T) {
	prompt := "ROUND6_MULTIPART_CANARY" + strings.Repeat("p", 270<<10)
	body, contentType := multipartBody(t, []multipartTestPart{
		{name: "prompt", value: []byte(prompt)},
		{name: "image", filename: "large.png", contentType: "image/png", value: []byte(strings.Repeat("A", 1<<20))},
	})
	sink := newRound6RecordingSink()
	result, err := ScanProfiledRequest(
		body,
		http.Header{"Content-Type": []string{contentType}},
		RequestProfile{Source: SourceProfileOpenAIImage},
		Limits{
			MaxTextPartBytes:          len(prompt),
			MaxMultipartTextBytes:     len(prompt),
			MaxMultipartTextPartBytes: len(prompt),
		},
		sink,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsComplete() || result.TextCoverage != TextCoverageComplete || !result.OpaqueMedia {
		t.Fatalf("result=%#v", result)
	}
	if sink.joined() != prompt || result.TextBytesScanned != len(prompt) || result.ClassificationChunks < 2 {
		t.Fatalf("bytes=%d chunks=%d streamed=%d", result.TextBytesScanned, result.ClassificationChunks, len(sink.joined()))
	}
}

func TestRound6MultipartSpecificTextLimitsAreEnforced(t *testing.T) {
	t.Run("text field count", func(t *testing.T) {
		body, contentType := multipartBody(t, []multipartTestPart{
			{name: "prompt", value: []byte("first")},
			{name: "negative_prompt", value: []byte("second")},
		})
		sink := newRound6RecordingSink()
		result, err := ScanProfiledRequest(
			body, http.Header{"Content-Type": []string{contentType}},
			RequestProfile{Source: SourceProfileOpenAIImage}, Limits{MaxMultipartTextFields: 1}, sink,
		)
		if err != nil || !sink.aborted || result.TextCoverage != TextCoverageExhausted ||
			!result.HasIncompleteReason(IncompleteMultipartTextLimit) || result.HasIncompleteReason(IncompleteTextPartLimit) {
			t.Fatalf("result=%#v aborted=%v err=%v", result, sink.aborted, err)
		}
	})

	wireBody, wireContentType := multipartBody(t, []multipartTestPart{{name: "prompt", value: []byte("0123456789")}})
	for _, fixture := range []struct {
		name        string
		body        []byte
		contentType string
	}{
		{name: "wire multipart", body: wireBody, contentType: wireContentType},
		{name: "transformed multipart JSON", body: []byte(`{"prompt":"0123456789"}`), contentType: "multipart/form-data; boundary=stale-cpa-boundary"},
	} {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			sink := newRound6RecordingSink()
			result, err := ScanProfiledRequest(
				fixture.body, http.Header{"Content-Type": []string{fixture.contentType}},
				RequestProfile{Source: SourceProfileOpenAIImage}, Limits{MaxMultipartTextBytes: 8}, sink,
			)
			if err != nil || !sink.aborted || result.TextCoverage != TextCoverageExhausted ||
				!result.HasIncompleteReason(IncompleteMultipartTextLimit) {
				t.Fatalf("result=%#v aborted=%v err=%v", result, sink.aborted, err)
			}
		})
	}
}

func TestRound6MultipartZeroPartEOFFailsClosed(t *testing.T) {
	boundary := "\n"
	contentType := mime.FormatMediaType("multipart/form-data", map[string]string{"boundary": boundary})
	if contentType == "" {
		t.Fatal("fuzz regression boundary did not produce a media type")
	}
	body := []byte(fmt.Sprintf("--%s\r\nContent-Disposition: form-dAtA;nAme=\"0\"\r\nContent-Type: 0\r\n\r\n0\r\n--%s--\r\n", boundary, boundary))
	sink := newRound6RecordingSink()
	result, err := ScanProfiledRequest(
		body,
		http.Header{"Content-Type": []string{contentType}},
		RequestProfile{Source: SourceProfileOpenAIImage},
		Limits{},
		sink,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !sink.aborted || result.IsComplete() || result.Envelope != EnvelopeIncomplete ||
		result.TextCoverage != TextCoverageUnavailable || !result.HasIncompleteReason(IncompleteMultipartParseError) {
		t.Fatalf("zero-part malformed multipart result=%#v aborted=%v", result, sink.aborted)
	}
	if len(result.Parts) != 0 || len(result.Segments) != 0 || len(sink.chunks) != 0 ||
		result.TextBytesScanned != 0 || result.LogicalTextParts != 0 ||
		result.ClassificationChunks != 0 || result.PeakTextBytesRetained != 0 {
		t.Fatalf("zero-part malformed multipart retained provisional state: result=%#v chunks=%d", result, len(sink.chunks))
	}
}

func TestRound6MultipartPromptEmitsBoundedDecodedView(t *testing.T) {
	const decoded = "ROUND6 MULTIPART DERIVED CANARY"
	encoded := base64.StdEncoding.EncodeToString([]byte(decoded))
	body, contentType := multipartBody(t, []multipartTestPart{{name: "prompt", value: []byte(encoded)}})
	sink := newRound6RecordingSink()
	result, err := ScanProfiledRequest(
		body,
		http.Header{"Content-Type": []string{contentType}},
		RequestProfile{Source: SourceProfileOpenAIImage},
		Limits{},
		sink,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsComplete() || sink.aborted || result.LogicalTextParts != 1 {
		t.Fatalf("result=%#v aborted=%v", result, sink.aborted)
	}
	found := false
	for fieldID, text := range sink.fieldText {
		if text.String() == decoded {
			found = true
			if sink.fieldRole[fieldID] != RoleUser || sink.fieldProv[fieldID] != ProvenanceContent {
				t.Fatalf("derived field role/provenance=%q/%d", sink.fieldRole[fieldID], sink.fieldProv[fieldID])
			}
		}
	}
	if !found {
		t.Fatalf("multipart decoded view not emitted; fields=%d", len(sink.fieldText))
	}
}

func TestRound6MultipartExactChunkMultiplesAlwaysEndField(t *testing.T) {
	for _, chunks := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("chunks-%d", chunks), func(t *testing.T) {
			prompt := strings.Repeat("q", chunks*DefaultMaxTextPartBytes)
			body, contentType := multipartBody(t, []multipartTestPart{{name: "prompt", value: []byte(prompt)}})
			sink := newRound6RecordingSink()
			result, err := ScanProfiledRequest(
				body,
				http.Header{"Content-Type": []string{contentType}},
				RequestProfile{Source: SourceProfileOpenAIImage},
				Limits{
					MaxTextWindowBytes:        DefaultMaxTextPartBytes,
					MaxTextPartBytes:          len(prompt),
					MaxMultipartTextPartBytes: len(prompt),
				},
				sink,
			)
			if err != nil {
				t.Fatal(err)
			}
			if !result.IsComplete() || sink.aborted || sink.active || len(sink.chunks) == 0 || !sink.chunks[len(sink.chunks)-1].End {
				t.Fatalf("result=%#v aborted=%v active=%v chunks=%d", result, sink.aborted, sink.active, len(sink.chunks))
			}
			if sink.joined() != prompt {
				t.Fatalf("streamed bytes=%d want=%d", len(sink.joined()), len(prompt))
			}
		})
	}
}

func TestRound6TransformedMultipartJSONLongPromptStreamsCompletely(t *testing.T) {
	for _, size := range []int{270 << 10, 1 << 20} {
		for _, metadataFirst := range []bool{true, false} {
			order := "metadata-after"
			if metadataFirst {
				order = "metadata-before"
			}
			t.Run(fmt.Sprintf("%d/%s", size, order), func(t *testing.T) {
				const canary = "ROUND6_TRANSFORMED_MULTIPART_CANARY"
				prompt := round6ExtractPaddedText(size, canary)
				promptJSON, err := json.Marshal(prompt)
				if err != nil {
					t.Fatal(err)
				}
				body := append([]byte(`{"prompt":`), promptJSON...)
				body = append(body, []byte(`,"model":"gpt-image-2"}`)...)
				if metadataFirst {
					body = append([]byte(`{"model":"gpt-image-2","prompt":`), promptJSON...)
					body = append(body, '}')
				}

				sink := newRound6RecordingSink()
				result, err := ScanProfiledRequest(
					body,
					http.Header{"Content-Type": []string{"multipart/form-data; boundary=stale-cpa-boundary"}},
					RequestProfile{Source: SourceProfileOpenAIImage},
					Limits{MaxMultipartTextBytes: len(prompt)},
					sink,
				)
				if err != nil {
					t.Fatal(err)
				}
				if !result.IsComplete() || result.Envelope != EnvelopeComplete || result.TextCoverage != TextCoverageComplete || sink.aborted {
					t.Fatalf("result=%#v aborted=%v", result, sink.aborted)
				}
				if result.TextBytesScanned != len(prompt) || result.LogicalTextParts != 1 || result.ClassificationChunks < 2 {
					t.Fatalf("bytes/parts/chunks=%d/%d/%d want=%d/1/>=2", result.TextBytesScanned, result.LogicalTextParts, result.ClassificationChunks, len(prompt))
				}
				if sink.joined() != prompt || !strings.Contains(sink.joined(), canary) {
					t.Fatal("transformed multipart prompt was not replayed exactly")
				}
			})
		}
	}

	t.Run("file-remains-opaque", func(t *testing.T) {
		const prompt = "ROUND6_VISIBLE_TRANSFORMED_PROMPT"
		body := []byte(`{"image":{"data":"PRIVATE_OPAQUE_IMAGE_BYTES"},"prompt":"` + prompt + `","model":"gpt-image-2"}`)
		sink := newRound6RecordingSink()
		result, err := ScanProfiledRequest(
			body,
			http.Header{"Content-Type": []string{"multipart/form-data; boundary=stale-cpa-boundary"}},
			RequestProfile{Source: SourceProfileOpenAIImage},
			Limits{},
			sink,
		)
		if err != nil {
			t.Fatal(err)
		}
		if !result.IsComplete() || !result.OpaqueMedia || sink.joined() != prompt || strings.Contains(sink.joined(), "PRIVATE_OPAQUE_IMAGE_BYTES") {
			t.Fatalf("result=%#v streamed=%q", result, sink.joined())
		}
	})

	t.Run("unknown-field-aborts-before-replay", func(t *testing.T) {
		body := []byte(`{"prompt":"PRIVATE_PREFIX_MUST_NOT_COMMIT","telemetry":"unknown"}`)
		sink := newRound6RecordingSink()
		result, err := ScanProfiledRequest(
			body,
			http.Header{"Content-Type": []string{"multipart/form-data; boundary=stale-cpa-boundary"}},
			RequestProfile{Source: SourceProfileOpenAIImage},
			Limits{},
			sink,
		)
		if err != nil {
			t.Fatal(err)
		}
		if !sink.aborted || len(sink.chunks) != 0 || len(result.Segments) != 0 ||
			result.TextBytesScanned != 0 || result.TextCoverage != TextCoverageUnavailable ||
			!result.HasIncompleteReason(IncompleteMultipartUnknownField) {
			t.Fatalf("result=%#v aborted=%v chunks=%d", result, sink.aborted, len(sink.chunks))
		}
	})

	t.Run("text-type-mismatch-aborts-before-replay", func(t *testing.T) {
		body := []byte(`{"prompt":{"text":"PRIVATE_NESTED_VALUE"},"model":"gpt-image-2"}`)
		sink := newRound6RecordingSink()
		result, err := ScanProfiledRequest(
			body,
			http.Header{"Content-Type": []string{"multipart/form-data; boundary=stale-cpa-boundary"}},
			RequestProfile{Source: SourceProfileOpenAIImage},
			Limits{},
			sink,
		)
		if err != nil {
			t.Fatal(err)
		}
		if !sink.aborted || len(sink.chunks) != 0 || result.TextCoverage != TextCoverageUnavailable || !result.HasIncompleteReason(IncompleteMultipartTextFieldTypeMismatch) {
			t.Fatalf("result=%#v aborted=%v chunks=%d", result, sink.aborted, len(sink.chunks))
		}
	})

	t.Run("binary-control-preserves-multipart-parse-category", func(t *testing.T) {
		body := []byte(`{"prompt":"safe\u0001value"}`)
		sink := newRound6RecordingSink()
		result, err := ScanProfiledRequest(
			body,
			http.Header{"Content-Type": []string{"multipart/form-data; boundary=stale-cpa-boundary"}},
			RequestProfile{Source: SourceProfileOpenAIImage},
			Limits{},
			sink,
		)
		if err != nil {
			t.Fatal(err)
		}
		if !sink.aborted || result.TextCoverage != TextCoverageUnavailable || !result.HasIncompleteReason(IncompleteMultipartParseError) || result.HasIncompleteReason(IncompleteTextPartByteLimit) {
			t.Fatalf("result=%#v aborted=%v", result, sink.aborted)
		}
	})

	t.Run("oversized-encoded-view-preserves-multipart-text-category", func(t *testing.T) {
		promptJSON, err := json.Marshal(strings.Repeat("%41", 50000))
		if err != nil {
			t.Fatal(err)
		}
		body := append([]byte(`{"prompt":`), promptJSON...)
		body = append(body, '}')
		sink := newRound6RecordingSink()
		result, err := ScanProfiledRequest(
			body,
			http.Header{"Content-Type": []string{"multipart/form-data; boundary=stale-cpa-boundary"}},
			RequestProfile{Source: SourceProfileOpenAIImage},
			Limits{},
			sink,
		)
		if err != nil {
			t.Fatal(err)
		}
		if !sink.aborted || result.TextCoverage != TextCoverageExhausted || !result.HasIncompleteReason(IncompleteMultipartTextLimit) || result.HasIncompleteReason(IncompleteTextPartByteLimit) {
			t.Fatalf("result=%#v aborted=%v", result, sink.aborted)
		}
	})
}

func round6ExtractPaddedText(size int, canary string) string {
	if size < len(canary) {
		return canary[:size]
	}
	const pattern = "ordinary football schedule note. "
	var builder strings.Builder
	builder.Grow(size)
	left := (size - len(canary)) / 2
	for builder.Len()+len(pattern) <= left {
		builder.WriteString(pattern)
	}
	if remaining := left - builder.Len(); remaining > 0 {
		builder.WriteString(pattern[:remaining])
	}
	builder.WriteString(canary)
	for builder.Len()+len(pattern) <= size {
		builder.WriteString(pattern)
	}
	if remaining := size - builder.Len(); remaining > 0 {
		builder.WriteString(pattern[:remaining])
	}
	return builder.String()
}

func TestRound6TrueIncompleteAbortsSink(t *testing.T) {
	sink := newRound6RecordingSink()
	result, err := ScanProfiledRequest([]byte(`{"input":"complete"`), round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, Limits{}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if !sink.aborted || result.Envelope != EnvelopeIncomplete || result.TextCoverage != TextCoverageUnavailable || !result.HasIncompleteReason(IncompleteParseError) {
		t.Fatalf("result=%#v aborted=%v", result, sink.aborted)
	}
}

func TestRound6TotalTextBudgetIsCoverageNotEnvelope(t *testing.T) {
	text := strings.Repeat("z", MinTextWindowBytes+1)
	body, err := json.Marshal(map[string]string{"input": text})
	if err != nil {
		t.Fatal(err)
	}
	sink := newRound6RecordingSink()
	result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, Limits{
		MaxTextWindowBytes:      MinTextWindowBytes,
		MaxTotalTextBytes:       MinTextWindowBytes,
		MaxClassificationChunks: 2,
	}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if !sink.aborted || result.Envelope != EnvelopeComplete || result.TextCoverage != TextCoverageExhausted || !result.HasIncompleteReason(IncompleteTotalTextLimit) {
		t.Fatalf("result=%#v aborted=%v", result, sink.aborted)
	}
}

func TestRound6StreamingAllocationCountDoesNotScaleWithLongField(t *testing.T) {
	makeBody := func(size int) []byte {
		body, err := json.Marshal(map[string]string{"input": strings.Repeat("a", size)})
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	small := makeBody(64 << 10)
	large := makeBody(1 << 20)
	allocs := func(body []byte) float64 {
		return testing.AllocsPerRun(5, func() {
			result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, Limits{}, discardChunkSink{})
			if err != nil || !result.IsComplete() {
				panic(fmt.Sprintf("scan result=%#v err=%v", result, err))
			}
		})
	}
	smallAllocs := allocs(small)
	largeAllocs := allocs(large)
	if largeAllocs > smallAllocs+16 {
		t.Fatalf("allocation count scaled with field bytes: 64KiB=%.0f 1MiB=%.0f", smallAllocs, largeAllocs)
	}
}

func TestRound6ShadowPlanCompactsCallerControlledStructure(t *testing.T) {
	const entries = 512
	longKey := strings.Repeat("k", 2048)
	longSemantic := strings.Repeat("v", 2048)
	var bodyBuilder strings.Builder
	bodyBuilder.Grow(6 << 20)
	bodyBuilder.WriteString(`{"metadata":{"padding":"`)
	bodyBuilder.WriteString(strings.Repeat("m", 1<<20))
	bodyBuilder.WriteString(`"},"items":[`)
	for index := 0; index < entries; index++ {
		if index > 0 {
			bodyBuilder.WriteByte(',')
		}
		fmt.Fprintf(
			&bodyBuilder,
			`{"%s%04d":0,"role":"%s","type":"%s","mimetype":"%s"}`,
			longKey,
			index,
			longSemantic,
			longSemantic,
			longSemantic,
		)
	}
	bodyBuilder.WriteString(`]}`)
	body := []byte(bodyBuilder.String())

	limits, err := (Limits{}).normalized()
	if err != nil {
		t.Fatal(err)
	}
	planner := shadowPlanner{
		body:       body,
		limits:     limits,
		shadow:     make([]byte, 0, 64<<10),
		spans:      make([]plannedText, 0, 8),
		trustRoles: true,
	}
	if _, err := planner.parseValue(planContext{role: RoleUser, provenance: ProvenanceContent, atRoot: true}, "", 0); err != nil {
		t.Fatal(err)
	}
	planner.skipWhitespace()
	if planner.position != len(body) {
		t.Fatalf("planner consumed %d/%d bytes", planner.position, len(body))
	}
	if len(planner.spans) != 0 {
		t.Fatalf("metadata/semantic-only fixture retained %d text spans", len(planner.spans))
	}
	if len(planner.shadow) > 128<<10 {
		t.Fatalf("shadow retained %d bytes for %d-byte caller structure", len(planner.shadow), len(body))
	}

	result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, Limits{}, discardChunkSink{})
	if err != nil || !result.IsComplete() || result.LogicalTextParts != 0 {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestRound6CompactSpanMarkerRoundTrip(t *testing.T) {
	for _, id := range []uint64{1, 35, 36, 4096, 1 << 63, ^uint64(0)} {
		marker := spanMarker(id)
		got, ok := markerID(marker)
		if !ok || got != id {
			t.Fatalf("markerID(%q)=%d,%t want=%d,true", marker, got, ok, id)
		}
		if embedded, embeddedOK := embeddedMarkerID("https://opaque.invalid/" + marker); !embeddedOK || embedded != id {
			t.Fatalf("embeddedMarkerID(%q)=%d,%t want=%d,true", marker, embedded, embeddedOK, id)
		}
	}
}

func FuzzRound6JSONStringChunkDecoderMatchesStdlib(f *testing.F) {
	for _, seed := range []struct {
		value     string
		chunkSize uint8
	}{
		{value: "plain text", chunkSize: 1},
		{value: "escaped\nquote \" and slash \\", chunkSize: 2},
		{value: "emoji 😀 and 中文", chunkSize: 3},
		{value: "combining e\u0301 and fullwidth Ａ", chunkSize: 7},
	} {
		f.Add(seed.value, seed.chunkSize)
	}
	f.Fuzz(func(t *testing.T, value string, rawChunkSize uint8) {
		if len(value) > 4<<10 {
			t.Skip()
		}
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var want string
		if err := json.Unmarshal(raw, &want); err != nil {
			t.Fatal(err)
		}
		chunkSize := int(rawChunkSize%64) + 1
		decoded := make([]byte, 0, len(want))
		finals := 0
		if err := decodeJSONStringChunks(raw, chunkSize, func(chunk []byte, final bool) error {
			decoded = append(decoded, chunk...)
			if final {
				finals++
			}
			return nil
		}); err != nil {
			t.Fatalf("chunkSize=%d decode error: %v", chunkSize, err)
		}
		if finals != 1 {
			t.Fatalf("chunkSize=%d final markers=%d, want exactly one", chunkSize, finals)
		}
		if string(decoded) != want {
			t.Fatalf("chunkSize=%d decoded=%q want=%q", chunkSize, decoded, want)
		}
	})
}

func BenchmarkRound6ScanLongJSON(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{name: "64KiB", size: 64 << 10},
		{name: "270KiB", size: 270 << 10},
		{name: "1MiB", size: 1 << 20},
		{name: "4MiB", size: 4 << 20},
		{name: "Near8MiB", size: HardMaxTotalTextBytes - 4096},
	}
	for _, fixture := range []struct {
		name string
		body func(int) []byte
	}{
		{name: "Text", body: round6LongTextBenchmarkBody},
		{name: "KeyRich", body: round6KeyRichBenchmarkBody},
		{name: "SemanticRich", body: round6SemanticRichBenchmarkBody},
	} {
		for _, size := range sizes {
			body := fixture.body(size.size)
			b.Run(fixture.name+"/"+size.name, func(b *testing.B) {
				benchmarkRound6ScanBody(b, body)
			})
		}
	}
}

func benchmarkRound6ScanBody(b *testing.B, body []byte) {
	b.Helper()
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		result, scanErr := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, Limits{}, discardChunkSink{})
		if scanErr != nil || !result.IsComplete() {
			b.Fatalf("result=%#v err=%v", result, scanErr)
		}
	}
}

func round6LongTextBenchmarkBody(size int) []byte {
	body, err := json.Marshal(map[string]string{"input": strings.Repeat("a", size)})
	if err != nil {
		panic(err)
	}
	return body
}

func round6KeyRichBenchmarkBody(target int) []byte {
	keyPrefix := strings.Repeat("k", 1024)
	var body strings.Builder
	body.Grow(target + 2048)
	body.WriteByte('{')
	for index := 0; ; index++ {
		entry := fmt.Sprintf(`"%s%08d":0`, keyPrefix, index)
		separator := 0
		if index > 0 {
			separator = 1
		}
		if body.Len()+separator+len(entry)+1 > target {
			break
		}
		if separator != 0 {
			body.WriteByte(',')
		}
		body.WriteString(entry)
	}
	body.WriteByte('}')
	return []byte(body.String())
}

func round6SemanticRichBenchmarkBody(target int) []byte {
	semantic := strings.Repeat("v", 4096)
	entry := fmt.Sprintf(`{"role":"%s","type":"%s","mimetype":"%s"}`, semantic, semantic, semantic)
	var body strings.Builder
	body.Grow(target + len(entry))
	body.WriteString(`{"items":[`)
	for index := 0; ; index++ {
		separator := 0
		if index > 0 {
			separator = 1
		}
		if body.Len()+separator+len(entry)+2 > target {
			break
		}
		if separator != 0 {
			body.WriteByte(',')
		}
		body.WriteString(entry)
	}
	body.WriteString(`]}`)
	return []byte(body.String())
}
