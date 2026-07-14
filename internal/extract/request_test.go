package extract

import (
	"bytes"
	"fmt"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestExtractRequestJSONSeparatesMediaFromTextBudget(t *testing.T) {
	prompt := "Summarize today's football scores."
	body := []byte(`{"input":[{"type":"input_image","image_url":"data:image/png;base64,` + strings.Repeat("A", 128<<10) + `"},{"type":"input_text","text":"` + prompt + `"}]}`)

	result, err := ExtractRequest(body, http.Header{"Content-Type": []string{"application/json; charset=utf-8"}}, Limits{
		MaxScanBytes: 128,
		MaxRawBytes:  len(body),
	})
	if err != nil {
		t.Fatalf("ExtractRequest() error = %v", err)
	}
	if !result.IsComplete() {
		t.Fatalf("completeness = %q reasons=%v", result.Completeness, result.IncompleteReasons)
	}
	if !result.OpaqueMedia || !containsOpaqueKind(result.OpaqueMediaKinds, OpaqueMediaBase64Image) {
		t.Fatalf("opaque media = %t kinds=%v", result.OpaqueMedia, result.OpaqueMediaKinds)
	}
	if !containsPart(result.Parts, prompt) {
		t.Fatalf("parts = %#v, want prompt", result.Parts)
	}
	if result.TextBytesScanned > 128 {
		t.Fatalf("TextBytesScanned = %d, want <= 128", result.TextBytesScanned)
	}
	if result.RawBytesObserved != int64(len(body)) {
		t.Fatalf("RawBytesObserved = %d, want %d", result.RawBytesObserved, len(body))
	}
}

func TestExtractRequestJSONIncompleteReasons(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		limits Limits
		reason IncompleteReason
	}{
		{name: "parse error", body: `{"messages":[`, reason: IncompleteParseError},
		{name: "empty JSON", body: ``, reason: IncompleteParseError},
		{name: "JSON scalar", body: `"unsupported request shape"`, reason: IncompleteParseError},
		{name: "text budget", body: `{"input":"` + strings.Repeat("x", 128) + `"}`, limits: Limits{MaxScanBytes: 32}, reason: IncompleteScanByteLimit},
		{name: "depth", body: `{"a":{"b":{"c":"text"}}}`, limits: Limits{MaxJSONDepth: 2}, reason: IncompleteJSONDepthLimit},
		{name: "parts", body: `{"input":["one","two","three"]}`, limits: Limits{MaxTextParts: 2}, reason: IncompleteTextPartLimit},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result, _ := ExtractRequest([]byte(testCase.body), http.Header{"Content-Type": []string{"application/json"}}, testCase.limits)
			if result.IsComplete() || !result.HasIncompleteReason(testCase.reason) {
				t.Fatalf("result = %#v, want incomplete reason %q", result, testCase.reason)
			}
		})
	}
}

func TestExtractRequestJSONMultimodalFieldMatrix(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantText  []string
		forbidden []string
		wantKind  OpaqueMediaKind
	}{
		{
			name:     "image generation prompts",
			body:     `{"model":"image-model","prompt":"draw a safe stadium","negative_prompt":"exclude unsafe text"}`,
			wantText: []string{"draw a safe stadium", "exclude unsafe text"},
		},
		{
			name:      "Responses file id",
			body:      `{"input":[{"type":"input_file","file_id":"file-private-canary"},{"type":"input_text","text":"summarize the attachment"}]}`,
			wantText:  []string{"summarize the attachment"},
			forbidden: []string{"file-private-canary"},
			wantKind:  OpaqueMediaDocument,
		},
		{
			name:      "Gemini file URI",
			body:      `{"contents":[{"parts":[{"fileData":{"mimeType":"application/pdf","fileUri":"gs://private-bucket/canary.pdf"}},{"text":"review the report"}]}]}`,
			wantText:  []string{"review the report"},
			forbidden: []string{"private-bucket", "canary.pdf"},
			wantKind:  OpaqueMediaDocument,
		},
		{
			name:      "audio base64",
			body:      `{"messages":[{"role":"user","content":[{"type":"input_audio","input_audio":{"data":"UklGRlBSSVZBVEVDQU5BUlk=","format":"wav"}},{"type":"text","text":"transcribe defensively"}]}]}`,
			wantText:  []string{"transcribe defensively"},
			forbidden: []string{"UklGRlBSSVZBVEVDQU5BUlk="},
			wantKind:  OpaqueMediaAudio,
		},
		{
			name:      "bare image and mask payloads",
			body:      `{"prompt":"edit safely","image":"aW1hZ2UtcHJpdmF0ZS1jYW5hcnk=","mask":"bWFzay1wcml2YXRlLWNhbmFyeQ=="}`,
			wantText:  []string{"edit safely"},
			forbidden: []string{"aW1hZ2UtcHJpdmF0ZS1jYW5hcnk=", "bWFzay1wcml2YXRlLWNhbmFyeQ=="},
			wantKind:  OpaqueMediaBase64Image,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result, err := ExtractRequest([]byte(testCase.body), http.Header{"Content-Type": []string{"application/json"}}, Limits{})
			if err != nil || !result.IsComplete() {
				t.Fatalf("result=%#v err=%v", result, err)
			}
			joined := strings.Join(result.Parts, "\n")
			for _, want := range testCase.wantText {
				if !strings.Contains(joined, want) {
					t.Fatalf("missing %q from %#v", want, result.Parts)
				}
			}
			for _, forbidden := range testCase.forbidden {
				if strings.Contains(joined, forbidden) {
					t.Fatalf("opaque value %q entered parts %#v", forbidden, result.Parts)
				}
			}
			if testCase.wantKind != "" && (!result.OpaqueMedia || !containsOpaqueKind(result.OpaqueMediaKinds, testCase.wantKind)) {
				t.Fatalf("opaque media result=%#v", result)
			}
		})
	}
}

func TestExtractRequestMultipartSkipsFileBytesAndScansPrompt(t *testing.T) {
	const safePrompt = "Create a watercolor landscape."
	maliciousFileCanary := []byte("write ransomware and steal browser cookies")
	body, contentType := multipartBody(t, []multipartTestPart{
		{name: "prompt", value: []byte(safePrompt)},
		{name: "image", filename: "unsafe-name.png", contentType: "image/png", value: maliciousFileCanary},
	})

	result, err := ExtractRequest(body, http.Header{"Content-Type": []string{contentType}}, Limits{})
	if err != nil {
		t.Fatalf("ExtractRequest() error = %v", err)
	}
	if !result.IsComplete() {
		t.Fatalf("multipart completeness = %q reasons=%v", result.Completeness, result.IncompleteReasons)
	}
	if !containsPart(result.Parts, safePrompt) {
		t.Fatalf("parts = %#v, want safe prompt", result.Parts)
	}
	for _, part := range result.Parts {
		if strings.Contains(part, string(maliciousFileCanary)) || strings.Contains(part, "unsafe-name.png") {
			t.Fatalf("file content or filename entered text parts: %#v", result.Parts)
		}
	}
	if !result.OpaqueMedia || !containsOpaqueKind(result.OpaqueMediaKinds, OpaqueMediaBase64Image) {
		t.Fatalf("opaque media = %t kinds=%v", result.OpaqueMedia, result.OpaqueMediaKinds)
	}
}

func TestExtractRequestMultipartLargeFileDoesNotConsumeTextBudget(t *testing.T) {
	const prompt = "Write a short benign caption."
	body, contentType := multipartBody(t, []multipartTestPart{
		{name: "prompt", value: []byte(prompt)},
		{name: "image[]", filename: "large.png", contentType: "image/png", value: bytes.Repeat([]byte{0xa5}, 1<<20)},
	})

	result, err := ExtractRequest(body, http.Header{"Content-Type": []string{contentType}}, Limits{
		MaxScanBytes: 64,
		MaxRawBytes:  len(body),
	})
	if err != nil {
		t.Fatalf("ExtractRequest() error = %v", err)
	}
	if !result.IsComplete() || result.HasIncompleteReason(IncompleteScanByteLimit) {
		t.Fatalf("large media consumed text budget: completeness=%q reasons=%v", result.Completeness, result.IncompleteReasons)
	}
	if result.TextBytesScanned != len(prompt) {
		t.Fatalf("TextBytesScanned = %d, want %d", result.TextBytesScanned, len(prompt))
	}
	if result.RawBytesObserved <= int64(1<<20) {
		t.Fatalf("RawBytesObserved = %d, want multipart body over 1 MiB", result.RawBytesObserved)
	}
}

func TestExtractRequestMultipartMalformedAndUnsupportedAreIncomplete(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        []byte
		reason      IncompleteReason
	}{
		{name: "missing boundary", contentType: "multipart/form-data", body: []byte("not-a-form"), reason: IncompleteMultipartParseError},
		{name: "unsupported", contentType: "application/octet-stream", body: []byte("opaque"), reason: IncompleteUnsupportedMediaType},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result, _ := ExtractRequest(testCase.body, http.Header{"Content-Type": []string{testCase.contentType}}, Limits{})
			if result.IsComplete() || !result.HasIncompleteReason(testCase.reason) {
				t.Fatalf("result = %#v, want reason %q", result, testCase.reason)
			}
		})
	}
}

func TestExtractRequestCPATransformedJSONWithMultipartHeader(t *testing.T) {
	const prompt = "Inspect this transformed image request."
	headers := http.Header{"Content-Type": []string{`multipart/form-data; boundary="stale-cpa-boundary"`}}

	result, err := ExtractRequest([]byte(`{"prompt":"`+prompt+`","image":"data:image/png;base64,QUFB"}`), headers, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsComplete() || !containsPart(result.Parts, prompt) || !result.OpaqueMedia {
		t.Fatalf("CPA transformed JSON result = %#v", result)
	}

	malformed, err := ExtractRequest([]byte(`{"prompt":"unterminated"`), headers, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if malformed.IsComplete() || !malformed.HasIncompleteReason(IncompleteMultipartParseError) {
		t.Fatalf("malformed multipart-declared JSON became complete: %#v", malformed)
	}
}

func TestExtractRequestHeaderAmbiguityAndEncodingAreIncomplete(t *testing.T) {
	body := []byte(`{"input":"ordinary request"}`)
	tests := []struct {
		name    string
		headers http.Header
		reason  IncompleteReason
	}{
		{
			name: "duplicate content type",
			headers: http.Header{"Content-Type": []string{
				"application/json", "application/json",
			}},
			reason: IncompleteUnsupportedMediaType,
		},
		{
			name:    "gzip is not decompressed",
			headers: http.Header{"Content-Type": []string{"application/json"}, "Content-Encoding": []string{"gzip"}},
			reason:  IncompleteUnsupportedContentEncoding,
		},
		{
			name:    "brotli is not decompressed",
			headers: http.Header{"content-type": []string{"application/json"}, "content-encoding": []string{"br"}},
			reason:  IncompleteUnsupportedContentEncoding,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result, err := ExtractRequest(body, testCase.headers, Limits{})
			if err != nil {
				t.Fatal(err)
			}
			if result.IsComplete() || !result.HasIncompleteReason(testCase.reason) {
				t.Fatalf("result = %#v, want %q", result, testCase.reason)
			}
			if result.ParseError != "" {
				t.Fatalf("transport failure leaked parser detail: %q", result.ParseError)
			}
		})
	}

	identity, err := ExtractRequest(body, http.Header{
		"content-type":     []string{"application/problem+json"},
		"content-encoding": []string{"identity"},
	}, Limits{})
	if err != nil || !identity.IsComplete() || !containsPart(identity.Parts, "ordinary request") {
		t.Fatalf("identity/+json request = %#v err=%v", identity, err)
	}
}

func TestExtractRequestJSONCharsetAndUTF8Validation(t *testing.T) {
	body := []byte(`{"input":"ordinary request"}`)
	for _, contentType := range []string{
		"application/json",
		"application/json; charset=utf-8",
		"application/json; charset=UTF-8",
		`application/problem+json; charset="utf-8"`,
		`application/json; charset=""`,
	} {
		result, err := ExtractRequest(body, http.Header{"Content-Type": []string{contentType}}, Limits{})
		if err != nil || !result.IsComplete() {
			t.Fatalf("Content-Type %q result=%#v err=%v", contentType, result, err)
		}
	}

	latin1, err := ExtractRequest(body, http.Header{"Content-Type": []string{"application/json; charset=iso-8859-1"}}, Limits{})
	if err != nil || latin1.IsComplete() || !latin1.HasIncompleteReason(IncompleteUnsupportedMediaType) {
		t.Fatalf("non-UTF-8 charset result=%#v err=%v", latin1, err)
	}

	invalidUTF8Body := []byte{'{', '"', 'i', 'n', 'p', 'u', 't', '"', ':', '"', 0xff, '"', '}'}
	invalid, err := ExtractRequest(invalidUTF8Body, http.Header{"Content-Type": []string{"application/json"}}, Limits{})
	if err != nil || invalid.IsComplete() || !invalid.HasIncompleteReason(IncompleteParseError) || invalid.ParseError != ErrInvalidJSON.Error() {
		t.Fatalf("invalid UTF-8 result=%#v err=%v", invalid, err)
	}
}

func TestExtractRequestJSONResourceReasons(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		limits Limits
		reason IncompleteReason
	}{
		{name: "raw body", body: `{"input":"ordinary"}`, limits: Limits{MaxRawBytes: 8}, reason: IncompleteRawBodyLimit},
		{name: "tokens", body: `{"input":["one","two"]}`, limits: Limits{MaxJSONTokens: 3}, reason: IncompleteJSONTokenLimit},
		{name: "nodes", body: `{"input":["one","two"]}`, limits: Limits{MaxJSONNodes: 2}, reason: IncompleteJSONNodeLimit},
		{name: "single text", body: `{"input":"0123456789"}`, limits: Limits{MaxTextPartBytes: 5}, reason: IncompleteTextPartByteLimit},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result, err := ExtractRequest([]byte(testCase.body), http.Header{"Content-Type": []string{"application/json"}}, testCase.limits)
			if err != nil {
				t.Fatal(err)
			}
			if result.IsComplete() || !result.HasIncompleteReason(testCase.reason) {
				t.Fatalf("result = %#v, want %q", result, testCase.reason)
			}
		})
	}
}

func TestIncompleteReasonsAreBoundedDeduplicatedAndStable(t *testing.T) {
	var result Result
	for index := len(incompleteReasonOrder) - 1; index >= 0; index-- {
		result.addIncomplete(incompleteReasonOrder[index])
		result.addIncomplete(incompleteReasonOrder[index])
	}
	if !reflect.DeepEqual(result.IncompleteReasons, incompleteReasonOrder[:]) {
		t.Fatalf("reasons = %v, want stable order %v", result.IncompleteReasons, incompleteReasonOrder)
	}
	if len(result.IncompleteReasons) != len(incompleteReasonOrder) {
		t.Fatalf("reason count = %d", len(result.IncompleteReasons))
	}
}

func TestExtractRequestMultipartResourceLimits(t *testing.T) {
	t.Run("boundary", func(t *testing.T) {
		boundary := strings.Repeat("b", 32)
		result, err := ExtractRequest([]byte("irrelevant"), http.Header{
			"Content-Type": []string{`multipart/form-data; boundary="` + boundary + `"`},
		}, Limits{MaxMultipartBoundaryBytes: 16})
		if err != nil || !result.HasIncompleteReason(IncompleteMultipartBoundaryLimit) {
			t.Fatalf("result=%#v err=%v", result, err)
		}
	})

	t.Run("parts", func(t *testing.T) {
		body, contentType := multipartBody(t, []multipartTestPart{
			{name: "prompt", value: []byte("one")},
			{name: "prompt", value: []byte("two")},
		})
		result, err := ExtractRequest(body, http.Header{"Content-Type": []string{contentType}}, Limits{MaxMultipartParts: 1})
		if err != nil || !result.HasIncompleteReason(IncompleteMultipartPartLimit) {
			t.Fatalf("result=%#v err=%v", result, err)
		}
	})

	t.Run("header count", func(t *testing.T) {
		body, contentType := multipartBody(t, []multipartTestPart{{
			name: "prompt", value: []byte("ordinary"), extraHeaders: textproto.MIMEHeader{
				"X-Guard-One": []string{"1"},
			},
		}})
		result, err := ExtractRequest(body, http.Header{"Content-Type": []string{contentType}}, Limits{MaxMultipartHeaders: 1})
		if err != nil || !result.HasIncompleteReason(IncompleteMultipartHeaderLimit) {
			t.Fatalf("result=%#v err=%v", result, err)
		}
	})

	t.Run("header bytes", func(t *testing.T) {
		body, contentType := multipartBody(t, []multipartTestPart{{
			name: "prompt", value: []byte("ordinary"), extraHeaders: textproto.MIMEHeader{
				"X-Guard-Padding": []string{strings.Repeat("h", 128)},
			},
		}})
		result, err := ExtractRequest(body, http.Header{"Content-Type": []string{contentType}}, Limits{MaxMultipartHeaderBytes: 64})
		if err != nil || !result.HasIncompleteReason(IncompleteMultipartHeaderLimit) {
			t.Fatalf("result=%#v err=%v", result, err)
		}
	})

	t.Run("text field", func(t *testing.T) {
		body, contentType := multipartBody(t, []multipartTestPart{{name: "prompt", value: []byte(strings.Repeat("p", 32))}})
		result, err := ExtractRequest(body, http.Header{"Content-Type": []string{contentType}}, Limits{MaxMultipartTextPartBytes: 8})
		if err != nil || !result.HasIncompleteReason(IncompleteMultipartTextLimit) {
			t.Fatalf("result=%#v err=%v", result, err)
		}
	})
}

func TestExtractRequestMultipartJSONFieldsUseSharedBoundedWalk(t *testing.T) {
	body, contentType := multipartBody(t, []multipartTestPart{
		{name: "prompt", value: []byte("ordinary prefix")},
		{name: "messages", value: []byte(`[{"role":"user","content":"inspect the nested instruction"}]`)},
	})
	result, err := ExtractRequest(body, http.Header{"Content-Type": []string{contentType}}, Limits{})
	if err != nil || !result.IsComplete() {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if !containsPart(result.Parts, "ordinary prefix") || !containsPart(result.Parts, "inspect the nested instruction") {
		t.Fatalf("multipart JSON semantics were not extracted: %#v", result.Parts)
	}
	if containsPart(result.Parts, string([]byte(`[{"role":"user","content":"inspect the nested instruction"}]`))) {
		t.Fatalf("raw JSON field was classified instead of semantic text: %#v", result.Parts)
	}

	malformedBody, malformedType := multipartBody(t, []multipartTestPart{{name: "messages", value: []byte(`[{"role":"user"}`)}})
	malformed, err := ExtractRequest(malformedBody, http.Header{"Content-Type": []string{malformedType}}, Limits{})
	if err != nil || malformed.IsComplete() || !malformed.HasIncompleteReason(IncompleteMultipartParseError) {
		t.Fatalf("malformed nested JSON result=%#v err=%v", malformed, err)
	}

	limitedBody, limitedType := multipartBody(t, []multipartTestPart{
		{name: "messages", value: []byte(`[{"content":"one"}]`)},
		{name: "input", value: []byte(`[{"content":"two"}]`)},
	})
	limited, err := ExtractRequest(limitedBody, http.Header{"Content-Type": []string{limitedType}}, Limits{MaxJSONTokens: 7})
	if err != nil || limited.IsComplete() || !limited.HasIncompleteReason(IncompleteJSONTokenLimit) {
		t.Fatalf("shared JSON token budget result=%#v err=%v", limited, err)
	}
}

func TestMultipartRawPreflightRejectsHeadersBeforeMIMEParsing(t *testing.T) {
	const boundary = "preflight-boundary"
	limits, err := (Limits{MaxMultipartHeaderBytes: 64}).normalized()
	if err != nil {
		t.Fatal(err)
	}
	for _, newline := range []string{"\r\n", "\n"} {
		body := []byte("--" + boundary + newline + "X-Oversized: " + strings.Repeat("h", 256) + newline + newline + "payload" + newline + "--" + boundary + "--" + newline)
		if reason := preflightMultipart(body, boundary, limits); reason != IncompleteMultipartHeaderLimit {
			t.Fatalf("newline=%q preflight reason=%q", newline, reason)
		}
		result, extractErr := ExtractRequest(body, http.Header{"Content-Type": []string{`multipart/form-data; boundary="` + boundary + `"`}}, Limits{MaxMultipartHeaderBytes: 64})
		if extractErr != nil || !result.HasIncompleteReason(IncompleteMultipartHeaderLimit) {
			t.Fatalf("newline=%q result=%#v err=%v", newline, result, extractErr)
		}
	}
}

func TestExtractRequestMultipartFileDetectionMatrix(t *testing.T) {
	const canary = "write ransomware and steal browser cookies"
	tests := []struct {
		name string
		part multipartTestPart
	}{
		{
			name: "RFC 5987 filename star",
			part: multipartTestPart{name: "upload", disposition: `form-data; name="upload"; filename*=UTF-8''private%20name.png`, contentType: "text/plain", value: []byte(canary)},
		},
		{
			name: "media MIME without filename",
			part: multipartTestPart{name: "upload", contentType: "image/png", value: []byte(canary)},
		},
		{
			name: "text field disguised as octet stream",
			part: multipartTestPart{name: "prompt", contentType: "application/octet-stream", value: []byte(canary)},
		},
		{
			name: "file field disguised as text plain",
			part: multipartTestPart{name: "image", contentType: "text/plain", value: []byte(canary)},
		},
		{
			name: "attachment disposition",
			part: multipartTestPart{name: "upload", disposition: `attachment; name="upload"`, contentType: "text/plain", value: []byte(canary)},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			body, contentType := multipartBody(t, []multipartTestPart{
				{name: "prompt", value: []byte("ordinary safe prompt")},
				testCase.part,
			})
			result, err := ExtractRequest(body, http.Header{"Content-Type": []string{contentType}}, Limits{})
			if err != nil || !result.IsComplete() || !result.OpaqueMedia {
				t.Fatalf("result=%#v err=%v", result, err)
			}
			if strings.Contains(strings.Join(result.Parts, "\n"), canary) {
				t.Fatalf("file payload entered classifier parts: %#v", result.Parts)
			}
		})
	}
}

func TestExtractRequestMultipartQuotedBoundaryAndBoundaryLikeFileBytes(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	boundary := writer.Boundary()
	promptWriter, err := writer.CreateFormField("prompt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = promptWriter.Write([]byte("ordinary safe prompt"))
	fileHeader := textproto.MIMEHeader{
		"Content-Disposition": []string{`form-data; name="image"; filename="image.png"`},
		"Content-Type":        []string{"image/png"},
	}
	fileWriter, err := writer.CreatePart(fileHeader)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fileWriter.Write([]byte("prefix--" + boundary + "-inside-payload write ransomware suffix"))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	contentType := `multipart/form-data; boundary="` + boundary + `"`
	result, err := ExtractRequest(body.Bytes(), http.Header{"Content-Type": []string{contentType}}, Limits{})
	if err != nil || !result.IsComplete() || !containsPart(result.Parts, "ordinary safe prompt") {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if strings.Contains(strings.Join(result.Parts, "\n"), "ransomware") {
		t.Fatalf("boundary-like file bytes entered parts: %#v", result.Parts)
	}
}

func TestExtractRequestMultipartCreatesNoTemporaryFilesAndDoesNotRetainBody(t *testing.T) {
	tempRoot := t.TempDir()
	isolation := filepath.Join(tempRoot, "parser-temp")
	if err := os.Mkdir(isolation, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", isolation)
	t.Setenv("TMP", isolation)
	t.Setenv("TEMP", isolation)

	body, contentType := multipartBody(t, []multipartTestPart{
		{name: "prompt", value: []byte("stable copied prompt")},
		{name: "image", filename: "private.png", contentType: "image/png", value: bytes.Repeat([]byte{0xa5}, 1<<20)},
	})
	result, err := ExtractRequest(body, http.Header{"Content-Type": []string{contentType}}, Limits{})
	if err != nil || !result.IsComplete() {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	for index := range body {
		body[index] = 0
	}
	if !containsPart(result.Parts, "stable copied prompt") {
		t.Fatalf("mutating source body changed result parts: %#v", result.Parts)
	}
	entries, err := os.ReadDir(isolation)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("multipart parser created temporary files: %v", entries)
	}
}

func TestExtractRequestMultipartMediaAllocationsDoNotScaleWithPayload(t *testing.T) {
	build := func(fileBytes int) ([]byte, http.Header) {
		body, contentType := multipartBody(t, []multipartTestPart{
			{name: "prompt", value: []byte("ordinary safe prompt")},
			{name: "image", filename: "image.png", contentType: "image/png", value: bytes.Repeat([]byte{0xa5}, fileBytes)},
		})
		return body, http.Header{"Content-Type": []string{contentType}}
	}
	smallBody, smallHeaders := build(1 << 20)
	largeBody, largeHeaders := build(8 << 20)
	measure := func(body []byte, headers http.Header) float64 {
		return testing.AllocsPerRun(3, func() {
			result, err := ExtractRequest(body, headers, Limits{})
			if err != nil || !result.IsComplete() {
				panic(fmt.Sprintf("result=%#v err=%v", result, err))
			}
		})
	}
	smallAllocs := measure(smallBody, smallHeaders)
	largeAllocs := measure(largeBody, largeHeaders)
	if largeAllocs > smallAllocs+4 {
		t.Fatalf("media allocations scaled with payload: 1MiB=%0.1f 8MiB=%0.1f", smallAllocs, largeAllocs)
	}
}

func TestExtractRequestMultipartConcurrent(t *testing.T) {
	body, contentType := multipartBody(t, []multipartTestPart{
		{name: "prompt", value: []byte("ordinary concurrent prompt")},
		{name: "image", filename: "image.png", contentType: "image/png", value: bytes.Repeat([]byte{0xa5}, 1<<20)},
	})
	headers := http.Header{"Content-Type": []string{contentType}}
	const workers = 16
	var wait sync.WaitGroup
	errors := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := ExtractRequest(body, headers, Limits{})
			if err != nil {
				errors <- err
				return
			}
			if !result.IsComplete() || !containsPart(result.Parts, "ordinary concurrent prompt") {
				errors <- fmt.Errorf("unexpected result: %#v", result)
			}
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
}

type multipartTestPart struct {
	name         string
	filename     string
	disposition  string
	contentType  string
	extraHeaders textproto.MIMEHeader
	value        []byte
}

func multipartBody(t testing.TB, parts []multipartTestPart) ([]byte, string) {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for _, part := range parts {
		var partWriter interface{ Write([]byte) (int, error) }
		var err error
		if part.filename == "" && part.disposition == "" && part.contentType == "" && len(part.extraHeaders) == 0 {
			partWriter, err = writer.CreateFormField(part.name)
		} else {
			header := make(textproto.MIMEHeader)
			disposition := part.disposition
			if disposition == "" {
				disposition = `form-data; name="` + part.name + `"`
				if part.filename != "" {
					disposition += `; filename="` + part.filename + `"`
				}
			}
			header.Set("Content-Disposition", disposition)
			if part.contentType != "" {
				header.Set("Content-Type", part.contentType)
			}
			for key, values := range part.extraHeaders {
				for _, value := range values {
					header.Add(key, value)
				}
			}
			partWriter, err = writer.CreatePart(header)
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := partWriter.Write(part.value); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return body.Bytes(), writer.FormDataContentType()
}

func BenchmarkExtractRequestMultipart1MiB(b *testing.B) {
	benchmarkExtractRequestMultipart(b, 1<<20)
}

func BenchmarkExtractRequestMultipart8MiB(b *testing.B) {
	benchmarkExtractRequestMultipart(b, 8<<20)
}

func benchmarkExtractRequestMultipart(b *testing.B, fileBytes int) {
	body, contentType := multipartBody(b, []multipartTestPart{
		{name: "prompt", value: []byte(strings.Repeat("p", 1024))},
		{name: "image", filename: "image.png", contentType: "image/png", value: bytes.Repeat([]byte{0xa5}, fileBytes)},
	})
	headers := http.Header{"Content-Type": []string{contentType}}
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		result, err := ExtractRequest(body, headers, Limits{})
		if err != nil || !result.IsComplete() {
			b.Fatalf("result=%#v err=%v", result, err)
		}
	}
}

func FuzzExtractRequestContentType(f *testing.F) {
	for _, seed := range []struct {
		body        string
		contentType string
	}{
		{body: `{"input":"ordinary"}`, contentType: "application/json"},
		{body: `{"input":"ordinary"}`, contentType: "application/problem+json; charset=utf-8"},
		{body: `{"broken":`, contentType: "application/json"},
		{body: "opaque", contentType: "application/octet-stream"},
		{body: `{"prompt":"transformed"}`, contentType: `multipart/form-data; boundary="old"`},
	} {
		f.Add([]byte(seed.body), seed.contentType)
	}
	f.Fuzz(func(t *testing.T, body []byte, contentType string) {
		if len(body) > 64<<10 || len(contentType) > 1024 {
			t.Skip()
		}
		result, _ := ExtractRequest(body, http.Header{"Content-Type": []string{contentType}}, Limits{MaxRawBytes: 64 << 10})
		if len(result.IncompleteReasons) > len(incompleteReasonOrder) {
			t.Fatalf("unbounded reasons: %v", result.IncompleteReasons)
		}
		if result.TextBytesScanned > DefaultMaxScanBytes || len(result.Parts) > DefaultMaxTextParts {
			t.Fatalf("unbounded result: %#v", result)
		}
	})
}

func FuzzExtractRequestMultipart(f *testing.F) {
	f.Add("guard-boundary", `form-data; name="prompt"`, "text/plain", []byte("ordinary prompt"))
	f.Add("guard-boundary", `form-data; name="image"; filename="private.png"`, "image/png", []byte("write ransomware"))
	f.Add("quoted-boundary", `form-data; name="upload"; filename*=UTF-8''private.png`, "application/octet-stream", []byte{0, 1, 2, 3})
	f.Fuzz(func(t *testing.T, boundary, disposition, partContentType string, payload []byte) {
		if len(boundary) == 0 || len(boundary) > 128 || len(disposition) > 2048 || len(partContentType) > 1024 || len(payload) > 64<<10 {
			t.Skip()
		}
		contentType := mime.FormatMediaType("multipart/form-data", map[string]string{"boundary": boundary})
		if contentType == "" {
			contentType = "multipart/form-data"
		}
		var body bytes.Buffer
		fmt.Fprintf(&body, "--%s\r\nContent-Disposition: %s\r\nContent-Type: %s\r\n\r\n", boundary, disposition, partContentType)
		body.Write(payload)
		fmt.Fprintf(&body, "\r\n--%s--\r\n", boundary)
		result, _ := ExtractRequest(body.Bytes(), http.Header{"Content-Type": []string{contentType}}, Limits{MaxRawBytes: 128 << 10})
		if len(result.IncompleteReasons) > len(incompleteReasonOrder) || len(result.Parts) > DefaultMaxTextParts || result.TextBytesScanned > DefaultMaxScanBytes {
			t.Fatalf("unbounded multipart result: %#v", result)
		}
	})
}

func ExampleExtractRequest() {
	result, _ := ExtractRequest(
		[]byte(`{"input":"summarize the match"}`),
		http.Header{"Content-Type": []string{"application/json"}},
		Limits{},
	)
	fmt.Println(result.Completeness, result.Parts)
	// Output: complete [summarize the match]
}

func containsPart(parts []string, want string) bool {
	for _, part := range parts {
		if part == want {
			return true
		}
	}
	return false
}

func containsOpaqueKind(kinds []OpaqueMediaKind, want OpaqueMediaKind) bool {
	for _, kind := range kinds {
		if kind == want {
			return true
		}
	}
	return false
}
