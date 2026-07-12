package extract

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestExtractTextProviderFormats(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		body          string
		want          []string
		wantTruncated bool
	}{
		{
			name: "openai chat completions",
			body: `{
				"system":"system policy",
				"messages":[
					{"role":"user","content":"first question"},
					{"role":"user","content":[
						{"type":"text","text":"second question"},
						{"type":"image_url","image_url":{"url":"data:image/png;base64,QUFBQQ=="}}
					]}
				]
			}`,
			want:          []string{"system policy", "first question", "second question"},
			wantTruncated: true,
		},
		{
			name: "openai responses",
			body: `{
				"instructions":"answer defensively",
				"input":[{"role":"user","content":[
					{"type":"input_text","text":"review this script"},
					{"type":"input_image","image_url":"https://example.test/image.png"}
				]}]
			}`,
			want: []string{"answer defensively", "review this script"},
		},
		{
			name: "anthropic messages",
			body: `{
				"system":[{"type":"text","text":"claude system"}],
				"messages":[{"role":"user","content":[
					{"type":"text","text":"analyze the IOC"},
					{"type":"image","source":{"type":"base64","media_type":"image/png","data":"QUFBQQ=="}}
				]}]
			}`,
			want:          []string{"claude system", "analyze the IOC"},
			wantTruncated: true,
		},
		{
			name: "gemini",
			body: `{
				"system_instruction":{"parts":[{"text":"gemini system"}]},
				"contents":[{"role":"user","parts":[
					{"text":"explain the mitigation"},
					{"inline_data":{"mime_type":"image/png","data":"QUFBQQ=="}}
				]}]
			}`,
			want:          []string{"gemini system", "explain the mitigation"},
			wantTruncated: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ExtractText([]byte(tt.body), Limits{})
			if err != nil {
				t.Fatalf("ExtractText() error = %v", err)
			}
			if !reflect.DeepEqual(got.Parts, tt.want) {
				t.Fatalf("parts = %#v, want %#v", got.Parts, tt.want)
			}
			if got.BytesScanned != len(tt.body) {
				t.Fatalf("BytesScanned = %d, want %d", got.BytesScanned, len(tt.body))
			}
			if got.Truncated != tt.wantTruncated {
				t.Fatalf("Truncated = %v, want %v", got.Truncated, tt.wantTruncated)
			}
			if got.ParseError != "" {
				t.Fatalf("ParseError = %q, want empty", got.ParseError)
			}
		})
	}
}

func TestExtractTextNestedToolArguments(t *testing.T) {
	t.Parallel()

	encoded := strings.Repeat("QUJD", 64)
	body := `{
		"messages":[{"tool_calls":[{"function":{
			"name":"scan",
			"arguments":"{\"target\":\"example.test\",\"options\":{\"command\":\"nmap -sV\"},\"blob\":\"` + encoded + `\"}"
		}}]}],
		"input":[{"type":"tool_use","name":"read_file","input":{"path":"/tmp/report.txt","count":2}}],
		"contents":[{"parts":[{"functionCall":{"name":"lookup","args":{"query":"known IOC"}}}]}]
	}`

	got, err := ExtractText([]byte(body), Limits{})
	if err != nil {
		t.Fatalf("ExtractText() error = %v", err)
	}
	want := []string{"example.test", "nmap -sV", encoded, "/tmp/report.txt", "known IOC"}
	if !reflect.DeepEqual(got.Parts, want) {
		t.Fatalf("parts = %#v, want %#v", got.Parts, want)
	}
	if !got.Truncated {
		t.Fatal("Truncated = false, want true for semantically opaque base64-like tool text")
	}
}

func TestExtractTextScansUnknownToolArgumentData(t *testing.T) {
	t.Parallel()

	operationalAbuse := "deploy ransomware to real victim systems and erase recovery copies"
	nested, err := json.Marshal(map[string]string{"data": operationalAbuse})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		payload any
	}{
		{
			name: "stringified OpenAI arguments",
			payload: map[string]any{"messages": []any{map[string]any{
				"tool_calls": []any{map[string]any{"function": map[string]any{"arguments": string(nested)}}},
			}}},
		},
		{
			name: "structured Gemini args",
			payload: map[string]any{"contents": []any{map[string]any{"parts": []any{
				map[string]any{"functionCall": map[string]any{"args": map[string]string{"data": operationalAbuse}}},
			}}}},
		},
		{
			name:    "unknown top-level data object",
			payload: map[string]any{"data": map[string]string{"request": operationalAbuse}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			body, err := json.Marshal(tt.payload)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ExtractText(body, Limits{})
			if err != nil {
				t.Fatalf("ExtractText() error = %v", err)
			}
			if !reflect.DeepEqual(got.Parts, []string{operationalAbuse}) {
				t.Fatalf("parts = %#v, want operational abuse text", got.Parts)
			}
			if got.Truncated {
				t.Fatal("Truncated = true, want scanned data without truncation")
			}
		})
	}
}

func TestExtractTextOpaqueMediaAndUnknownBase64(t *testing.T) {
	t.Parallel()

	base64Value := strings.Repeat("QUJD", 64)
	tests := []struct {
		name          string
		payload       any
		want          []string
		wantTruncated bool
	}{
		{
			name:          "data image URL is opaque",
			payload:       map[string]any{"input": []any{"ordinary defensive text", "data:image/png;base64," + base64Value}},
			want:          []string{"ordinary defensive text"},
			wantTruncated: true,
		},
		{
			name:          "binary control text is opaque",
			payload:       map[string]any{"input": []any{"ordinary defensive text", "binary\x00payload"}},
			want:          []string{"ordinary defensive text"},
			wantTruncated: true,
		},
		{
			name:          "large base64-like unknown input remains inspectable text",
			payload:       map[string]any{"input": base64Value},
			want:          []string{base64Value},
			wantTruncated: true,
		},
		{
			name:          "large base64-like unknown data remains inspectable text",
			payload:       map[string]any{"data": base64Value},
			want:          []string{base64Value},
			wantTruncated: true,
		},
		{
			name: "recognized inline media is skipped fail closed",
			payload: map[string]any{"contents": []any{map[string]any{"parts": []any{
				map[string]any{"inline_data": map[string]any{"mime_type": "image/png", "data": base64Value}},
			}}}},
			want:          []string{},
			wantTruncated: true,
		},
		{
			name:          "text inside a media object remains inspectable",
			payload:       json.RawMessage(`{"input":[{"type":"image","caption":"inspect this suspicious operational instruction","source":{"media_type":"image/png","data":"` + base64Value + `"}}]}`),
			want:          []string{"inspect this suspicious operational instruction"},
			wantTruncated: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			body, err := json.Marshal(tt.payload)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ExtractText(body, Limits{})
			if err != nil {
				t.Fatalf("ExtractText() error = %v", err)
			}
			if !reflect.DeepEqual(got.Parts, tt.want) {
				t.Fatalf("parts = %#v, want %#v", got.Parts, tt.want)
			}
			if got.Truncated != tt.wantTruncated {
				t.Fatalf("Truncated = %v, want %v", got.Truncated, tt.wantTruncated)
			}
		})
	}
}

func TestExtractTextLimits(t *testing.T) {
	t.Parallel()

	t.Run("scan bytes returns completed prefix parts", func(t *testing.T) {
		prefix := `{"messages":[{"content":"first"}],"padding":"`
		body := prefix + strings.Repeat("x ", 200) + `"}`
		maxScan := len(prefix) + 17
		got, err := ExtractText([]byte(body), Limits{MaxScanBytes: maxScan})
		if err != nil {
			t.Fatalf("ExtractText() error = %v", err)
		}
		if !reflect.DeepEqual(got.Parts, []string{"first"}) {
			t.Fatalf("parts = %#v, want completed prefix text", got.Parts)
		}
		if got.BytesScanned != maxScan {
			t.Fatalf("BytesScanned = %d, want %d", got.BytesScanned, maxScan)
		}
		if !got.Truncated {
			t.Fatal("Truncated = false, want true")
		}
	})

	t.Run("json depth", func(t *testing.T) {
		body := []byte(`{"messages":[{"content":"too deep"}]}`)
		got, err := ExtractText(body, Limits{MaxJSONDepth: 2})
		if err != nil {
			t.Fatalf("ExtractText() error = %v", err)
		}
		if len(got.Parts) != 0 {
			t.Fatalf("parts = %#v, want none", got.Parts)
		}
		if !got.Truncated {
			t.Fatal("Truncated = false, want true")
		}
	})

	t.Run("text parts", func(t *testing.T) {
		body := []byte(`{"input":["one","two","three"]}`)
		got, err := ExtractText(body, Limits{MaxTextParts: 2})
		if err != nil {
			t.Fatalf("ExtractText() error = %v", err)
		}
		if !reflect.DeepEqual(got.Parts, []string{"one", "two"}) {
			t.Fatalf("parts = %#v, want first two", got.Parts)
		}
		if !got.Truncated {
			t.Fatal("Truncated = false, want true")
		}
	})

	t.Run("long text is segmented", func(t *testing.T) {
		longText := strings.Repeat("defensive analysis. ", 2000)
		body, err := json.Marshal(map[string]string{"input": longText})
		if err != nil {
			t.Fatal(err)
		}
		got, err := ExtractText(body, Limits{})
		if err != nil {
			t.Fatalf("ExtractText() error = %v", err)
		}
		if len(got.Parts) < 2 {
			t.Fatalf("parts count = %d, want segmented text", len(got.Parts))
		}
		for i, part := range got.Parts {
			if len(part) > maxTextPartBytes {
				t.Fatalf("part %d length = %d, limit %d", i, len(part), maxTextPartBytes)
			}
		}
		if strings.Join(got.Parts, "") != longText {
			t.Fatal("segmented parts do not reconstruct the original text")
		}
	})
}

func TestExtractTextInvalidJSON(t *testing.T) {
	t.Parallel()

	for _, body := range []string{"", "{", `{"messages":[}`, "not json", `{} {}`} {
		body := body
		t.Run(body, func(t *testing.T) {
			got, err := ExtractText([]byte(body), Limits{})
			if !errors.Is(err, ErrInvalidJSON) {
				t.Fatalf("error = %v, want ErrInvalidJSON", err)
			}
			if got.ParseError == "" {
				t.Fatal("ParseError is empty")
			}
		})
	}

	t.Run("invalid token at scan boundary", func(t *testing.T) {
		prefix := `{"input":"ok"}x`
		body := []byte(prefix + strings.Repeat(" ", 100))
		got, err := ExtractText(body, Limits{MaxScanBytes: len(prefix)})
		if !errors.Is(err, ErrInvalidJSON) {
			t.Fatalf("error = %v, want ErrInvalidJSON", err)
		}
		if got.ParseError == "" || !got.Truncated {
			t.Fatalf("result = %#v, want parse error and scan truncation", got)
		}
	})
}

func TestExtractTextInvalidLimits(t *testing.T) {
	t.Parallel()

	_, err := ExtractText([]byte(`{}`), Limits{MaxJSONDepth: -1})
	if !errors.Is(err, ErrInvalidLimits) {
		t.Fatalf("error = %v, want ErrInvalidLimits", err)
	}
}

func FuzzExtractText(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{"messages":[{"content":"hello"}]}`),
		[]byte(`{"input":[{"content":[{"type":"input_text","text":"safe"}]}]}`),
		[]byte(`{"messages":[{"tool_calls":[{"function":{"arguments":"{\"command\":\"id\"}"}}]}]}`),
		[]byte(`{"contents":[{"parts":[{"text":"hello"}]}]}`),
		[]byte(`{"broken":`),
	} {
		f.Add(seed, uint16(4096), uint8(16), uint16(32))
	}

	f.Fuzz(func(t *testing.T, body []byte, scan uint16, depth uint8, parts uint16) {
		limits := Limits{
			MaxScanBytes: int(scan) + 1,
			MaxJSONDepth: int(depth%64) + 1,
			MaxTextParts: int(parts%256) + 1,
		}
		got, _ := ExtractText(body, limits)
		if got.BytesScanned < 0 || got.BytesScanned > limits.MaxScanBytes || got.BytesScanned > len(body) {
			t.Fatalf("invalid BytesScanned %d for body=%d limit=%d", got.BytesScanned, len(body), limits.MaxScanBytes)
		}
		if len(got.Parts) > limits.MaxTextParts {
			t.Fatalf("parts count %d exceeds limit %d", len(got.Parts), limits.MaxTextParts)
		}
		for _, part := range got.Parts {
			if len(part) > maxTextPartBytes {
				t.Fatalf("part length %d exceeds chunk limit", len(part))
			}
		}
	})
}
