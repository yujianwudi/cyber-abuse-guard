package classifier

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"unicode"

	"github.com/yujianwudi/cyber-abuse-guard/internal/extract"
	"github.com/yujianwudi/cyber-abuse-guard/internal/rules"
)

const holdoutSource = "independent-holdout-2026-07-12"

var retiredHoldoutV1Files = map[string]struct {
	Records int
	Bytes   int
	SHA256  string
}{
	"benign-security.jsonl": {
		Records: 246,
		Bytes:   69014,
		SHA256:  "46736f53d31c3caa7c1d585c3bdfb7bb60848c6d60ae75c12076c35cd2f19e1f",
	},
	"malicious-operational.jsonl": {
		Records: 260,
		Bytes:   90758,
		SHA256:  "a86bb28cc509969e2c3f27901413f9a82422c6dbeea98cda68145f47693688cc",
	},
}

type holdoutSegment struct {
	Role string `json:"role"`
	Text string `json:"text"`
}

type holdoutRecord struct {
	ID       string           `json:"id"`
	Text     string           `json:"text"`
	Parts    []string         `json:"parts"`
	Segments []holdoutSegment `json:"segments"`
	Payload  json.RawMessage  `json:"payload"`
	Category rules.Category   `json:"category"`
	Tags     []string         `json:"tags"`
	Source   string           `json:"source"`
}

type holdoutDecision struct {
	blocked  bool
	category rules.Category
}

type holdoutMetrics struct {
	benignTotal       int
	falsePositives    int
	maliciousTotal    int
	truePositives     int
	criticalTotal     map[rules.Category]int
	criticalHits      map[rules.Category]int
	exactCategoryHits int
}

type holdoutBucket struct {
	total int
	hits  int
}

// TestRetiredHoldoutV1Diagnostic preserves historical aggregate measurements
// for the consumed v1 set. It is not a release gate and cannot certify a
// candidate; a release decision requires a newly authored unseen holdout.
func TestRetiredHoldoutV1Diagnostic(t *testing.T) {
	if os.Getenv("RETIRED_HOLDOUT_V1_DIAGNOSTIC") != "1" {
		t.Skip("retired holdout v1 classification requires exact diagnostic opt-in")
	}

	c := newDefaultClassifier(t)
	ruleSet, err := rules.LoadDefault()
	if err != nil {
		t.Fatalf("reload default rules for retired diagnostic identity: %v", err)
	}
	ruleSnapshot, err := json.Marshal(ruleSet)
	if err != nil {
		t.Fatalf("marshal default rules for retired diagnostic identity: %v", err)
	}
	if c.version != ruleSet.Version {
		t.Fatalf("classifier ruleset %q does not match loaded ruleset %q", c.version, ruleSet.Version)
	}
	t.Logf("retired holdout v1 rule identity: ruleset=%s rules=%d signals=%d snapshot_sha256=%x", c.version, len(ruleSet.Rules), c.signalCount, sha256.Sum256(ruleSnapshot))
	benign := readHoldout(t, "benign-security.jsonl", false)
	malicious := readHoldout(t, "malicious-operational.jsonl", true)

	if len(benign) < 200 {
		t.Fatalf("benign holdout has %d records, want >= 200", len(benign))
	}
	if len(malicious) < 200 {
		t.Fatalf("malicious holdout has %d records, want >= 200", len(malicious))
	}
	assertHoldoutIndependenceAndCoverage(t, benign, malicious)

	critical := []rules.Category{
		rules.CategoryCredentialTheft,
		rules.CategoryPhishing,
		rules.CategoryRansomware,
		rules.CategoryExfiltration,
	}
	metrics := holdoutMetrics{
		benignTotal:    len(benign),
		maliciousTotal: len(malicious),
		criticalTotal:  make(map[rules.Category]int, len(critical)),
		criticalHits:   make(map[rules.Category]int, len(critical)),
	}
	benignByLanguage := make(map[string]*holdoutBucket)
	maliciousByLanguage := make(map[string]*holdoutBucket)
	maliciousByCategory := make(map[string]*holdoutBucket)
	maliciousByTechnique := make(map[string]*holdoutBucket)
	for _, item := range benign {
		decision := evaluateHoldout(t, c, item)
		updateBucket(benignByLanguage, languageBucket(item), !decision.blocked)
		if decision.blocked {
			metrics.falsePositives++
		}
	}
	for _, item := range malicious {
		decision := evaluateHoldout(t, c, item)
		updateBucket(maliciousByLanguage, languageBucket(item), decision.blocked)
		updateBucket(maliciousByCategory, string(item.Category), decision.blocked)
		for _, technique := range holdoutTechniqueTags {
			if hasTag(item, technique) {
				updateBucket(maliciousByTechnique, technique, decision.blocked)
			}
		}
		for _, category := range critical {
			if item.Category == category {
				metrics.criticalTotal[category]++
				if decision.blocked {
					metrics.criticalHits[category]++
				}
			}
		}
		if decision.blocked {
			metrics.truePositives++
			if decision.category == item.Category {
				metrics.exactCategoryHits++
			}
			continue
		}
	}

	t.Logf(
		"retired holdout v1 balanced diagnostic: benign FP=%d/%d (%.2f%%), malicious recall=%d/%d (%.2f%%), exact-category=%d/%d (%.2f%%)",
		metrics.falsePositives,
		metrics.benignTotal,
		percentage(metrics.falsePositives, metrics.benignTotal),
		metrics.truePositives,
		metrics.maliciousTotal,
		percentage(metrics.truePositives, metrics.maliciousTotal),
		metrics.exactCategoryHits,
		metrics.maliciousTotal,
		percentage(metrics.exactCategoryHits, metrics.maliciousTotal),
	)
	for _, category := range critical {
		t.Logf(
			"retired holdout v1 category %s recall=%d/%d (%.2f%%)",
			category,
			metrics.criticalHits[category],
			metrics.criticalTotal[category],
			percentage(metrics.criticalHits[category], metrics.criticalTotal[category]),
		)
	}
	logHoldoutBuckets(t, "benign allow by language", benignByLanguage)
	logHoldoutBuckets(t, "malicious recall by language", maliciousByLanguage)
	logHoldoutBuckets(t, "malicious recall by category", maliciousByCategory)
	logHoldoutBuckets(t, "malicious recall by bypass/structure tag", maliciousByTechnique)

	if err := validateRetiredHoldoutV1Metrics(metrics); err != nil {
		t.Error(err)
	}
}

func TestRetiredHoldoutV1FrozenIntegrity(t *testing.T) {
	for name, snapshot := range retiredHoldoutV1Files {
		path := filepath.Join("..", "..", "testdata", "holdout", name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read retired holdout v1 snapshot %s: %v", name, err)
		}
		if len(data) != snapshot.Bytes {
			t.Fatalf("retired holdout v1 byte count changed for %s: got %d want %d", name, len(data), snapshot.Bytes)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != snapshot.SHA256 {
			t.Fatalf("retired holdout v1 SHA-256 changed for %s", name)
		}
		malicious := name == "malicious-operational.jsonl"
		if got := len(readHoldout(t, name, malicious)); got != snapshot.Records {
			t.Fatalf("retired holdout v1 record count changed for %s: got %d want %d", name, got, snapshot.Records)
		}
	}
}

var holdoutTechniqueTags = []string{
	"base64", "url_encoding", "html_entity", "json_unicode", "char_split",
	"zero_width", "nbsp", "markdown", "string_concat", "multi_turn",
	"tool_json", "prompt_injection", "authorized_conflict", "unknown_role",
	"history_padding", "typo", "homoglyph",
}

// This preserves the historical v1 threshold semantics for diagnostics. It
// does not make the consumed set eligible to certify a release.
func TestRetiredHoldoutV1ThresholdDiagnosticsRejectFailures(t *testing.T) {
	baseline := holdoutMetrics{
		benignTotal:    200,
		falsePositives: 9,
		maliciousTotal: 200,
		truePositives:  181,
		criticalTotal: map[rules.Category]int{
			rules.CategoryCredentialTheft: 20,
			rules.CategoryPhishing:        20,
			rules.CategoryRansomware:      20,
			rules.CategoryExfiltration:    20,
		},
		criticalHits: map[rules.Category]int{
			rules.CategoryCredentialTheft: 19,
			rules.CategoryPhishing:        19,
			rules.CategoryRansomware:      19,
			rules.CategoryExfiltration:    19,
		},
	}
	if err := validateRetiredHoldoutV1Metrics(baseline); err != nil {
		t.Fatalf("passing boundary rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*holdoutMetrics)
	}{
		{"false positive rate at five percent", func(value *holdoutMetrics) { value.falsePositives = 10 }},
		{"overall recall at ninety percent", func(value *holdoutMetrics) { value.truePositives = 180 }},
		{"credential recall below ninety five percent", func(value *holdoutMetrics) { value.criticalHits[rules.CategoryCredentialTheft] = 18 }},
		{"phishing recall below ninety five percent", func(value *holdoutMetrics) { value.criticalHits[rules.CategoryPhishing] = 18 }},
		{"ransomware recall below ninety five percent", func(value *holdoutMetrics) { value.criticalHits[rules.CategoryRansomware] = 18 }},
		{"exfiltration recall below ninety five percent", func(value *holdoutMetrics) { value.criticalHits[rules.CategoryExfiltration] = 18 }},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			candidate := cloneHoldoutMetrics(baseline)
			testCase.mutate(&candidate)
			if err := validateRetiredHoldoutV1Metrics(candidate); err == nil {
				t.Fatal("failing historical metrics returned nil")
			}
		})
	}
}

func readHoldout(t *testing.T, name string, malicious bool) []holdoutRecord {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "holdout", name)
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	seen := make(map[string]struct{})
	records := make([]holdoutRecord, 0, 256)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 2<<20)
	for scanner.Scan() {
		lineNo := len(records) + 1
		line := append([]byte(nil), scanner.Bytes()...)
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		var item holdoutRecord
		if err := decoder.Decode(&item); err != nil {
			t.Fatalf("%s:%d: %v", name, lineNo, err)
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			t.Fatalf("%s:%d: trailing JSON data: %v", name, lineNo, err)
		}
		if item.ID == "" || item.Source != holdoutSource {
			t.Fatalf("%s:%d: invalid id/source: id=%q source=%q", name, lineNo, item.ID, item.Source)
		}
		if _, ok := seen[item.ID]; ok {
			t.Fatalf("%s:%d: duplicate id %q", name, lineNo, item.ID)
		}
		seen[item.ID] = struct{}{}
		if len(item.Tags) == 0 || hasDuplicateOrEmpty(item.Tags) {
			t.Fatalf("%s:%d: tags must be non-empty and unique: %v", name, lineNo, item.Tags)
		}
		forms := 0
		if strings.TrimSpace(item.Text) != "" {
			forms++
		}
		if len(item.Parts) > 0 {
			forms++
		}
		if len(item.Segments) > 0 {
			forms++
		}
		if len(item.Payload) > 0 {
			forms++
		}
		if forms != 1 {
			t.Fatalf("%s:%d: record %s has %d input forms, want exactly one", name, lineNo, item.ID, forms)
		}
		if malicious && item.Category == "" {
			t.Fatalf("%s:%d: malicious record %s has no category", name, lineNo, item.ID)
		}
		if !malicious && item.Category != "" {
			t.Fatalf("%s:%d: benign record %s has category %s", name, lineNo, item.ID, item.Category)
		}
		records = append(records, item)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return records
}

func evaluateHoldout(t *testing.T, c *Classifier, item holdoutRecord) holdoutDecision {
	t.Helper()
	var result Result
	switch {
	case item.Text != "":
		body, err := json.Marshal(map[string]string{"input": item.Text})
		if err != nil {
			t.Fatalf("record %s JSON envelope failed: %v", item.ID, err)
		}
		result = classifyExtractedHoldout(t, c, item.ID, body)
	case len(item.Parts) > 0:
		result = c.ClassifyUntrustedPartsWithPolicy(item.Parts, ModeBalanced, DefaultThresholds(), DefaultPolicy())
	case len(item.Segments) > 0:
		segments := make([]extract.Segment, 0, len(item.Segments))
		for _, source := range item.Segments {
			segments = append(segments, extract.Segment{Role: extract.Role(source.Role), Text: source.Text})
		}
		result = c.AnalyzeSegments(segments)
	case len(item.Payload) > 0:
		result = classifyExtractedHoldout(t, c, item.ID, item.Payload)
	default:
		t.Fatalf("record %s has no input", item.ID)
	}
	// This matches router.go: Balanced blocks either the classifier decision or
	// a bounded-extraction/normalization truncation.
	return holdoutDecision{
		blocked:  result.Score >= BalancedThreshold || result.Truncated,
		category: result.Category,
	}
}

func classifyExtractedHoldout(t *testing.T, c *Classifier, id string, body []byte) Result {
	t.Helper()
	extracted, err := extract.ExtractText(body, extract.Limits{})
	if err != nil {
		t.Fatalf("record %s extraction failed: %v", id, err)
	}
	var result Result
	if extracted.RoleAware {
		result = c.AnalyzeSegments(extracted.Segments)
	} else {
		result = c.ClassifyUntrustedPartsWithPolicy(extracted.Parts, ModeBalanced, DefaultThresholds(), DefaultPolicy())
	}
	result.Truncated = result.Truncated || extracted.Truncated
	return result
}

func assertHoldoutIndependenceAndCoverage(t *testing.T, benign, malicious []holdoutRecord) {
	t.Helper()
	all := append(append([]holdoutRecord(nil), benign...), malicious...)
	seenIDs := make(map[string]struct{}, len(all))
	seenInputs := make(map[string]string, len(all))
	tags := make(map[string]int)
	categoryTotals := make(map[rules.Category]int)
	authorizedCritical := make(map[rules.Category]int)
	regression := readRegressionTextSet(t)
	for _, item := range all {
		if previous, ok := seenIDs[item.ID]; ok {
			t.Fatalf("duplicate holdout id across files: %s (%v)", item.ID, previous)
		}
		seenIDs[item.ID] = struct{}{}
		for _, tag := range item.Tags {
			tags[tag]++
		}
		if item.Category != "" {
			categoryTotals[item.Category]++
			if hasTag(item, "authorized_conflict") {
				authorizedCritical[item.Category]++
			}
		}
		fingerprint := canonicalHoldoutInput(item)
		if previous, ok := seenInputs[fingerprint]; ok {
			t.Fatalf("holdout inputs %s and %s are duplicates", previous, item.ID)
		}
		seenInputs[fingerprint] = item.ID
		for _, candidate := range holdoutSemanticTexts(t, item) {
			if regressionID, ok := regression[canonicalText(candidate)]; ok {
				t.Fatalf("holdout %s directly copies regression record %s", item.ID, regressionID)
			}
		}
	}

	requiredTags := []string{
		"zh", "en", "mixed", "colloquial", "typo", "homoglyph", "zero_width",
		"base64", "url_encoding", "html_entity", "json_unicode", "char_split",
		"nbsp", "markdown", "string_concat", "multi_turn", "tool_json",
		"defensive", "remediation", "ctf", "authorized_conflict", "high_level",
		"detection_rule",
	}
	for _, tag := range requiredTags {
		if tags[tag] == 0 {
			t.Errorf("holdout coverage tag %q is absent", tag)
		}
	}
	if tags["zh"] < 60 || tags["en"] < 60 || tags["mixed"] < 10 {
		t.Errorf("language coverage too small: zh=%d en=%d mixed=%d", tags["zh"], tags["en"], tags["mixed"])
	}
	if tags["multi_turn"] < 20 || tags["tool_json"] < 20 {
		t.Errorf("structured coverage too small: multi_turn=%d tool_json=%d", tags["multi_turn"], tags["tool_json"])
	}
	for _, category := range []rules.Category{
		rules.CategoryCredentialTheft,
		rules.CategoryPhishing,
		rules.CategoryRansomware,
		rules.CategoryExfiltration,
		rules.CategoryMalware,
		rules.CategoryExploitation,
		rules.CategoryDisruption,
		rules.CategoryEvasion,
	} {
		if categoryTotals[category] < 25 {
			t.Errorf("holdout category %s has %d rows, want >= 25", category, categoryTotals[category])
		}
	}
	for _, category := range []rules.Category{
		rules.CategoryCredentialTheft,
		rules.CategoryPhishing,
		rules.CategoryRansomware,
		rules.CategoryExfiltration,
	} {
		if authorizedCritical[category] == 0 {
			t.Errorf("critical category %s has no authorization-conflict probe", category)
		}
	}
}

func validateRetiredHoldoutV1Metrics(metrics holdoutMetrics) error {
	var failures []string
	if metrics.benignTotal <= 0 || metrics.falsePositives*100 >= metrics.benignTotal*5 {
		failures = append(failures, fmt.Sprintf("Balanced Holdout false-positive rate %.2f%% (%d/%d), want < 5%%", percentage(metrics.falsePositives, metrics.benignTotal), metrics.falsePositives, metrics.benignTotal))
	}
	if metrics.maliciousTotal <= 0 || metrics.truePositives*100 <= metrics.maliciousTotal*90 {
		failures = append(failures, fmt.Sprintf("malicious operational recall %.2f%% (%d/%d), want > 90%%", percentage(metrics.truePositives, metrics.maliciousTotal), metrics.truePositives, metrics.maliciousTotal))
	}
	for _, category := range []rules.Category{
		rules.CategoryCredentialTheft,
		rules.CategoryPhishing,
		rules.CategoryRansomware,
		rules.CategoryExfiltration,
	} {
		total := metrics.criticalTotal[category]
		hits := metrics.criticalHits[category]
		if total <= 0 || hits*100 < total*95 {
			failures = append(failures, fmt.Sprintf("critical category %s recall %.2f%% (%d/%d), want >= 95%%", category, percentage(hits, total), hits, total))
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("retired holdout v1 diagnostic thresholds missed:\n- %s", strings.Join(failures, "\n- "))
	}
	return nil
}

func readRegressionTextSet(t *testing.T) map[string]string {
	t.Helper()
	result := make(map[string]string)
	for _, name := range []string{"benign-security.jsonl", "malicious-operational.jsonl"} {
		path := filepath.Join("..", "..", "testdata", "corpus", name)
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			var item struct {
				ID   string `json:"id"`
				Text string `json:"text"`
			}
			if err := json.Unmarshal(scanner.Bytes(), &item); err != nil {
				_ = file.Close()
				t.Fatal(err)
			}
			result[canonicalText(item.Text)] = item.ID
		}
		if err := scanner.Err(); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return result
}

func holdoutSemanticTexts(t *testing.T, item holdoutRecord) []string {
	t.Helper()
	var values []string
	values = append(values, item.Text)
	values = append(values, item.Parts...)
	for _, segment := range item.Segments {
		values = append(values, segment.Text)
	}
	if len(item.Payload) > 0 {
		extracted, err := extract.ExtractText(item.Payload, extract.Limits{})
		if err != nil {
			t.Fatalf("extract holdout %s for independence check: %v", item.ID, err)
		}
		values = append(values, extracted.Parts...)
		for _, segment := range extracted.Segments {
			values = append(values, segment.Text)
		}
	}
	result := values[:0]
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			result = append(result, value)
		}
	}
	return result
}

func canonicalHoldoutInput(item holdoutRecord) string {
	var values []string
	values = append(values, item.Text)
	values = append(values, item.Parts...)
	for _, segment := range item.Segments {
		values = append(values, segment.Role, segment.Text)
	}
	if len(item.Payload) > 0 {
		values = append(values, string(item.Payload))
	}
	return canonicalText(strings.Join(values, "\x00"))
}

func canonicalText(value string) string {
	return strings.ToLower(strings.Join(strings.FieldsFunc(value, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsPunct(r)
	}), " "))
}

func hasTag(item holdoutRecord, wanted string) bool {
	for _, tag := range item.Tags {
		if tag == wanted {
			return true
		}
	}
	return false
}

func languageBucket(item holdoutRecord) string {
	hasZH := hasTag(item, "zh")
	hasEN := hasTag(item, "en")
	if hasTag(item, "mixed") || (hasZH && hasEN) {
		return "mixed"
	}
	if hasZH {
		return "zh"
	}
	if hasEN {
		return "en"
	}
	return "unspecified"
}

func updateBucket(buckets map[string]*holdoutBucket, name string, hit bool) {
	bucket := buckets[name]
	if bucket == nil {
		bucket = &holdoutBucket{}
		buckets[name] = bucket
	}
	bucket.total++
	if hit {
		bucket.hits++
	}
}

func logHoldoutBuckets(t *testing.T, label string, buckets map[string]*holdoutBucket) {
	t.Helper()
	keys := make([]string, 0, len(buckets))
	for key := range buckets {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		bucket := buckets[key]
		t.Logf("%s %s=%d/%d (%.2f%%)", label, key, bucket.hits, bucket.total, percentage(bucket.hits, bucket.total))
	}
}

func hasDuplicateOrEmpty(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return true
		}
		if _, ok := seen[value]; ok {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

func percentage(numerator, denominator int) float64 {
	if denominator == 0 {
		return 0
	}
	return float64(numerator) * 100 / float64(denominator)
}

func cloneHoldoutMetrics(source holdoutMetrics) holdoutMetrics {
	clone := source
	clone.criticalTotal = make(map[rules.Category]int, len(source.criticalTotal))
	clone.criticalHits = make(map[rules.Category]int, len(source.criticalHits))
	for key, value := range source.criticalTotal {
		clone.criticalTotal[key] = value
	}
	for key, value := range source.criticalHits {
		clone.criticalHits[key] = value
	}
	return clone
}

func sortedTagSummary(records []holdoutRecord) []string {
	counts := make(map[string]int)
	for _, item := range records {
		for _, tag := range item.Tags {
			counts[tag]++
		}
	}
	result := make([]string, 0, len(counts))
	for tag, count := range counts {
		result = append(result, fmt.Sprintf("%s=%d", tag, count))
	}
	sort.Strings(result)
	return result
}
