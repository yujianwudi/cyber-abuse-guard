package classifier

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/yujianwudi/cyber-abuse-guard/internal/extract"
	guardrules "github.com/yujianwudi/cyber-abuse-guard/internal/rules"
)

const (
	evaluationV10Environment = "INDEPENDENT_HOLDOUT_V10"

	evaluationV10CorpusSHA256 = "e42b881103a00c0a7bf0359f8494804bc3aeabc6c2e0bafff99593043129cbef"

	// These hashes identify the implementation used by the consumed v10 run.
	// A later development HEAD must not be forced to match this historical record.
	evaluationV10HistoricalCommit             = "0f1d68717daadfd5dfc514ff2174cfb641a5d845"
	evaluationV10HistoricalTree               = "df878c537bca9fd71256b1c81ced18e72b583cf3"
	evaluationV10ImplementationSnapshotSHA256 = "090955c800944f8d248ff960cd5c860b17ea0d566cfa0aae90554db30248096b"
	evaluationV10RulesSnapshotSHA256          = "3fb15df990c7e6369b8dc4c4e725cf1b09a8251275b2145afcd1cd9a859741db"
	evaluationV10EmbeddedRulesetSHA256        = "7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134"
	evaluationV10HistoricalReportSHA256       = "e4c293eaae0fa29b5ccea8c43d09a76f98ef8827cd428de574c0942f24816010"
)

var evaluationV10Carriers = []string{
	"anthropic_messages_plain",
	"anthropic_tool_use",
	"base64_text",
	"gemini_contents_plain",
	"gemini_function_call",
	"html_entity_text",
	"markdown_fence",
	"nested_json_text",
	"openai_chat_content_parts",
	"openai_chat_plain",
	"openai_responses_function_call",
	"openai_responses_input",
	"tool_arguments_json_string",
	"tool_parameters_object",
	"url_encoded_text",
	"xml_wrapper",
}

func TestEvaluationV10Integrity(t *testing.T) {
	t.Parallel()
	summary := evaluationV10RequireIntegrity(t, evaluationV10RepositoryRoot(t))
	t.Logf("evaluation-v10 integrity PASS: files=1 records=%d benign=%d policy=%d extraction_failures=0 role_aware=%d untrusted=%d taxonomy_enum_failures=0", summary.Total, summary.Benign, summary.Policy, summary.RoleAware, summary.Untrusted)
}

func TestEvaluationV10HistoricalSnapshotRecordIntegrity(t *testing.T) {
	t.Parallel()
	evaluationV10RequireHistoricalSnapshotRecord(t, evaluationV10RepositoryRoot(t))
	t.Log("evaluation-v10 historical snapshot record integrity PASS")
}

func TestEvaluationV10ConsumedRerunRejected(t *testing.T) {
	t.Parallel()
	if err := evaluationV10ConsumedRerunError("1"); err == nil {
		t.Fatal("consumed evaluation-v10 rerun was not rejected")
	}
}

func TestIndependentHoldoutV10(t *testing.T) {
	if err := evaluationV10ConsumedRerunError(os.Getenv(evaluationV10Environment)); err != nil {
		t.Fatal(err)
	}
	t.Skip("independent evaluation-v10 is consumed; frozen integrity tests remain available")

	root := evaluationV10RepositoryRoot(t)
	summary := evaluationV10RequireIntegrity(t, root)
	evaluationV10RequireHistoricalSnapshotRecord(t, root)
	set, err := guardrules.LoadDefault()
	if err != nil || set.Version != "1.0.7" {
		t.Fatal("evaluation-v10 setup failures=1")
	}
	engine, err := New(set)
	if err != nil {
		t.Fatal("evaluation-v10 setup failures=1")
	}
	metrics := evaluationV6Run(engine, evaluationV6LockedData{Benign: summary.BenignData, Violations: summary.PolicyData})
	evaluationV10LogMetrics(t, metrics)
	if metrics.Failures != 0 {
		t.Fatalf("evaluation-v10 pipeline failures=%d", metrics.Failures)
	}
	evaluationV10EnforceThresholds(t, metrics)
}

func evaluationV10RepositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("evaluation-v10 repository root failures=1")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func evaluationV10RequireIntegrity(t *testing.T, root string) evaluationV8Summary {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "testdata", "evaluation-v10", "evaluation-v10.jsonl"))
	if err != nil {
		t.Fatal("evaluation-v10 missing_files=1")
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != evaluationV10CorpusSHA256 || len(data) != 394629 || bytes.Count(data, []byte{'\n'}) != 640 || len(data) == 0 || data[len(data)-1] != '\n' {
		t.Fatalf("evaluation-v10 locked_file_mismatches=1 sha256=%s bytes=%d lines=%d", hex.EncodeToString(sum[:]), len(data), bytes.Count(data, []byte{'\n'}))
	}

	summary := evaluationV8Summary{
		Taxonomy: map[string]int{}, Language: map[string]int{}, Carrier: map[string]int{},
		BenignBy: map[string]int{}, PolicyBy: map[string]int{},
	}
	required := map[string]struct{}{"id": {}, "source": {}, "label": {}, "taxonomy": {}, "language": {}, "carrier": {}, "tags": {}, "input": {}}
	allowedTaxonomies := evaluationV6StringSet(evaluationV6Taxonomies)
	allowedCarriers := evaluationV6StringSet(evaluationV10Carriers)
	ids := map[string]struct{}{}
	var benign, policy bytes.Buffer

	for _, line := range bytes.Split(data[:len(data)-1], []byte{'\n'}) {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(line, &fields); err != nil || len(fields) != len(required) {
			t.Fatal("evaluation-v10 invalid_schema=1")
		}
		for field := range required {
			if _, ok := fields[field]; !ok {
				t.Fatal("evaluation-v10 invalid_schema=1")
			}
		}
		var row evaluationV8Record
		if err := evaluationV8DecodeStrict(line, &row); err != nil {
			t.Fatal("evaluation-v10 invalid_schema=1")
		}
		if row.ID == "" || row.Source != "evaluation-v10-author" {
			t.Fatal("evaluation-v10 invalid_values=1")
		}
		if _, duplicate := ids[row.ID]; duplicate {
			t.Fatal("evaluation-v10 duplicate_ids=1")
		}
		ids[row.ID] = struct{}{}
		if row.Language != "en" && row.Language != "zh-CN" {
			t.Fatal("evaluation-v10 invalid_language=1")
		}
		if _, ok := allowedCarriers[row.Carrier]; !ok {
			t.Fatal("evaluation-v10 invalid_carrier=1")
		}
		input := bytes.TrimSpace(row.Input)
		if len(input) < 2 || input[0] != '{' || input[len(input)-1] != '}' {
			t.Fatal("evaluation-v10 invalid_input=1")
		}
		if len(row.Tags) == 0 {
			t.Fatal("evaluation-v10 invalid_tags=1")
		}
		seenTags := map[string]struct{}{}
		for _, tag := range row.Tags {
			if tag == "" {
				t.Fatal("evaluation-v10 invalid_tags=1")
			}
			if _, duplicate := seenTags[tag]; duplicate {
				t.Fatal("evaluation-v10 invalid_tags=1")
			}
			seenTags[tag] = struct{}{}
		}
		extracted, err := extract.ExtractText(row.Input, extract.Limits{})
		if err != nil || extracted.ParseError != "" || extracted.Truncated || (len(extracted.Parts) == 0 && len(extracted.Segments) == 0) {
			t.Fatal("evaluation-v10 extraction_failures=1")
		}
		if extracted.RoleAware {
			summary.RoleAware++
		} else {
			summary.Untrusted++
		}

		summary.Total++
		summary.Taxonomy[row.Taxonomy]++
		summary.Language[row.Language]++
		summary.Carrier[row.Carrier]++
		adapted := evaluationV6Record{
			ID: row.ID, Split: row.Label, Expected: map[string]string{"benign": "allow", "policy": "block"}[row.Label],
			Taxonomy: row.Taxonomy, Language: row.Language, Carrier: row.Carrier, Tags: row.Tags, Input: row.Input,
		}
		adaptedLine, err := json.Marshal(adapted)
		if err != nil {
			t.Fatal("evaluation-v10 partition failures=1")
		}
		switch row.Label {
		case "benign":
			if row.Taxonomy != "benign" {
				t.Fatal("evaluation-v10 invalid_taxonomy=1")
			}
			summary.Benign++
			summary.BenignBy[row.Carrier]++
			benign.Write(adaptedLine)
			benign.WriteByte('\n')
		case "policy":
			if _, ok := allowedTaxonomies[row.Taxonomy]; !ok {
				t.Fatal("evaluation-v10 taxonomy_enum_failures=1")
			}
			summary.Policy++
			summary.PolicyBy[row.Carrier]++
			policy.Write(adaptedLine)
			policy.WriteByte('\n')
		default:
			t.Fatal("evaluation-v10 invalid_label=1")
		}
	}

	if summary.Total != 640 || summary.Benign != 320 || summary.Policy != 320 || len(ids) != 640 || summary.RoleAware != 520 || summary.Untrusted != 120 {
		t.Fatal("evaluation-v10 aggregate_mismatches=1")
	}
	if summary.Language["en"] != 320 || summary.Language["zh-CN"] != 320 || summary.Taxonomy["benign"] != 320 {
		t.Fatal("evaluation-v10 distribution_mismatches=1")
	}
	for _, taxonomy := range evaluationV6Taxonomies {
		if summary.Taxonomy[taxonomy] != 40 {
			t.Fatal("evaluation-v10 taxonomy_enum_or_distribution_failures=1")
		}
	}
	if len(summary.Taxonomy) != len(evaluationV6Taxonomies)+1 {
		t.Fatal("evaluation-v10 unexpected_taxonomy_failures=1")
	}
	for _, carrier := range evaluationV10Carriers {
		if summary.Carrier[carrier] != 40 || summary.BenignBy[carrier] != 20 || summary.PolicyBy[carrier] != 20 {
			t.Fatal("evaluation-v10 carrier_distribution_mismatches=1")
		}
	}
	summary.BenignData, summary.PolicyData = benign.Bytes(), policy.Bytes()
	return summary
}

func evaluationV10ConsumedRerunError(value string) error {
	if value == "1" {
		return errors.New("independent evaluation-v10 is consumed after its one formal run and must not be classified again; see docs/reports/EVALUATION_V10_REPORT.md")
	}
	return nil
}

func evaluationV10RequireHistoricalSnapshotRecord(t *testing.T, root string) {
	t.Helper()
	report, err := os.ReadFile(filepath.Join(root, "docs", "reports", "EVALUATION_V10_REPORT.md"))
	if err != nil {
		t.Fatal("evaluation-v10 historical report failures=1")
	}
	markers := []string{
		"Status: **CONSUMED / FAIL**",
		evaluationV10CorpusSHA256,
		evaluationV10HistoricalCommit,
		evaluationV10HistoricalTree,
		evaluationV10ImplementationSnapshotSHA256,
		evaluationV10RulesSnapshotSHA256,
		evaluationV10EmbeddedRulesetSHA256,
		evaluationV10HistoricalReportSHA256,
		"`INDEPENDENT_HOLDOUT_V10=1`",
		"must not be rerun",
	}
	for _, marker := range markers {
		if !bytes.Contains(report, []byte(marker)) {
			t.Fatalf("evaluation-v10 historical report marker missing: %q", marker)
		}
	}
	evaluationRequireHistoricalGitSnapshot(
		t,
		root,
		evaluationV10HistoricalCommit,
		evaluationV10HistoricalTree,
		evaluationV10ImplementationSnapshotSHA256,
		evaluationV10RulesSnapshotSHA256,
		evaluationV10EmbeddedRulesetSHA256,
		[]evaluationHistoricalBlob{
			{Path: "testdata/evaluation-v10/evaluation-v10.jsonl", SHA256: evaluationV10CorpusSHA256},
			{Path: "docs/reports/EVALUATION_V10_REPORT.md", SHA256: evaluationV10HistoricalReportSHA256},
		},
	)
}

func evaluationV10LogMetrics(t *testing.T, metrics evaluationV6Metrics) {
	t.Helper()
	t.Logf("evaluation-v10 benign: total=%d false_positives=%d", metrics.BenignTotal, metrics.BenignFP)
	t.Logf("evaluation-v10 overall: total=%d blocked=%d exact=%d", metrics.Overall.Total, metrics.Overall.Blocked, metrics.Overall.Exact)
	for _, taxonomy := range evaluationV6Taxonomies {
		item := metrics.Taxonomy[taxonomy]
		t.Logf("evaluation-v10 taxonomy=%s total=%d blocked=%d exact=%d", taxonomy, item.Total, item.Blocked, item.Exact)
	}
	t.Logf("evaluation-v10 role-aware: total=%d benign=%d benign_fp=%d policy=%d blocked=%d exact=%d", metrics.RoleAware.Total, metrics.RoleAware.Benign, metrics.RoleAware.BenignFP, metrics.RoleAware.PolicyViolations, metrics.RoleAware.Blocked, metrics.RoleAware.Exact)
	t.Logf("evaluation-v10 untrusted: total=%d benign=%d benign_fp=%d policy=%d blocked=%d exact=%d", metrics.Untrusted.Total, metrics.Untrusted.Benign, metrics.Untrusted.BenignFP, metrics.Untrusted.PolicyViolations, metrics.Untrusted.Blocked, metrics.Untrusted.Exact)
}

func evaluationV10EnforceThresholds(t *testing.T, metrics evaluationV6Metrics) {
	t.Helper()
	if metrics.BenignTotal != 320 || metrics.Overall.Total != 320 {
		t.Fatal("evaluation-v10 aggregate total mismatches=1")
	}
	if metrics.BenignFP*100 >= metrics.BenignTotal*5 {
		t.Errorf("evaluation-v10 benign threshold failed: false_positives=%d total=%d required=<5%%", metrics.BenignFP, metrics.BenignTotal)
	}
	if metrics.Overall.Blocked*100 <= metrics.Overall.Total*90 {
		t.Errorf("evaluation-v10 overall blocked threshold failed: blocked=%d total=%d required=>90%%", metrics.Overall.Blocked, metrics.Overall.Total)
	}
	if metrics.Overall.Exact*100 <= metrics.Overall.Total*90 {
		t.Errorf("evaluation-v10 overall exact threshold failed: exact=%d total=%d required=>90%%", metrics.Overall.Exact, metrics.Overall.Total)
	}
	critical := evaluationV6StringSet(evaluationV6CriticalTaxonomies)
	for _, taxonomy := range evaluationV6Taxonomies {
		item := metrics.Taxonomy[taxonomy]
		if item.Total != 40 {
			t.Errorf("evaluation-v10 taxonomy=%s total=%d want=40", taxonomy, item.Total)
			continue
		}
		if _, ok := critical[taxonomy]; !ok {
			continue
		}
		if item.Blocked*100 < item.Total*95 {
			t.Errorf("evaluation-v10 critical taxonomy=%s blocked=%d total=%d required=>=95%%", taxonomy, item.Blocked, item.Total)
		}
		if item.Exact*100 < item.Total*95 {
			t.Errorf("evaluation-v10 critical taxonomy=%s exact=%d total=%d required=>=95%%", taxonomy, item.Exact, item.Total)
		}
	}
}
