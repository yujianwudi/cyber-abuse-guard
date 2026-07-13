package classifier

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
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

	evaluationV10TotalRecords = 640
	evaluationV10Benign       = 320
	evaluationV10Policy       = 320
	evaluationV10RoleAware    = 520
	evaluationV10Untrusted    = 120
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

var evaluationV10Taxonomies = []string{
	"credential_theft",
	"phishing_deployment",
	"malware_deployment",
	"ransomware_deployment",
	"unauthorized_exploitation",
	"service_disruption",
	"data_exfiltration",
	"defense_evasion",
}

// TestEvaluationV10Integrity intentionally validates only the frozen aggregate
// contract. The consumed corpus is not opened, parsed, extracted, or classified
// by the default unit-test path.
func TestEvaluationV10Integrity(t *testing.T) {
	t.Parallel()
	for name, value := range map[string]string{
		"corpus": evaluationV10CorpusSHA256, "implementation": evaluationV10ImplementationSnapshotSHA256,
		"rules": evaluationV10RulesSnapshotSHA256, "embedded": evaluationV10EmbeddedRulesetSHA256,
		"report": evaluationV10HistoricalReportSHA256,
	} {
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != 32 {
			t.Fatalf("evaluation-v10 %s aggregate hash constant is invalid", name)
		}
	}
	if evaluationV10TotalRecords != evaluationV10Benign+evaluationV10Policy ||
		evaluationV10RoleAware+evaluationV10Untrusted != evaluationV10TotalRecords {
		t.Fatal("evaluation-v10 aggregate totals are internally inconsistent")
	}
	if len(evaluationV10Taxonomies) != 8 || len(evaluationV10Carriers) != 16 {
		t.Fatal("evaluation-v10 aggregate taxonomy/carrier cardinality changed")
	}
	for label, values := range map[string][]string{"taxonomy": evaluationV10Taxonomies, "carrier": evaluationV10Carriers} {
		seen := make(map[string]struct{}, len(values))
		for _, value := range values {
			if value == "" {
				t.Fatalf("evaluation-v10 aggregate %s contains an empty value", label)
			}
			if _, duplicate := seen[value]; duplicate {
				t.Fatalf("evaluation-v10 aggregate %s contains duplicate %q", label, value)
			}
			seen[value] = struct{}{}
		}
	}
	t.Log("evaluation-v10 frozen aggregate contract PASS; consumed fixture was not accessed")
}

func TestEvaluationV10HistoricalSnapshotRecordIntegrity(t *testing.T) {
	t.Parallel()
	evaluationV10RequireHistoricalReportRecord(t)
	t.Log("evaluation-v10 historical aggregate report record integrity PASS")
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
	t.Skip("independent evaluation-v10 is consumed; only aggregate report checks remain available")
}

func evaluationV10ConsumedRerunError(value string) error {
	if value == "1" {
		return errors.New("independent evaluation-v10 is consumed after its one formal run and must not be classified again; see docs/reports/EVALUATION_V10_REPORT.md")
	}
	return nil
}

func evaluationV10RequireHistoricalReportRecord(t *testing.T) {
	t.Helper()
	report, err := os.ReadFile(filepath.Join("..", "..", "docs", "reports", "EVALUATION_V10_REPORT.md"))
	if err != nil {
		t.Fatal("evaluation-v10 historical aggregate report failures=1")
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
			t.Fatalf("evaluation-v10 historical aggregate report marker missing: %q", marker)
		}
	}
}
