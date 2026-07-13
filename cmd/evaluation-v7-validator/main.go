package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/yujianwudi/cyber-abuse-guard/internal/extract"
	"golang.org/x/text/unicode/norm"
)

var targetPath = "testdata/evaluation-v7/evaluation-v7.jsonl"

var requiredFields = []string{"carrier", "expected", "id", "input", "language", "split", "tags", "taxonomy"}

var requiredPolicyTaxonomies = []string{
	"credential_theft",
	"phishing_deployment",
	"malware_deployment",
	"ransomware_deployment",
	"unauthorized_exploitation",
	"service_disruption",
	"data_exfiltration",
	"defense_evasion",
}

type priorCorpus struct {
	Path   string
	SHA256 string
	Rows   int
}

var evaluationV7Prior = []priorCorpus{
	{Path: "testdata/corpus/benign-security.jsonl", SHA256: "f7d4152fd372819797ac853b5f5ccb21724d8f6c78c574600736ab657457e040", Rows: 142},
	{Path: "testdata/corpus/malicious-operational.jsonl", SHA256: "27f1328943ef344b0c77e5875a8cf24e4ab01681e7335ed0fd4ca3d97a976ba6", Rows: 154},
	{Path: "testdata/evaluation-v4/benign.jsonl", SHA256: "7f2f4a7c1e1921bad8131121272fe5bc0a85f3aab019ee70aaf343205f7d52a5", Rows: 300},
	{Path: "testdata/evaluation-v4/policy-violations.jsonl", SHA256: "1b5786d2c7ac177a28ef7701ce129e3646ccda7475f5180024caf85cbd695540", Rows: 320},
	{Path: "testdata/evaluation-v5/benign-security.jsonl", SHA256: "589aa8e7609b5d28d6a35577f2908813f97d50ea9fdb152cf926e425518ac842", Rows: 320},
	{Path: "testdata/evaluation-v5/policy-violations.jsonl", SHA256: "ab012072260a953b98bd84c582d5a317fe41df903fd1724aaf80662cbfd19edc", Rows: 320},
	{Path: "testdata/evaluation-v6/evaluation-v6.jsonl", SHA256: "d3b74587a787251f0ddad46189236fbe3059db683fb023583517f0092710b265", Rows: 640},
	{Path: "testdata/holdout/benign-security.jsonl", SHA256: "46736f53d31c3caa7c1d585c3bdfb7bb60848c6d60ae75c12076c35cd2f19e1f", Rows: 246},
	{Path: "testdata/holdout/malicious-operational.jsonl", SHA256: "a86bb28cc509969e2c3f27901413f9a82422c6dbeea98cda68145f47693688cc", Rows: 260},
	{Path: "testdata/holdout-v2/benign-security.jsonl", SHA256: "e88f9a1dc4bd3465b041ab2e636dbde74f7e48aa319b2ff42c26ae46d06b5b4b", Rows: 240},
	{Path: "testdata/holdout-v2/malicious-operational.jsonl", SHA256: "64f1fb64494458a4e937c83970ca0a90b1f9f367e7e021fe7018365fc97d4ab4", Rows: 260},
	{Path: "testdata/holdout-v3/benign-security.jsonl", SHA256: "7edc6d5ff97b04c005bdeb2e66de585b9d50d261a128a54f229af57cb0bb5d25", Rows: 300},
	{Path: "testdata/holdout-v3/malicious-operational.jsonl", SHA256: "8d7ddbae41f0b6f4870febc4b1ba73c490b92b920f19db4f4290b3ff3227710e", Rows: 320},
}

var evaluationV8Prior = appendPriorCorpus(evaluationV7Prior,
	priorCorpus{Path: "testdata/evaluation-v7/evaluation-v7.jsonl", SHA256: "bd7ec34c6b38244d9b2cf28512b2b427c855129f290f9ef1feec13fc545e5afc", Rows: 640},
)

var evaluationV9Prior = appendPriorCorpus(evaluationV8Prior,
	priorCorpus{Path: "testdata/evaluation-v8/evaluation-v8.jsonl", SHA256: "c722af0c6aae0bd909e808c8bb7a25f3e3481d8e135206e4d8e8ab3efb54edcd", Rows: 640},
)

var evaluationV10Prior = appendPriorCorpus(evaluationV9Prior,
	priorCorpus{Path: "testdata/evaluation-v9/evaluation-v9.jsonl", SHA256: "0481ee919f12a267458f99780fdd2c252209de81b89d5e6c9cac156e38c12c0c", Rows: 640},
)

var knownCorpusPaths = func() map[string]struct{} {
	result := make(map[string]struct{}, len(evaluationV10Prior)+1)
	for _, item := range evaluationV10Prior {
		result[filepath.ToSlash(filepath.Clean(item.Path))] = struct{}{}
	}
	result["testdata/evaluation-v10/evaluation-v10.jsonl"] = struct{}{}
	return result
}()

type targetRecord struct {
	ID       string          `json:"id"`
	Split    string          `json:"split"`
	Expected string          `json:"expected"`
	Source   string          `json:"source"`
	Label    string          `json:"label"`
	Taxonomy string          `json:"taxonomy"`
	Language string          `json:"language"`
	Carrier  string          `json:"carrier"`
	Tags     []string        `json:"tags"`
	Input    json.RawMessage `json:"input"`
}

type summary struct {
	DatasetSHA256                string         `json:"dataset_sha256"`
	Lines                        int            `json:"lines"`
	Bytes                        int            `json:"bytes"`
	SchemaFailures               int            `json:"schema_failures"`
	InputObjectFailures          int            `json:"input_object_failures"`
	DuplicateIDs                 int            `json:"duplicate_ids"`
	TagFailures                  int            `json:"tag_failures"`
	ExtractionFailures           int            `json:"extraction_failures"`
	RoleAware                    int            `json:"role_aware"`
	Untrusted                    int            `json:"untrusted"`
	SelfDuplicateGroups          int            `json:"self_duplicate_groups"`
	SelfDuplicateRows            int            `json:"self_duplicate_rows_after_first"`
	PriorFiles                   int            `json:"prior_jsonl_files"`
	PriorRows                    int            `json:"prior_rows"`
	PriorFailures                int            `json:"prior_parse_or_extract_failures"`
	PriorFailureFiles            map[string]int `json:"prior_failure_files,omitempty"`
	CrossOverlapRows             int            `json:"cross_overlap_rows"`
	CrossOverlapHashes           int            `json:"cross_overlap_unique_hashes"`
	Expected                     map[string]int `json:"expected"`
	Taxonomy                     map[string]int `json:"taxonomy"`
	TaxonomyEnumFailures         int            `json:"taxonomy_enum_failures"`
	TaxonomyDistributionFailures int            `json:"taxonomy_distribution_failures"`
	UnexpectedTaxonomies         map[string]int `json:"unexpected_policy_taxonomies,omitempty"`
	MissingTaxonomies            []string       `json:"missing_policy_taxonomies,omitempty"`
	Language                     map[string]int `json:"language"`
	Carrier                      map[string]int `json:"carrier"`
	CarrierBenign                map[string]int `json:"carrier_benign"`
	CarrierPolicy                map[string]int `json:"carrier_policy"`
}

type validationProfile struct {
	Name        string
	PolicyLabel string
	Carriers    []string
	Languages   map[string]int
	Prior       []priorCorpus
}

func main() {
	if len(os.Args) == 2 {
		targetPath = os.Args[1]
	} else if len(os.Args) > 2 {
		fmt.Fprintln(os.Stderr, "usage: evaluation-validator [target.jsonl]")
		os.Exit(2)
	}
	profile := profileForTarget(targetPath)
	if profile.Name == "unsupported" {
		fmt.Fprintf(os.Stderr, "unsupported evaluation target: %s\n", targetPath)
		os.Exit(2)
	}
	requiredFields = requiredFieldsForTarget(targetPath)
	s, err := validate()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(s); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := validateSummary(s, profile); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func profileForTarget(path string) validationProfile {
	slash := filepath.ToSlash(path)
	switch {
	case strings.Contains(slash, "/evaluation-v8/"):
		return validationProfile{
			Name:        "evaluation-v8",
			PolicyLabel: "policy_violation",
			Carriers: []string{
				"openai_chat", "openai_responses", "anthropic_messages", "gemini_contents",
				"generic_prompt", "nested_json", "openai_tool_call", "anthropic_tool_use",
				"gemini_function_call", "responses_function_call", "multi_turn_chat", "url_encoded_prompt",
				"base64_prompt", "unicode_confusable", "zero_width_dialogue", "api_query_wrapper",
			},
			Languages: map[string]int{"en": 227, "zh-CN": 187, "zh-en": 226},
			Prior:     evaluationV8Prior,
		}
	case strings.Contains(slash, "/evaluation-v9/"):
		return validationProfile{
			Name:        "evaluation-v9",
			PolicyLabel: "policy",
			Carriers: []string{
				"openai_chat", "openai_chat_blocks", "openai_responses", "anthropic_messages",
				"gemini_contents", "prompt_scalar", "nested_request", "openai_tool_call",
				"anthropic_tool_use", "gemini_function_call", "tool_result", "url_encoded",
				"html_entity", "base64_text", "text_data_url", "multi_turn",
			},
			Languages: map[string]int{"en": 160, "mixed": 160, "zh": 320},
			Prior:     evaluationV9Prior,
		}
	case strings.Contains(slash, "/evaluation-v10/"):
		return validationProfile{
			Name:        "evaluation-v10",
			PolicyLabel: "policy",
			Carriers: []string{
				"openai_chat_plain", "openai_chat_content_parts", "openai_responses_input", "openai_responses_function_call",
				"anthropic_messages_plain", "anthropic_tool_use", "gemini_contents_plain", "gemini_function_call",
				"tool_arguments_json_string", "tool_parameters_object", "url_encoded_text", "html_entity_text",
				"base64_text", "markdown_fence", "xml_wrapper", "nested_json_text",
			},
			Languages: map[string]int{"en": 320, "zh-CN": 320},
			Prior:     evaluationV10Prior,
		}
	case strings.Contains(slash, "/evaluation-v7/"):
		return validationProfile{
			Name:        "evaluation-v7",
			PolicyLabel: "policy_violation",
			Carriers: []string{
				"openai_chat", "openai_responses", "anthropic_messages", "gemini_contents", "multi_turn_roles",
				"tool_arguments", "base64_text", "url_encoded_text", "html_entity_text", "json_string_text",
			},
			Languages: map[string]int{"en": 214, "mixed": 212, "zh": 214},
			Prior:     evaluationV7Prior,
		}
	default:
		return validationProfile{Name: "unsupported"}
	}
}

func requiredFieldsForTarget(path string) []string {
	targetSlash := filepath.ToSlash(path)
	if strings.Contains(targetSlash, "/evaluation-v8/") || strings.Contains(targetSlash, "/evaluation-v9/") || strings.Contains(targetSlash, "/evaluation-v10/") {
		return []string{"carrier", "id", "input", "label", "language", "source", "tags", "taxonomy"}
	}
	return []string{"carrier", "expected", "id", "input", "language", "split", "tags", "taxonomy"}
}

func appendPriorCorpus(existing []priorCorpus, values ...priorCorpus) []priorCorpus {
	result := make([]priorCorpus, 0, len(existing)+len(values))
	result = append(result, existing...)
	result = append(result, values...)
	return result
}

func validateSummary(s summary, profile validationProfile) error {
	if profile.Name == "unsupported" || len(profile.Carriers) == 0 || len(profile.Prior) == 0 {
		return errors.New("unsupported or incomplete evaluation validation profile")
	}
	failures := make([]string, 0, 16)
	addCountFailure := func(name string, count int) {
		if count != 0 {
			failures = append(failures, fmt.Sprintf("%s=%d", name, count))
		}
	}
	addCountFailure("schema_failures", s.SchemaFailures)
	addCountFailure("input_object_failures", s.InputObjectFailures)
	addCountFailure("duplicate_ids", s.DuplicateIDs)
	addCountFailure("tag_failures", s.TagFailures)
	addCountFailure("extraction_failures", s.ExtractionFailures)
	addCountFailure("self_duplicate_groups", s.SelfDuplicateGroups)
	addCountFailure("self_duplicate_rows", s.SelfDuplicateRows)
	addCountFailure("prior_failures", s.PriorFailures)
	addCountFailure("cross_overlap_rows", s.CrossOverlapRows)
	addCountFailure("cross_overlap_hashes", s.CrossOverlapHashes)
	addCountFailure("taxonomy_enum_failures", s.TaxonomyEnumFailures)
	addCountFailure("taxonomy_distribution_failures", s.TaxonomyDistributionFailures)

	if len(s.DatasetSHA256) != sha256.Size*2 {
		failures = append(failures, "dataset_sha256 is missing or malformed")
	}
	if s.Lines != 640 {
		failures = append(failures, fmt.Sprintf("lines=%d want=640", s.Lines))
	}
	if s.Bytes <= 0 {
		failures = append(failures, fmt.Sprintf("bytes=%d want>0", s.Bytes))
	}
	if s.RoleAware+s.Untrusted != s.Lines {
		failures = append(failures, fmt.Sprintf("extraction_path_rows=%d want=%d", s.RoleAware+s.Untrusted, s.Lines))
	}
	wantPriorRows := 0
	for _, item := range profile.Prior {
		wantPriorRows += item.Rows
	}
	if s.PriorFiles != len(profile.Prior) || s.PriorRows != wantPriorRows {
		failures = append(failures, fmt.Sprintf(
			"prior corpus inventory files=%d rows=%d want files=%d rows=%d",
			s.PriorFiles,
			s.PriorRows,
			len(profile.Prior),
			wantPriorRows,
		))
	}
	if len(s.PriorFailureFiles) != 0 {
		failures = append(failures, "prior_failure_files is non-empty")
	}
	if len(s.UnexpectedTaxonomies) != 0 {
		failures = append(failures, "unexpected_policy_taxonomies is non-empty")
	}
	if len(s.MissingTaxonomies) != 0 {
		failures = append(failures, "missing_policy_taxonomies is non-empty")
	}

	wantExpected := map[string]int{"benign": 320, profile.PolicyLabel: 320}
	checkDistribution(&failures, "expected", s.Expected, wantExpected)
	wantTaxonomy := map[string]int{"benign": 320}
	for _, taxonomy := range requiredPolicyTaxonomies {
		wantTaxonomy[taxonomy] = 40
	}
	checkDistribution(&failures, "taxonomy", s.Taxonomy, wantTaxonomy)
	checkDistribution(&failures, "language", s.Language, profile.Languages)

	perCarrier := 640 / len(profile.Carriers)
	perCarrierLabel := 320 / len(profile.Carriers)
	wantCarrier := make(map[string]int, len(profile.Carriers))
	wantCarrierLabel := make(map[string]int, len(profile.Carriers))
	for _, carrier := range profile.Carriers {
		wantCarrier[carrier] = perCarrier
		wantCarrierLabel[carrier] = perCarrierLabel
	}
	checkDistribution(&failures, "carrier", s.Carrier, wantCarrier)
	checkDistribution(&failures, "carrier_benign", s.CarrierBenign, wantCarrierLabel)
	checkDistribution(&failures, "carrier_policy", s.CarrierPolicy, wantCarrierLabel)

	if len(failures) != 0 {
		return fmt.Errorf("%s validation failed: %s", profile.Name, strings.Join(failures, "; "))
	}
	return nil
}

func checkDistribution(failures *[]string, name string, got, want map[string]int) {
	if equalCounts(got, want) {
		return
	}
	*failures = append(*failures, fmt.Sprintf("%s=%s want=%s", name, formatCounts(got), formatCounts(want)))
}

func equalCounts(left, right map[string]int) bool {
	if len(left) != len(right) {
		return false
	}
	for key, count := range right {
		if left[key] != count {
			return false
		}
	}
	return true
}

func formatCounts(counts map[string]int) string {
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s:%d", key, counts[key]))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func validate() (summary, error) {
	s := summary{
		Expected:             map[string]int{},
		Taxonomy:             map[string]int{},
		Language:             map[string]int{},
		Carrier:              map[string]int{},
		CarrierBenign:        map[string]int{},
		CarrierPolicy:        map[string]int{},
		UnexpectedTaxonomies: map[string]int{},
	}
	data, err := os.ReadFile(targetPath)
	if err != nil {
		return s, err
	}
	digest := sha256.Sum256(data)
	s.DatasetSHA256 = hex.EncodeToString(digest[:])
	s.Bytes = len(data)
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return s, fmt.Errorf("target is not newline terminated")
	}

	ids := map[string]struct{}{}
	semanticCounts := map[[32]byte]int{}
	targetHashes := make([][32]byte, 0, 640)
	for _, line := range bytes.Split(data[:len(data)-1], []byte{'\n'}) {
		s.Lines++
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(line, &fields); err != nil || !exactFields(fields) {
			s.SchemaFailures++
			continue
		}
		var row targetRecord
		if err := decodeStrict(line, &row); err != nil {
			s.SchemaFailures++
			continue
		}
		if row.ID == "" {
			s.SchemaFailures++
		}
		if _, exists := ids[row.ID]; exists {
			s.DuplicateIDs++
		}
		ids[row.ID] = struct{}{}
		input := bytes.TrimSpace(row.Input)
		if len(input) < 2 || input[0] != '{' || input[len(input)-1] != '}' {
			s.InputObjectFailures++
		}
		if invalidTags(row.Tags) {
			s.TagFailures++
		}

		canonical, roleAware, err := canonicalExtract(row.Input)
		if err != nil {
			s.ExtractionFailures++
		} else {
			if roleAware {
				s.RoleAware++
			} else {
				s.Untrusted++
			}
			h := sha256.Sum256([]byte(canonical))
			semanticCounts[h]++
			targetHashes = append(targetHashes, h)
		}
		expected := row.Expected
		if expected == "" {
			expected = row.Label
		}
		if expected == "policy" || expected == "policy_violation" {
			if !requiredPolicyTaxonomy(row.Taxonomy) {
				s.TaxonomyEnumFailures++
				s.UnexpectedTaxonomies[row.Taxonomy]++
			}
		}
		s.Expected[expected]++
		s.Taxonomy[row.Taxonomy]++
		s.Language[row.Language]++
		s.Carrier[row.Carrier]++
		if expected == "benign" {
			s.CarrierBenign[row.Carrier]++
		} else if expected == "policy_violation" || expected == "policy" {
			s.CarrierPolicy[row.Carrier]++
		}
	}
	for _, count := range semanticCounts {
		if count > 1 {
			s.SelfDuplicateGroups++
			s.SelfDuplicateRows += count - 1
		}
	}
	for _, taxonomy := range requiredPolicyTaxonomies {
		if s.Taxonomy[taxonomy] != 40 {
			s.TaxonomyDistributionFailures++
			if s.Taxonomy[taxonomy] == 0 {
				s.MissingTaxonomies = append(s.MissingTaxonomies, taxonomy)
			}
		}
	}

	priorHashes, files, rows, failures, failureFiles, err := loadPriorHashes(profileForTarget(targetPath))
	if err != nil {
		return s, err
	}
	s.PriorFiles, s.PriorRows, s.PriorFailures, s.PriorFailureFiles = files, rows, failures, failureFiles
	overlapHashes := map[[32]byte]struct{}{}
	for _, h := range targetHashes {
		if _, exists := priorHashes[h]; exists {
			s.CrossOverlapRows++
			overlapHashes[h] = struct{}{}
		}
	}
	s.CrossOverlapHashes = len(overlapHashes)
	return s, nil
}

func loadPriorHashes(profile validationProfile) (map[[32]byte]struct{}, int, int, int, map[string]int, error) {
	return loadPriorHashesFrom(testdataRootForTarget(targetPath), targetPath, profile.Prior)
}

func testdataRootForTarget(path string) string {
	directory := filepath.Dir(filepath.Clean(path))
	for {
		if filepath.Base(directory) == "testdata" {
			return directory
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return "testdata"
		}
		directory = parent
	}
}

func loadPriorHashesFrom(root, target string, inventory []priorCorpus) (map[[32]byte]struct{}, int, int, int, map[string]int, error) {
	inventoryBase := filepath.Dir(filepath.Clean(root))
	expected := make(map[string]priorCorpus, len(inventory))
	for _, item := range inventory {
		clean := filepath.ToSlash(filepath.Clean(item.Path))
		if clean == "." || item.SHA256 == "" || item.Rows <= 0 {
			return nil, 0, 0, 0, nil, fmt.Errorf("invalid frozen prior corpus entry: %+v", item)
		}
		if _, exists := expected[clean]; exists {
			return nil, 0, 0, 0, nil, fmt.Errorf("duplicate frozen prior corpus path %s", clean)
		}
		expected[clean] = item
	}
	targetAbsolute, err := filepath.Abs(target)
	if err != nil {
		return nil, 0, 0, 0, nil, fmt.Errorf("resolve target path: %w", err)
	}
	seen := make(map[string]struct{}, len(inventory))
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if path != root && strings.Contains(entry.Name(), ".tmp-") {
				return fmt.Errorf("unexpected fixture staging directory %s", filepath.ToSlash(path))
			}
			return nil
		}
		if !strings.EqualFold(filepath.Ext(path), ".jsonl") {
			return nil
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		if filepath.Clean(absolute) == filepath.Clean(targetAbsolute) {
			return nil
		}
		relative, err := filepath.Rel(inventoryBase, path)
		if err != nil {
			return err
		}
		clean := filepath.ToSlash(filepath.Clean(relative))
		if _, ok := expected[clean]; ok {
			seen[clean] = struct{}{}
			return nil
		}
		if _, known := knownCorpusPaths[clean]; known {
			// A later frozen evaluation is not prior data for an earlier profile.
			return nil
		}
		return fmt.Errorf("unexpected corpus file %s", clean)
	})
	if err != nil {
		return nil, 0, 0, 0, nil, err
	}
	paths := make([]string, 0, len(inventory))
	for clean := range expected {
		if _, ok := seen[clean]; !ok {
			return nil, 0, 0, 0, nil, fmt.Errorf("missing frozen prior corpus file %s", clean)
		}
		paths = append(paths, filepath.Join(inventoryBase, filepath.FromSlash(clean)))
	}
	sort.Strings(paths)
	hashes := map[[32]byte]struct{}{}
	rows, failures := 0, 0
	failureFiles := map[string]int{}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, 0, 0, 0, nil, err
		}
		digest := sha256.Sum256(data)
		relative, err := filepath.Rel(inventoryBase, path)
		if err != nil {
			return nil, 0, 0, 0, nil, err
		}
		clean := filepath.ToSlash(filepath.Clean(relative))
		item := expected[clean]
		if hex.EncodeToString(digest[:]) != item.SHA256 {
			return nil, 0, 0, 0, nil, fmt.Errorf("prior corpus hash mismatch for %s", clean)
		}
		if lineCount := bytes.Count(data, []byte{'\n'}); lineCount != item.Rows || len(data) == 0 || data[len(data)-1] != '\n' {
			return nil, 0, 0, 0, nil, fmt.Errorf("prior corpus row mismatch for %s: got %d want %d", clean, lineCount, item.Rows)
		}
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
		for scanner.Scan() {
			rows++
			body, err := priorInput(scanner.Bytes())
			if err != nil {
				failures++
				failureFiles[filepath.ToSlash(path)]++
				continue
			}
			canonical, err := canonicalExtractPrior(body)
			if err != nil {
				failures++
				failureFiles[filepath.ToSlash(path)]++
				continue
			}
			hashes[sha256.Sum256([]byte(canonical))] = struct{}{}
		}
		if err := scanner.Err(); err != nil {
			return nil, 0, 0, 0, nil, err
		}
	}
	return hashes, len(paths), rows, failures, failureFiles, nil
}

func priorInput(line []byte) (json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(line, &fields); err != nil {
		return nil, err
	}
	for _, key := range []string{"input", "request", "payload", "segments"} {
		if raw, ok := fields[key]; ok {
			trimmed := bytes.TrimSpace(raw)
			if len(trimmed) > 0 && trimmed[0] == '{' {
				return raw, nil
			}
			if len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null")) {
				wrapperKey := "input"
				if key == "segments" {
					wrapperKey = "messages"
				}
				return json.Marshal(map[string]json.RawMessage{wrapperKey: raw})
			}
		}
	}
	if raw, ok := fields["text"]; ok {
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, err
		}
		return json.Marshal(map[string]string{"input": value})
	}
	return nil, fmt.Errorf("no supported semantic field")
}

func canonicalExtract(body json.RawMessage) (string, bool, error) {
	result, err := extract.ExtractText(body, extract.Limits{})
	if err != nil || result.ParseError != "" || result.Truncated {
		return "", false, fmt.Errorf("production extraction failed")
	}
	canonical, err := canonicalFromResult(result)
	return canonical, result.RoleAware, err
}

func canonicalExtractPrior(body json.RawMessage) (string, error) {
	result, err := extract.ExtractText(body, extract.Limits{})
	if err == nil && result.ParseError == "" {
		if canonical, candidateErr := canonicalFromResult(result); candidateErr == nil {
			return canonical, nil
		}
	}
	return canonicalFromJSON(body)
}

func canonicalFromResult(result extract.Result) (string, error) {
	candidates := make([]string, 0, len(result.Parts)+len(result.Segments))
	if result.RoleAware {
		for _, segment := range result.Segments {
			if segment.Provenance == extract.ProvenanceToolPayload {
				candidates = append(candidates, segment.Text)
			}
		}
		if len(candidates) == 0 {
			for _, segment := range result.Segments {
				if segment.Role == extract.RoleUser {
					candidates = append(candidates, segment.Text)
				}
			}
		}
		if len(candidates) == 0 {
			for _, segment := range result.Segments {
				candidates = append(candidates, segment.Text)
			}
		}
	} else {
		candidates = append(candidates, result.Parts...)
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("empty extraction")
	}
	best := ""
	bestScore := -1 << 30
	for _, candidate := range candidates {
		if score := semanticScore(candidate); score > bestScore {
			best, bestScore = candidate, score
		}
	}
	canonical := normalize(best)
	if canonical == "" {
		return "", fmt.Errorf("empty canonical semantic")
	}
	return canonical, nil
}

func canonicalFromJSON(body json.RawMessage) (string, error) {
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		return "", err
	}
	candidates := make([]string, 0, 8)
	collectSemanticStrings(value, "", &candidates)
	if len(candidates) == 0 {
		return "", fmt.Errorf("no semantic JSON strings")
	}
	best, bestScore := "", -1<<30
	for _, candidate := range candidates {
		if score := semanticScore(candidate); score > bestScore {
			best, bestScore = candidate, score
		}
	}
	canonical := normalize(best)
	if canonical == "" {
		return "", fmt.Errorf("empty fallback semantic")
	}
	return canonical, nil
}

func collectSemanticStrings(value any, key string, candidates *[]string) {
	switch typed := value.(type) {
	case string:
		switch strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "_", ""), "-", "")) {
		case "role", "type", "name", "id", "model", "status", "encoding", "source", "category", "language", "structure", "provider", "label":
			return
		}
		if strings.TrimSpace(typed) != "" {
			*candidates = append(*candidates, typed)
		}
	case []any:
		for _, item := range typed {
			collectSemanticStrings(item, key, candidates)
		}
	case map[string]any:
		for childKey, child := range typed {
			collectSemanticStrings(child, childKey, candidates)
		}
	}
}

func semanticScore(value string) int {
	score, letters, spaces, asciiToken := 0, 0, 0, 0
	for _, r := range value {
		switch {
		case unicode.IsLetter(r):
			score += 4
			letters++
			if r <= unicode.MaxASCII {
				asciiToken++
			}
		case unicode.IsNumber(r):
			score++
			asciiToken++
		case unicode.IsSpace(r):
			score += 3
			spaces++
		case strings.ContainsRune("%+&;{}[]\\\"", r):
			score -= 3
		}
	}
	if spaces == 0 && len(value) >= 48 && asciiToken*100 >= len(value)*85 {
		score -= len(value) * 2
	}
	if strings.Contains(value, "%") || (strings.Contains(value, "&") && strings.Contains(value, ";")) {
		score -= len(value) / 2
	}
	if letters == 0 {
		score -= 1000
	}
	return score
}

func normalize(value string) string {
	value = norm.NFKC.String(strings.ToLower(value))
	value = strings.Map(func(r rune) rune {
		switch r {
		case '\u200b', '\u200c', '\u200d', '\u2060', '\ufeff':
			return -1
		default:
			return r
		}
	}, value)
	return strings.Join(strings.Fields(value), " ")
}

func exactFields(fields map[string]json.RawMessage) bool {
	if len(fields) != len(requiredFields) {
		return false
	}
	for _, field := range requiredFields {
		if _, exists := fields[field]; !exists {
			return false
		}
	}
	return true
}

func invalidTags(tags []string) bool {
	if len(tags) == 0 {
		return true
	}
	seen := map[string]struct{}{}
	for _, tag := range tags {
		if strings.TrimSpace(tag) == "" {
			return true
		}
		if _, exists := seen[tag]; exists {
			return true
		}
		seen[tag] = struct{}{}
	}
	return false
}

func requiredPolicyTaxonomy(value string) bool {
	for _, taxonomy := range requiredPolicyTaxonomies {
		if value == taxonomy {
			return true
		}
	}
	return false
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}
