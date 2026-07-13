package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

func main() {
	if len(os.Args) == 2 {
		targetPath = os.Args[1]
	} else if len(os.Args) > 2 {
		fmt.Fprintln(os.Stderr, "usage: evaluation-validator [target.jsonl]")
		os.Exit(2)
	}
	targetSlash := filepath.ToSlash(targetPath)
	if strings.Contains(targetSlash, "/evaluation-v8/") || strings.Contains(targetSlash, "/evaluation-v9/") || strings.Contains(targetSlash, "/evaluation-v10/") {
		requiredFields = []string{"carrier", "id", "input", "label", "language", "source", "tags", "taxonomy"}
	}
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
	if s.TaxonomyEnumFailures != 0 || s.TaxonomyDistributionFailures != 0 {
		os.Exit(1)
	}
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

	priorHashes, files, rows, failures, failureFiles, err := loadPriorHashes()
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

func loadPriorHashes() (map[[32]byte]struct{}, int, int, int, map[string]int, error) {
	paths := make([]string, 0, 16)
	err := filepath.WalkDir("testdata", func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.EqualFold(filepath.Ext(path), ".jsonl") && filepath.Clean(path) != filepath.Clean(targetPath) {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, 0, 0, 0, nil, err
	}
	sort.Strings(paths)
	hashes := map[[32]byte]struct{}{}
	rows, failures := 0, 0
	failureFiles := map[string]int{}
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			return nil, 0, 0, 0, nil, err
		}
		scanner := bufio.NewScanner(file)
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
			_ = file.Close()
			return nil, 0, 0, 0, nil, err
		}
		if err := file.Close(); err != nil {
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
