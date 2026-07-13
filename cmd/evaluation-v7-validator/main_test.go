package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestValidateSummaryAcceptsFixedProfiles(t *testing.T) {
	t.Parallel()
	paths := []string{
		"testdata/evaluation-v7/evaluation-v7.jsonl",
		"testdata/evaluation-v8/evaluation-v8.jsonl",
		"testdata/evaluation-v9/evaluation-v9.jsonl",
		"testdata/evaluation-v10/evaluation-v10.jsonl",
	}
	for _, path := range paths {
		profile := profileForTarget(path)
		if err := validateSummary(validSummary(profile), profile); err != nil {
			t.Fatalf("%s: %v", profile.Name, err)
		}
	}
}

func TestUnknownEvaluationProfileIsRejected(t *testing.T) {
	t.Parallel()
	profile := profileForTarget("testdata/evaluation-v11/evaluation-v11.jsonl")
	if profile.Name != "unsupported" {
		t.Fatalf("unknown target selected profile %q", profile.Name)
	}
	if err := validateSummary(summary{}, profile); err == nil {
		t.Fatal("unsupported profile was accepted")
	}
}

func TestValidateFrozenDatasetsAgainstVersionedPriorInventories(t *testing.T) {
	previousTarget := targetPath
	previousFields := requiredFields
	t.Cleanup(func() {
		targetPath = previousTarget
		requiredFields = previousFields
	})
	for _, relative := range []string{
		"testdata/evaluation-v7/evaluation-v7.jsonl",
		"testdata/evaluation-v8/evaluation-v8.jsonl",
		"testdata/evaluation-v10/evaluation-v10.jsonl",
	} {
		path := filepath.Join(validatorRepositoryRoot(t), filepath.FromSlash(relative))
		targetPath = path
		requiredFields = requiredFieldsForTarget(path)
		result, err := validate()
		if err != nil {
			t.Fatalf("%s static validation: %v", path, err)
		}
		if err := validateSummary(result, profileForTarget(path)); err != nil {
			t.Fatalf("%s summary validation: %v", path, err)
		}
	}
}

func TestValidateV9FailsForTaxonomyNotFutureInventory(t *testing.T) {
	previousTarget := targetPath
	previousFields := requiredFields
	t.Cleanup(func() {
		targetPath = previousTarget
		requiredFields = previousFields
	})
	targetPath = filepath.Join(validatorRepositoryRoot(t), filepath.FromSlash("testdata/evaluation-v9/evaluation-v9.jsonl"))
	requiredFields = requiredFieldsForTarget(targetPath)
	result, err := validate()
	if err != nil {
		t.Fatalf("v9 static validation failed before taxonomy gate: %v", err)
	}
	err = validateSummary(result, profileForTarget(targetPath))
	if err == nil || !strings.Contains(err.Error(), "taxonomy") || strings.Contains(err.Error(), "prior corpus inventory") {
		t.Fatalf("v9 failure did not isolate taxonomy methodology: %v", err)
	}
}

func validatorRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
}

func TestValidateSummaryRejectsEveryHardFailureCounter(t *testing.T) {
	t.Parallel()
	profile := profileForTarget("testdata/evaluation-v10/evaluation-v10.jsonl")
	tests := []struct {
		name   string
		mutate func(*summary)
	}{
		{"schema", func(s *summary) { s.SchemaFailures = 1 }},
		{"input object", func(s *summary) { s.InputObjectFailures = 1 }},
		{"duplicate id", func(s *summary) { s.DuplicateIDs = 1 }},
		{"tag", func(s *summary) { s.TagFailures = 1 }},
		{"extraction", func(s *summary) { s.ExtractionFailures = 1 }},
		{"self duplicate group", func(s *summary) { s.SelfDuplicateGroups = 1 }},
		{"self duplicate row", func(s *summary) { s.SelfDuplicateRows = 1 }},
		{"prior parse", func(s *summary) { s.PriorFailures = 1 }},
		{"overlap row", func(s *summary) { s.CrossOverlapRows = 1 }},
		{"overlap hash", func(s *summary) { s.CrossOverlapHashes = 1 }},
		{"taxonomy enum", func(s *summary) { s.TaxonomyEnumFailures = 1 }},
		{"taxonomy distribution", func(s *summary) { s.TaxonomyDistributionFailures = 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := validSummary(profile)
			test.mutate(&s)
			if err := validateSummary(s, profile); err == nil {
				t.Fatal("hard failure counter did not fail validation")
			}
		})
	}
}

func TestValidateSummaryRejectsScaleAndDistributionDrift(t *testing.T) {
	t.Parallel()
	profile := profileForTarget("testdata/evaluation-v10/evaluation-v10.jsonl")
	tests := []struct {
		name   string
		mutate func(*summary)
	}{
		{"lines", func(s *summary) { s.Lines-- }},
		{"labels", func(s *summary) { s.Expected[profile.PolicyLabel]-- }},
		{"taxonomy", func(s *summary) { s.Taxonomy[requiredPolicyTaxonomies[0]]-- }},
		{"language", func(s *summary) { s.Language["en"]-- }},
		{"carrier", func(s *summary) { s.Carrier[profile.Carriers[0]]-- }},
		{"carrier benign", func(s *summary) { s.CarrierBenign[profile.Carriers[0]]-- }},
		{"carrier policy", func(s *summary) { s.CarrierPolicy[profile.Carriers[0]]-- }},
		{"empty prior corpus", func(s *summary) { s.PriorFiles = 0 }},
		{"path accounting", func(s *summary) { s.Untrusted-- }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := validSummary(profile)
			test.mutate(&s)
			if err := validateSummary(s, profile); err == nil {
				t.Fatal("scale or distribution drift did not fail validation")
			}
		})
	}
}

func TestV9ProfileStillEnforcesFixedTaxonomyContract(t *testing.T) {
	t.Parallel()
	profile := profileForTarget("testdata/evaluation-v9/evaluation-v9.jsonl")
	s := validSummary(profile)
	delete(s.Taxonomy, "phishing_deployment")
	s.Taxonomy["phishing_social_engineering"] = 40
	if err := validateSummary(s, profile); err == nil || !strings.Contains(err.Error(), "taxonomy") {
		t.Fatalf("v9 taxonomy contract drift was not rejected: %v", err)
	}
}

func TestProfilesFreezeCompletePriorInventories(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path  string
		files int
		rows  int
	}{
		{path: "testdata/evaluation-v7/evaluation-v7.jsonl", files: 13, rows: 3822},
		{path: "testdata/evaluation-v8/evaluation-v8.jsonl", files: 14, rows: 4462},
		{path: "testdata/evaluation-v9/evaluation-v9.jsonl", files: 15, rows: 5102},
		{path: "testdata/evaluation-v10/evaluation-v10.jsonl", files: 16, rows: 5742},
	}
	for _, test := range tests {
		profile := profileForTarget(test.path)
		rows := 0
		for _, item := range profile.Prior {
			rows += item.Rows
		}
		if len(profile.Prior) != test.files || rows != test.rows {
			t.Fatalf("%s prior inventory files=%d rows=%d want files=%d rows=%d", profile.Name, len(profile.Prior), rows, test.files, test.rows)
		}
	}
}

func TestLoadPriorHashesRequiresFrozenInventory(t *testing.T) {
	t.Run("accepts exact inventory", func(t *testing.T) {
		root, target, inventory, _ := writePriorFixture(t)
		_, files, rows, failures, _, err := loadPriorHashesFrom(root, target, inventory)
		if err != nil || files != 1 || rows != 1 || failures != 0 {
			t.Fatalf("loadPriorHashesFrom files=%d rows=%d failures=%d err=%v", files, rows, failures, err)
		}
	})
	t.Run("rejects missing file", func(t *testing.T) {
		root, target, inventory, path := writePriorFixture(t)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if _, _, _, _, _, err := loadPriorHashesFrom(root, target, inventory); err == nil || !strings.Contains(err.Error(), "missing") {
			t.Fatalf("missing prior corpus was not rejected: %v", err)
		}
	})
	t.Run("rejects unknown file", func(t *testing.T) {
		root, target, inventory, _ := writePriorFixture(t)
		unknown := filepath.Join(root, "unknown.jsonl")
		if err := os.WriteFile(unknown, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, _, _, _, err := loadPriorHashesFrom(root, target, inventory); err == nil || !strings.Contains(err.Error(), "unexpected") {
			t.Fatalf("unknown prior corpus was not rejected: %v", err)
		}
	})
	t.Run("rejects hash drift", func(t *testing.T) {
		root, target, inventory, path := writePriorFixture(t)
		if err := os.WriteFile(path, []byte(`{"input":{"prompt":"changed"}}`+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, _, _, _, err := loadPriorHashesFrom(root, target, inventory); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
			t.Fatalf("prior corpus hash drift was not rejected: %v", err)
		}
	})
	t.Run("rejects staging directory", func(t *testing.T) {
		root, target, inventory, _ := writePriorFixture(t)
		if err := os.Mkdir(filepath.Join(root, ".holdout.tmp-incomplete"), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, _, _, _, _, err := loadPriorHashesFrom(root, target, inventory); err == nil || !strings.Contains(err.Error(), "staging") {
			t.Fatalf("staging directory was not rejected: %v", err)
		}
	})
}

func writePriorFixture(t *testing.T) (root, target string, inventory []priorCorpus, path string) {
	t.Helper()
	base := t.TempDir()
	root = filepath.Join(base, "testdata")
	path = filepath.Join(root, "prior", "prior.jsonl")
	target = filepath.Join(root, "evaluation", "target.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	data := []byte(`{"input":{"prompt":"hello"}}` + "\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	inventory = []priorCorpus{{
		Path:   "testdata/prior/prior.jsonl",
		SHA256: hex.EncodeToString(digest[:]),
		Rows:   1,
	}}
	return root, target, inventory, path
}

func validSummary(profile validationProfile) summary {
	priorRows := 0
	for _, item := range profile.Prior {
		priorRows += item.Rows
	}
	s := summary{
		DatasetSHA256:        strings.Repeat("a", 64),
		Lines:                640,
		Bytes:                1,
		RoleAware:            320,
		Untrusted:            320,
		PriorFiles:           len(profile.Prior),
		PriorRows:            priorRows,
		Expected:             map[string]int{"benign": 320, profile.PolicyLabel: 320},
		Taxonomy:             map[string]int{"benign": 320},
		Language:             cloneCounts(profile.Languages),
		Carrier:              map[string]int{},
		CarrierBenign:        map[string]int{},
		CarrierPolicy:        map[string]int{},
		UnexpectedTaxonomies: map[string]int{},
	}
	for _, taxonomy := range requiredPolicyTaxonomies {
		s.Taxonomy[taxonomy] = 40
	}
	for _, carrier := range profile.Carriers {
		s.Carrier[carrier] = 640 / len(profile.Carriers)
		s.CarrierBenign[carrier] = 320 / len(profile.Carriers)
		s.CarrierPolicy[carrier] = 320 / len(profile.Carriers)
	}
	return s
}

func cloneCounts(source map[string]int) map[string]int {
	result := make(map[string]int, len(source))
	for key, count := range source {
		result[key] = count
	}
	return result
}
