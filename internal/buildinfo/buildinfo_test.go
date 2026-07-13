package buildinfo

import "testing"

func TestCurrentReturnsNormalizedCopy(t *testing.T) {
	originalVersion, originalCommit := Version, Commit
	originalRulesetVersion, originalRulesetSHA := RulesetVersion, RulesetSHA256
	originalDirty := Dirty
	t.Cleanup(func() {
		Version, Commit = originalVersion, originalCommit
		RulesetVersion, RulesetSHA256 = originalRulesetVersion, originalRulesetSHA
		Dirty = originalDirty
	})

	Version = " 0.1.2 "
	Commit = " abc123 "
	RulesetVersion = " 1.0.7 "
	RulesetSHA256 = " AABBCC "
	Dirty = " FALSE "

	got := Current()
	if got.Version != "0.1.2" || got.Commit != "abc123" || got.RulesetVersion != "1.0.7" || got.RulesetSHA256 != "aabbcc" || got.Dirty {
		t.Fatalf("Current() = %#v", got)
	}
}
