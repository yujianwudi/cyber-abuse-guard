package classifier

// ClassifierPolicyVersion identifies the behavior-model contract independently
// from the separately versioned YAML ruleset.
const ClassifierPolicyVersion = "classifier-policy-v2"

// ClassifierPolicySHA256 binds the deterministic classifier, role handling,
// bounded extractor, rules schema, and embedded policy sources listed in
// policy_identity_test.go. It is updated only when one of those sources changes.
const ClassifierPolicySHA256 = "a28c9da8eeea0420f33d9fb421b662108b7944f9f49e1f14083b951f181993b0"

// PolicyIdentity is safe to expose through management or audit metadata: it
// contains only stable identifiers and never includes request text.
type PolicyIdentity struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

// CurrentPolicyIdentity returns the compiled classifier behavior identity.
func CurrentPolicyIdentity() PolicyIdentity {
	return PolicyIdentity{Version: ClassifierPolicyVersion, SHA256: ClassifierPolicySHA256}
}
