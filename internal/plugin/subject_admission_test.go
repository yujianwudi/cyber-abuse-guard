package plugin

import (
	"net/http"
	"testing"

	"github.com/yujianwudi/cyber-abuse-guard/internal/classifier"
	"github.com/yujianwudi/cyber-abuse-guard/internal/extract"
	"github.com/yujianwudi/cyber-abuse-guard/internal/subject"
)

func TestSubjectAccumulationEligibility(t *testing.T) {
	t.Parallel()

	validIdentity := subject.Identity{Hash: "hmac-sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Source: subject.SourceAuthorization}
	validResult := classifier.Result{
		Score:             80,
		Action:            classifier.ActionBlock,
		Coverage:          classifier.Coverage{State: classifier.CoverageComplete},
		FindingConfidence: classifier.FindingCompleteRequest,
		Behavior:          &classifier.BehaviorGraph{BaseBehavior: true},
	}
	tests := []struct {
		name       string
		identity   subject.Identity
		result     classifier.Result
		incomplete []extract.IncompleteReason
		hardBlock  int
		want       bool
	}{
		{name: "authorization hard block", identity: validIdentity, result: validResult, hardBlock: 80, want: true},
		{name: "api key hard block", identity: subject.Identity{Hash: validIdentity.Hash, Source: subject.SourceAPIKey}, result: validResult, hardBlock: 80, want: true},
		{name: "anonymous", identity: subject.Identity{Hash: validIdentity.Hash, Source: subject.SourceAnonymous}, result: validResult, hardBlock: 80},
		{name: "unknown identity source", identity: subject.Identity{Hash: validIdentity.Hash, Source: subject.Source("future_source")}, result: validResult, hardBlock: 80},
		{name: "missing identity hash", identity: subject.Identity{Source: subject.SourceAuthorization}, result: validResult, hardBlock: 80},
		{name: "extractor incomplete", identity: validIdentity, result: validResult, incomplete: []extract.IncompleteReason{extract.IncompleteParseError}, hardBlock: 80},
		{name: "classifier coverage incomplete", identity: validIdentity, result: func() classifier.Result {
			result := validResult
			result.Coverage.State = classifier.CoverageBudgetExhausted
			return result
		}(), hardBlock: 80},
		{name: "finding not complete request", identity: validIdentity, result: func() classifier.Result {
			result := validResult
			result.FindingConfidence = classifier.FindingVerifiedLocalHardBlock
			return result
		}(), hardBlock: 80},
		{name: "missing behavior graph", identity: validIdentity, result: func() classifier.Result {
			result := validResult
			result.Behavior = nil
			return result
		}(), hardBlock: 80},
		{name: "wrapper without base behavior", identity: validIdentity, result: func() classifier.Result {
			result := validResult
			result.Behavior = &classifier.BehaviorGraph{Wrapper: true}
			return result
		}(), hardBlock: 80},
		{name: "not direct block", identity: validIdentity, result: func() classifier.Result {
			result := validResult
			result.Action = classifier.ActionAudit
			return result
		}(), hardBlock: 80},
		{name: "below hard threshold", identity: validIdentity, result: func() classifier.Result {
			result := validResult
			result.Score = 79
			return result
		}(), hardBlock: 80},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if got := subjectAccumulationEligible(testCase.identity, testCase.result, testCase.incomplete, testCase.hardBlock); got != testCase.want {
				t.Fatalf("subjectAccumulationEligible() = %t, want %t", got, testCase.want)
			}
		})
	}
}

func TestAnonymousHardBlockBypassesSubjectStateWithoutChangingDirectBlock(t *testing.T) {
	t.Setenv(subject.HMACKeyEnvironment, "0123456789abcdef0123456789abcdef")
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, "mode: balanced\naudit:\n  enabled: false\nsubject_control:\n  enabled: true\n  max_subjects: 32\n")

	anonymous := p.identifier.Anonymous()
	route := callRouteWithHeaders(t, p, maliciousRequest, nil)
	if !route.Handled || route.Reason != "cyber_abuse_guard_hard_policy" {
		t.Fatalf("anonymous direct hard block changed: %+v", route)
	}
	if state, present := p.runtime.Load().subject.Snapshot(anonymous.Hash); present {
		t.Fatalf("anonymous request persisted subject state: %+v", state)
	}
	if got := p.runtime.Load().subject.Count(); got != 0 {
		t.Fatalf("anonymous request allocated %d subjects", got)
	}

	headers := http.Header{"Authorization": []string{"Bearer admitted-subject"}}
	route = callRouteWithHeaders(t, p, maliciousRequest, headers)
	if !route.Handled || route.Reason != "cyber_abuse_guard_hard_policy" {
		t.Fatalf("authenticated direct hard block changed: %+v", route)
	}
	subjectHash := p.identifier.FromHeaders(headers).Hash
	state, present := p.runtime.Load().subject.Snapshot(subjectHash)
	if !present || state.HitCount != 1 {
		t.Fatalf("authenticated hard block subject state=%+v present=%t, want one hit", state, present)
	}
}
