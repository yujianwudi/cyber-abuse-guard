package plugin

import (
	"testing"

	"github.com/yujianwudi/cyber-abuse-guard/internal/classifier"
	"github.com/yujianwudi/cyber-abuse-guard/internal/config"
	"github.com/yujianwudi/cyber-abuse-guard/internal/extract"
)

func TestInspectionDispositionIncompleteOverridesMaliciousPrefix(t *testing.T) {
	reasons := []extract.IncompleteReason{
		extract.IncompleteParseError,
		extract.IncompleteScanByteLimit,
		extract.IncompleteJSONDepthLimit,
		extract.IncompleteJSONTokenLimit,
		extract.IncompleteJSONNodeLimit,
		extract.IncompleteTextPartLimit,
		extract.IncompleteTextPartByteLimit,
		extract.IncompleteMultipartBoundaryLimit,
		extract.IncompleteMultipartPartLimit,
		extract.IncompleteMultipartHeaderLimit,
		extract.IncompleteMultipartTextLimit,
		extract.IncompleteMultipartParseError,
		extract.IncompleteMultipartUnknownField,
		extract.IncompleteMultipartTextFieldTypeMismatch,
		extract.IncompleteDeferredTextCandidateLimit,
		extract.IncompleteUnsupportedMediaType,
		extract.IncompleteUnsupportedContentEncoding,
		extract.IncompleteRawBodyLimit,
		extract.IncompleteRPCBodyLimit,
	}
	modes := []struct {
		mode            config.Mode
		wantBlock       bool
		wantAudit       bool
		wantObserve     bool
		wantSubjectEval bool
	}{
		{mode: config.ModeOff},
		{mode: config.ModeObserve, wantObserve: true},
		{mode: config.ModeAudit, wantAudit: true},
		{mode: config.ModeBalanced, wantAudit: true},
		{mode: config.ModeStrict, wantBlock: true},
	}
	for _, reason := range reasons {
		for _, testCase := range modes {
			t.Run(string(reason)+"/"+string(testCase.mode), func(t *testing.T) {
				decision := inspectionDisposition(testCase.mode, inspectionOutcome{
					Classification: classifier.Result{Action: classifier.ActionBlock, Score: 100},
					Incomplete:     []extract.IncompleteReason{reason},
				}, config.OpaqueMediaPolicyAudit)
				if decision.Block != testCase.wantBlock || decision.Audit != testCase.wantAudit || decision.Observe != testCase.wantObserve {
					t.Fatalf("decision = %#v", decision)
				}
				if decision.EvaluateSubject != testCase.wantSubjectEval {
					t.Fatalf("EvaluateSubject = %t, want %t", decision.EvaluateSubject, testCase.wantSubjectEval)
				}
				if testCase.mode == config.ModeBalanced && decision.Code != "allow_due_to_incomplete_inspection" {
					t.Fatalf("balanced code = %q", decision.Code)
				}
				if testCase.mode == config.ModeStrict && decision.RouteReason == "" {
					t.Fatal("strict incomplete decision lacks route reason")
				}
			})
		}
	}
}

func TestInspectionDispositionCompleteMaliciousTextStillBlocksBalanced(t *testing.T) {
	decision := inspectionDisposition(config.ModeBalanced, inspectionOutcome{
		Classification: classifier.Result{Action: classifier.ActionBlock, Score: 100},
	}, config.OpaqueMediaPolicyAudit)
	if !decision.Block || !decision.EvaluateSubject || decision.Code != "block_malicious_text" {
		t.Fatalf("decision = %#v", decision)
	}
}

func TestInspectionDispositionCompleteOpaqueMediaAuditDoesNotHideTextBlock(t *testing.T) {
	blocked := inspectionDisposition(config.ModeBalanced, inspectionOutcome{
		Classification: classifier.Result{Action: classifier.ActionBlock, Score: 100},
		OpaqueMedia:    true,
	}, config.OpaqueMediaPolicyAudit)
	if !blocked.Block {
		t.Fatalf("malicious prompt with opaque media was not blocked: %#v", blocked)
	}

	allowed := inspectionDisposition(config.ModeBalanced, inspectionOutcome{
		Classification: classifier.Result{Action: classifier.ActionAllow},
		OpaqueMedia:    true,
	}, config.OpaqueMediaPolicyAudit)
	if allowed.Block || !allowed.Audit || allowed.Code != "allow_with_opaque_media_audit" {
		t.Fatalf("safe prompt with opaque media decision = %#v", allowed)
	}
}

func TestIncompleteCountersAreBoundedAndVisibleWithoutAuditStore(t *testing.T) {
	p := New()
	reasons := []extract.IncompleteReason{
		extract.IncompleteParseError,
		extract.IncompleteScanByteLimit,
		extract.IncompleteJSONDepthLimit,
		extract.IncompleteTextPartLimit,
		extract.IncompleteMultipartPartLimit,
		extract.IncompleteMultipartUnknownField,
		extract.IncompleteDeferredTextCandidateLimit,
		extract.IncompleteUnsupportedMediaType,
		extract.IncompleteUnsupportedContentEncoding,
		extract.IncompleteRPCBodyLimit,
	}
	p.recordIncompleteCounters(reasons, inspectionDecision{Audit: true})
	snapshot := p.counters.snapshot()
	for _, key := range []string{
		"incomplete_inspections",
		"incomplete_allowed",
		"incomplete_parse_error",
		"incomplete_scan_limit",
		"incomplete_json_depth_limit",
		"incomplete_text_part_limit",
		"incomplete_multipart_limit",
		"incomplete_multipart_schema",
		"incomplete_deferred_text_limit",
		"incomplete_unsupported_content_type",
		"incomplete_rpc_body_limit",
	} {
		if got := snapshot[key]; got != 1 {
			t.Fatalf("%s=%d, want 1; counters=%v", key, got, snapshot)
		}
	}
	if got := snapshot["incomplete_blocked"]; got != 0 {
		t.Fatalf("incomplete_blocked=%d, want 0", got)
	}
}
