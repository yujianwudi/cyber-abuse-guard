package classifier

import "github.com/yujianwudi/cyber-abuse-guard/internal/extract"

const maxRoleClassifierSegments = 64

// AnalyzeSegments scores a role-aware conversation under balanced defaults.
// The classifier is stateless: text is retained only for this call.
func (c *Classifier) AnalyzeSegments(segments []extract.Segment) Result {
	return c.ClassifySegments(segments, ModeBalanced, DefaultThresholds())
}

// ClassifySegments scores a role-aware conversation under the default policy.
func (c *Classifier) ClassifySegments(segments []extract.Segment, mode Mode, thresholds Thresholds) Result {
	return c.ClassifySegmentsWithPolicy(segments, mode, thresholds, DefaultPolicy())
}

// ClassifyUntrustedPartsWithPolicy is the fallback for valid provider bodies
// whose role provenance is absent or ambiguous. It preserves the legacy joint
// decision while also scanning each part and adjacent pair so older explicit
// abuse cannot be hidden behind appended benign fields. Work is capped by the
// same role-segment bound and reported as truncation when that cap is exceeded.
func (c *Classifier) ClassifyUntrustedPartsWithPolicy(parts []string, mode Mode, thresholds Thresholds, policy Policy) Result {
	start := 0
	if len(parts) > maxRoleClassifierSegments {
		start = len(parts) - maxRoleClassifierSegments
	}
	segments := make([]extract.Segment, len(parts)-start)
	for index, part := range parts[start:] {
		segments[index] = extract.Segment{Role: extract.Role("untrusted"), Text: part}
	}
	result := c.ClassifySegmentsWithPolicy(segments, mode, thresholds, policy)
	result.Truncated = result.Truncated || start > 0
	return result
}

// ClassifySegmentsWithPolicy keeps user-to-user follow-up semantics while
// preventing assistant/system/tool text from being combined with user evidence.
// Every segment is also classified independently so older explicit abuse can
// never be hidden by appending benign history. Unknown roles use the legacy
// all-parts classifier as a conservative fallback.
func (c *Classifier) ClassifySegmentsWithPolicy(segments []extract.Segment, mode Mode, thresholds Thresholds, policy Policy) Result {
	truncated := false
	if len(segments) > maxRoleClassifierSegments {
		segments = segments[len(segments)-maxRoleClassifierSegments:]
		truncated = true
	}
	if !knownSegmentRoles(segments) {
		parts := make([]string, 0, len(segments))
		for _, segment := range segments {
			parts = append(parts, segment.Text)
		}
		best := c.ClassifyWithPolicy(parts, mode, thresholds, policy)
		truncated = truncated || best.Truncated
		for index, segment := range segments {
			candidate := c.ClassifyWithPolicy([]string{segment.Text}, mode, thresholds, policy)
			truncated = truncated || candidate.Truncated
			if roleResultBetter(candidate, best) {
				best = candidate
			}
			if index > 0 {
				adjacent := c.ClassifyWithPolicy([]string{segments[index-1].Text, segment.Text}, mode, thresholds, policy)
				truncated = truncated || adjacent.Truncated
				if roleResultBetter(adjacent, best) {
					best = adjacent
				}
			}
		}
		best.Truncated = best.Truncated || truncated
		return best
	}

	best := c.ClassifyWithPolicy(nil, mode, thresholds, policy)
	previousUser := ""
	hasPreviousUser := false
	for _, segment := range segments {
		candidate := c.ClassifyWithPolicy([]string{segment.Text}, mode, thresholds, policy)
		truncated = truncated || candidate.Truncated
		if roleResultBetter(candidate, best) {
			best = candidate
		}
		if segment.Role != extract.RoleUser {
			continue
		}
		if hasPreviousUser {
			followUp := c.ClassifyWithPolicy([]string{previousUser, segment.Text}, mode, thresholds, policy)
			truncated = truncated || followUp.Truncated
			if roleResultBetter(followUp, best) {
				best = followUp
			}
		}
		previousUser = segment.Text
		hasPreviousUser = true
	}
	best.Truncated = best.Truncated || truncated
	return best
}

func knownSegmentRoles(segments []extract.Segment) bool {
	for _, segment := range segments {
		switch segment.Role {
		case extract.RoleSystem, extract.RoleUser, extract.RoleAssistant, extract.RoleTool:
		default:
			return false
		}
	}
	return true
}

func roleResultBetter(candidate, current Result) bool {
	if candidate.Score != current.Score {
		return candidate.Score > current.Score
	}
	if candidate.Action != current.Action {
		return roleActionPriority(candidate.Action) > roleActionPriority(current.Action)
	}
	if candidate.Category != current.Category {
		return categoryPriority(candidate.Category) < categoryPriority(current.Category)
	}
	return false
}

func roleActionPriority(action Action) int {
	switch action {
	case ActionBlock:
		return 4
	case ActionAudit:
		return 3
	case ActionObserve:
		return 2
	default:
		return 1
	}
}
