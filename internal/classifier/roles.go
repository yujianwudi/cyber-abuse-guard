package classifier

import (
	"strings"
	"unicode"

	"github.com/yujianwudi/cyber-abuse-guard/internal/extract"
)

const maxRoleClassifierSegments = 64

var roleSafetyPunctuation = strings.NewReplacer("’", "'", "‘", "'", "“", `"`, "”", `"`)

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
// abuse cannot be hidden behind appended benign fields. Longer inputs use the
// bounded streaming adapter instead of silently retaining only the tail.
func (c *Classifier) ClassifyUntrustedPartsWithPolicy(parts []string, mode Mode, thresholds Thresholds, policy Policy) Result {
	if len(parts) > maxRoleClassifierSegments {
		segments := make([]extract.Segment, len(parts))
		for index, part := range parts {
			segments[index] = extract.Segment{Role: extract.RoleUnknown, Provenance: extract.ProvenanceContent, Text: part}
		}
		result := c.classifyStreamingSegmentsCompat(segments, mode, thresholds, policy)
		result = withFindingOrigin(result, FindingOriginNonUserOrUntrusted)
		attachBehaviorGraph(&result, "untrusted_parts", "")
		return result
	}
	segments := make([]extract.Segment, len(parts))
	for index, part := range parts {
		segments[index] = extract.Segment{Role: extract.Role("untrusted"), Text: part}
	}
	result := c.ClassifySegmentsWithPolicy(segments, mode, thresholds, policy)
	for _, reconstructed := range reconstructedIsolatedPartRuns(parts) {
		candidate := withFindingOrigin(
			c.ClassifyWithPolicy([]string{reconstructed}, mode, thresholds, policy),
			FindingOriginNonUserOrUntrusted,
		)
		if roleResultBetter(candidate, result) {
			result = candidate
		}
	}
	attachBehaviorGraph(&result, "untrusted_parts", "")
	return result
}

// ClassifySegmentsWithPolicy keeps user-to-user follow-up semantics while
// preventing assistant/system/tool text from being combined with user evidence.
// Provider-native tool payloads are always scanned independently, even when an
// assistant emitted them. Clear assistant refusals and system safety policies
// are not attributed as user intent. Every other eligible segment is classified
// independently so older explicit abuse cannot be hidden by appended benign
// history. The sole exception is an immediately refused trusted-user attack
// followed by a narrow trusted safety-maintenance request; execution follow-ups
// reactivate the established block. Unknown roles or provenance use the legacy
// all-parts classifier as a conservative fallback.
func (c *Classifier) ClassifySegmentsWithPolicy(segments []extract.Segment, mode Mode, thresholds Thresholds, policy Policy) Result {
	if len(segments) > maxRoleClassifierSegments {
		return c.classifyStreamingSegmentsCompat(segments, mode, thresholds, policy)
	}
	truncated := false
	if !knownSegmentRoles(segments) {
		parts := make([]string, 0, len(segments))
		for _, segment := range segments {
			parts = append(parts, segment.Text)
		}
		best := withFindingOrigin(c.ClassifyWithPolicy(parts, mode, thresholds, policy), FindingOriginNonUserOrUntrusted)
		truncated = truncated || best.Truncated
		for index, segment := range segments {
			candidate := withFindingOrigin(
				c.ClassifyWithPolicy([]string{segment.Text}, mode, thresholds, policy),
				FindingOriginNonUserOrUntrusted,
			)
			truncated = truncated || candidate.Truncated
			if roleResultBetter(candidate, best) {
				best = candidate
			}
			if index > 0 {
				adjacent := withFindingOrigin(
					c.ClassifyWithPolicy([]string{segments[index-1].Text, segment.Text}, mode, thresholds, policy),
					FindingOriginNonUserOrUntrusted,
				)
				truncated = truncated || adjacent.Truncated
				if roleResultBetter(adjacent, best) {
					best = adjacent
				}
			}
		}
		best.Truncated = best.Truncated || truncated
		attachBehaviorGraph(&best, "unknown_role_fallback", "")
		return best
	}
	closedHistoryUser, closedHistoryRefusal, hasClosedHistory :=
		c.refusedHistoricalSafetyMaintenanceTail(segments, mode, thresholds, policy)

	best := c.ClassifyWithPolicy(nil, mode, thresholds, policy)
	previousUser := ""
	hasPreviousUser := false
	previousUserTrusted := false
	recentUsers := make([]string, 0, 3)
	recentUsersTrusted := make([]bool, 0, 3)
	linkedMetaUsers := make([]string, 0, 8)
	linkedMetaUsersTrusted := make([]bool, 0, 8)
	lastMetaUser := ""
	pendingNonUserControl := ""
	lastUserControl := ""
	considerControlPair := func(nonUser, user string) {
		if nonUser == "" || user == "" || !metaOverridePartsLinked(nonUser, user) {
			return
		}
		controlCandidate := withRoleAwareFindingOrigin(
			c.ClassifyWithPolicy([]string{nonUser, user}, mode, thresholds, policy),
			FindingOriginNonUserOrUntrusted,
			mode,
			thresholds,
		)
		truncated = truncated || controlCandidate.Truncated
		if standaloneMetaControlResult(controlCandidate) && roleResultBetter(controlCandidate, best) {
			best = controlCandidate
		}
	}
	for index, segment := range segments {
		if hasClosedHistory && index == closedHistoryUser {
			// This exact trusted-user block is the referent of the immediately
			// following clear assistant refusal. It is ignored only because the
			// final trusted-user turn is a narrow safety-maintenance request. Other
			// historical findings remain independently ranked.
			continue
		}
		classifySegment := shouldClassifyRoleSegment(segment)
		if classifySegment {
			candidate := c.classifyWithPolicy(
				[]string{segment.Text}, mode, thresholds, policy,
				segment.Provenance == extract.ProvenanceToolPayload,
			)
			candidate = withRoleAwareFindingOrigin(candidate, findingOriginForSegment(segment), mode, thresholds)
			truncated = truncated || candidate.Truncated
			if roleResultBetter(candidate, best) {
				best = candidate
			}
		}
		if segment.Role != extract.RoleUser || segment.Provenance != extract.ProvenanceContent {
			if classifySegment {
				considerControlPair(segment.Text, lastUserControl)
				pendingNonUserControl = segment.Text
			} else {
				pendingNonUserControl = ""
			}
		}
		if segment.Provenance == extract.ProvenanceContent && (segment.Role == extract.RoleAssistant || segment.Role == extract.RoleSystem) {
			if continuation := unscopedSafetyContinuation(segment.Role, strings.ToLower(roleSafetyPunctuation.Replace(segment.Text))); continuation != "" {
				candidate := withRoleAwareFindingOrigin(
					c.ClassifyWithPolicy([]string{continuation}, mode, thresholds, policy),
					FindingOriginNonUserOrUntrusted,
					mode,
					thresholds,
				)
				truncated = truncated || candidate.Truncated
				if roleResultBetter(candidate, best) {
					best = candidate
				}
			}
		}
		if hasClosedHistory && index == closedHistoryRefusal {
			// A proven refusal closes only its immediately preceding attack turn.
			// Clear the bounded user-composition state so the safe maintenance tail
			// cannot be recombined with that closed referent. Independently ranked
			// older findings in best are intentionally untouched.
			previousUser = ""
			hasPreviousUser = false
			previousUserTrusted = false
			clear(recentUsers)
			recentUsers = recentUsers[:0]
			clear(recentUsersTrusted)
			recentUsersTrusted = recentUsersTrusted[:0]
			clear(linkedMetaUsers)
			linkedMetaUsers = linkedMetaUsers[:0]
			clear(linkedMetaUsersTrusted)
			linkedMetaUsersTrusted = linkedMetaUsersTrusted[:0]
			lastMetaUser = ""
			lastUserControl = ""
		}
		if segment.Role != extract.RoleUser || segment.Provenance != extract.ProvenanceContent {
			continue
		}
		currentUserTrusted := segment.UserAttribution == extract.UserAttributionTrusted
		considerControlPair(pendingNonUserControl, segment.Text)
		pendingNonUserControl = ""
		lastUserControl = segment.Text
		if len(linkedMetaUsers) == 0 || metaOverridePartsLinked(lastMetaUser, segment.Text) {
			linkedMetaUsers = append(linkedMetaUsers, segment.Text)
			linkedMetaUsersTrusted = append(linkedMetaUsersTrusted, currentUserTrusted)
			if len(linkedMetaUsers) > maxRoleClassifierSegments {
				copy(linkedMetaUsers, linkedMetaUsers[len(linkedMetaUsers)-maxRoleClassifierSegments:])
				linkedMetaUsers = linkedMetaUsers[:maxRoleClassifierSegments]
				copy(linkedMetaUsersTrusted, linkedMetaUsersTrusted[len(linkedMetaUsersTrusted)-maxRoleClassifierSegments:])
				linkedMetaUsersTrusted = linkedMetaUsersTrusted[:maxRoleClassifierSegments]
			}
		} else {
			linkedMetaUsers = append(linkedMetaUsers[:0], segment.Text)
			linkedMetaUsersTrusted = append(linkedMetaUsersTrusted[:0], currentUserTrusted)
		}
		lastMetaUser = segment.Text
		if len(linkedMetaUsers) > 1 {
			metaCandidate := withRoleAwareFindingOrigin(
				c.ClassifyWithPolicy(linkedMetaUsers, mode, thresholds, policy),
				userCombinationFindingOrigin(allTrusted(linkedMetaUsersTrusted)),
				mode,
				thresholds,
			)
			truncated = truncated || metaCandidate.Truncated
			if roleResultBetter(metaCandidate, best) {
				best = metaCandidate
			}
		}
		if hasPreviousUser {
			origin := userCombinationFindingOrigin(previousUserTrusted && currentUserTrusted)
			followUp := withRoleAwareFindingOrigin(
				c.ClassifyWithPolicy([]string{previousUser, segment.Text}, mode, thresholds, policy),
				origin,
				mode,
				thresholds,
			)
			truncated = truncated || followUp.Truncated
			if roleResultBetter(followUp, best) {
				best = followUp
			}
			// Adjacent user turns may split an abuse intent from its object. Join
			// only user-authored text and only when the prior turn is eligible for
			// follow-up; system/assistant/tool examples can never contribute.
			joinEligible := followUpEligible([]rune(previousUser))
			if joinEligible && c.isRawInertQuotedSafetyReview(previousUser) {
				joinEligible = false
			}
			if joinEligible {
				joined := withRoleAwareFindingOrigin(
					c.ClassifyWithPolicy([]string{previousUser + "\n" + segment.Text}, mode, thresholds, policy),
					origin,
					mode,
					thresholds,
				)
				truncated = truncated || joined.Truncated
				if roleResultBetter(joined, best) {
					best = joined
				}
			}
		}
		recentUsers = append(recentUsers, segment.Text)
		recentUsersTrusted = append(recentUsersTrusted, currentUserTrusted)
		if len(recentUsers) > 3 {
			copy(recentUsers, recentUsers[len(recentUsers)-3:])
			recentUsers = recentUsers[:3]
			copy(recentUsersTrusted, recentUsersTrusted[len(recentUsersTrusted)-3:])
			recentUsersTrusted = recentUsersTrusted[:3]
		}
		if len(recentUsers) == 3 && threeTurnPlanWindowEligible(recentUsers) {
			joined := withRoleAwareFindingOrigin(
				c.ClassifyWithPolicy([]string{strings.Join(recentUsers, "\n")}, mode, thresholds, policy),
				userCombinationFindingOrigin(allTrusted(recentUsersTrusted)),
				mode,
				thresholds,
			)
			truncated = truncated || joined.Truncated
			if roleResultBetter(joined, best) {
				best = joined
			}
		}
		previousUser = segment.Text
		hasPreviousUser = true
		previousUserTrusted = currentUserTrusted
	}
	for _, reconstructed := range reconstructedIsolatedUserRuns(segments) {
		candidate := withRoleAwareFindingOrigin(
			c.ClassifyWithPolicy([]string{reconstructed.text}, mode, thresholds, policy),
			userCombinationFindingOrigin(reconstructed.trusted),
			mode,
			thresholds,
		)
		truncated = truncated || candidate.Truncated
		if roleResultBetter(candidate, best) {
			best = candidate
		}
	}
	// A bounded run of user-authored content parts may split one explicitly
	// quoted, inert review across segment boundaries. Prefixes are classified
	// conservatively while the run is incomplete; once the complete structural
	// boundary proves that the quoted sample is inert and the last effective
	// directive is analysis/non-execution, replace only a wrapper-only prefix
	// result. Base cyber-abuse behavior, tool text, non-user text, long runs, and
	// malformed quote boundaries can never be cleared by this path.
	if best.Behavior != nil && best.Behavior.Wrapper && !best.Behavior.BaseBehavior {
		if joined, ok := metaOverrideDefensiveUserSegmentRun(segments); ok {
			candidate := withRoleAwareFindingOrigin(
				c.ClassifyWithPolicy([]string{joined}, mode, thresholds, policy),
				FindingOriginUserContent,
				mode,
				thresholds,
			)
			truncated = truncated || candidate.Truncated
			if !truncated && candidate.Action == ActionAllow && candidate.Score < AuditThreshold &&
				(candidate.Behavior == nil || !candidate.Behavior.BaseBehavior) {
				best = candidate
			}
		}
	}
	best.Truncated = best.Truncated || truncated
	attachBehaviorGraph(&best, "role_aware", "")
	return best
}

// refusedHistoricalSafetyMaintenanceTail recognizes one deliberately narrow
// conversation closure: a trusted-user attack, an immediately adjacent clear
// assistant refusal, and a final trusted-user request to improve the guard or
// reduce false positives. The two candidate classifications prevent wording
// alone from creating safety credit. Any execution/implementation follow-up,
// untrusted attribution, non-adjacent refusal, or independent older finding
// keeps the established conservative behavior.
func (c *Classifier) refusedHistoricalSafetyMaintenanceTail(
	segments []extract.Segment,
	mode Mode,
	thresholds Thresholds,
	policy Policy,
) (historicalUser, refusal int, ok bool) {
	if c == nil || len(segments) < 3 {
		return 0, 0, false
	}
	historicalUser = len(segments) - 3
	refusal = len(segments) - 2
	currentIndex := len(segments) - 1
	historical := segments[historicalUser]
	assistant := segments[refusal]
	current := segments[currentIndex]
	if !trustedUserContentSegment(historical) || !trustedUserContentSegment(current) ||
		assistant.Role != extract.RoleAssistant || assistant.Provenance != extract.ProvenanceContent ||
		len(assistant.Text) > streamRoleSummaryBytes || len(current.Text) > streamRoleSummaryBytes ||
		!isClearNonUserSafetyContent(extract.RoleAssistant, assistant.Text) ||
		!c.isNarrowSafetyMaintenanceRequest(current.Text) {
		return 0, 0, false
	}

	currentResult := c.classifyWithPolicy([]string{current.Text}, mode, thresholds, policy, false)
	if !safeHistoricalMaintenanceCandidate(currentResult) {
		return 0, 0, false
	}
	historicalResult := c.classifyWithPolicy([]string{historical.Text}, mode, thresholds, policy, false)
	if historicalResult.Truncated || historicalResult.Action != ActionBlock {
		return 0, 0, false
	}
	return historicalUser, refusal, true
}

func trustedUserContentSegment(segment extract.Segment) bool {
	return segment.Role == extract.RoleUser && segment.Provenance == extract.ProvenanceContent &&
		segment.UserAttribution == extract.UserAttributionTrusted
}

func safeHistoricalMaintenanceCandidate(result Result) bool {
	return !result.Truncated && result.Action == ActionAllow && result.Score < AuditThreshold &&
		result.Category == "" && (result.Behavior == nil || !result.Behavior.BaseBehavior)
}

func (c *Classifier) isNarrowSafetyMaintenanceRequest(text string) bool {
	if c == nil || strings.TrimSpace(text) == "" {
		return false
	}
	normalized := strings.ToLower(roleSafetyPunctuation.Replace(text))
	falsePositiveReview := containsAnyRolePhrase(normalized,
		"reduce false positives", "lower false positives", "fewer false positives",
		"reduce false blocks", "reduce false rejections", "review false positives",
		"降低误伤", "减少误伤", "降低误拦", "减少误拦", "降低误报", "减少误报", "审查误拦", "检查误拦",
	)
	guardMaintenance := containsAnyRolePhrase(normalized,
		"improve the abuse guard", "improving the abuse guard", "improve abuse guard", "improving abuse guard",
		"tune the abuse guard", "refine the abuse guard", "improve the risk controls", "tune the risk controls",
		"完善风控", "优化风控", "改进风控", "调整风控", "完善防护", "优化防护", "改进防护",
	)
	if !falsePositiveReview && !guardMaintenance {
		return false
	}
	// These are exact reactivation speech acts for the refused referent. They
	// must win even when the same turn also contains safety-maintenance wording.
	if containsUnnegatedRuleIntentPrepared(
		normalized, quotedReviewSpecificContinuationIntents, quotedReviewSpecificContinuationPatterns,
	) {
		return false
	}
	activeReferent, _, complete := c.hasRawAffirmativeQuotedReviewFollowUp(text)
	return complete && !activeReferent && !c.hasAffirmativeImplementationRequest(normalized)
}

func metaOverrideDefensiveUserSegmentRun(segments []extract.Segment) (string, bool) {
	if len(segments) < 2 || len(segments) > 8 {
		return "", false
	}
	parts := make([]string, 0, len(segments))
	totalBytes := 0
	for _, segment := range segments {
		if segment.Role != extract.RoleUser || segment.Provenance != extract.ProvenanceContent ||
			segment.UserAttribution != extract.UserAttributionTrusted {
			return "", false
		}
		totalBytes += len(segment.Text)
		if totalBytes > maxClassifierInputBytes {
			return "", false
		}
		parts = append(parts, segment.Text)
	}
	joined := strings.Join(parts, "\n")
	if !metaOverrideDefensiveAnalysis(joined, ContextFlags{}) {
		return "", false
	}
	return joined, true
}

// threeTurnPlanWindowEligible permits one additional bounded user-only merge
// when a conversation explicitly links fragments and asks for an operational
// plan or sequence. Ordinary adjacent follow-ups retain the two-turn path; the
// third turn is never merged merely because three user messages exist.
func threeTurnPlanWindowEligible(turns []string) bool {
	if len(turns) != 3 {
		return false
	}
	first := strings.ToLower(roleSafetyPunctuation.Replace(turns[0]))
	second := strings.ToLower(roleSafetyPunctuation.Replace(turns[1]))
	last := strings.ToLower(roleSafetyPunctuation.Replace(turns[2]))
	if hasNegatedSafetyFraming(first) || hasNegatedSafetyFraming(second) || hasNegatedSafetyFraming(last) ||
		hasAffirmativeSafetyPurpose(last) || isSafetyDeliverableClause(last) ||
		containsAnyRolePhrase(last, "detection plan", "defensive plan", "recovery plan", "restoration plan", "patch plan", "检测计划", "防御计划", "恢复计划", "补丁计划") {
		return false
	}
	linked := containsAnyRolePhrase(first, "these messages", "one operation", "one workflow", "one rollout", "next pieces", "following pieces", "these fragments", "next details", "all three", "combine", "treat the next", "read the following", "这些消息", "同一操作", "同一流程", "同一投放", "下面几段", "以下片段", "接下来的内容", "合并") ||
		containsAnyRolePhrase(second, "the above", "those pieces", "same operation", "same workflow", "上述", "前面的内容", "同一操作", "同一流程") ||
		hasAnyPrefix(strings.TrimSpace(last), "now ", "next ", "then ", "continue ", "现在", "接下来", "然后", "继续")
	if !linked {
		return false
	}
	return containsAnyRolePhrase(last,
		"execution plan", "execution sequence", "operating sequence", "operational sequence",
		"implementation plan", "implementation sequence", "rollout plan", "deployment plan",
		"actionable plan", "practical workflow", "step-by-step plan",
		"执行计划", "执行步骤", "操作顺序", "实施计划", "实施步骤", "投放计划", "部署计划", "可操作方案",
	)
}

func knownSegmentRoles(segments []extract.Segment) bool {
	for _, segment := range segments {
		switch segment.Provenance {
		case extract.ProvenanceContent, extract.ProvenanceToolPayload:
		default:
			return false
		}
		switch segment.Role {
		case extract.RoleSystem, extract.RoleUser, extract.RoleAssistant, extract.RoleTool:
		default:
			return false
		}
	}
	return true
}

func findingOriginForSegment(segment extract.Segment) FindingOrigin {
	if segment.Role == extract.RoleUser && segment.Provenance == extract.ProvenanceContent &&
		segment.UserAttribution == extract.UserAttributionTrusted {
		return FindingOriginUserContent
	}
	return FindingOriginNonUserOrUntrusted
}

func userCombinationFindingOrigin(trusted bool) FindingOrigin {
	if trusted {
		return FindingOriginUserContent
	}
	return FindingOriginNonUserOrUntrusted
}

func allTrusted(values []bool) bool {
	if len(values) == 0 {
		return false
	}
	for _, trusted := range values {
		if !trusted {
			return false
		}
	}
	return true
}

func withFindingOrigin(result Result, origin FindingOrigin) Result {
	if result.Score == 0 && result.Action == ActionAllow && result.Category == "" &&
		len(result.RuleIDs) == 0 && len(result.Evidence) == 0 && result.Behavior == nil {
		result.FindingOrigin = FindingOriginNone
		return result
	}
	result.FindingOrigin = origin
	return result
}

// withRoleAwareFindingOrigin applies the role boundary before candidates are
// ranked. A persistent prompt-injection wrapper remains a local hard block when
// it is an explicit trusted-user request, but the same wrapper arriving from a
// system, assistant, tool, or structurally untrusted field is audit-only unless
// that field independently establishes a cyber-abuse base behavior.
//
// This helper is intentionally not used by the roleless Classify API or the
// unknown-role fallback: callers without proven role provenance retain their
// existing conservative behavior.
func withRoleAwareFindingOrigin(result Result, origin FindingOrigin, mode Mode, thresholds Thresholds) Result {
	result = withFindingOrigin(result, origin)
	if origin != FindingOriginNonUserOrUntrusted || result.Behavior == nil ||
		!result.Behavior.Wrapper || result.Behavior.BaseBehavior {
		return result
	}
	thresholds = validThresholdsOrDefault(thresholds)
	result.Score = metaControlAuditScore(result.Score, thresholds)
	result.Action = actionForMetaControl(mode, result.Score, thresholds)
	return result
}

func shouldClassifyRoleSegment(segment extract.Segment) bool {
	if segment.Provenance == extract.ProvenanceToolPayload {
		return true
	}
	switch segment.Role {
	case extract.RoleUser, extract.RoleTool:
		return true
	case extract.RoleAssistant, extract.RoleSystem:
		return !isClearNonUserSafetyContent(segment.Role, segment.Text)
	default:
		// This branch is reachable only if this helper is used independently;
		// ClassifySegmentsWithPolicy sends unknown provenance through its more
		// conservative all-parts fallback before reaching it.
		return true
	}
}

// isClearNonUserSafetyContent recognizes only explicit refusals or policy
// prohibitions. It is intentionally narrow: ordinary non-user instructions are
// still scanned, and a refusal/policy followed by an operational override is
// not suppressed. Tool payloads never reach this function.
func isClearNonUserSafetyContent(role extract.Role, value string) bool {
	text := strings.ToLower(strings.TrimSpace(value))
	text = roleSafetyPunctuation.Replace(text)
	text = strings.TrimLeft(text, " \t\r\n-*#>")
	if text == "" || hasUnscopedNonUserSafetyOverride(role, text) || hasUnscopedSafetyContinuation(role, text) {
		return false
	}

	switch role {
	case extract.RoleAssistant:
		return hasClearAssistantRefusal(text)
	case extract.RoleSystem:
		return hasClearSystemSafetyPolicy(text)
	default:
		return false
	}
}

func hasClearAssistantRefusal(text string) bool {
	return hasAnyPrefix(text,
		"i cannot ", "i can't ", "i will not ", "i won't ", "i refuse ", "i must refuse",
		"i am unable ", "i'm unable ", "sorry, i cannot ", "sorry, i can't ",
		"sorry, but i cannot ", "sorry, but i can't ", "cannot assist with ", "can't assist with ",
		"i'm sorry, but i cannot ", "i'm sorry, but i can't ", "i am sorry, but i cannot ", "i am sorry, but i can't ",
		"apologies, but i cannot ", "apologies, but i can't ", "as an ai, i cannot ", "as an ai, i can't ",
		"我不能", "我无法", "我不会", "我拒绝", "抱歉，我不能", "抱歉，我无法", "无法协助", "不能协助",
	)
}

func hasClearSystemSafetyPolicy(text string) bool {
	policyFraming := containsAnyRolePhrase(text,
		"system policy", "safety policy", "security policy", "content policy", "moderation policy", "abuse policy",
		"system safety", "safe system policy", "安全策略", "安全政策", "内容策略", "审核策略", "滥用策略",
	) || hasAnyPrefix(text,
		"you must not ", "you must never ", "never assist ", "do not assist ", "don't assist ",
		"never provide ", "do not provide ", "don't provide ", "you must refuse ", "always refuse ",
		"refuse requests ", "reject requests ", "block requests ",
		"不得协助", "不要协助", "严禁协助", "拒绝处理", "阻止请求",
	)
	prohibition := containsAnyRolePhrase(text,
		"must refuse", "should refuse", "refuse any", "refuse requests", "reject any", "reject requests",
		"block any", "block requests", "prevent ", "never ", "do not ", "don't ", "must not ",
		"prohibit", "forbid", "not allowed", "禁止", "不得", "严禁", "拒绝", "阻止", "防止", "不要",
	)
	return policyFraming && prohibition
}

func scopedSafetyContinuationIsInert(role extract.Role, fullText, clause string) bool {
	if !isScopedSafetyContinuation(role, clause) {
		return false
	}
	if !hasCoordinatedOperationalContinuation(clause) {
		return true
	}
	_, _, explicitlyQuoted := explicitQuotedSafetyState(role, fullText, clause)
	if !explicitlyQuoted {
		return false
	}
	switch role {
	case extract.RoleAssistant:
		return hasClearAssistantRefusal(fullText)
	case extract.RoleSystem:
		return hasClearSystemSafetyPolicy(fullText)
	default:
		return false
	}
}

func isExplicitQuotedSafetyContinuation(role extract.Role, clause string) bool {
	_, ok := explicitQuotedSafetyPayload(role, clause)
	return ok
}

func explicitQuotedSafetyPayload(role extract.Role, clause string) (string, bool) {
	clause = strings.TrimLeft(strings.TrimSpace(clause), "-*#> ")
	var prefixes []string
	switch role {
	case extract.RoleAssistant:
		prefixes = []string{
			"the blocked prompt was", "the forbidden prompt was", "the quoted prompt was", "the blocked prompt said",
			"the forbidden prompt said", "the quoted prompt said", "the quoted request was", "the forbidden request was",
			"the blocked request was", "被禁止的请求是", "被拦截的请求是", "引用的请求是", "引用提示词是",
		}
	case extract.RoleSystem:
		prefixes = []string{
			"the blocked prompt was", "the forbidden prompt was", "the quoted prompt was", "the blocked prompt said",
			"the forbidden prompt said", "the quoted prompt said", "the quoted request was", "the forbidden request was",
			"the blocked request was", "被禁止的请求是", "被拦截的请求是", "引用的请求是", "引用提示词是",
		}
	default:
		return "", false
	}
	for _, prefix := range prefixes {
		if !strings.HasPrefix(clause, prefix) {
			continue
		}
		payload := strings.TrimLeft(clause[len(prefix):], " \t:：=-")
		return payload, true
	}
	return "", false
}

func hasNonUserSafetyOverride(text string) bool {
	if containsAnyRolePhrase(text,
		"do not refuse", "don't refuse", "must not refuse", "never refuse", "ignore the safety", "ignore safety",
		"ignore the policy", "disregard the policy", "bypass the policy", "bypass safety", "policy is irrelevant",
		"must not be denied", "must not deny", "do not deny", "don't deny", "must not be blocked", "must not block",
		"do not block", "don't block", "must not be filtered", "do not filter", "disable guardrails", "remove guardrails",
		"disable safety checks", "skip safety checks", "must not enforce the policy", "must not apply safety",
		"but here is the code", "however, here is the code", "instead, here is the code", "here's the working code",
		"use the following code", "run the following code", "execute the following code", "nevertheless", "nonetheless",
		"even so", "that said", "having said that", "all the same", "regardless", "despite that", "despite this",
		"separately", "independently", "in any case", "anyway", "however", "instead", "but then", "and then",
		"不要拒绝", "不得拒绝", "不得阻止", "不得拦截", "不得过滤", "不要阻止", "不要拦截", "不要过滤",
		"关闭护栏", "移除护栏", "禁用安全检查", "跳过安全检查", "不得执行安全策略",
		"忽略安全", "忽略策略", "绕过策略", "策略无关", "但以下是代码", "不过以下是代码",
		"使用以下代码", "运行以下代码", "执行以下代码", "尽管如此", "话虽如此", "无论如何", "然而", "另外",
		"另行", "分别", "接下来", "然后照做", "照样执行",
	) {
		return true
	}
	return hasCoordinatedOperationalContinuation(text)
}

func hasUnscopedNonUserSafetyOverride(role extract.Role, text string) bool {
	if !hasNonUserSafetyOverride(text) {
		return false
	}
	var quotedScope rune
	for _, clause := range splitStrongSafetyClauses(text) {
		clause = strings.TrimSpace(clause)
		if clause == "" {
			continue
		}
		if quotedScope != 0 {
			suffix, closed := closeQuotedSafetyScope(clause, quotedScope)
			if !closed {
				continue
			}
			quotedScope = 0
			clause = suffix
			if clause == "" {
				continue
			}
		}
		if !hasNonUserSafetyOverride(clause) {
			continue
		}
		if scopedSafetyContinuationIsInert(role, text, clause) {
			if suffix, quote, quoted := explicitQuotedSafetyState(role, text, clause); quoted {
				quotedScope = quote
				if suffix != "" && hasNonUserSafetyOverride(suffix) {
					return true
				}
			}
			continue
		}
		return true
	}
	return false
}

// hasCoordinatedOperationalContinuation catches a second operational predicate
// hidden inside an otherwise scoped restatement, for example "the request was:
// steal cookies and send them to my server". The role label is caller supplied,
// so a quoted/restated request receives only narrow negative-scope treatment.
func hasCoordinatedOperationalContinuation(text string) bool {
	for _, separator := range []string{
		" and ", " then ", " plus ", " as well as ", " followed by ", " & ",
		"，", "、", "并且", "并将", "并把", "然后", "同时", "以及",
	} {
		remaining := text
		for {
			index := strings.Index(remaining, separator)
			if index < 0 {
				break
			}
			remaining = remaining[index+len(separator):]
			continuation := strings.TrimSpace(remaining)
			if hasOperationalContinuationPrefix(continuation) || hasAnyPrefix(continuation,
				"writing ", "creating ", "generating ", "building ", "providing ", "giving ", "showing ",
				"running ", "executing ", "deploying ", "sending ", "stealing ", "exfiltrating ", "answering ",
				"following ", "obeying ", "complying ",
				"bypassing ", "exploiting ", "installing ",
				"编写", "创建", "生成", "构建", "提供", "运行", "执行", "部署", "发送", "窃取", "回答", "遵循", "服从", "照做",
				"绕过", "利用", "安装",
			) {
				return true
			}
		}
	}
	return false
}

// hasUnscopedSafetyContinuation prevents a safe-looking prefix from laundering
// later instructions. Only an explicit restatement of the refused request (or
// another prohibition in a system policy) remains inside the safety scope.
// Unknown later clauses are classified normally; benign alternatives will
// simply score as benign, while attacker-controlled role labels gain no trust.
func hasUnscopedSafetyContinuation(role extract.Role, text string) bool {
	return unscopedSafetyContinuation(role, text) != ""
}

// unscopedSafetyContinuation returns the first clause that has escaped a
// refusal/policy's negative scope. It is classified separately so the leading
// refusal cannot cause the core negation detector to suppress the new request.
func unscopedSafetyContinuation(role extract.Role, text string) string {
	clauses := splitStrongSafetyClauses(text)
	var quotedScope rune
	for index, clause := range clauses {
		clause = strings.TrimSpace(clause)
		if clause == "" || index == 0 {
			continue
		}
		if quotedScope != 0 {
			suffix, closed := closeQuotedSafetyScope(clause, quotedScope)
			if !closed {
				continue
			}
			quotedScope = 0
			if suffix == "" {
				continue
			}
			return suffix
		}
		if scopedSafetyContinuationIsInert(role, text, clause) {
			if suffix, quote, quoted := explicitQuotedSafetyState(role, text, clause); quoted {
				quotedScope = quote
				if suffix != "" {
					return suffix
				}
			}
			continue
		}
		return clause
	}

	// A comma or colon can introduce an imperative without creating a new
	// sentence ("I cannot help: write ..."). Treat that as an operational
	// continuation unless the delimiter explicitly introduces a quotation or
	// restatement of the refused request.
	for _, delimiter := range []string{",", ":", "，", "："} {
		parts := strings.Split(text, delimiter)
		for index := 1; index < len(parts); index++ {
			continuation := strings.TrimSpace(parts[index])
			if continuation == "" || isScopedSafetyContinuation(role, continuation) {
				continue
			}
			if (delimiter == ":" || delimiter == "：") && isScopedSafetyContinuation(role, lastSafetyClause(parts[index-1])) {
				continue
			}
			if hasOperationalContinuationPrefix(continuation) {
				return continuation
			}
		}
	}
	return ""
}

// explicitQuotedSafetyState returns any text after a quote that closes in the
// current clause, or the balanced quote delimiter whose span continues into a
// later clause. This keeps only the actual quoted bytes inert; text after the
// closing delimiter is always classified again.
func explicitQuotedSafetyState(role extract.Role, fullText, clause string) (string, rune, bool) {
	payload, ok := explicitQuotedSafetyPayload(role, clause)
	if !ok {
		return "", 0, false
	}
	for _, quote := range []rune{'"', '`'} {
		quoteText := string(quote)
		if !strings.HasPrefix(payload, quoteText) {
			continue
		}
		remainder := payload[len(quoteText):]
		if closeIndex := strings.Index(remainder, quoteText); closeIndex >= 0 {
			return strings.TrimSpace(remainder[closeIndex+len(quoteText):]), 0, true
		}
		count := strings.Count(fullText, quoteText)
		if count >= 2 && count%2 == 0 {
			return "", quote, true
		}
	}
	return "", 0, false
}

func closeQuotedSafetyScope(clause string, quote rune) (string, bool) {
	quoteText := string(quote)
	closeIndex := strings.Index(clause, quoteText)
	if closeIndex < 0 {
		return "", false
	}
	return strings.TrimSpace(clause[closeIndex+len(quoteText):]), true
}

// splitStrongSafetyClauses treats Unicode punctuation, symbols, and
// non-ordinary whitespace as trust boundaries. This prevents a caller from
// choosing an unlisted separator to keep a new instruction inside a leading
// refusal's negative scope. Commas and colons retain their narrower handling
// below, while ordinary punctuation inside a word is preserved.
func splitStrongSafetyClauses(text string) []string {
	runes := []rune(text)
	clauses := make([]string, 0, 2)
	start := 0
	for index, current := range runes {
		var previous, next rune
		if index > 0 {
			previous = runes[index-1]
		}
		if index+1 < len(runes) {
			next = runes[index+1]
		}
		if !isStrongSafetyBoundary(current, previous, next) {
			continue
		}
		if clause := strings.TrimSpace(string(runes[start:index])); clause != "" {
			clauses = append(clauses, clause)
		}
		start = index + 1
	}
	if clause := strings.TrimSpace(string(runes[start:])); clause != "" {
		clauses = append(clauses, clause)
	}
	return clauses
}

func isStrongSafetyBoundary(current, previous, next rune) bool {
	if unicode.IsSpace(current) {
		return current != ' '
	}
	// Paired punctuation keeps quoted/restated content attached to the
	// surrounding refusal or policy scope. Curly quotes are normalized before
	// this helper; the Unicode categories cover brackets and other quote forms.
	if current == '`' || unicode.Is(unicode.Quotation_Mark, current) ||
		unicode.Is(unicode.Ps, current) || unicode.Is(unicode.Pe, current) ||
		unicode.Is(unicode.Pi, current) || unicode.Is(unicode.Pf, current) {
		return false
	}
	// A comma or colon may introduce a scoped quotation/restatement and is
	// evaluated with that context in unscopedSafetyContinuation.
	switch current {
	case ',', ':', '，', '：':
		return false
	}
	if isSafetyWordRune(previous) && isSafetyWordRune(next) {
		// Keep contractions, identifiers, and ordinary hyphenated words intact.
		if unicode.Is(unicode.Pc, current) || unicode.Is(unicode.Hyphen, current) {
			return false
		}
	}
	return unicode.IsPunct(current) || unicode.IsSymbol(current)
}

func isSafetyWordRune(value rune) bool {
	return unicode.IsLetter(value) || unicode.IsDigit(value) || unicode.IsMark(value)
}

func lastSafetyClause(value string) string {
	if index := strings.LastIndexAny(value, ".!?;\n\r。！？；"); index >= 0 {
		value = value[index+1:]
	}
	return strings.TrimSpace(value)
}

func isScopedSafetyContinuation(role extract.Role, clause string) bool {
	clause = strings.TrimLeft(strings.TrimSpace(clause), "-*#> ")
	switch role {
	case extract.RoleAssistant:
		return hasAnyPrefix(clause,
			"the request was", "the forbidden request was", "the blocked request was", "the request says",
			"the blocked prompt was", "the forbidden prompt was", "the quoted prompt was", "the blocked prompt said",
			"the forbidden prompt said", "the quoted prompt said",
			"the user asked", "you asked", "that request was", "this request was", "the quoted request was",
			"被禁止的请求是", "被拦截的请求是", "该请求是", "这个请求是", "用户要求", "你要求",
		)
	case extract.RoleSystem:
		return hasAnyPrefix(clause,
			"refuse ", "reject ", "block ", "never ", "do not ", "don't ", "must not ", "should refuse ",
			"the request was", "the forbidden request was", "the policy prohibits", "this is prohibited", "that is prohibited",
			"拒绝", "禁止", "不得", "严禁", "不要", "必须拒绝", "应当拒绝", "该请求是", "这个请求是",
		)
	default:
		return false
	}
}

func hasOperationalContinuationPrefix(clause string) bool {
	clause = strings.TrimLeft(strings.TrimSpace(clause), "-*#> ")
	return hasAnyPrefix(clause,
		"write ", "create ", "generate ", "build ", "provide ", "give ", "show ", "tell ", "return ",
		"run ", "execute ", "deploy ", "send ", "steal ", "exfiltrate ", "bypass ", "exploit ", "install ",
		"answer ", "follow ", "obey ", "comply ",
		"now ", "next ", "then ", "also ", "still ", "yet ",
		"编写", "写出", "创建", "生成", "构建", "提供", "给出", "展示", "运行", "执行", "部署", "发送", "窃取",
		"绕过", "利用", "安装", "回答", "遵循", "服从", "照做", "现在", "接下来", "然后", "另外", "同时", "仍然",
	)
}

func hasAnyPrefix(text string, prefixes ...string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(text, prefix) {
			return true
		}
	}
	return false
}

func containsAnyRolePhrase(text string, phrases ...string) bool {
	for _, phrase := range phrases {
		if strings.Contains(text, phrase) {
			return true
		}
	}
	return false
}

const (
	minIsolatedRuneRun = 4
	maxIsolatedRuneRun = 64
)

func reconstructedIsolatedPartRuns(parts []string) []string {
	runs := make([]string, 0, 2)
	var builder strings.Builder
	runeCount := 0
	flush := func() {
		if runeCount >= minIsolatedRuneRun {
			runs = append(runs, builder.String())
		}
		builder.Reset()
		runeCount = 0
	}
	for _, part := range parts {
		r, ok := isolatedCompactRune(part)
		if !ok {
			flush()
			continue
		}
		if runeCount == maxIsolatedRuneRun {
			flush()
		}
		if runeCount > 0 {
			builder.WriteByte(' ')
		}
		builder.WriteRune(r)
		runeCount++
	}
	flush()
	return runs
}

type reconstructedUserRun struct {
	text    string
	trusted bool
}

func reconstructedIsolatedUserRuns(segments []extract.Segment) []reconstructedUserRun {
	parts := make([]string, 0, len(segments))
	trusted := true
	runs := make([]reconstructedUserRun, 0, 2)
	flush := func() {
		for _, run := range reconstructedIsolatedPartRuns(parts) {
			runs = append(runs, reconstructedUserRun{text: run, trusted: trusted})
		}
		parts = parts[:0]
		trusted = true
	}
	for _, segment := range segments {
		if segment.Role != extract.RoleUser || segment.Provenance != extract.ProvenanceContent {
			flush()
			continue
		}
		if _, ok := isolatedCompactRune(segment.Text); !ok {
			flush()
			continue
		}
		parts = append(parts, segment.Text)
		trusted = trusted && segment.UserAttribution == extract.UserAttributionTrusted
	}
	flush()
	return runs
}

func isolatedCompactRune(value string) (rune, bool) {
	trimmed := strings.TrimSpace(value)
	runes := []rune(trimmed)
	if len(runes) != 1 || !isCompactRune(runes[0]) {
		return 0, false
	}
	return runes[0], true
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
	if candidate.FindingOrigin != current.FindingOrigin {
		return candidate.FindingOrigin == FindingOriginUserContent
	}
	return false
}

func resultContainsRuleID(result Result, want string) bool {
	for _, ruleID := range result.RuleIDs {
		if ruleID == want {
			return true
		}
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
