package classifier

import (
	"math/bits"
	"sort"
	"strings"

	"github.com/yujianwudi/cyber-abuse-guard/internal/rules"
)

const maxSemanticDirectiveSpan = 4

type semanticDimension uint8

const (
	semanticHarm semanticDimension = iota
	semanticObject
	semanticAction
	semanticOutcome
	semanticTarget
	semanticDestination
	semanticEvasion
	semanticScale
	semanticSequence
	semanticImpact
	semanticDimensionCount
)

var semanticDimensionKinds = [semanticDimensionCount]string{
	"harm", "object", "action", "outcome", "target",
	"destination", "evasion", "scale", "sequence", "impact",
}

type compiledSemanticEvidence struct {
	id             uint16
	signalID       int
	dimensionMask  uint16
	longerEvidence []uint16
}

type compiledSemanticProfile struct {
	category     rules.Category
	evidence     []compiledSemanticEvidence
	result       [semanticDimensionCount]Evidence
	intentStarts []string
}

func (profile compiledSemanticProfile) id() string {
	return "SEMANTIC-" + string(profile.category)
}

type semanticSignalWindow struct {
	signals [][]bool
	text    string
}

type semanticAssessment struct {
	score    int
	evidence []Evidence
}

type semanticDimensions struct {
	harm, object, action, outcome       bool
	target, destination, evasion, scale bool
	sequence, impact                    bool
}

func (dimensions semanticDimensions) mask() uint16 {
	var mask uint16
	for dimension, matched := range [...]bool{
		dimensions.harm, dimensions.object, dimensions.action, dimensions.outcome,
		dimensions.target, dimensions.destination, dimensions.evasion, dimensions.scale,
		dimensions.sequence, dimensions.impact,
	} {
		if matched {
			mask |= uint16(1) << semanticDimension(dimension)
		}
	}
	return mask
}

func semanticDimensionsFromMask(mask uint16) semanticDimensions {
	matched := func(dimension semanticDimension) bool { return mask&(uint16(1)<<dimension) != 0 }
	return semanticDimensions{
		harm: matched(semanticHarm), object: matched(semanticObject),
		action: matched(semanticAction), outcome: matched(semanticOutcome),
		target: matched(semanticTarget), destination: matched(semanticDestination),
		evasion: matched(semanticEvasion), scale: matched(semanticScale),
		sequence: matched(semanticSequence), impact: matched(semanticImpact),
	}
}

type semanticEvidenceTerm struct {
	normalized    string
	terms         rules.Terms
	dimensionMask uint16
}

func buildSemanticEvidenceTerms(profile rules.SemanticProfile, categoryRules []rules.Rule, implementation, outcome rules.Terms) []semanticEvidenceTerm {
	groups := [semanticDimensionCount]rules.Terms{
		semanticHarm: profile.Harm, semanticObject: profile.Object,
		semanticAction: profile.Action, semanticOutcome: profile.Outcome,
		semanticTarget: profile.Target, semanticDestination: profile.Destination,
		semanticEvasion: profile.Evasion, semanticScale: profile.Scale,
		semanticSequence: profile.Sequence, semanticImpact: profile.Impact,
	}
	appendTerms := func(target *rules.Terms, source rules.Terms) {
		target.ZH = append(target.ZH, source.ZH...)
		target.EN = append(target.EN, source.EN...)
	}
	appendTerms(&groups[semanticAction], implementation)
	appendTerms(&groups[semanticOutcome], outcome)
	for _, rule := range categoryRules {
		appendTerms(&groups[semanticHarm], rule.Intent)
		appendTerms(&groups[semanticObject], rule.Object)
		appendTerms(&groups[semanticAction], rule.Operational)
		appendTerms(&groups[semanticTarget], rule.Target)
		appendTerms(&groups[semanticEvasion], rule.Evasion)
		appendTerms(&groups[semanticScale], rule.Scale)
	}

	byPhrase := make(map[string]int)
	compiled := make([]semanticEvidenceTerm, 0, 96)
	add := func(value string, dimension semanticDimension, chinese bool) {
		normalized := string(normalizeParts([]string{value}).standardRunes)
		if normalized == "" {
			return
		}
		if index, ok := byPhrase[normalized]; ok {
			compiled[index].dimensionMask |= uint16(1) << dimension
			return
		}
		term := semanticEvidenceTerm{normalized: normalized, dimensionMask: uint16(1) << dimension}
		if chinese {
			term.terms.ZH = []string{value}
		} else {
			term.terms.EN = []string{value}
		}
		byPhrase[normalized] = len(compiled)
		compiled = append(compiled, term)
	}
	for dimension, group := range groups {
		for _, value := range group.ZH {
			add(value, semanticDimension(dimension), true)
		}
		for _, value := range group.EN {
			add(value, semanticDimension(dimension), false)
		}
	}
	sort.Slice(compiled, func(left, right int) bool { return compiled[left].normalized < compiled[right].normalized })
	return compiled
}

func linkLongerSemanticEvidence(profile *compiledSemanticProfile, terms []semanticEvidenceTerm) {
	for shorter := range terms {
		for longer := range terms {
			if shorter == longer || len(terms[longer].normalized) <= len(terms[shorter].normalized) {
				continue
			}
			if semanticPhraseContains(terms[longer].normalized, terms[shorter].normalized) {
				profile.evidence[shorter].longerEvidence = append(profile.evidence[shorter].longerEvidence, uint16(longer))
				// The longer occurrence owns the shared phrase ID, but it may be
				// assigned to any one of the dimensions represented by that phrase.
				// This preserves useful ontology meaning without counting the same
				// textual occurrence twice.
				profile.evidence[longer].dimensionMask |= profile.evidence[shorter].dimensionMask
			}
		}
	}
}

func semanticPhraseContains(longer, shorter string) bool {
	if isASCIIStringLocal(shorter) && isASCIIStringLocal(longer) {
		return containsASCIIWord(longer, shorter)
	}
	return strings.Contains(longer, shorter)
}

func semanticDimensionsPotential(dimensions semanticDimensions) bool {
	if !dimensions.object || !(dimensions.harm || dimensions.action || dimensions.outcome) {
		return false
	}
	riskAxes := 0
	evidence := 0
	for _, matched := range []bool{
		dimensions.harm, dimensions.object, dimensions.action, dimensions.outcome,
		dimensions.target, dimensions.destination, dimensions.evasion, dimensions.scale,
		dimensions.sequence, dimensions.impact,
	} {
		if matched {
			evidence++
		}
	}
	for _, matched := range []bool{
		dimensions.action, dimensions.target, dimensions.destination, dimensions.evasion,
		dimensions.scale, dimensions.sequence, dimensions.impact,
	} {
		if matched {
			riskAxes++
		}
	}
	return evidence >= 4 && riskAxes >= 2
}

func semanticDirectiveWindows(analysis analyzedDirectives) []semanticSignalWindow {
	windows := make([]semanticSignalWindow, 0, len(analysis.clauses)*2)
	for start := range analysis.clauses {
		text := ""
		signals := make([][]bool, 0, maxSemanticDirectiveSpan)
		for end := start; end < len(analysis.clauses) && end < start+maxSemanticDirectiveSpan; end++ {
			clause := analysis.clauses[end]
			if end > start && !semanticClausesLinked(analysis.clauses[end-1].text, clause.text, clause.boundaryBefore) {
				break
			}
			signals = append(signals, clause.signals)
			if text == "" {
				text = clause.text
			} else {
				text += "\n" + clause.text
			}
			windows = append(windows, semanticSignalWindow{signals: append([][]bool(nil), signals...), text: text})
		}
	}
	return windows
}

func semanticClausesLinked(previous, current string, boundary directiveBoundaryKind) bool {
	previous = strings.ToLower(strings.TrimSpace(previous))
	current = strings.ToLower(strings.TrimSpace(current))
	if boundary == directiveBoundaryStrong || semanticTopicBreak(previous) || semanticTopicBreak(current) || semanticNegatedBoundary(current) {
		return false
	}
	if boundary == directiveBoundaryNone {
		return false
	}
	if boundary == directiveBoundaryContinuation {
		return true
	}
	if hasAnyPrefix(current,
		"and ", "or ", "then ", "next ", "while ", "with ", "including ", "followed by ",
		"并", "且", "然后", "接着", "随后", "同时", "以及", "包括",
	) || containsAnyLiteral(current,
		" it ", " them ", " those ", " these ", " the same ", " the traffic", " those sessions", " their backups",
		"它", "其", "这些", "上述", "该对象", "该流量", "这些会话", "其备份",
	) {
		return true
	}
	if semanticParallelPassive(previous, current) || semanticElidedPassive(previous, current) ||
		(hasAnyPrefix(previous, "success means ", "success is ", "成功标准", "成功是") || containsAnyLiteral(previous, " success means ", " success is ")) {
		return true
	}
	// A comma-delimited imperative or nominalized list is an explicit local
	// composition. Finite subject clauses are not joined merely because they are
	// adjacent, which prevents unrelated sentences from donating remote axes.
	if semanticFiniteClause(current) {
		return false
	}
	return semanticContinuationFragment(current)
}

func semanticFiniteClause(text string) bool {
	return hasAnyPrefix(text, "i ", "we ", "you ", "he ", "she ", "they ", "the ", "a ", "an ", "this ", "that ", "weather ", "today ", "我", "我们", "你", "他", "她", "他们", "今天", "天气") ||
		containsAnyLiteral(text, " is ", " are ", " was ", " were ", " should ", " would ", " could ", " will ", " can ")
}

func semanticContinuationFragment(text string) bool {
	if text == "" {
		return false
	}
	return hasAnyPrefix(text,
		"avoid ", "bypass ", "copy ", "defeat ", "delete ", "destroy ", "disable ", "disguise ", "eliminate ",
		"accept ", "alter ", "erase ", "escalate ", "extend ", "fill ", "gain ", "have ", "hide ", "keep ", "label ", "leave ", "make ", "mute ", "obtain ", "place ", "prevent ", "provide ", "remove ",
		"retain ", "rewrite ", "route ", "send ", "stage ", "suppress ", "weaken ",
		"alert suppression", "attribution prevention", "authentication bypass", "audit cleanup", "capacity exhaustion",
		"covert ", "credential misuse", "destruction ", "evidence destruction", "failover prevention", "lateral access",
		"central monitoring", "dependency amplification", "privilege escalation", "security-control ", "staged ", "traffic disguise",
		"把", "借", "停掉", "填入", "压缩", "拿下", "留下", "只在", "避开", "绕过", "删除", "清除", "清掉", "拖垮", "隐藏", "静默", "改写", "分批", "随后", "之后", "批量", "外送", "抑制", "阻止",
	)
}

func semanticParallelPassive(previous, current string) bool {
	previousPassive := containsAnyLiteral(previous, " is to be ", " are to be ", " is to become ", " are to become ")
	currentPassive := containsAnyLiteral(current, " is to be ", " are to be ", " is to become ", " are to become ")
	return previousPassive && currentPassive
}

func semanticElidedPassive(previous, current string) bool {
	if !containsAnyLiteral(previous, " is to be ", " are to be ", " is to become ", " are to become ") {
		return false
	}
	return containsAnyLiteral(current,
		" records rewritten", " activity labeled", " export split", " clues erased",
		" nodes dragged", " jobs disturbed", " backups erased", " access returned",
	)
}

func semanticNegatedBoundary(text string) bool {
	text = strings.TrimSpace(text)
	for {
		matched := false
		for _, prefix := range []string{"and ", "or ", "then ", "next ", "并且", "以及", "然后", "接着"} {
			if strings.HasPrefix(text, prefix) {
				text = strings.TrimSpace(text[len(prefix):])
				matched = true
				break
			}
		}
		if !matched {
			break
		}
	}
	return hasAnyPrefix(text,
		"do not ", "don't ", "never ", "must not ", "should not ",
		"不得", "不要", "严禁", "禁止", "无需", "不需要", "无须",
	)
}

func semanticTopicBreak(text string) bool {
	for _, marker := range []string{
		"separately", "respectively", "unrelated", "in another request", "on a different topic", "on another topic", "change topic", "switch topic", "by contrast",
		"另一个请求", "另一个话题", "与此无关", "分别", "另行", "换题", "换个话题", "切换话题",
	} {
		if text == marker || strings.HasPrefix(text, marker+" ") || (!isASCIIStringLocal(marker) && strings.HasPrefix(text, marker)) {
			return true
		}
	}
	return false
}

func structuredSemanticFragment(text string) bool {
	text = strings.TrimSpace(text)
	if strings.Count(text, "--") >= 3 {
		return true
	}
	if len(text) < 2 || !((text[0] == '{' && text[len(text)-1] == '}') || (text[0] == '[' && text[len(text)-1] == ']')) {
		return false
	}
	return strings.Count(text, "\":") >= 3
}

func semanticPartsLinked(previous, current string) bool {
	previous = strings.ToLower(strings.TrimSpace(previous))
	current = strings.ToLower(strings.TrimSpace(current))
	if semanticTopicBreak(previous) || semanticTopicBreak(current) {
		return false
	}
	bound := containsAnyLiteral(previous,
		"combine these", "treat this as", "these details", "one operation", "one rollout", "one deployment",
		"the asset is", "the artifact is", "the component is", "affected assets", "the mechanism is",
		"合并这些", "视为同一", "同一操作", "同一投放", "同一部署", "该资产是", "该组件是", "受影响资产", "该机制是",
	)
	continuationPrefix := ""
	for _, prefix := range []string{"then ", "next ", "continue ", "now ", "接着", "接下来", "然后", "继续", "现在"} {
		if strings.HasPrefix(current, prefix) {
			continuationPrefix = prefix
			break
		}
	}
	if !bound || continuationPrefix == "" || semanticNegatedBoundary(current) {
		return false
	}
	remainder := strings.TrimSpace(current[len(continuationPrefix):])
	return semanticContinuationFragment(remainder) || containsAnyLiteral(remainder,
		"execution sequence", "operating sequence", "operational sequence", "implementation sequence",
		"execution plan", "implementation plan", "deployment plan", "rollout plan", "practical workflow",
		"provide the sequence", "give the sequence", "provide a sequence", "give a sequence",
		"执行顺序", "执行步骤", "实施步骤", "操作顺序", "部署计划", "投放计划", "可操作方案",
	)
}

func (c *Classifier) assessSemanticWindow(profile compiledSemanticProfile, window semanticSignalWindow, policy Policy) semanticAssessment {
	if strings.TrimSpace(window.text) == "" || isLegitimateCategoryWorkflow(profile.category, window.text) || hasAffirmativeSafetyPurpose(window.text) {
		return semanticAssessment{}
	}
	dimensions := c.semanticDimensions(profile, window.signals)
	if !dimensions.object || !(dimensions.harm || dimensions.action || dimensions.outcome) {
		return semanticAssessment{}
	}
	riskAxes := 0
	for _, matched := range []bool{dimensions.action, dimensions.target, dimensions.destination, dimensions.evasion, dimensions.scale, dimensions.sequence, dimensions.impact} {
		if matched {
			riskAxes++
		}
	}
	if riskAxes < 2 {
		return semanticAssessment{}
	}
	if semanticIntentOnlyNegated(window.text, profile.intentStarts) {
		return semanticAssessment{}
	}

	dimensionList := [...]struct {
		dimension semanticDimension
		matched   bool
		points    int
	}{
		{semanticHarm, dimensions.harm, 10}, {semanticObject, dimensions.object, 12},
		{semanticAction, dimensions.action, 9}, {semanticOutcome, dimensions.outcome, 9},
		{semanticTarget, dimensions.target, 8}, {semanticDestination, dimensions.destination, 8},
		{semanticEvasion, dimensions.evasion, 7}, {semanticScale, dimensions.scale, 6},
		{semanticSequence, dimensions.sequence, 6}, {semanticImpact, dimensions.impact, 9},
	}
	// Four independently owned dimensions are the semantic acceptance floor.
	// Base 27 makes the weakest valid object + agency + two-risk-axis set reach
	// balanced without requiring a fifth phrase from the same sentence.
	score := 27
	evidence := make([]Evidence, 0, len(dimensionList))
	for _, dimension := range dimensionList {
		if !dimension.matched {
			continue
		}
		score += dimension.points
		evidence = append(evidence, profile.result[dimension.dimension])
	}
	if len(evidence) < 4 {
		return semanticAssessment{}
	}

	contextSignals := make([]bool, c.signalCount)
	for _, signals := range window.signals {
		for signalID, matched := range signals {
			contextSignals[signalID] = contextSignals[signalID] || matched
		}
	}
	context := c.matchContextsWithPolicy(contextSignals, policy.Allow)
	if hasExplicitHarmConflict(window.text) {
		context.Authorized = false
		context.CTFOrLab = false
	}
	authorizationProtected := policy.HardBlockEvenIfAuthorized.protects(profile.category)
	score = applyContextDeductions(score, context, authorizationProtected)
	genuineSafetyContext := context.Defensive || context.Remediation || context.StaticAnalysis || context.IncidentResponse || context.HighLevel
	if authorizationProtected && !genuineSafetyContext && score < HardThreshold {
		score = HardThreshold
	}
	return semanticAssessment{score: clampScore(score), evidence: evidence}
}

func (c *Classifier) semanticDimensions(profile compiledSemanticProfile, windows [][]bool) semanticDimensions {
	matched := func(signalID int) bool {
		for _, signals := range windows {
			if signalMatched(signals, signalID) {
				return true
			}
		}
		return false
	}
	var reachable [1 << semanticDimensionCount]bool
	reachable[0] = true
	for _, evidence := range profile.evidence {
		if !matched(evidence.signalID) {
			continue
		}
		shadowed := false
		for _, longer := range evidence.longerEvidence {
			if matched(profile.evidence[longer].signalID) {
				shadowed = true
				break
			}
		}
		if shadowed {
			continue
		}
		for state := len(reachable) - 1; state >= 0; state-- {
			if !reachable[state] {
				continue
			}
			for choices := evidence.dimensionMask; choices != 0; choices &= choices - 1 {
				dimension := choices & -choices
				reachable[state|int(dimension)] = true
			}
		}
	}
	bestMask := uint16(0)
	bestUtility := -1
	for state, ok := range reachable {
		if !ok {
			continue
		}
		mask := uint16(state)
		utility := bits.OnesCount16(mask) * 100
		if mask&(uint16(1)<<semanticObject) != 0 {
			utility += 20
		}
		if mask&((uint16(1)<<semanticHarm)|(uint16(1)<<semanticAction)|(uint16(1)<<semanticOutcome)) != 0 {
			utility += 10
		}
		riskMask := mask & ((uint16(1) << semanticAction) | (uint16(1) << semanticTarget) |
			(uint16(1) << semanticDestination) | (uint16(1) << semanticEvasion) |
			(uint16(1) << semanticScale) | (uint16(1) << semanticSequence) | (uint16(1) << semanticImpact))
		utility += bits.OnesCount16(riskMask) * 2
		if utility > bestUtility {
			bestUtility = utility
			bestMask = mask
		}
	}
	return semanticDimensionsFromMask(bestMask)
}

func semanticIntentOnlyNegated(text string, intents []string) bool {
	if len(text) > maxCompactIntentProofBytes {
		// Semantic suppression is optional defensive credit. Oversized windows
		// retain the matched semantic intent instead of paying rules x input
		// rescans to prove that every occurrence is negated.
		return false
	}
	if !containsRuleIntent(text, intents) {
		return false
	}
	return !containsUnnegatedRuleIntent(text, intents)
}
