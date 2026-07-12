// Package classifier implements a deterministic, local abuse classifier. It
// performs no I/O and returns only stable identifiers and aggregate flags.
package classifier

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/yujianwudi/cyber-abuse-guard/internal/rules"
)

const (
	AuditThreshold    = 35
	BalancedThreshold = 60
	HardThreshold     = 80
)

// Mode controls how a score becomes an action. The hard threshold is a global
// safety ceiling for every enabled classifier mode; host integrations may
// still preserve a non-enforcing observe/audit transport policy explicitly.
type Mode string

const (
	ModeOff      Mode = "off"
	ModeObserve  Mode = "observe"
	ModeAudit    Mode = "audit"
	ModeBalanced Mode = "balanced"
	ModeStrict   Mode = "strict"
)

// Action is the policy disposition derived from a score and mode.
type Action string

const (
	ActionAllow   Action = "allow"
	ActionObserve Action = "observe"
	ActionAudit   Action = "audit"
	ActionBlock   Action = "block"
)

// Thresholds are configurable policy thresholds. A zero value selects the
// documented defaults.
type Thresholds struct {
	Audit         int
	BalancedBlock int
	HardBlock     int
}

// ContextPolicy controls which matched safety contexts may reduce risk. A
// disabled field still allows the context to be reported, but it has no effect
// on scoring. Keeping this type independent from internal/config avoids a
// package cycle at the plugin boundary.
type ContextPolicy struct {
	Defensive        bool
	Remediation      bool
	CTF              bool
	Lab              bool
	Authorized       bool
	StaticAnalysis   bool
	IncidentResponse bool
	HighLevel        bool
}

// HardBlockPolicy controls the categories for which an authorization claim is
// not a score-reducing exception.
type HardBlockPolicy struct {
	CredentialTheft      bool
	PhishingDeployment   bool
	RansomwareDeployment bool
	DataExfiltration     bool
}

// Policy contains the configurable context and authorization behavior used by
// ClassifyWithPolicy. It is a value type and is safe to reuse concurrently.
type Policy struct {
	Allow                     ContextPolicy
	HardBlockEvenIfAuthorized HardBlockPolicy
}

// DefaultThresholds returns the production defaults.
func DefaultThresholds() Thresholds {
	return Thresholds{Audit: AuditThreshold, BalancedBlock: BalancedThreshold, HardBlock: HardThreshold}
}

// DefaultPolicy returns the balanced task-book policy.
func DefaultPolicy() Policy {
	return Policy{
		Allow: ContextPolicy{
			Defensive:        true,
			Remediation:      true,
			CTF:              true,
			Lab:              true,
			Authorized:       true,
			StaticAnalysis:   true,
			IncidentResponse: true,
			HighLevel:        true,
		},
		HardBlockEvenIfAuthorized: HardBlockPolicy{
			CredentialTheft:      true,
			PhishingDeployment:   true,
			RansomwareDeployment: true,
			DataExfiltration:     true,
		},
	}
}

// ContextFlags contains no matched text and is safe to include in minimal
// audit metadata.
type ContextFlags struct {
	Defensive        bool `json:"defensive"`
	Remediation      bool `json:"remediation"`
	CTFOrLab         bool `json:"ctf_or_lab"`
	Authorized       bool `json:"authorized"`
	StaticAnalysis   bool `json:"static_analysis"`
	IncidentResponse bool `json:"incident_response"`
	HighLevel        bool `json:"high_level"`
}

// Evidence contains stable rule-local evidence identifiers only.
type Evidence struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

// Result intentionally has no field capable of carrying prompt fragments.
type Result struct {
	RuleSetVersion string         `json:"ruleset_version"`
	Score          int            `json:"score"`
	Category       rules.Category `json:"category,omitempty"`
	Action         Action         `json:"action"`
	RuleIDs        []string       `json:"rule_ids,omitempty"`
	Context        ContextFlags   `json:"context"`
	Evidence       []Evidence     `json:"evidence,omitempty"`
	Truncated      bool           `json:"truncated,omitempty"`
}

type compiledRule struct {
	id                     string
	category               rules.Category
	baseScore              int
	hardFloor              int
	authorizationProtected bool
	intent                 int
	object                 int
	operational            int
	target                 int
	evasion                int
	scale                  int
	intentStarts           []string
}

type compiledContexts map[rules.ContextKind]int

// Classifier is immutable after construction and safe for concurrent use.
type Classifier struct {
	version               string
	rules                 []compiledRule
	contexts              compiledContexts
	standardMatcher       *literalMatcher
	compactMatcher        *literalMatcher
	signalCount           int
	implementationRequest int
}

// New validates and precompiles a private matcher snapshot.
func New(set *rules.RuleSet) (*Classifier, error) {
	if err := rules.Validate(set); err != nil {
		return nil, fmt.Errorf("compile classifier: %w", err)
	}
	c := &Classifier{
		version:  set.Version,
		rules:    make([]compiledRule, 0, len(set.Rules)),
		contexts: make(compiledContexts, len(set.Contexts)),
	}
	standardBuilder := newMatcherBuilder()
	compactBuilder := newMatcherBuilder()
	nextSignal := 0
	compileGroup := func(terms rules.Terms, label string) (int, error) {
		signalID := nextSignal
		nextSignal++
		if err := addTerms(standardBuilder, compactBuilder, terms, signalID); err != nil {
			return 0, fmt.Errorf("compile classifier %s: %w", label, err)
		}
		return signalID, nil
	}
	for _, source := range set.Rules {
		compiled := compiledRule{
			id:                     source.ID,
			category:               source.Category,
			baseScore:              source.BaseScore,
			hardFloor:              source.HardFloor,
			authorizationProtected: source.AuthorizationProtected,
			intentStarts:           normalizedTermValues(source.Intent),
		}
		groups := []struct {
			source rules.Terms
			target *int
			name   string
		}{
			{source.Intent, &compiled.intent, "intent"},
			{source.Object, &compiled.object, "object"},
			{source.Operational, &compiled.operational, "operational"},
			{source.Target, &compiled.target, "target"},
			{source.Evasion, &compiled.evasion, "evasion"},
			{source.Scale, &compiled.scale, "scale"},
		}
		for _, group := range groups {
			signalID, err := compileGroup(group.source, "rule "+source.ID+" "+group.name)
			if err != nil {
				return nil, err
			}
			*group.target = signalID
		}
		c.rules = append(c.rules, compiled)
	}
	contextOrder := []rules.ContextKind{
		rules.ContextDefensive,
		rules.ContextRemediation,
		rules.ContextCTF,
		rules.ContextLab,
		rules.ContextAuthorized,
		rules.ContextStaticAnalysis,
		rules.ContextIncidentResponse,
		rules.ContextHighLevel,
	}
	for _, kind := range contextOrder {
		terms := set.Contexts[kind]
		signalID, err := compileGroup(terms, "context "+string(kind))
		if err != nil {
			return nil, err
		}
		c.contexts[kind] = signalID
	}
	implementationTerms := rules.Terms{
		ZH: []string{"现在给出代码", "现在写代码", "把它实现出来", "继续给完整步骤", "给我代码", "实现上述内容", "实现上面的方案", "按上面方案开始写", "按上述方案开始写", "给出源码", "展示源码", "开始实现", "用 python", "用 powershell", "用 bash", "用 go", "加入错误处理", "逐步给出命令", "把命令列出来"},
		EN: []string{"now give working code", "now write the code", "give me the code", "implement it", "implement the above", "implement the plan above", "now provide steps", "turn that into code", "now give code", "show me the source", "show the source", "provide the source", "start implementing", "write the implementation", "use python", "in python", "use powershell", "in powershell", "use bash", "in bash", "use go", "in go", "include error handling", "show the commands", "step by step"},
	}
	implementationSignal, err := compileGroup(implementationTerms, "implementation request")
	if err != nil {
		return nil, err
	}
	c.implementationRequest = implementationSignal
	c.standardMatcher = standardBuilder.build()
	c.compactMatcher = compactBuilder.build()
	c.signalCount = nextSignal
	return c, nil
}

// Analyze scores parts under the balanced policy defaults.
func (c *Classifier) Analyze(parts []string) Result {
	return c.Classify(parts, ModeBalanced, DefaultThresholds())
}

// Classify scores parts and derives an action for the selected mode.
func (c *Classifier) Classify(parts []string, mode Mode, thresholds Thresholds) Result {
	return c.ClassifyWithPolicy(parts, mode, thresholds, DefaultPolicy())
}

// ClassifyWithPolicy scores parts with explicit configurable context and
// authorization behavior. Callers should start from DefaultPolicy and override
// only fields exposed by their validated configuration.
func (c *Classifier) ClassifyWithPolicy(parts []string, mode Mode, thresholds Thresholds, policy Policy) Result {
	if c == nil {
		return Result{Action: ActionAllow}
	}
	if mode == ModeOff {
		return Result{RuleSetVersion: c.version, Action: ActionAllow}
	}
	thresholds = validThresholdsOrDefault(thresholds)
	signals := make([]bool, c.signalCount)
	coLocatedCores := make([]bool, len(c.rules))
	var previousSignals, currentSignals, scratchSignals []bool
	var previousRunes, currentRunes, scratchRunes []rune
	var normalizerScratch normalizationScratch
	var compactScratch []bool
	partCount := 0
	remainingBytes := maxClassifierInputBytes
	truncated := false
	for partIndex, part := range parts {
		if partIndex >= maxClassifierParts || remainingBytes <= 0 {
			truncated = true
			break
		}
		consumedBytes := len(part)
		if consumedBytes > remainingBytes {
			consumedBytes = remainingBytes
			part = validUTF8Prefix(part, consumedBytes)
			truncated = true
		}
		remainingBytes -= consumedBytes
		views := normalizePartsInto([]string{part}, scratchRunes, &normalizerScratch)
		truncated = truncated || views.truncated
		if len(views.standardRunes) == 0 {
			scratchRunes = views.standardRunes
			continue
		}
		if scratchSignals == nil {
			scratchSignals = make([]bool, c.signalCount)
		} else {
			clear(scratchSignals)
		}
		if compactScratch == nil && c.compactMatcher != nil {
			compactScratch = make([]bool, c.compactMatcher.maxPatternLength)
		}
		c.standardMatcher.match(views.standardRunes, scratchSignals)
		c.compactMatcher.matchCompactWithScratch(views.standardRunes, scratchSignals, compactScratch)
		for signalID, matched := range scratchSignals {
			if matched {
				signals[signalID] = true
			}
		}
		for ruleIndex, rule := range c.rules {
			coLocatedCores[ruleIndex] = coLocatedCores[ruleIndex] || (scratchSignals[rule.intent] && scratchSignals[rule.object])
		}

		previousSignals, currentSignals, scratchSignals = currentSignals, scratchSignals, previousSignals
		previousRunes, currentRunes, scratchRunes = currentRunes, views.standardRunes, previousRunes
		partCount++
	}
	currentContext := ContextFlags{}
	if partCount > 0 {
		currentContext = c.matchContextsWithPolicy(currentSignals, policy.Allow)
	}
	context := currentContext
	carriedCTFOrLab := false
	carriedAuthorized := false
	if partCount > 1 {
		prior := c.matchContextsWithPolicy(previousSignals, policy.Allow)
		carriedCTFOrLab = prior.CTFOrLab
		carriedAuthorized = prior.Authorized
		context.CTFOrLab = context.CTFOrLab || prior.CTFOrLab
		context.Authorized = context.Authorized || prior.Authorized
	}
	result := Result{
		RuleSetVersion: c.version,
		Action:         ActionAllow,
		Context:        context,
		Truncated:      truncated,
	}
	if partCount == 0 {
		result.Action = actionFor(mode, 0, thresholds)
		return result
	}

	type candidate struct {
		score    int
		category rules.Category
		ruleID   string
		evidence []Evidence
	}
	candidates := make([]candidate, 0, 4)
	previousFollowUpEligible := partCount > 1 && followUpEligible(previousRunes)
	var currentDirectives analyzedDirectives
	directivesReady := false
	for ruleIndex, rule := range c.rules {
		intent := signals[rule.intent]
		object := signals[rule.object]
		if !intent || !object {
			continue
		}
		current := currentSignals
		currentCore := current[rule.intent] && current[rule.object]
		if currentCore {
			if !directivesReady {
				currentDirectives = c.analyzeDirectives(currentRunes)
				directivesReady = true
			}
			currentCore = !currentDirectives.ruleCoreIsOnlyNegated(rule)
		}
		priorStrongCore := false
		var priorCoreSignals []bool
		if partCount > 1 {
			prior := previousSignals
			if previousFollowUpEligible && prior[rule.intent] && prior[rule.object] && (rule.baseScore >= BalancedThreshold || prior[rule.target] || prior[rule.evasion] || prior[rule.scale]) {
				priorStrongCore = true
				priorCoreSignals = prior
			}
		}
		implementationFollowUp := current[c.implementationRequest] && priorStrongCore
		if !currentCore && !implementationFollowUp {
			continue
		}
		coreCoLocated := coLocatedCores[ruleIndex]
		evidence := []Evidence{
			{ID: rule.id + ":intent", Kind: "intent"},
			{ID: rule.id + ":object", Kind: "object"},
		}
		score := rule.baseScore
		if !coreCoLocated {
			score -= 20
		}
		qualifiers := 0
		operational := current[rule.operational] || implementationFollowUp
		target := current[rule.target]
		evasion := current[rule.evasion]
		scale := current[rule.scale]
		if implementationFollowUp && priorCoreSignals != nil {
			target = target || priorCoreSignals[rule.target]
			evasion = evasion || priorCoreSignals[rule.evasion]
			scale = scale || priorCoreSignals[rule.scale]
		}
		if operational {
			score += 20
			qualifiers++
			evidence = append(evidence, Evidence{ID: rule.id + ":operational", Kind: "operational"})
		}
		if target {
			score += 18
			qualifiers++
			evidence = append(evidence, Evidence{ID: rule.id + ":target", Kind: "target"})
		}
		if evasion {
			score += 16
			qualifiers++
			evidence = append(evidence, Evidence{ID: rule.id + ":evasion", Kind: "evasion"})
		}
		if scale {
			score += 16
			qualifiers++
			evidence = append(evidence, Evidence{ID: rule.id + ":scale", Kind: "scale"})
		}
		if qualifiers >= 2 {
			score += 5
		}
		if qualifiers > 0 && rule.hardFloor > score {
			score = rule.hardFloor
		}
		effectiveContext := context
		if current[rule.target] {
			if carriedCTFOrLab && !currentContext.CTFOrLab {
				effectiveContext.CTFOrLab = false
			}
			if carriedAuthorized && !currentContext.Authorized {
				effectiveContext.Authorized = false
			}
		}
		authorizationProtected := rule.authorizationProtected && policy.HardBlockEvenIfAuthorized.protects(rule.category)
		contradictoryDirective := false
		if context != (ContextFlags{}) {
			if !directivesReady {
				currentDirectives = c.analyzeDirectives(currentRunes)
				directivesReady = true
			}
			contradictoryDirective = c.hasRuleContradictoryDirective(currentDirectives, rule, policy.Allow)
		}
		if contradictoryDirective {
			// Scoped authorization and named lab boundaries are affirmative scope
			// signals, not generic safety labels. Preserve them for categories where
			// authorization is an accepted exception; protected categories still
			// ignore these deductions below.
			effectiveContext = ContextFlags{
				CTFOrLab:   effectiveContext.CTFOrLab,
				Authorized: effectiveContext.Authorized,
			}
		}
		if implementationFollowUp && !(currentContext.Defensive && currentContext.StaticAnalysis) {
			effectiveContext = ContextFlags{
				CTFOrLab:   effectiveContext.CTFOrLab,
				Authorized: effectiveContext.Authorized,
			}
		}
		score = applyContextDeductions(score, effectiveContext, authorizationProtected)
		strongOperationalAbuse := operational && (target || evasion || scale)
		genuineSafetyContext := effectiveContext.Defensive || effectiveContext.Remediation || effectiveContext.StaticAnalysis || effectiveContext.IncidentResponse || effectiveContext.HighLevel
		protectedOperationalAbuse := authorizationProtected && operational && !genuineSafetyContext
		unmitigatedOperationalAbuse := strongOperationalAbuse && effectiveContext == (ContextFlags{})
		if rule.hardFloor > score && (unmitigatedOperationalAbuse || protectedOperationalAbuse) {
			score = rule.hardFloor
		}
		candidates = append(candidates, candidate{score: score, category: rule.category, ruleID: rule.id, evidence: evidence})
	}
	if len(candidates) == 0 {
		result.Action = actionFor(mode, 0, thresholds)
		result.Evidence = contextEvidence(context)
		return result
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		if candidates[i].category != candidates[j].category {
			return categoryPriority(candidates[i].category) < categoryPriority(candidates[j].category)
		}
		return candidates[i].ruleID < candidates[j].ruleID
	})
	best := candidates[0]
	result.Score = clampScore(best.score)
	result.Category = best.category
	result.RuleIDs = []string{best.ruleID}
	result.Evidence = append(result.Evidence, best.evidence...)
	for _, other := range candidates[1:] {
		if other.category != best.category || other.score != best.score {
			continue
		}
		result.RuleIDs = append(result.RuleIDs, other.ruleID)
		result.Evidence = append(result.Evidence, other.evidence...)
	}
	result.Evidence = append(result.Evidence, contextEvidence(context)...)
	result.RuleIDs = uniqueSorted(result.RuleIDs)
	result.Evidence = uniqueSortedEvidence(result.Evidence)
	result.Action = actionFor(mode, result.Score, thresholds)
	return result
}

func categoryPriority(category rules.Category) int {
	switch category {
	case rules.CategoryCredentialTheft:
		return 0
	case rules.CategoryPhishing:
		return 1
	case rules.CategoryRansomware:
		return 2
	case rules.CategoryExfiltration:
		return 3
	case rules.CategoryEvasion:
		return 4
	case rules.CategoryExploitation:
		return 5
	case rules.CategoryDisruption:
		return 6
	case rules.CategoryMalware:
		return 7
	default:
		return 8
	}
}

const maxAnalyzedDirectiveClauses = 64

type analyzedDirectiveClause struct {
	runes   []rune
	text    string
	signals []bool
}

type analyzedDirectives struct {
	clauses  []analyzedDirectiveClause
	overflow bool
}

// analyzeDirectives scans the current part once and shares the result across
// all candidate rules. The previous implementation reran both literal
// automata for every candidate, making adversarial candidate-rich input scale
// with rules times input size.
func (c *Classifier) analyzeDirectives(text []rune) analyzedDirectives {
	analysis := analyzedDirectives{clauses: make([]analyzedDirectiveClause, 0, 4)}
	walkDirectiveClauses(text, func(clause []rune) bool {
		if len(analysis.clauses) >= maxAnalyzedDirectiveClauses {
			analysis.overflow = true
			return false
		}
		analysis.clauses = append(analysis.clauses, analyzedDirectiveClause{runes: clause})
		return true
	})
	if len(analysis.clauses) == 0 {
		return analysis
	}
	allSignals := make([]bool, len(analysis.clauses)*c.signalCount)
	compactScratch := make([]bool, c.compactMatcher.maxPatternLength)
	for index := range analysis.clauses {
		clause := &analysis.clauses[index]
		clause.text = string(clause.runes)
		clause.signals = allSignals[index*c.signalCount : (index+1)*c.signalCount]
		c.standardMatcher.match(clause.runes, clause.signals)
		c.compactMatcher.matchCompactWithScratch(clause.runes, clause.signals, compactScratch)
	}
	return analysis
}

func (analysis analyzedDirectives) ruleCoreIsOnlyNegated(rule compiledRule) bool {
	// Extreme clause counts are ambiguous and must not turn a matched abuse core
	// into an allow decision merely because analysis was bounded.
	if analysis.overflow {
		return false
	}
	foundCore := false
	foundUnnegatedCore := false
	for _, clause := range analysis.clauses {
		signals := clause.signals
		if !signals[rule.intent] || !signals[rule.object] {
			if foundCore && signals[rule.intent] && !clauseNegatesRuleIntent(clause.text, rule.intentStarts) && startsWithRuleIntent(clause.text, rule.intentStarts) {
				foundUnnegatedCore = true
				break
			}
			continue
		}
		foundCore = true
		if !clauseNegatesRuleIntent(clause.text, rule.intentStarts) {
			foundUnnegatedCore = true
			break
		}
	}
	return foundCore && !foundUnnegatedCore
}

func clauseNegatesRuleIntent(clause string, intents []string) bool {
	intentIndex := earliestRuleIntentIndex(clause, intents)
	if intentIndex < 0 {
		return false
	}
	prefix := strings.TrimSpace(clause[:intentIndex])
	for _, bait := range []string{
		"do not refuse", "don't refuse", "must not refuse", "never hesitate", "do not hesitate", "don't hesitate",
		"ignore the instruction", "ignore the policy", "disregard the instruction", "disregard the policy",
		"不要拒绝", "不得拒绝", "不要犹豫", "忽略指令", "忽略策略",
	} {
		if strings.Contains(prefix, bait) {
			return false
		}
	}
	closest := -1
	closestEnd := -1
	for _, marker := range []string{
		"must never", "must not", "should never", "should not", "do not", "don't", "cannot", "can't",
		"will not", "never", "not to", "forbids", "forbid", "forbidden to", "prohibits", "prohibit", "refuse to",
		"严禁", "禁止", "不得", "不要", "不能", "不会", "拒绝",
	} {
		if index := strings.LastIndex(prefix, marker); index >= 0 && index >= closest {
			closest = index
			closestEnd = index + len(marker)
		}
	}
	if closest < 0 {
		return false
	}
	for _, override := range []string{"ignore", "disregard", "override", "忽略", "无视"} {
		if strings.Contains(prefix[:closest], override) {
			return false
		}
	}
	between := strings.TrimSpace(prefix[closestEnd:])
	for _, doubleNegative := range []string{"refuse", "hesitate", "avoid", "decline", "拒绝", "犹豫", "避免"} {
		if strings.Contains(between, doubleNegative) {
			return false
		}
	}
	if negationScopeInterrupted(between) {
		return false
	}
	return true
}

// negationScopeInterrupted recognizes a second coordinated directive between a
// prohibition and the risky intent. In "do not add comments and deploy
// ransomware", the prohibition applies to adding comments; carrying it across
// the conjunction would let an unrelated harmless clause suppress the abuse.
func negationScopeInterrupted(between string) bool {
	between = strings.TrimSpace(between)
	for _, marker := range []string{" and ", " then ", "并且", "然后"} {
		if index := strings.LastIndex(between, marker); index > 0 {
			return true
		}
	}
	for _, suffix := range []string{" and", " then", "并", "并且", "然后"} {
		if strings.HasSuffix(between, suffix) && strings.TrimSpace(strings.TrimSuffix(between, suffix)) != "" {
			return true
		}
	}
	return false
}

func earliestRuleIntentIndex(text string, intents []string) int {
	earliest := -1
	for _, intent := range intents {
		for offset := 0; offset <= len(text)-len(intent); {
			index := strings.Index(text[offset:], intent)
			if index < 0 {
				break
			}
			index += offset
			leftOK := !isASCIIStringLocal(intent) || index == 0 || !isASCIIWordByte(text[index-1])
			right := index + len(intent)
			rightOK := !isASCIIStringLocal(intent) || right == len(text) || !isASCIIWordByte(text[right])
			if leftOK && rightOK && (earliest < 0 || index < earliest) {
				earliest = index
			}
			offset = index + 1
		}
	}
	return earliest
}

func (c *Classifier) hasRuleContradictoryDirective(analysis analyzedDirectives, rule compiledRule, allow ContextPolicy) bool {
	if analysis.overflow {
		// A context-bearing request with an extreme clause count is ambiguous;
		// fail closed without unbounded rescanning or allocation.
		return true
	}
	for _, clause := range analysis.clauses {
		signals := clause.signals
		if !signals[rule.intent] || !signals[rule.object] {
			continue
		}
		clauseText := clause.text
		clauseContext := c.matchContextsWithPolicy(signals, allow)
		if isSafetyDeliverableClause(clauseText) {
			if c.safetyMarkerHasPriorRuleCore(clauseText, rule) || safetyDeliverableTurnsOperational(clauseText, rule.intentStarts) {
				return true
			}
			continue
		}
		if containsDetectionArtifact(clauseText) {
			if !isSafeDetectionArtifactClause(clauseText) || explanatoryFramingTurnsOperational(clauseText, rule.intentStarts) {
				return true
			}
			continue
		}
		if clauseContext.Remediation && isScopedRetentionMaintenance(clauseText) {
			continue
		}
		if signals[rule.operational] && hasOperationalDeliverableFraming(clauseText) {
			return true
		}
		if startsWithRuleIntent(clauseText, rule.intentStarts) {
			if !isSafeDetectionArtifactClause(clauseText) {
				return true
			}
			continue
		}
		if hasExplanatoryFraming(clauseText) {
			if explanatoryFramingTurnsOperational(clauseText, rule.intentStarts) {
				return true
			}
			continue
		}
		if clauseContext == (ContextFlags{}) {
			return true
		}
	}
	return false
}

func hasOperationalDeliverableFraming(clause string) bool {
	clause = strings.TrimSpace(clause)
	for {
		before := clause
		for _, prefix := range []string{
			"please ", "now ", "then ", "actually ", "instead ", "kindly ", "go ahead and ",
			"could you ", "can you ", "i need you to ", "i want you to ",
			"for incident response ", "for remediation ", "for defensive analysis ", "for static analysis ",
			"请", "现在", "然后", "改为", "用于事件响应", "用于修复", "用于防御分析", "用于静态分析",
		} {
			if strings.HasPrefix(clause, prefix) {
				clause = strings.TrimSpace(clause[len(prefix):])
				break
			}
		}
		if clause == before {
			break
		}
	}
	for _, prefix := range []string{
		"give ", "provide ", "write ", "build ", "create ", "make ", "generate ", "show ", "produce ", "implement ", "develop ", "return ", "supply ",
		"给出", "提供", "编写", "写出", "制作", "创建", "生成", "展示", "实现", "开发",
	} {
		if strings.HasPrefix(clause, prefix) {
			return true
		}
	}
	return false
}

func isScopedRetentionMaintenance(clause string) bool {
	scope := false
	for _, marker := range []string{
		"maintenance", "retention policy", "retention procedure", "expired logs", "old logs", "decommissioned", "end-of-life",
		"维护", "保留策略", "留存策略", "过期日志", "旧日志", "退役",
	} {
		if strings.Contains(clause, marker) {
			scope = true
			break
		}
	}
	if !scope {
		return false
	}
	for _, abusive := range []string{
		"after intrusion", "hide the intrusion", "avoid detection", "destroy evidence", "erase traces", "before the payload", "undetected",
		"入侵后", "掩盖入侵", "躲避检测", "销毁证据", "擦除痕迹", "避免告警",
	} {
		if strings.Contains(clause, abusive) {
			return false
		}
	}
	return true
}

var safetyDeliverableMarkers = []string{
	"recovery checklist", "remediation plan", "mitigation plan", "patch guidance", "restore from backups",
	"detection rule", "security checklist", "incident response plan", "malware protection", "ransomware insurance",
	"malware prevention", "insurance options", "ransomware awareness", "ransomware-awareness", "phishing simulation", "campaign simulation", "phishing campaign tabletop exercise", "awareness training",
	"恢复清单", "修复方案", "缓解方案", "补丁指南", "检测规则", "安全清单", "应急响应方案",
}

func isSafetyDeliverableClause(clause string) bool {
	for _, marker := range safetyDeliverableMarkers {
		if strings.Contains(clause, marker) {
			return true
		}
	}
	return false
}

func (c *Classifier) safetyMarkerHasPriorRuleCore(clause string, rule compiledRule) bool {
	earliest := -1
	for _, marker := range safetyDeliverableMarkers {
		index := strings.Index(clause, marker)
		if index >= 0 && (earliest < 0 || index < earliest) {
			earliest = index
		}
	}
	if earliest < 0 {
		return false
	}
	runes := []rune(clause[:earliest])
	signals := make([]bool, c.signalCount)
	c.standardMatcher.match(runes, signals)
	c.compactMatcher.matchCompact(runes, signals)
	return signals[rule.intent] && signals[rule.object]
}

func safetyDeliverableTurnsOperational(clause string, intents []string) bool {
	for _, marker := range safetyDeliverableMarkers {
		if index := strings.Index(clause, marker); index >= 0 {
			return containsRuleIntent(clause[index+len(marker):], intents)
		}
	}
	return false
}

func explanatoryFramingTurnsOperational(clause string, intents []string) bool {
	for _, marker := range []string{" and ", " while ", " but ", " then ", " instead ", " actually ", " with ", " by ", " using ", " via ", " through ", " including ", "并且", "但是", "然后", "改为", "通过", "使用", "包含"} {
		if index := strings.Index(clause, marker); index >= 0 && containsUnnegatedRuleIntent(clause[index+len(marker):], intents) {
			return true
		}
	}
	return false
}

func containsUnnegatedRuleIntent(text string, intents []string) bool {
	foundLiteral := false
	for _, intent := range intents {
		for offset := 0; offset <= len(text)-len(intent); {
			index := strings.Index(text[offset:], intent)
			if index < 0 {
				break
			}
			index += offset
			leftOK := !isASCIIStringLocal(intent) || index == 0 || !isASCIIWordByte(text[index-1])
			right := index + len(intent)
			rightOK := !isASCIIStringLocal(intent) || right == len(text) || !isASCIIWordByte(text[right])
			if leftOK && rightOK {
				foundLiteral = true
				prefix := strings.TrimSpace(text[:index])
				negated := false
				for _, negation := range []string{"without", "not", "never", "do not", "don't", "不要", "不得", "不"} {
					if strings.HasSuffix(prefix, negation) {
						negated = true
						break
					}
				}
				if !negated {
					return true
				}
			}
			offset = index + 1
		}
	}
	return !foundLiteral && containsRuleIntent(text, intents)
}

func containsRuleIntent(text string, intents []string) bool {
	text = strings.TrimSpace(text)
	for _, intent := range intents {
		if isASCIIStringLocal(intent) {
			if containsASCIIWord(text, intent) {
				return true
			}
		} else if strings.Contains(text, intent) {
			return true
		}
	}
	compactText := compactString([]rune(text))
	for _, intent := range intents {
		compactIntent := compactString([]rune(intent))
		if len(compactIntent) >= 2 && strings.Contains(compactText, compactIntent) {
			return true
		}
	}
	return false
}

func isASCIIStringLocal(value string) bool {
	for _, r := range value {
		if r > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func normalizedTermValues(terms rules.Terms) []string {
	values := make([]string, 0, len(terms.ZH)+len(terms.EN))
	source := append(append([]string(nil), terms.ZH...), terms.EN...)
	for _, value := range source {
		normalized := string(normalizeParts([]string{value}).standardRunes)
		if normalized != "" {
			values = append(values, normalized)
		}
	}
	sort.Slice(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
	return values
}

func startsWithRuleIntent(clause string, intents []string) bool {
	clause = strings.TrimSpace(clause)
	for {
		before := clause
		for _, prefix := range []string{
			"please ", "now ", "then ", "actually ", "instead ", "kindly ", "go ahead and ",
			"could you ", "can you ", "i need you to ", "i want you to ",
			"for incident response ", "for remediation ", "for defensive analysis ",
			"for static analysis ", "for a high-level analysis ", "for high-level analysis ",
			"as part of remediation ", "in an incident response exercise ",
			"请", "现在", "然后", "改为", "用于事件响应", "用于修复", "用于防御分析", "用于静态分析", "用于高层次分析",
		} {
			if strings.HasPrefix(clause, prefix) {
				clause = strings.TrimSpace(clause[len(prefix):])
				break
			}
		}
		if clause == before {
			break
		}
	}
	for _, intent := range intents {
		if !strings.HasPrefix(clause, intent) {
			continue
		}
		if len(clause) == len(intent) || !isASCIIWordByte(clause[len(intent)]) {
			return true
		}
	}
	compactClause := compactString([]rune(clause))
	for _, intent := range intents {
		compactIntent := compactString([]rune(intent))
		if len(compactIntent) >= 2 && strings.HasPrefix(compactClause, compactIntent) {
			return true
		}
	}
	return false
}

func isSafeDetectionArtifactClause(clause string) bool {
	if !containsDetectionArtifact(clause) {
		return false
	}
	detectionSemantics := false
	for _, marker := range []string{"detect", "alert", "signature", "indicator", "match", "检测", "告警", "签名", "指标", "匹配"} {
		if strings.Contains(clause, marker) {
			detectionSemantics = true
			break
		}
	}
	if !detectionSemantics {
		return false
	}
	clause = strings.TrimSpace(clause)
	for _, prefix := range []string{
		"write a ", "write ", "create a ", "create ", "build a ", "build ", "generate a ", "generate ", "draft a ", "draft ", "produce a ", "produce ",
		"编写", "创建", "制作", "生成", "起草",
	} {
		if strings.HasPrefix(clause, prefix) {
			return true
		}
	}
	return false
}

func containsDetectionArtifact(clause string) bool {
	for _, marker := range []string{
		"yara rule", "yara signature", "sigma rule", "suricata rule", "suricata signature", "snort rule", "snort signature", "ioc extraction", "indicators of compromise",
		"yara 规则", "sigma 规则", "suricata 规则", "snort 规则", "ioc 提取", "入侵指标",
	} {
		if strings.Contains(clause, marker) {
			return true
		}
	}
	return false
}

var directiveMarkers = [][]rune{
	[]rune(" but "), []rune(" however "), []rune(" then "), []rune(" instead "), []rune(" actually "), []rune(" while "),
	[]rune("但是"), []rune("然而"), []rune("然后"), []rune("改为"), []rune("实际"),
}

func walkDirectiveClauses(text []rune, visit func([]rune) bool) {
	start := 0
	for index := 0; index < len(text); index++ {
		width := directiveBoundaryWidth(text, index)
		if width == 0 {
			continue
		}
		if clause := trimRuneSpaces(text[start:index]); len(clause) > 0 {
			if !visit(clause) {
				return
			}
		}
		start = index + width
		index += width - 1
	}
	if clause := trimRuneSpaces(text[start:]); len(clause) > 0 {
		visit(clause)
	}
}

func directiveBoundaryWidth(text []rune, index int) int {
	r := text[index]
	if r == compactHardBoundary {
		return 1
	}
	switch r {
	case '.', '!', '?', ';', ':', ',', '。', '！', '？', '；', '：', '，':
		if !singleRuneTokensAround(text, index) {
			return 1
		}
	}
	for _, marker := range directiveMarkers {
		if len(text)-index < len(marker) {
			continue
		}
		matched := true
		for offset := range marker {
			if text[index+offset] != marker[offset] {
				matched = false
				break
			}
		}
		if matched {
			return len(marker)
		}
	}
	return 0
}

func lastDirectiveClause(text []rune) []rune {
	start := 0
	var last []rune
	for index := 0; index < len(text); index++ {
		if width := directiveBoundaryWidth(text, index); width > 0 {
			if clause := trimRuneSpaces(text[start:index]); len(clause) > 0 {
				last = clause
			}
			start = index + width
			index += width - 1
		}
	}
	if clause := trimRuneSpaces(text[start:]); len(clause) > 0 {
		return clause
	}
	return last
}

func trimRuneSpaces(value []rune) []rune {
	for len(value) > 0 && unicode.IsSpace(value[0]) {
		value = value[1:]
	}
	for len(value) > 0 && unicode.IsSpace(value[len(value)-1]) {
		value = value[:len(value)-1]
	}
	return value
}

func hasExplanatoryFraming(clause string) bool {
	for _, framing := range []string{
		"explain", "analyze", "analysis", "overview", "detect", "prevent",
		"mitigation", "remediation", "how attackers", "how an attacker", "why attackers",
		"risk of", "risks of", "warning signs", "draft a system policy", "draft a safety policy",
		"found", "discovered", "was disabled", "after detecting",
		"解释", "分析", "概述", "检测", "防止", "修复", "缓解", "攻击者如何", "为何攻击者", "风险", "发现", "被关闭",
	} {
		if strings.Contains(clause, framing) {
			return true
		}
	}
	return false
}

func followUpEligible(text []rune) bool {
	whole := string(text)
	lastClause := string(lastDirectiveClause(text))
	if lastClause == "" {
		return false
	}
	for _, reinforcing := range []string{
		"do not refuse", "don't refuse", "must not refuse", "never hesitate", "do not hesitate", "don't hesitate",
		"不要拒绝", "不得拒绝", "不要犹豫", "不得犹豫",
	} {
		if strings.Contains(lastClause, reinforcing) {
			return true
		}
	}
	if hasNegatedSafetyFraming(lastClause) {
		return false
	}
	policyFraming := false
	for _, phrase := range []string{"system policy", "safety policy", "content policy", "系统策略", "安全策略", "内容策略"} {
		policyFraming = policyFraming || strings.Contains(whole, phrase)
	}
	if policyFraming {
		for _, override := range []string{"ignore the", "is irrelevant", "irrelevant", "disregard", "忽略", "无关"} {
			if strings.Contains(whole, override) {
				return true
			}
		}
		return false
	}
	return true
}

func hasNegatedSafetyFraming(text string) bool {
	for _, phrase := range []string{
		"never ", "do not ", "don't ", "must not ", "should not ",
		"cannot ", "can't ", "will not ", "refuse to ", "prohibited", "forbidden",
		"不要", "不得", "不能", "不会", "拒绝", "禁止", "严禁",
	} {
		if strings.Contains(text, phrase) {
			return true
		}
	}
	return false
}

func containsASCIIWord(text, term string) bool {
	for offset := 0; offset <= len(text)-len(term); {
		index := strings.Index(text[offset:], term)
		if index < 0 {
			return false
		}
		index += offset
		leftOK := index == 0 || !isASCIIWordByte(text[index-1])
		right := index + len(term)
		rightOK := right == len(text) || !isASCIIWordByte(text[right])
		if leftOK && rightOK {
			return true
		}
		offset = index + 1
	}
	return false
}

func isASCIIWordByte(value byte) bool {
	return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9') || value == '_'
}

func (c *Classifier) matchContexts(signals []bool) ContextFlags {
	return ContextFlags{
		Defensive:        signals[c.contexts[rules.ContextDefensive]],
		Remediation:      signals[c.contexts[rules.ContextRemediation]],
		CTFOrLab:         signals[c.contexts[rules.ContextCTF]] || signals[c.contexts[rules.ContextLab]],
		Authorized:       signals[c.contexts[rules.ContextAuthorized]],
		StaticAnalysis:   signals[c.contexts[rules.ContextStaticAnalysis]],
		IncidentResponse: signals[c.contexts[rules.ContextIncidentResponse]],
		HighLevel:        signals[c.contexts[rules.ContextHighLevel]],
	}
}

func (c *Classifier) matchContextsWithPolicy(signals []bool, policy ContextPolicy) ContextFlags {
	context := c.matchContexts(signals)
	return ContextFlags{
		Defensive:        context.Defensive && policy.Defensive,
		Remediation:      context.Remediation && policy.Remediation,
		CTFOrLab:         (signals[c.contexts[rules.ContextCTF]] && policy.CTF) || (signals[c.contexts[rules.ContextLab]] && policy.Lab),
		Authorized:       context.Authorized && policy.Authorized,
		StaticAnalysis:   context.StaticAnalysis && policy.StaticAnalysis,
		IncidentResponse: context.IncidentResponse && policy.IncidentResponse,
		HighLevel:        context.HighLevel && policy.HighLevel,
	}
}

func (policy HardBlockPolicy) protects(category rules.Category) bool {
	switch category {
	case rules.CategoryCredentialTheft:
		return policy.CredentialTheft
	case rules.CategoryPhishing:
		return policy.PhishingDeployment
	case rules.CategoryRansomware:
		return policy.RansomwareDeployment
	case rules.CategoryExfiltration:
		return policy.DataExfiltration
	default:
		return false
	}
}

func applyContextDeductions(score int, context ContextFlags, authorizationProtected bool) int {
	if context.Defensive {
		score -= 22
	}
	if context.Remediation {
		score -= 28
	}
	if context.CTFOrLab && !(authorizationProtected && context.Authorized) {
		score -= 28
	}
	if context.Authorized && !authorizationProtected {
		score -= 22
	}
	if context.StaticAnalysis {
		score -= 28
	}
	if context.IncidentResponse {
		score -= 30
	}
	if context.HighLevel {
		score -= 25
	}
	return clampScore(score)
}

func contextEvidence(context ContextFlags) []Evidence {
	evidence := make([]Evidence, 0, 7)
	appendIf := func(condition bool, id string) {
		if condition {
			evidence = append(evidence, Evidence{ID: id, Kind: "context"})
		}
	}
	appendIf(context.Defensive, "CTX:defensive")
	appendIf(context.Remediation, "CTX:remediation")
	appendIf(context.CTFOrLab, "CTX:ctf_lab")
	appendIf(context.Authorized, "CTX:authorized")
	appendIf(context.StaticAnalysis, "CTX:static_analysis")
	appendIf(context.IncidentResponse, "CTX:incident_response")
	appendIf(context.HighLevel, "CTX:high_level")
	return evidence
}

func actionFor(mode Mode, score int, thresholds Thresholds) Action {
	if mode != ModeOff && score >= thresholds.HardBlock {
		return ActionBlock
	}
	switch mode {
	case ModeObserve:
		if score >= thresholds.Audit {
			return ActionObserve
		}
		return ActionAllow
	case ModeAudit:
		if score >= thresholds.Audit {
			return ActionAudit
		}
		return ActionAllow
	case ModeStrict:
		if score >= thresholds.Audit {
			return ActionBlock
		}
		return ActionAllow
	case ModeBalanced:
		if score >= thresholds.BalancedBlock {
			return ActionBlock
		}
		if score >= thresholds.Audit {
			return ActionAudit
		}
		return ActionAllow
	default:
		return ActionAllow
	}
}

func validThresholdsOrDefault(thresholds Thresholds) Thresholds {
	if thresholds == (Thresholds{}) {
		return DefaultThresholds()
	}
	if thresholds.Audit < 0 || thresholds.BalancedBlock < thresholds.Audit || thresholds.HardBlock < thresholds.BalancedBlock || thresholds.HardBlock > 100 {
		return DefaultThresholds()
	}
	return thresholds
}

func clampScore(score int) int {
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

func uniqueSorted(values []string) []string {
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func uniqueSortedEvidence(values []Evidence) []Evidence {
	sort.Slice(values, func(i, j int) bool {
		if values[i].ID != values[j].ID {
			return values[i].ID < values[j].ID
		}
		return values[i].Kind < values[j].Kind
	})
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}
