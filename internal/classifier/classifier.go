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
	PolicyVersion  string         `json:"policy_version"`
	PolicySHA256   string         `json:"policy_sha256"`
	RuleSetVersion string         `json:"ruleset_version"`
	Score          int            `json:"score"`
	Category       rules.Category `json:"category,omitempty"`
	Action         Action         `json:"action"`
	RuleIDs        []string       `json:"rule_ids,omitempty"`
	Context        ContextFlags   `json:"context"`
	Evidence       []Evidence     `json:"evidence,omitempty"`
	Behavior       *BehaviorGraph `json:"behavior,omitempty"`
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
	independentOperational int
	independentTarget      int
	independentEvasion     int
	independentScale       int
	intentStarts           []string
}

type compiledContexts map[rules.ContextKind]int

var classifierCategoryOrder = []rules.Category{
	rules.CategoryCredentialTheft,
	rules.CategoryPhishing,
	rules.CategoryMalware,
	rules.CategoryRansomware,
	rules.CategoryExploitation,
	rules.CategoryDisruption,
	rules.CategoryExfiltration,
	rules.CategoryEvasion,
}

// Classifier is immutable after construction and safe for concurrent use.
type Classifier struct {
	version               string
	rules                 []compiledRule
	contexts              compiledContexts
	standardMatcher       *literalMatcher
	compactMatcher        *literalMatcher
	categoryRules         map[rules.Category][]int
	signalCount           int
	implementationRequest int
	outcomeRequest        int
	metaOverride          compiledMetaOverrideSignals
	semanticProfiles      []compiledSemanticProfile
}

// New validates and precompiles a private matcher snapshot.
func New(set *rules.RuleSet) (*Classifier, error) {
	if err := rules.Validate(set); err != nil {
		return nil, fmt.Errorf("compile classifier: %w", err)
	}
	c := &Classifier{
		version:       set.Version,
		rules:         make([]compiledRule, 0, len(set.Rules)),
		contexts:      make(compiledContexts, len(set.Contexts)),
		categoryRules: make(map[rules.Category][]int, len(classifierCategoryOrder)),
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
	compileOptionalGroup := func(terms rules.Terms, label string) (int, error) {
		if len(terms.ZH) == 0 && len(terms.EN) == 0 {
			return -1, nil
		}
		return compileGroup(terms, label)
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
		independentGroups := []struct {
			source rules.Terms
			target *int
			name   string
		}{
			{source.Operational, &compiled.independentOperational, "independent operational"},
			{source.Target, &compiled.independentTarget, "independent target"},
			{source.Evasion, &compiled.independentEvasion, "independent evasion"},
			{source.Scale, &compiled.independentScale, "independent scale"},
		}
		coveredGroups := []rules.Terms{source.Intent, source.Object}
		for _, group := range independentGroups {
			terms := independentQualifierTerms(group.source, coveredGroups...)
			signalID, err := compileOptionalGroup(terms, "rule "+source.ID+" "+group.name)
			if err != nil {
				return nil, err
			}
			*group.target = signalID
			coveredGroups = append(coveredGroups, group.source)
		}
		c.rules = append(c.rules, compiled)
		c.categoryRules[compiled.category] = append(c.categoryRules[compiled.category], len(c.rules)-1)
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
		ZH: []string{"现在给出代码", "现在写代码", "把它实现出来", "继续给完整步骤", "给我代码", "实现上述内容", "实现上面的方案", "按上面方案开始写", "按上述方案开始写", "给出源码", "展示源码", "开始实现", "用 python", "用 powershell", "用 bash", "用 go", "加入错误处理", "逐步给出命令", "把命令列出来", "给出实际步骤", "给出执行流程", "给出可操作方案", "制定执行计划", "制定投放计划", "具体怎么做", "实施步骤"},
		EN: []string{"now give working code", "now write the code", "give me the code", "implement it", "implement the above", "implement the plan above", "now provide steps", "turn that into code", "now give code", "show me the source", "show the source", "provide the source", "start implementing", "write the implementation", "use python", "in python", "use powershell", "in powershell", "use bash", "in bash", "use go", "in go", "include error handling", "show the commands", "step by step", "practical steps", "actionable steps", "practical workflow", "operational workflow", "execution plan", "deployment plan", "rollout plan", "implementation plan", "lay out how to"},
	}
	implementationSignal, err := compileGroup(implementationTerms, "implementation request")
	if err != nil {
		return nil, err
	}
	c.implementationRequest = implementationSignal
	outcomeTerms := rules.Terms{
		ZH: []string{"最终结果", "最终要", "最终应", "最终状态", "最终需要", "目标结果", "目标是", "成功标准", "完成后", "交付后", "结果应", "结果要", "期望结果", "预期结果", "所需终态", "要求的终态"},
		EN: []string{"desired outcome", "desired result", "required outcome", "required result", "specific outcome", "target outcome", "end result", "end state", "end-state", "required end state", "final outcome", "final state", "success means", "success is", "success criteria", "at completion", "when finished", "by the end", "once complete", "once finished"},
	}
	outcomeSignal, err := compileGroup(outcomeTerms, "outcome request")
	if err != nil {
		return nil, err
	}
	c.outcomeRequest = outcomeSignal
	metaTargets := []*int{
		&c.metaOverride.hierarchy,
		&c.metaOverride.refusalSuppression,
		&c.metaOverride.unrestrictedMode,
		&c.metaOverride.directCompletion,
		&c.metaOverride.scopeLaundering,
		&c.metaOverride.outputControl,
		&c.metaOverride.secretDisclosure,
		&c.metaOverride.negativeAuthorization,
	}
	for index, terms := range metaOverrideTermGroups() {
		signalID, compileErr := compileGroup(terms, fmt.Sprintf("meta override family %d", index+1))
		if compileErr != nil {
			return nil, compileErr
		}
		*metaTargets[index] = signalID
	}
	for _, category := range classifierCategoryOrder {
		profile, ok := set.Semantics[category]
		if !ok {
			continue
		}
		compiled := compiledSemanticProfile{
			category:     category,
			intentStarts: append(normalizedTermValues(profile.Harm), normalizedTermValues(profile.Action)...),
		}
		categorySources := make([]rules.Rule, 0, len(c.categoryRules[category]))
		for _, ruleIndex := range c.categoryRules[category] {
			compiled.intentStarts = append(compiled.intentStarts, c.rules[ruleIndex].intentStarts...)
			categorySources = append(categorySources, set.Rules[ruleIndex])
		}
		compiled.intentStarts = uniqueSorted(compiled.intentStarts)
		evidenceTerms := buildSemanticEvidenceTerms(profile, categorySources, implementationTerms, outcomeTerms)
		compiled.evidence = make([]compiledSemanticEvidence, len(evidenceTerms))
		for index, evidenceTerm := range evidenceTerms {
			signalID, compileErr := compileGroup(evidenceTerm.terms, "semantic "+string(category)+" evidence")
			if compileErr != nil {
				return nil, compileErr
			}
			compiled.evidence[index] = compiledSemanticEvidence{
				id: uint16(index), signalID: signalID, dimensionMask: evidenceTerm.dimensionMask,
			}
		}
		linkLongerSemanticEvidence(&compiled, evidenceTerms)
		for dimension, kind := range semanticDimensionKinds {
			compiled.result[dimension] = Evidence{ID: compiled.id() + ":" + kind, Kind: kind}
		}
		c.semanticProfiles = append(c.semanticProfiles, compiled)
	}
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
	return c.classifyWithPolicy(parts, mode, thresholds, policy, false)
}

// classifyWithPolicy keeps role provenance out of the public API while
// allowing a provider-native structured tool payload to retain one whole-part
// semantic window. Ordinary user text never receives that exception.
func (c *Classifier) classifyWithPolicy(parts []string, mode Mode, thresholds Thresholds, policy Policy, structuredToolPayload bool) Result {
	if c == nil {
		return Result{PolicyVersion: ClassifierPolicyVersion, PolicySHA256: ClassifierPolicySHA256, Action: ActionAllow}
	}
	if mode == ModeOff {
		return Result{
			PolicyVersion: ClassifierPolicyVersion, PolicySHA256: ClassifierPolicySHA256,
			RuleSetVersion: c.version, Action: ActionAllow,
		}
	}
	thresholds = validThresholdsOrDefault(thresholds)
	signals := make([]bool, c.signalCount)
	coLocatedCores := make([]bool, len(c.rules))
	var previousSignals, currentSignals, scratchSignals []bool
	var previousRunes, currentRunes, scratchRunes []rune
	var previousRunesUsed, currentRunesUsed, scratchRunesUsed int
	defer func() {
		putNormalizedRuneBuffer(previousRunes, previousRunesUsed)
		putNormalizedRuneBuffer(currentRunes, currentRunesUsed)
		putNormalizedRuneBuffer(scratchRunes, scratchRunesUsed)
	}()
	var normalizerScratch normalizationScratch
	var compactScratch []bool
	// Family bits accumulate across the current explicitly linked meta chain so
	// a long chain cannot evict its first unique signal. Only the raw text window
	// is capped at eight parts; the signal set itself is bounded by signalCount.
	metaTailSignals := make([]bool, c.signalCount)
	metaTailParts := make([]string, 0, 8)
	metaTailActive := false
	metaTailLastPart := ""
	bestMeta := metaOverrideAssessment{}
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
		if scratchRunes == nil {
			scratchRunes = takeNormalizedRuneBuffer()
		}
		views := normalizePartsInto([]string{part}, scratchRunes, &normalizerScratch)
		bufferUsed := views.storageUsed
		if scratchRunesUsed > bufferUsed {
			bufferUsed = scratchRunesUsed
		}
		truncated = truncated || views.truncated
		if len(views.standardRunes) == 0 {
			scratchRunes = views.standardRunes
			scratchRunesUsed = bufferUsed
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
		currentHasMeta := c.hasMetaOverrideSignal(scratchSignals)
		if currentHasMeta {
			partText := string(views.standardRunes)
			linked := metaTailActive && metaOverridePartsLinked(metaTailLastPart, partText)
			if !linked {
				clear(metaTailSignals)
				metaTailParts = metaTailParts[:0]
				metaTailActive = false
				metaTailLastPart = ""
			}
			metaTailActive = true
			metaTailLastPart = partText
			if len(metaTailParts) == cap(metaTailParts) {
				copy(metaTailParts, metaTailParts[1:])
				metaTailParts = metaTailParts[:len(metaTailParts)-1]
			}
			for signalID, matched := range scratchSignals {
				if matched {
					metaTailSignals[signalID] = true
				}
			}
			metaTailParts = append(metaTailParts, partText)
			metaTailText := partText
			if len(metaTailParts) > 1 {
				metaTailText = strings.Join(metaTailParts, "\n")
			}
			metaContext := c.matchContextsWithPolicy(metaTailSignals, policy.Allow)
			assessment := c.assessMetaOverride([][]bool{metaTailSignals}, metaTailText, metaContext)
			if assessment.score > bestMeta.score || (assessment.score == bestMeta.score && len(assessment.evidence) > len(bestMeta.evidence)) {
				bestMeta = assessment
			}
		} else if metaTailActive {
			clear(metaTailSignals)
			metaTailParts = metaTailParts[:0]
			metaTailActive = false
			metaTailLastPart = ""
		}
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
		previousRunesUsed, currentRunesUsed, scratchRunesUsed = currentRunesUsed, bufferUsed, previousRunesUsed
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
		PolicyVersion:  ClassifierPolicyVersion,
		PolicySHA256:   ClassifierPolicySHA256,
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
		ruleIDs  []string
		evidence []Evidence
	}
	candidates := make([]candidate, 0, 8)
	var categoryHasCandidate [8]bool
	previousFollowUpEligible := partCount > 1 && followUpEligible(previousRunes)
	var currentDirectives analyzedDirectives
	directivesReady := false
	currentText := string(currentRunes)
	previousHarmConflict := false
	previousHarmConflictReady := false
	for ruleIndex, rule := range c.rules {
		intent := signals[rule.intent]
		object := signals[rule.object]
		current := currentSignals
		objectQualifiedFallback := isCredentialObjectQualifiedFallback(rule, current) &&
			!isLegitimateCategoryWorkflow(rule.category, currentText)
		if (!intent || !object) && !objectQualifiedFallback {
			continue
		}
		currentCore := current[rule.intent] && current[rule.object]
		if currentCore {
			if !directivesReady {
				currentDirectives = c.analyzeDirectives(currentRunes)
				directivesReady = true
			}
			currentCore = !currentDirectives.ruleCoreIsOnlyNegated(rule)
			if currentCore && isLegitimateCategoryWorkflow(rule.category, currentText) {
				currentCore = false
			}
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
		if !currentCore && !implementationFollowUp && !objectQualifiedFallback {
			continue
		}
		coreCoLocated := coLocatedCores[ruleIndex]
		score := rule.baseScore
		evidence := []Evidence{{ID: rule.id + ":object", Kind: "object"}}
		if objectQualifiedFallback {
			// Credential artifacts combined with operational, real-target, and
			// evasion evidence form four independent signals even when an
			// unfamiliar theft verb is used. A missing intent still receives a
			// conservative penalty and a bare credential keyword never blocks.
			score -= 25
		} else {
			evidence = append(evidence, Evidence{ID: rule.id + ":intent", Kind: "intent"})
		}
		if !objectQualifiedFallback && !coreCoLocated {
			score -= 20
		}
		qualifiers := 0
		// A same-turn request for code, commands, an execution plan, or a
		// practical workflow is operational evidence too. Previously this signal
		// was used only for a later follow-up, which let explicit abuse phrased as
		// "give me a plan to ..." remain below the balanced threshold.
		operational := signalMatched(current, rule.independentOperational) || current[c.implementationRequest] || implementationFollowUp
		target := signalMatched(current, rule.independentTarget)
		evasion := signalMatched(current, rule.independentEvasion)
		scale := signalMatched(current, rule.independentScale)
		if implementationFollowUp && priorCoreSignals != nil {
			target = target || signalMatched(priorCoreSignals, rule.independentTarget)
			evasion = evasion || signalMatched(priorCoreSignals, rule.independentEvasion)
			scale = scale || signalMatched(priorCoreSignals, rule.independentScale)
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
		priorTargetConflict := implementationFollowUp && priorCoreSignals != nil && signalMatched(priorCoreSignals, rule.target)
		if current[rule.target] || priorTargetConflict {
			if carriedCTFOrLab && !currentContext.CTFOrLab {
				effectiveContext.CTFOrLab = false
			}
			if carriedAuthorized && !currentContext.Authorized {
				effectiveContext.Authorized = false
			}
		}
		priorHarmConflict := false
		if implementationFollowUp {
			if !previousHarmConflictReady {
				previousHarmConflict = hasExplicitHarmConflict(string(previousRunes))
				previousHarmConflictReady = true
			}
			priorHarmConflict = previousHarmConflict
		}
		if hasExplicitHarmConflict(currentText) || priorHarmConflict {
			effectiveContext.Authorized = false
			effectiveContext.CTFOrLab = false
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
		categoryHasCandidate[categoryPriority(rule.category)] = true
	}

	// A requested end state can describe clear abuse without using a familiar
	// action verb. Compose this semantic intent only inside one category and
	// require a harmful object plus two independent qualifier dimensions. This
	// lets related rules contribute complementary target/destination/scale
	// vocabulary while retaining the same multi-evidence floor as ordinary
	// rule candidates.
	if signalMatched(currentSignals, c.outcomeRequest) && !hasAffirmativeSafetyPurpose(currentText) {
		for _, category := range classifierCategoryOrder {
			if categoryHasCandidate[categoryPriority(category)] || isLegitimateCategoryWorkflow(category, currentText) {
				continue
			}
			if !directivesReady {
				currentDirectives = c.analyzeDirectives(currentRunes)
				directivesReady = true
			}
			if c.categoryMatchedIntentsAreOnlyNegated(category, currentSignals, currentDirectives) {
				continue
			}
			providers := c.categoryOutcomeProviders(category, currentSignals)
			if providers.object < 0 || providers.qualifierCount() < 2 {
				continue
			}
			objectRule := c.rules[providers.object]
			score := 45
			evidence := []Evidence{
				{ID: objectRule.id + ":object", Kind: "object"},
				{ID: objectRule.id + ":outcome", Kind: "intent"},
			}
			ruleIDs := []string{objectRule.id}
			appendQualifier := func(provider int, present bool, points int, kind string) {
				if !present {
					return
				}
				score += points
				qualifierRule := objectRule
				if provider >= 0 {
					qualifierRule = c.rules[provider]
					ruleIDs = append(ruleIDs, qualifierRule.id)
				}
				evidence = append(evidence, Evidence{ID: qualifierRule.id + ":" + kind, Kind: kind})
			}
			appendQualifier(providers.operational, providers.hasOperational, 20, "operational")
			appendQualifier(providers.target, providers.target >= 0, 18, "target")
			appendQualifier(providers.evasion, providers.evasion >= 0, 16, "evasion")
			appendQualifier(providers.scale, providers.scale >= 0, 16, "scale")
			if providers.qualifierCount() >= 2 {
				score += 5
			}

			effectiveContext := context
			if hasExplicitHarmConflict(currentText) {
				effectiveContext.Authorized = false
				effectiveContext.CTFOrLab = false
			}
			authorizationProtected := objectRule.authorizationProtected && policy.HardBlockEvenIfAuthorized.protects(category)
			score = applyContextDeductions(score, effectiveContext, authorizationProtected)
			genuineSafetyContext := effectiveContext.Defensive || effectiveContext.Remediation || effectiveContext.StaticAnalysis || effectiveContext.IncidentResponse || effectiveContext.HighLevel
			if authorizationProtected && !genuineSafetyContext && score < HardThreshold {
				score = HardThreshold
			}
			candidates = append(candidates, candidate{
				score:    clampScore(score),
				category: category,
				ruleIDs:  uniqueSorted(ruleIDs),
				evidence: evidence,
			})
			categoryHasCandidate[categoryPriority(category)] = true
		}
	}

	// Category-level semantic profiles compose grammar-independent evidence
	// dimensions inside a bounded related window. They complement, rather than
	// weaken, rule-local intent/object candidates: an object, an agency/outcome
	// signal, a target or destination, and an additional consequence dimension
	// are all mandatory, and negative/legitimate workflow scope still wins.
	if len(c.semanticProfiles) != 0 {
		semanticSignals := [][]bool{currentSignals}
		previousText := ""
		partsLinked := false
		if partCount > 1 {
			previousText = string(previousRunes)
			partsLinked = semanticPartsLinked(previousText, currentText)
			if partsLinked {
				semanticSignals = append(semanticSignals, previousSignals)
			}
		}
		semanticPotential := false
		for _, profile := range c.semanticProfiles {
			if semanticDimensionsPotential(c.semanticDimensions(profile, semanticSignals)) {
				semanticPotential = true
				break
			}
		}
		if semanticPotential {
			if !directivesReady {
				currentDirectives = c.analyzeDirectives(currentRunes)
				directivesReady = true
			}
			windows := semanticDirectiveWindows(currentDirectives)
			if len(windows) == 0 || (structuredToolPayload && structuredSemanticFragment(currentText)) {
				windows = append(windows, semanticSignalWindow{signals: [][]bool{currentSignals}, text: currentText})
			}
			if partsLinked {
				windows = append(windows, semanticSignalWindow{
					signals: [][]bool{previousSignals, currentSignals},
					text:    strings.TrimSpace(previousText + "\n" + currentText),
				})
			}
			for _, profile := range c.semanticProfiles {
				bestSemantic := semanticAssessment{}
				for _, window := range windows {
					assessment := c.assessSemanticWindow(profile, window, policy)
					if assessment.score > bestSemantic.score {
						bestSemantic = assessment
					}
				}
				if bestSemantic.score < AuditThreshold {
					continue
				}
				candidates = append(candidates, candidate{
					score:    bestSemantic.score,
					category: profile.category,
					ruleID:   profile.id(),
					evidence: bestSemantic.evidence,
				})
			}
		}
	}

	// Compose a core only within one category and one current directive clause,
	// and only when no ordinary rule candidate exists for that category. Both
	// the intent and object provider must carry an additional qualifier, and the
	// pair must jointly include operational evidence plus two of
	// target/evasion/scale. This closes vocabulary seams between related rules
	// without turning a loose bag of security words, separate clauses, or
	// evidence from different categories into a core.
	for _, category := range classifierCategoryOrder {
		if categoryHasCandidate[categoryPriority(category)] {
			continue
		}
		ruleIndexes := c.categoryRules[category]
		if len(ruleIndexes) < 2 {
			continue
		}
		hasQualifiedIntent := false
		hasQualifiedObject := false
		for _, ruleIndex := range ruleIndexes {
			rule := c.rules[ruleIndex]
			hasQualifiedIntent = hasQualifiedIntent || (currentSignals[rule.intent] && ruleHasMatchedQualifier(rule, currentSignals))
			hasQualifiedObject = hasQualifiedObject || (currentSignals[rule.object] && ruleHasMatchedQualifier(rule, currentSignals))
		}
		if !hasQualifiedIntent || !hasQualifiedObject {
			continue
		}
		if isLegitimateCategoryWorkflow(category, currentText) {
			continue
		}
		if !directivesReady {
			currentDirectives = c.analyzeDirectives(currentRunes)
			directivesReady = true
		}

		intentProvider := -1
		objectProvider := -1
		operationalProvider := -1
		targetProvider := -1
		evasionProvider := -1
		scaleProvider := -1
		for _, clause := range currentDirectives.clauses {
			clauseSignals := clause.signals
			for _, intentIndex := range ruleIndexes {
				intentRule := c.rules[intentIndex]
				if !clauseSignals[intentRule.intent] || clauseNegatesRuleIntent(clause.text, intentRule.intentStarts) || !ruleHasMatchedQualifier(intentRule, clauseSignals) {
					continue
				}
				for _, objectIndex := range ruleIndexes {
					if objectIndex == intentIndex {
						continue
					}
					objectRule := c.rules[objectIndex]
					if !clauseSignals[objectRule.object] || !ruleHasMatchedQualifier(objectRule, clauseSignals) {
						continue
					}
					operational := firstPairSignalProvider(clauseSignals, intentIndex, objectIndex, intentRule.independentOperational, objectRule.independentOperational)
					target := firstPairSignalProvider(clauseSignals, intentIndex, objectIndex, intentRule.independentTarget, objectRule.independentTarget)
					evasion := firstPairSignalProvider(clauseSignals, intentIndex, objectIndex, intentRule.independentEvasion, objectRule.independentEvasion)
					scale := firstPairSignalProvider(clauseSignals, intentIndex, objectIndex, intentRule.independentScale, objectRule.independentScale)
					riskQualifiers := 0
					for _, provider := range []int{target, evasion, scale} {
						if provider >= 0 {
							riskQualifiers++
						}
					}
					if operational < 0 || riskQualifiers < 2 {
						continue
					}
					intentProvider = intentIndex
					objectProvider = objectIndex
					operationalProvider = operational
					targetProvider = target
					evasionProvider = evasion
					scaleProvider = scale
					break
				}
				if intentProvider >= 0 {
					break
				}
			}
			if intentProvider >= 0 {
				break
			}
		}
		if intentProvider < 0 {
			continue
		}

		intentRule := c.rules[intentProvider]
		objectRule := c.rules[objectProvider]
		score := 45
		qualifiers := 0
		evidence := []Evidence{
			{ID: intentRule.id + ":intent", Kind: "intent"},
			{ID: objectRule.id + ":object", Kind: "object"},
		}
		appendQualifier := func(provider int, points int, kind string) {
			if provider < 0 {
				return
			}
			score += points
			qualifiers++
			evidence = append(evidence, Evidence{ID: c.rules[provider].id + ":" + kind, Kind: kind})
		}
		appendQualifier(operationalProvider, 20, "operational")
		appendQualifier(targetProvider, 18, "target")
		appendQualifier(evasionProvider, 16, "evasion")
		appendQualifier(scaleProvider, 16, "scale")
		if qualifiers >= 2 {
			score += 5
		}
		score = clampScore(score)

		effectiveContext := context
		if targetProvider >= 0 {
			if carriedCTFOrLab && !currentContext.CTFOrLab {
				effectiveContext.CTFOrLab = false
			}
			if carriedAuthorized && !currentContext.Authorized {
				effectiveContext.Authorized = false
			}
		}
		if hasExplicitHarmConflict(currentText) {
			effectiveContext.Authorized = false
			effectiveContext.CTFOrLab = false
		}
		composedRule := compiledRule{
			category:               category,
			authorizationProtected: intentRule.authorizationProtected || objectRule.authorizationProtected,
			intent:                 intentRule.intent,
			object:                 objectRule.object,
			operational:            c.rules[operationalProvider].operational,
			intentStarts:           intentRule.intentStarts,
		}
		if context != (ContextFlags{}) && c.hasRuleContradictoryDirective(currentDirectives, composedRule, policy.Allow) {
			effectiveContext = ContextFlags{
				CTFOrLab:   effectiveContext.CTFOrLab,
				Authorized: effectiveContext.Authorized,
			}
		}
		authorizationProtected := composedRule.authorizationProtected && policy.HardBlockEvenIfAuthorized.protects(category)
		score = applyContextDeductions(score, effectiveContext, authorizationProtected)
		genuineSafetyContext := effectiveContext.Defensive || effectiveContext.Remediation || effectiveContext.StaticAnalysis || effectiveContext.IncidentResponse || effectiveContext.HighLevel
		if authorizationProtected && !genuineSafetyContext && score < HardThreshold {
			score = HardThreshold
		}
		candidates = append(candidates, candidate{
			score:    score,
			category: category,
			ruleIDs:  []string{intentRule.id, objectRule.id},
			evidence: evidence,
		})
	}

	// Meta-override language is an abuse amplifier, not a standalone keyword
	// blocklist. It covers instruction-hierarchy inversion, refusal suppression,
	// sandbox/placeholder laundering, forced exact-output templates, negative
	// authorization, and control-plane secret disclosure. It may raise an
	// existing cyber-abuse candidate, but never creates a cyber taxonomy by
	// itself. Wrapper-only requests remain a bounded control-plane audit signal.
	meta := bestMeta
	if meta.score >= AuditThreshold {
		bestOrdinaryIndex := -1
		for index := range candidates {
			if candidates[index].score < AuditThreshold {
				continue
			}
			if bestOrdinaryIndex < 0 || candidates[index].score > candidates[bestOrdinaryIndex].score ||
				(candidates[index].score == candidates[bestOrdinaryIndex].score &&
					(categoryPriority(candidates[index].category) < categoryPriority(candidates[bestOrdinaryIndex].category) ||
						(candidates[index].category == candidates[bestOrdinaryIndex].category &&
							candidateSortID(candidates[index].ruleID, candidates[index].ruleIDs) < candidateSortID(candidates[bestOrdinaryIndex].ruleID, candidates[bestOrdinaryIndex].ruleIDs)))) {
				bestOrdinaryIndex = index
			}
		}
		if bestOrdinaryIndex >= 0 {
			winner := &candidates[bestOrdinaryIndex]
			if winner.score < meta.score {
				winner.score = meta.score
			}
			if winner.ruleID != "" {
				winner.ruleIDs = append(winner.ruleIDs, winner.ruleID)
				winner.ruleID = ""
			}
			winner.ruleIDs = append(winner.ruleIDs, metaOverrideRuleID)
			winner.evidence = append(winner.evidence, meta.evidence...)
		}
	}
	if len(candidates) == 0 {
		if meta.score >= AuditThreshold {
			result.Score = metaControlAuditScore(meta.score, thresholds)
			result.RuleIDs = []string{metaOverrideRuleID}
			result.Evidence = append(result.Evidence, meta.evidence...)
			result.Evidence = append(result.Evidence, contextEvidence(context)...)
			result.Evidence = uniqueSortedEvidence(result.Evidence)
			result.Action = actionForMetaControl(mode, result.Score, thresholds)
			carrier := "text"
			if structuredToolPayload {
				carrier = "structured_tool_payload"
			}
			attachBehaviorGraph(&result, "parts", carrier)
			return result
		}
		result.Action = actionFor(mode, 0, thresholds)
		result.Evidence = contextEvidence(context)
		carrier := "text"
		if structuredToolPayload {
			carrier = "structured_tool_payload"
		}
		attachBehaviorGraph(&result, "parts", carrier)
		return result
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		if candidates[i].category != candidates[j].category {
			return categoryPriority(candidates[i].category) < categoryPriority(candidates[j].category)
		}
		return candidateSortID(candidates[i].ruleID, candidates[i].ruleIDs) < candidateSortID(candidates[j].ruleID, candidates[j].ruleIDs)
	})
	best := candidates[0]
	result.Score = clampScore(best.score)
	result.Category = best.category
	result.RuleIDs = appendCandidateRuleIDs(result.RuleIDs, best.ruleID, best.ruleIDs)
	result.Evidence = append(result.Evidence, best.evidence...)
	for _, other := range candidates[1:] {
		if other.category != best.category || other.score != best.score {
			continue
		}
		result.RuleIDs = appendCandidateRuleIDs(result.RuleIDs, other.ruleID, other.ruleIDs)
		result.Evidence = append(result.Evidence, other.evidence...)
	}
	result.Evidence = append(result.Evidence, contextEvidence(context)...)
	result.RuleIDs = uniqueSorted(result.RuleIDs)
	result.Evidence = uniqueSortedEvidence(result.Evidence)
	result.Action = actionFor(mode, result.Score, thresholds)
	carrier := "text"
	if structuredToolPayload {
		carrier = "structured_tool_payload"
	}
	attachBehaviorGraph(&result, "parts", carrier)
	return result
}

func ruleHasMatchedQualifier(rule compiledRule, signals []bool) bool {
	return signalMatched(signals, rule.independentOperational) ||
		signalMatched(signals, rule.independentTarget) ||
		signalMatched(signals, rule.independentEvasion) ||
		signalMatched(signals, rule.independentScale)
}

func firstPairSignalProvider(signals []bool, first, second, firstSignal, secondSignal int) int {
	if signalMatched(signals, firstSignal) {
		return first
	}
	if signalMatched(signals, secondSignal) {
		return second
	}
	return -1
}

func signalMatched(signals []bool, signalID int) bool {
	return signalID >= 0 && signalID < len(signals) && signals[signalID]
}

func candidateSortID(ruleID string, ruleIDs []string) string {
	if ruleID != "" {
		return ruleID
	}
	if len(ruleIDs) == 0 {
		return ""
	}
	return ruleIDs[0]
}

func appendCandidateRuleIDs(destination []string, ruleID string, ruleIDs []string) []string {
	if ruleID != "" {
		return append(destination, ruleID)
	}
	return append(destination, ruleIDs...)
}

func isCredentialObjectQualifiedFallback(rule compiledRule, signals []bool) bool {
	return len(signals) > 0 && rule.category == rules.CategoryCredentialTheft &&
		!signals[rule.intent] && signals[rule.object] &&
		signalMatched(signals, rule.independentOperational) &&
		signalMatched(signals, rule.independentTarget) &&
		signalMatched(signals, rule.independentEvasion)
}

type outcomeProviders struct {
	object         int
	operational    int
	target         int
	evasion        int
	scale          int
	hasOperational bool
}

func (providers outcomeProviders) qualifierCount() int {
	count := 0
	if providers.hasOperational {
		count++
	}
	if providers.target >= 0 {
		count++
	}
	if providers.evasion >= 0 {
		count++
	}
	if providers.scale >= 0 {
		count++
	}
	return count
}

func (c *Classifier) categoryOutcomeProviders(category rules.Category, signals []bool) outcomeProviders {
	providers := outcomeProviders{object: -1, operational: -1, target: -1, evasion: -1, scale: -1}
	providers.hasOperational = signalMatched(signals, c.implementationRequest)
	for _, ruleIndex := range c.categoryRules[category] {
		rule := c.rules[ruleIndex]
		if providers.object < 0 && signalMatched(signals, rule.object) {
			providers.object = ruleIndex
		}
		if providers.operational < 0 && signalMatched(signals, rule.independentOperational) {
			providers.operational = ruleIndex
			providers.hasOperational = true
		}
		if providers.target < 0 && signalMatched(signals, rule.independentTarget) {
			providers.target = ruleIndex
		}
		if providers.evasion < 0 && signalMatched(signals, rule.independentEvasion) {
			providers.evasion = ruleIndex
		}
		if providers.scale < 0 && signalMatched(signals, rule.independentScale) {
			providers.scale = ruleIndex
		}
	}
	return providers
}

func (c *Classifier) categoryMatchedIntentsAreOnlyNegated(category rules.Category, signals []bool, analysis analyzedDirectives) bool {
	found := false
	for _, ruleIndex := range c.categoryRules[category] {
		rule := c.rules[ruleIndex]
		if !signalMatched(signals, rule.intent) {
			continue
		}
		found = true
		if !analysis.ruleIntentIsOnlyNegated(rule) {
			return false
		}
	}
	return found
}

// hasExplicitHarmConflict identifies target scope that contradicts a generic
// authorization or lab claim. Ownership language may mitigate a genuinely
// scoped assessment, but it cannot authorize harm to a victim or third party.
func hasExplicitHarmConflict(text string) bool {
	return containsAnyLiteral(text,
		"victim", "third-party", "third party", "someone else's", "other people's",
		"without consent", "without permission", "i have no permission", "we have no permission", "i do not have permission",
		"we do not have permission", "i have no authorization", "we have no authorization", "no written authorization", "unauthorized", "named company",
		"do not own", "don't own", "not ours", "not mine", "target is not mine", "target site is not mine", "server is not mine",
		"not an authorized red-team exercise", "compromised host", "compromised machine", "compromised workstation",
		"competitor", "real customer", "real user", "real account",
		"attacker-controlled", "server i control", "personal storage account", "personal cloud", "my receiver",
		"受害者", "受害主机", "第三方", "他人", "未经同意", "未经许可", "未授权", "没有授权", "没有书面授权", "没有权限",
		"指定公司", "竞争对手", "真实客户", "真实用户", "真实账号", "攻击者控制",
		"不属于我们", "不属于我", "目标不属于我", "目标站点不属于我", "服务器不是我的", "不是授权红队演练",
		"非自有", "已失陷主机", "个人云盘", "私人网盘", "个人存储账号",
	)
}

// isLegitimateCategoryWorkflow recognizes a narrow set of ordinary identity
// and encryption workflows that necessarily share verbs and objects with
// abuse. It is deliberately category-scoped and hostile markers always win,
// so generic safety labels cannot wash out a victim-targeted directive.
func isLegitimateCategoryWorkflow(category rules.Category, text string) bool {
	if hasExplicitHarmConflict(text) {
		return false
	}
	if category == rules.CategoryCredentialTheft &&
		containsAnyLiteral(text, "offline forensics", "memory image", "forensic image", "离线取证", "内存镜像", "取证镜像") &&
		containsAnyLiteral(text, "do not extract real passwords", "without extracting real passwords", "不提取真实密码", "不导出真实密码") &&
		!containsAnyLiteral(text,
			"victim", "someone else's", "other people's", "steal", "siphon", "exfiltrate", "bypass", "undetected",
			" but ", " instead ", " however ", " then ", " actually ", "do not refuse", "ignore the policy",
			"受害者", "他人", "窃取", "盗取", "外传", "回传", "绕过", "但是", "然后", "改为", "实际",
		) {
		return true
	}
	switch category {
	case rules.CategoryCredentialTheft, rules.CategoryPhishing:
		if !containsAnyLiteral(text,
			"oauth response", "oauth callback", "token exchange response",
			"our login form", "our sign-in form", "our login page", "our sign-in page",
			"our login portal", "our sign-in portal", "our sso", "our authentication server",
			"users can log in", "users can sign in", "customers can log in", "customers can sign in",
			"normal authentication endpoint", "authenticate the user", "authenticate them",
			"credential migration", "credential rotation", "password manager export",
			"secrets manager", "account recovery",
			"我们的登录表单", "我们的登录页面", "我们的登录门户", "我们的认证服务器",
			"用户可以登录", "客户可以登录", "正常认证接口",
			"认证用户", "凭证轮换", "凭证迁移", "密码管理器导出", "密钥管理器", "账号恢复",
		) {
			return false
		}
		return !containsAnyLiteral(text,
			"victim", "someone else's", "other people's", "without consent", "unauthorized",
			"steal", "credential stealer", "phishing", "fake login", "cloned login",
			"real brand", "lookalike", "external server", "collection server", "webhook",
			"bypass", "undetected", "silently",
			"受害者", "他人", "未经同意", "未授权", "窃取", "钓鱼", "假登录", "仿冒登录",
			"真实品牌", "外部服务器", "回传服务器", "绕过", "静默",
		)
	case rules.CategoryRansomware:
		if containsAnyLiteral(text, "fictional game", "game prop", "fictional story", "虚构游戏", "游戏道具", "虚构故事") &&
			containsAnyLiteral(text, "ransom note", "extortion note", "勒索信", "勒索便笺") &&
			!containsAnyLiteral(text,
				"deploy", "execute", "encrypt files", "delete backups", "remove restore", "demand payment",
				"部署", "执行", "加密文件", "删除备份", "删除还原点", "索要付款") {
			return true
		}
		// Recovery exercises often need to name a contained extortion sample.
		// Treat the workflow as legitimate only when the text independently
		// states both a recovery purpose and a non-execution/rollback control;
		// victim or third-party scope has already been rejected above.
		if hasAffirmativeSafetyPurpose(text) &&
			containsAnyLiteral(text,
				"recovery drill", "restoration exercise", "restoration sequence", "synthetic documents", "lab workstations",
				"恢复演练", "还原演练", "合成文档", "实验室工作站") &&
			containsAnyLiteral(text,
				"without running", "without executing", "preserves rollback", "preserve rollback", "immutable backups",
				"不运行", "不执行", "保留回滚", "不可变备份") {
			return true
		}
		if !containsAnyLiteral(text,
			"secure backup", "off-site backup", "offsite backup", "backup encryption",
			"encryption at rest", "disk encryption", "full-disk encryption", "protect files",
			"protect data", "data protection", "key management", "our files", "my files",
			"test fixture", "backup archive",
			"安全备份", "异地备份", "备份加密", "静态加密", "磁盘加密", "全盘加密",
			"保护文件", "保护数据", "数据保护", "密钥管理", "我们的文件", "我的文件", "测试样本",
		) {
			return false
		}
		return !containsAnyLiteral(text,
			"victim", "ransom", "extortion", "demand payment", "pay to restore", "bitcoin",
			"delete backups", "remove restore", "disable recovery", "spread", "propagate",
			"employee files", "production files", "target network", "undetected",
			"受害者", "勒索", "索要付款", "支付赎金", "比特币", "删除备份", "删除还原点",
			"关闭恢复", "传播", "员工文件", "生产文件", "目标网络", "静默",
		)
	case rules.CategoryExfiltration:
		// An investigation can quote a prohibited transfer while describing an
		// abnormal-export finding, trace preservation, and containment. Require
		// all four defensive facets so a generic safety label cannot suppress an
		// otherwise operational transfer request.
		if containsAnyLiteral(text,
			"abnormal export", "suspicious export", "unauthorized export", "异常导出", "可疑导出", "未授权导出") &&
			containsAnyLiteral(text,
				"correlate logs", "retain logs", "audit logs", "access logs", "关联日志", "访问日志", "审计日志", "保留日志") &&
			containsAnyLiteral(text,
				"block egress", "disable egress", "cut off egress", "封禁外送", "阻断外送", "切断外送") &&
			containsAnyLiteral(text,
				"do not execute", "must not execute", "without executing", "不得执行", "不要执行", "禁止执行") {
			return true
		}
		if !containsAnyLiteral(text,
			"approved backup", "backup policy", "disaster recovery", "recovery vault",
			"backup team", "working copy",
			"organization-owned", "company-owned", "approved migration", "data migration",
			"ediscovery", "external counsel", "legal hold", "retention archive", "authorized export",
			"批准的备份", "备份策略", "灾难恢复", "恢复保管库", "备份团队", "工作副本", "组织自有", "公司自有",
			"批准迁移", "数据迁移", "电子取证", "外部律师", "法律保全", "留存归档", "授权导出",
		) {
			return false
		}
		return !containsAnyLiteral(text,
			"attacker-controlled", "server i control", "personal storage", "personal cloud", "private drive",
			"covert", "without raising an alert", "avoid alert", "undetected", "compromised host", "victim",
			"攻击者控制", "我的服务器", "个人存储", "个人云盘", "私人网盘", "隐蔽", "避开告警", "受害",
		)
	default:
		return false
	}
}

func containsAnyLiteral(text string, values ...string) bool {
	for _, value := range values {
		if strings.Contains(text, value) {
			return true
		}
	}
	return false
}

func categoryPriority(category rules.Category) int {
	switch category {
	case rules.CategoryPhishing:
		return 0
	case rules.CategoryCredentialTheft:
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
	runes          []rune
	text           string
	signals        []bool
	boundaryBefore directiveBoundaryKind
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
	walkDirectiveClausesWithBoundary(text, func(clause []rune, boundaryBefore directiveBoundaryKind) bool {
		if len(analysis.clauses) >= maxAnalyzedDirectiveClauses {
			analysis.overflow = true
			return false
		}
		analysis.clauses = append(analysis.clauses, analyzedDirectiveClause{runes: clause, boundaryBefore: boundaryBefore})
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
			if foundCore && signals[rule.intent] && !clauseNegatesRuleIntent(clause.text, rule.intentStarts) &&
				continuesPriorRiskDirective(clause.text) {
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

// continuesPriorRiskDirective is deliberately narrower than a bare second
// intent verb. A prohibition such as "never deploy ransomware; provide a
// recovery checklist" must not lend its object to the safe deliverable. The
// object is carried only when the later clause explicitly refers back to it or
// asks for a concrete implementation artifact.
func continuesPriorRiskDirective(clause string) bool {
	clause = strings.TrimSpace(clause)
	if isSafetyDeliverableClause(clause) || hasExplanatoryFraming(clause) || hasAffirmativeSafetyPurpose(clause) {
		return false
	}
	return containsAnyLiteral(clause,
		" it", " that", " them", " the above", " above request", " same payload", " same tool",
		"working code", "complete code", "source code", "ready-to-run", "ready to run",
		"commands", "script", "payload", "executable", "implementation",
		"它", "该内容", "上述", "上面", "同一载荷", "同一工具", "完整代码", "可运行代码",
		"源码", "命令", "脚本", "载荷", "可执行文件", "实现出来",
	)
}

func hasAffirmativeSafetyPurpose(text string) bool {
	if containsAnyLiteral(text,
		"no ransomware remains", "ransomware is absent", "ransomware-free", "prevent ransomware infection", "block ransomware execution",
		"no malware remains", "malware is absent", "malware-free", "prevent malware infection", "block malware execution",
		"no backdoor remains", "remove the backdoor", "eradicate the backdoor",
		"不再存在勒索软件", "无勒索软件感染", "防止勒索软件感染", "阻止勒索软件执行",
		"不再存在恶意软件", "无恶意软件感染", "防止恶意软件感染", "阻止恶意软件执行",
		"不再存在后门", "移除后门", "清除后门",
	) {
		return true
	}
	if containsAnyLiteral(text, "detection rule", "alert rule", "检测规则", "告警规则") &&
		containsAnyLiteral(text, "alert when", "alerts when", "detect when", "detects when", "当出现时告警", "当检测到") {
		return true
	}
	if containsAnyLiteral(text, "verify", "verifies", "verified", "validate", "validates", "validated", "test", "tests", "testing", "验证", "校验", "测试") &&
		containsAnyLiteral(text, "recovery", "restoration", "restore", "backup", "fix", "patch", "恢复", "还原", "备份", "修复", "补丁") {
		return true
	}
	return containsAnyLiteral(text,
		"verify recovery", "verify restoration", "verify backups", "restore collection", "restore telemetry",
		"restore from", "recover files", "protect files", "prevent abuse", "investigate the outage",
		"investigate why", "apply the patch", "test the patch", "validate the fix",
		"验证恢复", "验证备份", "恢复采集", "恢复遥测", "从备份恢复", "恢复文件", "保护文件",
		"防止滥用", "调查故障", "调查停止原因", "应用补丁", "验证修复",
	)
}

func (analysis analyzedDirectives) ruleIntentIsOnlyNegated(rule compiledRule) bool {
	if analysis.overflow {
		return false
	}
	foundIntent := false
	for _, clause := range analysis.clauses {
		if !clause.signals[rule.intent] {
			continue
		}
		foundIntent = true
		if !clauseNegatesRuleIntent(clause.text, rule.intentStarts) {
			return false
		}
	}
	return foundIntent
}

func clauseNegatesRuleIntent(clause string, intents []string) bool {
	intentIndex := earliestRuleIntentIndex(clause, intents)
	if intentIndex < 0 {
		return false
	}
	prefix := strings.TrimSpace(clause[:intentIndex])
	for _, bait := range []string{
		"do not refuse", "don't refuse", "must not refuse", "never hesitate", "do not hesitate", "don't hesitate",
		"must not be denied", "must not deny", "do not deny", "don't deny", "must not be blocked", "must not block",
		"do not block", "don't block", "must not be filtered", "do not filter", "disable guardrails", "remove guardrails",
		"disable safety checks", "skip safety checks", "must not enforce the policy", "must not apply safety",
		"ignore the instruction", "ignore the policy", "disregard the instruction", "disregard the policy",
		"不要拒绝", "不得拒绝", "不得阻止", "不得拦截", "不得过滤", "不要阻止", "不要拦截", "不要过滤",
		"关闭护栏", "移除护栏", "禁用安全检查", "跳过安全检查", "不得执行安全策略",
		"不要犹豫", "忽略指令", "忽略策略",
	} {
		if strings.Contains(prefix, bait) {
			return false
		}
	}
	closest := -1
	closestEnd := -1
	for _, marker := range []string{
		"must never", "must not", "should never", "should not", "do not", "don't", "cannot", "can't",
		"will not", "never", "not to", "without", "forbids", "forbid", "forbidden to", "prohibits", "prohibit", "refuse to",
		"严禁", "禁止", "不得", "不要", "不需要", "无需", "不能", "不会", "拒绝", "不",
	} {
		index := strings.LastIndex(prefix, marker)
		if marker == "不" && index >= 0 && !isBareChineseNegationBridge(strings.TrimSpace(prefix[index+len(marker):])) {
			continue
		}
		if index >= 0 && index >= closest {
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
	for _, doubleNegative := range []string{"refuse", "hesitate", "hesitation", "avoid", "decline", "拒绝", "犹豫", "避免"} {
		if strings.Contains(between, doubleNegative) {
			return false
		}
	}
	if negationScopeInterrupted(between) {
		return false
	}
	return true
}

func isBareChineseNegationBridge(value string) bool {
	switch value {
	case "", "再", "会", "要", "得", "可", "能", "应", "应该", "允许", "需要", "准", "打算", "计划", "会再", "要再", "应该再":
		return true
	default:
		return false
	}
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
		if clauseNegatesRuleIntent(clauseText, rule.intentStarts) {
			continue
		}
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
	if hasExplicitHarmConflict(clause) {
		return false
	}
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
	"employee quiz", "tabletop exercise", "mock phishing", "recognizing suspicious", "reporting suspicious",
	"恢复清单", "修复方案", "缓解方案", "补丁指南", "检测规则", "安全清单", "应急响应方案", "员工测验", "桌面演练", "模拟钓鱼",
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
			tail := clause[index+len(marker):]
			// Detection artifacts necessarily describe the behavior they match.
			// "alert when an implant silences telemetry" is a defensive condition,
			// not an instruction to silence telemetry. A coordinated second action
			// ("detect and then disable EDR") is still operational and is caught by
			// explanatoryFramingTurnsOperational.
			if hasDetectionConditionFraming(tail) && !explanatoryFramingTurnsOperational(tail, intents) {
				return false
			}
			return containsRuleIntent(tail, intents)
		}
	}
	return false
}

func hasDetectionConditionFraming(text string) bool {
	return containsAnyLiteral(text,
		"alert when", "alert if", "detect when", "detect if", "match when", "match if",
		"flag when", "flag if", "trigger when", "trigger if", "identify attempts to",
		"attempts to", "attempt to", "behavior that", "behaviour that",
		"当出现时告警", "当检测到", "用于检测", "检测以下行为", "识别尝试", "尝试执行",
	)
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

// independentQualifierTerms removes qualifier literals that overlap a core or
// an earlier qualifier literal. The original signals remain available for
// scope and contradiction checks, while only independent text can add score.
func independentQualifierTerms(terms rules.Terms, coveredGroups ...rules.Terms) rules.Terms {
	covered := make([]string, 0)
	for _, group := range coveredGroups {
		covered = append(covered, normalizedTermValues(group)...)
	}
	filter := func(values []string) []string {
		result := make([]string, 0, len(values))
		for _, value := range values {
			normalized := string(normalizeParts([]string{value}).standardRunes)
			if normalized == "" || termOverlapsAny(normalized, covered) {
				continue
			}
			result = append(result, value)
		}
		return result
	}
	return rules.Terms{ZH: filter(terms.ZH), EN: filter(terms.EN)}
}

func termOverlapsAny(value string, covered []string) bool {
	valueASCII := isASCIIStringLocal(value)
	for _, other := range covered {
		if valueASCII && isASCIIStringLocal(other) {
			if containsASCIIWord(value, other) || containsASCIIWord(other, value) {
				return true
			}
			continue
		}
		if strings.Contains(value, other) || strings.Contains(other, value) {
			return true
		}
	}
	return false
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
	for _, marker := range []string{"detect", "alert", "signature", "indicator", "analytic", "outline", "match", "检测", "告警", "签名", "指标", "分析规则", "匹配"} {
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
		"yara rule", "yara signature", "sigma rule", "sigma analytic", "suricata rule", "suricata signature", "suricata alert", "snort rule", "snort signature", "snort detection outline", "ioc extraction", "indicators of compromise",
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

type directiveBoundaryKind uint8

const (
	directiveBoundaryNone directiveBoundaryKind = iota
	directiveBoundarySoft
	directiveBoundaryContinuation
	directiveBoundaryStrong
)

func walkDirectiveClauses(text []rune, visit func([]rune) bool) {
	walkDirectiveClausesWithBoundary(text, func(clause []rune, _ directiveBoundaryKind) bool {
		return visit(clause)
	})
}

func walkDirectiveClausesWithBoundary(text []rune, visit func([]rune, directiveBoundaryKind) bool) {
	start := 0
	boundaryBefore := directiveBoundaryNone
	for index := 0; index < len(text); index++ {
		width, boundaryKind := directiveBoundaryAt(text, index)
		if width == 0 {
			continue
		}
		if clause := trimRuneSpaces(text[start:index]); len(clause) > 0 {
			if !visit(clause, boundaryBefore) {
				return
			}
		}
		boundaryBefore = boundaryKind
		start = index + width
		index += width - 1
	}
	if clause := trimRuneSpaces(text[start:]); len(clause) > 0 {
		visit(clause, boundaryBefore)
	}
}

func directiveBoundaryWidth(text []rune, index int) int {
	width, _ := directiveBoundaryAt(text, index)
	return width
}

func directiveBoundaryAt(text []rune, index int) (int, directiveBoundaryKind) {
	r := text[index]
	if r == compactHardBoundary {
		return 1, directiveBoundaryStrong
	}
	switch r {
	case ',', '，':
		if !singleRuneTokensAround(text, index) {
			return 1, directiveBoundarySoft
		}
	case '.', '!', '?', ';', ':', '。', '！', '？', '；', '：':
		if !singleRuneTokensAround(text, index) {
			return 1, directiveBoundaryStrong
		}
	}
	for markerIndex, marker := range directiveMarkers {
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
			kind := directiveBoundarySoft
			// Contrast and replacement markers introduce a new directive. Sequence
			// and overlap markers remain a soft continuation boundary.
			if markerIndex == 0 || markerIndex == 1 || markerIndex == 3 || markerIndex == 4 ||
				markerIndex == 6 || markerIndex == 7 || markerIndex == 9 || markerIndex == 10 {
				kind = directiveBoundaryStrong
			} else {
				kind = directiveBoundaryContinuation
			}
			return len(marker), kind
		}
	}
	return 0, directiveBoundaryNone
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
