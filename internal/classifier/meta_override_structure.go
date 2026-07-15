package classifier

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxMetaOverrideQuotedSpans = 16

type metaOverrideQuotedSpan struct {
	start int
	end   int
}

var metaOverrideAnalysisTopics = []string{
	"prompt injection", "jailbreak attempt", "jailbreak sample", "instruction override", "instruction-hierarchy attack",
	"system prompt leakage", "quoted prompt", "red-team transcript", "untrusted instruction", "hostile instruction",
	"提示注入", "越狱尝试", "越狱样本", "指令覆盖", "指令层级攻击", "系统提示泄露", "引用提示词", "红队转录",
	"不可信指令", "敌意指令",
}

var metaOverrideAnalysisPurposes = []string{
	"analyze", "analyse", "review", "detect", "prevent", "mitigate", "summarize", "classify", "flag", "write a detector",
	"recommend controls", "explain why", "analysis only", "static analysis", "security review",
	"分析", "审查", "检测", "防止", "缓解", "总结", "分类", "标记", "编写检测器", "建议防护", "解释为什么", "仅用于分析", "静态分析",
}

var metaOverrideDirectiveActions = []string{
	"apply", "follow", "obey", "execute", "comply", "use", "install", "activate", "enable", "deploy", "persist",
	"load", "append", "replace", "override", "configure", "implement", "adopt", "run", "carry out", "operationalize",
	"应用", "遵循", "服从", "执行", "照做", "采用", "使用", "安装", "激活", "启用", "部署", "持久化", "加载",
	"追加", "替换", "覆盖", "配置", "落地", "实施", "运行", "生效",
}

var metaOverrideDirectiveObjects = []string{
	"the sample", "this sample", "quoted sample", "the example", "this example", "the prompt", "this prompt",
	"the instruction", "these instruction", "following instruction", "the configuration", "this configuration", "following configuration",
	"the template", "this template", "the override", "this override", "the mode", "model_instructions_file", "agents.md",
	" it", "it ", " them", "them ", "the above", "the following",
	"样本", "示例", "提示词", "提示", "指令", "配置", "模板", "覆盖", "模式", "上述", "以下", "这些", "它",
}

var metaOverrideContinuationCues = []string{
	"then", "now", "next", "afterwards", "afterward", "subsequently", "finally", "later", "once complete", "once done",
	"go ahead", "still", "anyway", "from there", "following that",
	"然后", "现在", "接下来", "随后", "之后", "接着", "最后", "完成后", "仍然", "照样", "再",
}

var metaOverrideNegations = []string{
	"do not", "don't", "must not", "must never", "never", "prohibit", "prohibits", "prohibiting", "forbid", "forbids", "forbidding", "keep disabled",
	"不要", "不得", "禁止", "严禁", "切勿", "不应", "不可", "保持禁用",
}

var metaOverrideReversalCues = []string{
	" but ", " instead", " rather", " however", " except", "—", "–",
	"但是", "但要", "而是", "改为", "反而", "不过", "却", "而执行", "而遵循",
}

func metaOverrideDefensiveStructure(text string) bool {
	text = strings.ToLower(strings.TrimSpace(text))
	if text == "" {
		return false
	}
	spans, complete := metaOverrideQuotedSpans(text)
	if !complete {
		return false
	}
	if len(spans) == 0 {
		if span, ok := metaOverrideImplicitSampleSpan(text); ok {
			spans = append(spans, span)
		}
	}
	// Defensive deduction is intentionally single-sample. Additional unbound
	// quoted spans are ambiguous: text inside them cannot supply the inert
	// directive, and a trailing quoted imperative must not be masked. Fail closed
	// instead of guessing which quote the user intended as the analysis object.
	if len(spans) > 1 {
		return false
	}
	primary, hasPrimary := metaOverridePrimarySignalSpan(text, spans)
	maskedSpans := []metaOverrideQuotedSpan(nil)
	if hasPrimary {
		maskedSpans = []metaOverrideQuotedSpan{primary}
	}
	if metaOverrideConfigurationSafetyStructure(text, maskedSpans) {
		return true
	}
	if !hasPrimary {
		return false
	}

	// Only the single signal-bearing sample span is inert.
	outside := metaOverrideMaskQuotedSpans(text, maskedSpans)
	if !containsAnyLiteral(outside, metaOverrideAnalysisTopics...) ||
		!containsAnyLiteral(outside, metaOverrideAnalysisPurposes...) ||
		metaOverrideHasDoubleNegatedInertDirective(outside) ||
		!metaOverrideHasInertDirective(outside) ||
		metaOverrideHasActiveDirective(outside) {
		return false
	}
	last := metaOverrideLastDirectiveClause(outside)
	return last != "" && metaOverrideClauseIsInert(last)
}

func metaOverrideImplicitSampleSpan(text string) (metaOverrideQuotedSpan, bool) {
	for _, marker := range []string{
		"quoted prompt injection sample:", "prompt injection sample:", "quoted jailbreak sample:", "jailbreak sample:",
		"引用的提示注入样本:", "提示注入样本:", "引用的越狱样本:", "越狱样本:",
		"引用的提示注入样本：", "提示注入样本：", "引用的越狱样本：", "越狱样本：",
	} {
		markerIndex := strings.Index(text, marker)
		if markerIndex < 0 {
			continue
		}
		start := markerIndex + len(marker)
		for start < len(text) {
			r, size := utf8.DecodeRuneInString(text[start:])
			if !unicode.IsSpace(r) {
				break
			}
			start += size
		}
		end := len(text)
		for index := start; index < len(text); {
			r, size := utf8.DecodeRuneInString(text[index:])
			switch r {
			case '.', '!', '?', ';', '。', '！', '？', '；':
				end = index
				index = len(text)
				continue
			default:
				index += size
			}
		}
		if start < end && lastMetaOverrideLiteralIndex(text[start:end]) >= 0 {
			return metaOverrideQuotedSpan{start: start, end: end}, true
		}
	}
	return metaOverrideQuotedSpan{}, false
}

func metaOverrideConfigurationSafetyStructure(text string, spans []metaOverrideQuotedSpan) bool {
	outside := metaOverrideMaskQuotedSpans(text, spans)
	safetyPurpose := containsAnyLiteral(outside,
		"write a safety policy", "write a security policy", "document a policy", "policy that prohibits",
		"configuration hardening guidance", "configuration hardening", "review why administrators must never",
		"编写安全策略", "编写安全政策", "记录禁止", "配置加固", "审查管理员为何不得",
	)
	if !safetyPurpose || metaOverrideHasDoubleNegatedInertDirective(outside) || !metaOverrideHasNegatedMetaAction(outside) {
		return false
	}
	if metaOverrideHasActiveDirective(outside) {
		return false
	}
	last := metaOverrideLastDirectiveClause(outside)
	if last == "" {
		return false
	}
	return metaOverrideClauseIsSafetyPolicy(last) || metaOverrideHasInertDirective(last)
}

func metaOverrideQuotedSpans(text string) ([]metaOverrideQuotedSpan, bool) {
	spans := make([]metaOverrideQuotedSpan, 0, 4)
	for index := 0; index < len(text); {
		if len(spans) >= maxMetaOverrideQuotedSpans {
			return spans, false
		}
		if strings.HasPrefix(text[index:], "```") {
			closeAt := strings.Index(text[index+3:], "```")
			if closeAt < 0 {
				return spans, false
			}
			end := index + 3 + closeAt + 3
			spans = append(spans, metaOverrideQuotedSpan{start: index, end: end})
			index = end
			continue
		}
		if strings.HasPrefix(text[index:], "<sample>") {
			closeAt := strings.Index(text[index+len("<sample>"):], "</sample>")
			if closeAt < 0 {
				return spans, false
			}
			end := index + len("<sample>") + closeAt + len("</sample>")
			spans = append(spans, metaOverrideQuotedSpan{start: index, end: end})
			index = end
			continue
		}
		if strings.HasPrefix(text[index:], "[sample]") {
			closeAt := strings.Index(text[index+len("[sample]"):], "[/sample]")
			if closeAt < 0 {
				return spans, false
			}
			end := index + len("[sample]") + closeAt + len("[/sample]")
			spans = append(spans, metaOverrideQuotedSpan{start: index, end: end})
			index = end
			continue
		}

		r, size := utf8.DecodeRuneInString(text[index:])
		closeDelimiter := ""
		switch r {
		case '"':
			closeDelimiter = "\""
		case '“':
			closeDelimiter = "”"
		case '「':
			closeDelimiter = "」"
		case '『':
			closeDelimiter = "』"
		case '`':
			closeDelimiter = "`"
		case '\'':
			if metaOverrideSingleQuoteOpens(text, index, size) {
				closeDelimiter = "'"
			}
		case '‘':
			closeDelimiter = "’"
		}
		if closeDelimiter == "" {
			index += size
			continue
		}
		closeAt := metaOverrideFindClosingDelimiter(text, index+size, closeDelimiter)
		if closeAt < 0 {
			if r == '\'' {
				index += size
				continue
			}
			return spans, false
		}
		end := closeAt + len(closeDelimiter)
		spans = append(spans, metaOverrideQuotedSpan{start: index, end: end})
		index = end
	}
	return spans, true
}

func metaOverrideSingleQuoteOpens(text string, index, size int) bool {
	if index > 0 {
		previous, _ := utf8.DecodeLastRuneInString(text[:index])
		if unicode.IsLetter(previous) || unicode.IsDigit(previous) {
			return false
		}
	}
	if index+size >= len(text) {
		return false
	}
	next, _ := utf8.DecodeRuneInString(text[index+size:])
	return !unicode.IsSpace(next)
}

func metaOverrideFindClosingDelimiter(text string, start int, delimiter string) int {
	for offset := start; offset < len(text); {
		found := strings.Index(text[offset:], delimiter)
		if found < 0 {
			return -1
		}
		index := offset + found
		if !metaOverrideEscapedAt(text, index) {
			if delimiter != "'" || metaOverrideSingleQuoteCloses(text, index) {
				return index
			}
		}
		offset = index + len(delimiter)
	}
	return -1
}

func metaOverrideSingleQuoteCloses(text string, index int) bool {
	if index+1 >= len(text) {
		return true
	}
	next, _ := utf8.DecodeRuneInString(text[index+1:])
	return unicode.IsSpace(next) || unicode.IsPunct(next) || unicode.IsSymbol(next)
}

func metaOverrideEscapedAt(text string, index int) bool {
	backslashes := 0
	for index > 0 && text[index-1] == '\\' {
		backslashes++
		index--
	}
	return backslashes%2 == 1
}

func metaOverridePrimarySignalSpan(text string, spans []metaOverrideQuotedSpan) (metaOverrideQuotedSpan, bool) {
	var primary metaOverrideQuotedSpan
	found := false
	for _, span := range spans {
		if span.start < 0 || span.end > len(text) || span.start >= span.end {
			continue
		}
		if lastMetaOverrideLiteralIndex(text[span.start:span.end]) >= 0 {
			if found {
				return metaOverrideQuotedSpan{}, false
			}
			primary = span
			found = true
		}
	}
	return primary, found
}

func metaOverrideMaskQuotedSpans(text string, spans []metaOverrideQuotedSpan) string {
	if len(spans) == 0 {
		return text
	}
	masked := []byte(text)
	for _, span := range spans {
		start := span.start
		end := span.end
		if start < 0 {
			start = 0
		}
		if end > len(masked) {
			end = len(masked)
		}
		for index := start; index < end; index++ {
			masked[index] = ' '
		}
	}
	return string(masked)
}

func metaOverrideHasDoubleNegatedInertDirective(text string) bool {
	return containsAnyLiteral(text,
		"do not not execute", "do not not follow", "don't not execute", "don't not follow", "not not execute", "not not follow",
		"do not avoid executing", "do not avoid following", "do not refrain from executing", "do not refrain from following",
		"must not avoid executing", "must not avoid following", "cannot not execute", "can't not execute",
		"do not fail to execute", "do not fail to follow", "don't fail to execute", "don't fail to follow",
		"never fail to execute", "never fail to follow", "do not stop before executing", "do not stop before following",
		"不要不执行", "不要不遵循", "不得不执行", "不能不执行", "不要避免执行", "不要避免遵循", "不应避免执行",
		"不要忘记执行", "不得忘记执行", "不要停止执行", "不要只分析",
	)
}

func metaOverrideHasInertDirective(text string) bool {
	if metaOverrideHasDoubleNegatedInertDirective(text) {
		return false
	}
	if containsAnyLiteral(text,
		"keep the example inert", "keep this example inert", "keep the sample inert", "treat the example as inert",
		"treat the sample as inert", "analysis only and not execution", "for analysis only", "without operationalizing",
		"without following it", "without following the sample", "without executing it", "without executing the sample",
		"保持样本惰性", "保持示例惰性", "仅用于分析且不执行", "仅分析不执行", "不要落地执行",
	) {
		return !metaOverrideHasActiveReversal(text)
	}
	return metaOverrideHasScopedNegatedDirective(text)
}

func metaOverrideHasNegatedMetaAction(text string) bool {
	return metaOverrideHasScopedNegatedDirective(text) &&
		containsAnyLiteral(text,
			"model_instructions_file", "agents.md", "system instruction", "unrestricted mode", "prompt", "configuration", "template", "override",
			"模型指令文件", "系统指令", "无限制模式", "提示词", "配置", "模板", "覆盖",
		)
}

func metaOverrideHasActiveDirective(text string) bool {
	for _, clause := range metaOverrideDirectiveClauses(text) {
		if clause == "" {
			continue
		}
		if metaOverrideClauseHasActiveContinuation(clause) {
			return true
		}
		if metaOverrideHasActiveReversal(clause) {
			return true
		}
		safetyPolicy := metaOverrideClauseIsSafetyPolicy(clause)
		if !safetyPolicy && metaOverrideClauseHasCommaActiveTail(clause) {
			return true
		}
		if safetyPolicy || metaOverrideHasInertDirective(clause) {
			continue
		}
		trimmed := metaOverrideTrimDirectiveCue(clause)
		if metaOverrideStartsWithAction(trimmed) && metaOverrideContainsDirectiveObject(trimmed) {
			return true
		}
		if containsAnyLiteral(clause, "please ", "must ", "should ", "go ahead ", "i need you to ", "i want you to ", "请", "必须", "务必", "要求") &&
			metaOverrideContainsAction(clause) && metaOverrideContainsDirectiveObject(clause) {
			return true
		}
	}
	return false
}

func metaOverrideHasScopedNegatedDirective(text string) bool {
	for _, negation := range metaOverrideNegations {
		searchAt := 0
		for searchAt < len(text) {
			index := metaOverrideIndexToken(text[searchAt:], negation)
			if index < 0 {
				break
			}
			index += searchAt
			tail := text[index+len(negation):]
			if len(tail) > 192 {
				tail = validUTF8Prefix(tail, 192)
			}
			if boundary := metaOverrideFirstDirectiveBoundary(tail); boundary >= 0 {
				tail = tail[:boundary]
			}
			if !metaOverrideHasActiveReversal(tail) &&
				metaOverrideNegationDirectlyControlsAction(negation, tail) &&
				metaOverrideContainsDirectiveObject(tail) {
				return true
			}
			searchAt = index + len(negation)
		}
	}
	return false
}

func metaOverrideNegationDirectlyControlsAction(negation, tail string) bool {
	tail = strings.TrimLeft(strings.TrimSpace(tail), ",，:：-—– ")
	if tail == "" {
		return false
	}
	for _, prefix := range []string{"ever ", "directly ", "immediately ", "explicitly ", "再", "直接", "立即", "擅自"} {
		if strings.HasPrefix(tail, prefix) {
			tail = strings.TrimSpace(tail[len(prefix):])
			break
		}
	}
	if metaOverrideStartsWithAction(tail) {
		return true
	}
	if strings.HasPrefix(negation, "prohibit") || strings.HasPrefix(negation, "forbid") {
		for _, prefix := range []string{"appending", "replacing", "overriding", "installing", "enabling", "deploying", "applying", "executing", "following"} {
			if strings.HasPrefix(tail, prefix) {
				return true
			}
		}
	}
	if containsAnyLiteral(negation, "不要", "不得", "禁止", "严禁", "切勿", "不应", "不可") {
		for _, marker := range []string{"把", "将"} {
			if !strings.HasPrefix(tail, marker) {
				continue
			}
			actionIndex := metaOverrideFirstActionIndex(tail)
			if actionIndex > 0 && actionIndex <= 48 {
				return true
			}
		}
	}
	return false
}

func metaOverrideFirstActionIndex(text string) int {
	first := -1
	for _, action := range metaOverrideDirectiveActions {
		if index := metaOverrideIndexToken(text, action); index >= 0 && (first < 0 || index < first) {
			first = index
		}
	}
	return first
}

func metaOverrideFirstDirectiveBoundary(text string) int {
	for index, r := range text {
		switch r {
		case '.', '!', '?', ';', ':', '\n', '\r', '。', '！', '？', '；', '：':
			return index
		}
	}
	return -1
}

func metaOverrideHasActiveReversal(text string) bool {
	for _, cue := range metaOverrideReversalCues {
		searchAt := 0
		for searchAt < len(text) {
			index := strings.Index(text[searchAt:], cue)
			if index < 0 {
				break
			}
			index += searchAt
			tail := text[index+len(cue):]
			if metaOverrideContainsAction(tail) && metaOverrideContainsDirectiveObject(tail) {
				return true
			}
			searchAt = index + len(cue)
		}
	}
	return false
}

func metaOverrideClauseHasCommaActiveTail(clause string) bool {
	for index, r := range clause {
		if r != ',' && r != '，' {
			continue
		}
		tail := metaOverrideTrimDirectiveCue(clause[index+utf8.RuneLen(r):])
		if metaOverrideStartsWithAction(tail) && metaOverrideContainsDirectiveObject(tail) {
			return true
		}
	}
	return false
}

func metaOverrideClauseHasActiveContinuation(clause string) bool {
	for _, cue := range metaOverrideContinuationCues {
		searchAt := 0
		for searchAt < len(clause) {
			index := metaOverrideIndexToken(clause[searchAt:], cue)
			if index < 0 {
				break
			}
			index += searchAt
			tail := clause[index+len(cue):]
			if metaOverrideContainsAction(tail) && metaOverrideContainsDirectiveObject(tail) {
				return true
			}
			searchAt = index + len(cue)
		}
	}
	return false
}

func metaOverrideClauseIsInert(clause string) bool {
	if clause == "" || metaOverrideHasDoubleNegatedInertDirective(clause) || metaOverrideHasActiveDirective(clause) {
		return false
	}
	return metaOverrideHasInertDirective(clause) ||
		(containsAnyLiteral(clause, metaOverrideAnalysisPurposes...) &&
			(containsAnyLiteral(clause, metaOverrideAnalysisTopics...) || metaOverrideContainsDirectiveObject(clause) ||
				containsAnyLiteral(clause, "controls", "safeguards", "unsafe", "risk", "防护", "风险", "不安全")))
}

func metaOverrideClauseIsSafetyPolicy(clause string) bool {
	return containsAnyLiteral(clause,
		"safety policy", "security policy", "policy that prohibits", "configuration hardening", "administrators must never",
		"安全策略", "安全政策", "记录禁止", "配置加固", "管理员不得",
	) && metaOverrideHasNegatedMetaAction(clause)
}

func metaOverrideDirectiveClauses(text string) []string {
	return strings.FieldsFunc(text, func(r rune) bool {
		switch r {
		case '.', '!', '?', ';', ':', '\n', '\r', '。', '！', '？', '；', '：':
			return true
		default:
			return false
		}
	})
}

func metaOverrideLastDirectiveClause(text string) string {
	clauses := metaOverrideDirectiveClauses(text)
	for index := len(clauses) - 1; index >= 0; index-- {
		if clause := strings.TrimSpace(clauses[index]); clause != "" {
			return clause
		}
	}
	return ""
}

func metaOverrideTrimDirectiveCue(text string) string {
	text = strings.TrimLeft(strings.TrimSpace(text), "-*#>,， \"'`“”‘’「」『』")
	for pass := 0; pass < 4; pass++ {
		trimmed := text
		for _, cue := range metaOverrideContinuationCues {
			if strings.HasPrefix(trimmed, cue) {
				trimmed = strings.TrimLeft(strings.TrimSpace(trimmed[len(cue):]), ",，:：- ")
				break
			}
		}
		if trimmed == text {
			break
		}
		text = trimmed
	}
	return text
}

func metaOverrideContainsAction(text string) bool {
	for _, action := range metaOverrideDirectiveActions {
		if metaOverrideIndexToken(text, action) >= 0 {
			return true
		}
	}
	return false
}

func metaOverrideStartsWithAction(text string) bool {
	for _, action := range metaOverrideDirectiveActions {
		if strings.HasPrefix(text, action) {
			end := len(action)
			if end == len(text) || !metaOverrideASCIIWordByte(text[end]) || !metaOverrideASCIIWordByte(action[0]) {
				return true
			}
		}
	}
	return false
}

func metaOverrideContainsDirectiveObject(text string) bool {
	return containsAnyLiteral(text, metaOverrideDirectiveObjects...)
}

func metaOverrideIndexToken(text, token string) int {
	searchAt := 0
	for searchAt <= len(text)-len(token) {
		found := strings.Index(text[searchAt:], token)
		if found < 0 {
			return -1
		}
		index := searchAt + found
		beforeOK := index == 0 || !metaOverrideASCIIWordByte(text[index-1]) || !metaOverrideASCIIWordByte(token[0])
		end := index + len(token)
		afterOK := end == len(text) || !metaOverrideASCIIWordByte(text[end]) || !metaOverrideASCIIWordByte(token[len(token)-1])
		if beforeOK && afterOK {
			return index
		}
		searchAt = index + 1
	}
	return -1
}

func metaOverrideASCIIWordByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '_'
}

func metaOverrideQuoteBoundaryOpen(text string) bool {
	_, complete := metaOverrideQuotedSpans(strings.ToLower(text))
	return !complete
}

func metaOverrideMayContainQuotedPrefix(text string) bool {
	return strings.ContainsAny(text, "\"'`“‘「『<[：:")
}

func metaOverridePotentialQuotedPrefix(text string) bool {
	text = strings.ToLower(strings.TrimSpace(text))
	return text != "" &&
		containsAnyLiteral(text, metaOverrideAnalysisTopics...) &&
		containsAnyLiteral(text, metaOverrideAnalysisPurposes...) &&
		(metaOverrideQuoteBoundaryOpen(text) || metaOverrideEndsWithSampleMarker(text))
}

func metaOverrideEndsWithSampleMarker(text string) bool {
	for _, marker := range []string{
		"prompt injection sample:", "jailbreak sample:", "提示注入样本:", "越狱样本:", "提示注入样本：", "越狱样本：",
	} {
		if strings.HasSuffix(text, marker) {
			return true
		}
	}
	return false
}
