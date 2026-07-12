package classifier

import (
	"fmt"
	"sort"
	"unicode"
	"unicode/utf8"

	"cyber-abuse-guard/internal/rules"
)

type patternSpec struct {
	value     string
	runes     []rune
	ascii     bool
	signalIDs map[int]struct{}
}

type matcherBuilder struct {
	patterns map[string]*patternSpec
}

func newMatcherBuilder() *matcherBuilder {
	return &matcherBuilder{patterns: make(map[string]*patternSpec)}
}

func (b *matcherBuilder) add(value string, ascii bool, signalID int) {
	pattern, ok := b.patterns[value]
	if !ok {
		pattern = &patternSpec{
			value:     value,
			runes:     []rune(value),
			ascii:     ascii,
			signalIDs: make(map[int]struct{}),
		}
		b.patterns[value] = pattern
	}
	pattern.signalIDs[signalID] = struct{}{}
}

func addTerms(standard, compact *matcherBuilder, terms rules.Terms, signalID int) error {
	values := make([]string, 0, len(terms.ZH)+len(terms.EN))
	values = append(values, terms.ZH...)
	values = append(values, terms.EN...)
	seenStandard := make(map[string]struct{}, len(values))
	seenCompact := make(map[string]struct{}, len(values))
	for _, value := range values {
		views := normalizeParts([]string{value})
		standardValue := string(views.standardRunes)
		compactValue := compactString(views.standardRunes)
		if standardValue == "" || compactValue == "" {
			return fmt.Errorf("literal %q normalizes to empty", value)
		}
		ascii := isASCII(standardValue)
		if _, exists := seenStandard[standardValue]; !exists {
			seenStandard[standardValue] = struct{}{}
			standard.add(standardValue, ascii, signalID)
		}
		if utf8.RuneCountInString(compactValue) >= 2 {
			if _, exists := seenCompact[compactValue]; !exists {
				seenCompact[compactValue] = struct{}{}
				compact.add(compactValue, ascii, signalID)
			}
		}
	}
	return nil
}

func isASCII(value string) bool {
	for _, r := range value {
		if r > unicode.MaxASCII {
			return false
		}
	}
	return true
}

type compiledPattern struct {
	length    int
	ascii     bool
	signalIDs []int
}

type automatonNode struct {
	next    map[rune]int
	failure int
	outputs []int
}

// literalMatcher is a precompiled Aho-Corasick automaton. Both ordinary and
// lightly obfuscated views are scanned in linear time without regexes.
type literalMatcher struct {
	nodes            []automatonNode
	patterns         []compiledPattern
	maxPatternLength int
}

func (b *matcherBuilder) build() *literalMatcher {
	matcher := &literalMatcher{nodes: []automatonNode{{next: make(map[rune]int)}}}
	keys := make([]string, 0, len(b.patterns))
	for key := range b.patterns {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		spec := b.patterns[key]
		signalIDs := make([]int, 0, len(spec.signalIDs))
		for signalID := range spec.signalIDs {
			signalIDs = append(signalIDs, signalID)
		}
		sort.Ints(signalIDs)
		patternIndex := len(matcher.patterns)
		matcher.patterns = append(matcher.patterns, compiledPattern{
			length:    len(spec.runes),
			ascii:     spec.ascii,
			signalIDs: signalIDs,
		})
		if len(spec.runes) > matcher.maxPatternLength {
			matcher.maxPatternLength = len(spec.runes)
		}
		state := 0
		for _, r := range spec.runes {
			next, exists := matcher.nodes[state].next[r]
			if !exists {
				next = len(matcher.nodes)
				matcher.nodes = append(matcher.nodes, automatonNode{next: make(map[rune]int)})
				matcher.nodes[state].next[r] = next
			}
			state = next
		}
		matcher.nodes[state].outputs = append(matcher.nodes[state].outputs, patternIndex)
	}
	matcher.buildFailures()
	return matcher
}

func (m *literalMatcher) buildFailures() {
	queue := make([]int, 0, len(m.nodes))
	for _, child := range m.nodes[0].next {
		m.nodes[child].failure = 0
		queue = append(queue, child)
	}
	for head := 0; head < len(queue); head++ {
		state := queue[head]
		for r, child := range m.nodes[state].next {
			queue = append(queue, child)
			failure := m.nodes[state].failure
			for failure != 0 {
				if next, ok := m.nodes[failure].next[r]; ok {
					failure = next
					break
				}
				failure = m.nodes[failure].failure
			}
			if failure == 0 {
				if next, ok := m.nodes[0].next[r]; ok && next != child {
					failure = next
				}
			}
			m.nodes[child].failure = failure
			m.nodes[child].outputs = append(m.nodes[child].outputs, m.nodes[failure].outputs...)
		}
	}
}

func (m *literalMatcher) match(text []rune, signals []bool) {
	if m == nil || len(text) == 0 {
		return
	}
	state := 0
	for index, r := range text {
		for {
			if next, ok := m.nodes[state].next[r]; ok {
				state = next
				break
			}
			if state == 0 {
				break
			}
			state = m.nodes[state].failure
		}
		for _, patternIndex := range m.nodes[state].outputs {
			pattern := m.patterns[patternIndex]
			start := index - pattern.length + 1
			if start < 0 {
				continue
			}
			if pattern.ascii && !hasWordBoundaries(text, start, index) {
				continue
			}
			for _, signalID := range pattern.signalIDs {
				signals[signalID] = true
			}
		}
	}
}

func (m *literalMatcher) matchCompact(text []rune, signals []bool) {
	if m == nil || len(text) == 0 || m.maxPatternLength == 0 {
		return
	}
	beforeRing := make([]bool, m.maxPatternLength)
	state := 0
	compactIndex := 0
	for index, r := range text {
		if r == compactHardBoundary || isHardCompactSeparator(text, index) {
			state = 0
			compactIndex = 0
			continue
		}
		if !isCompactRune(r) {
			continue
		}
		beforeRing[compactIndex%m.maxPatternLength] = index == 0 || !isASCIILetterOrDigit(text[index-1])
		for {
			if next, ok := m.nodes[state].next[r]; ok {
				state = next
				break
			}
			if state == 0 {
				break
			}
			state = m.nodes[state].failure
		}
		after := index+1 == len(text) || !isASCIILetterOrDigit(text[index+1])
		for _, patternIndex := range m.nodes[state].outputs {
			pattern := m.patterns[patternIndex]
			start := compactIndex - pattern.length + 1
			if start < 0 {
				continue
			}
			if pattern.ascii && (!beforeRing[start%m.maxPatternLength] || !after) {
				continue
			}
			for _, signalID := range pattern.signalIDs {
				signals[signalID] = true
			}
		}
		compactIndex++
	}
}

func isHardCompactSeparator(text []rune, index int) bool {
	r := text[index]
	if r == compactHardBoundary {
		return true
	}
	if unicode.IsSpace(r) || isCompactRune(r) || r == '_' {
		return false
	}
	switch r {
	case '。', '！', '？', '!', '?', '，', '：':
		return !singleRuneTokensAround(text, index)
	case '.', ',', ':', ';':
		if singleRuneTokensAround(text, index) {
			return false
		}
		return index == 0 || index+1 == len(text) || unicode.IsSpace(text[index-1]) || unicode.IsSpace(text[index+1])
	default:
		return false
	}
}

func singleRuneTokensAround(text []rune, index int) bool {
	left := index - 1
	for left >= 0 && unicode.IsSpace(text[left]) {
		left--
	}
	right := index + 1
	for right < len(text) && unicode.IsSpace(text[right]) {
		right++
	}
	if left < 0 || right >= len(text) || !isCompactRune(text[left]) || !isCompactRune(text[right]) {
		return false
	}
	leftSingle := left == 0 || !isCompactRune(text[left-1])
	rightSingle := right+1 == len(text) || !isCompactRune(text[right+1])
	return leftSingle && rightSingle
}

func hasWordBoundaries(text []rune, start, end int) bool {
	leftOK := start == 0 || !isASCIIWordRune(text[start-1])
	rightOK := end+1 == len(text) || !isASCIIWordRune(text[end+1])
	return leftOK && rightOK
}

func isASCIIWordRune(r rune) bool {
	return isASCIILetterOrDigit(r) || r == '_'
}
