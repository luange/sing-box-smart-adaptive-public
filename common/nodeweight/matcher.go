package nodeweight

import (
	"errors"
	"math"
	"strings"
	"unicode/utf8"
)

const Default = 1.0

type Rule struct {
	Match  string
	Weight float64
}

type compiledRule struct {
	match  string
	exact  bool
	weight float64
}

type Matcher struct {
	rules []compiledRule
}

type Match struct {
	Weight float64
	Rule   string
	Exact  bool
}

func New(rules []Rule) (*Matcher, error) {
	matcher := &Matcher{rules: make([]compiledRule, 0, len(rules))}
	for _, rule := range rules {
		match := strings.TrimSpace(rule.Match)
		if match == "" || math.IsNaN(rule.Weight) || math.IsInf(rule.Weight, 0) || rule.Weight < 0.01 || rule.Weight > 100 {
			return nil, errors.New("node weight rule is invalid")
		}
		exact := strings.HasPrefix(match, "=")
		if exact {
			match = strings.TrimSpace(strings.TrimPrefix(match, "="))
			if match == "" {
				return nil, errors.New("node weight exact match is empty")
			}
		}
		matcher.rules = append(matcher.rules, compiledRule{match: strings.ToLower(match), exact: exact, weight: rule.Weight})
	}
	return matcher, nil
}

func (m *Matcher) Weight(tag string) float64 {
	return m.Explain(tag).Weight
}

func (m *Matcher) Explain(tag string) Match {
	if m == nil || len(m.rules) == 0 {
		return Match{Weight: Default}
	}
	tag = strings.ToLower(tag)
	bestWeight := Default
	bestLength := -1
	bestRule := ""
	bestExact := false
	for _, rule := range m.rules {
		matched := tag == rule.match
		if !rule.exact {
			matched = strings.Contains(tag, rule.match)
		}
		if !matched {
			continue
		}
		// Exact matches always win. Keyword ties use the longest/more specific
		// match, then the later rule to permit an explicit local override.
		length := utf8.RuneCountInString(rule.match)
		if rule.exact {
			length += 1 << 20
		}
		if length >= bestLength {
			bestLength = length
			bestWeight = rule.weight
			bestRule = rule.match
			bestExact = rule.exact
		}
	}
	return Match{Weight: bestWeight, Rule: bestRule, Exact: bestExact}
}
