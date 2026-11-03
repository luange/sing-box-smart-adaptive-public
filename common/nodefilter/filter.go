package nodefilter

import (
	"errors"
	"strings"
)

const (
	maxEntries    = 256
	maxEntryBytes = 256
)

// Matcher implements the human-maintained node exclusion list shared by
// Smart and AdaptivePool. Plain entries are case-insensitive keywords. An
// entry beginning with '=' matches the complete node tag exactly.
type Matcher struct {
	exact    map[string]struct{}
	keywords []string
}

func New(entries []string) (*Matcher, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	if len(entries) > maxEntries {
		return nil, errors.New("manual node exclusion list is too large")
	}
	matcher := &Matcher{exact: make(map[string]struct{})}
	seenKeywords := make(map[string]struct{})
	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" || len(entry) > maxEntryBytes || strings.ContainsAny(entry, "\r\n\x00") {
			return nil, errors.New("manual node exclusion entry is invalid")
		}
		if strings.HasPrefix(entry, "=") {
			exact := strings.TrimSpace(strings.TrimPrefix(entry, "="))
			if exact == "" {
				return nil, errors.New("manual exact node exclusion is empty")
			}
			matcher.exact[exact] = struct{}{}
			continue
		}
		keyword := strings.ToLower(entry)
		if _, loaded := seenKeywords[keyword]; loaded {
			continue
		}
		seenKeywords[keyword] = struct{}{}
		matcher.keywords = append(matcher.keywords, keyword)
	}
	return matcher, nil
}

func (m *Matcher) Match(tag string) bool {
	if m == nil || tag == "" {
		return false
	}
	if _, loaded := m.exact[tag]; loaded {
		return true
	}
	lowerTag := strings.ToLower(tag)
	for _, keyword := range m.keywords {
		if strings.Contains(lowerTag, keyword) {
			return true
		}
	}
	return false
}
