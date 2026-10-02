package rule

import (
	"io"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common"
	F "github.com/sagernet/sing/common/format"
)

type abstractDefaultRule struct {
	items                   []RuleItem
	sourceAddressItems      []RuleItem
	sourcePortItems         []RuleItem
	destinationAddressItems []RuleItem
	destinationIPCIDRItems  []RuleItem
	destinationPortItems    []RuleItem
	allItems                []RuleItem
	ruleSetItem             *RuleSetItem
	invert                  bool
	action                  adapter.RuleAction
}

func (r *abstractDefaultRule) Type() string {
	return C.RuleTypeDefault
}

func (r *abstractDefaultRule) Start() error {
	for _, item := range r.allItems {
		if starter, isStarter := item.(interface {
			Start() error
		}); isStarter {
			err := starter.Start()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *abstractDefaultRule) Close() error {
	for _, item := range r.allItems {
		err := common.Close(item)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *abstractDefaultRule) Match(metadata *adapter.InboundContext) bool {
	if len(r.allItems) == 0 {
		return true
	}
	// Accumulate classes into a scratch copy so failed rules never pollute
	// the caller's MatchInputs (even without ResetRuleCache).
	before := metadata.MatchInputs
	beforeDeferred := metadata.DeferredIPCIDRMatchGroups
	metadata.MatchInputs = 0
	metadata.DeferredIPCIDRMatchGroups = 0
	matched := r.matchInner(metadata)
	ruleInputs := metadata.MatchInputs
	deferredGroups := metadata.DeferredIPCIDRMatchGroups
	if r.invert {
		if !matched {
			deferredGroups = 0
			matched = true
		} else {
			matched = deferredGroups != 0
		}
	}
	if matched {
		// Commit only the winning rule's evaluated classes onto the prior base.
		metadata.MatchInputs = before | ruleInputs
		metadata.DeferredIPCIDRMatchGroups = beforeDeferred | deferredGroups
	} else {
		metadata.MatchInputs = before
		metadata.DeferredIPCIDRMatchGroups = beforeDeferred
	}
	return matched
}

func (r *abstractDefaultRule) matchInner(metadata *adapter.InboundContext) bool {
	groups := r.evaluateGroups(metadata)
	for _, item := range r.items {
		metadata.MatchInputs |= itemMatchClass(item)
		if !item.Match(metadata) {
			return false
		}
	}
	if r.ruleSetItem != nil {
		metadata.MatchInputs |= itemMatchClass(r.ruleSetItem)
		matched := r.ruleSetItem.matchWithOuterGroups(metadata, groups)
		if matched {
			metadata.DeferredIPCIDRMatchGroups &^= uint8(groups.satisfied)
		}
		return matched
	}
	matched := groups.done()
	if matched {
		metadata.DeferredIPCIDRMatchGroups &^= uint8(groups.satisfied)
	}
	return matched
}

func (r *abstractDefaultRule) evaluateForMerge(metadata *adapter.InboundContext) (ruleGroupMatch, bool) {
	groups := r.evaluateGroups(metadata)
	for _, item := range r.items {
		metadata.MatchInputs |= itemMatchClass(item)
		if !item.Match(metadata) {
			return ruleGroupMatch{}, false
		}
	}
	return groups, true
}

func (r *abstractDefaultRule) destinationIPCIDRMatchesSource(metadata *adapter.InboundContext) bool {
	return metadata.IPCIDRMatchSource && len(r.destinationIPCIDRItems) > 0
}

func (r *abstractDefaultRule) destinationIPCIDRMatchesDestination(metadata *adapter.InboundContext) bool {
	return !metadata.IgnoreDestinationIPCIDRMatch && !metadata.IPCIDRMatchSource && len(r.destinationIPCIDRItems) > 0
}

func (r *abstractDefaultRule) evaluateGroups(metadata *adapter.InboundContext) ruleGroupMatch {
	var groups ruleGroupMatch
	if len(r.sourceAddressItems) > 0 {
		accumulateItemClasses(metadata, r.sourceAddressItems)
		groups.required |= ruleMatchSourceAddress
		if matchAnyItem(r.sourceAddressItems, metadata) {
			groups.satisfied |= ruleMatchSourceAddress
		}
	}
	if r.destinationIPCIDRMatchesSource(metadata) {
		accumulateItemClasses(metadata, r.destinationIPCIDRItems)
		groups.required |= ruleMatchSourceAddress
		if !groups.satisfied.has(ruleMatchSourceAddress) && matchAnyItem(r.destinationIPCIDRItems, metadata) {
			groups.satisfied |= ruleMatchSourceAddress
		}
	}
	if len(r.sourcePortItems) > 0 {
		accumulateItemClasses(metadata, r.sourcePortItems)
		groups.required |= ruleMatchSourcePort
		if matchAnyItem(r.sourcePortItems, metadata) {
			groups.satisfied |= ruleMatchSourcePort
		}
	}
	if len(r.destinationAddressItems) > 0 {
		accumulateItemClasses(metadata, r.destinationAddressItems)
		groups.required |= ruleMatchDestinationAddress
		if matchAnyItem(r.destinationAddressItems, metadata) {
			groups.satisfied |= ruleMatchDestinationAddress
		}
	}
	if r.destinationIPCIDRMatchesDestination(metadata) {
		accumulateItemClasses(metadata, r.destinationIPCIDRItems)
		groups.required |= ruleMatchDestinationAddress
		if !groups.satisfied.has(ruleMatchDestinationAddress) && matchAnyItem(r.destinationIPCIDRItems, metadata) {
			groups.satisfied |= ruleMatchDestinationAddress
		}
	}
	if len(r.destinationPortItems) > 0 {
		accumulateItemClasses(metadata, r.destinationPortItems)
		groups.required |= ruleMatchDestinationPort
		if matchAnyItem(r.destinationPortItems, metadata) {
			groups.satisfied |= ruleMatchDestinationPort
		}
	}
	if metadata.IgnoreDestinationIPCIDRMatch && !metadata.IPCIDRMatchSource && len(r.destinationIPCIDRItems) > 0 && len(r.destinationAddressItems) == 0 {
		metadata.DeferredIPCIDRMatchGroups |= uint8(ruleMatchDestinationAddress)
	}
	return groups
}

func accumulateItemClasses(metadata *adapter.InboundContext, items []RuleItem) {
	for _, item := range items {
		metadata.MatchInputs |= itemMatchClass(item)
	}
}

func (r *abstractDefaultRule) Action() adapter.RuleAction {
	return r.action
}

func (r *abstractDefaultRule) String() string {
	if !r.invert {
		return strings.Join(F.MapToString(r.allItems), " ")
	} else {
		return "!(" + strings.Join(F.MapToString(r.allItems), " ") + ")"
	}
}

type abstractLogicalRule struct {
	rules  []adapter.HeadlessRule
	mode   string
	invert bool
	action adapter.RuleAction
}

// legacyPreMatcher preserves deferred destination-IP semantics when a logical
// DNS rule is nested inside another logical rule. Calling Match directly on a
// LogicalDNSRule intentionally evaluates it as a final boolean and drops the
// deferred group marker; pre-match must use its LegacyPreMatch path instead.
type legacyPreMatcher interface {
	LegacyPreMatch(*adapter.InboundContext) bool
}

func matchLogicalChild(rule adapter.HeadlessRule, metadata *adapter.InboundContext) bool {
	if metadata.IgnoreDestinationIPCIDRMatch {
		if preMatcher, ok := rule.(legacyPreMatcher); ok {
			return preMatcher.LegacyPreMatch(metadata)
		}
	}
	return rule.Match(metadata)
}

func (r *abstractLogicalRule) Type() string {
	return C.RuleTypeLogical
}

func (r *abstractLogicalRule) Start() error {
	for _, rule := range common.FilterIsInstance(r.rules, func(it adapter.HeadlessRule) (interface {
		Start() error
	}, bool,
	) {
		rule, loaded := it.(interface {
			Start() error
		})
		return rule, loaded
	}) {
		err := rule.Start()
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *abstractLogicalRule) Close() error {
	for _, rule := range common.FilterIsInstance(r.rules, func(it adapter.HeadlessRule) (io.Closer, bool) {
		rule, loaded := it.(io.Closer)
		return rule, loaded
	}) {
		err := rule.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *abstractLogicalRule) Match(metadata *adapter.InboundContext) bool {
	var (
		matched        bool
		collected      adapter.RouteMatchInputs
		deferredGroups uint8
	)
	before := metadata.MatchInputs
	beforeDeferred := metadata.DeferredIPCIDRMatchGroups
	if r.mode == C.LogicalTypeAnd {
		matched = true
		for _, rule := range r.rules {
			nestedMetadata := *metadata
			nestedMetadata.ResetRuleCache()
			subMatched := matchLogicalChild(rule, &nestedMetadata)
			// A nested branch may be unable to decide while destination IP
			// matching is deliberately deferred. Preserve that evidence even when
			// the branch currently returns false; an outer OR/invert must re-enter
			// address-limit evaluation instead of treating the provisional result
			// as a final boolean.
			collected |= nestedMetadata.MatchInputs
			deferredGroups |= nestedMetadata.DeferredIPCIDRMatchGroups
			if !subMatched {
				matched = false
				if deferredGroups == 0 {
					break
				}
			}
		}
	} else {
		for _, rule := range r.rules {
			nestedMetadata := *metadata
			nestedMetadata.ResetRuleCache()
			subMatched := matchLogicalChild(rule, &nestedMetadata)
			deferredGroups |= nestedMetadata.DeferredIPCIDRMatchGroups
			if subMatched {
				matched = true
				// OR: prefer the first fully-resolved match. If the match is
				// deferred, retain its classes while allowing a later rule to
				// resolve the same destination group.
				collected = nestedMetadata.MatchInputs
				if nestedMetadata.DeferredIPCIDRMatchGroups == 0 {
					break
				}
			}
		}
	}
	if r.invert {
		// A deferred address group is an unknown, not a false, result. Keep the
		// rule eligible for the post-DNS address check; otherwise nested logical
		// invert rules incorrectly skip routing during pre-match.
		if deferredGroups != 0 {
			matched = true
		} else {
			matched = !matched
		}
	}
	if matched {
		metadata.MatchInputs = before | collected
		metadata.DeferredIPCIDRMatchGroups = beforeDeferred | deferredGroups
	} else {
		metadata.MatchInputs = before
		metadata.DeferredIPCIDRMatchGroups = beforeDeferred
	}
	return matched
}

func (r *abstractLogicalRule) Action() adapter.RuleAction {
	return r.action
}

func (r *abstractLogicalRule) String() string {
	var op string
	switch r.mode {
	case C.LogicalTypeAnd:
		op = "&&"
	case C.LogicalTypeOr:
		op = "||"
	}
	if !r.invert {
		return strings.Join(F.MapToString(r.rules), " "+op+" ")
	} else {
		return "!(" + strings.Join(F.MapToString(r.rules), " "+op+" ") + ")"
	}
}

func matchAnyItem(items []RuleItem, metadata *adapter.InboundContext) bool {
	return common.Any(items, func(it RuleItem) bool {
		return it.Match(metadata)
	})
}

func (s ruleMatchState) has(target ruleMatchState) bool {
	return s&target != 0
}
