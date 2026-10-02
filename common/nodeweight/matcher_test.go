package nodeweight

import "testing"

func TestMatcherPrefersExactAndSpecificRules(t *testing.T) {
	matcher, err := New([]Rule{
		{Match: "美国", Weight: 1.2},
		{Match: "BGP", Weight: 1.5},
		{Match: "=airport/美国-广东专线 BGP 1-2", Weight: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := matcher.Weight("airport/美国-广东专线 BGP 1-2"); got != 2 {
		t.Fatalf("exact weight mismatch: %v", got)
	}
	if got := matcher.Weight("airport/美国-广东专线 BGP 2-2"); got != 1.5 {
		t.Fatalf("specific keyword weight mismatch: %v", got)
	}
	if got := matcher.Weight("airport/美国-广东专线 DAOport-2"); got != 1.2 {
		t.Fatalf("general keyword weight mismatch: %v", got)
	}
	if got := matcher.Weight("airport/日本节点"); got != Default {
		t.Fatalf("default weight mismatch: %v", got)
	}
	if got := matcher.Explain("airport/美国-广东专线 BGP 1-2"); got.Weight != 2 || !got.Exact || got.Rule != "airport/美国-广东专线 bgp 1-2" {
		t.Fatalf("exact explanation mismatch: %+v", got)
	}
	if got := matcher.Explain("airport/美国-广东专线 DAOport-2"); got.Weight != 1.2 || got.Exact || got.Rule != "美国" {
		t.Fatalf("keyword explanation mismatch: %+v", got)
	}
}

func TestMatcherRejectsUnsafeWeights(t *testing.T) {
	for _, rule := range []Rule{{Match: ""}, {Match: "node", Weight: 0}, {Match: "node", Weight: 101}, {Match: "=", Weight: 1}} {
		if _, err := New([]Rule{rule}); err == nil {
			t.Fatalf("invalid rule accepted: %+v", rule)
		}
	}
}
