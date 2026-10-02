package nodefilter

import "testing"

func TestMatcherSupportsKeywordAndExactExclusions(t *testing.T) {
	matcher, err := New([]string{" Gcore ", "=airport/完整节点名", "gcore"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{"airport/US-GCORE-01", "airport/完整节点名"} {
		if !matcher.Match(tag) {
			t.Fatalf("expected excluded tag: %s", tag)
		}
	}
	for _, tag := range []string{"airport/完整节点名-备用", "airport/普通节点"} {
		if matcher.Match(tag) {
			t.Fatalf("unexpected excluded tag: %s", tag)
		}
	}
}

func TestMatcherRejectsInvalidEntries(t *testing.T) {
	for _, entries := range [][]string{{""}, {"="}, {"bad\nentry"}} {
		if _, err := New(entries); err == nil {
			t.Fatalf("invalid entries accepted: %q", entries)
		}
	}
}
