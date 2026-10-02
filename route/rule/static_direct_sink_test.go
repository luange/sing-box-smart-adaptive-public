package rule

import (
	"net/netip"
	"testing"
)

func TestIPCIDRItemPrefixesDestinationOnly(t *testing.T) {
	dst, err := NewIPCIDRItem(false, []string{"1.1.1.0/24", "8.8.8.8"})
	if err != nil {
		t.Fatal(err)
	}
	prefixes := dst.Prefixes()
	if len(prefixes) < 2 {
		t.Fatalf("want >=2 prefixes got %v", prefixes)
	}
	src, err := NewIPCIDRItem(true, []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	if len(src.Prefixes()) != 0 {
		t.Fatal("source cidr must not export prefixes")
	}
}

func TestCollectStaticDirectPrefixesEmpty(t *testing.T) {
	got := CollectStaticDirectPrefixes(nil, nil)
	if len(got) != 0 {
		t.Fatalf("%v", got)
	}
	// Sanity: parse helper
	_ = netip.MustParsePrefix("0.0.0.0/0")
}
