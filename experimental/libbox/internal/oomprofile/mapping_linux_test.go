//go:build linux

package oomprofile

import (
	"fmt"
	"strings"
	"testing"
)

func TestParseProcSelfMaps(t *testing.T) {
	input := strings.Join([]string{
		"00400000-0040b000 r-xp 00000000 08:01 123 /bin/example",
		"0040b000-0040c000 r--p 0000b000 08:01 123 /bin/example",
		"7f000000-7f001000 rw-p 00000000 00:00 0",
		"7f001000-7f002000 r-xp invalid 00:00 0 [vdso]",
		"7f002000-7f003000 r-xp 00000000 00:00 0",
		"7f003000-7f004000 r-xp 00001000 08:01 456 /tmp/lib.so (deleted)",
	}, "\n")

	var got []string
	parseProcSelfMaps([]byte(input), func(lo, hi, offset uint64, file, buildID string) {
		got = append(got, fmt.Sprintf("%x-%x %x %s", lo, hi, offset, file))
	})
	want := []string{
		"400000-40b000 0 /bin/example",
		"7f003000-7f004000 1000 /tmp/lib.so",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("unexpected mappings:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
