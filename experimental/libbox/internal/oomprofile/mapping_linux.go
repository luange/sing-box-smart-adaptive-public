//go:build linux

package oomprofile

import (
	"bytes"
	"os"
	"strconv"
	"strings"
)

func (b *profileBuilder) readMapping() {
	data, _ := os.ReadFile("/proc/self/maps")
	parseProcSelfMaps(data, func(lo, hi, offset uint64, file, buildID string) {
		b.addMappingEntry(lo, hi, offset, file, buildID, false)
	})
	if len(b.mem) == 0 {
		b.addMappingEntry(0, 0, 0, "", "", true)
	}
}

// parseProcSelfMaps parses Linux /proc/self/maps without depending on the
// unexported runtime/pprof parser. That symbol is not a stable Go API and was
// removed from newer toolchains, while the maps format itself is stable.
func parseProcSelfMaps(data []byte, addMapping func(lo, hi, offset uint64, file, buildID string)) {
	var line []byte
	next := func() []byte {
		var field []byte
		field, line, _ = bytes.Cut(line, []byte{' '})
		line = bytes.TrimLeft(line, " ")
		return field
	}

	for len(data) > 0 {
		line, data, _ = bytes.Cut(data, []byte{'\n'})
		address := next()
		loString, hiString, ok := strings.Cut(string(address), "-")
		if !ok {
			continue
		}
		lo, err := strconv.ParseUint(loString, 16, 64)
		if err != nil {
			continue
		}
		hi, err := strconv.ParseUint(hiString, 16, 64)
		if err != nil {
			continue
		}
		permissions := next()
		if len(permissions) < 4 || permissions[2] != 'x' {
			continue
		}
		offset, err := strconv.ParseUint(string(next()), 16, 64)
		if err != nil {
			continue
		}
		next() // device
		inode := next()
		if line == nil {
			continue
		}
		file := string(line)
		const deleted = " (deleted)"
		if strings.HasSuffix(file, deleted) {
			file = strings.TrimSuffix(file, deleted)
		}
		if len(inode) == 1 && inode[0] == '0' && file == "" {
			// Unpopulated huge-page fragments are not useful mappings.
			continue
		}
		buildID, _ := elfBuildID(file)
		addMapping(lo, hi, offset, file, buildID)
	}
}
