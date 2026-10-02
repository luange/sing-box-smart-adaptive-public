//go:build linux

package oomprofile

import (
	"debug/elf"
	"encoding/hex"
	"errors"
)

var errNoELFBuildID = errors.New("ELF build ID not found")

// elfBuildID returns the GNU build ID of an ELF mapping. Keeping this small
// parser local avoids linking to runtime/pprof's private elfBuildID symbol,
// which is not stable across Go toolchains.
func elfBuildID(file string) (string, error) {
	binary, err := elf.Open(file)
	if err != nil {
		return "", err
	}
	defer binary.Close()

	for _, section := range binary.Sections {
		if section.Type != elf.SHT_NOTE {
			continue
		}
		data, err := section.Data()
		if err != nil {
			continue
		}
		for offset := 0; offset+12 <= len(data); {
			nameSize := int(binary.ByteOrder.Uint32(data[offset:]))
			descSize := int(binary.ByteOrder.Uint32(data[offset+4:]))
			noteType := binary.ByteOrder.Uint32(data[offset+8:])
			nameStart := offset + 12
			nameEnd := nameStart + nameSize
			descStart := nameStart + (nameSize+3)&^3
			descEnd := descStart + descSize
			if nameEnd > len(data) || descEnd > len(data) {
				break
			}
			if nameSize == 4 && noteType == 3 && string(data[nameStart:nameEnd]) == "GNU\x00" {
				return hex.EncodeToString(data[descStart:descEnd]), nil
			}
			offset = descStart + (descSize+3)&^3
		}
	}
	return "", errNoELFBuildID
}
