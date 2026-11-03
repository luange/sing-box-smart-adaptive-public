package trafficfamily

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxPDBFileSize = 32 << 20
	keyRecordSize  = 40
)

type CatalogStats struct {
	Applications int
	SNI          int
	Host         int
	Invalid      int
	Ambiguous    int
}

type Catalog struct {
	sni          domainIndex
	host         domainIndex
	applications map[string]struct{}
}

type domainIndex struct {
	suffix    map[string]string
	exact     map[string]string
	ambiguous map[string]struct{}
}

// LoadApplicationCatalog reads a Panabit PDB package directly. It never loads
// or executes either shared object: dict.so is scanned as a versioned data
// dictionary, while dpi.so's relocation-backed snikey/hostkey tables are read
// through debug/elf. A feature-library update therefore needs no rebuild.
func LoadApplicationCatalog(path string) (*Catalog, CatalogStats, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, CatalogStats{}, nil
	}
	dictData, dpiData, err := readPDBFiles(path)
	if err != nil {
		return nil, CatalogStats{}, err
	}
	applications := scanApplicationDictionary(dictData)
	if len(applications) == 0 {
		return nil, CatalogStats{}, fmt.Errorf("application feature library contains no valid dictionary entries")
	}
	catalog := &Catalog{
		sni:          newDomainIndex(),
		host:         newDomainIndex(),
		applications: make(map[string]struct{}, len(applications)),
	}
	for _, application := range applications {
		catalog.applications[application] = struct{}{}
	}
	stats := CatalogStats{Applications: len(applications)}
	if err = catalog.readELFKeys(dpiData, "snikey", applications, &stats); err != nil {
		return nil, stats, err
	}
	if err = catalog.readELFKeys(dpiData, "hostkey", applications, &stats); err != nil {
		return nil, stats, err
	}
	if stats.SNI+stats.Host == 0 {
		return nil, stats, fmt.Errorf("application feature library contains no valid SNI/Host entries")
	}
	return catalog, stats, nil
}

func newDomainIndex() domainIndex {
	return domainIndex{suffix: make(map[string]string), exact: make(map[string]string), ambiguous: make(map[string]struct{})}
}

func readPDBFiles(path string) ([]byte, []byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open application feature library: %w", err)
	}
	if info.IsDir() {
		dictData, dictErr := readBoundedFile(filepath.Join(path, "dict.so"))
		if dictErr != nil {
			return nil, nil, dictErr
		}
		dpiData, dpiErr := readBoundedFile(filepath.Join(path, "dpi.so"))
		return dictData, dpiData, dpiErr
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open application feature library: %w", err)
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(io.LimitReader(file, maxPDBFileSize))
	if err != nil {
		return nil, nil, fmt.Errorf("decode application feature library gzip: %w", err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	var dictData, dpiData []byte
	for {
		header, nextErr := tarReader.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			return nil, nil, fmt.Errorf("decode application feature library tar: %w", nextErr)
		}
		base := filepath.Base(header.Name)
		if base != "dict.so" && base != "dpi.so" {
			continue
		}
		if header.Size <= 0 || header.Size > maxPDBFileSize {
			return nil, nil, fmt.Errorf("invalid %s size %d", base, header.Size)
		}
		content, readErr := io.ReadAll(io.LimitReader(tarReader, header.Size+1))
		if readErr != nil {
			return nil, nil, fmt.Errorf("read %s: %w", base, readErr)
		}
		if int64(len(content)) != header.Size {
			return nil, nil, fmt.Errorf("read %s: truncated content", base)
		}
		if base == "dict.so" {
			dictData = content
		} else {
			dpiData = content
		}
	}
	if len(dictData) == 0 || len(dpiData) == 0 {
		return nil, nil, fmt.Errorf("application feature library is missing dict.so or dpi.so")
	}
	return dictData, dpiData, nil
}

func readBoundedFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", filepath.Base(path), err)
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maxPDBFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	if len(content) > maxPDBFileSize {
		return nil, fmt.Errorf("%s exceeds size limit", filepath.Base(path))
	}
	return content, nil
}

// Panabit application leaves are fixed 56-byte records. Requiring a valid
// APID range, parent group, ASCII name, zero padding and nil children makes
// the scan independent of symbol names while rejecting unrelated byte runs.
func scanApplicationDictionary(data []byte) map[uint16]string {
	applications := make(map[uint16]string)
	for offset := 0; offset+56 <= len(data); offset++ {
		apid := binary.LittleEndian.Uint16(data[offset:])
		root := binary.LittleEndian.Uint16(data[offset+2:])
		if !validApplicationID(apid) || root < 0x400 || root > 0x4ea || binary.LittleEndian.Uint64(data[offset+48:]) != 0 {
			continue
		}
		field := data[offset+4 : offset+24]
		zero := bytes.IndexByte(field, 0)
		if zero <= 0 || !allZero(field[zero+1:]) {
			continue
		}
		name := strings.ToLower(string(field[:zero]))
		if normalizeApplicationName(name) != name {
			continue
		}
		applications[apid] = name
	}
	return applications
}

func validApplicationID(apid uint16) bool {
	return apid <= 0x3ff || apid >= 0x7d0 && apid <= 0xa4f || apid >= 0xfa0 && apid <= 0x119f
}

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

func (c *Catalog) readELFKeys(data []byte, table string, applications map[uint16]string, stats *CatalogStats) error {
	file, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("decode dpi.so: %w", err)
	}
	defer file.Close()
	symbols, err := file.DynamicSymbols()
	if err != nil {
		return fmt.Errorf("read dpi.so symbols: %w", err)
	}
	var start, stop uint64
	for _, symbol := range symbols {
		switch symbol.Name {
		case "__start__" + table + "_data":
			start = symbol.Value
		case "__stop__" + table + "_data":
			stop = symbol.Value
		}
	}
	if start == 0 || stop <= start || (stop-start)%keyRecordSize != 0 {
		return fmt.Errorf("dpi.so has invalid %s table", table)
	}
	relocations, err := relativeRelocations(file)
	if err != nil {
		return err
	}
	for address := start; address < stop; address += keyRecordSize {
		record, ok := readVirtual(file, address, keyRecordSize)
		if !ok {
			return fmt.Errorf("read dpi.so %s record at %#x", table, address)
		}
		keyAddress, ok := relocations[address+8]
		if !ok {
			stats.Invalid++
			continue
		}
		rawDomain, ok := readCString(file, keyAddress, 512)
		if !ok {
			stats.Invalid++
			continue
		}
		apid := binary.LittleEndian.Uint64(record[24:32])
		if apid > 0xffff {
			stats.Invalid++
			continue
		}
		application, ok := applications[uint16(apid)]
		if !ok {
			// Handler-backed records cannot be reproduced from static data.
			stats.Invalid++
			continue
		}
		exact := strings.HasPrefix(strings.TrimSpace(rawDomain), "^")
		index := &c.sni
		if table == "hostkey" {
			index = &c.host
		}
		if index.add(rawDomain, application, exact, stats) {
			if table == "hostkey" {
				stats.Host++
			} else {
				stats.SNI++
			}
		}
	}
	return nil
}

func relativeRelocations(file *elf.File) (map[uint64]uint64, error) {
	result := make(map[uint64]uint64)
	for _, section := range file.Sections {
		if section.Type != elf.SHT_RELA {
			continue
		}
		data, err := section.Data()
		if err != nil {
			return nil, fmt.Errorf("read dpi.so relocations: %w", err)
		}
		for offset := 0; offset+24 <= len(data); offset += 24 {
			address := file.ByteOrder.Uint64(data[offset:])
			addend := file.ByteOrder.Uint64(data[offset+16:])
			result[address] = addend
		}
	}
	return result, nil
}

func readVirtual(file *elf.File, address uint64, size int) ([]byte, bool) {
	for _, program := range file.Progs {
		if program.Type != elf.PT_LOAD || address < program.Vaddr || address+uint64(size) > program.Vaddr+program.Filesz {
			continue
		}
		data := make([]byte, size)
		_, err := program.ReadAt(data, int64(address-program.Vaddr))
		return data, err == nil
	}
	return nil, false
}

func readCString(file *elf.File, address uint64, limit int) (string, bool) {
	for size := limit; size > 0; size /= 2 {
		data, ok := readVirtual(file, address, size)
		if !ok {
			continue
		}
		zero := bytes.IndexByte(data, 0)
		if zero >= 0 {
			return string(data[:zero]), true
		}
	}
	return "", false
}

func (c *domainIndex) add(raw, application string, exact bool, stats *CatalogStats) bool {
	domain := normalizeCatalogDomain(raw)
	if domain == "" {
		stats.Invalid++
		return false
	}
	if _, blocked := c.ambiguous[domain]; blocked {
		return false
	}
	table := c.suffix
	if exact {
		table = c.exact
	}
	if existing, loaded := table[domain]; loaded && existing != application {
		delete(c.suffix, domain)
		delete(c.exact, domain)
		c.ambiguous[domain] = struct{}{}
		stats.Ambiguous++
		return false
	}
	table[domain] = application
	return true
}

func (c *Catalog) ClassifyHost(host, protocol string) Match {
	if c == nil {
		return Match{}
	}
	if strings.EqualFold(protocol, "http") {
		if match := c.host.classify(host); match.ID != "" {
			return match
		}
		return c.sni.classify(host)
	}
	if match := c.sni.classify(host); match.ID != "" {
		return match
	}
	return c.host.classify(host)
}

func (c *domainIndex) classify(host string) Match {
	host = normalizeHost(host)
	if application := c.exact[host]; application != "" {
		return applicationMatch(application)
	}
	for candidate := host; candidate != ""; {
		if application := c.suffix[candidate]; application != "" {
			return applicationMatch(application)
		}
		separator := strings.IndexByte(candidate, '.')
		if separator < 0 {
			break
		}
		candidate = candidate[separator+1:]
	}
	return Match{}
}

func (c *Catalog) ClassifyApplication(application string) Match {
	application = normalizeApplicationName(application)
	if c == nil || application == "" {
		return Match{}
	}
	if _, loaded := c.applications[application]; !loaded {
		return Match{}
	}
	return applicationMatch(application)
}

func applicationMatch(application string) Match {
	id := "app:" + application
	business := applicationBusiness(application)
	return Match{ID: id, Business: business, StrictAffinity: true, ParentCandidate: true}
}

// applicationBusiness deliberately normalizes only families whose aliases are
// unambiguous. The application ID remains visible for diagnostics, while the
// business key is shared by SNI, Host and application evidence. Unknown PDB
// applications stay isolated: guessing here would make unrelated services
// inherit the same Smart incumbent.
func applicationBusiness(application string) string {
	application = normalizeApplicationName(application)
	if application == "" {
		return "app:unknown"
	}
	groups := []struct {
		business string
		aliases  []string
	}{
		{business: "telegram", aliases: []string{"telegram", "tg", "telegramweb"}},
		{business: "wechat", aliases: []string{"wechat", "weixin", "weixinwork", "wx"}},
		{business: "youtube", aliases: []string{"youtube", "googlevideo", "ytimg", "ggpht", "youtubemusic"}},
		{business: "google", aliases: []string{"google", "googleapis", "gstatic", "googleplay", "googledrive"}},
		{business: "openai", aliases: []string{"openai", "chatgpt", "gpt", "openaiapi"}},
		{business: "microsoft", aliases: []string{"microsoft", "office365", "onedrive", "teams", "xbox"}},
		{business: "apple", aliases: []string{"apple", "icloud", "itunes", "appstore"}},
		{business: "netflix", aliases: []string{"netflix", "nflxvideo", "nflximg"}},
	}
	for _, group := range groups {
		for _, alias := range group.aliases {
			if application == alias || strings.HasPrefix(application, alias+"_") || strings.HasPrefix(application, alias+"-") {
				return "app:" + group.business
			}
		}
	}
	return "app:" + application
}

func normalizeApplicationName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "app:")
	value = strings.TrimPrefix(value, "k3:")
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_' || character == '-' {
			continue
		}
		return ""
	}
	return value
}

func normalizeCatalogDomain(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "^")
	value = strings.TrimPrefix(value, ".")
	value = strings.TrimSuffix(value, ".")
	if value == "" || len(value) > 253 {
		return ""
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, character := range label {
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '_' {
				continue
			}
			return ""
		}
	}
	return value
}
