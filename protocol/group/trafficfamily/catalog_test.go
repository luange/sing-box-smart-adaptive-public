package trafficfamily

import (
	"encoding/binary"
	"os"
	"testing"
)

func TestScanApplicationDictionaryRejectsFalseRecords(t *testing.T) {
	data := make([]byte, 256)
	writeApplicationRecord(data[13:], 0x9d1, 0x405, "youtube")
	writeApplicationRecord(data[83:], 0x850, 0x404, "telegram")
	writeApplicationRecord(data[153:], 0x850, 0x404, "invalid name")
	applications := scanApplicationDictionary(data)
	if len(applications) != 2 || applications[0x9d1] != "youtube" || applications[0x850] != "telegram" {
		t.Fatalf("unexpected applications: %+v", applications)
	}
}

func TestCatalogKeepsSNIAndHostContextsSeparate(t *testing.T) {
	catalog := &Catalog{sni: newDomainIndex(), host: newDomainIndex(), applications: map[string]struct{}{"video": {}, "web": {}}}
	stats := new(CatalogStats)
	catalog.sni.add(".example.com", "video", false, stats)
	catalog.host.add(".example.com", "web", false, stats)
	if got := catalog.ClassifyHost("cdn.example.com", "tls"); got.ID != "app:video" {
		t.Fatalf("SNI table mismatch: %+v", got)
	}
	if got := catalog.ClassifyHost("cdn.example.com", "http"); got.ID != "app:web" {
		t.Fatalf("Host table mismatch: %+v", got)
	}
	if got := catalog.ClassifyApplication("tls"); got.ID != "" {
		t.Fatalf("unknown transport became an application: %+v", got)
	}
}

func TestApplicationBusinessNormalization(t *testing.T) {
	for _, application := range []string{"youtube", "googlevideo", "ytimg"} {
		match := applicationMatch(application)
		if match.Business != "app:youtube" {
			t.Fatalf("%s was not normalized to youtube business: %+v", application, match)
		}
	}
	if applicationMatch("telegram").Business != "app:telegram" {
		t.Fatal("telegram business was not normalized")
	}
	if applicationMatch("unrelated_service").Business != "app:unrelated_service" {
		t.Fatal("unknown application was over-normalized")
	}
}

func TestLoadPrivatePDB(t *testing.T) {
	path := os.Getenv("PANABIT_PDB_TEST")
	if path == "" {
		t.Skip("PANABIT_PDB_TEST is not set")
	}
	catalog, stats, err := LoadApplicationCatalog(path)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Applications < 1000 || stats.SNI < 1000 || stats.Host < 100 {
		t.Fatalf("unexpected catalog stats: %+v", stats)
	}
	if match := catalog.ClassifyHost("r1.googlevideo.com", "tls"); match.ID == "" {
		t.Fatal("known SNI did not classify")
	}
}

func writeApplicationRecord(target []byte, apid, root uint16, name string) {
	binary.LittleEndian.PutUint16(target, apid)
	binary.LittleEndian.PutUint16(target[2:], root)
	copy(target[4:24], name)
}
