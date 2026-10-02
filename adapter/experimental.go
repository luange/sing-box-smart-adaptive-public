package adapter

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"time"

	"github.com/sagernet/sing-box/common/hash"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/observable"
	"github.com/sagernet/sing/common/varbin"
)

type ClashServer interface {
	LifecycleService
	Mode() string
	ModeList() []string
	SetMode(mode string)
	AddModeUpdateHook(hook *observable.Subscriber[struct{}])
}

type URLTestHistory struct {
	Time  time.Time `json:"time"`
	Delay uint16    `json:"delay"`
}

type V2RayServer interface {
	LifecycleService
	StatsService() ConnectionTracker
}

// SelectedRecord is the versioned identity of a persisted group selection.
// DisplayTag is a UI alias and may change when a provider refreshes duplicate
// names; the identity fields keep the selection attached to the same
// endpoint across refreshes and restarts. Identities are opaque hashes and
// must never contain credentials or subscription URLs.
type SelectedRecord struct {
	Version          uint8  `json:"version"`
	DisplayTag       string `json:"display_tag,omitempty"`
	DialIdentity     string `json:"dial_identity,omitempty"`
	EndpointIdentity string `json:"endpoint_identity,omitempty"`
}

// SelectedRecordStore is an optional extension implemented by cache files
// that understand identity-aware persisted selections. Keeping it separate
// from CacheFile preserves compatibility with external CacheFile providers.
type SelectedRecordStore interface {
	LoadSelectedRecord(group string) (SelectedRecord, bool)
	StoreSelectedRecord(group string, record SelectedRecord) error
}

type CacheFile interface {
	LifecycleService

	CacheID() string

	StoreFakeIP() bool
	FakeIPStorage

	StoreRDRC() bool
	RDRCStore

	StoreDNS() bool
	DNSCacheStore

	SetDisableExpire(disableExpire bool)
	SetOptimisticTimeout(timeout time.Duration)

	LoadMode() string
	StoreMode(mode string) error
	LoadSelected(group string) string
	StoreSelected(group string, selected string) error
	LoadGroupExpand(group string) (isExpand bool, loaded bool)
	StoreGroupExpand(group string, expand bool) error
	LoadRuleSet(tag string) *SavedBinary
	SaveRuleSet(tag string, set *SavedBinary) error

	LoadSubscription(tag string) *SavedBinary
	SaveSubscription(tag string, sub *SavedBinary) error
}

type SavedBinary struct {
	Content     []byte
	LastUpdated time.Time
	LastEtag    string
	// URLHash belongs to the official rule-set cache format. Hash is kept
	// separately for provider subscription identity and is serialized by the
	// provider cache codec, not by MarshalBinary.
	URLHash []byte
	Hash    hash.HashType
}

func (s *SavedBinary) MarshalBinary() ([]byte, error) {
	var buffer bytes.Buffer
	err := binary.Write(&buffer, binary.BigEndian, uint8(2))
	if err != nil {
		return nil, err
	}
	_, err = varbin.WriteUvarint(&buffer, uint64(len(s.Content)))
	if err != nil {
		return nil, err
	}
	_, err = buffer.Write(s.Content)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&buffer, binary.BigEndian, s.LastUpdated.Unix())
	if err != nil {
		return nil, err
	}
	_, err = varbin.WriteUvarint(&buffer, uint64(len(s.LastEtag)))
	if err != nil {
		return nil, err
	}
	_, err = buffer.WriteString(s.LastEtag)
	if err != nil {
		return nil, err
	}
	_, err = varbin.WriteUvarint(&buffer, uint64(len(s.URLHash)))
	if err != nil {
		return nil, err
	}
	_, err = buffer.Write(s.URLHash)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func (s *SavedBinary) UnmarshalBinary(data []byte) error {
	reader := bytes.NewReader(data)
	var version uint8
	err := binary.Read(reader, binary.BigEndian, &version)
	if err != nil {
		return err
	}
	contentLength, err := binary.ReadUvarint(reader)
	if err != nil {
		return err
	}
	if contentLength > uint64(reader.Len()) {
		return E.New("invalid content length: ", contentLength)
	}
	s.Content = make([]byte, contentLength)
	_, err = io.ReadFull(reader, s.Content)
	if err != nil {
		return err
	}
	var lastUpdated int64
	err = binary.Read(reader, binary.BigEndian, &lastUpdated)
	if err != nil {
		return err
	}
	s.LastUpdated = time.Unix(lastUpdated, 0)
	etagLength, err := binary.ReadUvarint(reader)
	if err != nil {
		return err
	}
	if etagLength > uint64(reader.Len()) {
		return E.New("invalid etag length: ", etagLength)
	}
	etagBytes := make([]byte, etagLength)
	_, err = io.ReadFull(reader, etagBytes)
	if err != nil {
		return err
	}
	s.LastEtag = string(etagBytes)
	if version < 2 {
		return nil
	}
	urlHashLength, err := binary.ReadUvarint(reader)
	if err != nil {
		return err
	}
	if urlHashLength > uint64(reader.Len()) {
		return E.New("invalid url hash length: ", urlHashLength)
	}
	s.URLHash = make([]byte, urlHashLength)
	_, err = io.ReadFull(reader, s.URLHash)
	if err != nil {
		return err
	}
	return nil
}

type OutboundGroup interface {
	Outbound
	Now() string
	All() []string
}

type URLTestGroup interface {
	OutboundGroup
	URLTest(ctx context.Context) (map[string]uint16, error)
	PerformUpdateCheck()
}

// DashboardURLTestGroup is the bounded, non-fan-out probe surface used by
// control-plane clients such as Zashboard.  It is intentionally separate from
// URLTest: the latter is the full group check used by the configured scheduler,
// while a dashboard request must never turn into one dial per provider alias.
// Implementations must share their normal endpoint registry/scheduler and may
// return a partial result when the caller's deadline expires.
type DashboardURLTestGroup interface {
	OutboundGroup
	DashboardURLTest(ctx context.Context) (map[string]uint16, error)
}
