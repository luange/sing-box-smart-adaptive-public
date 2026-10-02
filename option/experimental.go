package option

import (
	"github.com/sagernet/sing/common/byteformats"
	"github.com/sagernet/sing/common/json/badoption"
)

type ExperimentalOptions struct {
	CacheFile         *CacheFileOptions         `json:"cache_file,omitempty"`
	ClashAPI          *ClashAPIOptions          `json:"clash_api,omitempty"`
	ConnectionHistory *ConnectionHistoryOptions `json:"connection_history,omitempty"`
	V2RayAPI          *V2RayAPIOptions          `json:"v2ray_api,omitempty"`
	Debug             *DebugOptions             `json:"debug,omitempty"`
}

type ConnectionHistoryOptions struct {
	Enabled            bool                     `json:"enabled,omitempty"`
	Path               string                   `json:"path,omitempty"`
	ExternalUI         string                   `json:"external_ui,omitempty"`
	Retention          badoption.Duration       `json:"retention,omitempty"`
	DetailRetention    badoption.Duration       `json:"detail_retention,omitempty"`
	AggregateRetention badoption.Duration       `json:"aggregate_retention,omitempty"`
	SegmentSize        *byteformats.MemoryBytes `json:"segment_size,omitempty"`
	MaxDiskSize        *byteformats.MemoryBytes `json:"max_disk_size,omitempty"`
}

type CacheFileOptions struct {
	Enabled     bool               `json:"enabled,omitempty"`
	Path        string             `json:"path,omitempty"`
	CacheID     string             `json:"cache_id,omitempty"`
	StoreFakeIP bool               `json:"store_fakeip,omitempty"`
	StoreRDRC   bool               `json:"store_rdrc,omitempty" schema:"omit"`
	RDRCTimeout badoption.Duration `json:"rdrc_timeout,omitempty"`
	StoreDNS    bool               `json:"store_dns,omitempty"`
}

type ClashAPIOptions struct {
	ExternalController               string                     `json:"external_controller,omitempty"`
	ExternalUI                       string                     `json:"external_ui,omitempty"`
	ExternalUIDownloadURL            string                     `json:"external_ui_download_url,omitempty"`
	ExternalUIDownloadDetour         string                     `json:"external_ui_download_detour,omitempty" reference:"outbound"`
	Secret                           string                     `json:"secret,omitempty"`
	DefaultMode                      string                     `json:"default_mode,omitempty"`
	ModeList                         []string                   `json:"-"`
	AccessControlAllowOrigin         badoption.Listable[string] `json:"access_control_allow_origin,omitempty"`
	AccessControlAllowPrivateNetwork bool                       `json:"access_control_allow_private_network,omitempty"`
	MemoryReclaim                    *MemoryReclaimOptions      `json:"memory_reclaim,omitempty"`

	// Deprecated: migrated to global cache file
	CacheFile string `json:"cache_file,omitempty" schema:"omit"`
	// Deprecated: migrated to global cache file
	CacheID string `json:"cache_id,omitempty" schema:"omit"`
	// Deprecated: migrated to global cache file
	StoreMode bool `json:"store_mode,omitempty" schema:"omit"`
	// Deprecated: migrated to global cache file
	StoreSelected bool `json:"store_selected,omitempty" schema:"omit"`
	// Deprecated: migrated to global cache file
	StoreFakeIP bool `json:"store_fakeip,omitempty" schema:"omit"`
}

// MemoryReclaimOptions controls conservative return of unused Go heap pages to
// the operating system. It never discards live objects or connection state.
// Behavior mirrors reF1nd clash memory_reclaim: eligible idle heap is returned
// via debug.FreeOSMemory on a cooldown, which lowers zashboard inuse
// (StackInuse+HeapInuse+HeapIdle-HeapReleased) without changing the metric formula.
type MemoryReclaimOptions struct {
	Enabled             bool                     `json:"enabled,omitempty"`
	CheckInterval       badoption.Duration       `json:"check_interval,omitempty"`
	Cooldown            badoption.Duration       `json:"cooldown,omitempty"`
	MinimumProcessAge   badoption.Duration       `json:"minimum_process_age,omitempty"`
	MinimumIdle         *byteformats.MemoryBytes `json:"minimum_idle,omitempty"`
	MaximumHeapAlloc    *byteformats.MemoryBytes `json:"maximum_heap_alloc,omitempty"`
	ConsecutiveEligible int                      `json:"consecutive_eligible,omitempty"`
}

type V2RayAPIOptions struct {
	Listen string                    `json:"listen,omitempty"`
	Stats  *V2RayStatsServiceOptions `json:"stats,omitempty"`
}

type V2RayStatsServiceOptions struct {
	Enabled   bool     `json:"enabled,omitempty"`
	Inbounds  []string `json:"inbounds,omitempty"`
	Outbounds []string `json:"outbounds,omitempty"`
	Users     []string `json:"users,omitempty"`
}
