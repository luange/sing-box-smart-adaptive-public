package connectionhistory

import (
	"errors"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

const BuildTag = "with_connection_history"

var ErrAggregateDimensionHistoryIncomplete = errors.New("aggregate history predates inbound/network dimensions")

type Query struct {
	Start         time.Time
	End           time.Time
	Search        string
	SourceIP      string
	Inbound       string
	Outbound      string
	Rule          string
	Domain        string
	DestinationIP string
	Network       string
	CloseReason   string
	Offset        int
	Limit         int
}

func (q Query) HasDetailedOnlyFilters() bool {
	return q.Inbound != "" || q.Network != "" || q.CloseReason != ""
}

type Record struct {
	ID              string    `json:"id"`
	Network         string    `json:"network"`
	Inbound         string    `json:"inbound,omitempty"`
	SourceIP        string    `json:"sourceIP,omitempty"`
	SourcePort      uint16    `json:"sourcePort,omitempty"`
	SourceMAC       string    `json:"sourceMAC,omitempty"`
	SourceHostname  string    `json:"sourceHostname,omitempty"`
	DestinationIP   string    `json:"destinationIP,omitempty"`
	DestinationPort uint16    `json:"destinationPort,omitempty"`
	Domain          string    `json:"domain,omitempty"`
	Process         string    `json:"process,omitempty"`
	User            string    `json:"user,omitempty"`
	Outbound        string    `json:"outbound,omitempty"`
	OutboundType    string    `json:"outboundType,omitempty"`
	CloseReason     string    `json:"closeReason,omitempty"`
	Chain           []string  `json:"chain,omitempty"`
	Rule            string    `json:"rule,omitempty"`
	StartedAt       time.Time `json:"startedAt"`
	ClosedAt        time.Time `json:"closedAt"`
	Upload          int64     `json:"upload"`
	Download        int64     `json:"download"`
}

type ConnectionPage struct {
	Data  []Record `json:"data"`
	Total int      `json:"total"`
}

type Summary struct {
	Upload      int64 `json:"upload"`
	Download    int64 `json:"download"`
	Connections int64 `json:"connections"`
	Active      int   `json:"active"`
}

type TrafficPoint struct {
	Time        time.Time `json:"time"`
	Upload      int64     `json:"upload"`
	Download    int64     `json:"download"`
	Connections int64     `json:"connections"`
}

type Dimension struct {
	Value       string `json:"value"`
	Upload      int64  `json:"upload"`
	Download    int64  `json:"download"`
	Connections int64  `json:"connections"`
}

type DimensionPage struct {
	Data      []Dimension `json:"data"`
	Total     int         `json:"total"`
	Truncated bool        `json:"truncated,omitempty"`
}

type Status struct {
	DatabasePath               string     `json:"databasePath"`
	DatabaseSize               int64      `json:"databaseSize"`
	LegacyDatabaseSize         int64      `json:"legacyDatabaseSize,omitempty"`
	MaxDiskSize                int64      `json:"maxDiskSize"`
	SegmentCount               int        `json:"segmentCount"`
	StorageFormat              string     `json:"storageFormat"`
	Queued                     int        `json:"queued"`
	DroppedOpen                uint64     `json:"droppedOpen"`
	DroppedClose               uint64     `json:"droppedClose"`
	DroppedPendingRecords      uint64     `json:"droppedPendingRecords"`
	DroppedPendingAggregates   uint64     `json:"droppedPendingAggregates"`
	LastSampleAt               *time.Time `json:"lastSampleAt,omitempty"`
	LastPersistAt              *time.Time `json:"lastPersistAt,omitempty"`
	RawPersistFailures         uint64     `json:"rawPersistFailures"`
	RollupPersistFailures      uint64     `json:"rollupPersistFailures"`
	MaintenancePersistFailures uint64     `json:"maintenancePersistFailures"`
}

type Service interface {
	adapter.LifecycleService
	ExternalUI() string
	Summary(query Query) (Summary, error)
	Trend(query Query) ([]TrafficPoint, error)
	Connections(query Query) (ConnectionPage, error)
	Dimensions(name string, query Query) (DimensionPage, error)
	Status() Status
}
