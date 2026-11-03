package clashapi

type privateProcessMetrics struct {
	State                string  `json:"state"`
	RSSBytes             *uint64 `json:"rss_bytes,omitempty"`
	CPUUserNanoseconds   *uint64 `json:"cpu_user_nanoseconds,omitempty"`
	CPUSystemNanoseconds *uint64 `json:"cpu_system_nanoseconds,omitempty"`
	Diagnostic           string  `json:"diagnostic,omitempty"`
}
