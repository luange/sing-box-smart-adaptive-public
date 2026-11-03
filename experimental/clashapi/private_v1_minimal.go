package clashapi

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"runtime"
	"sort"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

// privateV1Router is intentionally versioned and capability-gated.  Panels
// must never infer support from a reachable Clash controller: every endpoint
// below has an explicit declaration in GET /private/v1/capabilities.
func privateV1Router(server *Server) http.Handler {
	r := chi.NewRouter()
	r.Get("/capabilities", privateV1Capabilities(server))
	r.Get("/runtime/telemetry", privateV1RuntimeTelemetry(server))
	r.Get("/smart/status", privateV1SmartStatus(server))
	return r
}

func newPrivateProcessInstanceID() string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		// A failed OS random read is exceptionally unusual.  Keep the API
		// available, but do not return a process-stable synthetic constant.
		return hex.EncodeToString([]byte(time.Now().UTC().Format("20060102150405.000000000")))[:32]
	}
	return hex.EncodeToString(value)
}

func privateV1CoreRevision() string {
	if C.Revision != "" {
		return C.Revision
	}
	return C.Version
}

func privateV1SmartGroupID(tag string) string {
	digest := sha256.Sum256([]byte(tag))
	return "smart_" + hex.EncodeToString(digest[:16])
}

func privateV1Capabilities(server *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		render.JSON(w, r, map[string]any{
			"api_version":         map[string]int{"major": 1, "minor": 11},
			"core_revision":       privateV1CoreRevision(),
			"process_instance_id": server.processInstanceID,
			"features": map[string]any{
				"runtime.telemetry": map[string]any{"supported": true, "schema_version": 1},
				"smart.status":      map[string]any{"supported": true, "schema_version": 3},
				"smart.pin":         map[string]any{"supported": false, "schema_version": 0, "diagnostic": "use the native /smart endpoint until private Smart migration completes"},
			},
			"endpoints": []map[string]string{
				{"method": http.MethodGet, "path": "/private/v1/capabilities"},
				{"method": http.MethodGet, "path": "/private/v1/runtime/telemetry", "feature": "runtime.telemetry"},
				{"method": http.MethodGet, "path": "/private/v1/smart/status", "feature": "smart.status"},
			},
		})
	}
}

// privateV1SmartStatus is a projection of the one Smart owner. Observing it
// cannot probe, score, or select a leaf, so dashboard refreshes are inert.
func privateV1SmartStatus(server *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type statusView struct {
			OwnerInstanceID      string                        `json:"owner_instance_id"`
			SelectionRevision    uint64                        `json:"selection_revision"`
			Pinned               string                        `json:"pinned,omitempty"`
			Selected             string                        `json:"selected,omitempty"`
			SelectedEndpointID   string                        `json:"selected_endpoint_id,omitempty"`
			ActualDialEndpointID string                        `json:"actual_dial_endpoint_id,omitempty"`
			SelectionGeneration  uint64                        `json:"selection_generation,omitempty"`
			Network              string                        `json:"network,omitempty"`
			Site                 string                        `json:"site,omitempty"`
			CircuitState         string                        `json:"circuit_state,omitempty"`
			Reason               string                        `json:"reason,omitempty"`
			UpdatedAt            time.Time                     `json:"updated_at,omitempty"`
			Contexts             []adapter.SmartContextStatus  `json:"contexts,omitempty"`
			RecentSwitches       []adapter.SmartSwitchAudit    `json:"recent_switches,omitempty"`
			RecentDialEvents     []adapter.SmartDialDiagnostic `json:"recent_dial_events"`
		}
		type groupView struct {
			GroupID              string     `json:"group_id"`
			Tag                  string     `json:"tag"`
			ActualDialEndpointID string     `json:"actual_dial_endpoint_id,omitempty"`
			Status               statusView `json:"status"`
		}
		groups := make([]groupView, 0)
		for _, outbound := range server.outbound.Outbounds() {
			if outbound == nil || outbound.Tag() == "" {
				continue
			}
			controller, ok := outbound.(adapter.SmartRuntimeController)
			if !ok {
				continue
			}
			runtimeStatus := controller.SmartRuntimeStatus()
			status := runtimeStatus.Status
			groups = append(groups, groupView{
				GroupID: privateV1SmartGroupID(outbound.Tag()), Tag: outbound.Tag(), ActualDialEndpointID: status.ActualDialEndpointID,
				Status: statusView{
					OwnerInstanceID: runtimeStatus.OwnerInstanceID, SelectionRevision: runtimeStatus.SelectionRevision,
					Pinned: status.Pinned, Selected: status.Selected, SelectedEndpointID: status.SelectedEndpointID,
					ActualDialEndpointID: status.ActualDialEndpointID, SelectionGeneration: status.SelectionGeneration,
					Network: status.Network, Site: status.Site, CircuitState: status.CircuitState, Reason: status.Reason,
					UpdatedAt:        status.UpdatedAt,
					Contexts:         append([]adapter.SmartContextStatus{}, status.Contexts...),
					RecentSwitches:   append([]adapter.SmartSwitchAudit{}, status.RecentSwitches...),
					RecentDialEvents: append([]adapter.SmartDialDiagnostic{}, status.RecentDialEvents...),
				},
			})
		}
		sort.Slice(groups, func(i, j int) bool { return groups[i].Tag < groups[j].Tag })
		w.Header().Set("Cache-Control", "no-store")
		render.JSON(w, r, map[string]any{
			"schema_version": 3, "core_revision": privateV1CoreRevision(),
			"process_instance_id": server.processInstanceID, "sampled_at": time.Now().UTC(), "groups": groups,
		})
	}
}

func privateV1RuntimeTelemetry(server *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		now := time.Now().UTC()
		startedAt := server.startedAt
		if startedAt.IsZero() || startedAt.After(now) {
			startedAt = now
		}
		var memory runtime.MemStats
		runtime.ReadMemStats(&memory)
		outboundActive := 0
		var upload, download int64
		if server.trafficManager != nil {
			outboundActive = server.trafficManager.ConnectionsLen()
			upload, download = server.trafficManager.Total()
		}
		w.Header().Set("Cache-Control", "no-store")
		render.JSON(w, r, map[string]any{
			"schema_version":      1,
			"core_revision":       privateV1CoreRevision(),
			"process_instance_id": server.processInstanceID,
			"process_id":          os.Getpid(),
			"sampled_at":          now,
			"started_at":          startedAt,
			"uptime_seconds":      int64(now.Sub(startedAt).Seconds()),
			"process":             map[string]any{"state": "unsupported", "diagnostic": "OS RSS and CPU counters are not yet exposed by this core build"},
			"runtime": map[string]any{
				"go_version": runtime.Version(), "goroutines": runtime.NumGoroutine(),
				"heap_alloc_bytes": memory.HeapAlloc, "heap_inuse_bytes": memory.HeapInuse,
				"heap_sys_bytes": memory.HeapSys, "stack_inuse_bytes": memory.StackInuse,
				"total_alloc_bytes": memory.TotalAlloc, "num_gc": memory.NumGC,
				"gc_pause_total_ns": memory.PauseTotalNs,
			},
			"connections": map[string]any{
				"inbound_available": false, "inbound_active": nil,
				"outbound_available": server.trafficManager != nil, "outbound_active": func() *int {
					if server.trafficManager == nil {
						return nil
					}
					return &outboundActive
				}(),
			},
			"traffic": map[string]any{
				"available": server.trafficManager != nil,
				"uplink_total_bytes": func() *int64 {
					if server.trafficManager == nil {
						return nil
					}
					return &upload
				}(),
				"downlink_total_bytes": func() *int64 {
					if server.trafficManager == nil {
						return nil
					}
					return &download
				}(),
			},
		})
	}
}
