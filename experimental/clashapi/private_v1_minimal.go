package clashapi

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
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
	r.Get("/smart/groups/{groupID}/endpoint", privateV1SmartEndpoint(server))
	r.Put("/smart/groups/{groupID}/pin", privateV1SmartPin(server, true))
	r.Delete("/smart/groups/{groupID}/pin", privateV1SmartPin(server, false))
	return r
}

const privateV1SmartMutationLifetime = 10 * time.Minute
const privateV1SmartMutationCapacity = 256

type privateV1SmartMutationCache struct {
	fingerprint [32]byte
	expiresAt   time.Time
	status      int
	body        []byte
}

type privateV1SmartPinRequest struct {
	CoreRevision              string `json:"core_revision"`
	ProcessInstanceID         string `json:"process_instance_id"`
	OwnerInstanceID           string `json:"owner_instance_id"`
	ExpectedSelectionRevision uint64 `json:"expected_selection_revision"`
	EndpointID                string `json:"endpoint_id,omitempty"`
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
				"smart.pin":         map[string]any{"supported": true, "schema_version": 2},
			},
			"endpoints": []map[string]string{
				{"method": http.MethodGet, "path": "/private/v1/capabilities"},
				{"method": http.MethodGet, "path": "/private/v1/runtime/telemetry", "feature": "runtime.telemetry"},
				{"method": http.MethodGet, "path": "/private/v1/smart/status", "feature": "smart.status"},
				{"method": http.MethodGet, "path": "/private/v1/smart/groups/{groupID}/endpoint", "feature": "smart.pin"},
				{"method": http.MethodPut, "path": "/private/v1/smart/groups/{groupID}/pin", "feature": "smart.pin", "operation": "pin"},
				{"method": http.MethodDelete, "path": "/private/v1/smart/groups/{groupID}/pin", "feature": "smart.pin", "operation": "restore_automatic"},
			},
		})
	}
}

func privateV1SmartController(server *Server, groupID string) (adapter.SmartRuntimeController, bool) {
	if server.outbound == nil || !strings.HasPrefix(groupID, "smart_") || len(groupID) != len("smart_")+32 {
		return nil, false
	}
	for _, outbound := range server.outbound.Outbounds() {
		if outbound == nil || privateV1SmartGroupID(outbound.Tag()) != groupID {
			continue
		}
		controller, ok := outbound.(adapter.SmartRuntimeController)
		return controller, ok
	}
	return nil, false
}

func privateV1SmartError(w http.ResponseWriter, status int, code string, retryable bool) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": code, "message": code, "retryable": retryable}})
}

func privateV1SmartEndpoint(server *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		controller, ok := privateV1SmartController(server, chi.URLParam(r, "groupID"))
		tag := r.URL.Query().Get("tag")
		if !ok || tag == "" {
			privateV1SmartError(w, http.StatusNotFound, "smart_endpoint_not_found", false)
			return
		}
		status, endpointID, found := controller.SmartEndpointSnapshot(tag)
		if !found {
			privateV1SmartError(w, http.StatusNotFound, "smart_endpoint_not_found", false)
			return
		}
		render.JSON(w, r, map[string]string{
			"group_id": chi.URLParam(r, "groupID"), "tag": tag, "endpoint_id": endpointID,
			"core_revision": privateV1CoreRevision(), "process_instance_id": server.processInstanceID,
			"owner_instance_id": status.OwnerInstanceID,
		})
	}
}

func privateV1ReadSmartPinRequest(r *http.Request, requireEndpoint bool) (privateV1SmartPinRequest, []byte, bool) {
	var request privateV1SmartPinRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, (16<<10)+1))
	if err != nil || len(body) == 0 || len(body) > 16<<10 || !json.Valid(body) {
		return request, nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || request.CoreRevision != privateV1CoreRevision() || request.ProcessInstanceID == "" || request.OwnerInstanceID == "" || request.ExpectedSelectionRevision == 0 {
		return request, nil, false
	}
	if requireEndpoint && (request.EndpointID == "" || len(request.EndpointID) > 128 || strings.ContainsAny(request.EndpointID, "\r\n\t ")) {
		return request, nil, false
	}
	return request, body, true
}

func privateV1SmartPin(server *Server, pin bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		if len(key) < 32 || len(key) > 128 {
			privateV1SmartError(w, http.StatusBadRequest, "invalid_smart_request", false)
			return
		}
		if _, err := hex.DecodeString(key); err != nil {
			privateV1SmartError(w, http.StatusBadRequest, "invalid_smart_request", false)
			return
		}
		request, body, valid := privateV1ReadSmartPinRequest(r, pin)
		if !valid {
			privateV1SmartError(w, http.StatusBadRequest, "invalid_smart_request", false)
			return
		}
		fingerprint := sha256.Sum256(append([]byte(r.Method+"\x00"+r.URL.Path+"\x00"+server.processInstanceID+"\x00"), body...))
		server.privateSmartMu.Lock()
		defer server.privateSmartMu.Unlock()
		now := time.Now()
		for existingKey, cached := range server.privateSmartCache {
			if !now.Before(cached.expiresAt) {
				delete(server.privateSmartCache, existingKey)
			}
		}
		if cached, exists := server.privateSmartCache[key]; exists {
			if cached.fingerprint != fingerprint {
				privateV1SmartError(w, http.StatusConflict, "idempotency_conflict", false)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(cached.status)
			_, _ = w.Write(cached.body)
			return
		}
		if len(server.privateSmartCache) >= privateV1SmartMutationCapacity {
			privateV1SmartError(w, http.StatusServiceUnavailable, "idempotency_capacity_exceeded", true)
			return
		}
		status, response := privateV1ApplySmartPin(server, chi.URLParam(r, "groupID"), request, pin)
		server.privateSmartCache[key] = privateV1SmartMutationCache{fingerprint: fingerprint, expiresAt: now.Add(privateV1SmartMutationLifetime), status: status, body: response}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(response)
	}
}

func privateV1ApplySmartPin(server *Server, groupID string, request privateV1SmartPinRequest, pin bool) (int, []byte) {
	if request.ProcessInstanceID != server.processInstanceID {
		return privateV1SmartJSONError(http.StatusConflict, "smart_core_identity_changed", true)
	}
	controller, ok := privateV1SmartController(server, groupID)
	if !ok {
		return privateV1SmartJSONError(http.StatusNotFound, "smart_group_not_found", false)
	}
	current := controller.SmartRuntimeStatus()
	if current.OwnerInstanceID != request.OwnerInstanceID || current.SelectionRevision != request.ExpectedSelectionRevision {
		return privateV1SmartJSONError(http.StatusConflict, "smart_selection_revision_conflict", true)
	}
	var revision uint64
	var committed bool
	mode := "automatic"
	if pin {
		revision, committed = controller.SmartSetPinnedEndpoint(request.EndpointID, request.OwnerInstanceID, request.ExpectedSelectionRevision)
		mode = "pinned"
	} else {
		revision, committed = controller.SmartRestoreAutomatic(request.OwnerInstanceID, request.ExpectedSelectionRevision)
	}
	if !committed {
		return privateV1SmartJSONError(http.StatusConflict, "smart_selection_revision_conflict", true)
	}
	response, err := json.Marshal(map[string]any{"group_id": groupID, "core_revision": privateV1CoreRevision(), "process_instance_id": server.processInstanceID, "owner_instance_id": request.OwnerInstanceID, "selection_revision": revision, "mode": mode})
	if err != nil {
		return privateV1SmartJSONError(http.StatusServiceUnavailable, "smart_response_unavailable", true)
	}
	return http.StatusOK, response
}

func privateV1SmartJSONError(status int, code string, retryable bool) (int, []byte) {
	body, _ := json.Marshal(map[string]any{"error": map[string]any{"code": code, "message": code, "retryable": retryable}})
	return status, body
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
		if server.outbound != nil {
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
			"process":             readPrivateProcessMetrics(),
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
