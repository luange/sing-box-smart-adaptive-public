package clashapi

import (
	"net/http"
	"runtime"
	"sort"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/protocol/group"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

// smartRouter is a native Smart control-plane surface. Clash's standard
// /proxies endpoint remains compatible, while this endpoint gives panels a
// stable way to fetch Smart state and issue explicit, revision-guarded
// controls without interpreting selector fields.
func smartRouter(server *Server) http.Handler {
	r := chi.NewRouter()
	r.Get("/", getSmartGroups(server))
	r.Get("/health", getSharedSmartHealth(server))
	r.Get("/health/entries", getSharedSmartHealthEntries(server))
	r.Get("/health/events", getSharedSmartHealthEvents(server))
	r.Get("/memory", getSmartMemory(server))
	r.Get("/{name}/events", getSmartGroupEvents(server))
	r.Get("/{name}/runtime", getSmartGroupRuntime(server))
	r.Post("/{name}/probe", requestSmartGroupProbe(server))
	r.Post("/{name}/pin", pinSmartGroup(server))
	r.Delete("/{name}/pin", restoreSmartGroupAutomatic(server))
	r.Get("/{name}", getSmartGroupStatus(server))
	return r
}

type smartMemoryStatus struct {
	Timestamp      time.Time                    `json:"timestamp"`
	HeapAlloc      uint64                       `json:"heap_alloc"`
	HeapInuse      uint64                       `json:"heap_inuse"`
	HeapIdle       uint64                       `json:"heap_idle"`
	HeapReleased   uint64                       `json:"heap_released"`
	StackInuse     uint64                       `json:"stack_inuse"`
	Sys            uint64                       `json:"sys"`
	NumGC          uint32                       `json:"num_gc"`
	Goroutines     int                          `json:"goroutines"`
	URLTestHistory urltest.HistoryStorageStatus `json:"urltest_history"`
}

func getSmartMemory(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		render.JSON(w, r, smartMemoryStatus{
			Timestamp: time.Now().UTC(), HeapAlloc: stats.HeapAlloc, HeapInuse: stats.HeapInuse,
			HeapIdle: stats.HeapIdle, HeapReleased: stats.HeapReleased, StackInuse: stats.StackInuse,
			Sys: stats.Sys, NumGC: stats.NumGC, Goroutines: runtime.NumGoroutine(),
			URLTestHistory: server.urlTestHistory.Status(),
		})
	}
}

func getSharedSmartHealthEntries(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		entries, initialized := group.SharedNodeHealthEntries(server.outbound, 0)
		render.JSON(w, r, render.M{
			"initialized": initialized,
			"entries":     entries,
		})
	}
}

func getSharedSmartHealthEvents(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		events, initialized := group.SharedNodeHealthEvents(server.outbound, 0)
		render.JSON(w, r, render.M{
			"initialized": initialized,
			"events":      events,
		})
	}
}

func getSharedSmartHealth(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		status, initialized := group.SharedNodeHealthStatus(server.outbound)
		render.JSON(w, r, render.M{
			"initialized":  initialized,
			"health_store": status,
		})
	}
}

func smartStatusSnapshot(outbounds []adapter.Outbound) map[string]adapter.SmartGroupStatus {
	groups := make(map[string]adapter.SmartGroupStatus)
	for _, outbound := range outbounds {
		if outbound == nil || outbound.Tag() == "" {
			continue
		}
		if smart, ok := outbound.(adapter.SmartGroup); ok {
			groups[outbound.Tag()] = smart.SmartStatus()
		}
	}
	return groups
}

func getSmartGroups(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		groups := smartStatusSnapshot(server.outbound.Outbounds())
		names := make([]string, 0, len(groups))
		for name := range groups {
			names = append(names, name)
		}
		sort.Strings(names)
		render.JSON(w, r, render.M{
			"groups": groups,
			"order":  names,
		})
	}
}

func getSmartGroupStatus(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		smart, ok := findSmartGroup(server, r)
		if !ok {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, ErrNotFound)
			return
		}
		render.JSON(w, r, smart.SmartStatus())
	}
}

func getSmartGroupEvents(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		smart, ok := findSmartGroup(server, r)
		if !ok {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, ErrNotFound)
			return
		}
		status := smart.SmartStatus()
		render.JSON(w, r, render.M{
			"health_revision":         status.HealthStore.Revision,
			"provider_generation":     status.ProviderGeneration,
			"provider_scope":          status.ProviderScope,
			"selected":                status.Selected,
			"selected_endpoint_id":    status.SelectedEndpointID,
			"pinned":                  status.Pinned,
			"pin_invalidation_reason": status.PinInvalidationReason,
			"pin_invalidated_at":      status.PinInvalidatedAt,
			"control_events":          status.RecentControlEvents,
			"dial_events":             status.RecentDialEvents,
			"switches":                status.RecentSwitches,
		})
	}
}

func findSmartGroup(server *Server, r *http.Request) (adapter.SmartGroup, bool) {
	name := getEscapeParam(r, "name")
	outbound, loaded := server.outbound.Outbound(name)
	if !loaded {
		return nil, false
	}
	smart, ok := outbound.(adapter.SmartGroup)
	return smart, ok
}

type smartRuntimeResponse struct {
	OwnerInstanceID   string                   `json:"owner_instance_id"`
	SelectionRevision uint64                   `json:"selection_revision"`
	Status            adapter.SmartGroupStatus `json:"status"`
}

type smartPinRequest struct {
	EndpointID        string `json:"endpoint_id"`
	OwnerInstanceID   string `json:"owner_instance_id"`
	SelectionRevision uint64 `json:"selection_revision"`
}

func smartRuntimeController(server *Server, r *http.Request) (adapter.SmartRuntimeController, bool) {
	smart, ok := findSmartGroup(server, r)
	if !ok {
		return nil, false
	}
	controller, ok := smart.(adapter.SmartRuntimeController)
	return controller, ok
}

func smartRuntimeJSON(controller adapter.SmartRuntimeController) smartRuntimeResponse {
	runtime := controller.SmartRuntimeStatus()
	return smartRuntimeResponse{
		OwnerInstanceID:   runtime.OwnerInstanceID,
		SelectionRevision: runtime.SelectionRevision,
		Status:            runtime.Status,
	}
}

func getSmartGroupRuntime(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		controller, ok := smartRuntimeController(server, r)
		if !ok {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, ErrNotFound)
			return
		}
		render.JSON(w, r, smartRuntimeJSON(controller))
	}
}

func pinSmartGroup(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		controller, ok := smartRuntimeController(server, r)
		if !ok {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, ErrNotFound)
			return
		}
		var request smartPinRequest
		if err := render.DecodeJSON(r.Body, &request); err != nil || request.EndpointID == "" || request.OwnerInstanceID == "" {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
		if _, updated := controller.SmartSetPinnedEndpoint(request.EndpointID, request.OwnerInstanceID, request.SelectionRevision); !updated {
			render.Status(r, http.StatusConflict)
			render.JSON(w, r, smartRuntimeJSON(controller))
			return
		}
		render.JSON(w, r, smartRuntimeJSON(controller))
	}
}

func restoreSmartGroupAutomatic(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		controller, ok := smartRuntimeController(server, r)
		if !ok {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, ErrNotFound)
			return
		}
		var request smartPinRequest
		if err := render.DecodeJSON(r.Body, &request); err != nil || request.OwnerInstanceID == "" {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
		if _, updated := controller.SmartRestoreAutomatic(request.OwnerInstanceID, request.SelectionRevision); !updated {
			render.Status(r, http.StatusConflict)
			render.JSON(w, r, smartRuntimeJSON(controller))
			return
		}
		render.JSON(w, r, smartRuntimeJSON(controller))
	}
}

func requestSmartGroupProbe(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		smart, ok := findSmartGroup(server, r)
		if !ok {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, ErrNotFound)
			return
		}
		// This deliberately queues Smart's dashboard probe path. It records
		// advisory health evidence but never directly commits a new selection;
		// live traffic remains the only path that advances the data-plane
		// choice.
		smart.PerformUpdateCheck()
		render.JSON(w, r, render.M{
			"accepted": true,
			"status":   smart.SmartStatus(),
		})
	}
}
