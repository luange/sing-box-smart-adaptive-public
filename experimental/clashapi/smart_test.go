package clashapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type smartStatusTestGroup struct {
	outbound.Adapter
	status     adapter.SmartGroupStatus
	ownerID    string
	revision   uint64
	probeCalls int
}

type smartStatusTestOutbound struct{ outbound.Adapter }

type smartStatusTestManager struct {
	adapter.OutboundManager
	outbounds []adapter.Outbound
}

func (m *smartStatusTestManager) Outbounds() []adapter.Outbound {
	return append([]adapter.Outbound(nil), m.outbounds...)
}

func (m *smartStatusTestManager) Outbound(tag string) (adapter.Outbound, bool) {
	for _, outbound := range m.outbounds {
		if outbound.Tag() == tag {
			return outbound, true
		}
	}
	return nil, false
}

func (*smartStatusTestOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (*smartStatusTestOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

func (g *smartStatusTestGroup) Now() string { return g.status.Selected }

func (g *smartStatusTestGroup) All() []string { return nil }

func (*smartStatusTestGroup) Selected(string) adapter.Outbound { return nil }

func (*smartStatusTestGroup) AttachConnection(io.Closer) func() { return func() {} }

func (*smartStatusTestGroup) URLTest(context.Context) (map[string]uint16, error) { return nil, nil }

func (g *smartStatusTestGroup) PerformUpdateCheck() { g.probeCalls++ }

func (g *smartStatusTestGroup) SmartStatus() adapter.SmartGroupStatus { return g.status }

func (*smartStatusTestGroup) SelectOutbound(string) bool { return false }

func (*smartStatusTestGroup) ClearSelection() {}

func (*smartStatusTestGroup) SelectTemporaryOutbound(string, time.Duration, string) bool {
	return false
}

func (*smartStatusTestGroup) ClearTemporarySelection() {}

func (g *smartStatusTestGroup) SmartRuntimeStatus() adapter.SmartRuntimeStatus {
	return adapter.SmartRuntimeStatus{OwnerInstanceID: g.ownerID, SelectionRevision: g.revision, Status: g.status}
}

func (*smartStatusTestGroup) SmartEndpointIdentity(string) (string, bool) {
	return "endpoint:test", true
}

func (g *smartStatusTestGroup) SmartEndpointSnapshot(string) (adapter.SmartRuntimeStatus, string, bool) {
	return g.SmartRuntimeStatus(), "endpoint:test", true
}

func (g *smartStatusTestGroup) SmartSetPinnedEndpoint(endpointID, ownerID string, revision uint64) (uint64, bool) {
	if endpointID == "" || ownerID != g.ownerID || revision != g.revision {
		return g.revision, false
	}
	g.revision++
	return g.revision, true
}

func (g *smartStatusTestGroup) SmartRestoreAutomatic(ownerID string, revision uint64) (uint64, bool) {
	if ownerID != g.ownerID || revision != g.revision {
		return g.revision, false
	}
	g.revision++
	return g.revision, true
}

func (*smartStatusTestGroup) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (*smartStatusTestGroup) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

func TestSmartStatusSnapshotOnlyReturnsSmartGroups(t *testing.T) {
	smart := &smartStatusTestGroup{
		Adapter: outbound.NewAdapter(C.TypeSmart, "US", []string{N.NetworkTCP}, nil),
		status:  adapter.SmartGroupStatus{Selected: "node-a", HealthStore: adapter.SmartHealthStoreStatus{Revision: 7}},
	}
	direct := &smartStatusTestOutbound{Adapter: outbound.NewAdapter(C.TypeDirect, "direct", []string{N.NetworkTCP}, nil)}
	groups := smartStatusSnapshot([]adapter.Outbound{smart, direct})
	if len(groups) != 1 || groups["US"].Selected != "node-a" || groups["US"].HealthStore.Revision != 7 {
		t.Fatalf("unexpected smart snapshot: %#v", groups)
	}
}

func TestSmartRuntimeResponseKeepsCASIdentitySeparateFromStatus(t *testing.T) {
	smart := &smartStatusTestGroup{ownerID: "instance-a", revision: 9, status: adapter.SmartGroupStatus{SelectionGeneration: 4}}
	response := smartRuntimeJSON(smart)
	if response.OwnerInstanceID != "instance-a" || response.SelectionRevision != 9 || response.Status.SelectionGeneration != 4 {
		t.Fatalf("unexpected Smart runtime response: %+v", response)
	}
}

func TestSmartHTTPControlsUseCASAndProbeIsAdvisory(t *testing.T) {
	smart := &smartStatusTestGroup{
		Adapter:  outbound.NewAdapter(C.TypeSmart, "US", []string{N.NetworkTCP}, nil),
		ownerID:  "instance-a",
		revision: 7,
		status:   adapter.SmartGroupStatus{Selected: "node-a"},
	}
	server := &Server{outbound: &smartStatusTestManager{outbounds: []adapter.Outbound{smart}}}
	router := smartRouter(server)

	runtimeRequest := httptest.NewRequest(http.MethodGet, "/US/runtime", nil)
	runtimeResponse := httptest.NewRecorder()
	router.ServeHTTP(runtimeResponse, runtimeRequest)
	if runtimeResponse.Code != http.StatusOK {
		t.Fatalf("runtime status=%d body=%s", runtimeResponse.Code, runtimeResponse.Body.String())
	}
	var runtime smartRuntimeResponse
	if err := json.Unmarshal(runtimeResponse.Body.Bytes(), &runtime); err != nil {
		t.Fatal(err)
	}
	if runtime.OwnerInstanceID != "instance-a" || runtime.SelectionRevision != 7 {
		t.Fatalf("unexpected runtime payload: %+v", runtime)
	}

	payload, err := json.Marshal(smartPinRequest{EndpointID: "endpoint:test", OwnerInstanceID: runtime.OwnerInstanceID, SelectionRevision: runtime.SelectionRevision})
	if err != nil {
		t.Fatal(err)
	}
	pinRequest := httptest.NewRequest(http.MethodPost, "/US/pin", bytes.NewReader(payload))
	pinResponse := httptest.NewRecorder()
	router.ServeHTTP(pinResponse, pinRequest)
	if pinResponse.Code != http.StatusOK || smart.revision != 8 {
		t.Fatalf("pin status=%d revision=%d body=%s", pinResponse.Code, smart.revision, pinResponse.Body.String())
	}

	// The same stale form submission must not overwrite the newer control state.
	staleRequest := httptest.NewRequest(http.MethodPost, "/US/pin", bytes.NewReader(payload))
	staleResponse := httptest.NewRecorder()
	router.ServeHTTP(staleResponse, staleRequest)
	if staleResponse.Code != http.StatusConflict || smart.revision != 8 {
		t.Fatalf("stale pin was accepted: status=%d revision=%d", staleResponse.Code, smart.revision)
	}

	probeRequest := httptest.NewRequest(http.MethodPost, "/US/probe", nil)
	probeResponse := httptest.NewRecorder()
	router.ServeHTTP(probeResponse, probeRequest)
	if probeResponse.Code != http.StatusOK || smart.probeCalls != 1 || smart.status.Selected != "node-a" {
		t.Fatalf("probe changed control state: status=%d calls=%d selected=%q", probeResponse.Code, smart.probeCalls, smart.status.Selected)
	}
}

func TestSmartEventsExposeTheSameCandidateScopeAsStatus(t *testing.T) {
	smart := &smartStatusTestGroup{
		Adapter: outbound.NewAdapter(C.TypeSmart, "GLOBAL", []string{N.NetworkTCP}, nil),
		status: adapter.SmartGroupStatus{
			ProviderGeneration:    11,
			ProviderScope:         "all_providers",
			HealthStore:           adapter.SmartHealthStoreStatus{Revision: 5},
			Selected:              "node-a",
			SelectedEndpointID:    "endpoint:node-a",
			PinInvalidationReason: "provider_refresh",
			RecentControlEvents: []adapter.SmartControlEvent{{
				Type:               "provider_catalog_updated",
				ProviderTag:        "airport",
				ProviderGeneration: 11,
			}},
		},
	}
	server := &Server{outbound: &smartStatusTestManager{outbounds: []adapter.Outbound{smart}}}
	response := httptest.NewRecorder()
	smartRouter(server).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/GLOBAL/events", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("events status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		ProviderScope         string                      `json:"provider_scope"`
		ProviderGeneration    uint64                      `json:"provider_generation"`
		HealthRevision        uint64                      `json:"health_revision"`
		Selected              string                      `json:"selected"`
		SelectedEndpointID    string                      `json:"selected_endpoint_id"`
		Pinned                string                      `json:"pinned"`
		PinInvalidationReason string                      `json:"pin_invalidation_reason"`
		ControlEvents         []adapter.SmartControlEvent `json:"control_events"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.ProviderScope != "all_providers" || payload.ProviderGeneration != 11 || payload.HealthRevision != 5 || payload.Selected != "node-a" || payload.SelectedEndpointID != "endpoint:node-a" || payload.Pinned != "" || payload.PinInvalidationReason != "provider_refresh" {
		t.Fatalf("unexpected event metadata: %+v", payload)
	}
	if len(payload.ControlEvents) != 1 || payload.ControlEvents[0].Type != "provider_catalog_updated" || payload.ControlEvents[0].ProviderTag != "airport" {
		t.Fatalf("unexpected control events: %+v", payload.ControlEvents)
	}
}

func TestSharedSmartHealthEndpointReportsInitializationState(t *testing.T) {
	server := &Server{outbound: &smartStatusTestManager{}}
	response := httptest.NewRecorder()
	smartRouter(server).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("health status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Initialized bool `json:"initialized"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Initialized {
		t.Fatal("health endpoint reported an uncreated store as initialized")
	}
}
