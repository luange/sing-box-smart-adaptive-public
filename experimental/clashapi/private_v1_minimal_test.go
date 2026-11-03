package clashapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	N "github.com/sagernet/sing/common/network"
)

func TestPrivateV1MinimalContractKeepsInstanceIdentity(t *testing.T) {
	server := &Server{startedAt: time.Now().UTC(), processInstanceID: newPrivateProcessInstanceID()}
	capabilityResponse := httptest.NewRecorder()
	privateV1Capabilities(server).ServeHTTP(capabilityResponse, httptest.NewRequest(http.MethodGet, "/private/v1/capabilities", nil))
	if capabilityResponse.Code != http.StatusOK {
		t.Fatalf("capabilities status = %d", capabilityResponse.Code)
	}
	var capability struct {
		APIVersion struct {
			Major int `json:"major"`
			Minor int `json:"minor"`
		} `json:"api_version"`
		ProcessInstanceID string `json:"process_instance_id"`
		Features          map[string]struct {
			Supported     bool `json:"supported"`
			SchemaVersion int  `json:"schema_version"`
		} `json:"features"`
	}
	if err := json.Unmarshal(capabilityResponse.Body.Bytes(), &capability); err != nil {
		t.Fatal(err)
	}
	if capability.APIVersion.Major != 1 || capability.APIVersion.Minor < 11 || capability.ProcessInstanceID != server.processInstanceID || !capability.Features["runtime.telemetry"].Supported || capability.Features["runtime.telemetry"].SchemaVersion != 1 {
		t.Fatalf("invalid capability contract: %#v", capability)
	}
	runtimeResponse := httptest.NewRecorder()
	privateV1RuntimeTelemetry(server).ServeHTTP(runtimeResponse, httptest.NewRequest(http.MethodGet, "/private/v1/runtime/telemetry", nil))
	if runtimeResponse.Code != http.StatusOK {
		t.Fatalf("runtime status = %d", runtimeResponse.Code)
	}
	var runtime struct {
		SchemaVersion     int    `json:"schema_version"`
		ProcessInstanceID string `json:"process_instance_id"`
		ProcessID         int    `json:"process_id"`
		Runtime           struct {
			HeapAlloc uint64 `json:"heap_alloc_bytes"`
			HeapInuse uint64 `json:"heap_inuse_bytes"`
			HeapSys   uint64 `json:"heap_sys_bytes"`
		} `json:"runtime"`
	}
	if err := json.Unmarshal(runtimeResponse.Body.Bytes(), &runtime); err != nil {
		t.Fatal(err)
	}
	if runtime.SchemaVersion != 1 || runtime.ProcessInstanceID != capability.ProcessInstanceID || runtime.ProcessID <= 0 || runtime.Runtime.HeapAlloc > runtime.Runtime.HeapInuse || runtime.Runtime.HeapInuse > runtime.Runtime.HeapSys {
		t.Fatalf("invalid runtime contract: %#v", runtime)
	}
}

func TestPrivateV1SmartPinUsesCASAndIdempotency(t *testing.T) {
	ownerID := "0123456789abcdef0123456789abcdef"
	smart := &smartStatusTestGroup{
		Adapter:  outbound.NewAdapter(C.TypeSmart, "US", []string{N.NetworkTCP}, nil),
		ownerID:  ownerID,
		revision: 7,
		status:   adapter.SmartGroupStatus{RecentDialEvents: []adapter.SmartDialDiagnostic{}},
	}
	server := &Server{startedAt: time.Now().UTC(), processInstanceID: newPrivateProcessInstanceID(), outbound: &smartStatusTestManager{outbounds: []adapter.Outbound{smart}}, privateSmartCache: make(map[string]privateV1SmartMutationCache)}
	router := privateV1Router(server)
	groupID := privateV1SmartGroupID("US")
	payload := func(revision uint64, endpointID string) []byte {
		value, err := json.Marshal(privateV1SmartPinRequest{CoreRevision: privateV1CoreRevision(), ProcessInstanceID: server.processInstanceID, OwnerInstanceID: ownerID, ExpectedSelectionRevision: revision, EndpointID: endpointID})
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	request := func(key string, body []byte) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/smart/groups/"+groupID+"/pin", bytes.NewReader(body))
		req.Header.Set("Idempotency-Key", key)
		router.ServeHTTP(recorder, req)
		return recorder
	}
	key := "0123456789abcdef0123456789abcdef"
	first := request(key, payload(7, "endpoint:test"))
	if first.Code != http.StatusOK || smart.revision != 8 {
		t.Fatalf("first pin status=%d revision=%d body=%s", first.Code, smart.revision, first.Body.String())
	}
	second := request(key, payload(7, "endpoint:test"))
	if second.Code != http.StatusOK || second.Body.String() != first.Body.String() || smart.revision != 8 {
		t.Fatalf("idempotent retry status=%d revision=%d body=%s", second.Code, smart.revision, second.Body.String())
	}
	conflict := request(key, payload(7, "endpoint:other"))
	if conflict.Code != http.StatusConflict || smart.revision != 8 {
		t.Fatalf("reused key status=%d revision=%d body=%s", conflict.Code, smart.revision, conflict.Body.String())
	}
	restorePayload, err := json.Marshal(privateV1SmartPinRequest{CoreRevision: privateV1CoreRevision(), ProcessInstanceID: server.processInstanceID, OwnerInstanceID: ownerID, ExpectedSelectionRevision: 8})
	if err != nil {
		t.Fatal(err)
	}
	restore := httptest.NewRecorder()
	restoreRequest := httptest.NewRequest(http.MethodDelete, "/smart/groups/"+groupID+"/pin", bytes.NewReader(restorePayload))
	restoreRequest.Header.Set("Idempotency-Key", "abcdef0123456789abcdef0123456789")
	router.ServeHTTP(restore, restoreRequest)
	if restore.Code != http.StatusOK || smart.revision != 9 {
		t.Fatalf("restore status=%d revision=%d body=%s", restore.Code, smart.revision, restore.Body.String())
	}
}

func TestPrivateV1SmartStatusIsReadOnlyProjection(t *testing.T) {
	ownerID := "0123456789abcdef0123456789abcdef"
	smart := &smartStatusTestGroup{
		Adapter:  outbound.NewAdapter(C.TypeSmart, "US", []string{N.NetworkTCP}, nil),
		ownerID:  ownerID,
		revision: 7,
		status: adapter.SmartGroupStatus{
			Selected: "node-a", SelectedEndpointID: "endpoint:node-a", ActualDialEndpointID: "endpoint:node-a",
			RecentDialEvents: []adapter.SmartDialDiagnostic{},
		},
	}
	server := &Server{startedAt: time.Now().UTC(), processInstanceID: newPrivateProcessInstanceID(), outbound: &smartStatusTestManager{outbounds: []adapter.Outbound{smart}}}
	response := httptest.NewRecorder()
	privateV1SmartStatus(server).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/private/v1/smart/status", nil))
	if response.Code != http.StatusOK || smart.probeCalls != 0 {
		t.Fatalf("status=%d probeCalls=%d", response.Code, smart.probeCalls)
	}
	var result struct {
		SchemaVersion int `json:"schema_version"`
		Groups        []struct {
			GroupID string `json:"group_id"`
			Tag     string `json:"tag"`
			Status  struct {
				OwnerInstanceID   string            `json:"owner_instance_id"`
				SelectionRevision uint64            `json:"selection_revision"`
				RecentDialEvents  []json.RawMessage `json:"recent_dial_events"`
			} `json:"status"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.SchemaVersion != 3 || len(result.Groups) != 1 || result.Groups[0].Tag != "US" || result.Groups[0].GroupID != privateV1SmartGroupID("US") || result.Groups[0].Status.OwnerInstanceID != ownerID || result.Groups[0].Status.SelectionRevision != 7 || result.Groups[0].Status.RecentDialEvents == nil {
		t.Fatalf("invalid Smart projection: %#v", result)
	}
}
