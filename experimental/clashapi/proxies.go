package clashapi

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing/common"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json/badjson"
	N "github.com/sagernet/sing/common/network"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func proxyRouter(server *Server, router adapter.Router) http.Handler {
	r := chi.NewRouter()
	r.Get("/", getProxies(server))

	r.Route("/{name}", func(r chi.Router) {
		r.Use(parseProxyName, findProxyByName(server))
		r.Get("/", getProxy(server))
		r.Get("/delay", getProxyDelay(server))
		r.Put("/", updateProxy)
	})
	return r
}

func parseProxyName(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := getEscapeParam(r, "name")
		ctx := context.WithValue(r.Context(), CtxKeyProxyName, name)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func findProxyByName(server *Server) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			name := r.Context().Value(CtxKeyProxyName).(string)
			proxy, exist := server.outbound.Outbound(name)
			if !exist {
				render.Status(r, http.StatusNotFound)
				render.JSON(w, r, ErrNotFound)
				return
			}
			ctx := context.WithValue(r.Context(), CtxKeyProxy, proxy)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func proxyInfo(server *Server, detour adapter.Outbound) *badjson.JSONObject {
	var info badjson.JSONObject
	var clashType string
	switch detour.Type() {
	case C.TypeBlock:
		clashType = "Reject"
	default:
		clashType = C.ProxyDisplayName(detour.Type())
	}
	info.Put("type", clashType)
	info.Put("name", detour.Tag())
	info.Put("udp", common.Contains(detour.Network(), N.NetworkUDP))
	realTag := group.RealTag(server.outbound, detour)
	leaf, loaded := server.outbound.Outbound(realTag)
	if !loaded {
		leaf = detour
	}
	delayHistory := server.urlTestHistory.LoadLatestURLTestHistoryForOutbound(leaf, N.NetworkTCP)
	if delayHistory != nil {
		info.Put("history", []*adapter.URLTestHistory{delayHistory})
	} else {
		info.Put("history", []*adapter.URLTestHistory{})
	}
	if group, isGroup := detour.(adapter.OutboundGroup); isGroup {
		info.Put("now", group.Now())
		info.Put("all", group.All())
	}
	if smartGroup, isSmart := detour.(adapter.SmartGroup); isSmart {
		status := smartGroup.SmartStatus()
		// Keep the standard Clash schema consumable by dashboards that do not
		// know the Smart extension. Smart-aware clients detect smart_mode/smart
		// and can render richer semantics without requiring a second API.
		info.Put("type", "Selector")
		info.Put("all", append([]string{"♻️ 智能选择"}, smartGroup.All()...))
		if status.TemporaryOverride != "" {
			info.Put("now", status.TemporaryOverride)
			info.Put("fixed", status.TemporaryOverride)
			info.Put("smart_mode", "temporary")
		} else if status.Pinned != "" {
			info.Put("now", status.Pinned)
			info.Put("fixed", status.Pinned)
			info.Put("smart_mode", "pinned")
		} else if status.Selected != "" {
			info.Put("now", status.Selected)
			info.Put("smart_mode", "auto")
		} else {
			info.Put("now", "♻️ 智能选择")
			info.Put("smart_mode", "warming")
		}
		info.Put("smart", status)
	}
	if adaptiveGroup, isAdaptive := detour.(adapter.AdaptivePoolGroup); isAdaptive {
		status := adaptiveGroup.AdaptiveStatus()
		info.Put("type", "Selector")
		info.Put("all", append([]string{"♻️ 智能选择"}, adaptiveGroup.All()...))
		if status.Shadow {
			info.Put("now", "shadow")
		} else if status.Pinned != "" {
			info.Put("now", status.Pinned)
		} else {
			info.Put("now", "♻️ 智能选择")
		}
		info.Put("adaptive_pool", status)
		info.Put("adaptive_generation", status.Generation)
		info.Put("adaptive_control_revision", status.ControlRevision)
		info.Put("adaptive_mode", status.Mode)
		info.Put("adaptive_active_leases", status.ActiveLeases)
		info.Put("adaptive_probe_queue", status.ProbeQueueDepth)
		info.Put("adaptive_candidates", status.Candidates)
	}
	return &info
}

func getProxies(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var proxyMap badjson.JSONObject
		outbounds := common.Filter(server.outbound.Outbounds(), func(detour adapter.Outbound) bool {
			return detour.Tag() != ""
		})
		outbounds = append(outbounds, common.Map(common.Filter(server.endpoint.Endpoints(), func(detour adapter.Endpoint) bool {
			return detour.Tag() != ""
		}), func(it adapter.Endpoint) adapter.Outbound {
			return it
		})...)

		allProxies := make([]string, 0, len(outbounds))

		for _, detour := range outbounds {
			switch detour.Type() {
			case C.TypeDirect, C.TypeBlock, C.TypeDNS:
				continue
			}
			allProxies = append(allProxies, detour.Tag())
		}

		defaultTag := server.outbound.Default().Tag()

		sort.SliceStable(allProxies, func(i, j int) bool {
			return allProxies[i] == defaultTag
		})

		// fix clash dashboard
		proxyMap.Put("GLOBAL", map[string]any{
			"type":    "Fallback",
			"name":    "GLOBAL",
			"udp":     true,
			"history": []*adapter.URLTestHistory{},
			"all":     allProxies,
			"now":     defaultTag,
		})

		for i, detour := range outbounds {
			var tag string
			if detour.Tag() == "" {
				tag = F.ToString(i)
			} else {
				tag = detour.Tag()
			}
			proxyMap.Put(tag, proxyInfo(server, detour))
		}
		var responseMap badjson.JSONObject
		responseMap.Put("proxies", &proxyMap)
		response, err := responseMap.MarshalJSON()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		w.Write(response)
	}
}

func getProxy(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		proxy := r.Context().Value(CtxKeyProxy).(adapter.Outbound)
		response, err := proxyInfo(server, proxy).MarshalJSON()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		w.Write(response)
	}
}

type UpdateProxyRequest struct {
	Name       string  `json:"name"`
	Temporary  *bool   `json:"temporary,omitempty"`
	TTL        int64   `json:"ttl,omitempty"`
	Persistent bool    `json:"persistent,omitempty"`
	Reason     string  `json:"reason,omitempty"`
	Revision   *uint64 `json:"revision,omitempty"`
}

func updateProxy(w http.ResponseWriter, r *http.Request) {
	req := UpdateProxyRequest{}
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	proxy := r.Context().Value(CtxKeyProxy).(adapter.Outbound)
	if selector, isSelector := proxy.(*group.Selector); isSelector {
		if !selector.SelectOutbound(req.Name) {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("Selector update error: not found"))
			return
		}
	} else if smartGroup, isSmart := proxy.(adapter.SmartGroup); isSmart {
		if req.Name == "" || req.Name == "♻️ 智能选择" {
			smartGroup.ClearTemporarySelection()
			smartGroup.ClearSelection()
		} else if !useTemporarySmartOverride(req) {
			smartGroup.ClearTemporarySelection()
			if !smartGroup.SelectOutbound(req.Name) {
				render.Status(r, http.StatusBadRequest)
				render.JSON(w, r, newError("Smart pin error: candidate not found"))
				return
			}
		} else {
			ttl := req.TTL
			if ttl <= 0 {
				ttl = 1800
			}
			ttl = min(max(ttl, 60), 86400)
			smartGroup.ClearSelection()
			if !smartGroup.SelectTemporaryOutbound(req.Name, time.Duration(ttl)*time.Second, req.Reason) {
				render.Status(r, http.StatusBadRequest)
				render.JSON(w, r, newError("Smart override error: candidate not found"))
				return
			}
		}
	} else if adaptiveGroup, isAdaptive := proxy.(adapter.AdaptivePoolGroup); isAdaptive {
		revisioned, hasRevision := adaptiveGroup.(adapter.AdaptivePoolRevisioned)
		if req.Revision != nil && (!hasRevision || revisioned.AdaptiveSelectionRevision() != *req.Revision) {
			render.Status(r, http.StatusConflict)
			render.JSON(w, r, newError("adaptive selection revision conflict"))
			return
		}
		if req.Name == "" || req.Name == "♻️ 智能选择" {
			if hasRevision && req.Revision != nil {
				if !revisioned.ClearAdaptiveSelectionAt(*req.Revision) {
					render.Status(r, http.StatusConflict)
					render.JSON(w, r, newError("adaptive selection revision conflict"))
					return
				}
			} else {
				adaptiveGroup.ClearAdaptiveSelection()
			}
		} else if hasRevision && req.Revision != nil {
			if !revisioned.SelectAdaptiveOutboundAt(req.Name, *req.Revision) {
				render.Status(r, http.StatusConflict)
				render.JSON(w, r, newError("Adaptive pin error: candidate not found"))
				return
			}
		} else if !adaptiveGroup.SelectAdaptiveOutbound(req.Name) {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("Adaptive pin error: candidate not found"))
			return
		}
	} else {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("Must be a Selector, Smart, or AdaptivePool group"))
		return
	}

	render.NoContent(w, r)
}

func useTemporarySmartOverride(request UpdateProxyRequest) bool {
	return request.Temporary != nil && *request.Temporary && !request.Persistent
}

func getProxyDelay(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		url := query.Get("url")
		if strings.HasPrefix(url, "http://") {
			url = ""
		}
		timeout, err := strconv.ParseInt(query.Get("timeout"), 10, 16)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}

		proxy := r.Context().Value(CtxKeyProxy).(adapter.Outbound)
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*time.Duration(timeout))
		defer cancel()
		// A delay request for Smart is observational.  Carry the dashboard
		// marker through its DialContext path so a panel ping cannot be mistaken
		// for real traffic and replace a healthy incumbent or manual pin.
		if _, isSmart := proxy.(adapter.SmartGroup); isSmart {
			ctx = adapter.WithDashboardProbe(ctx)
		}

		delay, err := urltest.URLTest(ctx, url, proxy)
		defer func() {
			realTag := group.RealTag(server.outbound, proxy)
			leaf, loaded := server.outbound.Outbound(realTag)
			if !loaded {
				leaf = proxy
			}
			key := urltest.KeyForOutbound(leaf, url, N.NetworkTCP)
			if err != nil {
				server.urlTestHistory.DeleteURLTestHistoryKey(key)
			} else {
				server.urlTestHistory.StoreURLTestHistoryKey(key, &adapter.URLTestHistory{
					Time:  time.Now(),
					Delay: delay,
				})
			}
			for _, detour := range server.outbound.Outbounds() {
				urlTestGroup, isURLTestGroup := detour.(adapter.URLTestGroup)
				if !isURLTestGroup {
					continue
				}
				if !groupContains(server.outbound, urlTestGroup, realTag, map[string]bool{detour.Tag(): true}) {
					continue
				}
				urlTestGroup.PerformUpdateCheck()
			}
		}()

		if ctx.Err() != nil {
			render.Status(r, http.StatusGatewayTimeout)
			render.JSON(w, r, ErrRequestTimeout)
			return
		}

		if err != nil || delay == 0 {
			render.Status(r, http.StatusServiceUnavailable)
			render.JSON(w, r, newError("An error occurred in the delay test"))
			return
		}

		render.JSON(w, r, render.M{
			"delay": delay,
		})
	}
}

// groupContains follows nested outbound groups without recursing through the
// same group twice. Manual delay tests use it to wake every affected URL-test
// group while keeping the Clash API handler independent of group internals.
func groupContains(outboundManager adapter.OutboundManager, outboundGroup adapter.OutboundGroup, tag string, visited map[string]bool) bool {
	for _, memberTag := range outboundGroup.All() {
		if memberTag == tag {
			return true
		}
		member, loaded := outboundManager.Outbound(memberTag)
		if !loaded {
			continue
		}
		if group.RealTag(outboundManager, member) == tag {
			return true
		}
		memberGroup, isGroup := member.(adapter.OutboundGroup)
		if !isGroup || visited[memberTag] {
			continue
		}
		visited[memberTag] = true
		if groupContains(outboundManager, memberGroup, tag, visited) {
			return true
		}
	}
	return false
}
