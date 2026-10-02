package clashapi

import (
	"context"
	"net/http"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/json/badjson"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func proxyProviderRouter(server *Server) http.Handler {
	r := chi.NewRouter()
	r.Get("/", getProviders(server))

	r.Route("/{name}", func(r chi.Router) {
		r.Use(parseProviderName, findProviderByName(server))
		r.Get("/", getProvider(server))
		r.Put("/", updateProvider)
		r.Patch("/", patchProvider)
		r.Delete("/", deleteProvider(server))
		r.Get("/healthcheck", healthCheckProvider)
		r.Route("/{proxyName}", func(r chi.Router) {
			r.Use(parseProviderProxyName, findProviderProxyByName)
			r.Get("/healthcheck", getProxyDelay(server))
		})
	})
	return r
}

func getProviders(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		providerMap := make(render.M)
		if server.provider == nil {
			render.JSON(w, r, render.M{"providers": providerMap})
			return
		}
		for _, provider := range server.provider.Providers() {
			providerMap[provider.Tag()] = providerInfo(server, provider)
		}
		render.JSON(w, r, render.M{
			"providers": providerMap,
		})
	}
}

func getProvider(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		provider := r.Context().Value(CtxKeyProvider).(adapter.Provider)
		render.JSON(w, r, providerInfo(server, provider))
	}
}

func providerInfo(server *Server, p adapter.Provider) *badjson.JSONObject {
	var info badjson.JSONObject
	proxies := make([]*badjson.JSONObject, 0)
	for _, detour := range p.Outbounds() {
		proxies = append(proxies, proxyInfo(server, detour))
	}
	info.Put("type", "Proxy")                                // Proxy, Rule
	info.Put("vehicleType", C.ProviderDisplayName(p.Type())) // HTTP, File, Compatible
	info.Put("name", p.Tag())
	info.Put("proxies", proxies)
	info.Put("updatedAt", p.UpdatedAt())
	if controller, ok := p.(adapter.ProviderLifecycleController); ok {
		info.Put("paused", controller.ProviderPaused())
		info.Put("consumers", controller.ProviderConsumers())
		info.Put("supportsPause", true)
	} else {
		info.Put("paused", false)
		info.Put("consumers", 0)
		info.Put("supportsPause", false)
	}
	if p, ok := p.(adapter.ProviderSubscriptionInfo); ok {
		info.Put("subscriptionInfo", p.SubscriptionInfo())
	}
	return &info
}

type providerPatchRequest struct {
	Paused *bool `json:"paused"`
}

func patchProvider(w http.ResponseWriter, r *http.Request) {
	provider := r.Context().Value(CtxKeyProvider).(adapter.Provider)
	controller, supported := provider.(adapter.ProviderLifecycleController)
	if !supported {
		render.Status(r, http.StatusNotImplemented)
		render.JSON(w, r, newError("provider does not support runtime pause"))
		return
	}
	var request providerPatchRequest
	if err := render.DecodeJSON(r.Body, &request); err != nil || request.Paused == nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("paused is required"))
		return
	}
	controller.SetProviderPaused(*request.Paused)
	render.NoContent(w, r)
}

func deleteProvider(server *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		provider := r.Context().Value(CtxKeyProvider).(adapter.Provider)
		controller, controllable := provider.(adapter.ProviderLifecycleController)
		if r.URL.Query().Get("permanent") != "true" {
			if !controllable {
				render.Status(r, http.StatusNotImplemented)
				render.JSON(w, r, newError("provider does not support recoverable deletion"))
				return
			}
			controller.SetProviderPaused(true)
			render.NoContent(w, r)
			return
		}
		if controllable && controller.ProviderConsumers() > 0 {
			render.Status(r, http.StatusConflict)
			render.JSON(w, r, newError("provider is still referenced by runtime consumers; pause it or remove those references first"))
			return
		}
		if err := server.provider.Remove(provider.Tag()); err != nil {
			render.Status(r, http.StatusServiceUnavailable)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		render.NoContent(w, r)
	}
}

func updateProvider(w http.ResponseWriter, r *http.Request) {
	provider := r.Context().Value(CtxKeyProvider).(adapter.Provider)
	if provider, isUpdater := provider.(adapter.ProviderUpdater); isUpdater {
		if err := provider.Update(); err != nil {
			render.Status(r, http.StatusServiceUnavailable)
			render.JSON(w, r, newError(err.Error()))
			return
		}
	}
	render.NoContent(w, r)
}

func healthCheckProvider(w http.ResponseWriter, r *http.Request) {
	provider := r.Context().Value(CtxKeyProvider).(adapter.Provider)
	provider.HealthCheck(r.Context())
	render.NoContent(w, r)
}

func parseProviderName(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := getEscapeParam(r, "name")
		ctx := context.WithValue(r.Context(), CtxKeyProviderName, name)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func findProviderByName(server *Server) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			name := r.Context().Value(CtxKeyProviderName).(string)
			if server.provider == nil {
				render.Status(r, http.StatusNotFound)
				render.JSON(w, r, ErrNotFound)
				return
			}
			provider, exist := server.provider.Get(name)
			if !exist {
				render.Status(r, http.StatusNotFound)
				render.JSON(w, r, ErrNotFound)
				return
			}

			ctx := context.WithValue(r.Context(), CtxKeyProvider, provider)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func parseProviderProxyName(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := getEscapeParam(r, "proxyName")
		ctx := context.WithValue(r.Context(), CtxKeyProxyName, name)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func findProviderProxyByName(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.Context().Value(CtxKeyProxyName).(string)
		provider := r.Context().Value(CtxKeyProvider).(adapter.Provider)
		proxy, exist := provider.Outbound(name)
		if !exist {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, ErrNotFound)
			return
		}

		ctx := context.WithValue(r.Context(), CtxKeyProxy, proxy)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
