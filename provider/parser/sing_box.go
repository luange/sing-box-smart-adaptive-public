package parser

import (
	"context"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/service"
)

// SingBoxDocument is intentionally decoded member-by-member. A provider is a
// best-effort collection: one stale, unsupported, or malformed node must not
// make all valid nodes disappear during a refresh.
type _SingBoxDocument struct {
	Outbounds []option.Outbound `json:"outbounds"`
	Endpoints []option.Endpoint `json:"endpoints"`
}
type SingBoxDocument _SingBoxDocument

func (o *SingBoxDocument) UnmarshalJSONContext(ctx context.Context, inputContent []byte) error {
	var content badjson.JSONObject
	if err := content.UnmarshalJSONContext(ctx, inputContent); err != nil {
		return err
	}

	var result SingBoxDocument
	if raw, ok := content.Get("outbounds"); ok {
		array, ok := raw.(badjson.JSONArray)
		if !ok {
			warnIgnoredProviderMember(providerTagFromContext(ctx), "outbounds", 0, "", "", E.New("expected array"))
		} else {
			for index, item := range array {
				parsed, keep := parseBoxOutbound(ctx, item, index)
				if keep {
					result.Outbounds = append(result.Outbounds, parsed)
				}
			}
		}
	}
	if raw, ok := content.Get("endpoints"); ok {
		array, ok := raw.(badjson.JSONArray)
		if !ok {
			warnIgnoredProviderMember(providerTagFromContext(ctx), "endpoints", 0, "", "", E.New("expected array"))
		} else {
			for index, item := range array {
				parsed, keep := parseBoxEndpoint(ctx, item, index)
				if keep {
					result.Endpoints = append(result.Endpoints, parsed)
				}
			}
		}
	}
	if len(result.Outbounds) == 0 && len(result.Endpoints) == 0 {
		return E.New("no supported servers found")
	}
	*o = result
	return nil
}

func parseBoxOutbound(ctx context.Context, item any, index int) (option.Outbound, bool) {
	var result option.Outbound
	object, ok := item.(*badjson.JSONObject)
	if !ok {
		warnIgnoredProviderMember(providerTagFromContext(ctx), "outbound", index, "", "", E.New("expected object"))
		return result, false
	}
	protocol, tag, ok := boxMemberMetadata(object)
	if !ok {
		warnIgnoredProviderMember(providerTagFromContext(ctx), "outbound", index, tag, protocol, E.New("missing or invalid type"))
		return result, false
	}
	if isProviderGroupOutbound(protocol) {
		warnIgnoredProviderMember(providerTagFromContext(ctx), "outbound", index, tag, protocol, E.New("group members are not supported in a provider"))
		return result, false
	}
	if support := service.FromContext[option.OutboundSupportRegistry](ctx); support != nil && !support.IsSupported(protocol) {
		warnIgnoredProviderMember(providerTagFromContext(ctx), "outbound", index, tag, protocol, E.New("unsupported protocol in this build"))
		return result, false
	}
	if registry := service.FromContext[option.OutboundOptionsRegistry](ctx); registry != nil {
		if _, loaded := registry.CreateOptions(protocol); !loaded {
			warnIgnoredProviderMember(providerTagFromContext(ctx), "outbound", index, tag, protocol, E.New("unsupported protocol in this build"))
			return result, false
		}
	}
	raw, err := object.MarshalJSONContext(ctx)
	if err != nil {
		warnIgnoredProviderMember(providerTagFromContext(ctx), "outbound", index, tag, protocol, E.Cause(err, "marshal member"))
		return result, false
	}
	if err = json.UnmarshalContext(ctx, raw, &result); err != nil {
		warnIgnoredProviderMember(providerTagFromContext(ctx), "outbound", index, tag, protocol, E.Cause(err, "parse member"))
		return result, false
	}
	return result, true
}

func parseBoxEndpoint(ctx context.Context, item any, index int) (option.Endpoint, bool) {
	var result option.Endpoint
	object, ok := item.(*badjson.JSONObject)
	if !ok {
		warnIgnoredProviderMember(providerTagFromContext(ctx), "endpoint", index, "", "", E.New("expected object"))
		return result, false
	}
	protocol, tag, ok := boxMemberMetadata(object)
	if !ok {
		warnIgnoredProviderMember(providerTagFromContext(ctx), "endpoint", index, tag, protocol, E.New("missing or invalid type"))
		return result, false
	}
	if support := service.FromContext[option.EndpointSupportRegistry](ctx); support != nil && !support.IsSupported(protocol) {
		warnIgnoredProviderMember(providerTagFromContext(ctx), "endpoint", index, tag, protocol, E.New("unsupported protocol in this build"))
		return result, false
	}
	if registry := service.FromContext[option.EndpointOptionsRegistry](ctx); registry != nil {
		if _, loaded := registry.CreateOptions(protocol); !loaded {
			warnIgnoredProviderMember(providerTagFromContext(ctx), "endpoint", index, tag, protocol, E.New("unsupported protocol in this build"))
			return result, false
		}
	}
	raw, err := object.MarshalJSONContext(ctx)
	if err != nil {
		warnIgnoredProviderMember(providerTagFromContext(ctx), "endpoint", index, tag, protocol, E.Cause(err, "marshal member"))
		return result, false
	}
	if err = json.UnmarshalContext(ctx, raw, &result); err != nil {
		warnIgnoredProviderMember(providerTagFromContext(ctx), "endpoint", index, tag, protocol, E.Cause(err, "parse member"))
		return result, false
	}
	return result, true
}

func boxMemberMetadata(object *badjson.JSONObject) (protocol, tag string, ok bool) {
	typeValue, loaded := object.Get("type")
	if !loaded {
		return "", "", false
	}
	protocol, ok = typeValue.(string)
	if !ok || protocol == "" {
		return "", "", false
	}
	if tagValue, loaded := object.Get("tag"); loaded {
		tag, _ = tagValue.(string)
	}
	return protocol, tag, true
}

func isProviderGroupOutbound(protocol string) bool {
	switch protocol {
	case C.TypeDirect, C.TypeBlock, C.TypeDNS, C.TypeSelector, C.TypeURLTest, C.TypeLoadBalance, C.TypeSmart, C.TypeAdaptivePool, C.TypePass:
		return true
	default:
		return false
	}
}

func ParseBoxSubscription(ctx context.Context, content string) ([]option.Outbound, []option.Endpoint, error) {
	options, err := json.UnmarshalExtendedContext[SingBoxDocument](ctx, []byte(content))
	if err != nil {
		return nil, nil, err
	}
	if len(options.Outbounds) == 0 && len(options.Endpoints) == 0 {
		return nil, nil, E.New("no supported servers found")
	}
	outbounds, endpoints := filterSupportedMembers(ctx, options.Outbounds, options.Endpoints, providerTagFromContext(ctx))
	if len(outbounds) == 0 && len(endpoints) == 0 {
		return nil, nil, E.New("no supported servers found")
	}
	return outbounds, endpoints, nil
}
