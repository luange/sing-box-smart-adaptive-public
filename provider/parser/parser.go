package parser

import (
	"context"
	"fmt"
	"log"
	"reflect"
	"strings"
	"sync"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"
)

type subscriptionParser struct {
	name  string
	parse func(context.Context, string) ([]option.Outbound, []option.Endpoint, error)
}

type providerTagContextKey struct{}

func providerTagFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	providerTag, _ := ctx.Value(providerTagContextKey{}).(string)
	return providerTag
}

var subscriptionParsers = []subscriptionParser{
	{name: "sing-box", parse: ParseBoxSubscription},
	{name: "clash", parse: ParseClashSubscription},
	{name: "sip008", parse: ParseSIP008Subscription},
	{name: "raw", parse: ParseRawSubscription},
}

// warningDeduper bounds diagnostic state. Provider feeds can rotate tags and
// indexes indefinitely; an unbounded sync.Map would turn harmless log
// suppression into a slow memory leak.
type warningDeduper struct {
	access sync.Mutex
	limit  int
	keys   map[string]struct{}
	order  []string
}

func newWarningDeduper(limit int) *warningDeduper {
	if limit < 1 {
		limit = 1
	}
	return &warningDeduper{limit: limit, keys: make(map[string]struct{}, limit), order: make([]string, 0, limit)}
}

func (d *warningDeduper) first(key string) bool {
	d.access.Lock()
	defer d.access.Unlock()
	if _, exists := d.keys[key]; exists {
		return false
	}
	if len(d.order) >= d.limit {
		oldest := d.order[0]
		delete(d.keys, oldest)
		d.order = d.order[1:]
	}
	d.keys[key] = struct{}{}
	d.order = append(d.order, key)
	return true
}

var ignoredProviderWarnings = newWarningDeduper(4096)

func warnIgnoredProviderField(field, reason string) {
	key := "field|" + field + "|" + reason
	if !ignoredProviderWarnings.first(key) {
		return
	}
	log.Printf("provider: ignoring unsupported field %q (%s)", field, reason)
}

// warnIgnoredProviderMember deliberately logs only protocol metadata. Provider
// options can contain credentials and signed URLs, so never include the raw
// object or source line in this diagnostic.
func warnIgnoredProviderMember(providerTag, kind string, index int, tag, protocol string, reason error) {
	providerTag = safeProviderText(providerTag)
	tag = safeProviderText(tag)
	protocol = safeProviderText(protocol)
	message := providerErrorReason(reason)
	key := providerTag + "|" + kind + "|" + fmt.Sprint(index) + "|" + tag + "|" + protocol + "|" + message
	if !ignoredProviderWarnings.first(key) {
		return
	}
	if providerTag == "" {
		log.Printf("provider: ignoring %s[%d] tag=%q type=%q: %s", kind, index, tag, protocol, message)
		return
	}
	log.Printf("provider[%s]: ignoring %s[%d] tag=%q type=%q: %s", providerTag, kind, index, tag, protocol, message)
}

func warnProviderParserError(providerTag, parserName string, err error) {
	if err == nil {
		return
	}
	message := providerErrorReason(err)
	key := "parser|" + safeProviderText(providerTag) + "|" + parserName + "|" + message
	if !ignoredProviderWarnings.first(key) {
		return
	}
	if providerTag == "" {
		log.Printf("provider: %s parser skipped unsupported or malformed members: %s", parserName, message)
		return
	}
	log.Printf("provider[%s]: %s parser skipped unsupported or malformed members: %s", safeProviderText(providerTag), parserName, message)
}

func safeProviderText(value string) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
	if len(value) > 256 {
		return value[:256] + "..."
	}
	return value
}

// providerErrorReason intentionally discards parser error text. JSON/YAML and
// URL parsers are allowed to echo the offending value (which may contain a
// password, token, signed query, or full subscription URI). Provider logs need
// a stable diagnostic category, not the secret-bearing payload. The member
// index/tag/type in the caller still identifies the bad entry for remediation.
func providerErrorReason(err error) string {
	if err == nil {
		return "invalid member"
	}
	message := strings.ToLower(safeProviderText(err.Error()))
	switch {
	case strings.Contains(message, "unsupported"),
		strings.Contains(message, "not supported"),
		strings.Contains(message, "unknown outbound type"),
		strings.Contains(message, "unknown endpoint type"),
		strings.Contains(message, "unsupported scheme"):
		return "unsupported protocol"
	case strings.Contains(message, "missing"):
		return "missing required field"
	case strings.Contains(message, "expected"),
		strings.Contains(message, "unmarshal"),
		strings.Contains(message, "parse"),
		strings.Contains(message, "invalid"),
		strings.Contains(message, "malformed"),
		strings.Contains(message, "bad "):
		return "malformed or invalid member"
	case strings.Contains(message, "no supported"),
		strings.Contains(message, "no servers"):
		return "no supported members"
	default:
		return "invalid member"
	}
}

func nilProviderOptions(value any) bool {
	if value == nil {
		return true
	}
	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

// filterSupportedMembers is the final provider boundary. Parsers may support
// more protocols than a particular build was compiled with; only the runtime
// registry is authoritative. This keeps minimal builds useful and prevents a
// single unsupported member from invalidating an otherwise valid subscription.
func filterSupportedMembers(ctx context.Context, outbounds []option.Outbound, endpoints []option.Endpoint, providerTag string) ([]option.Outbound, []option.Endpoint) {
	var outboundRegistry option.OutboundOptionsRegistry
	var endpointRegistry option.EndpointOptionsRegistry
	var outboundSupport option.OutboundSupportRegistry
	var endpointSupport option.EndpointSupportRegistry
	if ctx != nil {
		outboundRegistry = service.FromContext[option.OutboundOptionsRegistry](ctx)
		endpointRegistry = service.FromContext[option.EndpointOptionsRegistry](ctx)
		outboundSupport = service.FromContext[option.OutboundSupportRegistry](ctx)
		endpointSupport = service.FromContext[option.EndpointSupportRegistry](ctx)
	}
	filteredOutbounds := make([]option.Outbound, 0, len(outbounds))
	for index, item := range outbounds {
		if item.Type == "" {
			warnIgnoredProviderMember(providerTag, "outbound", index, item.Tag, item.Type, E.New("missing protocol type"))
			continue
		}
		if outboundSupport != nil && !outboundSupport.IsSupported(item.Type) {
			warnIgnoredProviderMember(providerTag, "outbound", index, item.Tag, item.Type, E.New("unsupported protocol in this build"))
			continue
		}
		if outboundRegistry != nil {
			expected, loaded := outboundRegistry.CreateOptions(item.Type)
			if !loaded {
				warnIgnoredProviderMember(providerTag, "outbound", index, item.Tag, item.Type, E.New("unsupported protocol in this build"))
				continue
			}
			if reflect.TypeOf(expected) != reflect.TypeOf(item.Options) {
				warnIgnoredProviderMember(providerTag, "outbound", index, item.Tag, item.Type, E.New("unparseable options for registered protocol"))
				continue
			}
		}
		// A parser must never hand a nil options payload to overrideOutbounds:
		// that path intentionally uses concrete option types for zero-copy
		// overrides and would otherwise panic in a minimal/no-registry context.
		if nilProviderOptions(item.Options) {
			warnIgnoredProviderMember(providerTag, "outbound", index, item.Tag, item.Type, E.New("unparseable options"))
			continue
		}
		filteredOutbounds = append(filteredOutbounds, item)
	}
	filteredEndpoints := make([]option.Endpoint, 0, len(endpoints))
	for index, item := range endpoints {
		if item.Type == "" {
			warnIgnoredProviderMember(providerTag, "endpoint", index, item.Tag, item.Type, E.New("missing protocol type"))
			continue
		}
		if endpointSupport != nil && !endpointSupport.IsSupported(item.Type) {
			warnIgnoredProviderMember(providerTag, "endpoint", index, item.Tag, item.Type, E.New("unsupported protocol in this build"))
			continue
		}
		if endpointRegistry != nil {
			expected, loaded := endpointRegistry.CreateOptions(item.Type)
			if !loaded {
				warnIgnoredProviderMember(providerTag, "endpoint", index, item.Tag, item.Type, E.New("unsupported protocol in this build"))
				continue
			}
			if reflect.TypeOf(expected) != reflect.TypeOf(item.Options) {
				warnIgnoredProviderMember(providerTag, "endpoint", index, item.Tag, item.Type, E.New("unparseable options for registered protocol"))
				continue
			}
		}
		// Keep the same nil invariant for endpoint options.
		if nilProviderOptions(item.Options) {
			warnIgnoredProviderMember(providerTag, "endpoint", index, item.Tag, item.Type, E.New("unparseable options"))
			continue
		}
		filteredEndpoints = append(filteredEndpoints, item)
	}
	return filteredOutbounds, filteredEndpoints
}

func ParseSubscription(ctx context.Context, content string, overrideDialerOptions *option.OverrideDialerOptions, overrideTLSOptions *option.OverrideTLSOptions, overrideAnyTLSOptions *option.OverrideAnyTLSOptions, providerTag string) ([]option.Outbound, []option.Endpoint, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx = context.WithValue(ctx, providerTagContextKey{}, providerTag)
	var pErr error
	for _, parser := range subscriptionParsers {
		outbounds, endpoints, err := parser.parse(ctx, content)
		if len(outbounds) > 0 || len(endpoints) > 0 {
			if err != nil {
				warnProviderParserError(providerTag, parser.name, err)
			}
			outbounds, endpoints = filterSupportedMembers(ctx, outbounds, endpoints, providerTag)
			if len(outbounds) == 0 && len(endpoints) == 0 {
				pErr = E.Errors(pErr, E.New(parser.name, " parser produced no supported members"))
				continue
			}
			tags := providerTags(outbounds, endpoints)
			return overrideOutbounds(outbounds, overrideDialerOptions, overrideTLSOptions, overrideAnyTLSOptions, tags, providerTag),
				overrideEndpoints(endpoints, overrideDialerOptions, tags, providerTag),
				nil
		}
		if err != nil {
			pErr = E.Errors(pErr, err)
		}
	}
	return nil, nil, E.Cause(pErr, "no servers found")
}

func providerTags(outbounds []option.Outbound, endpoints []option.Endpoint) []string {
	tags := make([]string, 0, len(outbounds)+len(endpoints))
	for _, outbound := range outbounds {
		tags = append(tags, outbound.Tag)
	}
	for _, endpoint := range endpoints {
		tags = append(tags, endpoint.Tag)
	}
	return tags
}

func overrideOutbounds(outbounds []option.Outbound, overrideDialerOptions *option.OverrideDialerOptions, overrideTLSOptions *option.OverrideTLSOptions, overrideAnyTLSOptions *option.OverrideAnyTLSOptions, tags []string, providerTag string) []option.Outbound {
	var parsedOutbounds []option.Outbound
	for _, outbound := range outbounds {
		switch outbound.Type {
		case C.TypeHTTP:
			options := outbound.Options.(*option.HTTPOutboundOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideDialerOptions, tags, providerTag)
			options.OutboundTLSOptionsContainer.TLS = overrideTLSOption(options.OutboundTLSOptionsContainer.TLS, overrideTLSOptions)
			outbound.Options = options
		case C.TypeSOCKS:
			options := outbound.Options.(*option.SOCKSOutboundOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideDialerOptions, tags, providerTag)
			outbound.Options = options
		case C.TypeTUIC:
			options := outbound.Options.(*option.TUICOutboundOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideDialerOptions, tags, providerTag)
			options.OutboundTLSOptionsContainer.TLS = overrideTLSOption(options.OutboundTLSOptionsContainer.TLS, overrideTLSOptions)
			outbound.Options = options
		case C.TypeVMess:
			options := outbound.Options.(*option.VMessOutboundOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideDialerOptions, tags, providerTag)
			options.OutboundTLSOptionsContainer.TLS = overrideTLSOption(options.OutboundTLSOptionsContainer.TLS, overrideTLSOptions)
			outbound.Options = options
		case C.TypeVLESS:
			options := outbound.Options.(*option.VLESSOutboundOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideDialerOptions, tags, providerTag)
			options.OutboundTLSOptionsContainer.TLS = overrideTLSOption(options.OutboundTLSOptionsContainer.TLS, overrideTLSOptions)
			outbound.Options = options
		case C.TypeTrojan:
			options := outbound.Options.(*option.TrojanOutboundOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideDialerOptions, tags, providerTag)
			options.OutboundTLSOptionsContainer.TLS = overrideTLSOption(options.OutboundTLSOptionsContainer.TLS, overrideTLSOptions)
			outbound.Options = options
		case C.TypeHysteria:
			options := outbound.Options.(*option.HysteriaOutboundOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideDialerOptions, tags, providerTag)
			options.OutboundTLSOptionsContainer.TLS = overrideTLSOption(options.OutboundTLSOptionsContainer.TLS, overrideTLSOptions)
			outbound.Options = options
		case C.TypeShadowTLS:
			options := outbound.Options.(*option.ShadowTLSOutboundOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideDialerOptions, tags, providerTag)
			options.OutboundTLSOptionsContainer.TLS = overrideTLSOption(options.OutboundTLSOptionsContainer.TLS, overrideTLSOptions)
			outbound.Options = options
		case C.TypeHysteria2:
			options := outbound.Options.(*option.Hysteria2OutboundOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideDialerOptions, tags, providerTag)
			options.OutboundTLSOptionsContainer.TLS = overrideTLSOption(options.OutboundTLSOptionsContainer.TLS, overrideTLSOptions)
			outbound.Options = options
		case C.TypeAnyTLS:
			options := outbound.Options.(*option.AnyTLSOutboundOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideDialerOptions, tags, providerTag)
			options.OutboundTLSOptionsContainer.TLS = overrideTLSOption(options.OutboundTLSOptionsContainer.TLS, overrideTLSOptions)
			if overrideAnyTLSOptions != nil {
				if overrideAnyTLSOptions.ClientMetadata != nil {
					options.ClientMetadata = *overrideAnyTLSOptions.ClientMetadata
				}
				if overrideAnyTLSOptions.DisableReuse != nil {
					warnIgnoredProviderField("anytls.disable_reuse", "not supported on pure SagerNet AnyTLS options")
				}
			}
			outbound.Options = options
		case C.TypeShadowsocks:
			options := outbound.Options.(*option.ShadowsocksOutboundOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideDialerOptions, tags, providerTag)
			outbound.Options = options
		case C.TypeSnell:
			options := outbound.Options.(*option.SnellOutboundOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideDialerOptions, tags, providerTag)
			outbound.Options = options
		}
		parsedOutbounds = append(parsedOutbounds, outbound)
	}
	return parsedOutbounds
}

func overrideEndpoints(endpoints []option.Endpoint, overrideDialerOptions *option.OverrideDialerOptions, tags []string, providerTag string) []option.Endpoint {
	if len(endpoints) == 0 {
		return nil
	}
	var parsedEndpoints []option.Endpoint
	for _, ep := range endpoints {
		switch ep.Type {
		case C.TypeWireGuard:
			options := ep.Options.(*option.WireGuardEndpointOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideDialerOptions, tags, providerTag)
			ep.Options = options
		case C.TypeTailscale:
			options := ep.Options.(*option.TailscaleEndpointOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideDialerOptions, tags, providerTag)
			ep.Options = options
		}
		parsedEndpoints = append(parsedEndpoints, ep)
	}
	return parsedEndpoints
}

func overrideDialerOption(options option.DialerOptions, overrideDialerOptions *option.OverrideDialerOptions, tags []string, providerTag string) option.DialerOptions {
	if options.Detour != "" {
		if common.Any(tags, func(tag string) bool {
			return options.Detour == tag
		}) {
			if providerTag != "" {
				options.Detour = providerTag + "/" + options.Detour
			}
		} else {
			options.Detour = ""
		}
	}
	var defaultOptions option.OverrideDialerOptions
	if overrideDialerOptions == nil || reflect.DeepEqual(*overrideDialerOptions, defaultOptions) {
		return options
	}
	if overrideDialerOptions.Detour != nil && options.Detour == "" {
		options.Detour = *overrideDialerOptions.Detour
	}
	if overrideDialerOptions.BindInterface != nil {
		options.BindInterface = *overrideDialerOptions.BindInterface
	}
	if overrideDialerOptions.Inet4BindAddress != nil {
		options.Inet4BindAddress = overrideDialerOptions.Inet4BindAddress
	}
	if overrideDialerOptions.Inet6BindAddress != nil {
		options.Inet6BindAddress = overrideDialerOptions.Inet6BindAddress
	}
	if overrideDialerOptions.ProtectPath != nil {
		options.ProtectPath = *overrideDialerOptions.ProtectPath
	}
	if overrideDialerOptions.RoutingMark != nil {
		options.RoutingMark = *overrideDialerOptions.RoutingMark
	}
	if overrideDialerOptions.ReuseAddr != nil {
		options.ReuseAddr = *overrideDialerOptions.ReuseAddr
	}
	if overrideDialerOptions.ConnectTimeout != nil {
		options.ConnectTimeout = *overrideDialerOptions.ConnectTimeout
	}
	if overrideDialerOptions.TCPFastOpen != nil {
		options.TCPFastOpen = *overrideDialerOptions.TCPFastOpen
	}
	if overrideDialerOptions.TCPMultiPath != nil {
		options.TCPMultiPath = *overrideDialerOptions.TCPMultiPath
	}
	if overrideDialerOptions.TCPKeepAlive != nil {
		options.TCPKeepAlive = *overrideDialerOptions.TCPKeepAlive
	}
	if overrideDialerOptions.TCPKeepAliveInterval != nil {
		options.TCPKeepAliveInterval = *overrideDialerOptions.TCPKeepAliveInterval
	}
	if overrideDialerOptions.UDPFragment != nil {
		options.UDPFragment = overrideDialerOptions.UDPFragment
	}
	// A partial provider override must not erase the outbound's existing
	// resolver. Only replace it when the field is explicitly present.
	if overrideDialerOptions.DomainResolver != nil {
		options.DomainResolver = overrideDialerOptions.DomainResolver
	}
	if overrideDialerOptions.NetworkStrategy != nil {
		options.NetworkStrategy = overrideDialerOptions.NetworkStrategy
	}
	if overrideDialerOptions.NetworkType != nil {
		options.NetworkType = *overrideDialerOptions.NetworkType
	}
	if overrideDialerOptions.FallbackNetworkType != nil {
		options.FallbackNetworkType = *overrideDialerOptions.FallbackNetworkType
	}
	if overrideDialerOptions.FallbackDelay != nil {
		options.FallbackDelay = *overrideDialerOptions.FallbackDelay
	}
	if overrideDialerOptions.TCPKeepAliveCount != nil {
		warnIgnoredProviderField("override_dialer.tcp_keep_alive_count", "not supported on pure SagerNet DialerOptions")
	}
	if overrideDialerOptions.DisableTCPKeepAlive != nil {
		options.DisableTCPKeepAlive = *overrideDialerOptions.DisableTCPKeepAlive
	}

	//nolint:staticcheck
	if overrideDialerOptions.DomainStrategy != nil {
		options.DomainStrategy = *overrideDialerOptions.DomainStrategy
	}
	return options
}

func overrideTLSOption(options *option.OutboundTLSOptions, overrideTLSOptions *option.OverrideTLSOptions) *option.OutboundTLSOptions {
	if options == nil {
		return options
	}
	var defaultOptions option.OutboundTLSOptions
	if overrideTLSOptions == nil || reflect.DeepEqual(*overrideTLSOptions, defaultOptions) {
		return options
	}
	if overrideTLSOptions.Enabled != nil && !*overrideTLSOptions.Enabled {
		return &defaultOptions
	}
	// if override.OverrideTLSOptions.Enabled != nil {
	// options.Enabled = *override.OverrideTLSOptions.Enabled
	// }
	if overrideTLSOptions.DisableSNI != nil {
		options.DisableSNI = *overrideTLSOptions.DisableSNI
	}
	if overrideTLSOptions.ServerName != nil {
		options.ServerName = *overrideTLSOptions.ServerName
	}
	if overrideTLSOptions.CertificateServerName != nil {
		warnIgnoredProviderField("override_tls.certificate_server_name", "not supported on pure SagerNet OutboundTLSOptions")
	}
	if overrideTLSOptions.Insecure != nil {
		options.Insecure = *overrideTLSOptions.Insecure
	}
	if overrideTLSOptions.KernelTx != nil {
		options.KernelTx = *overrideTLSOptions.KernelTx
	}
	if overrideTLSOptions.KernelRx != nil {
		options.KernelRx = *overrideTLSOptions.KernelRx
	}
	return options
}
