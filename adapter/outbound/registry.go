package outbound

import (
	"context"
	"maps"
	"slices"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

type ConstructorFunc[T any] func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options T) (adapter.Outbound, error)

func Register[Options any](registry *Registry, outboundType string, constructor ConstructorFunc[Options]) {
	registry.register(outboundType, func() any {
		return new(Options)
	}, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, rawOptions any) (adapter.Outbound, error) {
		var options *Options
		if rawOptions != nil {
			options = rawOptions.(*Options)
		}
		return constructor(ctx, router, logger, tag, common.PtrValueOrDefault(options))
	}, true)
}

// RegisterUnsupported keeps a schema entry for a protocol that is not present
// in this build. Decoding can still produce a useful, bounded error, while
// provider filtering can distinguish it from a constructible protocol.
func RegisterUnsupported[Options any](registry *Registry, outboundType string, constructor ConstructorFunc[Options]) {
	registry.register(outboundType, func() any {
		return new(Options)
	}, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, rawOptions any) (adapter.Outbound, error) {
		var options *Options
		if rawOptions != nil {
			options = rawOptions.(*Options)
		}
		return constructor(ctx, router, logger, tag, common.PtrValueOrDefault(options))
	}, false)
}

var _ adapter.OutboundRegistry = (*Registry)(nil)
var _ option.OutboundSupportRegistry = (*Registry)(nil)

type (
	optionsConstructorFunc func() any
	constructorFunc        func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options any) (adapter.Outbound, error)
)

type Registry struct {
	access       sync.Mutex
	optionsType  map[string]optionsConstructorFunc
	constructors map[string]constructorFunc
	supported    map[string]bool
}

func NewRegistry() *Registry {
	return &Registry{
		optionsType:  make(map[string]optionsConstructorFunc),
		constructors: make(map[string]constructorFunc),
		supported:    make(map[string]bool),
	}
}

func (r *Registry) OptionTypes() []string {
	r.access.Lock()
	defer r.access.Unlock()
	return slices.Sorted(maps.Keys(r.optionsType))
}

func (r *Registry) CreateOptions(outboundType string) (any, bool) {
	r.access.Lock()
	defer r.access.Unlock()
	optionsConstructor, loaded := r.optionsType[outboundType]
	if !loaded {
		return nil, false
	}
	return optionsConstructor(), true
}

func (r *Registry) IsSupported(outboundType string) bool {
	r.access.Lock()
	defer r.access.Unlock()
	supported, loaded := r.supported[outboundType]
	return loaded && supported
}

func (r *Registry) CreateOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, outboundType string, options any) (adapter.Outbound, error) {
	r.access.Lock()
	defer r.access.Unlock()
	constructor, loaded := r.constructors[outboundType]
	if !loaded {
		return nil, E.New("outbound type not found: " + outboundType)
	}
	return constructor(ctx, router, logger, tag, options)
}

func (r *Registry) register(outboundType string, optionsConstructor optionsConstructorFunc, constructor constructorFunc, supported bool) {
	r.access.Lock()
	defer r.access.Unlock()
	r.optionsType[outboundType] = optionsConstructor
	r.constructors[outboundType] = constructor
	r.supported[outboundType] = supported
}
