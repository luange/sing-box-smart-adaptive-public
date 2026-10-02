//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net"
	"net/netip"
	"reflect"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.EBPFOutboundOptions](registry, C.TypeEBPF, NewRoutableOutbound)
}

var (
	_ adapter.Outbound             = (*RoutableOutbound)(nil)
	_ dialer.DirectDialer          = (*RoutableOutbound)(nil)
	_ N.ParallelDialer             = (*RoutableOutbound)(nil)
	_ dialer.ParallelNetworkDialer = (*RoutableOutbound)(nil)
)

// RoutableOutbound is type "ebpf" outbound: direct-class dialer that participates
// in eBPF inbound outbound_offload (splice / verdict) when offload is enabled.
// Without an eBPF inbound it still works as plain direct.
type RoutableOutbound struct {
	outbound.Adapter
	logger  logger.ContextLogger
	dialer  dialer.ParallelInterfaceDialer
	isEmpty bool
}

func NewRoutableOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.EBPFOutboundOptions) (adapter.Outbound, error) {
	options.UDPFragmentDefault = true
	if options.Detour != "" {
		return nil, E.New("ebpf outbound does not support detour (direct-class offload only; route proxies via their own type)")
	}
	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:        ctx,
		Options:        options.DialerOptions,
		RemoteIsDomain: true,
		DirectOutbound: true,
	})
	if err != nil {
		return nil, err
	}
	isEmpty := reflect.DeepEqual(options.DialerOptions, option.DialerOptions{
		AbstractDialerOptions: option.AbstractDialerOptions{UDPFragmentDefault: true},
	})
	return &RoutableOutbound{
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeEBPF, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		logger:  logger,
		dialer:  outboundDialer.(dialer.ParallelInterfaceDialer),
		isEmpty: isEmpty,
	}, nil
}

func (o *RoutableOutbound) IsEmpty() bool {
	return o.isEmpty
}

func (o *RoutableOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = o.Tag()
	metadata.Destination = destination
	network = N.NetworkName(network)
	switch network {
	case N.NetworkTCP:
		o.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		o.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	return o.dialer.DialContext(ctx, network, destination)
}

func (o *RoutableOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = o.Tag()
	metadata.Destination = destination
	o.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	return o.dialer.ListenPacket(ctx, destination)
}

func (o *RoutableOutbound) DialParallel(ctx context.Context, network string, destination M.Socksaddr, destinationAddresses []netip.Addr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = o.Tag()
	metadata.Destination = destination
	network = N.NetworkName(network)
	preferIPv6 := len(destinationAddresses) > 0 && destinationAddresses[0].Is6()
	return dialer.DialParallelNetwork(ctx, o.dialer, network, destination, destinationAddresses, preferIPv6, nil, nil, nil, 0)
}

func (o *RoutableOutbound) DialParallelNetwork(ctx context.Context, network string, destination M.Socksaddr, destinationAddresses []netip.Addr, networkStrategy *C.NetworkStrategy, networkType []C.InterfaceType, fallbackNetworkType []C.InterfaceType, fallbackDelay time.Duration) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = o.Tag()
	metadata.Destination = destination
	network = N.NetworkName(network)
	preferIPv6 := len(destinationAddresses) > 0 && destinationAddresses[0].Is6()
	return dialer.DialParallelNetwork(ctx, o.dialer, network, destination, destinationAddresses, preferIPv6, networkStrategy, networkType, fallbackNetworkType, fallbackDelay)
}

func (o *RoutableOutbound) ListenSerialNetworkPacket(ctx context.Context, destination M.Socksaddr, destinationAddresses []netip.Addr, networkStrategy *C.NetworkStrategy, networkType []C.InterfaceType, fallbackNetworkType []C.InterfaceType, fallbackDelay time.Duration) (net.PacketConn, netip.Addr, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = o.Tag()
	metadata.Destination = destination
	o.logger.InfoContext(ctx, "outbound packet connection")
	return dialer.ListenSerialNetworkPacket(ctx, o.dialer, destination, destinationAddresses, networkStrategy, networkType, fallbackNetworkType, fallbackDelay)
}
