package interrupt

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/x/list"
)

type Group struct {
	shards [64]groupShard
}

type groupShard struct {
	access      sync.Mutex
	connections list.List[*groupConnItem]
}

type groupConnItem struct {
	conn       io.Closer
	isExternal bool
	isProvider bool
	key        string
	createdAt  time.Time
	lastActive atomic.Int64
	removed    atomic.Bool
}

type InterruptPolicy struct {
	IdleThreshold time.Duration
	LongConnAge   time.Duration
	GracePeriod   time.Duration
	ForceAll      bool
	TargetKey     string
	OnInterrupted func()
}

type InterruptResult struct {
	Interrupted int
	Deferred    int
	Idle        int
	Short       int
	Kept        int
	KeptLong    int
}

func NewGroup() *Group {
	return &Group{}
}

func connectionShardIndex(key string) uint32 {
	// FNV-1a is stable, allocation-free and sufficient for lock distribution.
	var hash uint32 = 2166136261
	for index := 0; index < len(key); index++ {
		hash ^= uint32(key[index])
		hash *= 16777619
	}
	return hash & 63
}

func (g *Group) shard(key string) *groupShard {
	return &g.shards[connectionShardIndex(key)]
}

// NewConn wraps a connection for interrupt tracking (official 2-arg API).
func (g *Group) NewConn(conn net.Conn, isExternal bool) net.Conn {
	return g.NewConnWithKey(conn, isExternal, false, "")
}

// NewConnEx is the provider-aware variant used by smart/adaptive.
func (g *Group) NewConnEx(conn net.Conn, isExternal, isProvider bool) net.Conn {
	return g.NewConnWithKey(conn, isExternal, isProvider, "")
}

func (g *Group) NewConnWithKey(conn net.Conn, isExternal, isProvider bool, key string) net.Conn {
	shard := g.shard(key)
	shard.access.Lock()
	defer shard.access.Unlock()
	now := time.Now()
	value := &groupConnItem{conn: conn, isExternal: isExternal, isProvider: isProvider, key: key, createdAt: now}
	value.lastActive.Store(now.UnixNano())
	item := shard.connections.PushBack(value)
	return &Conn{Conn: conn, shard: shard, element: item}
}

// NewPacketConn wraps a packet connection for interrupt tracking (official 2-arg API).
func (g *Group) NewPacketConn(conn net.PacketConn, isExternal bool) net.PacketConn {
	return g.NewPacketConnWithKey(conn, isExternal, false, "")
}

// NewPacketConnEx is the provider-aware variant used by smart/adaptive.
func (g *Group) NewPacketConnEx(conn net.PacketConn, isExternal, isProvider bool) net.PacketConn {
	return g.NewPacketConnWithKey(conn, isExternal, isProvider, "")
}

func (g *Group) NewPacketConnWithKey(conn net.PacketConn, isExternal, isProvider bool, key string) net.PacketConn {
	shard := g.shard(key)
	shard.access.Lock()
	defer shard.access.Unlock()
	now := time.Now()
	value := &groupConnItem{conn: conn, isExternal: isExternal, isProvider: isProvider, key: key, createdAt: now}
	value.lastActive.Store(now.UnixNano())
	item := shard.connections.PushBack(value)
	return &PacketConn{PacketConn: conn, shard: shard, element: item}
}

func (g *Group) Interrupt(interruptExternalConnections bool) {
	var closeItems []*groupConnItem
	for shardIndex := range g.shards {
		shard := &g.shards[shardIndex]
		shard.access.Lock()
		for element := shard.connections.Front(); element != nil; {
			next := element.Next()
			if !element.Value.isProvider && (!element.Value.isExternal || interruptExternalConnections) &&
				element.Value.removed.CompareAndSwap(false, true) {
				closeItems = append(closeItems, element.Value)
				shard.connections.Remove(element)
			}
			element = next
		}
		shard.access.Unlock()
	}
	for _, item := range closeItems {
		_ = item.conn.Close()
	}
}

func (g *Group) InterruptSelective(policy InterruptPolicy) InterruptResult {
	if policy.IdleThreshold <= 0 {
		policy.IdleThreshold = 10 * time.Second
	}
	if policy.LongConnAge <= 0 {
		policy.LongConnAge = 30 * time.Second
	}
	now := time.Now()
	var result InterruptResult
	var immediate []*groupConnItem
	var delayed []*groupConnItem
	visit := func(shard *groupShard) {
		shard.access.Lock()
		defer shard.access.Unlock()
		for element := shard.connections.Front(); element != nil; {
			next := element.Next()
			item := element.Value
			if item.isProvider || (policy.TargetKey != "" && item.key != policy.TargetKey) {
				result.Kept++
				element = next
				continue
			}
			lastActive := time.Unix(0, item.lastActive.Load())
			idle := now.Sub(lastActive) >= policy.IdleThreshold
			longActive := now.Sub(item.createdAt) >= policy.LongConnAge && !idle
			if !policy.ForceAll && longActive {
				result.Kept++
				result.KeptLong++
				element = next
				continue
			}
			if !item.removed.CompareAndSwap(false, true) {
				element = next
				continue
			}
			if idle {
				result.Idle++
			} else {
				result.Short++
			}
			shard.connections.Remove(element)
			if !policy.ForceAll && !idle && policy.GracePeriod > 0 {
				delayed = append(delayed, item)
				result.Deferred++
			} else {
				immediate = append(immediate, item)
				result.Interrupted++
			}
			element = next
		}
	}
	for shardIndex := range g.shards {
		visit(&g.shards[shardIndex])
	}
	for _, item := range immediate {
		_ = item.conn.Close()
		if policy.OnInterrupted != nil {
			policy.OnInterrupted()
		}
	}
	for _, item := range delayed {
		if conn, loaded := item.conn.(net.Conn); loaded {
			_ = conn.SetDeadline(now.Add(policy.GracePeriod))
		} else if conn, loaded := item.conn.(net.PacketConn); loaded {
			_ = conn.SetDeadline(now.Add(policy.GracePeriod))
		}
		time.AfterFunc(policy.GracePeriod, func() {
			_ = item.conn.Close()
			if policy.OnInterrupted != nil {
				policy.OnInterrupted()
			}
		})
	}
	return result
}
