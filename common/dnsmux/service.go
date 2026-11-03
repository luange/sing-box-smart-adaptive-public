package dnsmux

import (
	"context"
	"encoding/binary"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const defaultMaxTransactions = 4096
const defaultMaxCoalescedResponders = 64

type PrepareFunc func(source, destination M.Socksaddr, userData any) (context.Context, N.PacketWriter, N.CloseHandlerFunc)

// HandleFunc must consume or unpack payload before returning. A response may be
// written asynchronously through writer; the service keeps only lightweight
// transaction accounting, never a per-client PacketConn or goroutine.
type HandleFunc func(ctx context.Context, payload []byte, writer N.PacketWriter, source, destination M.Socksaddr, userData any)

type Options struct {
	Handle                 HandleFunc
	Prepare                PrepareFunc
	Timeout                time.Duration
	MaxTransactions        int
	MaxCoalescedResponders int
	LaneKey                func(source M.Socksaddr, userData any) string
}

type RuntimeStats struct {
	Lanes             uint64
	Transactions      uint64
	Queries           uint64
	Replies           uint64
	TransactionMisses uint64
	AdmissionRejected uint64
	InvalidRejected   uint64
	WriterRejected    uint64
	CapacityRejected  uint64
	FollowerRejected  uint64
	Coalesced         uint64
	PeakTransactions  uint64
	QueueDrops        uint64
}

type transaction struct {
	laneKey    string
	dedupeKey  string
	responders []responder
	createdAt  time.Time
}

type responder struct {
	writer  N.PacketWriter
	onClose N.CloseHandlerFunc
	queryID uint16
}

type lane struct {
	transactions int
	lastActive   time.Time
}

type Service struct {
	options          Options
	access           sync.Mutex
	lanes            map[string]*lane
	transactions     map[uint64]transaction
	inflight         map[string]uint64
	nextID           atomic.Uint64
	closed           chan struct{}
	once             sync.Once
	queries          atomic.Uint64
	replies          atomic.Uint64
	misses           atomic.Uint64
	rejected         atomic.Uint64
	invalidRejected  atomic.Uint64
	writerRejected   atomic.Uint64
	capacityRejected atomic.Uint64
	followerRejected atomic.Uint64
	coalesced        atomic.Uint64
	peakTransactions atomic.Uint64
}

func New(options Options) *Service {
	if options.Handle == nil || options.Prepare == nil {
		panic("dnsmux: missing handle or prepare callback")
	}
	if options.Timeout <= 0 {
		options.Timeout = time.Minute
	}
	if options.MaxTransactions <= 0 {
		options.MaxTransactions = defaultMaxTransactions
	}
	if options.MaxCoalescedResponders <= 0 {
		options.MaxCoalescedResponders = defaultMaxCoalescedResponders
	}
	service := &Service{
		options:      options,
		lanes:        make(map[string]*lane),
		transactions: make(map[uint64]transaction),
		inflight:     make(map[string]uint64),
		closed:       make(chan struct{}),
	}
	go service.reapLoop()
	return service
}

func defaultLaneKey(source M.Socksaddr) string {
	return source.Addr.Unmap().String()
}

func (s *Service) NewPacket(payload []byte, source, destination M.Socksaddr, userData any) bool {
	// Close stops the reaper and purges the current table. Reject before
	// Prepare so a packet racing with shutdown cannot allocate a writer that
	// will never be completed.
	select {
	case <-s.closed:
		s.rejected.Add(1)
		return false
	default:
	}
	if len(payload) < 12 {
		s.rejected.Add(1)
		s.invalidRejected.Add(1)
		return false
	}
	ctx, writer, onClose := s.options.Prepare(source, destination, userData)
	if writer == nil {
		s.rejected.Add(1)
		s.writerRejected.Add(1)
		return false
	}
	key := defaultLaneKey(source)
	if s.options.LaneKey != nil {
		key = s.options.LaneKey(source, userData)
	}
	now := time.Now()
	// DNS clients are free to retransmit an identical question with a new ID.
	// The ID is a client-side correlation value, not part of the upstream work,
	// so exclude it from the in-flight key and restore it per responder later.
	dedupeKey := key + "\x00" + destination.String() + "\x00" + string(payload[2:])
	queryID := binary.BigEndian.Uint16(payload[:2])
	s.access.Lock()
	// Close may have won the race after Prepare returned. Re-check while
	// holding the admission lock so no transaction can be inserted after the
	// final purge.
	select {
	case <-s.closed:
		s.access.Unlock()
		if onClose != nil {
			onClose(io.ErrClosedPipe)
		}
		s.rejected.Add(1)
		return false
	default:
	}
	if existingID, loaded := s.inflight[dedupeKey]; loaded {
		currentTransaction, exists := s.transactions[existingID]
		if exists {
			if len(currentTransaction.responders) >= s.options.MaxCoalescedResponders {
				s.access.Unlock()
				if onClose != nil {
					onClose(syscall.ENOBUFS)
				}
				s.rejected.Add(1)
				s.followerRejected.Add(1)
				return false
			}
			currentTransaction.responders = append(currentTransaction.responders, responder{
				writer: writer, onClose: onClose, queryID: queryID,
			})
			s.transactions[existingID] = currentTransaction
			s.access.Unlock()
			s.queries.Add(1)
			s.coalesced.Add(1)
			return true
		}
		delete(s.inflight, dedupeKey)
	}
	if len(s.transactions) >= s.options.MaxTransactions {
		s.access.Unlock()
		if onClose != nil {
			onClose(syscall.ENOBUFS)
		}
		s.rejected.Add(1)
		s.capacityRejected.Add(1)
		return false
	}
	id := s.nextID.Add(1)
	current := s.lanes[key]
	if current == nil {
		current = &lane{}
		s.lanes[key] = current
	}
	current.transactions++
	current.lastActive = now
	s.transactions[id] = transaction{
		laneKey: key, dedupeKey: dedupeKey,
		responders: []responder{{writer: writer, onClose: onClose, queryID: queryID}}, createdAt: now,
	}
	s.inflight[dedupeKey] = id
	transactionCount := uint64(len(s.transactions))
	s.access.Unlock()
	for {
		peak := s.peakTransactions.Load()
		if transactionCount <= peak || s.peakTransactions.CompareAndSwap(peak, transactionCount) {
			break
		}
	}

	s.queries.Add(1)
	s.options.Handle(ctx, payload, &trackingWriter{service: s, id: id}, source, destination, userData)
	return true
}

type trackingWriter struct {
	service *Service
	id      uint64
	access  sync.Mutex
	done    bool
}

func (w *trackingWriter) take() (transaction, bool) {
	w.access.Lock()
	if w.done {
		w.access.Unlock()
		return transaction{}, false
	}
	w.done = true
	w.access.Unlock()
	return w.service.remove(w.id)
}

func (w *trackingWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	entry, loaded := w.take()
	if !loaded {
		buffer.Release()
		w.service.misses.Add(1)
		return io.ErrClosedPipe
	}
	var writeErr error
	for index, current := range entry.responders {
		response := buffer
		if index != len(entry.responders)-1 {
			response = buf.NewSize(buffer.Len())
			response.Write(buffer.Bytes())
		}
		if response.Len() >= 2 {
			binary.BigEndian.PutUint16(response.Bytes()[:2], current.queryID)
		}
		err := current.writer.WritePacket(response, destination)
		if writeErr == nil && err != nil {
			writeErr = err
		}
		if current.onClose != nil {
			current.onClose(err)
		}
	}
	if writeErr == nil {
		w.service.replies.Add(1)
	}
	return writeErr
}

// Close completes an accepted DNS transaction which cannot produce a packet
// response (for example an unpack error, policy rejection or upstream timeout).
// DNS routing is asynchronous, so relying only on WritePacket would retain
// failed transactions until the reap timeout and allow failure bursts to fill
// the admission table.
func (w *trackingWriter) Close(closeErr error) {
	entry, loaded := w.take()
	if !loaded {
		return
	}
	for _, current := range entry.responders {
		if current.onClose != nil {
			current.onClose(closeErr)
		}
	}
}

func (s *Service) remove(id uint64) (transaction, bool) {
	s.access.Lock()
	entry, loaded := s.transactions[id]
	if loaded {
		delete(s.transactions, id)
		if s.inflight[entry.dedupeKey] == id {
			delete(s.inflight, entry.dedupeKey)
		}
		if current := s.lanes[entry.laneKey]; current != nil {
			current.transactions--
			current.lastActive = time.Now()
		}
	}
	s.access.Unlock()
	return entry, loaded
}

func (s *Service) reapLoop() {
	interval := min(s.options.Timeout/2, 30*time.Second)
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			s.expire(now, false)
		case <-s.closed:
			return
		}
	}
}

func (s *Service) expire(now time.Time, all bool) {
	var expired []transaction
	s.access.Lock()
	for id, entry := range s.transactions {
		if all || now.Sub(entry.createdAt) >= s.options.Timeout {
			delete(s.transactions, id)
			if s.inflight[entry.dedupeKey] == id {
				delete(s.inflight, entry.dedupeKey)
			}
			expired = append(expired, entry)
			if current := s.lanes[entry.laneKey]; current != nil {
				current.transactions--
			}
		}
	}
	for key, current := range s.lanes {
		if current.transactions == 0 && (all || now.Sub(current.lastActive) >= s.options.Timeout) {
			delete(s.lanes, key)
		}
	}
	s.access.Unlock()
	for _, entry := range expired {
		for _, current := range entry.responders {
			if current.onClose != nil {
				current.onClose(io.ErrClosedPipe)
			}
		}
	}
}

func (s *Service) Purge() {
	s.expire(time.Now(), true)
}

func (s *Service) Close() {
	s.once.Do(func() { close(s.closed) })
	s.Purge()
}

func (s *Service) RuntimeStats() RuntimeStats {
	s.access.Lock()
	lanes := len(s.lanes)
	transactions := len(s.transactions)
	s.access.Unlock()
	return RuntimeStats{
		Lanes: uint64(lanes), Transactions: uint64(transactions), Queries: s.queries.Load(),
		Replies: s.replies.Load(), TransactionMisses: s.misses.Load(), AdmissionRejected: s.rejected.Load(),
		InvalidRejected: s.invalidRejected.Load(), WriterRejected: s.writerRejected.Load(),
		CapacityRejected: s.capacityRejected.Load(), FollowerRejected: s.followerRejected.Load(),
		Coalesced: s.coalesced.Load(), PeakTransactions: s.peakTransactions.Load(),
	}
}

func AddressLaneKey(source M.Socksaddr, suffix string) string {
	address := source.Addr.Unmap()
	if !address.IsValid() {
		address = netip.IPv4Unspecified()
	}
	return address.String() + "\x00" + suffix
}

var _ N.PacketWriter = (*trackingWriter)(nil)
