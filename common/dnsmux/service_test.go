package dnsmux

import (
	"context"
	"encoding/binary"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

type countingWriter struct{ replies *atomic.Uint64 }

func (w countingWriter) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	buffer.Release()
	w.replies.Add(1)
	return nil
}

type idWriter struct{ ids chan uint16 }

func (w idWriter) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	w.ids <- binary.BigEndian.Uint16(buffer.Bytes()[:2])
	buffer.Release()
	return nil
}

func TestServiceSharesOneLaneAcrossHighCardinalitySourcePorts(t *testing.T) {
	var replies atomic.Uint64
	service := New(Options{
		Handle: func(_ context.Context, payload []byte, writer N.PacketWriter, _, destination M.Socksaddr, _ any) {
			response := buf.NewSize(len(payload))
			response.Write(payload)
			response.Bytes()[2] |= 0x80
			require.NoError(t, writer.WritePacket(response, destination))
		},
		Timeout: time.Minute,
		Prepare: func(M.Socksaddr, M.Socksaddr, any) (context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return context.Background(), countingWriter{replies: &replies}, nil
		},
	})
	defer service.Close()
	destination := M.Socksaddr{Addr: netip.MustParseAddr("192.0.2.53"), Port: 53}
	for index := range 100 {
		message := make([]byte, 12)
		binary.BigEndian.PutUint16(message[:2], uint16(index+1))
		binary.BigEndian.PutUint16(message[4:6], 1)
		message = append(message, 1, 'a', 0, 0, 1, 0, 1)
		source := M.Socksaddr{Addr: netip.MustParseAddr("192.0.2.1"), Port: uint16(10000 + index)}
		require.True(t, service.NewPacket(message, source, destination, nil))
	}
	require.Eventually(t, func() bool { return replies.Load() == 100 }, time.Second, 10*time.Millisecond)
	stats := service.RuntimeStats()
	require.Equal(t, uint64(1), stats.Lanes)
	require.Equal(t, uint64(0), stats.Transactions)
	require.Equal(t, uint64(0), stats.TransactionMisses)
}

func TestServiceBoundsOutstandingTransactions(t *testing.T) {
	service := New(Options{
		Handle: func(context.Context, []byte, N.PacketWriter, M.Socksaddr, M.Socksaddr, any) {},
		Prepare: func(M.Socksaddr, M.Socksaddr, any) (context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return context.Background(), countingWriter{replies: new(atomic.Uint64)}, nil
		},
		Timeout: time.Minute, MaxTransactions: 2,
	})
	defer service.Close()
	message := make([]byte, 13)
	source := M.Socksaddr{Addr: netip.MustParseAddr("192.0.2.1"), Port: 10000}
	destination := M.Socksaddr{Addr: netip.MustParseAddr("192.0.2.53"), Port: 53}
	message[12] = 1
	require.True(t, service.NewPacket(message, source, destination, nil))
	message[12] = 2
	require.True(t, service.NewPacket(message, source, destination, nil))
	message[12] = 3
	require.False(t, service.NewPacket(message, source, destination, nil))
	stats := service.RuntimeStats()
	require.Equal(t, uint64(2), stats.Transactions)
	require.Equal(t, uint64(1), stats.AdmissionRejected)
	require.Equal(t, uint64(1), stats.CapacityRejected)
	require.Equal(t, uint64(2), stats.PeakTransactions)
}

func TestServiceCoalescesIdenticalInflightQueriesAndFansOut(t *testing.T) {
	var handles atomic.Uint64
	ids := make(chan uint16, 2)
	responseWriter := make(chan N.PacketWriter, 1)
	service := New(Options{
		Handle: func(_ context.Context, _ []byte, writer N.PacketWriter, _, _ M.Socksaddr, _ any) {
			handles.Add(1)
			responseWriter <- writer
		},
		Prepare: func(M.Socksaddr, M.Socksaddr, any) (context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return context.Background(), idWriter{ids: ids}, nil
		},
		Timeout: time.Minute,
	})
	defer service.Close()
	message := make([]byte, 12)
	binary.BigEndian.PutUint16(message[:2], 42)
	binary.BigEndian.PutUint16(message[4:6], 1)
	message = append(message, 1, 'a', 0, 0, 1, 0, 1)
	destination := M.Socksaddr{Addr: netip.MustParseAddr("192.0.2.53"), Port: 53}
	require.True(t, service.NewPacket(message,
		M.Socksaddr{Addr: netip.MustParseAddr("192.0.2.1"), Port: 10000}, destination, nil))
	binary.BigEndian.PutUint16(message[:2], 43)
	require.True(t, service.NewPacket(message,
		M.Socksaddr{Addr: netip.MustParseAddr("192.0.2.1"), Port: 10001}, destination, nil))
	require.Equal(t, uint64(1), handles.Load())
	stats := service.RuntimeStats()
	require.Equal(t, uint64(1), stats.Transactions)
	require.Equal(t, uint64(1), stats.Coalesced)

	response := buf.NewSize(len(message))
	response.Write(message)
	require.NoError(t, (<-responseWriter).WritePacket(response, destination))
	require.ElementsMatch(t, []uint16{42, 43}, []uint16{<-ids, <-ids})
	require.Equal(t, uint64(0), service.RuntimeStats().Transactions)
}

func TestServiceBoundsCoalescedFollowers(t *testing.T) {
	service := New(Options{
		Handle: func(context.Context, []byte, N.PacketWriter, M.Socksaddr, M.Socksaddr, any) {},
		Prepare: func(M.Socksaddr, M.Socksaddr, any) (context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return context.Background(), countingWriter{replies: new(atomic.Uint64)}, nil
		},
		Timeout: time.Minute, MaxCoalescedResponders: 2,
	})
	defer service.Close()
	message := make([]byte, 12)
	source := M.Socksaddr{Addr: netip.MustParseAddr("192.0.2.1"), Port: 10000}
	destination := M.Socksaddr{Addr: netip.MustParseAddr("192.0.2.53"), Port: 53}
	require.True(t, service.NewPacket(message, source, destination, nil))
	source.Port++
	require.True(t, service.NewPacket(message, source, destination, nil))
	source.Port++
	require.False(t, service.NewPacket(message, source, destination, nil))
	stats := service.RuntimeStats()
	require.Equal(t, uint64(1), stats.Transactions)
	require.Equal(t, uint64(1), stats.Coalesced)
	require.Equal(t, uint64(1), stats.FollowerRejected)
}

func TestServiceFailureCompletionReleasesCoalescedTransaction(t *testing.T) {
	var closes atomic.Uint64
	responseWriter := make(chan N.PacketWriter, 1)
	service := New(Options{
		Handle: func(_ context.Context, _ []byte, writer N.PacketWriter, _, _ M.Socksaddr, _ any) {
			responseWriter <- writer
		},
		Prepare: func(M.Socksaddr, M.Socksaddr, any) (context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return context.Background(), countingWriter{replies: new(atomic.Uint64)}, func(error) { closes.Add(1) }
		},
		Timeout: time.Minute,
	})
	defer service.Close()
	message := make([]byte, 12)
	source := M.Socksaddr{Addr: netip.MustParseAddr("192.0.2.1"), Port: 10000}
	destination := M.Socksaddr{Addr: netip.MustParseAddr("192.0.2.53"), Port: 53}
	require.True(t, service.NewPacket(message, source, destination, nil))
	source.Port++
	require.True(t, service.NewPacket(message, source, destination, nil))
	writer := <-responseWriter
	completionWriter, loaded := writer.(interface{ Close(error) })
	require.True(t, loaded)
	completionWriter.Close(context.DeadlineExceeded)
	stats := service.RuntimeStats()
	require.Equal(t, uint64(0), stats.Transactions)
	require.Equal(t, uint64(1), stats.Coalesced)
	require.Equal(t, uint64(2), closes.Load())
}

func TestServiceRejectsPacketsAfterClose(t *testing.T) {
	var handled atomic.Uint64
	service := New(Options{
		Handle: func(context.Context, []byte, N.PacketWriter, M.Socksaddr, M.Socksaddr, any) {
			handled.Add(1)
		},
		Prepare: func(M.Socksaddr, M.Socksaddr, any) (context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return context.Background(), countingWriter{replies: new(atomic.Uint64)}, nil
		},
		Timeout: time.Minute,
	})
	service.Close()

	message := make([]byte, 12)
	source := M.Socksaddr{Addr: netip.MustParseAddr("192.0.2.1"), Port: 10000}
	destination := M.Socksaddr{Addr: netip.MustParseAddr("192.0.2.53"), Port: 53}
	require.False(t, service.NewPacket(message, source, destination, nil))
	require.Equal(t, uint64(0), handled.Load())
	stats := service.RuntimeStats()
	require.Equal(t, uint64(0), stats.Transactions)
	require.Equal(t, uint64(1), stats.AdmissionRejected)
}
