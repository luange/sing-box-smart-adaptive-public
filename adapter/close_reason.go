package adapter

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"
)

// ConnectionCloseReason is a best-effort classification of why a routed
// connection left the traffic manager. It is deliberately small and stable so
// history consumers can aggregate it without depending on platform errors.
type ConnectionCloseReason string

const (
	CloseReasonUnknown          ConnectionCloseReason = "unknown"
	CloseReasonClientEOF        ConnectionCloseReason = "client_eof"
	CloseReasonRemoteEOF        ConnectionCloseReason = "remote_eof"
	CloseReasonRemoteReset      ConnectionCloseReason = "remote_rst"
	CloseReasonDialError        ConnectionCloseReason = "dial_error"
	CloseReasonDialTimeout      ConnectionCloseReason = "dial_timeout"
	CloseReasonHandshake        ConnectionCloseReason = "handshake_error"
	CloseReasonHandshakeTimeout ConnectionCloseReason = "handshake_timeout"
	CloseReasonIdleTimeout      ConnectionCloseReason = "idle_timeout"
)

// ClassifyDialError keeps dial failures separate from an established flow
// ending. This is used before a connection tracker is closed.
func ClassifyDialError(err error) ConnectionCloseReason {
	if err == nil {
		return CloseReasonUnknown
	}
	if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
		return CloseReasonDialTimeout
	}
	return CloseReasonDialError
}

func ClassifyHandshakeError(err error) ConnectionCloseReason {
	if err != nil && (errors.Is(err, context.DeadlineExceeded) || isTimeout(err)) {
		return CloseReasonHandshakeTimeout
	}
	return CloseReasonHandshake
}

// ClassifyStreamError classifies one direction of an established stream.
// EOF is directional: the first copy direction is the client side, while the
// reverse direction is the remote side. Reset-like errors are kept distinct
// from a clean EOF so short client cancellations are not counted as failures.
func ClassifyStreamError(err error, clientDirection bool) ConnectionCloseReason {
	if err == nil {
		if clientDirection {
			return CloseReasonClientEOF
		}
		return CloseReasonRemoteEOF
	}
	if errors.Is(err, io.EOF) {
		if clientDirection {
			return CloseReasonClientEOF
		}
		return CloseReasonRemoteEOF
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
		if clientDirection {
			return CloseReasonClientEOF
		}
		return CloseReasonRemoteEOF
	}
	if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
		return CloseReasonIdleTimeout
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.EPIPE) {
		return CloseReasonRemoteReset
	}
	if clientDirection {
		return CloseReasonClientEOF
	}
	return CloseReasonRemoteReset
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

type closeReasonState struct {
	reason ConnectionCloseReason
}

func (c *InboundContextExtended) SetCloseReason(reason ConnectionCloseReason) {
	if c == nil || reason == "" {
		return
	}
	// A timeout/reset is more actionable than a clean EOF when both directions
	// race to close. Preserve the first actionable reason without rewriting a
	// more specific failure with a later normal completion.
	for {
		current := c.closeReason.Load()
		if current != nil && closeReasonPriority(reason) <= closeReasonPriority(current.reason) {
			return
		}
		state := &closeReasonState{reason: reason}
		if c.closeReason.CompareAndSwap(current, state) {
			return
		}
	}
}

func (c *InboundContextExtended) CloseReason() ConnectionCloseReason {
	if c == nil {
		return ""
	}
	state := c.closeReason.Load()
	if state == nil {
		return ""
	}
	return state.reason
}

func closeReasonPriority(reason ConnectionCloseReason) int {
	switch reason {
	case CloseReasonDialTimeout, CloseReasonDialError,
		CloseReasonHandshake, CloseReasonHandshakeTimeout, CloseReasonIdleTimeout, CloseReasonRemoteReset:
		return 3
	case CloseReasonClientEOF, CloseReasonRemoteEOF:
		return 1
	default:
		return 0
	}
}
