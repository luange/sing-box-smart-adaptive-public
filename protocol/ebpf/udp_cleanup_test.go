//go:build with_ebpf && linux

package ebpf

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestUDPNATCleanupInterval(t *testing.T) {
	require.Equal(t, 5*time.Second, udpNATCleanupInterval(2*time.Second))
	require.Equal(t, 30*time.Second, udpNATCleanupInterval(time.Minute))
	require.Equal(t, time.Minute, udpNATCleanupInterval(5*time.Minute))
}
