//go:build !linux

package group

// smartTCPRetransmitRatio is a no-op on platforms without Linux TCP_INFO.
// The rest of Smart remains fully functional and simply scores from its other
// evidence sources.
func smartTCPRetransmitRatio(any) (float64, bool) {
	return 0, false
}
