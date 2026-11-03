//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	ECommon "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

// The verdict-learner and splice registrations were once a silent no-op:
// the hub existed in box.go but route/conn.go wiring was missing. This
// contract test pins the inbound-side wiring so a refactor that drops the
// hub.Add call fails here instead of producing a dataplane whose learned
// bypass and splice paths never fire.
func TestInboundWiresVerdictLearnerAndSpliceHooks(t *testing.T) {
	verdictHub := adapter.NewVerdictLearnerHub()
	splicerHub := adapter.NewConnectionSplicerHub()
	ctx := service.ContextWith[*adapter.VerdictLearnerHub](context.Background(), verdictHub)
	ctx = service.ContextWith[*adapter.ConnectionSplicerHub](ctx, splicerHub)

	inbound := &Inbound{ctx: ctx}
	inbound.outboundCoord = &outboundCoordinator{spliceOpts: option.EBPFSpliceOptions{Enabled: true}}
	// Zero-value VerdictBackend/SpliceBackend are non-nil pointers here: the
	// wiring must depend only on presence, not on a live kernel attach.
	if inbound.outboundCoord.verdict == nil {
		inbound.outboundCoord.verdict = &ECommon.VerdictBackend{}
	}
	if inbound.outboundCoord.splice == nil {
		inbound.outboundCoord.splice = &ECommon.SpliceBackend{}
	}

	inbound.wireVerdictLearner()
	inbound.wirePromoteAndSpliceHooks()

	if n := verdictHub.Len(); n != 1 {
		t.Fatalf("verdict learners registered = %d, want 1 (silent no-op regression)", n)
	}
	if n := splicerHub.Len(); n != 1 {
		t.Fatalf("connection splicers registered = %d, want 1 (silent no-op regression)", n)
	}
	if inbound.outboundCoord.promoteToBypass == nil {
		t.Fatal("promote hook not wired")
	}
}
