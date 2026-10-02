package adapter

import (
	"errors"
	"testing"
)

type runtimeEpochTestOutbound struct {
	Outbound
	published int
	retired   int
	fail      bool
}

func (o *runtimeEpochTestOutbound) OnRuntimeEpochPublish() error {
	o.published++
	if o.fail {
		return errRuntimeEpochTestPublish
	}
	return nil
}
func (o *runtimeEpochTestOutbound) OnRuntimeEpochPublishRollback() { o.published-- }
func (o *runtimeEpochTestOutbound) OnRuntimeEpochPublishCommit()   {}
func (o *runtimeEpochTestOutbound) OnRuntimeEpochRetire()          { o.retired++ }

var errRuntimeEpochTestPublish = errors.New("publish failed")

func TestPublishRuntimeEpochOutbounds(t *testing.T) {
	first := new(runtimeEpochTestOutbound)
	second := new(runtimeEpochTestOutbound)
	if err := PublishRuntimeEpochOutbounds([]Outbound{first, nil, second}); err != nil {
		t.Fatal(err)
	}
	if first.published != 1 || second.published != 1 {
		t.Fatalf("runtime epoch outbounds were not published: first=%d second=%d", first.published, second.published)
	}
}

func TestPublishRuntimeEpochOutboundsRollsBackEarlierOutbound(t *testing.T) {
	first := new(runtimeEpochTestOutbound)
	second := &runtimeEpochTestOutbound{fail: true}
	if err := PublishRuntimeEpochOutbounds([]Outbound{first, second}); !errors.Is(err, errRuntimeEpochTestPublish) {
		t.Fatalf("unexpected publish error: %v", err)
	}
	if first.published != 0 || second.published != 0 {
		t.Fatalf("partial publish remained visible: first=%d second=%d", first.published, second.published)
	}
}
