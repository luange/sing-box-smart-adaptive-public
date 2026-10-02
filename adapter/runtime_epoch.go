package adapter

type RuntimeEpochLifecycle interface {
	OnRuntimeEpochPublish() error
	OnRuntimeEpochPublishCommit()
	OnRuntimeEpochPublishRollback()
	OnRuntimeEpochRetire()
}

type RuntimeEpochLease interface {
	Release()
}

func PublishRuntimeEpochOutbounds(outbounds []Outbound) error {
	var published []RuntimeEpochLifecycle
	for _, outbound := range outbounds {
		if lifecycle, loaded := outbound.(RuntimeEpochLifecycle); loaded {
			if err := lifecycle.OnRuntimeEpochPublish(); err != nil {
				lifecycle.OnRuntimeEpochPublishRollback()
				for index := len(published) - 1; index >= 0; index-- {
					published[index].OnRuntimeEpochPublishRollback()
				}
				return err
			}
			published = append(published, lifecycle)
		}
	}
	for _, lifecycle := range published {
		lifecycle.OnRuntimeEpochPublishCommit()
	}
	return nil
}
