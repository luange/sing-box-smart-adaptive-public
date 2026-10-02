package libbox

import (
	"time"
)

func TriggerGoPanic() {
	time.AfterFunc(200*time.Millisecond, func() {
		panic("sing-box debug crash")
	})
}
