package audit

import (
	"log/slog"
	"sync/atomic"
)

type Log struct {
	Logger  *slog.Logger
	Success atomic.Uint64
	Failure atomic.Uint64
}

func (a *Log) Event(method, reason string, ok bool) {
	if a == nil {
		return
	}
	if ok {
		a.Success.Add(1)
	} else {
		a.Failure.Add(1)
	}
	if a.Logger != nil {
		a.Logger.Info("authentication", "method", method, "reason", reason, "success", ok)
	}
}
