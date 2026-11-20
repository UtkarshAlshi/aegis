package audit

import (
	"bytes"
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

// TLSLog consumes net/http diagnostics without emitting peer-controlled content.
type TLSLog struct{ Audit *Log }

func (l TLSLog) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("TLS handshake error")) {
		l.Audit.Event("mtls", "handshake_rejected", false)
	} else if l.Audit != nil && l.Audit.Logger != nil {
		l.Audit.Logger.Error("machine HTTP server error")
	}
	return len(p), nil
}
