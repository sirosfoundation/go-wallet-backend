package engine

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
)

// Why a WebSocket session ended. These values are the stable `reason` log
// field and the `reason` label of siros_engine_ws_session_closed_total; do
// not rename them without updating docs/DEPLOYMENT.md ("WebSocket close
// reasons"). The set is closed, so metric cardinality is bounded.
const (
	closeReasonReadDeadline     = "read_deadline"
	closeReasonPeerClose        = "peer_close"
	closeReasonSuperseded       = "superseded"
	closeReasonTokenRevoked     = "token_revoked"
	closeReasonAccountDeleted   = "account_deleted"
	closeReasonRevocationFailed = "revocation_check_failed"
	closeReasonWriteError       = "write_error"
	closeReasonServerShutdown   = "server_shutdown"
	closeReasonReadError        = "read_error"
	closeReasonServerClose      = "server_close"
)

var wsSessionClosedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: "siros",
	Subsystem: "engine_ws",
	Name:      "session_closed_total",
	Help:      "WebSocket engine sessions that ended, by reason.",
}, []string{"reason"})

// closeBookkeeping is the per-session state behind the close-reason log. It is
// purely observational: nothing in it changes when or how a connection closes.
type closeBookkeeping struct {
	createdAt  time.Time
	remoteAddr string

	mu sync.Mutex
	// pending is the reason a server-side path recorded just before it closed
	// the connection. The first one wins: the read loop only sees an
	// "use of closed network connection" error afterwards, which says nothing
	// about the cause.
	pending      string
	supersededBy string // ID of the session that superseded this one
	// supersedes is the ID of the session this one superseded, if any.
	supersedes string
	logged     bool
	readErr    error
}

func newCloseBookkeeping(conn *websocket.Conn) *closeBookkeeping {
	b := &closeBookkeeping{createdAt: time.Now()}
	if conn != nil && conn.RemoteAddr() != nil {
		b.remoteAddr = conn.RemoteAddr().String()
	}
	return b
}

// markClosing records reason (first call wins) and reports whether it was
// recorded. Call it BEFORE closing the connection.
func (s *Session) markClosing(reason, supersededBy string) bool {
	if s.closeInfo == nil { // Session built without newCloseBookkeeping (tests)
		return false
	}
	s.closeInfo.mu.Lock()
	defer s.closeInfo.mu.Unlock()
	// Once the read loop has ended with an error (or the close was reported)
	// that error is the cause; a later server-side mark must not override it.
	if s.closeInfo.pending != "" || s.closeInfo.readErr != nil || s.closeInfo.logged {
		return false
	}
	s.closeInfo.pending = reason
	s.closeInfo.supersededBy = supersededBy
	return true
}

// noteReadError remembers the error that ended the read loop.
func (s *Session) noteReadError(err error) {
	if s.closeInfo == nil {
		return
	}
	s.closeInfo.mu.Lock()
	s.closeInfo.readErr = err
	s.closeInfo.mu.Unlock()
}

// closeReasonFromText maps the free text passed to closeWithReason (always a
// server-chosen constant, never peer input) to a stable reason label.
func closeReasonFromText(text string) string {
	switch text {
	case "account deleted":
		return closeReasonAccountDeleted
	case "token revoked":
		return closeReasonTokenRevoked
	case "revocation check unavailable":
		return closeReasonRevocationFailed
	default:
		return closeReasonServerClose
	}
}

// classifyClose decides the reason a session ended. pending, when set, was
// recorded by the server path that closed the connection and wins; otherwise
// the read error is classified. code is the peer's numeric close code for
// peer_close (0 otherwise). The close-frame TEXT is peer-controlled and is
// deliberately never returned or logged.
func classifyClose(pending string, readErr error) (reason string, code int) {
	if pending != "" {
		return pending, 0
	}
	var ce *websocket.CloseError
	if errors.As(readErr, &ce) {
		return closeReasonPeerClose, ce.Code
	}
	var ne net.Error
	if errors.As(readErr, &ne) && ne.Timeout() {
		return closeReasonReadDeadline, 0
	}
	return closeReasonReadError, 0
}

// errorClass names the Go type of err without any of its message text, which
// can embed peer-supplied data.
func errorClass(err error) string {
	if err == nil {
		return "nil"
	}
	return fmt.Sprintf("%T", err)
}

// lastInbound returns when the socket last yielded bytes, if known.
func (s *Session) lastInbound() (time.Time, bool) {
	if s.conn == nil {
		return time.Time{}, false
	}
	if ac, ok := s.conn.NetConn().(*activityConn); ok {
		if n := ac.lastRead.Load(); n != 0 {
			return time.Unix(0, n), true
		}
	}
	return time.Time{}, false
}

// logClosed emits the single "Session close reason" Info line and bumps the
// metric. Safe to call more than once; only the first call reports.
func (s *Session) logClosed(fallback string) {
	if s.closeInfo == nil {
		return
	}
	s.closeInfo.mu.Lock()
	if s.closeInfo.logged {
		s.closeInfo.mu.Unlock()
		return
	}
	s.closeInfo.logged = true
	pending, supersededBy, readErr := s.closeInfo.pending, s.closeInfo.supersededBy, s.closeInfo.readErr
	s.closeInfo.mu.Unlock()

	if pending == "" && readErr == nil {
		pending = fallback
	}
	reason, code := classifyClose(pending, readErr)
	wsSessionClosedTotal.WithLabelValues(reason).Inc()

	now := time.Now()
	fields := []zap.Field{
		zap.String("reason", reason),
		zap.String("session_id", s.ID),
		zap.String("tenant_id", s.TenantID),
		zap.String("remote_addr", s.closeInfo.remoteAddr),
		zap.Duration("session_age", now.Sub(s.closeInfo.createdAt).Round(time.Millisecond)),
		zap.Duration("ping_interval", s.pingInterval),
		zap.Duration("pong_timeout", s.pongTimeout),
	}
	switch reason {
	case closeReasonReadDeadline:
		fields = append(fields, zap.Duration("read_window", s.pingInterval+s.pongTimeout))
		if t, ok := s.lastInbound(); ok {
			fields = append(fields, zap.Duration("since_last_inbound", now.Sub(t).Round(time.Millisecond)))
		}
	case closeReasonPeerClose:
		fields = append(fields, zap.Int("close_code", code))
	case closeReasonSuperseded:
		fields = append(fields, zap.String("superseded_by_session_id", supersededBy))
	case closeReasonReadError:
		fields = append(fields, zap.String("error_class", errorClass(readErr)))
	}
	s.logger.Info("Session close reason", fields...)
}

// logSuperseding records, at Info, that registering next closes prev ("last
// connection wins"), with both sessions' IDs, ages and remote addresses, and
// notes on next which session it superseded. Call with sessionsMu held.
func (m *Manager) logSuperseding(prev, next *Session) {
	if prev.closeInfo == nil || next.closeInfo == nil {
		return
	}
	next.closeInfo.supersedes = prev.ID
	now := time.Now()
	m.logger.Info("Closing existing session",
		zap.String("user_id", shortID(next.UserID)),
		zap.String("tenant_id", next.TenantID),
		zap.String("old_session_id", prev.ID),
		zap.Duration("old_session_age", now.Sub(prev.closeInfo.createdAt).Round(time.Millisecond)),
		zap.String("old_remote_addr", prev.closeInfo.remoteAddr),
		zap.String("new_session_id", next.ID),
		zap.Duration("new_session_age", now.Sub(next.closeInfo.createdAt).Round(time.Millisecond)),
		zap.String("new_remote_addr", next.closeInfo.remoteAddr),
	)
}

// shortID matches the 8-character user label session.logger already carries.
func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// supersededID returns the ID of the session this one superseded, or "".
func (s *Session) supersededID() string {
	if s.closeInfo == nil {
		return ""
	}
	return s.closeInfo.supersedes
}
