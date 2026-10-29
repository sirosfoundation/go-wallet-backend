package engine

// SessionTransport carries a Session that is not a WebSocket connection: the
// WMP bridge (wmp.go) is the one implementation. The engine writes to it with
// Session.Send; what arrives from the client is handed to the Session directly
// (see Session.dispatchAction and its siblings), so the interface has no read
// side.
type SessionTransport interface {
	// SendJSON delivers one engine message to the client.
	SendJSON(msg interface{}) error

	// Close ends the transport. It is called when the session is closed from
	// the engine side (user revoked, superseded, shutdown).
	Close() error
}
