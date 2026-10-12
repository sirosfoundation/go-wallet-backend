package server

import (
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// warnProcessLocalState logs a warning for each piece of security state that
// is kept per process although the database is shared, i.e. the deployments
// that can run several replicas. There is no replica count in the
// configuration, so a MongoDB storage backend is the signal that more than
// one replica is plausible; with in-memory storage a single process is the
// only possibility and nothing is logged.
func warnProcessLocalState(cfg *config.Config, store storage.Store, logger *zap.Logger) {
	if _, shared := store.(interface{ Database() *mongo.Database }); !shared {
		return
	}
	if cfg.AS.Enabled && cfg.AS.SessionStore == "memory" {
		logger.Warn("as.session_store=memory with a MongoDB storage backend: AS sessions are per process and lost on restart; with more than one replica a session is only valid on the replica that created it. Use mongodb (or auto) instead")
	}
	if cfg.Security.TokenBlacklist.Enabled && cfg.Security.TokenBlacklist.Backend == config.TokenBlacklistBackendMemory {
		logger.Warn("security.token_blacklist.backend=memory with a MongoDB storage backend: logouts and account deletions are per process and lost on restart; with more than one replica they are not enforced on the others. Use storage (or leave unset) instead")
	}
}
