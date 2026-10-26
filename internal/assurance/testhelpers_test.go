package assurance

import "go.uber.org/zap"

func testLogger() *zap.Logger { return zap.NewNop() }
