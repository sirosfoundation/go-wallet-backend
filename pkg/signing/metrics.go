//go:build pkcs11

package signing

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	pkcs11SignTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "siros",
		Subsystem: "pkcs11",
		Name:      "sign_total",
		Help:      "Total number of PKCS#11 sign operations.",
	})
	pkcs11SignErrors = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "siros",
		Subsystem: "pkcs11",
		Name:      "sign_errors_total",
		Help:      "Total number of PKCS#11 sign failures.",
	})
	pkcs11SignDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "siros",
		Subsystem: "pkcs11",
		Name:      "sign_duration_seconds",
		Help:      "Histogram of PKCS#11 sign operation duration in seconds.",
		Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0},
	})
)
