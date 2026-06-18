package service

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// Challenge metrics
	challengeCreatedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "siros",
		Subsystem: "wia",
		Name:      "challenges_created_total",
		Help:      "Total number of WIA challenges created.",
	})
	challengeConsumedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "siros",
		Subsystem: "wia",
		Name:      "challenges_consumed_total",
		Help:      "Total number of WIA challenges successfully consumed.",
	})
	challengeExpiredTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "siros",
		Subsystem: "wia",
		Name:      "challenges_expired_total",
		Help:      "Total number of WIA challenges that expired or were invalid.",
	})
	challengeCapacityExceeded = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "siros",
		Subsystem: "wia",
		Name:      "challenges_capacity_exceeded_total",
		Help:      "Total number of challenge creation attempts rejected due to capacity.",
	})

	// WIA generation metrics
	wiaGeneratedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "siros",
		Subsystem: "wia",
		Name:      "generated_total",
		Help:      "Total number of WIA JWTs successfully generated.",
	})
	wiaGenerationErrors = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "siros",
		Subsystem: "wia",
		Name:      "generation_errors_total",
		Help:      "Total number of WIA generation failures.",
	})

	// KA metrics
	kaGeneratedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "siros",
		Subsystem: "ka",
		Name:      "generated_total",
		Help:      "Total number of Key Attestation JWTs generated.",
	})
	kaGenerationErrors = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "siros",
		Subsystem: "ka",
		Name:      "generation_errors_total",
		Help:      "Total number of Key Attestation generation failures.",
	})

	// Native attestation metrics
	nativeAttestationSuccess = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "siros",
		Subsystem: "wia",
		Name:      "native_attestation_success_total",
		Help:      "Total number of successful native attestation verifications.",
	})
	nativeAttestationErrors = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "siros",
		Subsystem: "wia",
		Name:      "native_attestation_errors_total",
		Help:      "Total number of failed native attestation verifications.",
	})
)
