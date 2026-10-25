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
	challengeEvictedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "siros",
		Subsystem: "wia",
		Name:      "challenges_evicted_total",
		Help:      "Total number of expired challenges evicted by the cleanup loop.",
	})

	// WIA generation metrics
	wiaGeneratedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "siros",
		Subsystem: "wia",
		Name:      "generated_total",
		Help:      "Total number of WIA JWTs successfully generated.",
	}, []string{"attestation_source"})
	wiaGenerationErrors = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "siros",
		Subsystem: "wia",
		Name:      "generation_errors_total",
		Help:      "Total number of WIA generation failures.",
	})

	// Instance-key evidence (key_attestation) metrics
	instanceKeyNotQualifying = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "siros",
		Subsystem: "wia",
		Name:      "instance_key_not_qualifying_total",
		Help:      "Well formed instance-key evidence that could not name a home, by reason and enforcement mode (ignore: the WIA issued with the home unknown; reject: the WIA was refused).",
	}, []string{"reason", "enforcement"})
	instanceKeyRecheck = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "siros",
		Subsystem: "wia",
		Name:      "instance_key_recheck_total",
		Help:      "Re-checks of stored instance-key evidence on use, by outcome: ok, revoked (marked now), already_revoked, expired, not_qualifying (no longer accepted by the current configuration), legacy_unknown (no stored serials or no checker), unavailable (no fresh status list), replaced_stale (a stale stored record replaced by a fresh submission in one conditional write).",
	}, []string{"outcome"})

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

	// Latency histograms
	wiaGenerationDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "siros",
		Subsystem: "wia",
		Name:      "generation_duration_seconds",
		Help:      "Duration of WIA JWT generation.",
		Buckets:   prometheus.DefBuckets,
	})
	kaGenerationDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "siros",
		Subsystem: "ka",
		Name:      "generation_duration_seconds",
		Help:      "Duration of KA JWT generation.",
		Buckets:   prometheus.DefBuckets,
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
	nativeAttestationDevChainBypass = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "siros",
		Subsystem: "wia",
		Name:      "native_attestation_dev_chain_bypass_total",
		Help:      "Total number of App Attest verifications that proceeded despite a failed x5c chain check because apple_app_attest_environment=development. Should be zero in production.",
	})
)
