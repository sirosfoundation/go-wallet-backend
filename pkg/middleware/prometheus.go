package middleware

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	httpRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "sirosid",
		Name:      "http_requests_total",
		Help:      "Total number of HTTP requests by method, path pattern, and status code.",
	}, []string{"method", "path", "status"})

	httpRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "sirosid",
		Name:      "http_request_duration_seconds",
		Help:      "HTTP request duration in seconds.",
		Buckets:   prometheus.DefBuckets,
	}, []string{"method", "path"})
)

// Prometheus returns a Gin middleware that records HTTP request metrics.
// skipPaths are URL paths that should not be recorded (e.g. "/health", "/readyz").
func Prometheus(skipPaths ...string) gin.HandlerFunc {
	skip := make(map[string]bool, len(skipPaths))
	for _, p := range skipPaths {
		skip[p] = true
	}

	return func(c *gin.Context) {
		if skip[c.Request.URL.Path] {
			c.Next()
			return
		}

		start := time.Now()
		c.Next()
		elapsed := time.Since(start).Seconds()

		// Use the matched route pattern rather than the raw URL to avoid
		// high-cardinality label explosion.
		path := c.FullPath()
		if path == "" {
			path = "unmatched"
		}

		method := c.Request.Method
		status := strconv.Itoa(c.Writer.Status())

		httpRequestsTotal.WithLabelValues(method, path, status).Inc()
		httpRequestDuration.WithLabelValues(method, path).Observe(elapsed)
	}
}
