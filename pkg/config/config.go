package config

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/kelseyhightower/envconfig"
	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	Server         ServerConfig         `yaml:"server" envconfig:"SERVER"`
	Storage        StorageConfig        `yaml:"storage" envconfig:"STORAGE"`
	Logging        LoggingConfig        `yaml:"logging" envconfig:"LOGGING"`
	JWT            JWTConfig            `yaml:"jwt" envconfig:"JWT"`
	AS             ASConfig             `yaml:"as" envconfig:"AS"`
	WalletProvider WalletProviderConfig `yaml:"wallet_provider" envconfig:"WALLET_PROVIDER"`
	Trust          TrustConfig          `yaml:"trust" envconfig:"TRUST"`
	SessionStore   SessionStoreConfig   `yaml:"session_store" envconfig:"SESSION_STORE"`
	Features       FeaturesConfig       `yaml:"features" envconfig:"FEATURES"`
	Security       SecurityConfig       `yaml:"security" envconfig:"SECURITY"`
	HTTPClient     HTTPClientConfig     `yaml:"http_client" envconfig:"HTTP_CLIENT"`
	AuthZENProxy   AuthZENProxyConfig   `yaml:"authzen_proxy" envconfig:"AUTHZEN_PROXY"`
}

// ASConfig contains the new Authorization Server configuration.
type ASConfig struct {
	// Enabled controls whether the new AS is active.
	Enabled bool `yaml:"enabled" envconfig:"ENABLED"`

	// SigningKeyPath is the path to a PEM-encoded private key (ECDSA P-256, P-384, or Ed25519)
	// used to sign access tokens. Mutually exclusive with SigningKeyPKCS11.
	SigningKeyPath string `yaml:"signing_key_path" envconfig:"SIGNING_KEY_PATH"`

	// SigningKeyPKCS11 is a PKCS#11 URI for HSM-backed signing.
	// Mutually exclusive with SigningKeyPath.
	SigningKeyPKCS11 string `yaml:"signing_key_pkcs11" envconfig:"SIGNING_KEY_PKCS11"`

	// Issuer is the value of the "iss" claim in issued access tokens.
	// Defaults to JWT.Issuer if not set.
	Issuer string `yaml:"issuer" envconfig:"ISSUER"`

	// DefaultTokenTTL is the default access token lifetime.
	// Default: 2m
	DefaultTokenTTL time.Duration `yaml:"default_token_ttl" envconfig:"DEFAULT_TOKEN_TTL"`

	// AudienceTTLs allows per-audience TTL overrides.
	// Keys are audience strings, values are durations.
	AudienceTTLs map[string]time.Duration `yaml:"audience_ttls" envconfig:"AUDIENCE_TTLS"`

	// Audiences lists the accepted audience values for token validation.
	// Tokens must contain at least one of these in their "aud" claim.
	// When empty, audience validation is skipped.
	// Documented values: "wallet-backend", "wallet-engine", "wallet-registry".
	Audiences []string `yaml:"audiences" envconfig:"AUDIENCES"`

	// RulesDir is the path to a directory containing SPOCP policy rule files.
	RulesDir string `yaml:"rules_dir" envconfig:"RULES_DIR"`

	// SessionTTL is the maximum session lifetime before re-authentication.
	// Default: 24h
	SessionTTL time.Duration `yaml:"session_ttl" envconfig:"SESSION_TTL"`

	// DefaultMaxTAC is the default maximum TAC for sessions created via passkey auth.
	// Admin sessions (e.g. via OIDC) may get a different MaxTAC per policy.
	// Default: "rwl" (read, write, list)
	DefaultMaxTAC string `yaml:"default_max_tac" envconfig:"DEFAULT_MAX_TAC"`

	// Legacy contains configuration for legacy (HMAC) token compatibility.
	Legacy ASLegacyConfig `yaml:"legacy" envconfig:"LEGACY"`

	// ExternalURL is the public-facing base URL of the AS (e.g. "https://wallet.example.com").
	// Used to construct OIDC redirect URIs. Required when OIDC is used.
	ExternalURL string `yaml:"external_url" envconfig:"EXTERNAL_URL"`

	// InsecureCookies disables the __Host- prefix and Secure flag on session cookies.
	// Required for local development over HTTP. NEVER enable in production.
	InsecureCookies bool `yaml:"insecure_cookies" envconfig:"INSECURE_COOKIES"`
}

// ASLegacyConfig controls the legacy all-in-one HMAC token sunset.
type ASLegacyConfig struct {
	// Enabled controls whether legacy HMAC tokens are accepted.
	// Default: true (for backward compatibility)
	Enabled bool `yaml:"enabled" envconfig:"ENABLED"`

	// DeprecationHeader controls whether Deprecation + Sunset headers
	// are sent on legacy token responses.
	DeprecationHeader bool `yaml:"deprecation_header" envconfig:"DEPRECATION_HEADER"`

	// SunsetDate is the date after which legacy tokens will no longer be supported.
	// Used in the Sunset HTTP header. Format: RFC 3339 date (e.g. "2027-10-01T00:00:00Z").
	SunsetDate string `yaml:"sunset_date" envconfig:"SUNSET_DATE"`
}

// SetDefaults sets default values for AS configuration.
func (c *ASConfig) SetDefaults() {
	if c.DefaultTokenTTL == 0 {
		c.DefaultTokenTTL = 2 * time.Minute
	}
	if c.SessionTTL == 0 {
		c.SessionTTL = 24 * time.Hour
	}
	if c.DefaultMaxTAC == "" {
		c.DefaultMaxTAC = "rwl"
	}
}

// GetTokenTTL returns the TTL for a given audience, falling back to the default.
func (c *ASConfig) GetTokenTTL(audience string) time.Duration {
	if ttl, ok := c.AudienceTTLs[audience]; ok {
		return ttl
	}
	return c.DefaultTokenTTL
}

// HTTPClientConfig contains HTTP client configuration for outbound requests
type HTTPClientConfig struct {
	// ProxyURL is the URL of the HTTP proxy for egress requests (e.g., http://proxy:8080)
	ProxyURL string `yaml:"proxy_url" envconfig:"PROXY_URL"`
	// Timeout is the timeout for HTTP requests in seconds (default: 30)
	Timeout int `yaml:"timeout" envconfig:"TIMEOUT"`
	// InsecureSkipVerify disables TLS certificate verification (not recommended for production)
	InsecureSkipVerify bool `yaml:"insecure_skip_verify" envconfig:"INSECURE_SKIP_VERIFY"`
	// AllowPrivateIPs permits outbound requests to private/internal/loopback/link-local ranges.
	// Required when credential issuers run on Docker, k8s internal networks, or localhost.
	// Default: false (private/loopback/cloud-metadata IPs are blocked by the SSRF DialContext).
	// Set to true when issuers are hosted on internal networks (dev/staging environments).
	// Env: WALLET_HTTP_CLIENT_ALLOW_PRIVATE_IPS
	AllowPrivateIPs bool `yaml:"allow_private_ips" envconfig:"ALLOW_PRIVATE_IPS"`
	// AllowHTTP permits non-TLS (plain HTTP) connections for metadata resolution.
	// Default: false (HTTPS required). Use only for local development.
	// Env: WALLET_HTTP_CLIENT_ALLOW_HTTP
	AllowHTTP bool `yaml:"allow_http" envconfig:"ALLOW_HTTP"`
}

// NewHTTPClient creates an *http.Client from the configuration, applying proxy,
// timeout, and TLS settings. If timeoutOverride > 0 it is used instead of the
// configured timeout. A zero-value HTTPClientConfig produces a sensible default
// (30 s timeout, system proxy, TLS verification enabled).
// When AllowPrivateIPs is false, a custom dialer blocks connections to private,
// loopback, and link-local IP ranges to prevent SSRF.
func (c HTTPClientConfig) NewHTTPClient(timeoutOverride time.Duration) *http.Client {
	timeout := time.Duration(c.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if timeoutOverride > 0 {
		timeout = timeoutOverride
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()

	if c.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}

	if c.ProxyURL != "" {
		proxyURL, err := url.Parse(c.ProxyURL)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	if !c.AllowPrivateIPs {
		// Block connections to private/loopback/link-local IPs to prevent SSRF.
		// DNS resolution happens inside the dialer so post-DNS rebinding is also blocked.
		baseDialer := &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid address %q: %w", addr, err)
			}
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			if err != nil {
				return nil, fmt.Errorf("DNS lookup failed for %s: %w", host, err)
			}
			for _, ip := range ips {
				// Block cloud metadata endpoints (169.254.169.254, fd00::1)
				// before the generic private/link-local check for a clearer message.
				if ip.Equal(net.ParseIP("169.254.169.254")) || ip.Equal(net.ParseIP("fd00::1")) {
					return nil, fmt.Errorf("connection to cloud metadata endpoint %s (%s) is not allowed", host, ip)
				}
				if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
					return nil, fmt.Errorf("connection to %s (%s) is not allowed: private/loopback address", host, ip)
				}
			}
			return baseDialer.DialContext(ctx, network, net.JoinHostPort(host, port))
		}
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}

// ServerConfig contains HTTP server configuration
type ServerConfig struct {
	Host           string `yaml:"host" envconfig:"HOST"`
	Port           int    `yaml:"port" envconfig:"PORT"`
	AdminHost      string `yaml:"admin_host" envconfig:"ADMIN_HOST"`             // Admin API bind address (defaults to Host)
	AdminPort      int    `yaml:"admin_port" envconfig:"ADMIN_PORT"`             // Internal admin API port (0 to disable)
	EngineHost     string `yaml:"engine_host" envconfig:"ENGINE_HOST"`           // WebSocket engine bind address (defaults to Host)
	EnginePort     int    `yaml:"engine_port" envconfig:"ENGINE_PORT"`           // WebSocket engine port (defaults to Port if 0)
	RegistryHost   string `yaml:"registry_host" envconfig:"REGISTRY_HOST"`       // Registry bind address (defaults to Host)
	RegistryPort   int    `yaml:"registry_port" envconfig:"REGISTRY_PORT"`       // VCTM registry port (defaults to 8097)
	WPHost         string `yaml:"wp_host" envconfig:"WP_HOST"`                   // Wallet-provider bind address (defaults to Host)
	WPPort         int    `yaml:"wp_port" envconfig:"WP_PORT"`                   // Wallet-provider port (0 = co-hosted with backend)
	AdminToken     string `yaml:"admin_token" envconfig:"ADMIN_TOKEN"`           // Bearer token for admin API (auto-generated if empty)
	AdminTokenPath string `yaml:"admin_token_path" envconfig:"ADMIN_TOKEN_PATH"` // Path to file containing admin token
	RPID           string `yaml:"rp_id" envconfig:"RP_ID"`
	// RPOrigin is the legacy single-origin setting. Kept for backward compatibility.
	// New deployments should use RPOrigins. When both are set, RPOrigin is prepended.
	RPOrigin  string   `yaml:"rp_origin" envconfig:"RP_ORIGIN"`
	RPOrigins []string `yaml:"rp_origins" envconfig:"RP_ORIGINS"`
	RPName    string   `yaml:"rp_name" envconfig:"RP_NAME"`
	BaseURL   string   `yaml:"base_url" envconfig:"BASE_URL"`

	// CORS configuration
	CORS CORSConfig `yaml:"cors" envconfig:"CORS"`

	// ExternalURLs for split-mode deployment (when services run separately)
	ExternalURLs ExternalURLsConfig `yaml:"external_urls" envconfig:"EXTERNAL_URLS"`

	// ServedByHeader sets the X-Served-By response header value.
	// If nil (not configured), defaults to the system hostname.
	// If set to empty string, the header is disabled.
	ServedByHeader *string `yaml:"served_by_header" envconfig:"SERVED_BY_HEADER"`

	// TLS configuration for HTTPS listeners
	TLS TLSConfig `yaml:"tls" envconfig:"TLS"`

	// AdminTLS provides separate TLS configuration for the admin server.
	// When set and enabled, the admin server uses its own certificate/key
	// instead of inheriting the main TLS configuration.
	AdminTLS *TLSConfig `yaml:"admin_tls,omitempty" envconfig:"ADMIN_TLS"`
}

// TLSConfig contains TLS configuration for HTTPS listeners
type TLSConfig struct {
	// Enabled enables TLS for the HTTP listeners
	Enabled bool `yaml:"enabled" envconfig:"ENABLED"`
	// CertFile is the path to the TLS certificate file
	CertFile string `yaml:"cert_file" envconfig:"CERT_FILE"`
	// KeyFile is the path to the TLS private key file
	KeyFile string `yaml:"key_file" envconfig:"KEY_FILE"`
	// MinVersion is the minimum TLS version (tls12 or tls13, default: tls12)
	MinVersion string `yaml:"min_version" envconfig:"MIN_VERSION"`
}

// TLSMinVersion returns the tls.Config MinVersion constant for the configured value.
func (t *TLSConfig) TLSMinVersion() uint16 {
	switch strings.ToLower(t.MinVersion) {
	case "tls13", "1.3":
		return tls.VersionTLS13
	default:
		return tls.VersionTLS12
	}
}

// ListenAndServe starts srv using TLS if t is enabled, plain HTTP otherwise.
// If TLS is enabled, it merges the MinVersion setting into any existing TLSConfig.
func (t *TLSConfig) ListenAndServe(srv *http.Server) error {
	if t.Enabled {
		if srv.TLSConfig == nil {
			srv.TLSConfig = &tls.Config{}
		}
		srv.TLSConfig.MinVersion = t.TLSMinVersion()
		return srv.ListenAndServeTLS(t.CertFile, t.KeyFile)
	}
	return srv.ListenAndServe()
}

// CORSConfig contains CORS (Cross-Origin Resource Sharing) configuration
type CORSConfig struct {
	// AllowedOrigins is a list of origins that may access the resource.
	// Use "*" to allow all origins (default for development).
	AllowedOrigins []string `yaml:"allowed_origins" envconfig:"ALLOWED_ORIGINS"`

	// AllowedMethods is a list of HTTP methods allowed for cross-origin requests.
	AllowedMethods []string `yaml:"allowed_methods" envconfig:"ALLOWED_METHODS"`

	// AllowedHeaders is a list of request headers allowed in cross-origin requests.
	AllowedHeaders []string `yaml:"allowed_headers" envconfig:"ALLOWED_HEADERS"`

	// ExposedHeaders is a list of headers that browsers are allowed to access.
	ExposedHeaders []string `yaml:"exposed_headers" envconfig:"EXPOSED_HEADERS"`

	// AllowCredentials indicates whether the request can include credentials.
	// Cannot be true when AllowedOrigins is "*".
	AllowCredentials bool `yaml:"allow_credentials" envconfig:"ALLOW_CREDENTIALS"`

	// MaxAge indicates how long (in seconds) the results of a preflight request can be cached.
	MaxAge int `yaml:"max_age" envconfig:"MAX_AGE"`
}

// GetRPOrigins returns the deduplicated list of WebAuthn RP origins.
// RPOrigin (legacy single-value field) is prepended when non-empty,
// so existing deployments continue to work without any config change.
func (c *ServerConfig) GetRPOrigins() []string {
	seen := make(map[string]struct{})
	var result []string
	for _, o := range append([]string{c.RPOrigin}, c.RPOrigins...) {
		if o == "" {
			continue
		}
		if _, dup := seen[o]; dup {
			continue
		}
		seen[o] = struct{}{}
		result = append(result, o)
	}
	return result
}

// SetDefaults sets default values for CORS configuration
func (c *CORSConfig) SetDefaults() {
	if len(c.AllowedOrigins) == 0 {
		c.AllowedOrigins = []string{"*"}
	}
	if len(c.AllowedMethods) == 0 {
		c.AllowedMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	}
	if len(c.AllowedHeaders) == 0 {
		c.AllowedHeaders = []string{
			"Authorization", "Content-Type", "X-Tenant-ID",
			"If-None-Match", "X-Private-Data-If-Match", "X-Private-Data-If-None-Match",
			"Upgrade", "Connection", "Sec-WebSocket-Key",
			"Sec-WebSocket-Version", "Sec-WebSocket-Protocol",
		}
	}
	if len(c.ExposedHeaders) == 0 {
		c.ExposedHeaders = []string{"X-Private-Data-ETag"}
	}
	if c.MaxAge == 0 {
		c.MaxAge = 43200 // 12 hours
	}
}

// ExternalURLsConfig contains URLs for split-mode deployment
// When services run as separate containers/pods, they need external URLs to reference each other.
type ExternalURLsConfig struct {
	// BackendURL is the external URL for the backend service (for engine → backend calls)
	BackendURL string `yaml:"backend_url" envconfig:"BACKEND_URL"`

	// EngineURL is the external URL for the engine service (for WebSocket connections)
	EngineURL string `yaml:"engine_url" envconfig:"ENGINE_URL"`

	// RegistryURL is the external URL for the registry service (for VCTM lookups)
	RegistryURL string `yaml:"registry_url" envconfig:"REGISTRY_URL"`

	// AdminURL is the external URL for the admin API (for inter-service admin calls)
	AdminURL string `yaml:"admin_url" envconfig:"ADMIN_URL"`
}

// GetBackendURL returns the backend URL, with fallback to localhost
func (e *ExternalURLsConfig) GetBackendURL(host string, port int) string {
	if e.BackendURL != "" {
		return e.BackendURL
	}
	return fmt.Sprintf("http://%s:%d", host, port)
}

// GetEngineURL returns the engine URL, with fallback to localhost
func (e *ExternalURLsConfig) GetEngineURL(host string, port int) string {
	if e.EngineURL != "" {
		return e.EngineURL
	}
	return fmt.Sprintf("http://%s:%d", host, port)
}

// GetRegistryURL returns the registry URL, with fallback to localhost
func (e *ExternalURLsConfig) GetRegistryURL(host string, port int) string {
	if e.RegistryURL != "" {
		return e.RegistryURL
	}
	return fmt.Sprintf("http://%s:%d", host, port)
}

// GetAdminURL returns the admin URL, with fallback to localhost
func (e *ExternalURLsConfig) GetAdminURL(host string, port int) string {
	if e.AdminURL != "" {
		return e.AdminURL
	}
	return fmt.Sprintf("http://%s:%d", host, port)
}

// StorageConfig contains storage configuration
type StorageConfig struct {
	Type    string        `yaml:"type" envconfig:"TYPE"` // memory, sqlite, mongodb
	SQLite  SQLiteConfig  `yaml:"sqlite" envconfig:"SQLITE"`
	MongoDB MongoDBConfig `yaml:"mongodb" envconfig:"MONGODB"`
}

// SQLiteConfig contains SQLite-specific configuration
type SQLiteConfig struct {
	Path string `yaml:"path" envconfig:"DB_PATH"`
}

// MongoDBConfig contains MongoDB-specific configuration
type MongoDBConfig struct {
	URI          string `yaml:"uri" envconfig:"URI"`
	Database     string `yaml:"database" envconfig:"DATABASE"`
	Timeout      int    `yaml:"timeout" envconfig:"TIMEOUT"`             // seconds
	PasswordPath string `yaml:"password_path" envconfig:"PASSWORD_PATH"` // Path to file containing MongoDB password
	// TLS/mTLS configuration
	TLSEnabled bool   `yaml:"tls_enabled" envconfig:"TLS_ENABLED"` // Enable TLS for MongoDB connection
	CAPath     string `yaml:"ca_path" envconfig:"CA_PATH"`         // Path to CA certificate for server verification
	CertPath   string `yaml:"cert_path" envconfig:"CERT_PATH"`     // Path to client certificate for mTLS
	KeyPath    string `yaml:"key_path" envconfig:"KEY_PATH"`       // Path to client key for mTLS
}

// LoggingConfig contains logging configuration
type LoggingConfig struct {
	Level  string `yaml:"level" envconfig:"LEVEL"`   // debug, info, warn, error
	Format string `yaml:"format" envconfig:"FORMAT"` // json, text
}

// JWTConfig contains JWT configuration
type JWTConfig struct {
	Secret      string `yaml:"secret" envconfig:"SECRET"`
	SecretPath  string `yaml:"secret_path" envconfig:"SECRET_PATH"` // Path to file containing JWT secret
	ExpiryHours int    `yaml:"expiry_hours" envconfig:"EXPIRY_HOURS"`
	RefreshDays int    `yaml:"refresh_days" envconfig:"REFRESH_DAYS"`
	Issuer      string `yaml:"issuer" envconfig:"ISSUER"`
}

// JWTLeeway is the clock-skew tolerance applied when validating JWT time claims
// (nbf, exp, iat). This accounts for minor clock differences between token
// issuers and validators in distributed deployments.
const JWTLeeway = 5 * time.Second

// WalletProviderConfig contains wallet provider key attestation configuration
type WalletProviderConfig struct {
	PrivateKeyPath  string `yaml:"private_key_path" envconfig:"PRIVATE_KEY_PATH"`
	CertificatePath string `yaml:"certificate_path" envconfig:"CERTIFICATE_PATH"`
	CACertPath      string `yaml:"ca_cert_path" envconfig:"CA_CERT_PATH"`

	// PKCS11 enables HSM-backed signing (takes precedence over file-based key)
	PKCS11 *PKCS11SigningConfig `yaml:"pkcs11,omitempty" envconfig:"PKCS11"`

	// WIA (Wallet Instance Attestation) configuration
	WIA WIAConfig `yaml:"wia" envconfig:"WIA"`

	// Attestation controls attestation behavior for both WIA and KA
	Attestation AttestationConfig `yaml:"attestation" envconfig:"ATTESTATION"`
}

// PKCS11SigningConfig holds PKCS#11 HSM configuration for the wallet provider signer.
type PKCS11SigningConfig struct {
	ModulePath string `yaml:"module_path" envconfig:"MODULE_PATH"`
	SlotID     uint   `yaml:"slot_id" envconfig:"SLOT_ID"`
	PIN        string `yaml:"pin" envconfig:"PIN"`
	KeyLabel   string `yaml:"key_label" envconfig:"KEY_LABEL"`
	PoolSize   int    `yaml:"pool_size" envconfig:"POOL_SIZE"` // Session pool size (default 4)
}

// AttestationConfig controls attestation lifecycle behavior.
type AttestationConfig struct {
	// LifetimeSeconds is the global attestation lifetime (WIA + KA).
	// CS-04 requires < 24h (86400). Default: 3600 (1 hour).
	LifetimeSeconds int `yaml:"lifetime_seconds" envconfig:"LIFETIME_SECONDS"`

	// KAExpirySeconds is the key attestation JWT expiry.
	// Short-lived by default (15s) for single-use credential issuance.
	KAExpirySeconds int `yaml:"ka_expiry_seconds" envconfig:"KA_EXPIRY_SECONDS"`

	// StatusListMode controls whether attestations include a status_list entry.
	// Values: "always" (always include), "never" (omit for short-lived),
	// "auto" (include only if lifetime > threshold). Default: "never".
	StatusListMode string `yaml:"status_list_mode" envconfig:"STATUS_LIST_MODE"`

	// StatusListURL is the base URL for the Token Status List endpoint.
	StatusListURL string `yaml:"status_list_url" envconfig:"STATUS_LIST_URL"`

	// NativeAttestation controls platform attestation verification.
	NativeAttestation NativeAttestationConfig `yaml:"native_attestation" envconfig:"NATIVE_ATTESTATION"`
}

// NativeAttestationConfig controls platform-specific attestation verification.
type NativeAttestationConfig struct {
	// Enabled controls whether native platform attestation is required.
	Enabled bool `yaml:"enabled" envconfig:"ENABLED"`

	// AppleAppAttestEnvironment: "production" or "development"
	AppleAppAttestEnvironment string `yaml:"apple_app_attest_environment" envconfig:"APPLE_APP_ATTEST_ENVIRONMENT"`
	// AppleAppID is the full App ID (TeamID.BundleID) for Apple App Attest.
	AppleAppID string `yaml:"apple_app_id" envconfig:"APPLE_APP_ID"`

	// GooglePackageName is the Android package name for Play Integrity.
	GooglePackageName string `yaml:"google_package_name" envconfig:"GOOGLE_PACKAGE_NAME"`
	// GooglePlayIntegrityDecryptionKey is the base64-encoded decryption key.
	GooglePlayIntegrityDecryptionKey string `yaml:"google_play_integrity_decryption_key" envconfig:"GOOGLE_PLAY_INTEGRITY_DECRYPTION_KEY"`
	// GooglePlayIntegrityVerificationKey is the base64-encoded verification key.
	GooglePlayIntegrityVerificationKey string `yaml:"google_play_integrity_verification_key" envconfig:"GOOGLE_PLAY_INTEGRITY_VERIFICATION_KEY"`
}

// WIAConfig contains WIA-specific configuration (CS-04 §7.1.2)
type WIAConfig struct {
	// Enabled controls whether WIA endpoints are registered
	Enabled bool `yaml:"enabled" envconfig:"ENABLED"`
	// WalletProviderURI is the expected `aud` in WIA-PoP JWTs (wallet provider identifier)
	WalletProviderURI string `yaml:"wallet_provider_uri" envconfig:"WALLET_PROVIDER_URI"`
	// WalletName is the wallet_name claim in WIA JWT
	WalletName string `yaml:"wallet_name" envconfig:"WALLET_NAME"`
	// WalletVersion is the wallet_version claim
	WalletVersion string `yaml:"wallet_version" envconfig:"WALLET_VERSION"`
	// WalletLink is the wallet download/info URI
	WalletLink string `yaml:"wallet_link" envconfig:"WALLET_LINK"`
	// MaxExpirySeconds is the maximum WIA lifetime in seconds (CS-04 requires < 24h)
	MaxExpirySeconds int `yaml:"max_expiry_seconds" envconfig:"MAX_EXPIRY_SECONDS"`
	// ChallengeTTLSeconds is the lifetime of WIA challenge nonces in seconds
	ChallengeTTLSeconds int `yaml:"challenge_ttl_seconds" envconfig:"CHALLENGE_TTL_SECONDS"`
}

// FlowTrustConfig contains per-flow trust evaluation overrides.
// Each flow (issuer/verifier) can independently configure trust evaluation.
//
// The pdp_url field controls both which PDP to use and whether trust is enabled:
//   - Not set (empty): inherit the global trust configuration
//   - Set to a URL: use that PDP for this flow (implies trust is enabled)
//   - Set to "none": explicitly disable trust evaluation for this flow ("allow all")
type FlowTrustConfig struct {
	// PDPURL overrides the global PDP URL for this specific flow.
	// Empty inherits from global. Set to "none" to explicitly disable trust.
	PDPURL string `yaml:"pdp_url" envconfig:"PDP_URL"`
}

// IsExplicitlyDisabled returns true if trust is explicitly disabled for this flow
// by setting pdp_url to "none".
func (c *FlowTrustConfig) IsExplicitlyDisabled() bool {
	return c.PDPURL == "none"
}

// TrustConfig contains trust evaluation configuration.
//
// Trust evaluation operates in one of two modes:
//   - When PDPURL is configured: "default deny" mode - all trust decisions go through the PDP
//   - When PDPURL is empty: "allow all" mode - requests are always considered trusted
//
// Per-flow overrides allow independent trust configuration for issuer (OID4VCI)
// and verifier (OID4VP) flows. Setting a per-flow pdp_url implies trust is enabled
// for that flow. Setting it to "none" explicitly disables trust for that flow.
// Configuration applies equally regardless of transport (proxy/websockets).
type TrustConfig struct {
	// PDPURL is the URL of the AuthZEN PDP (Policy Decision Point) for trust evaluation.
	// When set, operates in "default deny" mode - trust decisions require PDP approval.
	// When empty, operates in "allow all" mode - requests are always considered trusted.
	PDPURL string `yaml:"pdp_url" envconfig:"PDP_URL"`

	// DefaultEndpoint is deprecated. Use PDPURL instead.
	// Retained for backward compatibility - if PDPURL is empty and DefaultEndpoint is set,
	// DefaultEndpoint is used.
	// Deprecated: This field will be removed in a future release.
	DefaultEndpoint string `yaml:"default_endpoint" envconfig:"DEFAULT_ENDPOINT"`

	// RegistryURL is the URL for the VCTM registry service.
	RegistryURL string `yaml:"registry_url" envconfig:"REGISTRY_URL"`
	// Timeout is the HTTP timeout for trust evaluation requests (seconds).
	Timeout int `yaml:"timeout" envconfig:"TIMEOUT"`

	// InsecureSkipVerify disables TLS certificate verification for PDP requests.
	// Use only in development or when the PDP uses a self-signed certificate.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify" envconfig:"INSECURE_SKIP_VERIFY"`

	// CACertPath is the path to a PEM-encoded CA certificate used to verify the PDP's
	// TLS certificate. Set this when the PDP is signed by an internal/private CA.
	CACertPath string `yaml:"ca_cert_path" envconfig:"CA_CERT_PATH"`

	// Issuer contains per-flow trust configuration overrides for OID4VCI (credential issuance).
	// When not set, inherits the global trust configuration.
	Issuer FlowTrustConfig `yaml:"issuer" envconfig:"ISSUER"`

	// Verifier contains per-flow trust configuration overrides for OID4VP (credential presentation).
	// When not set, inherits the global trust configuration.
	Verifier FlowTrustConfig `yaml:"verifier" envconfig:"VERIFIER"`
}

// NewPDPHTTPClient creates an *http.Client for use with operator-configured PDP endpoints.
//
// Unlike the global HTTP client, this client:
//   - Does NOT use any configured HTTP proxy (PDP is expected to be directly reachable)
//   - Does NOT apply SSRF dial restrictions (PDP URL is operator-controlled)
//   - Uses PDP-specific TLS settings (InsecureSkipVerify, CACertPath) from this TrustConfig
//
// The timeout is taken from TrustConfig.Timeout unless timeoutOverride > 0.
func (c *TrustConfig) NewPDPHTTPClient(timeoutOverride time.Duration) (*http.Client, error) {
	timeout := time.Duration(c.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if timeoutOverride > 0 {
		timeout = timeoutOverride
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12} //nolint:gosec
	if c.InsecureSkipVerify {
		tlsCfg.InsecureSkipVerify = true //nolint:gosec
	}
	if c.CACertPath != "" {
		pem, err := os.ReadFile(c.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("trust: failed to read PDP CA certificate %q: %w", c.CACertPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("trust: failed to parse PDP CA certificate %q", c.CACertPath)
		}
		tlsCfg.RootCAs = pool
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsCfg
	// No proxy — PDP is an internal service reached directly.
	transport.Proxy = nil

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}, nil
}

// GetPDPURL returns the effective global PDP URL, preferring PDPURL over the deprecated DefaultEndpoint.
func (c *TrustConfig) GetPDPURL() string {
	if c.PDPURL != "" {
		return c.PDPURL
	}
	return c.DefaultEndpoint
}

// GetIssuerPDPURL returns the effective PDP URL for issuer (OID4VCI) flows.
// Returns empty string if trust is explicitly disabled for this flow.
// Priority: flow-specific PDPURL > global PDPURL > deprecated DefaultEndpoint.
func (c *TrustConfig) GetIssuerPDPURL() string {
	if c.Issuer.IsExplicitlyDisabled() {
		return ""
	}
	if c.Issuer.PDPURL != "" {
		return c.Issuer.PDPURL
	}
	return c.GetPDPURL()
}

// GetVerifierPDPURL returns the effective PDP URL for verifier (OID4VP) flows.
// Returns empty string if trust is explicitly disabled for this flow.
// Priority: flow-specific PDPURL > global PDPURL > deprecated DefaultEndpoint.
func (c *TrustConfig) GetVerifierPDPURL() string {
	if c.Verifier.IsExplicitlyDisabled() {
		return ""
	}
	if c.Verifier.PDPURL != "" {
		return c.Verifier.PDPURL
	}
	return c.GetPDPURL()
}

// IsIssuerTrustEnabled returns whether trust evaluation is enabled for issuer flows.
// Trust is enabled if a PDP URL is configured (flow-specific or global) and not
// explicitly disabled via pdp_url: "none".
func (c *TrustConfig) IsIssuerTrustEnabled() bool {
	return c.GetIssuerPDPURL() != ""
}

// IsVerifierTrustEnabled returns whether trust evaluation is enabled for verifier flows.
// Trust is enabled if a PDP URL is configured (flow-specific or global) and not
// explicitly disabled via pdp_url: "none".
func (c *TrustConfig) IsVerifierTrustEnabled() bool {
	return c.GetVerifierPDPURL() != ""
}

// FeaturesConfig contains feature flags for controlling behavior
type FeaturesConfig struct {
	// ProxyEnabled controls whether the /proxy endpoint is available.
	// Set to false to disable the proxy (requires WebSocket engine for flows).
	// Default: true (for backward compatibility)
	ProxyEnabled bool `yaml:"proxy_enabled" envconfig:"PROXY_ENABLED"`

	// WebSocketRequired forces WebSocket transport for credential flows.
	// When true, the proxy endpoint will return an error directing clients
	// to use the WebSocket transport instead.
	// Default: false
	WebSocketRequired bool `yaml:"websocket_required" envconfig:"WEBSOCKET_REQUIRED"`

	// CredentialStorageEnabled controls whether server-side credential storage
	// endpoints (/storage/vc/*) are available. By default, credentials are stored
	// exclusively in the encrypted client-side private_data blob and the server-side
	// storage path is unused. Set to true only if you need backward-compatible
	// server-side credential storage.
	// Default: false (server-side credential storage disabled)
	CredentialStorageEnabled bool `yaml:"credential_storage_enabled" envconfig:"CREDENTIAL_STORAGE_ENABLED"`
}

// AuthZENProxyConfig configures the AuthZEN proxy endpoint for frontend trust evaluation.
//
// The proxy provides an authenticated endpoint for the frontend to make trust decisions
// by forwarding AuthZEN evaluation requests to the configured PDP (Policy Decision Point).
// Query authorization is performed using SPOCP policies to restrict what queries are allowed.
type AuthZENProxyConfig struct {
	// Enabled controls whether the /v1/evaluate endpoint is available.
	// Default: true (set in defaultConfig)
	Enabled bool `yaml:"enabled" envconfig:"ENABLED"`

	// PDPURL is the backend PDP URL to proxy requests to.
	// If empty, uses the global trust.pdp_url configuration.
	PDPURL string `yaml:"pdp_url" envconfig:"PDP_URL"`

	// Timeout is the timeout for PDP requests in seconds.
	// Default: 30
	Timeout int `yaml:"timeout" envconfig:"TIMEOUT"`

	// RulesFile is the path to a SPOCP rules file for query authorization.
	// If empty, default wallet rules are used.
	RulesFile string `yaml:"rules_file" envconfig:"RULES_FILE"`

	// AllowResolution controls whether resolution-only requests are allowed.
	// Resolution requests fetch metadata (DID documents, entity configs) without key validation.
	// Default: true
	AllowResolution bool `yaml:"allow_resolution" envconfig:"ALLOW_RESOLUTION"`

	// FailOpenOnTenantLookupError controls behavior when per-tenant PDP lookup fails.
	// If false (default), tenant lookup errors return an error to the client.
	// If true, falls back to the global PDP URL on lookup errors.
	// Security note: fail-closed (false) prevents bypassing per-tenant security policies.
	FailOpenOnTenantLookupError bool `yaml:"fail_open_on_tenant_lookup_error" envconfig:"FAIL_OPEN_ON_TENANT_LOOKUP_ERROR"`
}

// SetDefaults sets default values for AuthZEN proxy configuration.
func (c *AuthZENProxyConfig) SetDefaults() {
	if c.Timeout == 0 {
		c.Timeout = 30
	}
}

// GetPDPURL returns the effective PDP URL, falling back to the provided default.
func (c *AuthZENProxyConfig) GetPDPURL(defaultURL string) string {
	if c.PDPURL != "" {
		return c.PDPURL
	}
	return defaultURL
}

// SecurityConfig contains security-related configuration
type SecurityConfig struct {
	// AuthRateLimit contains rate limiting configuration for auth endpoints
	AuthRateLimit AuthRateLimitConfig `yaml:"auth_rate_limit" envconfig:"AUTH_RATE_LIMIT"`

	// AAGUIDBlacklist contains AAGUID blacklist configuration for WebAuthn
	AAGUIDBlacklist AAGUIDBlacklistConfig `yaml:"aaguid_blacklist" envconfig:"AAGUID_BLACKLIST"`

	// ChallengeCleanup contains challenge cleanup worker configuration
	ChallengeCleanup ChallengeCleanupConfig `yaml:"challenge_cleanup" envconfig:"CHALLENGE_CLEANUP"`

	// TokenBlacklist contains token blacklist/revocation configuration
	TokenBlacklist TokenBlacklistConfig `yaml:"token_blacklist" envconfig:"TOKEN_BLACKLIST"`

	// WebAuthn contains WebAuthn-specific security configuration
	WebAuthn WebAuthnSecurityConfig `yaml:"webauthn" envconfig:"WEBAUTHN"`
}

// WebAuthnSecurityConfig contains WebAuthn-specific security configuration
type WebAuthnSecurityConfig struct {
	// AttestationConveyance controls how the RP requests attestation from authenticators.
	// Valid values: "none", "indirect", "direct", "enterprise"
	// Default: "none" (recommended for most deployments - avoids certificate validation issues)
	// Use "direct" only if you need to verify authenticator makes/models.
	AttestationConveyance string `yaml:"attestation_conveyance" envconfig:"ATTESTATION_CONVEYANCE"`
}

// GetAttestationConveyance returns the attestation conveyance preference
// Defaults to "none" (recommended for most deployments)
// Use "direct" for testing authenticator attestation verification
func (c *WebAuthnSecurityConfig) GetAttestationConveyance() string {
	switch c.AttestationConveyance {
	case "none", "indirect", "direct", "enterprise":
		return c.AttestationConveyance
	default:
		return "none"
	}
}

// AuthRateLimitConfig contains rate limiting configuration for auth endpoints
type AuthRateLimitConfig struct {
	// Enabled controls whether rate limiting is active
	Enabled bool `yaml:"enabled" envconfig:"ENABLED"`

	// MaxAttempts is the maximum number of login/registration attempts per window
	// Default: 10
	MaxAttempts int `yaml:"max_attempts" envconfig:"MAX_ATTEMPTS"`

	// WindowSeconds is the time window for rate limiting (in seconds)
	// Default: 60 (1 minute)
	WindowSeconds int `yaml:"window_seconds" envconfig:"WINDOW_SECONDS"`

	// LockoutSeconds is how long to lock out after exceeding the limit
	// Default: 300 (5 minutes)
	LockoutSeconds int `yaml:"lockout_seconds" envconfig:"LOCKOUT_SECONDS"`
}

// SetDefaults sets default values for auth rate limiting
func (c *AuthRateLimitConfig) SetDefaults() {
	if c.MaxAttempts == 0 {
		c.MaxAttempts = 10
	}
	if c.WindowSeconds == 0 {
		c.WindowSeconds = 60
	}
	if c.LockoutSeconds == 0 {
		c.LockoutSeconds = 300
	}
}

// AAGUIDBlacklistConfig contains AAGUID blacklist configuration
type AAGUIDBlacklistConfig struct {
	// Enabled controls whether AAGUID blacklist checking is active
	Enabled bool `yaml:"enabled" envconfig:"ENABLED"`

	// AAGUIDs is a list of blocked AAGUIDs (hex-encoded UUIDs without dashes)
	// Example: ["00000000000000000000000000000000"] to block zero AAGUID
	AAGUIDs []string `yaml:"aaguids" envconfig:"AAGUIDS"`

	// RejectUnknown rejects authenticators with zero/unknown AAGUIDs
	// Default: false (permissive - allows unknown authenticators)
	RejectUnknown bool `yaml:"reject_unknown" envconfig:"REJECT_UNKNOWN"`
}

// ChallengeCleanupConfig contains challenge cleanup worker configuration
type ChallengeCleanupConfig struct {
	// Enabled controls whether the cleanup worker runs
	Enabled bool `yaml:"enabled" envconfig:"ENABLED"`

	// IntervalSeconds is how often to run cleanup (in seconds)
	// Default: 300 (5 minutes)
	IntervalSeconds int `yaml:"interval_seconds" envconfig:"INTERVAL_SECONDS"`
}

// SetDefaults sets default values for challenge cleanup
func (c *ChallengeCleanupConfig) SetDefaults() {
	if c.IntervalSeconds == 0 {
		c.IntervalSeconds = 300
	}
}

// TokenBlacklistConfig contains token blacklist/revocation configuration
type TokenBlacklistConfig struct {
	// Enabled controls whether token blacklist checking is active
	Enabled bool `yaml:"enabled" envconfig:"ENABLED"`

	// CleanupIntervalSeconds is how often to clean up expired blacklist entries
	// Default: 3600 (1 hour)
	CleanupIntervalSeconds int `yaml:"cleanup_interval_seconds" envconfig:"CLEANUP_INTERVAL_SECONDS"`
}

// SetDefaults sets default values for token blacklist
func (c *TokenBlacklistConfig) SetDefaults() {
	if c.CleanupIntervalSeconds == 0 {
		c.CleanupIntervalSeconds = 3600
	}
}

// SessionStoreConfig contains WebSocket session store configuration
type SessionStoreConfig struct {
	// Type is the session store type: "memory" or "redis"
	Type string `yaml:"type" envconfig:"TYPE"`
	// Redis contains Redis-specific configuration
	Redis RedisConfig `yaml:"redis" envconfig:"REDIS"`
	// DefaultTTL is the default session TTL in hours
	DefaultTTLHours int `yaml:"default_ttl_hours" envconfig:"DEFAULT_TTL_HOURS"`
}

// RedisConfig contains Redis connection configuration
type RedisConfig struct {
	Address   string `yaml:"address" envconfig:"ADDRESS"`
	Password  string `yaml:"password" envconfig:"PASSWORD"`
	DB        int    `yaml:"db" envconfig:"DB"`
	KeyPrefix string `yaml:"key_prefix" envconfig:"KEY_PREFIX"`
}

// Load loads configuration from file and environment variables
func Load(configFile string) (*Config, error) {
	// Start with defaults
	cfg := defaultConfig()

	// Load from YAML file if provided (overrides defaults)
	if configFile != "" {
		data, err := os.ReadFile(configFile)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("failed to read config file: %w", err)
			}
			// File doesn't exist, that's ok - we'll use defaults and env vars
		} else {
			if err := yaml.Unmarshal(data, cfg); err != nil {
				return nil, fmt.Errorf("failed to parse config file: %w", err)
			}
		}
	}

	// Override with environment variables (highest priority)
	// Since we removed `default:` tags, this only applies actual env vars
	if err := envconfig.Process("WALLET", cfg); err != nil {
		return nil, fmt.Errorf("failed to process environment variables: %w", err)
	}

	// Load secrets from files if configured
	if err := cfg.loadSecretsFromFiles(); err != nil {
		return nil, fmt.Errorf("failed to load secrets from files: %w", err)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Set BaseURL if not provided
	if cfg.Server.BaseURL == "" {
		cfg.Server.BaseURL = fmt.Sprintf("http://%s:%d", cfg.Server.Host, cfg.Server.Port)
	}

	// Ensure CORS has defaults
	cfg.Server.CORS.SetDefaults()

	return cfg, nil
}

// loadSecretsFromFiles loads secrets from file paths.
// This allows sensitive values like JWT secrets and admin tokens to be stored
// in separate files (e.g., mounted Kubernetes secrets) rather than in the
// main configuration file or environment variables.
func (c *Config) loadSecretsFromFiles() error {
	var err error

	// Load admin token from file
	if c.Server.AdminTokenPath != "" {
		c.Server.AdminToken, err = readSecretFile(c.Server.AdminTokenPath)
		if err != nil {
			return fmt.Errorf("admin_token_path: %w", err)
		}
	}

	// Load JWT secret from file
	if c.JWT.SecretPath != "" {
		c.JWT.Secret, err = readSecretFile(c.JWT.SecretPath)
		if err != nil {
			return fmt.Errorf("jwt.secret_path: %w", err)
		}
	}

	// Load MongoDB password from file and inject into URI
	if c.Storage.MongoDB.PasswordPath != "" {
		password, err := readSecretFile(c.Storage.MongoDB.PasswordPath)
		if err != nil {
			return fmt.Errorf("storage.mongodb.password_path: %w", err)
		}
		// Replace %PASSWORD% placeholder in URI (no-op if not present)
		c.Storage.MongoDB.URI = strings.Replace(c.Storage.MongoDB.URI, "%PASSWORD%", password, 1)
	}

	return nil
}

// readSecretFile reads a secret value from a file, trimming whitespace.
// Returns an error if the file cannot be read or is empty.
func readSecretFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read file %s: %w", path, err)
	}
	secret := strings.TrimSpace(string(data))
	if secret == "" {
		return "", fmt.Errorf("file %s is empty", path)
	}
	return secret, nil
}

// defaultConfig returns a Config with sensible default values
func defaultConfig() *Config {
	corsConfig := CORSConfig{}
	corsConfig.SetDefaults()

	return &Config{
		Server: ServerConfig{
			Host:         "0.0.0.0",
			Port:         8080,
			AdminPort:    8081, // Internal admin API port
			EnginePort:   8082, // WebSocket engine port
			RegistryPort: 8097, // VCTM registry port
			RPID:         "localhost",
			RPOrigin:     "http://localhost:8080",
			RPOrigins:    nil,
			RPName:       "Wallet Backend",
			CORS:         corsConfig,
		},
		Storage: StorageConfig{
			Type: "memory",
			SQLite: SQLiteConfig{
				Path: "wallet.db",
			},
			MongoDB: MongoDBConfig{
				URI:      "mongodb://localhost:27017",
				Database: "wallet",
				Timeout:  10,
			},
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
		},
		JWT: JWTConfig{
			ExpiryHours: 24,
			RefreshDays: 7,
			Issuer:      "wallet-backend",
		},
		Trust: TrustConfig{
			Timeout: 30, // seconds
		},
		SessionStore: SessionStoreConfig{
			Type:            "memory",
			DefaultTTLHours: 24,
			Redis: RedisConfig{
				Address:   "localhost:6379",
				KeyPrefix: "ws:session:",
			},
		},
		Features: FeaturesConfig{
			ProxyEnabled:             true,  // Default: proxy enabled for backward compatibility
			WebSocketRequired:        false, // Default: proxy still allowed
			CredentialStorageEnabled: false, // Default: server-side credential storage disabled
		},
		Security: SecurityConfig{
			AuthRateLimit: AuthRateLimitConfig{
				Enabled:        true,
				MaxAttempts:    10,
				WindowSeconds:  60,
				LockoutSeconds: 300,
			},
			AAGUIDBlacklist: AAGUIDBlacklistConfig{
				Enabled:       false, // Disabled by default
				AAGUIDs:       []string{},
				RejectUnknown: false,
			},
			ChallengeCleanup: ChallengeCleanupConfig{
				Enabled:         true, // Enabled by default to prevent storage leaks
				IntervalSeconds: 300,
			},
			TokenBlacklist: TokenBlacklistConfig{
				Enabled:                true, // Enabled by default for security
				CleanupIntervalSeconds: 3600,
			},
		},
		HTTPClient: HTTPClientConfig{
			Timeout: 30, // 30 seconds default
			// AllowPrivateIPs defaults to false — SSRF protection blocks private/loopback IPs.
			// Set allow_private_ips: true in config when issuers are on internal networks.
		},
		AuthZENProxy: AuthZENProxyConfig{
			Enabled:         true, // Enabled by default - required for engine flows
			AllowResolution: true, // Allow DID/metadata resolution by default
			Timeout:         30,
		},
		AS: ASConfig{
			DefaultTokenTTL: 2 * time.Minute,
			Legacy: ASLegacyConfig{
				Enabled:           true,  // Legacy tokens accepted by default
				DeprecationHeader: false, // No deprecation headers until explicitly enabled
			},
		},
		WalletProvider: WalletProviderConfig{
			WIA: WIAConfig{
				Enabled:             true,
				WalletName:          "SIROS ID",
				MaxExpirySeconds:    86400,
				ChallengeTTLSeconds: 300,
			},
			Attestation: AttestationConfig{
				LifetimeSeconds: 3600,
				KAExpirySeconds: 15,
				StatusListMode:  "never",
			},
		},
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}

	// Validate wallet-provider port when explicitly configured
	if c.Server.WPPort != 0 && (c.Server.WPPort < 1 || c.Server.WPPort > 65535) {
		return fmt.Errorf("invalid wallet-provider port: %d", c.Server.WPPort)
	}
	// WPHost defaults to Host when empty, so treat empty as equivalent
	effectiveWPHost := c.Server.WPHost
	if effectiveWPHost == "" {
		effectiveWPHost = c.Server.Host
	}
	if c.Server.WPPort != 0 && c.Server.WPPort == c.Server.Port && effectiveWPHost == c.Server.Host {
		return fmt.Errorf("wallet-provider port %d conflicts with main server port on the same host", c.Server.WPPort)
	}

	if c.Server.RPID == "" {
		return fmt.Errorf("rp_id is required")
	}

	if len(c.Server.GetRPOrigins()) == 0 {
		return fmt.Errorf("rp_origin or rp_origins is required")
	}

	// Validate TLS configuration
	if c.Server.TLS.Enabled {
		if c.Server.TLS.CertFile == "" {
			return fmt.Errorf("server.tls.cert_file is required when TLS is enabled")
		}
		if c.Server.TLS.KeyFile == "" {
			return fmt.Errorf("server.tls.key_file is required when TLS is enabled")
		}
	}

	// Validate admin TLS configuration (if explicitly set)
	if c.Server.AdminTLS != nil && c.Server.AdminTLS.Enabled {
		if c.Server.AdminTLS.CertFile == "" {
			return fmt.Errorf("server.admin_tls.cert_file is required when admin TLS is enabled")
		}
		if c.Server.AdminTLS.KeyFile == "" {
			return fmt.Errorf("server.admin_tls.key_file is required when admin TLS is enabled")
		}
	}

	// Storage type validation
	switch c.Storage.Type {
	case "memory", "mongodb":
		// Supported storage types
	case "sqlite":
		return fmt.Errorf("sqlite storage is not yet implemented - please use 'memory' or 'mongodb'")
	default:
		return fmt.Errorf("invalid storage type: %s (must be memory or mongodb)", c.Storage.Type)
	}

	if c.Storage.Type == "mongodb" && c.Storage.MongoDB.URI == "" {
		return fmt.Errorf("mongodb uri is required when using mongodb storage")
	}

	// Validate MongoDB mTLS configuration
	if c.Storage.MongoDB.CertPath != "" && c.Storage.MongoDB.KeyPath == "" {
		return fmt.Errorf("mongodb.key_path is required when mongodb.cert_path is set")
	}
	if c.Storage.MongoDB.KeyPath != "" && c.Storage.MongoDB.CertPath == "" {
		return fmt.Errorf("mongodb.cert_path is required when mongodb.key_path is set")
	}

	if c.JWT.Secret == "" {
		return fmt.Errorf("jwt secret is required")
	}

	// Validate CORS: AllowCredentials cannot be true with wildcard origins
	if c.Server.CORS.AllowCredentials {
		for _, origin := range c.Server.CORS.AllowedOrigins {
			if origin == "*" {
				return fmt.Errorf("CORS: allow_credentials cannot be true when allowed_origins contains '*'")
			}
		}
	}

	// Validate AS configuration
	if c.AS.Enabled {
		if c.AS.SigningKeyPath == "" && c.AS.SigningKeyPKCS11 == "" {
			return fmt.Errorf("as: signing_key_path or signing_key_pkcs11 is required when AS is enabled")
		}
		if c.AS.SigningKeyPath != "" && c.AS.SigningKeyPKCS11 != "" {
			return fmt.Errorf("as: signing_key_path and signing_key_pkcs11 are mutually exclusive")
		}
		if c.AS.SigningKeyPKCS11 != "" {
			return fmt.Errorf("as: signing_key_pkcs11 is not yet implemented; use signing_key_path")
		}
		if c.AS.RulesDir == "" {
			return fmt.Errorf("as: rules_dir is required when AS is enabled (AllowAll is not safe for production)")
		}
		if c.AS.DefaultTokenTTL < 0 {
			return fmt.Errorf("as: default_token_ttl must be positive")
		}
		if c.AS.SessionTTL < 0 {
			return fmt.Errorf("as: session_ttl must be positive")
		}
		for aud, ttl := range c.AS.AudienceTTLs {
			if ttl <= 0 {
				return fmt.Errorf("as: audience_ttls[%q] must be positive", aud)
			}
		}
		if c.AS.DefaultMaxTAC != "" {
			for i := range c.AS.DefaultMaxTAC {
				ch := c.AS.DefaultMaxTAC[i]
				switch ch {
				case 'r', 'w', 'l', 'i', 'd', 'k', 'a':
					// valid
				default:
					return fmt.Errorf("as: default_max_tac contains invalid character %q", ch)
				}
			}
		}
		c.AS.SetDefaults()
		// Default issuer to JWT.Issuer if not explicitly set.
		if c.AS.Issuer == "" {
			c.AS.Issuer = c.JWT.Issuer
		}
		if c.AS.Issuer == "" {
			return fmt.Errorf("as: issuer is required (set as.issuer or jwt.issuer)")
		}
	}

	return nil
}

// Address returns the server address
func (c *ServerConfig) Address() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// AdminAddress returns the admin server address
func (c *ServerConfig) AdminAddress() string {
	host := c.AdminHost
	if host == "" {
		host = c.Host
	}
	return fmt.Sprintf("%s:%d", host, c.AdminPort)
}

// EngineAddress returns the engine server address
func (c *ServerConfig) EngineAddress() string {
	host := c.EngineHost
	if host == "" {
		host = c.Host
	}
	port := c.EnginePort
	if port == 0 {
		port = c.Port // fallback to main port for backward compatibility
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// RegistryAddress returns the registry server address
func (c *ServerConfig) RegistryAddress() string {
	host := c.RegistryHost
	if host == "" {
		host = c.Host
	}
	port := c.RegistryPort
	if port == 0 {
		port = 8097 // default registry port
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// ResolvedServedBy returns the resolved X-Served-By header value.
// Returns the system hostname if not configured, the configured value if set,
// or empty string if explicitly set to "" (disabled).
func (c *ServerConfig) ResolvedServedBy() string {
	if c.ServedByHeader == nil {
		h, err := os.Hostname()
		if err != nil {
			return "unknown"
		}
		return h
	}
	return *c.ServedByHeader
}
