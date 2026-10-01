package config

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math"
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
	Audit          AuditConfig          `yaml:"audit" envconfig:"AUDIT"`
	Presentation   PresentationConfig   `yaml:"presentation" envconfig:"PRESENTATION"`

	// asEnabledExplicit records whether as.enabled was explicitly present in
	// the YAML file or environment (as opposed to defaulting to its bool
	// zero-value, false) - set by Load(), consumed by EnableForRole() so it
	// can tell "operator explicitly disabled AS" apart from "AS section
	// never configured". Unexported: never (un)marshaled, so it can't leak
	// into YAML output or be set by config files/env itself.
	asEnabledExplicit bool
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
	// Required when AS is enabled, but an empty list is filled with the
	// documented defaults ("wallet-backend", "wallet-engine",
	// "wallet-registry", plus server.rp_id while as.legacy.enabled is true)
	// before validation, so configs that never set it keep working.
	// Validate() rejects an empty list only if that defaulting was skipped.
	// go-tokenauth v0.5.0 made this mandatory at the validator level too
	// (both its validation paths now refuse to validate at all when their
	// own configured Audiences is empty, closing a fail-open
	// audience-confusion gap - a deployment upgraded past that version
	// with no audiences configured would otherwise reject every request
	// silently at runtime instead of failing to start).
	// Documented values: "wallet-backend", "wallet-engine", "wallet-registry".
	// When as.legacy.enabled is true an explicitly configured list must ALSO
	// include server.rp_id: legacy (HMAC) tokens carry the RP ID as their
	// audience, and Validate() rejects a configuration that omits it.
	Audiences []string `yaml:"audiences" envconfig:"AUDIENCES"`

	// RulesDir is the path to a directory containing SPOCP policy rule files.
	RulesDir string `yaml:"rules_dir" envconfig:"RULES_DIR"`

	// SessionTTL is the maximum session lifetime before re-authentication.
	// Default: 24h
	SessionTTL time.Duration `yaml:"session_ttl" envconfig:"SESSION_TTL"`

	// SessionStore selects where AS sessions (the cookie-bound server-side
	// sessions that mint access tokens) are kept: "mongodb", "memory" or
	// "auto". "auto" (the default when empty) means "mongodb" when the
	// storage backend is MongoDB and "memory" otherwise. Memory sessions are
	// lost on restart and are not shared between instances; use "mongodb" for
	// high availability.
	SessionStore string `yaml:"session_store" envconfig:"SESSION_STORE"`

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

// defaultASRulesDir is where EnableForRole expects the baseline SPOCP
// policy to ship inside the container image (see rules/, copied here by
// the Dockerfile). It's a var, not a const, so a packager whose filesystem
// layout doesn't match the container's (e.g. a .deb following FHS) can
// override it at build time without patching this file:
//
//	go build -ldflags "-X github.com/sirosfoundation/go-wallet-backend/pkg/config.defaultASRulesDir=/usr/share/go-wallet-backend/rules"
var defaultASRulesDir = "/app/rules"

// EnableForRole turns on the AS for deployments that request the "auth" role
// (including via --mode=all), and fills in defaults for anything left
// unconfigured. There is no separate AS-specific key or policy to configure:
// it reuses the wallet provider's own signing key (when file-based - see the
// PKCS11 note below), since every deployment already configures one for
// WIA/Key Attestation, and falls back to the baseline policy bundled in the
// image (see rules/, copied to /app/rules by the Dockerfile) rather than
// requiring a deployment-specific RulesDir - a role flag alone should be
// enough to turn AS on, matching how every other role works.
//
// An operator's explicit as.enabled: false always wins and skips all of the
// above - relies on Config.asEnabledExplicit (set by Load()) rather than
// c.AS.Enabled itself, since a plain bool can't distinguish "explicitly set
// to false" from "never configured" (both are the zero value). An explicit
// as.enabled: true does NOT skip defaulting here - it's treated the same as
// "unconfigured" by this function's own logic.
//
// That said, `as: {enabled: true}` alone in a YAML file does NOT actually
// work end-to-end via the normal startup path: Load() calls Validate()
// before cmd/server/main.go ever calls EnableForRole(), and Validate()
// unconditionally requires signing_key_path/rules_dir whenever AS.Enabled is
// true - so Load() itself rejects that YAML before this function gets a
// chance to fill in the defaults. This function's explicit-true handling
// only matters for callers that construct/mutate a Config without going
// through Load()'s validation first.
func (c *Config) EnableForRole() {
	if c.asEnabledExplicit && !c.AS.Enabled {
		return
	}
	c.AS.Enabled = true
	// Auto-enable can only inherit the wallet provider's signing key when
	// the wallet provider is purely file-based - never when PKCS11 is
	// configured for it, even if PrivateKeyPath is ALSO set as a runtime
	// fallback (WalletProviderService tries PKCS11 first, independently of
	// whether a file key is also configured). Inheriting the file path
	// there would silently sign AS tokens with the weaker on-disk key while
	// the wallet provider itself actually signs WIA/KA with the HSM key -
	// a real, silent security downgrade, not just an unsupported
	// configuration. AS's own PKCS11 signing is not implemented (see
	// Validate()), so this deliberately leaves SigningKeyPath empty in that
	// case; Validate() then rejects with a clear, actionable error rather
	// than silently limping along with AS enabled on the wrong key.
	walletProviderUsesPKCS11 := c.WalletProvider.PKCS11 != nil && c.WalletProvider.PKCS11.ModulePath != ""
	if c.AS.SigningKeyPath == "" && c.AS.SigningKeyPKCS11 == "" && !walletProviderUsesPKCS11 {
		c.AS.SigningKeyPath = c.WalletProvider.PrivateKeyPath
	}
	if c.AS.RulesDir == "" {
		// Baseline policy (read-only always allowed, own-tenant access for
		// any tac) every deployment gets unless it configures its own.
		c.AS.RulesDir = defaultASRulesDir
	}
	c.AS.SetDefaults()
	if c.AS.Issuer == "" {
		c.AS.Issuer = c.JWT.Issuer
	}
	c.applyASSecurityDefaults()
}

// defaultASAudiences is the documented default for as.audiences.
var defaultASAudiences = []string{"wallet-backend", "wallet-engine", "wallet-registry"}

// defaultJWTIssuer is the documented default for jwt.issuer (see defaultConfig).
const defaultJWTIssuer = "wallet-backend"

// applyASSecurityDefaults fills in the documented defaults for the settings
// Validate() makes mandatory whenever the AS is enabled, so that existing
// deployments that never set them (e.g. the siros-id-stack chart renders
// `as.enabled: true` with no `audiences`) keep starting. It is a no-op when
// the AS is disabled, and never overrides an explicitly configured value.
//
// Shared by Load() (which must run it BEFORE Validate()) and EnableForRole()
// so both paths produce an identical result.
//
//   - as.audiences empty: the documented default set, plus server.rp_id while
//     legacy (HMAC) tokens are enabled (they carry the RP ID as "aud").
//   - jwt.issuer empty while legacy tokens are enabled: "wallet-backend".
func (c *Config) applyASSecurityDefaults() {
	if !c.AS.Enabled {
		return
	}
	if len(c.AS.Audiences) == 0 {
		c.AS.Audiences = append([]string(nil), defaultASAudiences...)
		if c.AS.Legacy.Enabled && c.Server.RPID != "" && !containsString(c.AS.Audiences, c.Server.RPID) {
			c.AS.Audiences = append(c.AS.Audiences, c.Server.RPID)
		}
	}
	if c.AS.Legacy.Enabled && c.JWT.Issuer == "" {
		c.JWT.Issuer = defaultJWTIssuer
	}
}

// GetTokenTTL returns the TTL for a given audience, falling back to the default.
func (c *ASConfig) GetTokenTTL(audience string) time.Duration {
	if ttl, ok := c.AudienceTTLs[audience]; ok {
		return ttl
	}
	return c.DefaultTokenTTL
}

// DCQLConsentCheckMode selects how the engine treats a consent that does not
// fit the DCQL query the backend sent to the client.
type DCQLConsentCheckMode string

const (
	// DCQLConsentCheckOff performs no comparison.
	DCQLConsentCheckOff DCQLConsentCheckMode = "off"
	// DCQLConsentCheckWarn (the default) logs a structured warning naming the
	// reason class and query id, and proceeds.
	DCQLConsentCheckWarn DCQLConsentCheckMode = "warn"
	// DCQLConsentCheckEnforce refuses the presentation before any signing:
	// the verifier gets access_denied and the client a PRESENTATION_ERROR.
	DCQLConsentCheckEnforce DCQLConsentCheckMode = "enforce"
)

// Effective returns the mode to apply, treating the zero value as the default.
func (m DCQLConsentCheckMode) Effective() DCQLConsentCheckMode {
	if m == "" {
		return DCQLConsentCheckWarn
	}
	return m
}

func (m DCQLConsentCheckMode) validate() error {
	switch m.Effective() {
	case DCQLConsentCheckOff, DCQLConsentCheckWarn, DCQLConsentCheckEnforce:
		return nil
	}
	return fmt.Errorf("invalid presentation.dcql_consent_check %q: must be one of off, warn, enforce", string(m))
}

// PresentationConfig controls checks the engine applies to what the wallet is
// about to present in an OpenID4VP flow.
type PresentationConfig struct {
	// DCQLConsentCheck compares the user's consent (selected credential query
	// ids and disclosed claims) with the DCQL query the backend sent to the
	// client, before any signing. The frontend is not trusted to have
	// honoured the query. Values: `off` (no check);
	// `warn` (default: log a warning with the reason class and query id, never
	// refuse; claim-path matching can disagree with a real verifier's
	// notion of a path, so a deployer opts into enforcement);
	// `enforce` (refuse with PRESENTATION_ERROR and answer the verifier
	// access_denied, without signing). Nothing about claim names or values is
	// logged. Not enforced: credential_sets satisfaction (only that no query
	// outside every option is selected), `values` constraints, and the
	// contents of the resulting vp_token. Unknown values fail at startup.
	// Env: WALLET_PRESENTATION_DCQL_CONSENT_CHECK
	DCQLConsentCheck DCQLConsentCheckMode `yaml:"dcql_consent_check" envconfig:"DCQL_CONSENT_CHECK"`
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
	// AllowHTTP permits non-TLS (plain HTTP) for every fetch that goes through
	// the client this configuration builds - request objects, issuer and
	// verifier metadata, JWKS, logos, registry and proxy calls - not only for
	// metadata resolution, which was its scope while the resolver was the sole
	// consumer. Code that builds its own client rather than taking this one is
	// not governed by it; see NewHTTPClient for which paths those are.
	// Default: false (HTTPS required). Use only for local development.
	// It is not the only setting that permits plaintext: see AllowsPlaintext,
	// which is what every check in the codebase actually consults.
	// Env: WALLET_HTTP_CLIENT_ALLOW_HTTP
	AllowHTTP bool `yaml:"allow_http" envconfig:"ALLOW_HTTP"`
	// TrustedIdPHosts lists hostnames of operator-configured OIDC identity
	// providers that may resolve to private/loopback/link-local addresses.
	// It applies only to the client NewIdPHTTPClient builds (the AS's OIDC
	// discovery, token exchange and JWKS fetches), never to the client used
	// for issuers, verifiers and other counterparties. Matching is by exact,
	// case-insensitive hostname of every request, redirect hops and the
	// token_endpoint/jwks_uri named by a discovery document included, so a
	// discovery document cannot steer the request to an unlisted internal
	// host. Cloud metadata endpoints stay blocked regardless.
	// Only the wallet server's AS reads this setting; the registry has no
	// identity-provider client and ignores it.
	// Env: WALLET_HTTP_CLIENT_TRUSTED_IDP_HOSTS (comma-separated)
	TrustedIdPHosts []string `yaml:"trusted_idp_hosts" envconfig:"TRUSTED_IDP_HOSTS"`
}

// NewHTTPClient creates an *http.Client from the configuration, applying proxy,
// timeout, and TLS settings. If timeoutOverride > 0 it is used instead of the
// configured timeout. A zero-value HTTPClientConfig produces a sensible default
// (30 s timeout, system proxy, TLS verification enabled).
//
// When AllowPrivateIPs is false, two guards apply to every request this client
// makes, including each hop of a redirect. Both exist because much of what this
// backend fetches is addressed by whoever it is talking to: a verifier picks
// the request_uri the wallet dereferences, an issuer picks its metadata URLs.
//
//   - a dialer that refuses private, loopback, link-local and cloud metadata
//     addresses, and then connects to an address it checked;
//   - plain HTTP is refused unless AllowsPlaintext says otherwise, so a fetch
//     cannot be downgraded to a network any observer on the path can read or
//     rewrite.
//
// Both guards reach only what is fetched through this client. internal/as's
// OIDC discovery and token exchange use NewIdPHTTPClient, which applies the
// same policy but lets the operator's TrustedIdPHosts sit on private
// addresses.
//
// internal/service.HelperService.GetCertificateChain also dials TLS directly
// rather than through an http.Client (it reads a certificate chain off a
// manual handshake), but it is not exempt: it applies the address half of
// this same policy via GuardedDialContext, since it has no http.Client for
// this method's own guard to attach to.
//
// When a proxy is in use the dialer only ever sees the proxy, so the address
// policy is applied to the request's own host before it is sent. That check is
// best effort by nature: the proxy resolves the name itself and may reach an
// address this process never saw. A deployment that relies on an egress proxy
// should enforce its own egress policy there.
func (c HTTPClientConfig) NewHTTPClient(timeoutOverride time.Duration) *http.Client {
	return c.newHTTPClient(timeoutOverride, nil)
}

// NewIdPHTTPClient is NewHTTPClient for talking to the operator's OIDC
// identity providers: the same address and scheme policy, except that the
// hostnames in TrustedIdPHosts may resolve to private addresses. Use it for
// the AS's OIDC discovery, token exchange and JWKS fetches, and nothing that
// dials a host a counterparty chose.
func (c HTTPClientConfig) NewIdPHTTPClient(timeoutOverride time.Duration) *http.Client {
	return c.newHTTPClient(timeoutOverride, c.trustedIdPHostSet())
}

// trustedIdPHostSet returns TrustedIdPHosts as a lowercase set, or nil.
func (c HTTPClientConfig) trustedIdPHostSet() map[string]struct{} {
	if len(c.TrustedIdPHosts) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(c.TrustedIdPHosts))
	for _, h := range c.TrustedIdPHosts {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			set[h] = struct{}{}
		}
	}
	return set
}

func (c HTTPClientConfig) newHTTPClient(timeoutOverride time.Duration, trustedHosts map[string]struct{}) *http.Client {
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

	var roundTripper http.RoundTripper = transport

	if !c.AllowPrivateIPs {
		baseDialer := &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		transport.DialContext = guardedDial(defaultLookupIP, baseDialer.DialContext, trustedHosts)
		roundTripper = ssrfGuard{
			base:      transport,
			proxy:     transport.Proxy,
			lookup:    defaultLookupIP,
			httpsOnly: !c.AllowsPlaintext(),
			trusted:   trustedHosts,
		}
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: roundTripper,
	}
}

// GuardedDialContext returns a dial function applying the same address policy
// as NewHTTPClient's transport (private/loopback/link-local/cloud-metadata
// blocked unless AllowPrivateIPs, dialing the address it checked rather than
// re-resolving), for a caller that needs a raw net.Conn rather than an
// *http.Client - e.g. HelperService.GetCertificateChain, which reads a
// certificate chain off a manual TLS handshake and so has no http.Client for
// NewHTTPClient's guard to attach to. When AllowPrivateIPs is set, this
// returns a plain, unchecked dial, matching NewHTTPClient's own behavior.
func (c HTTPClientConfig) GuardedDialContext() func(ctx context.Context, network, addr string) (net.Conn, error) {
	baseDialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	if c.AllowPrivateIPs {
		return baseDialer.DialContext
	}
	return guardedDial(defaultLookupIP, baseDialer.DialContext, nil)
}

// AllowsPlaintext reports whether this configuration permits non-TLS (plain
// HTTP) requests. Three settings say so, and they are consulted together
// everywhere the policy is applied - this transport, the issuer metadata
// resolver's URL validation, the AuthZEN proxy - so that a URL one layer
// accepts is not refused by the next:
//
//   - AllowHTTP, which says it directly;
//   - AllowPrivateIPs, because a deployment reaching its own network is
//     already reaching services that terminate no TLS, the in-process
//     registry among them (http://localhost:<registry_port>);
//   - InsecureSkipVerify, which the provider wiring has always folded into
//     AllowHTTP: a deployment that has given up certificate verification
//     altogether is not the one a scheme check is protecting.
func (c HTTPClientConfig) AllowsPlaintext() bool {
	return c.AllowHTTP || c.AllowPrivateIPs || c.InsecureSkipVerify
}

// lookupFunc resolves a host to its addresses. Named so guardedDial can be
// driven without a resolver in tests.
type lookupFunc func(ctx context.Context, host string) ([]net.IP, error)

// dialFunc opens a connection to an address, as net.Dialer.DialContext does.
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

func defaultLookupIP(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

// guardedDial wraps dial so that it refuses to reach the deployment's own
// network: private, loopback and link-local ranges, and the cloud metadata
// endpoints on top of them.
//
// It connects to an address it checked rather than handing the hostname back
// to the dialer, which would resolve it a second time. That second lookup is
// the hole: a DNS server under the requester's control can answer with a
// public address for the check and an internal one a moment later for the
// connection, and the guard above would have inspected an address that is
// never dialled.
//
// trusted names hosts (lowercase) that may resolve to private ranges; see
// HTTPClientConfig.TrustedIdPHosts. The metadata endpoints stay blocked.
func guardedDial(lookup lookupFunc, dial dialFunc, trusted map[string]struct{}) dialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid address %q: %w", addr, err)
		}
		ips, err := lookup(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("DNS lookup failed for %s: %w", host, err)
		}
		if err := checkAddressesFor(host, ips, trusted); err != nil {
			return nil, err
		}

		// Every address was checked above, so any of them is safe to use.
		candidates := make([]string, 0, len(ips))
		for _, ip := range ips {
			if matchesNetwork(network, ip) {
				candidates = append(candidates, net.JoinHostPort(ip.String(), port))
			}
		}
		if len(candidates) == 0 {
			return nil, fmt.Errorf("no %s address found for %s", network, host)
		}
		return dialCandidates(ctx, dial, network, candidates)
	}
}

// dialFallbackDelay is how long one connection attempt is given on its own
// before the next checked address is tried alongside it.
const dialFallbackDelay = 300 * time.Millisecond

// dialCandidates connects to the first of addrs that answers.
//
// The attempts are staggered rather than strictly serial, which is what
// net.Dialer does for a hostname it resolved itself (RFC 6555, "Happy
// Eyeballs"). Dialing one after another instead would let a single black-holed
// address - a dead IPv6 route, most often - hold the whole request for the
// dialer's full timeout before the working address is ever tried. That
// behaviour comes free when the dialer is handed a name, and is lost here
// precisely because this dials addresses it has checked.
func dialCandidates(ctx context.Context, dial dialFunc, network string, addrs []string) (net.Conn, error) {
	if len(addrs) == 1 {
		return dial(ctx, network, addrs[0])
	}

	ctx, cancel := context.WithCancel(ctx)
	// Returning cancels whatever is still in flight. A connection that is
	// already established is not affected by its dial context being cancelled.
	defer cancel()

	type attempt struct {
		conn net.Conn
		err  error
	}
	results := make(chan attempt, len(addrs))

	// closeLate consumes the attempts still outstanding when a winner has been
	// picked, so a connection that completes just after the race is closed
	// rather than left open.
	closeLate := func(outstanding int) {
		go func() {
			for i := 0; i < outstanding; i++ {
				if a := <-results; a.conn != nil {
					_ = a.conn.Close()
				}
			}
		}()
	}

	timer := time.NewTimer(0)
	defer timer.Stop()

	var firstErr error
	started, pending := 0, 0
	for started < len(addrs) || pending > 0 {
		var nextAttempt <-chan time.Time
		if started < len(addrs) {
			nextAttempt = timer.C
		}

		select {
		case <-ctx.Done():
			closeLate(pending)
			if firstErr == nil {
				firstErr = ctx.Err()
			}
			return nil, firstErr

		case <-nextAttempt:
			addr := addrs[started]
			started++
			pending++
			go func() {
				conn, err := dial(ctx, network, addr)
				results <- attempt{conn: conn, err: err}
			}()
			if started < len(addrs) {
				timer.Reset(dialFallbackDelay)
			}

		case a := <-results:
			pending--
			if a.err == nil {
				closeLate(pending)
				return a.conn, nil
			}
			if firstErr == nil {
				firstErr = a.err
			}
		}
	}

	if firstErr == nil {
		firstErr = fmt.Errorf("no address could be dialled")
	}
	return nil, firstErr
}

// matchesNetwork reports whether ip can be dialled on the requested network.
// "tcp" (and anything else) takes either family; "tcp4" and "tcp6" do not.
func matchesNetwork(network string, ip net.IP) bool {
	switch network {
	case "tcp4", "udp4", "ip4":
		return ip.To4() != nil
	case "tcp6", "udp6", "ip6":
		return ip.To4() == nil
	default:
		return true
	}
}

// checkAddresses applies the address policy: nothing that would reach the
// deployment's own network, and the cloud metadata endpoints named separately
// so the refusal says which rule was hit.
func checkAddresses(host string, ips []net.IP) error {
	return checkAddressesFor(host, ips, nil)
}

// checkAddressesFor is checkAddresses, except that a host in trusted is
// allowed private, loopback and link-local addresses. Cloud metadata
// endpoints and unspecified addresses are refused for every host.
func checkAddressesFor(host string, ips []net.IP, trusted map[string]struct{}) error {
	_, isTrusted := trusted[strings.ToLower(host)]
	if len(ips) == 0 {
		return fmt.Errorf("no addresses found for %s", host)
	}
	for _, ip := range ips {
		// Block cloud metadata endpoints (169.254.169.254, fd00::1)
		// before the generic private/link-local check for a clearer message.
		if ip.Equal(net.ParseIP("169.254.169.254")) || ip.Equal(net.ParseIP("fd00::1")) {
			return fmt.Errorf("connection to cloud metadata endpoint %s (%s) is not allowed", host, ip)
		}
		if !isTrusted && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()) {
			return fmt.Errorf("connection to %s (%s) is not allowed: private/loopback address", host, ip)
		}
		// 0.0.0.0 / :: name no real destination, but connect() on Linux (and
		// most other stacks) treats an unspecified destination address as
		// loopback - so left unchecked, this is a plain loopback bypass, not
		// merely a theoretical gap.
		if ip.IsUnspecified() {
			return fmt.Errorf("connection to %s (%s) is not allowed: unspecified address", host, ip)
		}
	}
	return nil
}

// ssrfGuard is the half of the protection that has to sit above the transport
// rather than in its dialer.
//
// The scheme is only visible here, and this is the layer every hop of a
// redirect chain passes through: a fetch that starts at https:// can be sent
// anywhere by a 302, and the URL it lands on is no more trusted than the one
// it started from.
//
// A proxied request needs the address policy applied here too. http.Transport
// dials the proxy, not the target - for https the target travels in a CONNECT
// and never reaches the dialer at all - so without this a configured or
// ambient (HTTP_PROXY, HTTPS_PROXY) proxy would quietly forward exactly the
// requests the dialer exists to refuse. The check is weaker than the dialer's:
// the proxy resolves the name itself, so it can reach an address this process
// never saw, which is why it is done only where the dialer cannot see.
type ssrfGuard struct {
	base      http.RoundTripper
	proxy     func(*http.Request) (*url.URL, error)
	lookup    lookupFunc
	httpsOnly bool
	trusted   map[string]struct{}
}

func (g ssrfGuard) RoundTrip(req *http.Request) (*http.Response, error) {
	if g.httpsOnly && req.URL.Scheme != "https" {
		// Naming all three keys AllowsPlaintext consults, since an operator
		// who reads only one of them is told to change a setting that may
		// already be set. insecure_skip_verify is listed last and with the
		// warning it deserves: it permits plaintext as a side effect of
		// giving up certificate verification, which is not a reason to set it.
		return nil, fmt.Errorf("refusing to send a %s request to %q: this client allows https only "+
			"(set http_client.allow_http, or http_client.allow_private_ips for an internal deployment; "+
			"http_client.insecure_skip_verify also permits plaintext, but do not enable it for that)",
			req.URL.Scheme, req.URL.Host)
	}

	if g.proxied(req) {
		host := req.URL.Hostname()
		ips, err := g.lookup(req.Context(), host)
		if err != nil {
			return nil, fmt.Errorf("DNS lookup failed for %s: %w", host, err)
		}
		if err := checkAddressesFor(host, ips, g.trusted); err != nil {
			return nil, err
		}
	}

	return g.base.RoundTrip(req)
}

// proxied reports whether this request would be sent through a proxy, and so
// whether the dialer below will see the proxy's address instead of the
// target's.
func (g ssrfGuard) proxied(req *http.Request) bool {
	if g.proxy == nil {
		return false
	}
	proxyURL, err := g.proxy(req)
	return err == nil && proxyURL != nil
}

// ServerConfig contains HTTP server configuration
type ServerConfig struct {
	Host       string `yaml:"host" envconfig:"HOST"`
	Port       int    `yaml:"port" envconfig:"PORT"`
	AdminHost  string `yaml:"admin_host" envconfig:"ADMIN_HOST"`   // Admin API bind address (defaults to Host)
	AdminPort  int    `yaml:"admin_port" envconfig:"ADMIN_PORT"`   // Internal admin API port (0 to disable)
	EngineHost string `yaml:"engine_host" envconfig:"ENGINE_HOST"` // WebSocket engine bind address (defaults to Host)
	EnginePort int    `yaml:"engine_port" envconfig:"ENGINE_PORT"` // WebSocket engine port (defaults to Port if 0)
	// TrustedProxies lists the proxy addresses or CIDRs whose X-Forwarded-For
	// (and X-Real-IP) headers are believed when determining the client IP,
	// which the per-IP rate limits depend on. Use ["none"] to trust no proxy
	// (the client IP is then the TCP peer, which is right when clients connect
	// directly).
	// BACKWARDS COMPATIBILITY: when unset, gin's original behaviour is kept and
	// every peer is trusted. That lets any direct caller choose its own client
	// IP by sending X-Forwarded-For, so the per-IP limits can be bypassed (the
	// per-tenant limit still holds), and a warning is logged at startup while
	// per-IP limiting is enabled. It stays the default so an upgrade does not
	// put every client behind a load balancer into one rate-limit bucket.
	// Production deployments should set this: to the load balancer's addresses
	// behind one, or ["none"] without one.
	// Env: WALLET_SERVER_TRUSTED_PROXIES (comma-separated)
	TrustedProxies []string `yaml:"trusted_proxies" envconfig:"TRUSTED_PROXIES"`
	// EngineWSPingInterval is how often the server sends a WebSocket ping to
	// the client, and (via HandshakeCompleteMessage.Config) the interval the
	// client is told to use for its own pings - see that message's doc
	// comment for why both directions need to agree on this rather than
	// each hardcoding its own guess. Defaults to 3s: found empirically (raw
	// idle-TLS-connection tests against production Fly.io apps, not
	// documentation - Fly's own docs don't state a number) that Fly.io's
	// edge closes a connection with no traffic on it after ~5-6s, far
	// sooner than the 30s this used to be hardcoded to, which is why every
	// engine WebSocket on Fly was silently reconnecting every few seconds.
	// Deployments behind a more permissive proxy/LB can raise this.
	EngineWSPingInterval time.Duration `yaml:"engine_ws_ping_interval" envconfig:"ENGINE_WS_PING_INTERVAL"`
	// EngineWSPongTimeout is how long the server waits for a pong after
	// sending a ping before treating the connection as dead. Unlike
	// EngineWSPingInterval, this doesn't need to be short to keep an
	// intermediary from seeing the connection go idle - the ping itself is
	// what does that - so it stays generous.
	EngineWSPongTimeout time.Duration `yaml:"engine_ws_pong_timeout" envconfig:"ENGINE_WS_PONG_TIMEOUT"`
	RegistryHost        string        `yaml:"registry_host" envconfig:"REGISTRY_HOST"`       // Registry bind address (defaults to Host)
	RegistryPort        int           `yaml:"registry_port" envconfig:"REGISTRY_PORT"`       // VCTM registry port (defaults to 8097)
	WPHost              string        `yaml:"wp_host" envconfig:"WP_HOST"`                   // Wallet-provider bind address (defaults to Host)
	WPPort              int           `yaml:"wp_port" envconfig:"WP_PORT"`                   // Wallet-provider port (0 = co-hosted with backend)
	AdminToken          string        `yaml:"admin_token" envconfig:"ADMIN_TOKEN"`           // Bearer token for admin API (auto-generated if empty)
	AdminTokenPath      string        `yaml:"admin_token_path" envconfig:"ADMIN_TOKEN_PATH"` // Path to file containing admin token
	RPID                string        `yaml:"rp_id" envconfig:"RP_ID"`
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
			"Authorization", "Content-Type", "X-Tenant-ID", "X-Token-Mode",
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
	// Issuer is the "iss" claim of legacy (HMAC) tokens. Required (non-empty) when as.legacy.enabled is true: legacy tokens are issued and validated with it. Defaults to "wallet-backend"; if it is blanked while as.legacy.enabled is true, that default is re-applied before validation.
	Issuer string `yaml:"issuer" envconfig:"ISSUER"`
}

// MaxTokenLifetime returns the longer of the configured access-token
// (ExpiryHours) and refresh-token (RefreshDays) lifetimes. A refresh-token
// family revocation marker must be retained at least this long, since
// nothing enforces that the refresh token outlives the access token.
func (c JWTConfig) MaxTokenLifetime() time.Duration {
	refresh := time.Duration(c.RefreshDays) * 24 * time.Hour
	access := time.Duration(c.ExpiryHours) * time.Hour
	if refresh > access {
		return refresh
	}
	return access
}

// MinFamilyRetention is the floor for how long a refresh-token family
// revocation marker is kept (365 days).
//
// The marker must outlive every token of the family, but the only bound
// available at logout is the CURRENT configuration, while tokens may have
// been minted under an earlier, longer one (e.g. jwt.refresh_days lowered
// after deployment). A retention derived from the current lifetimes alone
// could therefore expire early and un-revoke older tokens. The floor makes
// retention non-shrinking across configuration changes for any earlier
// configuration with token lifetimes up to a year; markers are tiny and
// swept afterwards, so the cost is negligible. Configurations that ever
// issued tokens beyond a year are covered by MaxTokenLifetime taking the
// larger value.
const MinFamilyRetention = 365 * 24 * time.Hour

// FamilyRetention returns how long to keep a refresh-token family
// revocation marker: the longer of MaxTokenLifetime and MinFamilyRetention.
func (c JWTConfig) FamilyRetention() time.Duration {
	if m := c.MaxTokenLifetime(); m > MinFamilyRetention {
		return m
	}
	return MinFamilyRetention
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
	PINPath    string `yaml:"pin_path" envconfig:"PIN_PATH"` // Path to file containing PIN (preferred over inline PIN)
	KeyLabel   string `yaml:"key_label" envconfig:"KEY_LABEL"`
	PoolSize   int    `yaml:"pool_size" envconfig:"POOL_SIZE"` // Session pool size (default 4)
}

// AttestationConfig controls attestation lifecycle behavior.
//
// Revocation design: WIAs carry a `client_status` and KAs a
// `key_storage_status` (see signWIA/GenerateKeyAttestation), both required
// by WE BUILD CS-04 §7.1.2/§7.1.3 (TS-03 clauses 2.3.1/2.3.2) — an issuer
// conforming to CS-04 rejects a WUA that omits them. Both reference this
// wallet provider's own Token Status List
// (RegisterWalletProviderStatusListRoute), which is served but never has a
// bit set: this wallet provider does not implement revocation-chaining, and
// what actually bounds exposure from a compromised or revoked wallet
// instance is LifetimeSeconds being short enough (default 5 minutes) that
// an outstanding WIA expires before it matters. See StatusListConfig for
// what that does and does not buy an issuer, and how to turn the claims off.
type AttestationConfig struct {
	// LifetimeSeconds is the WIA lifetime. TS03 v1.5.2 caps this at < 24h
	// (86400); this wallet provider defaults far below that (300s / 5 min)
	// specifically so that WIA lifetime — not revocation-list checking — is
	// the mechanism that bounds exposure from a compromised/revoked wallet
	// instance. See the type-level comment above.
	LifetimeSeconds int `yaml:"lifetime_seconds" envconfig:"LIFETIME_SECONDS"`

	// KAExpirySeconds is the key attestation JWT expiry.
	// Short-lived by default (15s) for single-use credential issuance.
	KAExpirySeconds int `yaml:"ka_expiry_seconds" envconfig:"KA_EXPIRY_SECONDS"`

	// NativeAttestation controls platform attestation verification.
	NativeAttestation NativeAttestationConfig `yaml:"native_attestation" envconfig:"NATIVE_ATTESTATION"`

	// FIDO2Attestation controls FIDO2/CTAP2 hardware-key attestation
	// verification (e.g. a YubiKey's rawSign plugin) — a distinct trust
	// path from NativeAttestation (platform attestation), verified once at
	// key-registration time rather than per-WIA-request. See
	// FIDO2AttestationService.
	FIDO2Attestation FIDO2AttestationConfig `yaml:"fido2_attestation" envconfig:"FIDO2_ATTESTATION"`

	// StatusList controls the Token Status List references embedded in the
	// WIA (`client_status`) and KA (`key_storage_status`).
	StatusList StatusListConfig `yaml:"status_list" envconfig:"STATUS_LIST"`
}

// StatusListRefMinMaintenanceSeconds is the floor CS-04 §7.2.2 (TS-03
// clause 2.4.2) puts on how far ahead `client_status.exp` /
// `key_storage_status.exp` must be at the time of presentation: 31 days.
const StatusListRefMinMaintenanceSeconds = 31 * 24 * 60 * 60

// StatusListDefaultMaintenanceSeconds is the default
// StatusListConfig.MaintenancePeriodSeconds: 45 days. Note that it is not
// StatusListRefMinMaintenanceSeconds — CS-04 §7.2.2's 31 days must remain
// *at presentation*, not at issuance, so defaulting to exactly the floor
// would put a WUA out of conformance the moment it sat unused for a
// second. The 14-day margin is what a WUA can spend between issuance and
// presentation. Anything deriving a maintenance period must use this, not
// the floor.
const StatusListDefaultMaintenanceSeconds = 45 * 24 * 60 * 60

// StatusListConfig configures the `client_status` (WIA) and
// `key_storage_status` (KA) claims, which WE BUILD CS-04 §7.1.2/§7.1.3
// (TS-03 clauses 2.3.1/2.3.2) require on every WUA.
//
// What these claims mean here: both reference this wallet provider's own
// Token Status List endpoint (RegisterWalletProviderStatusListRoute), whose
// entries are always 0 (VALID). This wallet provider does not revoke via
// the list — see AttestationConfig's type-level comment for why (short
// attestation lifetimes instead) — so an issuer that polls the referenced
// entry learns nothing beyond "still valid". The claims are emitted because
// a CS-04-conformant issuer rejects a WUA without them, not because they
// carry revocation signal; a deployment that would rather advertise no
// revocation mechanism at all than advertise an inert one can set Enabled
// to false, at the cost of failing CS-04 conformance.
type StatusListConfig struct {
	// Enabled controls whether `client_status`/`key_storage_status` are
	// emitted at all. Defaults to true (CS-04 conformance); set false to go
	// back to omitting them.
	Enabled bool `yaml:"enabled" envconfig:"ENABLED"`

	// URI overrides the status list URI the claims reference. Defaults to
	// this wallet provider's own endpoint,
	// "<server.base_url>/wallet-provider/status-list". Set it only when the
	// list is published somewhere else (e.g. behind a CDN on a different
	// host than server.base_url).
	URI string `yaml:"uri" envconfig:"URI"`

	// MaintenancePeriodSeconds is how far ahead of issuance the claims'
	// `exp` — the revocation *maintenance* commitment, independent of the
	// token's own `exp` (CS-04 §7.2's note; TS-03 clause 2.4.1) — is set.
	// CS-04 §7.2.2 requires at least 31 days remaining at presentation;
	// this defaults to 45 days so a WUA still satisfies that after sitting
	// unused for a fortnight. Values below 31 days are rejected by
	// Validate() when StatusList is enabled.
	MaintenancePeriodSeconds int `yaml:"maintenance_period_seconds" envconfig:"MAINTENANCE_PERIOD_SECONDS"`
}

// FIDO2AttestationConfig controls FIDO2/CTAP2 hardware-key attestation
// verification.
type FIDO2AttestationConfig struct {
	// Enabled controls whether the FIDO2 key-attestation registration
	// endpoint accepts and verifies attestation objects. Off by default —
	// like NativeAttestation, this is an explicit opt-in trust decision.
	Enabled bool `yaml:"enabled" envconfig:"ENABLED"`
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
	// Prefer GooglePlayIntegrityDecryptionKeyPath for production deployments.
	GooglePlayIntegrityDecryptionKey string `yaml:"google_play_integrity_decryption_key" envconfig:"GOOGLE_PLAY_INTEGRITY_DECRYPTION_KEY"`
	// GooglePlayIntegrityDecryptionKeyPath is a path to a file containing the
	// decryption key (preferred over the inline value — same pattern as
	// PKCS11.PINPath / JWT.SecretPath, so this AES key material can be
	// mounted from a secret store instead of living in plain env vars/YAML).
	GooglePlayIntegrityDecryptionKeyPath string `yaml:"google_play_integrity_decryption_key_path" envconfig:"GOOGLE_PLAY_INTEGRITY_DECRYPTION_KEY_PATH"`
	// GooglePlayIntegrityVerificationKey is the base64-encoded verification key.
	// Prefer GooglePlayIntegrityVerificationKeyPath for production deployments.
	GooglePlayIntegrityVerificationKey string `yaml:"google_play_integrity_verification_key" envconfig:"GOOGLE_PLAY_INTEGRITY_VERIFICATION_KEY"`
	// GooglePlayIntegrityVerificationKeyPath is a path to a file containing
	// the verification key (preferred over the inline value).
	GooglePlayIntegrityVerificationKeyPath string `yaml:"google_play_integrity_verification_key_path" envconfig:"GOOGLE_PLAY_INTEGRITY_VERIFICATION_KEY_PATH"`
}

// WIA trust-model modes — see WIAConfig.Mode.
const (
	WIAModeETSI = "etsi"
	WIAModeIETF = "ietf"
)

// WIAConfig contains WIA-specific configuration (CS-04 §7.1.2)
type WIAConfig struct {
	// Enabled controls whether WIA endpoints are registered
	Enabled bool `yaml:"enabled" envconfig:"ENABLED"`
	// Issuer is the `iss` claim in WIA JWTs. Required when Mode is "ietf"
	// (it's the only way a relying party can locate the JWKS to verify the
	// WIA); unused/omitted when Mode is "etsi".
	Issuer string `yaml:"issuer" envconfig:"ISSUER"`

	// Mode selects which WIA trust model this wallet provider issues:
	//
	//   - "etsi" (default): the EUDI ARF v3.0 / EC TS03 v1.5.2 / ETSI TS 119
	//     472-3 V1.1.1 model. The WIA always carries the signing certificate
	//     chain in the `x5c` JOSE header; relying parties verify it against
	//     the Trusted List for Wallet Providers (ETSI TS 119 472-3
	//     AUTH-REQ-PROC-4.4.3-01 / TOKEN-REQ-PROC-4.5.2-01). No `iss` or
	//     `kid` is set — TS03 v1.5 explicitly removed `iss` from the WIA;
	//     Wallet Provider identity is inferred solely from the x5c signing
	//     certificate. This is the only mode with a defined trust path under
	//     the current EUDI/ARF/ETSI specs; use it when interoperating with
	//     ARF-conformant PID/EAA Providers.
	//
	//   - "ietf": the generic IETF draft-ietf-oauth-attestation-based-client-auth
	//     model, with no ARF/ETSI counterpart. The WIA always carries a
	//     `kid` header plus the `iss` claim (required), and also includes
	//     `x5c` when a certificate chain is configured so consumers can
	//     resolve trust either from the header or via JWKS discovery at
	//     "<issuer>/.well-known/jwks.json" (see
	//     RegisterWalletProviderJWKSRoute). Only meaningful for non-EUDI,
	//     generic-OAuth ecosystems — an ARF-conformant PID/EAA Provider has
	//     no spec-defined way to resolve trust via this path.
	//
	// Note SUNET/vc's parseAttestationIdentity treats x5c as authoritative
	// and `iss` as a secondary consistency check only when both are present,
	// so "etsi" mode (no iss) remains unambiguous and "ietf" mode can offer
	// both trust-resolution paths to that consumer.
	Mode string `yaml:"mode" envconfig:"MODE"`
	// WalletProviderURI is the expected `aud` in WIA-PoP JWTs (wallet provider identifier)
	WalletProviderURI string `yaml:"wallet_provider_uri" envconfig:"WALLET_PROVIDER_URI"`
	// WalletName is the wallet_name claim in WIA JWT. REQUIRED by EC TS03
	// v1.5.2 §2.3.1 when Mode is "etsi" — Validate() enforces this (defaults
	// to "SIROS ID" so it's populated out of the box).
	WalletName string `yaml:"wallet_name" envconfig:"WALLET_NAME"`
	// WalletVersion is the wallet_version claim. REQUIRED by EC TS03 v1.5.2
	// §2.3.1 ("Added `wallet_version` (REQUIRED) to the WIA") when Mode is
	// "etsi" — Validate() enforces this; there is no sensible built-in
	// default (it must reflect this deployment's actual released version).
	WalletVersion string `yaml:"wallet_version" envconfig:"WALLET_VERSION"`
	// WalletLink is the wallet download/info URI. SHOULD per TS03 §2.3.1;
	// not enforced by Validate().
	WalletLink string `yaml:"wallet_link" envconfig:"WALLET_LINK"`
	// CertificationInfo is the wallet_solution_certification_information
	// claim. Free-form map included as-is in the WIA JWT. SHALL-required by
	// TS03 §2.3.1 when Mode is "etsi", but TS03 itself notes the
	// certification scheme is not yet finalized ("the exact content of
	// wallet_solution_certification_information is undefined") — Validate()
	// only warns (via the WIA service logger at startup) rather than hard
	// failing, unlike WalletVersion.
	CertificationInfo map[string]interface{} `yaml:"certification_info,omitempty"`
	// MaxExpirySeconds is the maximum WIA lifetime in seconds (CS-04 requires < 24h)
	MaxExpirySeconds int `yaml:"max_expiry_seconds" envconfig:"MAX_EXPIRY_SECONDS"`
	// ChallengeTTLSeconds is the lifetime of WIA challenge nonces in seconds
	ChallengeTTLSeconds int `yaml:"challenge_ttl_seconds" envconfig:"CHALLENGE_TTL_SECONDS"`
	// RateLimit caps how many challenges a single authenticated caller may
	// request per window. Without this, one caller can exhaust the shared
	// challenge capacity (maxChallenges) and 503 out every other tenant/user.
	RateLimit AuthRateLimitConfig `yaml:"rate_limit" envconfig:"RATE_LIMIT"`
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

	// CacheDisabled turns the engine's in-memory verifier trust cache off, so
	// every flow asks the PDP again.
	//
	// For testing, not for production. A trust decision - including a denial -
	// is otherwise reused for CacheTTLSeconds, which makes iterating on trust
	// configuration nearly impossible: fix the whitelist or the keys, redeploy
	// the PDP, retry, and the wallet is still refused by a cached answer, with
	// nothing in any log to say the answer was stale. It also means a PDP that
	// is briefly unreachable takes a verifier down for the rest of the TTL.
	CacheDisabled bool `yaml:"cache_disabled" envconfig:"CACHE_DISABLED"`

	// CacheTTLSeconds is how long a verifier trust decision is reused.
	// Zero selects the default of one hour. Ignored when CacheDisabled.
	CacheTTLSeconds int `yaml:"cache_ttl_seconds" envconfig:"CACHE_TTL_SECONDS"`

	// Issuer contains per-flow trust configuration overrides for OID4VCI (credential issuance).
	// When not set, inherits the global trust configuration.
	Issuer FlowTrustConfig `yaml:"issuer" envconfig:"ISSUER"`

	// Verifier contains per-flow trust configuration overrides for OID4VP (credential presentation).
	// When not set, inherits the global trust configuration.
	Verifier FlowTrustConfig `yaml:"verifier" envconfig:"VERIFIER"`
}

// DefaultTrustCacheTTL is how long a verifier trust decision is reused when
// TrustConfig.CacheTTLSeconds says nothing.
const DefaultTrustCacheTTL = time.Hour

// MaxTrustCacheTTLSeconds is the largest CacheTTLSeconds that survives the
// conversion to a time.Duration, which counts nanoseconds in an int64 - about
// 292 years. Anything larger wraps to a negative duration, which the cache
// reads as "off", so a number meant to say "cache for a very long time" would
// silently mean the opposite. Config.Validate refuses those.
const MaxTrustCacheTTLSeconds = int(math.MaxInt64 / int64(time.Second))

// VerifierCacheTTL is how long the engine may reuse a verifier trust decision.
//
// Zero means "do not cache at all", which is what CacheDisabled selects; the
// engine's cache treats a non-positive TTL as off rather than as an instantly
// expiring entry, so there is one meaning for the value and one place that
// decides it.
//
// A negative CacheTTLSeconds reads as the default here, but Config.Validate
// refuses it before a process gets this far: it is the one value whose intent
// ("off") differs from what this returns, so it is rejected at startup rather
// than guessed at.
func (t TrustConfig) VerifierCacheTTL() time.Duration {
	if t.CacheDisabled {
		return 0
	}
	if t.CacheTTLSeconds > 0 {
		return time.Duration(t.CacheTTLSeconds) * time.Second
	}
	return DefaultTrustCacheTTL
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

	// IssuerEntitlementMode decides what happens when a PID or attestation
	// provider is not registered for what it is offering: "warn" (default,
	// report and continue), "fail" (refuse), or "off" (do not check).
	//
	// The default is warn, not fail, because the ARF obligation to verify
	// registration certificates applies 24 months after the amending
	// Regulation enters into force. Until then, refusing a provider that has
	// simply not been registered yet would break issuance that is currently
	// legitimate. An unrecognised value is treated as warn rather than off, so
	// a typo cannot silently disable the check.
	IssuerEntitlementMode string `yaml:"issuer_entitlement_mode" envconfig:"ISSUER_ENTITLEMENT_MODE"`

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

	// OIDCGateRateLimit limits requests that present a token to the OIDC
	// registration/login gates (#65). Two independent buckets: per client IP
	// and per tenant; a request must fit in both.
	OIDCGateRateLimit OIDCGateRateLimitConfig `yaml:"oidc_gate_rate_limit" envconfig:"OIDC_GATE_RATE_LIMIT"`

	// AAGUIDBlacklist contains AAGUID blacklist configuration for WebAuthn
	AAGUIDBlacklist AAGUIDBlacklistConfig `yaml:"aaguid_blacklist" envconfig:"AAGUID_BLACKLIST"`

	// ChallengeCleanup contains challenge cleanup worker configuration
	ChallengeCleanup ChallengeCleanupConfig `yaml:"challenge_cleanup" envconfig:"CHALLENGE_CLEANUP"`

	// TokenBlacklist contains token blacklist/revocation configuration
	TokenBlacklist TokenBlacklistConfig `yaml:"token_blacklist" envconfig:"TOKEN_BLACKLIST"`

	// DeletionTombstone contains the retention and cleanup settings of the
	// account-deletion tombstones that keep a deleted user's old tokens refused
	DeletionTombstone DeletionTombstoneConfig `yaml:"deletion_tombstone" envconfig:"DELETION_TOMBSTONE"`

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

// OIDCGateRateLimitConfig configures rate limiting in front of the OIDC gates.
//
// Token validation is the expensive part of a gated request (discovery and
// JWKS fetches, signature checks), so the limiter runs before it. It only
// counts requests that carry a bearer token, so tenants without a gate are
// unaffected. A failed validation costs the client extra tokens (three in
// total instead of one), so guessing is dearer than valid use.
//
// Two buckets, because either alone fails badly: per-IP alone lets one
// tenant's attackers lock out everyone behind a shared NAT; per-tenant alone
// lets a single client exhaust a whole tenant. Client-IP keying relies on
// gin's trusted-proxy handling being correct behind a load balancer.
type OIDCGateRateLimitConfig struct {
	// PerIP limits by client IP.
	PerIP OIDCGateIPLimitConfig `yaml:"per_ip" envconfig:"PER_IP"`
	// PerTenant limits by tenant.
	PerTenant OIDCGateTenantLimitConfig `yaml:"per_tenant" envconfig:"PER_TENANT"`
}

// OIDCGateIPLimitConfig is the per-client-IP bucket of the OIDC gate limiter.
// It has the same shape as AuthRateLimitConfig but its own documentation and
// defaults; convert with AuthRateLimitConfig(c).
type OIDCGateIPLimitConfig struct {
	// Enabled controls whether the per-IP limit is active. Default: true
	Enabled bool `yaml:"enabled" envconfig:"ENABLED"`
	// MaxAttempts is the number of token-bearing gate requests one client IP
	// may make per window. Default: 30
	MaxAttempts int `yaml:"max_attempts" envconfig:"MAX_ATTEMPTS"`
	// WindowSeconds is the rate-limit window in seconds. Default: 60
	WindowSeconds int `yaml:"window_seconds" envconfig:"WINDOW_SECONDS"`
	// LockoutSeconds is how long a client IP is refused after exceeding the
	// limit, and the Retry-After it is sent. Default: 60
	LockoutSeconds int `yaml:"lockout_seconds" envconfig:"LOCKOUT_SECONDS"`
}

// OIDCGateTenantLimitConfig is the per-tenant bucket of the OIDC gate limiter.
// It has the same shape as AuthRateLimitConfig but its own documentation and
// defaults; convert with AuthRateLimitConfig(c).
type OIDCGateTenantLimitConfig struct {
	// Enabled controls whether the per-tenant limit is active. Default: true
	Enabled bool `yaml:"enabled" envconfig:"ENABLED"`
	// MaxAttempts is the number of token-bearing gate requests one tenant
	// may receive per window, across all clients. Default: 300
	MaxAttempts int `yaml:"max_attempts" envconfig:"MAX_ATTEMPTS"`
	// WindowSeconds is the rate-limit window in seconds. Default: 60
	WindowSeconds int `yaml:"window_seconds" envconfig:"WINDOW_SECONDS"`
	// LockoutSeconds is how long a tenant is refused after exceeding the
	// limit, and the Retry-After it is sent. Default: 60
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

// DeletionTombstoneConfig configures the tombstone DeleteUser leaves behind.
//
// Deleting a user removes the record that carries the token cut-off, so
// without a tombstone every token issued before the deletion would be taken
// for one of an unknown (external) identity and pass the token gate. The
// tombstone outlives every token it could cover and is then removed by a
// periodic sweeper (and, on MongoDB, by a TTL index).
type DeletionTombstoneConfig struct {
	// CleanupIntervalSeconds is how often expired tombstones are swept.
	// The sweeper is what expires tombstones on backends without a TTL index
	// (memory) and a backstop on MongoDB.
	// Default: 3600 (1 hour)
	CleanupIntervalSeconds int `yaml:"cleanup_interval_seconds" envconfig:"CLEANUP_INTERVAL_SECONDS"`

	// RetentionMarginDays is the safety margin added to the longest token
	// lifetime (access token, refresh token, AS session; itself floored at one
	// year, see MinFamilyRetention) when a tombstone's expiry is computed.
	// Default: 30
	RetentionMarginDays int `yaml:"retention_margin_days" envconfig:"RETENTION_MARGIN_DAYS"`
}

// SetDefaults sets default values for the deletion tombstone settings
func (c *DeletionTombstoneConfig) SetDefaults() {
	if c.CleanupIntervalSeconds == 0 {
		c.CleanupIntervalSeconds = 3600
	}
	if c.RetentionMarginDays == 0 {
		c.RetentionMarginDays = 30
	}
}

// DeletionTombstoneRetention is how long a deletion tombstone must be kept:
// the longest lifetime of any bearer token that can name the deleted user
// (legacy access token JWT.ExpiryHours, refresh token JWT.RefreshDays, AS
// access token TTLs, AS session TTL) plus RetentionMarginDays. A tombstone
// that expired earlier would let a still-valid token for the deleted account
// pass the token gate again.
//
// The lifetimes are floored at MinFamilyRetention, the same deployment-wide
// floor used for refresh-token family markers. Tokens carry the expiry they
// were minted with, but the only bound available at deletion time is the
// CURRENT configuration; if a lifetime was lowered after tokens were issued
// (e.g. jwt.refresh_days 365 -> 7), a tombstone sized from the new value
// would expire while older tokens are still valid, and the token gate would
// then treat the deleted user as an external identity and accept them.
// The floor keeps retention from shrinking below what earlier configurations
// with lifetimes up to a year may have issued; larger current lifetimes still
// extend it. The margin is added on top of the floored value.
func (c *Config) DeletionTombstoneRetention() time.Duration {
	margin := c.Security.DeletionTombstone
	margin.SetDefaults()

	longest := time.Duration(c.JWT.ExpiryHours) * time.Hour
	if r := time.Duration(c.JWT.RefreshDays) * 24 * time.Hour; r > longest {
		longest = r
	}
	if c.AS.DefaultTokenTTL > longest {
		longest = c.AS.DefaultTokenTTL
	}
	for _, ttl := range c.AS.AudienceTTLs {
		if ttl > longest {
			longest = ttl
		}
	}
	sessionTTL := c.AS.SessionTTL
	if sessionTTL == 0 {
		sessionTTL = 24 * time.Hour // ASConfig.SetDefaults
	}
	if sessionTTL > longest {
		longest = sessionTTL
	}
	if longest < MinFamilyRetention {
		longest = MinFamilyRetention
	}
	return longest + time.Duration(margin.RetentionMarginDays)*24*time.Hour
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
			cfg.asEnabledExplicit = yamlHasASEnabledKey(data)
		}
	}

	// Override with environment variables (highest priority)
	// Since we removed `default:` tags, this only applies actual env vars
	if _, ok := os.LookupEnv("WALLET_AS_ENABLED"); ok {
		cfg.asEnabledExplicit = true
	}
	if err := envconfig.Process("WALLET", cfg); err != nil {
		return nil, fmt.Errorf("failed to process environment variables: %w", err)
	}

	// Load secrets from files if configured
	if err := cfg.loadSecretsFromFiles(); err != nil {
		return nil, fmt.Errorf("failed to load secrets from files: %w", err)
	}

	// Apply the documented AS defaults before validating: Validate() makes
	// them mandatory, and configs written before that must keep loading.
	cfg.applyASSecurityDefaults()

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

// yamlHasASEnabledKey reports whether the raw YAML explicitly sets an
// `as.enabled` key, regardless of its value - used to distinguish "operator
// explicitly configured as.enabled" from "AS section absent/defaulted",
// which a plain bool field can't express on its own (see EnableForRole).
func yamlHasASEnabledKey(data []byte) bool {
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return false
	}
	as, ok := raw["as"].(map[string]any)
	if !ok {
		return false
	}
	_, ok = as["enabled"]
	return ok
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

	// Load PKCS#11 PIN from file
	if c.WalletProvider.PKCS11 != nil && c.WalletProvider.PKCS11.PINPath != "" {
		c.WalletProvider.PKCS11.PIN, err = readSecretFile(c.WalletProvider.PKCS11.PINPath)
		if err != nil {
			return fmt.Errorf("wallet_provider.pkcs11.pin_path: %w", err)
		}
	}

	// Load Play Integrity decryption/verification keys from file
	natCfg := &c.WalletProvider.Attestation.NativeAttestation
	if natCfg.GooglePlayIntegrityDecryptionKeyPath != "" {
		natCfg.GooglePlayIntegrityDecryptionKey, err = readSecretFile(natCfg.GooglePlayIntegrityDecryptionKeyPath)
		if err != nil {
			return fmt.Errorf("wallet_provider.attestation.native_attestation.google_play_integrity_decryption_key_path: %w", err)
		}
	}
	if natCfg.GooglePlayIntegrityVerificationKeyPath != "" {
		natCfg.GooglePlayIntegrityVerificationKey, err = readSecretFile(natCfg.GooglePlayIntegrityVerificationKeyPath)
		if err != nil {
			return fmt.Errorf("wallet_provider.attestation.native_attestation.google_play_integrity_verification_key_path: %w", err)
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
			Host:       "0.0.0.0",
			Port:       8080,
			AdminPort:  8081, // Internal admin API port
			EnginePort: 8082, // WebSocket engine port
			// See EngineWSPingInterval's doc comment for where 3s/5s come from.
			EngineWSPingInterval: 3 * time.Second,
			EngineWSPongTimeout:  5 * time.Second,
			RegistryPort:         8097, // VCTM registry port
			RPID:                 "localhost",
			RPOrigin:             "http://localhost:8080",
			RPOrigins:            nil,
			RPName:               "Wallet Backend",
			CORS:                 corsConfig,
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
			Issuer:      defaultJWTIssuer,
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
			OIDCGateRateLimit: OIDCGateRateLimitConfig{
				PerIP:     OIDCGateIPLimitConfig{Enabled: true, MaxAttempts: 30, WindowSeconds: 60, LockoutSeconds: 60},
				PerTenant: OIDCGateTenantLimitConfig{Enabled: true, MaxAttempts: 300, WindowSeconds: 60, LockoutSeconds: 60},
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
			DeletionTombstone: DeletionTombstoneConfig{
				CleanupIntervalSeconds: 3600,
				RetentionMarginDays:    30,
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
		Presentation: PresentationConfig{DCQLConsentCheck: DCQLConsentCheckWarn},
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
				Mode:                WIAModeETSI,
				WalletName:          "SIROS ID",
				MaxExpirySeconds:    86400,
				ChallengeTTLSeconds: 300,
				RateLimit: AuthRateLimitConfig{
					Enabled:        true,
					MaxAttempts:    30,
					WindowSeconds:  60,
					LockoutSeconds: 60,
				},
			},
			Attestation: AttestationConfig{
				// 5 minutes: short enough that WIA expiry — not revocation-list
				// checking — bounds exposure from a compromised/revoked wallet
				// instance. See AttestationConfig's type-level comment.
				LifetimeSeconds: 300,
				KAExpirySeconds: 15,
				StatusList: StatusListConfig{
					// On by default: CS-04 §7.1.2/§7.1.3 require
					// client_status/key_storage_status on every WUA, and a
					// conformant issuer rejects one without them.
					Enabled:                  true,
					MaintenancePeriodSeconds: StatusListDefaultMaintenanceSeconds,
				},
			},
		},
	}
}

// validateTrustedProxies rejects entries that are neither an IP, a CIDR nor
// the literal "none", so a typo fails at startup instead of at first request.
func (c ServerConfig) validateTrustedProxies() error {
	for _, p := range c.TrustedProxies {
		p = strings.TrimSpace(p)
		if strings.EqualFold(p, "none") {
			if len(c.TrustedProxies) != 1 {
				return fmt.Errorf("server.trusted_proxies: \"none\" cannot be combined with other entries")
			}
			continue
		}
		if net.ParseIP(p) != nil {
			continue
		}
		if _, _, err := net.ParseCIDR(p); err != nil {
			return fmt.Errorf("server.trusted_proxies: %q is not an IP address, CIDR or \"none\"", p)
		}
	}
	return nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}
	if err := c.Server.validateTrustedProxies(); err != nil {
		return err
	}
	if c.Security.DeletionTombstone.CleanupIntervalSeconds < 0 {
		return fmt.Errorf("security.deletion_tombstone.cleanup_interval_seconds must not be negative")
	}
	if c.Security.DeletionTombstone.RetentionMarginDays < 0 {
		return fmt.Errorf("security.deletion_tombstone.retention_margin_days must not be negative")
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

	// Sub-millisecond values are silently unrepresentable on the wire:
	// HandshakeCompleteMessage.Config reports PingIntervalMs via
	// time.Duration.Milliseconds(), which truncates a positive
	// sub-millisecond duration to 0 - the client would then see "unset"
	// and fall back to its own hardcoded default while the server keeps
	// pinging at the (much faster) configured cadence, exactly the
	// client/server disagreement this whole mechanism exists to prevent.
	// 0 itself is the legitimate "use the default" sentinel (see
	// Manager.wsKeepalive) and is not rejected here.
	if c.Server.EngineWSPingInterval != 0 && c.Server.EngineWSPingInterval < time.Millisecond {
		return fmt.Errorf(
			"server.engine_ws_ping_interval must be at least 1ms (or 0 to use the default) - got %s",
			c.Server.EngineWSPingInterval,
		)
	}
	if c.Server.EngineWSPongTimeout != 0 && c.Server.EngineWSPongTimeout < time.Millisecond {
		return fmt.Errorf(
			"server.engine_ws_pong_timeout must be at least 1ms (or 0 to use the default) - got %s",
			c.Server.EngineWSPongTimeout,
		)
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
	if len(c.JWT.Secret) < 32 {
		return fmt.Errorf("jwt secret must be at least 32 bytes for HMAC-SHA256 security")
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
		// Required as of the go-tokenauth v0.5.0 dependency bump: an empty
		// Audiences list used to mean "skip audience validation" both here
		// and in go-tokenauth's own Validator, but go-tokenauth v0.5.0
		// made it a hard configuration error there instead (closing a
		// fail-open audience-confusion gap) - every request would
		// otherwise start being silently rejected at runtime the moment
		// this dependency is upgraded, for any deployment that previously
		// relied on the old "empty means accept any audience" behavior.
		// Failing fast here, at startup, is far preferable to that.
		if len(c.AS.Audiences) == 0 {
			return fmt.Errorf("as: audiences is required when AS is enabled (see Config.AS.Audiences's doc comment)")
		}
		// Legacy (HMAC) tokens carry "aud": Server.RPID (see
		// UserService/WebAuthnService.generateToken), and go-tokenauth v0.5
		// validates that against AS.Audiences. If the RP ID is not among
		// them, every legacy login token is rejected on its next protected
		// request - a failure that only shows up at runtime, so refuse it here.
		// Legacy tokens are minted with "iss": jwt.issuer and validated
		// against Legacy.Issuers=[jwt.issuer]; an empty value would mint
		// tokens with an empty iss and turn go-tokenauth's mandatory issuer
		// check into a no-op, so require it (as.issuer does not help: it is
		// not the legacy issuer).
		if c.AS.Legacy.Enabled && c.JWT.Issuer == "" {
			return fmt.Errorf("as: legacy tokens are enabled but jwt.issuer is empty; legacy tokens are issued and validated with jwt.issuer, so set it or disable as.legacy.enabled")
		}
		if c.AS.Legacy.Enabled && !containsString(c.AS.Audiences, c.Server.RPID) {
			return fmt.Errorf("as: legacy tokens are enabled but server.rp_id %q is not listed in as.audiences; "+
				"legacy tokens carry the RP ID as their audience, so add it to as.audiences or disable as.legacy.enabled",
				c.Server.RPID)
		}
	}

	// Validate WIA configuration
	if c.WalletProvider.WIA.Enabled {
		switch c.WalletProvider.WIA.Mode {
		case WIAModeETSI, WIAModeIETF:
		case "":
			c.WalletProvider.WIA.Mode = WIAModeETSI
		default:
			return fmt.Errorf("invalid wallet_provider.wia.mode: %q (must be %q or %q)",
				c.WalletProvider.WIA.Mode, WIAModeETSI, WIAModeIETF)
		}

		if c.WalletProvider.WIA.MaxExpirySeconds > 86400 {
			return fmt.Errorf("wallet_provider.wia.max_expiry_seconds exceeds 24h (86400), CS-04 requires < 24h")
		}
		if c.WalletProvider.WIA.ChallengeTTLSeconds > 0 && c.WalletProvider.WIA.MaxExpirySeconds > 0 &&
			c.WalletProvider.WIA.ChallengeTTLSeconds > c.WalletProvider.WIA.MaxExpirySeconds {
			return fmt.Errorf("wallet_provider.wia.challenge_ttl_seconds (%d) must not exceed max_expiry_seconds (%d)",
				c.WalletProvider.WIA.ChallengeTTLSeconds, c.WalletProvider.WIA.MaxExpirySeconds)
		}
		if c.WalletProvider.Attestation.LifetimeSeconds > 86400 {
			return fmt.Errorf("wallet_provider.attestation.lifetime_seconds exceeds 24h (86400), CS-04 requires < 24h")
		}

		// wallet_provider_uri is what binds the WIA-PoP's aud claim to this
		// wallet provider; validatePop silently skips that check when it's
		// unset. Only require it once WIA is actually operational (signing keys
		// configured) — not on the zero-config default, where WIA.Enabled is
		// true but no keys are present and no endpoints get registered.
		// Note: unlike Mode-specific checks below, this doesn't require a
		// certificate — a signing key alone (file or PKCS#11, with or
		// without a cert) is enough to make WIA operational in "ietf" mode.
		walletProviderKeysConfigured := c.WalletProvider.PrivateKeyPath != "" ||
			(c.WalletProvider.PKCS11 != nil && c.WalletProvider.PKCS11.ModulePath != "")
		if walletProviderKeysConfigured {
			if c.WalletProvider.WIA.WalletProviderURI == "" {
				return fmt.Errorf("wallet_provider.wia.wallet_provider_uri is required when WIA is enabled with signing keys configured (used to validate the WIA-PoP aud claim)")
			}

			switch c.WalletProvider.WIA.Mode {
			case WIAModeIETF:
				// x5c is never sent in ietf mode, so `iss` + this wallet
				// provider's own JWKS (RegisterWalletProviderJWKSRoute) is the
				// only trust path a relying party has — without Issuer, a
				// WIA would carry no identity at all. No certificate is
				// required in this mode (JWKS-only trust).
				if c.WalletProvider.WIA.Issuer == "" {
					return fmt.Errorf("wallet_provider.wia.issuer is required when wallet_provider.wia.mode is %q", WIAModeIETF)
				}
			case WIAModeETSI:
				// EC TS03 v1.5.2 §2.3.1: wallet_version is REQUIRED. There's
				// no sensible default (see WIAConfig.WalletVersion), so this
				// hard-fails rather than silently emitting a non-conformant WIA.
				if c.WalletProvider.WIA.WalletVersion == "" {
					return fmt.Errorf("wallet_provider.wia.wallet_version is required when wallet_provider.wia.mode is %q (EC TS03 v1.5.2 requires it)", WIAModeETSI)
				}
				if c.WalletProvider.WIA.WalletName == "" {
					return fmt.Errorf("wallet_provider.wia.wallet_name is required when wallet_provider.wia.mode is %q (EC TS03 v1.5.2 requires it)", WIAModeETSI)
				}
				// x5c is mandatory in etsi mode; without a cert the WIA has
				// no valid trust path under ETSI TS 119 472-3.
				if c.WalletProvider.CertificatePath == "" {
					return fmt.Errorf("wallet_provider.certificate_path is required when wallet_provider.wia.mode is %q (WIA identity is x5c-only under ETSI TS 119 472-3)", WIAModeETSI)
				}
			}
		}
	}

	// Validate the WUA status-list references. Applies regardless of
	// WIA.Enabled: the same settings drive the KA's key_storage_status, and
	// KAs are issued through the wallet-provider service independently of
	// the WIA endpoints.
	if c.WalletProvider.Attestation.StatusList.Enabled {
		if c.WalletProvider.Attestation.StatusList.MaintenancePeriodSeconds == 0 {
			c.WalletProvider.Attestation.StatusList.MaintenancePeriodSeconds = StatusListDefaultMaintenanceSeconds
		}
		if c.WalletProvider.Attestation.StatusList.MaintenancePeriodSeconds < StatusListRefMinMaintenanceSeconds {
			return fmt.Errorf("wallet_provider.attestation.status_list.maintenance_period_seconds (%d) is below the 31-day (%d) minimum CS-04 §7.2.2 requires to still be remaining at presentation",
				c.WalletProvider.Attestation.StatusList.MaintenancePeriodSeconds, StatusListRefMinMaintenanceSeconds)
		}
	}

	if err := c.Presentation.DCQLConsentCheck.validate(); err != nil {
		return err
	}

	// Validate audit configuration — without this, cfg.Audit.Enabled=true
	// with a missing issuer/key_path/key_id silently disables the SET audit
	// emitter at startup (NewFromConfig just returns nil) instead of failing
	// fast on the actual misconfiguration.
	if err := c.Audit.validateIdentityEvents(); err != nil {
		return err
	}
	if len(c.Audit.IdentityEvents) > 0 && !c.Audit.Enabled {
		return fmt.Errorf("audit.identity_events requires audit.enabled")
	}
	if c.Audit.Enabled {
		if c.Audit.Issuer == "" {
			return fmt.Errorf("audit.issuer is required when audit is enabled")
		}
		if c.Audit.KeyPath == "" {
			return fmt.Errorf("audit.key_path is required when audit is enabled")
		}
		if c.Audit.KeyID == "" {
			return fmt.Errorf("audit.key_id is required when audit is enabled")
		}
	}

	// A negative TTL is refused rather than quietly rounded up to the
	// default. Someone who writes -1 here means "off", and silently giving
	// them an hour of cached trust decisions is the exact failure this
	// setting exists to cure: an answer that is not what the operator asked
	// for, with nothing anywhere saying so. trust.cache_disabled is the way
	// to say off.
	if c.Trust.CacheTTLSeconds < 0 {
		return fmt.Errorf("invalid trust.cache_ttl_seconds %d: must not be negative (set trust.cache_disabled to turn the cache off)", c.Trust.CacheTTLSeconds)
	}
	// And not so large that it wraps. A value past the int64 nanosecond
	// range becomes a negative duration, which the cache reads as "off" -
	// so without this, a number meant to cache for centuries would disable
	// caching instead, which is the same silent inversion as the negative
	// case above.
	if c.Trust.CacheTTLSeconds > MaxTrustCacheTTLSeconds {
		return fmt.Errorf("invalid trust.cache_ttl_seconds %d: must not exceed %d (a larger value overflows time.Duration and would silently disable the cache)", c.Trust.CacheTTLSeconds, MaxTrustCacheTTLSeconds)
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

// AuditConfig configures the SET (Security Event Token) audit trail emitter.
type AuditConfig struct {
	// Enabled enables SET audit event emission.
	Enabled bool `yaml:"enabled" envconfig:"ENABLED"`
	// Issuer is the iss claim in SET records (e.g. "https://wallet.siros.org").
	Issuer string `yaml:"issuer" envconfig:"ISSUER"`
	// KeyPath is the path to a PEM-encoded EC private key for signing SET records.
	KeyPath string `yaml:"key_path" envconfig:"KEY_PATH"`
	// KeyID is the kid used in SET JWS headers.
	KeyID string `yaml:"key_id" envconfig:"KEY_ID"`
	// IdentityEvents selects which enterprise-identity (OIDC gate) audit events
	// are emitted, by short name: bound, verified, mismatch, gate_bypass.
	// Default: none. Requires enabled. The subject is only ever emitted as a
	// hash. Unknown names are rejected at startup.
	// Env: WALLET_AUDIT_IDENTITY_EVENTS (comma-separated)
	IdentityEvents []string `yaml:"identity_events" envconfig:"IDENTITY_EVENTS"`
}

// Names accepted in AuditConfig.IdentityEvents.
const (
	// AuditIdentityBound: an OIDC identity was bound to a wallet at registration.
	AuditIdentityBound = "bound"
	// AuditIdentityVerified: a bound identity was verified at login.
	AuditIdentityVerified = "verified"
	// AuditIdentityMismatch: a login was refused because the presented identity,
	// issuer, audience or required claims did not match.
	AuditIdentityMismatch = "mismatch"
	// AuditIdentityGateBypass: a login gate was required but no token was presented.
	AuditIdentityGateBypass = "gate_bypass"
)

// validAuditIdentityEvents is the set of names IdentityEvents may contain.
var validAuditIdentityEvents = map[string]struct{}{
	AuditIdentityBound:      {},
	AuditIdentityVerified:   {},
	AuditIdentityMismatch:   {},
	AuditIdentityGateBypass: {},
}

// IdentityEventEnabled reports whether the named identity event is selected.
func (c AuditConfig) IdentityEventEnabled(name string) bool {
	for _, e := range c.IdentityEvents {
		if strings.EqualFold(strings.TrimSpace(e), name) {
			return true
		}
	}
	return false
}

// validateIdentityEvents rejects unknown event names, so a typo cannot
// silently leave an intended audit event switched off.
func (c AuditConfig) validateIdentityEvents() error {
	for _, e := range c.IdentityEvents {
		name := strings.ToLower(strings.TrimSpace(e))
		if _, ok := validAuditIdentityEvents[name]; !ok {
			return fmt.Errorf("audit.identity_events: unknown event %q (valid: bound, verified, mismatch, gate_bypass)", e)
		}
	}
	return nil
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
