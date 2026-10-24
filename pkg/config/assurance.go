package config

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// DefaultLevelSchemeID is the built-in level scheme: the OpenID4VCI 1.0
// Appendix D.2 attack-potential-resistance values, weakest to strongest.
const DefaultLevelSchemeID = "iso_18045"

// AssuranceConfig controls the backend-owned assurance policy that decides
// the values in the Key Attestation (key_storage, user_authentication,
// certification) by applying a set of SPOCP rules to verified evidence.
// See docs/assurance-policy.md.
//
// When Enabled is false (the default) the Key Attestation is produced
// exactly as before this feature existed, including the clamp to the
// software floor for untrusted batches.
type AssuranceConfig struct {
	// Enabled switches the policy engine on. Default false.
	Enabled bool `yaml:"enabled" envconfig:"ENABLED"`

	// RulesFile is the path to the SPOCP rules file (advanced form, one rule
	// per line, each preceded by a "# id: <name>" comment line). Required
	// when Enabled; an existing but empty file is valid and means every
	// dimension resolves to its floor. The name must not end in .spocp or
	// .bin (go-spocp auto-detects those as binary); use ".rules".
	RulesFile string `yaml:"rules_file" envconfig:"RULES_FILE"`

	// LevelSchemes are the named level schemes available to the dimensions.
	// The built-in "iso_18045" scheme is always available unless a scheme
	// with that id is configured here.
	LevelSchemes LevelSchemeList `yaml:"level_schemes" envconfig:"LEVEL_SCHEMES"`

	// KeyStorageScheme and UserAuthenticationScheme select the scheme (by
	// id) used for each dimension. Default "iso_18045".
	KeyStorageScheme         string `yaml:"key_storage_scheme" envconfig:"KEY_STORAGE_SCHEME"`
	UserAuthenticationScheme string `yaml:"user_authentication_scheme" envconfig:"USER_AUTHENTICATION_SCHEME"`

	// LowerByClaims, per dimension: when true (default) the result is
	// min(level the client claimed, level the rules grant) whenever the
	// client sent a claim for that dimension; with no claim nothing is
	// lowered. When false the rules are the sole authority and claims
	// matter only through (claimed ...) groups in rules.
	LowerByClaimsKeyStorage         bool `yaml:"lower_by_claims_key_storage" envconfig:"LOWER_BY_CLAIMS_KEY_STORAGE"`
	LowerByClaimsUserAuthentication bool `yaml:"lower_by_claims_user_authentication" envconfig:"LOWER_BY_CLAIMS_USER_AUTHENTICATION"`

	// Certification is the certification catalogue probed by assure-cert.
	Certification CertificationCatalogueConfig `yaml:"certification" envconfig:"CERTIFICATION"`

	// CertificationBasisInClaim, when true, adds a "basis" member
	// ({policy, rules}) to an object-valued certification claim. Default
	// false and NOT spec-supported: OpenID4VCI 1.0/1.1 Appendix D defines
	// certification as a URL string. See docs/assurance-policy.md.
	CertificationBasisInClaim bool `yaml:"certification_basis_in_claim" envconfig:"CERTIFICATION_BASIS_IN_CLAIM"`

	// WIAProfileSchemes are the named S-profile schemes available to the
	// Wallet Instance Attestation (WIA) decision (assure-wia). The built-in
	// "cs04_annex_c" scheme is always available unless one with that id is
	// configured here.
	WIAProfileSchemes WIAProfileSchemeList `yaml:"wia_profile_schemes" envconfig:"WIA_PROFILE_SCHEMES"`

	// WIAProfileScheme selects the scheme (by id) the WIA profile is decided
	// in. Default "cs04_annex_c".
	WIAProfileScheme string `yaml:"wia_profile_scheme" envconfig:"WIA_PROFILE_SCHEME"`

	// WIACertification is the catalogue of wallet_solution_certification_
	// information values assure-wia-cert may select for the WIA. When no
	// entry is permitted the static wallet_provider.wia.certification_info
	// is used, exactly as without the policy.
	WIACertification WIACertificationCatalogueConfig `yaml:"wia_certification" envconfig:"WIA_CERTIFICATION"`
}

// DefaultWIAProfileSchemeID is the built-in S-profile scheme, named after the
// attestation coverage tiers of WE BUILD CS-04 Annex C.2.2.
const DefaultWIAProfileSchemeID = "cs04_annex_c"

// WIAProfileSchemeConfig is a named, ordered set of WIA attestation-coverage
// profiles (the S dimension of CS-04 Annex C). It has the shape of a level
// scheme with the levels called profiles.
type WIAProfileSchemeConfig struct {
	// ID names the scheme.
	ID string `yaml:"id" json:"id"`
	// Profiles are the profile names, weakest first. They are the atoms
	// rules use in (profile ...).
	Profiles []string `yaml:"profiles" json:"profiles"`
	// Values are the strings emitted in the WIA's attestation_source claim
	// for each profile, same length and order as Profiles.
	Values []string `yaml:"values" json:"values"`
	// Floor is the profile returned when nothing is granted.
	Floor string `yaml:"floor" json:"floor"`
	// Ceiling optionally caps the result.
	Ceiling string `yaml:"ceiling,omitempty" json:"ceiling,omitempty"`
}

// AsLevelScheme returns the equivalent level scheme, which is what the
// engine indexes.
func (s WIAProfileSchemeConfig) AsLevelScheme() LevelSchemeConfig {
	return LevelSchemeConfig{ID: s.ID, Levels: s.Profiles, Values: s.Values, Floor: s.Floor, Ceiling: s.Ceiling}
}

// Validate checks one profile scheme for internal consistency.
func (s WIAProfileSchemeConfig) Validate() error { return s.AsLevelScheme().Validate() }

// WIAProfileSchemeList is a list of profile schemes that can also be supplied
// through an environment variable as a JSON array.
type WIAProfileSchemeList []WIAProfileSchemeConfig

// Decode implements envconfig.Decoder (JSON array).
func (l *WIAProfileSchemeList) Decode(value string) error {
	if strings.TrimSpace(value) == "" {
		*l = nil
		return nil
	}
	var out []WIAProfileSchemeConfig
	if err := json.Unmarshal([]byte(value), &out); err != nil {
		return fmt.Errorf("wia_profile_schemes must be a JSON array: %w", err)
	}
	*l = out
	return nil
}

// BuiltinWIAProfileScheme returns the default S-profile scheme. The profiles
// are the CS-04 Annex C.2.2 tiers S3 (backend-only attestation) and S1 (full
// client attestation); S2 (partial client attestation) has no evidence source
// and no existing attestation_source value, so it is not in the default.
// The emitted values are the attestation_source strings the WIA has always
// carried, so enabling the policy does not change the vocabulary.
func BuiltinWIAProfileScheme() WIAProfileSchemeConfig {
	return WIAProfileSchemeConfig{
		ID:       DefaultWIAProfileSchemeID,
		Profiles: []string{"s3-backend-only", "s1-full-client"},
		Values:   []string{"backend_attested", "platform_attested"},
		Floor:    "s3-backend-only",
	}
}

// WIACertificationCatalogueConfig lists the wallet_solution_certification_
// information values the policy may select.
type WIACertificationCatalogueConfig struct {
	// Entries are probed in order (list the strongest first); the first one a
	// rule permits wins.
	Entries WIACertificationEntryList `yaml:"entries" envconfig:"ENTRIES"`
}

// WIACertificationEntry is a named wallet_solution_certification_information
// value a rule can select.
type WIACertificationEntry struct {
	// Name is the atom rules use in (assure-wia-cert (name ...)).
	Name string `yaml:"name" json:"name"`
	// Information is emitted verbatim as wallet_solution_certification_
	// information.
	Information map[string]interface{} `yaml:"information" json:"information"`
}

// WIACertificationEntryList is a list of entries that can also be supplied
// through an environment variable as a JSON array.
type WIACertificationEntryList []WIACertificationEntry

// Decode implements envconfig.Decoder (JSON array).
func (l *WIACertificationEntryList) Decode(value string) error {
	if strings.TrimSpace(value) == "" {
		*l = nil
		return nil
	}
	var out []WIACertificationEntry
	if err := json.Unmarshal([]byte(value), &out); err != nil {
		return fmt.Errorf("wia certification entries must be a JSON array: %w", err)
	}
	*l = out
	return nil
}

// EffectiveWIAProfileSchemes returns the configured profile schemes plus the
// built-in one when none with its id is configured.
func (c *AssuranceConfig) EffectiveWIAProfileSchemes() []WIAProfileSchemeConfig {
	out := append([]WIAProfileSchemeConfig(nil), c.WIAProfileSchemes...)
	for _, s := range out {
		if s.ID == DefaultWIAProfileSchemeID {
			return out
		}
	}
	return append(out, BuiltinWIAProfileScheme())
}

// WIAProfileSchemeByID returns the effective profile scheme with the given id
// (the default when id is empty).
func (c *AssuranceConfig) WIAProfileSchemeByID(id string) (WIAProfileSchemeConfig, bool) {
	if id == "" {
		id = DefaultWIAProfileSchemeID
	}
	for _, s := range c.EffectiveWIAProfileSchemes() {
		if s.ID == id {
			return s, true
		}
	}
	return WIAProfileSchemeConfig{}, false
}

// LevelSchemeConfig is a named, ordered set of assurance levels.
type LevelSchemeConfig struct {
	// ID names the scheme.
	ID string `yaml:"id" json:"id"`
	// Levels are the level names, weakest first. They are the atoms rules
	// use in (tier ...).
	Levels []string `yaml:"levels" json:"levels"`
	// Values are the strings emitted in the KA for each level, same length
	// and order as Levels.
	Values []string `yaml:"values" json:"values"`
	// Floor is the level returned when nothing is granted.
	Floor string `yaml:"floor" json:"floor"`
	// Ceiling optionally caps the result.
	Ceiling string `yaml:"ceiling,omitempty" json:"ceiling,omitempty"`
}

// LevelSchemeList is a list of schemes that can also be supplied through an
// environment variable as a JSON array.
type LevelSchemeList []LevelSchemeConfig

// Decode implements envconfig.Decoder (JSON array).
func (l *LevelSchemeList) Decode(value string) error {
	if strings.TrimSpace(value) == "" {
		*l = nil
		return nil
	}
	var out []LevelSchemeConfig
	if err := json.Unmarshal([]byte(value), &out); err != nil {
		return fmt.Errorf("level_schemes must be a JSON array: %w", err)
	}
	*l = out
	return nil
}

// CertificationCatalogueConfig lists the certifications the policy may
// grant.
type CertificationCatalogueConfig struct {
	// Scheme is the default certification scheme name for derived entries.
	Scheme string `yaml:"scheme" envconfig:"SCHEME"`
	// Levels are the assurance levels of Scheme, strongest first. When
	// Entries is empty one entry per level is derived, named after the level.
	Levels []string `yaml:"levels" envconfig:"LEVELS"`
	// Entries are the named certifications, probed in order (list the
	// strongest first); the first one a rule permits wins.
	Entries CertificationEntryList `yaml:"entries" envconfig:"ENTRIES"`
}

// CertificationEntry is a named certification a rule can grant.
type CertificationEntry struct {
	// Name is the atom rules use in (assure-cert (name ...)).
	Name string `yaml:"name" json:"name"`
	// Scheme and AssuranceLevel become the emitted certification object.
	Scheme         string `yaml:"scheme" json:"scheme"`
	AssuranceLevel string `yaml:"assurance_level" json:"assurance_level"`
	// URL, when set, makes the emitted certification the URL string, which
	// is the shape OpenID4VCI Appendix D defines. Takes precedence over the
	// object.
	URL string `yaml:"url,omitempty" json:"url,omitempty"`
}

// CertificationEntryList is a list of entries that can also be supplied
// through an environment variable as a JSON array.
type CertificationEntryList []CertificationEntry

// Decode implements envconfig.Decoder (JSON array).
func (l *CertificationEntryList) Decode(value string) error {
	if strings.TrimSpace(value) == "" {
		*l = nil
		return nil
	}
	var out []CertificationEntry
	if err := json.Unmarshal([]byte(value), &out); err != nil {
		return fmt.Errorf("certification entries must be a JSON array: %w", err)
	}
	*l = out
	return nil
}

// BuiltinISO18045Scheme returns the default level scheme. Levels are in
// ISO 18045 attack-potential order: basic (VAN.2) < enhanced-basic (VAN.3)
// < moderate (VAN.4) < high (VAN.5).
func BuiltinISO18045Scheme() LevelSchemeConfig {
	return LevelSchemeConfig{
		ID:     DefaultLevelSchemeID,
		Levels: []string{"basic", "enhanced-basic", "moderate", "high"},
		Values: []string{
			"iso_18045_basic", "iso_18045_enhanced-basic",
			"iso_18045_moderate", "iso_18045_high",
		},
		Floor: "basic",
	}
}

// RegisteredAttackPotentialValues are the key_storage / user_authentication
// values registered by OpenID4VCI 1.0 Appendix D.2.
var RegisteredAttackPotentialValues = map[string]bool{
	"iso_18045_high":           true,
	"iso_18045_moderate":       true,
	"iso_18045_enhanced-basic": true,
	"iso_18045_basic":          true,
}

// assuranceAtom is what a level name, scheme id or entry name must look like
// so it is a plain token in a rules file.
var assuranceAtom = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

// IsAssuranceAtom reports whether s is usable as a level name, scheme id or
// certification entry name.
func IsAssuranceAtom(s string) bool { return len(s) <= 64 && assuranceAtom.MatchString(s) }

// EffectiveSchemes returns the configured schemes plus the built-in one when
// no scheme with its id is configured.
func (c *AssuranceConfig) EffectiveSchemes() []LevelSchemeConfig {
	out := append([]LevelSchemeConfig(nil), c.LevelSchemes...)
	for _, s := range out {
		if s.ID == DefaultLevelSchemeID {
			return out
		}
	}
	return append(out, BuiltinISO18045Scheme())
}

// SchemeByID returns the effective scheme with the given id.
func (c *AssuranceConfig) SchemeByID(id string) (LevelSchemeConfig, bool) {
	if id == "" {
		id = DefaultLevelSchemeID
	}
	for _, s := range c.EffectiveSchemes() {
		if s.ID == id {
			return s, true
		}
	}
	return LevelSchemeConfig{}, false
}

// EffectiveCertificationEntries returns the explicit entries, or entries
// derived from Scheme and Levels.
func (c *AssuranceConfig) EffectiveCertificationEntries() []CertificationEntry {
	if len(c.Certification.Entries) > 0 {
		return append([]CertificationEntry(nil), c.Certification.Entries...)
	}
	var out []CertificationEntry
	for _, lvl := range c.Certification.Levels {
		out = append(out, CertificationEntry{
			Name: lvl, Scheme: c.Certification.Scheme, AssuranceLevel: lvl,
		})
	}
	return out
}

// Validate checks the structural configuration. It is fail-closed: any
// problem is an error. Only meaningful, and only enforced, when Enabled; a
// disabled policy is not inspected so it can never block startup.
func (c *AssuranceConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	const p = "wallet_provider.attestation.assurance"
	if strings.TrimSpace(c.RulesFile) == "" {
		return fmt.Errorf("%s.rules_file is required when %s.enabled is true (an empty rules file is valid)", p, p)
	}
	lower := strings.ToLower(c.RulesFile)
	if strings.HasSuffix(lower, ".spocp") || strings.HasSuffix(lower, ".bin") {
		return fmt.Errorf("%s.rules_file %q must not end in .spocp or .bin (go-spocp would load it as a binary file); use .rules", p, c.RulesFile)
	}

	seen := map[string]bool{}
	for i, s := range c.EffectiveSchemes() {
		if !IsAssuranceAtom(s.ID) {
			return fmt.Errorf("%s.level_schemes[%d].id %q is not a valid identifier", p, i, s.ID)
		}
		if seen[s.ID] {
			return fmt.Errorf("%s.level_schemes: duplicate scheme id %q", p, s.ID)
		}
		seen[s.ID] = true
		if err := s.Validate(); err != nil {
			return fmt.Errorf("%s.level_schemes[%q]: %w", p, s.ID, err)
		}
	}
	for dim, id := range map[string]string{
		"key_storage_scheme":         c.KeyStorageScheme,
		"user_authentication_scheme": c.UserAuthenticationScheme,
	} {
		if _, ok := c.SchemeByID(id); !ok {
			return fmt.Errorf("%s.%s references unknown scheme %q", p, dim, id)
		}
	}

	names := map[string]bool{}
	for i, e := range c.EffectiveCertificationEntries() {
		if !IsAssuranceAtom(e.Name) {
			return fmt.Errorf("%s.certification entry %d: name %q is not a valid identifier", p, i, e.Name)
		}
		if names[e.Name] {
			return fmt.Errorf("%s.certification: duplicate entry name %q", p, e.Name)
		}
		names[e.Name] = true
		if e.URL == "" && (e.Scheme == "" || e.AssuranceLevel == "") {
			return fmt.Errorf("%s.certification entry %q needs scheme and assurance_level (or a url)", p, e.Name)
		}
	}
	if len(c.Certification.Entries) == 0 && len(c.Certification.Levels) > 0 && c.Certification.Scheme == "" {
		return fmt.Errorf("%s.certification.levels requires certification.scheme", p)
	}

	seenWIA := map[string]bool{}
	for i, s := range c.EffectiveWIAProfileSchemes() {
		if !IsAssuranceAtom(s.ID) {
			return fmt.Errorf("%s.wia_profile_schemes[%d].id %q is not a valid identifier", p, i, s.ID)
		}
		if seenWIA[s.ID] {
			return fmt.Errorf("%s.wia_profile_schemes: duplicate scheme id %q", p, s.ID)
		}
		seenWIA[s.ID] = true
		if err := s.Validate(); err != nil {
			return fmt.Errorf("%s.wia_profile_schemes[%q]: %w", p, s.ID, err)
		}
	}
	if _, ok := c.WIAProfileSchemeByID(c.WIAProfileScheme); !ok {
		return fmt.Errorf("%s.wia_profile_scheme references unknown scheme %q", p, c.WIAProfileScheme)
	}
	wiaNames := map[string]bool{}
	for i, e := range c.WIACertification.Entries {
		if !IsAssuranceAtom(e.Name) {
			return fmt.Errorf("%s.wia_certification entry %d: name %q is not a valid identifier", p, i, e.Name)
		}
		if wiaNames[e.Name] {
			return fmt.Errorf("%s.wia_certification: duplicate entry name %q", p, e.Name)
		}
		wiaNames[e.Name] = true
		if len(e.Information) == 0 {
			return fmt.Errorf("%s.wia_certification entry %q needs a non-empty information object", p, e.Name)
		}
	}
	return nil
}

// Validate checks one scheme for internal consistency.
func (s LevelSchemeConfig) Validate() error {
	if len(s.Levels) == 0 {
		return fmt.Errorf("levels must not be empty")
	}
	if len(s.Values) != len(s.Levels) {
		return fmt.Errorf("values (%d) must match levels (%d) one to one", len(s.Values), len(s.Levels))
	}
	idx := map[string]int{}
	vals := map[string]bool{}
	for i, l := range s.Levels {
		if !IsAssuranceAtom(l) {
			return fmt.Errorf("level %q is not a valid identifier", l)
		}
		if _, dup := idx[l]; dup {
			return fmt.Errorf("duplicate level %q", l)
		}
		idx[l] = i
		v := s.Values[i]
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("value for level %q is empty", l)
		}
		if vals[v] {
			return fmt.Errorf("duplicate emitted value %q", v)
		}
		vals[v] = true
	}
	fi, ok := idx[s.Floor]
	if !ok {
		return fmt.Errorf("floor %q is not one of the levels", s.Floor)
	}
	if s.Ceiling != "" {
		ci, ok := idx[s.Ceiling]
		if !ok {
			return fmt.Errorf("ceiling %q is not one of the levels", s.Ceiling)
		}
		if ci < fi {
			return fmt.Errorf("ceiling %q is below floor %q", s.Ceiling, s.Floor)
		}
	}
	return nil
}
