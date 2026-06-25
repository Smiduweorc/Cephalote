// Package rules holds the declarative metadata for the tier-1 (Go AST) crypto
// misuse detections, both presence-based (e.g. MD5) and value/structure-based
// (e.g. undersized RSA keys, hardcoded keys). Tier-3 presence detection across
// all languages is driven separately by the algorithm catalog in package
// scheme. Centralizing metadata here means every tier reports findings the same
// way regardless of how they were detected.
package rules

import (
	"github.com/Smiduweorc/Cephalote/internal/finding"
)

// Rule is one declarative tier-1 detection's metadata.
type Rule struct {
	ID          string
	Title       string
	Description string
	Severity    finding.Severity
	Remediation string
}

// Stable rule IDs referenced by the AST analyzer.
const (
	MD5          = "weak-hash-md5"
	SHA1         = "weak-hash-sha1"
	MD4          = "weak-hash-md4"
	DES          = "weak-cipher-des"
	TripleDES    = "weak-cipher-3des"
	RC4          = "weak-cipher-rc4"
	Blowfish     = "weak-cipher-blowfish"
	ECB          = "insecure-mode-ecb"
	RSASmall     = "weak-key-rsa"
	WeakRand     = "insecure-random"
	WeakTLS      = "deprecated-tls"
	HardcodedKey = "hardcoded-key"
	StaticIV     = "static-iv"
)

// catalog is the single source of truth for rule metadata, keyed by ID.
var catalog = map[string]Rule{
	MD5: {
		ID:          MD5,
		Title:       "Use of MD5",
		Description: "MD5 is cryptographically broken and unsuitable for security purposes (collisions are trivial).",
		Severity:    finding.HighSev,
		Remediation: "Use SHA-256 or stronger. For password hashing use bcrypt, scrypt, or Argon2.",
	},
	SHA1: {
		ID:          SHA1,
		Title:       "Use of SHA-1",
		Description: "SHA-1 is deprecated; practical collision attacks exist (SHAttered).",
		Severity:    finding.Medium,
		Remediation: "Use SHA-256 or SHA-3 for digests and signatures.",
	},
	MD4: {
		ID:          MD4,
		Title:       "Use of MD4",
		Description: "MD4 is severely broken and must never be used for security.",
		Severity:    finding.HighSev,
		Remediation: "Use SHA-256 or stronger.",
	},
	DES: {
		ID:          DES,
		Title:       "Use of DES",
		Description: "DES has a 56-bit key and is brute-forceable in hours.",
		Severity:    finding.HighSev,
		Remediation: "Use AES-256-GCM or ChaCha20-Poly1305.",
	},
	TripleDES: {
		ID:          TripleDES,
		Title:       "Use of Triple DES (3DES)",
		Description: "3DES has a 64-bit block (Sweet32) and is deprecated by NIST.",
		Severity:    finding.Medium,
		Remediation: "Use AES-256-GCM or ChaCha20-Poly1305.",
	},
	RC4: {
		ID:          RC4,
		Title:       "Use of RC4",
		Description: "RC4 has biased keystream output and is prohibited (RFC 7465).",
		Severity:    finding.HighSev,
		Remediation: "Use a modern AEAD cipher such as AES-GCM or ChaCha20-Poly1305.",
	},
	Blowfish: {
		ID:          Blowfish,
		Title:       "Use of Blowfish",
		Description: "Blowfish has a 64-bit block and is vulnerable to birthday attacks (Sweet32).",
		Severity:    finding.Medium,
		Remediation: "Use AES-256-GCM or ChaCha20-Poly1305.",
	},
	ECB: {
		ID:          ECB,
		Title:       "Use of ECB cipher mode",
		Description: "ECB mode does not hide data patterns; identical plaintext blocks produce identical ciphertext.",
		Severity:    finding.HighSev,
		Remediation: "Use an authenticated mode such as GCM, or CBC with a random IV plus a MAC.",
	},
	RSASmall: {
		ID:          RSASmall,
		Title:       "Undersized RSA key",
		Description: "RSA keys smaller than 2048 bits do not provide adequate security margin.",
		Severity:    finding.HighSev,
		Remediation: "Generate RSA keys of at least 2048 bits (3072+ preferred), or use an EC/Ed25519 key.",
	},
	WeakRand: {
		ID:          WeakRand,
		Title:       "Insecure randomness for security context",
		Description: "Non-cryptographic PRNGs (math/rand, Math.random) are predictable and unsafe for keys, IVs, tokens, or salts.",
		Severity:    finding.Medium,
		Remediation: "Use a CSPRNG: crypto/rand in Go, crypto.getRandomValues / node:crypto in JS, secrets in Python.",
	},
	WeakTLS: {
		ID:          WeakTLS,
		Title:       "Deprecated TLS/SSL version",
		Description: "SSLv3 and TLS 1.0/1.1 are deprecated and vulnerable (POODLE, BEAST).",
		Severity:    finding.Medium,
		Remediation: "Require TLS 1.2 as a minimum, preferably TLS 1.3.",
	},
	HardcodedKey: {
		ID:          HardcodedKey,
		Title:       "Hardcoded cryptographic key",
		Description: "A cipher/MAC key is built from a literal in source; anyone with the code has the key.",
		Severity:    finding.Critical,
		Remediation: "Load keys from a secret store, environment, or KMS; never embed them in source.",
	},
	StaticIV: {
		ID:          StaticIV,
		Title:       "Static or zero IV/nonce",
		Description: "A literal or all-zero IV/nonce destroys semantic security; identical plaintexts leak.",
		Severity:    finding.HighSev,
		Remediation: "Generate a fresh random IV/nonce per message with crypto/rand and prepend it to the ciphertext.",
	},
}

// Get returns the rule metadata for an ID. The second result is false if the
// ID is unknown.
func Get(id string) (Rule, bool) {
	r, ok := catalog[id]
	return r, ok
}

// MustGet returns rule metadata for an ID, panicking if it is unknown. It is
// intended for engine code using the compile-time ID constants above.
func MustGet(id string) Rule {
	r, ok := catalog[id]
	if !ok {
		panic("rules: unknown rule id " + id)
	}
	return r
}
