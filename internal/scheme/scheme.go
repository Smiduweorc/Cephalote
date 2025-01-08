// Package scheme is the authoritative catalog of cryptographic algorithms
// Cephalote knows about, each tagged with a security class and a matcher.
//
// It serves two purposes:
//
//  1. It is the grounded "list of weak schemes" the weak-scan tiers draw from.
//  2. It powers user-driven search (`--scheme`), letting anyone locate a
//     specific algorithm by name, weak or strong (e.g. find every SHA-256
//     use for a crypto-agility migration).
//
// Matching here is regex-based and therefore low confidence (it cannot tell a
// real call from a comment), but it is language-agnostic and exhaustive.
package scheme

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/Smiduweorc/Cephalote/internal/finding"
)

// Class is the security posture of an algorithm.
type Class string

const (
	Broken     Class = "broken"     // catastrophically broken; never use
	Weak       Class = "weak"       // deprecated / practically attackable
	Legacy     Class = "legacy"     // dated but not broken; avoid in new code
	Contextual Class = "contextual" // safe or unsafe depending on parameters
	Strong     Class = "strong"     // modern, recommended
)

// Scheme is one named algorithm.
type Scheme struct {
	Name    string // canonical lowercase id, e.g. "sha256"
	Title   string // display name, e.g. "SHA-256"
	Class   Class
	Note    string
	pattern *regexp.Regexp

	// custom holds the remediation for user-defined schemes; built-in schemes
	// leave it empty and resolve guidance via remediationByName/class.
	custom string
}

// New compiles a user-defined scheme (e.g. from a config file). The pattern is
// a Go regular expression; matching is case-sensitive unless the pattern opts
// in with (?i).
func New(name, title string, class Class, note, remediation, pattern string) (Scheme, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return Scheme{}, fmt.Errorf("scheme %q: invalid pattern: %w", name, err)
	}
	if title == "" {
		title = name
	}
	if class == "" {
		class = Weak
	}
	return Scheme{Name: name, Title: title, Class: class, Note: note, pattern: re, custom: remediation}, nil
}

// Severity maps an algorithm's class to a finding severity.
func (s Scheme) Severity() finding.Severity {
	switch s.Class {
	case Broken:
		return finding.HighSev
	case Weak:
		return finding.Medium
	case Legacy:
		return finding.LowSev
	default: // Strong, Contextual
		return finding.Info
	}
}

func mk(name, title string, class Class, note, re string) Scheme {
	return Scheme{
		Name:    name,
		Title:   title,
		Class:   class,
		Note:    note,
		pattern: regexp.MustCompile("(?i)" + re),
	}
}

// catalog is ordered roughly by category then strength. Patterns use word
// boundaries to limit false positives; entries whose plain name is a common
// English word (e.g. IDEA, TEA) are intentionally omitted to preserve signal.
var catalog = []Scheme{
	// --- Hash functions ---
	mk("md2", "MD2", Broken, "Obsolete hash; broken.", `\bmd2\b`),
	mk("md4", "MD4", Broken, "Severely broken hash.", `\bmd4\b`),
	mk("md5", "MD5", Broken, "Collision-broken hash; unfit for security.", `\bmd5\b`),
	mk("sha0", "SHA-0", Broken, "Withdrawn, broken hash.", `\bsha-?0\b`),
	mk("sha1", "SHA-1", Weak, "Deprecated; practical collisions (SHAttered).", `\bsha-?1\b`),
	mk("ntlm", "NTLM/NT hash", Broken, "Unsalted MD4-based password hash.", `\bntlm\b|\bnt hash\b`),
	mk("ripemd160", "RIPEMD-160", Legacy, "Dated; prefer SHA-2/SHA-3.", `\bripemd-?160\b`),
	mk("sha224", "SHA-224", Strong, "SHA-2 family.", `\bsha-?224\b`),
	mk("sha256", "SHA-256", Strong, "SHA-2 family; recommended.", `\bsha-?256\b`),
	mk("sha384", "SHA-384", Strong, "SHA-2 family.", `\bsha-?384\b`),
	mk("sha512", "SHA-512", Strong, "SHA-2 family.", `\bsha-?512\b`),
	mk("sha3", "SHA-3", Strong, "Keccak-based; recommended.", `\bsha-?3\b|\bkeccak\b`),
	mk("blake2", "BLAKE2", Strong, "Fast modern hash.", `\bblake2[bs]?\b`),
	mk("blake3", "BLAKE3", Strong, "Fast modern hash.", `\bblake3\b`),

	// --- Symmetric ciphers ---
	mk("des", "DES", Broken, "56-bit key; brute-forceable.", `\bdes(-(cbc|ecb|cfb|ofb))?\b`),
	mk("3des", "Triple DES", Weak, "64-bit block (Sweet32); deprecated.", `\b(3des|triple-?des|des-?ede|des3)\b`),
	mk("rc2", "RC2", Broken, "Weak legacy cipher.", `\brc2\b`),
	mk("rc4", "RC4", Broken, "Biased keystream; prohibited (RFC 7465).", `\brc4\b|\barcfour\b`),
	mk("blowfish", "Blowfish", Weak, "64-bit block (Sweet32).", `\bblowfish\b`),
	mk("cast5", "CAST5/CAST-128", Weak, "64-bit block.", `\bcast-?5\b|\bcast-?128\b`),
	mk("skipjack", "Skipjack", Broken, "Withdrawn 80-bit cipher.", `\bskipjack\b`),
	mk("rc5", "RC5", Legacy, "Aging; use AES.", `\brc5\b`),
	mk("camellia", "Camellia", Strong, "128-bit block; acceptable.", `\bcamellia\b`),
	mk("salsa20", "Salsa20", Legacy, "Prefer ChaCha20.", `\bsalsa20\b`),
	mk("chacha20", "ChaCha20", Strong, "Modern stream cipher.", `\bchacha20(-?poly1305)?\b`),
	mk("aes", "AES", Strong, "Recommended block cipher.", `\baes(-?(128|192|256))?\b`),

	// --- Cipher modes ---
	mk("ecb", "ECB mode", Weak, "Leaks plaintext patterns.", `\becb\b`),
	mk("cbc", "CBC mode", Contextual, "Needs random IV + MAC (padding-oracle risk).", `\bcbc\b`),
	mk("gcm", "GCM mode", Strong, "Authenticated (AEAD).", `\bgcm\b`),
	mk("ccm", "CCM mode", Strong, "Authenticated (AEAD).", `\bccm\b`),

	// --- Asymmetric ---
	mk("rsa", "RSA", Contextual, "Secure only with >=2048-bit keys and OAEP/PSS.", `\brsa\b`),
	mk("dsa", "DSA", Weak, "Fragile to bad nonces; prefer EdDSA/ECDSA.", `\bdsa\b`),
	mk("dh", "Diffie-Hellman", Contextual, "Needs >=2048-bit groups.", `\bdiffie-?hellman\b`),
	mk("elgamal", "ElGamal", Legacy, "Rarely needed today.", `\belgamal\b`),
	mk("ecdsa", "ECDSA", Strong, "Use strong curves (P-256+).", `\becdsa\b`),
	mk("ecdh", "ECDH", Strong, "Modern key agreement.", `\becdh\b`),
	mk("ed25519", "Ed25519", Strong, "Modern signature scheme.", `\bed25519\b`),
	mk("x25519", "X25519", Strong, "Modern key agreement.", `\bx25519\b`),

	// --- Password hashing / KDF ---
	mk("pbkdf2", "PBKDF2", Strong, "Acceptable with high iteration count.", `\bpbkdf2\b`),
	mk("bcrypt", "bcrypt", Strong, "Recommended password hash.", `\bbcrypt\b`),
	mk("scrypt", "scrypt", Strong, "Recommended password hash.", `\bscrypt\b`),
	mk("argon2", "Argon2", Strong, "Recommended password hash.", `\bargon2(id|i|d)?\b`),

	// --- Randomness ---
	mk("weak-random", "Insecure PRNG", Weak, "Predictable RNG unsafe for secrets.",
		`math\.random\s*\(|\bmath/rand\b|\bmt_rand\b|\bjava\.util\.random\b|\bsrand\s*\(`),

	// --- Transport ---
	mk("sslv2", "SSLv2", Broken, "Obsolete, broken protocol.", `\bsslv2\b|\bssl2\b`),
	mk("sslv3", "SSLv3", Broken, "POODLE-vulnerable.", `\bsslv3\b|\bssl3\b`),
	mk("tls10", "TLS 1.0", Weak, "Deprecated (BEAST).", `\btls-?v?1[._]0\b|\btlsv1\b`),
	mk("tls11", "TLS 1.1", Weak, "Deprecated.", `\btls-?v?1[._]1\b`),
	mk("tls12", "TLS 1.2", Strong, "Acceptable minimum.", `\btls-?v?1[._]2\b`),
	mk("tls13", "TLS 1.3", Strong, "Preferred.", `\btls-?v?1[._]3\b`),
}

// All returns the full catalog.
func All() []Scheme { return catalog }

// weakSet is the broken+weak subset, precomputed once. It is the single source
// of truth for the default tier-3 (regex) weak-crypto scan, so adding a weak
// algorithm to the catalog automatically extends regex coverage.
var weakSet = func() []Scheme {
	ss, _ := Resolve([]string{"weak"})
	return ss
}()

// WeakSchemes returns the broken+weak schemes scanned for by default at tier 3.
func WeakSchemes() []Scheme { return weakSet }

// remediationByName gives specific guidance for the most common risky schemes;
// other risky schemes fall back to class-based advice via Remediation.
var remediationByName = map[string]string{
	"md2":         "Use SHA-256 or stronger.",
	"md4":         "Use SHA-256 or stronger.",
	"md5":         "Use SHA-256+. For passwords use bcrypt, scrypt, or Argon2.",
	"sha0":        "Use SHA-256 or SHA-3.",
	"sha1":        "Use SHA-256 or SHA-3 for digests and signatures.",
	"ntlm":        "Use a salted password hash (bcrypt/scrypt/Argon2).",
	"des":         "Use AES-256-GCM or ChaCha20-Poly1305.",
	"3des":        "Use AES-256-GCM or ChaCha20-Poly1305.",
	"rc2":         "Use AES-256-GCM or ChaCha20-Poly1305.",
	"rc4":         "Use a modern AEAD cipher (AES-GCM, ChaCha20-Poly1305).",
	"blowfish":    "Use AES-256-GCM or ChaCha20-Poly1305.",
	"cast5":       "Use AES-256-GCM or ChaCha20-Poly1305.",
	"skipjack":    "Use AES-256-GCM or ChaCha20-Poly1305.",
	"ecb":         "Use an authenticated mode (GCM), or CBC with a random IV plus a MAC.",
	"dsa":         "Use Ed25519 or ECDSA with a strong curve.",
	"weak-random": "Use a CSPRNG: crypto/rand, crypto.getRandomValues, secrets.",
	"sslv2":       "Disable; require TLS 1.2 minimum (TLS 1.3 preferred).",
	"sslv3":       "Disable; require TLS 1.2 minimum (TLS 1.3 preferred).",
	"tls10":       "Require TLS 1.2 as a minimum, preferably TLS 1.3.",
	"tls11":       "Require TLS 1.2 as a minimum, preferably TLS 1.3.",
}

// Remediation returns actionable guidance for a scheme, or "" when none applies
// (e.g. strong algorithms surfaced only by search).
func (s Scheme) Remediation() string {
	if s.custom != "" {
		return s.custom
	}
	if r, ok := remediationByName[s.Name]; ok {
		return r
	}
	switch s.Class {
	case Broken:
		return "This algorithm is broken; remove it and use a modern primitive."
	case Weak:
		return "This algorithm is deprecated; migrate to a modern primitive."
	case Legacy:
		return "Prefer a modern, well-supported algorithm."
	default:
		return ""
	}
}

// Resolve turns user tokens into schemes. Tokens may be class selectors
// ("all", "weak", "broken", "legacy", "strong", "contextual"), canonical names,
// or aliases (resolved by testing a token against each scheme's own matcher, so
// "sha-256", "des3", and "arcfour" all work). Unknown tokens are an error.
//
// The "weak" selector means "everything you should worry about": both the
// Broken and Weak classes.
func Resolve(tokens []string) ([]Scheme, error) {
	seen := map[string]bool{}
	var out []Scheme
	add := func(s Scheme) {
		if !seen[s.Name] {
			seen[s.Name] = true
			out = append(out, s)
		}
	}
	addClass := func(classes ...Class) {
		for _, s := range catalog {
			for _, c := range classes {
				if s.Class == c {
					add(s)
				}
			}
		}
	}

	for _, raw := range tokens {
		t := strings.ToLower(strings.TrimSpace(raw))
		if t == "" {
			continue
		}
		switch t {
		case "all":
			addClass(Broken, Weak, Legacy, Contextual, Strong)
			continue
		case "weak", "insecure":
			addClass(Broken, Weak)
			continue
		case "broken":
			addClass(Broken)
			continue
		case "legacy":
			addClass(Legacy)
			continue
		case "contextual":
			addClass(Contextual)
			continue
		case "strong":
			addClass(Strong)
			continue
		}

		matched := false
		for _, s := range catalog {
			if s.Name == t {
				add(s)
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		// Alias resolution: reuse each scheme's matcher against the token.
		for _, s := range catalog {
			if s.pattern.MatchString(t) {
				add(s)
				matched = true
			}
		}
		if !matched {
			return nil, fmt.Errorf("unknown scheme %q (run `cephalote schemes` to list known schemes)", raw)
		}
	}
	return out, nil
}

// Scan searches src line by line for any of the wanted schemes, emitting one
// low-confidence finding per scheme per matching line.
func Scan(path string, src []byte, want []Scheme) ([]finding.Finding, error) {
	var out []finding.Finding
	sc := bufio.NewScanner(bytes.NewReader(src))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		for _, s := range want {
			loc := s.pattern.FindStringIndex(line)
			if loc == nil {
				continue
			}
			out = append(out, finding.Finding{
				RuleID:      "scheme:" + s.Name,
				Title:       fmt.Sprintf("%s (%s)", s.Title, s.Class),
				Description: s.Note,
				Severity:    s.Severity(),
				Confidence:  finding.Low,
				Remediation: s.Remediation(),
				File:        path,
				Line:        lineNo,
				Column:      loc[0] + 1,
				Snippet:     strings.TrimSpace(line),
			})
		}
	}
	return out, sc.Err()
}
