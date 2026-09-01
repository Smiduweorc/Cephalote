//go:build treesitter

package ts

import "strings"

// Crypto factory APIs in most languages take the algorithm as a string rather
// than as a named symbol: `Cipher.getInstance("DES/ECB/PKCS5Padding")` in Java,
// `crypto.createHash('md5')` in Node, `OpenSSL::Cipher.new('des-ede3-cbc')` in
// Ruby, `hash('md5', ...)` in PHP. The spellings differ only in separators and
// case, so one classifier serves every language.

// algoTokens maps a single normalized token of an algorithm string to the rule
// it triggers. Tokens that are merely dated but not actionable on their own
// (padding schemes, key lengths, "cbc") are deliberately absent.
var algoTokens = map[string]string{
	"md5": ruleMD5,
	"md4": ruleMD4,

	"rc4":     ruleRC4,
	"arc4":    ruleRC4,
	"arcfour": ruleRC4,

	"blowfish": ruleBlowfish,
	"bf":       ruleBlowfish,

	"des": ruleDES,

	"3des":      rule3DES,
	"des3":      rule3DES,
	"desede":    rule3DES,
	"desede3":   rule3DES,
	"ede":       rule3DES,
	"ede3":      rule3DES,
	"tripledes": rule3DES,

	"ecb": ruleECB,

	"ssl":     ruleWeakTLS,
	"sslv2":   ruleWeakTLS,
	"sslv3":   ruleWeakTLS,
	"tlsv1":   ruleWeakTLS,
	"tlsv1.0": ruleWeakTLS,
	"tlsv1.1": ruleWeakTLS,
}

// classifyAlgorithm maps an algorithm-naming string to every rule it triggers.
// It returns nil for strings that name nothing we flag, which is the common
// case (an argument that merely happens to be a literal).
func classifyAlgorithm(s string) []string {
	toks := algoSplit(s)
	var out []string
	add := func(id string) {
		for _, have := range out {
			if have == id {
				return
			}
		}
		out = append(out, id)
	}
	for i, t := range toks {
		// "SHA1withRSA" and friends name the digest first; the part after
		// "with" is the signature scheme, and matching it would flag
		// "PBKDF2WithHmacSHA1", where SHA-1 is not the weakness.
		if j := strings.Index(t, "with"); j > 0 {
			t = t[:j]
		}
		if t == "sha" {
			// "sha" alone (hashlib.new("sha")) and "sha-1" are SHA-1; "sha-256"
			// must not be.
			if i+1 >= len(toks) || toks[i+1] == "1" {
				add(ruleSHA1)
			}
			continue
		}
		if t == "sha1" {
			add(ruleSHA1)
			continue
		}
		if id, ok := algoTokens[t]; ok {
			add(id)
		}
	}
	// "des-ede3-cbc" tokenizes to both DES and 3DES; report only the latter.
	if contains(out, rule3DES) {
		out = drop(out, ruleDES)
	}
	return out
}

// algoSplit lowercases and splits an algorithm string on the separators these
// APIs use. "." is not a separator: it distinguishes "TLSv1.2", which is fine,
// from "TLSv1", which is not.
func algoSplit(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return r == '/' || r == '-' || r == '_' || r == ' ' || r == ':'
	})
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func drop(xs []string, x string) []string {
	out := xs[:0]
	for _, v := range xs {
		if v != x {
			out = append(out, v)
		}
	}
	return out
}
