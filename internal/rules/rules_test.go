package rules

import (
	"testing"

	"github.com/Smiduweorc/Cephalote/internal/finding"
)

// allIDs is every exported rule-ID constant. The engines reference these
// directly, so each one must resolve.
var allIDs = []string{
	MD5, SHA1, MD4, DES, TripleDES, RC4, Blowfish, ECB,
	RSASmall, WeakRand, WeakTLS, HardcodedKey, StaticIV,
}

func TestGet(t *testing.T) {
	for _, id := range allIDs {
		r, ok := Get(id)
		if !ok {
			t.Errorf("Get(%q) = not found", id)
			continue
		}
		if r.ID != id {
			t.Errorf("Get(%q).ID = %q", id, r.ID)
		}
	}
	if _, ok := Get("no-such-rule"); ok {
		t.Error("Get(no-such-rule) = found, want not found")
	}
	if _, ok := Get(""); ok {
		t.Error("Get(\"\") = found, want not found")
	}
}

func TestMustGet(t *testing.T) {
	if got := MustGet(MD5).Title; got != "Use of MD5" {
		t.Errorf("MustGet(MD5).Title = %q", got)
	}
}

// MustGet is called by the engines with compile-time constants, so an unknown
// ID is a programming error and must fail loudly rather than return a zero
// Rule that would render as a blank finding.
func TestMustGetPanicsOnUnknownID(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("MustGet(unknown) did not panic")
		}
	}()
	MustGet("no-such-rule")
}

// The catalog is what every tier renders from, so a malformed entry would
// produce a finding with a blank title or an unusable severity.
func TestCatalogIsWellFormed(t *testing.T) {
	validSeverity := map[finding.Severity]bool{
		finding.Critical: true, finding.HighSev: true, finding.Medium: true,
		finding.LowSev: true, finding.Info: true,
	}
	for key, r := range catalog {
		if r.ID != key {
			t.Errorf("catalog[%q].ID = %q; the key and the ID must match", key, r.ID)
		}
		if r.Title == "" {
			t.Errorf("catalog[%q] has no Title", key)
		}
		if r.Description == "" {
			t.Errorf("catalog[%q] has no Description", key)
		}
		if r.Remediation == "" {
			t.Errorf("catalog[%q] has no Remediation; findings would offer no fix", key)
		}
		if !validSeverity[r.Severity] {
			t.Errorf("catalog[%q].Severity = %q, not a valid severity", key, r.Severity)
		}
	}
}

// Every catalogued rule should be reachable through a constant, and every
// constant should be catalogued; otherwise a rule is either unusable or fires
// with no metadata.
func TestCatalogAndConstantsAgree(t *testing.T) {
	byConst := map[string]bool{}
	for _, id := range allIDs {
		byConst[id] = true
		if _, ok := catalog[id]; !ok {
			t.Errorf("constant %q has no catalog entry", id)
		}
	}
	for id := range catalog {
		if !byConst[id] {
			t.Errorf("catalog entry %q is not exposed as a constant", id)
		}
	}
}

func TestRuleIDsAreStable(t *testing.T) {
	// These IDs appear in user config files (rules.disable, rules.severity)
	// and in SARIF consumed by code scanning, so renaming one is a breaking
	// change and should have to be done deliberately.
	want := map[string]string{
		"MD5": "weak-hash-md5", "SHA1": "weak-hash-sha1", "MD4": "weak-hash-md4",
		"DES": "weak-cipher-des", "TripleDES": "weak-cipher-3des",
		"RC4": "weak-cipher-rc4", "Blowfish": "weak-cipher-blowfish",
		"ECB": "insecure-mode-ecb", "RSASmall": "weak-key-rsa",
		"WeakRand": "insecure-random", "WeakTLS": "deprecated-tls",
		"HardcodedKey": "hardcoded-key", "StaticIV": "static-iv",
	}
	got := map[string]string{
		"MD5": MD5, "SHA1": SHA1, "MD4": MD4, "DES": DES, "TripleDES": TripleDES,
		"RC4": RC4, "Blowfish": Blowfish, "ECB": ECB, "RSASmall": RSASmall,
		"WeakRand": WeakRand, "WeakTLS": WeakTLS, "HardcodedKey": HardcodedKey,
		"StaticIV": StaticIV,
	}
	for name, wantID := range want {
		if got[name] != wantID {
			t.Errorf("rule %s = %q, want %q (changing a rule ID breaks user config and SARIF history)", name, got[name], wantID)
		}
	}
}
