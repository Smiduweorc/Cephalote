//go:build !cgo

// Package ts is the tier-2 Tree-sitter analyzer. Tree-sitter grammars are C
// and need cgo; this stub is only compiled when cgo is disabled
// (CGO_ENABLED=0), which no shipped build does. Released binaries are linked
// statically against musl instead, so they are still single static files.
// `cephalote --version` says which one a binary is.
package ts

import "github.com/Smiduweorc/Cephalote/internal/finding"

// Available reports whether tier-2 Tree-sitter analysis is compiled in.
func Available() bool { return false }

// Supported reports whether a grammar+ruleset exists for a language.
func Supported(string) bool { return false }

// Analyze is a no-op in the default build; callers fall back to tier 3.
func Analyze(_, _ string, _ []byte) ([]finding.Finding, error) { return nil, nil }
