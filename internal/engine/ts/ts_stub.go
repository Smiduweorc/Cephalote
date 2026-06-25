//go:build !treesitter

// Package ts is the tier-2 Tree-sitter analyzer. Tree-sitter grammars require
// cgo, which conflicts with the default single-static-binary (CGO_ENABLED=0)
// build. This stub is compiled into the default profile; build with
// `-tags treesitter` (and CGO enabled) to get the real implementation.
package ts

import "github.com/Smiduweorc/Cephalote/internal/finding"

// Available reports whether tier-2 Tree-sitter analysis is compiled in.
func Available() bool { return false }

// Supported reports whether a grammar+ruleset exists for a language.
func Supported(string) bool { return false }

// Analyze is a no-op in the default build; callers fall back to tier 3.
func Analyze(_, _ string, _ []byte) ([]finding.Finding, error) { return nil, nil }
