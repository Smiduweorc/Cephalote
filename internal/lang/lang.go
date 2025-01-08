// Package lang detects a source file's language and routes it to the most
// precise detection tier available.
package lang

import (
	"bufio"
	"bytes"
	"path/filepath"
	"strings"
)

// Tier identifies which analysis engine should handle a file.
type Tier int

const (
	// TierNone means the file is not recognized as source we analyze.
	TierNone Tier = iota
	// TierGoAST is the native go/ast analyzer (tier 1).
	TierGoAST
	// TierTreeSitter is the Tree-sitter analyzer (tier 2). Not yet
	// implemented; such files currently fall back to the regex tier.
	TierTreeSitter
	// TierRegex is the generic line-by-line regex fallback (tier 3).
	TierRegex
)

// Language is the result of detection.
type Language struct {
	// Name is a stable lowercase identifier ("go", "python", "unknown").
	Name string
	// Tier is the most precise engine available for this language today.
	Tier Tier
}

// byExt maps a lowercased file extension to a language name and the highest
// tier we can currently apply. Languages that would ideally use Tree-sitter
// are marked TierTreeSitter but fall back to regex until that engine lands.
var byExt = map[string]Language{
	".go": {"go", TierGoAST},

	".py":    {"python", TierTreeSitter},
	".pyw":   {"python", TierTreeSitter},
	".js":    {"javascript", TierTreeSitter},
	".mjs":   {"javascript", TierTreeSitter},
	".cjs":   {"javascript", TierTreeSitter},
	".ts":    {"typescript", TierTreeSitter},
	".tsx":   {"typescript", TierTreeSitter},
	".jsx":   {"javascript", TierTreeSitter},
	".java":  {"java", TierTreeSitter},
	".c":     {"c", TierTreeSitter},
	".h":     {"c", TierTreeSitter},
	".cc":    {"cpp", TierTreeSitter},
	".cpp":   {"cpp", TierTreeSitter},
	".cxx":   {"cpp", TierTreeSitter},
	".hpp":   {"cpp", TierTreeSitter},
	".rb":    {"ruby", TierTreeSitter},
	".php":   {"php", TierTreeSitter},
	".rs":    {"rust", TierTreeSitter},
	".cs":    {"csharp", TierTreeSitter},
	".kt":    {"kotlin", TierTreeSitter},
	".swift": {"swift", TierTreeSitter},
	".scala": {"scala", TierTreeSitter},
}

// shebangLang maps interpreter basenames seen in a "#!" line to a language.
var shebangLang = map[string]Language{
	"python":  {"python", TierTreeSitter},
	"python3": {"python", TierTreeSitter},
	"node":    {"javascript", TierTreeSitter},
	"ruby":    {"ruby", TierTreeSitter},
	"php":     {"php", TierTreeSitter},
}

// Detect classifies a file by extension first, then by shebang/content
// sniffing for extensionless files. Files we cannot place are returned as
// {"unknown", TierNone}; the caller decides (via --include-unknown) whether to
// still run the regex fallback on them.
func Detect(path string, content []byte) Language {
	ext := strings.ToLower(filepath.Ext(path))
	if l, ok := byExt[ext]; ok {
		return l
	}
	if l, ok := detectShebang(content); ok {
		return l
	}
	return Language{Name: "unknown", Tier: TierNone}
}

func detectShebang(content []byte) (Language, bool) {
	if !bytes.HasPrefix(content, []byte("#!")) {
		return Language{}, false
	}
	sc := bufio.NewScanner(bytes.NewReader(content))
	if !sc.Scan() {
		return Language{}, false
	}
	line := sc.Text()
	// Take the last whitespace-separated token's basename, e.g.
	// "#!/usr/bin/env python3" -> "python3", "#!/usr/bin/python" -> "python".
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return Language{}, false
	}
	last := filepath.Base(fields[len(fields)-1])
	if l, ok := shebangLang[last]; ok {
		return l, true
	}
	// Handle "#!/usr/bin/python" where the interpreter is the only token.
	first := filepath.Base(strings.TrimPrefix(fields[0], "#!"))
	if l, ok := shebangLang[first]; ok {
		return l, true
	}
	return Language{}, false
}
