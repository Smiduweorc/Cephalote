package scan

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/Smiduweorc/Cephalote/internal/rules"
)

// globMatcher matches a path against a compiled glob. Patterns without a slash
// match against the basename (gitignore semantics); patterns with a slash match
// against the path relative to the scan root.
type globMatcher struct {
	re        *regexp.Regexp
	matchBase bool
}

func compileGlobs(patterns []string) ([]globMatcher, error) {
	var out []globMatcher
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		re, err := regexp.Compile(globToRegex(strings.TrimSuffix(p, "/")))
		if err != nil {
			return nil, err
		}
		out = append(out, globMatcher{re: re, matchBase: !strings.Contains(p, "/")})
	}
	return out, nil
}

func (g globMatcher) match(rel, base string) bool {
	if g.matchBase {
		return g.re.MatchString(base)
	}
	return g.re.MatchString(rel)
}

// globToRegex converts a glob (supporting *, **, and ?) into an anchored
// regexp. `*` matches within a path segment, `**` matches across segments.
func globToRegex(glob string) string {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(glob); i++ {
		c := glob[i]
		switch c {
		case '*':
			if i+1 < len(glob) && glob[i+1] == '*' {
				i++
				if i+1 < len(glob) && glob[i+1] == '/' {
					i++
					b.WriteString("(?:.*/)?")
				} else {
					b.WriteString(".*")
				}
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		case '.', '+', '(', ')', '|', '^', '$', '{', '}', '[', ']', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteString("$")
	return b.String()
}

// ignoreRe finds an inline suppression directive and captures the rest of
// the line after it.
var ignoreRe = regexp.MustCompile(`cephalote:ignore\b(.*)`)

// commentClosers end the comment a directive sits in; nothing after one
// belongs to the directive.
var commentClosers = []string{"*/", "-->"}

// suppressed reports whether a source line silences a finding with ruleID.
//
// The grammar is `cephalote:ignore [id ...] [reason]`. Ids are separated by
// commas or whitespace, and each is a built-in rule id, `all`, or any
// `scheme:<name>`. The first word that is none of those starts a free-text
// reason, which runs to the end of the comment. With no ids the directive is
// bare and silences everything on the line; so does `all`.
func suppressed(line, ruleID string) bool {
	m := ignoreRe.FindStringSubmatch(line)
	if m == nil {
		return false
	}
	rest := m[1]
	for _, c := range commentClosers {
		if i := strings.Index(rest, c); i >= 0 {
			rest = rest[:i]
		}
	}
	words := strings.FieldsFunc(rest, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
	listed := false
	for _, w := range words {
		if !isRuleID(w) {
			break
		}
		if w == "all" || w == ruleID {
			return true
		}
		listed = true
	}
	return !listed
}

// isRuleID reports whether a directive word names a rule rather than starting
// the reason. Any scheme: word counts, so a custom scheme needs no registry.
func isRuleID(w string) bool {
	if w == "all" || strings.HasPrefix(w, "scheme:") {
		return true
	}
	_, ok := rules.Get(w)
	return ok
}
