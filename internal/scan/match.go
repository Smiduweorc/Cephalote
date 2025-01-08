package scan

import (
	"regexp"
	"strings"
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

// ignoreRe captures an inline suppression directive and its optional id list.
var ignoreRe = regexp.MustCompile(`cephalote:ignore\b[ \t]*([\w:.,\-]*)`)

// suppressed reports whether a source line silences a finding with ruleID. A
// bare `cephalote:ignore` (or `cephalote:ignore all`) silences everything on
// the line; otherwise only the listed ids are silenced.
func suppressed(line, ruleID string) bool {
	m := ignoreRe.FindStringSubmatch(line)
	if m == nil {
		return false
	}
	ids := strings.TrimSpace(m[1])
	if ids == "" || ids == "all" {
		return true
	}
	for _, id := range strings.FieldsFunc(ids, func(r rune) bool { return r == ',' || r == ' ' }) {
		if id == ruleID {
			return true
		}
	}
	return false
}
